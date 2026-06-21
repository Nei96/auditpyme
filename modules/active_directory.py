"""
Módulo Active Directory / LDAP — AuditPyme
Detecta presencia de AD, enumera sin credenciales y (si se proporcionan)
audita política de contraseñas, cuentas privilegiadas, Kerberoasting, AS-REP Roasting.
"""

import socket
import ssl
import dns.resolver
from datetime import datetime, timezone

try:
    import ldap3
    from ldap3 import Server, Connection, ALL, ANONYMOUS, SIMPLE, NTLM, SUBTREE, ALL_ATTRIBUTES
    from ldap3.core.exceptions import LDAPException
    _LDAP3 = True
except ImportError:
    _LDAP3 = False

TIMEOUT = 6

# UAC flags de Active Directory
UAC_DONT_REQUIRE_PREAUTH = 0x400000
UAC_NORMAL_ACCOUNT       = 0x200
UAC_DISABLED             = 0x2

# Windows FILETIME epoch
_WIN_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _filetime_to_dt(ft: int) -> datetime | None:
    if not ft or ft in (0, 9223372036854775807):
        return None
    return _WIN_EPOCH + __import__("datetime").timedelta(microseconds=ft // 10)


def _port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT):
            return True
    except Exception:
        return False


def _smb_signing_check(host: str) -> bool | None:
    """
    Comprueba si SMB signing es requerido via nmap smb2-security-mode.
    Devuelve True si signing es requerido (seguro), False si no, None si error.
    """
    import subprocess
    try:
        out = subprocess.check_output(
            ["nmap", "-p445", "--script", "smb2-security-mode",
             "--host-timeout", "15s", host],
            timeout=20, stderr=subprocess.DEVNULL
        ).decode(errors="ignore")
        if "Message signing enabled and required" in out:
            return True
        if "Message signing enabled but not required" in out or \
           "Message signing not required" in out:
            return False
        return None
    except Exception:
        return None


def _detect_ad_via_dns(domain: str) -> bool:
    """Comprueba registros SRV típicos de AD en DNS."""
    srv_records = [
        f"_ldap._tcp.{domain}",
        f"_kerberos._tcp.{domain}",
        f"_kpasswd._tcp.{domain}",
    ]
    for rec in srv_records:
        try:
            dns.resolver.resolve(rec, "SRV", lifetime=4)
            return True
        except Exception:
            continue
    return False


class ActiveDirectoryAuditor:
    def __init__(self, target: str, recon: dict = None,
                 ad_user: str = None, ad_pass: str = None, ad_domain: str = None):
        self.target    = target
        self.recon     = recon or {}
        self.ad_user   = ad_user
        self.ad_pass   = ad_pass
        self.ad_domain = ad_domain or target
        self._findings = []

    def scan(self) -> list:
        if not _LDAP3:
            self._add("ldap3 no instalado", "Config", "INFO",
                      "Instalar ldap3 para habilitar auditoría AD/LDAP.", "pip install ldap3")
            return self._findings

        print("\n  [AD] Detectando presencia de Active Directory...")

        has_ldap   = _port_open(self.target, 389)
        has_ldaps  = _port_open(self.target, 636)
        has_kerb   = _port_open(self.target, 88)
        has_gc     = _port_open(self.target, 3268)
        has_smb    = _port_open(self.target, 445)
        has_dns_ad = _detect_ad_via_dns(self.ad_domain)

        ad_detected = has_ldap or has_kerb or has_gc or has_dns_ad

        if not ad_detected:
            print("  [AD] No se detectó Active Directory en este objetivo.")
            return self._findings

        print(f"  [AD] Activo — LDAP:{has_ldap} LDAPS:{has_ldaps} "
              f"Kerberos:{has_kerb} GlobalCatalog:{has_gc} SMB:{has_smb}")

        # Checks sin credenciales
        self._check_ldap_rootdse(has_ldap, has_ldaps)
        self._check_ldap_anonymous(has_ldap)
        self._check_smb_signing(has_smb)
        self._check_ldap_signing(has_ldap)

        # Checks con credenciales
        if self.ad_user and self.ad_pass:
            print(f"  [AD] Autenticando como {self.ad_user}@{self.ad_domain}...")
            conn = self._connect_auth(has_ldap, has_ldaps)
            if conn:
                base_dn = self._get_base_dn(conn)
                self._check_password_policy(conn, base_dn)
                self._check_asrep_roasting(conn, base_dn)
                self._check_kerberoasting(conn, base_dn)
                self._check_stale_accounts(conn, base_dn)
                self._check_privileged_accounts(conn, base_dn)
                self._check_laps(conn, base_dn)
                conn.unbind()
            else:
                self._add("Autenticación AD fallida", "Config", "INFO",
                          f"No se pudo autenticar como {self.ad_user}@{self.ad_domain}.",
                          "Verificar credenciales y conectividad.")
        else:
            print("  [AD] Sin credenciales — solo checks anónimos.")

        return self._findings

    # ── Checks sin credenciales ───────────────────────────────────────────────

    def _check_ldap_rootdse(self, has_ldap: bool, has_ldaps: bool):
        """RootDSE siempre es accesible anónimamente — extrae info del dominio."""
        configs = []
        if has_ldap:
            configs.append((389, False))
        if has_ldaps:
            configs.append((636, True))

        info = None
        for port, use_ssl in configs:
            try:
                tls = ldap3.Tls(validate=ssl.CERT_NONE) if use_ssl else None
                server = Server(self.target, port=port, use_ssl=use_ssl,
                                tls=tls, get_info=ALL, connect_timeout=TIMEOUT)
                conn = Connection(server, auto_bind=True)
                info = server.info
                conn.unbind()
                if info:
                    break
            except Exception:
                continue

        if not info:
            return

        naming_contexts = getattr(info, "naming_contexts", []) or []
        nc0 = str(naming_contexts[0]) if naming_contexts else ""
        domain_name = nc0.replace("DC=", "").replace(",", ".").lstrip(".")
        forest = (getattr(info, "other", {}) or {}).get("rootDomainNamingContext", [""])[0]

        # domainFunctionality: 0=2000, 1=2003, 2=2003interim, 3=2008, 4=2008R2, 5=2012, 6=2012R2, 7=2016+
        func_raw = (getattr(info, "other", {}) or {}).get("domainFunctionality", [""])
        func_str = str(func_raw[0]) if func_raw else ""

        desc = (f"Dominio: {domain_name or '—'} · Naming context: {nc0 or '—'} · Forest: {forest or '—'}.")
        self._add("Active Directory detectado", "AD/LDAP", "INFO", desc,
                  "Restringir acceso LDAP a redes internas mediante firewall.")

        if func_str.isdigit():
            ver = int(func_str)
            win_map = {0: "2000", 1: "2003", 2: "2003 interim", 3: "2008",
                       4: "2008 R2", 5: "2012", 6: "2012 R2", 7: "2016+"}
            win_ver = win_map.get(ver, f"nivel {ver}")
            if ver <= 1:
                self._add(f"Windows Server {win_ver} — sin soporte", "AD/LDAP", "CRITICAL",
                          f"Nivel funcional de dominio {ver} (Windows Server {win_ver}), sin soporte desde hace años.",
                          "Migrar a Windows Server 2019/2022 inmediatamente.")
            elif ver <= 3:
                self._add(f"Windows Server {win_ver} — obsoleto", "AD/LDAP", "HIGH",
                          f"Nivel funcional de dominio {ver} (Windows Server {win_ver}), sin soporte extendido.",
                          "Planificar migración a Windows Server 2019/2022.")

    def _check_ldap_anonymous(self, has_ldap: bool):
        if not has_ldap:
            return
        try:
            server = Server(self.target, port=389, get_info=ALL, connect_timeout=TIMEOUT)
            conn = Connection(server, authentication=ANONYMOUS, auto_bind=True)
            # Intentar búsqueda de usuarios anónimamente
            base_dn = self._get_base_dn(conn)
            conn.search(base_dn, "(objectClass=user)",
                        search_scope=SUBTREE, attributes=["cn"], size_limit=5)
            if conn.entries:
                self._add(
                    "LDAP permite acceso anónimo con enumeración de usuarios",
                    "AD/LDAP", "CRITICAL",
                    f"Un atacante sin credenciales puede enumerar usuarios del dominio via LDAP. "
                    f"Se encontraron {len(conn.entries)} entradas en consulta anónima.",
                    "Deshabilitar el acceso anónimo LDAP en el controlador de dominio: "
                    "GPO → Restricciones de acceso LDAP anónimo."
                )
            else:
                conn.search(base_dn, "(objectClass=*)", search_scope=SUBTREE,
                            attributes=["cn"], size_limit=1)
                if conn.entries:
                    self._add(
                        "LDAP acepta bind anónimo (enumeración limitada)",
                        "AD/LDAP", "MEDIUM",
                        "El servidor LDAP acepta conexiones sin autenticación aunque la enumeración está restringida.",
                        "Configurar 'dsHeuristics' para requerir autenticación en todas las consultas LDAP."
                    )
            conn.unbind()
        except Exception:
            pass

    def _check_smb_signing(self, has_smb: bool):
        if not has_smb:
            return
        result = _smb_signing_check(self.target)
        if result is False:
            self._add(
                "SMB Signing no requerido — riesgo de relay NTLM",
                "SMB/AD", "HIGH",
                "SMB message signing no está configurado como obligatorio. Un atacante en la red "
                "puede realizar ataques de relay NTLM (LLMNR/NBT-NS poisoning) para autenticarse "
                "en otros sistemas con las credenciales capturadas, sin conocer la contraseña.",
                "GPO: 'Microsoft network server: Digitally sign communications (always)' → Enabled. "
                "Aplicar también en clientes."
            )
        elif result is True:
            self._add("SMB Signing requerido", "SMB/AD", "INFO",
                      "SMB signing está configurado como obligatorio. Protegido contra relay NTLM.",
                      "")

    def _check_ldap_signing(self, has_ldap: bool):
        if not has_ldap:
            return
        try:
            server = Server(self.target, port=389, connect_timeout=TIMEOUT)
            # Intentar un bind sin signing — si lo permite, no es requerido
            conn = Connection(server, user=f"test@{self.ad_domain}", password="wrongpass_test_signing")
            conn.bind()
            # Si llegamos aquí sin SSL/signing negociado, el servidor no lo requiere
            self._add(
                "LDAP signing no requerido — riesgo de relay LDAP",
                "AD/LDAP", "MEDIUM",
                "El controlador de dominio no requiere firma (signing) en las comunicaciones LDAP. "
                "Combinado con SMB relay, esto puede permitir a un atacante autenticarse en LDAP "
                "y crear cuentas o modificar ACLs del dominio.",
                "GPO: 'Domain controller: LDAP server signing requirements' → Require signing. "
                "Verificar también que los clientes usen 'Network security: LDAP client signing requirements'."
            )
            conn.unbind()
        except Exception:
            pass

    # ── Checks con credenciales ───────────────────────────────────────────────

    def _connect_auth(self, has_ldap: bool, has_ldaps: bool) -> "Connection | None":
        configs = []
        if has_ldaps:
            configs.append((636, True))
        if has_ldap:
            configs.append((389, False))

        for port, use_ssl in configs:
            for auth_type in (NTLM, SIMPLE):
                try:
                    if auth_type == NTLM:
                        user = f"{self.ad_domain}\\{self.ad_user}"
                    else:
                        user = f"{self.ad_user}@{self.ad_domain}"
                    server = Server(self.target, port=port, use_ssl=use_ssl,
                                    get_info=ALL, connect_timeout=TIMEOUT)
                    conn = Connection(server, user=user, password=self.ad_pass,
                                      authentication=auth_type, auto_bind=True)
                    print(f"  [AD] Autenticación exitosa ({auth_type.__name__ if hasattr(auth_type,'__name__') else auth_type}, port {port})")
                    return conn
                except Exception:
                    continue
        return None

    def _get_base_dn(self, conn: "Connection") -> str:
        try:
            info = conn.server.info
            if info and info.naming_contexts:
                return str(info.naming_contexts[0])
        except Exception:
            pass
        parts = self.ad_domain.split(".")
        return ",".join(f"DC={p}" for p in parts)

    def _check_password_policy(self, conn: "Connection", base_dn: str):
        try:
            conn.search(base_dn, "(objectClass=domainDNS)",
                        search_scope=SUBTREE,
                        attributes=["minPwdLength", "pwdHistoryLength",
                                    "lockoutThreshold", "pwdProperties",
                                    "maxPwdAge", "lockoutDuration"])
            if not conn.entries:
                return
            e = conn.entries[0]

            min_len = int(e.minPwdLength.value or 0)
            history = int(e.pwdHistoryLength.value or 0)
            lockout = int(e.lockoutThreshold.value or 0)
            complexity = bool(int(e.pwdProperties.value or 0) & 1)

            issues = []
            if min_len < 8:
                issues.append(f"longitud mínima de contraseña: {min_len} caracteres (recomendado ≥12)")
            if history < 5:
                issues.append(f"historial de contraseñas: {history} (recomendado ≥10)")
            if lockout == 0:
                issues.append("sin bloqueo de cuenta por intentos fallidos (riesgo de fuerza bruta)")
            if not complexity:
                issues.append("complejidad de contraseña no requerida")

            if issues:
                self._add(
                    "Política de contraseñas AD débil",
                    "AD/Política", "HIGH",
                    "La política de contraseñas del dominio no cumple las recomendaciones mínimas: "
                    + "; ".join(issues) + ".",
                    "GPO: Computer Configuration → Windows Settings → Security Settings → Account Policies. "
                    "Mínimo recomendado: 12 caracteres, complejidad ON, historial 10, bloqueo a 5 intentos."
                )
            else:
                self._add("Política de contraseñas AD correcta", "AD/Política", "INFO",
                          f"Longitud: {min_len}, historial: {history}, bloqueo: {lockout}, complejidad: {complexity}.",
                          "")
        except Exception:
            pass

    def _check_asrep_roasting(self, conn: "Connection", base_dn: str):
        """Busca cuentas con DONT_REQUIRE_PREAUTH activo (AS-REP Roasting)."""
        try:
            conn.search(base_dn,
                        f"(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:={UAC_DONT_REQUIRE_PREAUTH})"
                        f"(!(userAccountControl:1.2.840.113556.1.4.803:={UAC_DISABLED})))",
                        search_scope=SUBTREE,
                        attributes=["sAMAccountName", "distinguishedName"])
            if conn.entries:
                users = [str(e.sAMAccountName) for e in conn.entries]
                self._add(
                    f"AS-REP Roasting — {len(users)} cuenta(s) vulnerable(s)",
                    "AD/Kerberos", "HIGH",
                    f"Las siguientes cuentas no requieren preautenticación Kerberos, lo que permite "
                    f"solicitar un ticket AS-REP y crackearlo offline sin necesidad de conocer la contraseña: "
                    f"{', '.join(users[:10])}{'...' if len(users) > 10 else ''}.",
                    "Habilitar 'Do not require Kerberos preauthentication' solo en cuentas que lo necesiten. "
                    "Audit: Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}."
                )
        except Exception:
            pass

    def _check_kerberoasting(self, conn: "Connection", base_dn: str):
        """Busca cuentas de servicio con SPN (candidatas a Kerberoasting)."""
        try:
            conn.search(base_dn,
                        "(&(objectClass=user)(servicePrincipalName=*)"
                        "(!(objectClass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                        search_scope=SUBTREE,
                        attributes=["sAMAccountName", "servicePrincipalName", "pwdLastSet"])
            if conn.entries:
                svc_accounts = []
                for e in conn.entries:
                    spn_list = e.servicePrincipalName.values if e.servicePrincipalName else []
                    svc_accounts.append(f"{e.sAMAccountName} ({len(spn_list)} SPN)")
                self._add(
                    f"Kerberoasting — {len(conn.entries)} cuenta(s) de servicio con SPN",
                    "AD/Kerberos", "MEDIUM",
                    f"Las cuentas de servicio con SPN permiten a cualquier usuario autenticado solicitar "
                    f"un ticket TGS y crackearlo offline. Cuentas: {', '.join(svc_accounts[:8])}.",
                    "Usar Group Managed Service Accounts (gMSA) — contraseñas de 120 chars rotadas automáticamente. "
                    "Si no es posible, establecer contraseñas largas y aleatorias (>25 chars) en las cuentas de servicio."
                )
        except Exception:
            pass

    def _check_stale_accounts(self, conn: "Connection", base_dn: str):
        """Cuentas activas sin login en más de 90 días."""
        try:
            from datetime import timedelta
            cutoff_dt = datetime.now(timezone.utc) - timedelta(days=90)
            cutoff_ft = int((cutoff_dt - _WIN_EPOCH).total_seconds() * 10_000_000)
            conn.search(base_dn,
                        f"(&(objectClass=user)(!(objectClass=computer))"
                        f"(!(userAccountControl:1.2.840.113556.1.4.803:={UAC_DISABLED}))"
                        f"(lastLogonTimestamp<={cutoff_ft}))",
                        search_scope=SUBTREE,
                        attributes=["sAMAccountName", "lastLogonTimestamp"])
            if conn.entries and len(conn.entries) > 0:
                count = len(conn.entries)
                examples = [str(e.sAMAccountName) for e in conn.entries[:5]]
                self._add(
                    f"Cuentas activas sin uso en más de 90 días — {count} cuenta(s)",
                    "AD/Usuarios", "MEDIUM",
                    f"Existen {count} cuentas de usuario habilitadas que no han iniciado sesión en más de 90 días. "
                    f"Ejemplos: {', '.join(examples)}. "
                    f"Las cuentas abandonadas son un vector de ataque frecuente.",
                    "Deshabilitar o eliminar cuentas inactivas. "
                    "Automatizar con GPO o script: Disable-ADAccount para cuentas sin lastLogon > 90 días."
                )
        except Exception:
            pass

    def _check_privileged_accounts(self, conn: "Connection", base_dn: str):
        """Cuenta el número de Domain Admins y verifica si hay cuentas de servicio en él."""
        try:
            conn.search(base_dn,
                        "(&(objectClass=group)(sAMAccountName=Domain Admins))",
                        search_scope=SUBTREE,
                        attributes=["member"])
            if not conn.entries:
                return
            members = conn.entries[0].member.values if conn.entries[0].member else []
            count = len(members)

            if count > 5:
                self._add(
                    f"Exceso de Domain Admins — {count} miembros",
                    "AD/Privilegios", "HIGH",
                    f"El grupo Domain Admins tiene {count} miembros. Un número elevado aumenta la superficie "
                    f"de ataque: si cualquiera de estas cuentas se ve comprometida, el atacante obtiene "
                    f"control total del dominio.",
                    "Reducir Domain Admins al mínimo imprescindible (1-3 cuentas). "
                    "Usar grupos de administración delegada para tareas específicas."
                )
            else:
                self._add(f"Domain Admins — {count} miembros", "AD/Privilegios", "INFO",
                          f"El grupo Domain Admins tiene {count} miembros, cifra razonable.", "")
        except Exception:
            pass

    def _check_laps(self, conn: "Connection", base_dn: str):
        """Comprueba si LAPS (Local Administrator Password Solution) está desplegado."""
        try:
            conn.search(base_dn,
                        "(objectClass=computer)",
                        search_scope=SUBTREE,
                        attributes=["ms-Mcs-AdmPwd", "cn"],
                        size_limit=5)
            if not conn.entries:
                return
            has_laps = any(
                hasattr(e, "ms-Mcs-AdmPwd") and getattr(e, "ms-Mcs-AdmPwd").value
                for e in conn.entries
            )
            if not has_laps:
                self._add(
                    "LAPS no desplegado — contraseña local admin idéntica en todos los equipos",
                    "AD/Privilegios", "HIGH",
                    "No se detectó LAPS (Local Administrator Password Solution) en los equipos del dominio. "
                    "Si la cuenta de administrador local tiene la misma contraseña en todos los equipos "
                    "(práctica habitual), comprometer un equipo permite moverse lateralmente a todos los demás.",
                    "Desplegar Microsoft LAPS (o Windows LAPS nativo en Server 2022/W11 22H2+). "
                    "Garantiza contraseñas únicas y rotación automática en cada equipo."
                )
        except Exception:
            pass

    # ── Utilidades ────────────────────────────────────────────────────────────

    def _add(self, nombre: str, tipo: str, severidad: str, descripcion: str, recomendacion: str):
        self._findings.append({
            "nombre":        nombre,
            "tipo":          tipo,
            "severidad":     severidad,
            "descripcion":   descripcion,
            "recomendacion": recomendacion,
        })
