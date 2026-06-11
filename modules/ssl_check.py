"""
Módulo de análisis SSL/TLS
Comprueba versión TLS, fecha de expiración, cifrados débiles y validez del certificado.
Usa el módulo ssl de la stdlib — sin dependencias externas.
"""

import ssl
import socket
from datetime import datetime, timezone


# Versiones consideradas inseguras
WEAK_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

# Cifrados considerados débiles (substrings en el nombre del cipher)
WEAK_CIPHER_KEYWORDS = [
    "RC4", "DES", "3DES", "EXPORT", "NULL", "ANON", "MD5",
    "RC2", "IDEA", "SEED", "CAMELLIA_128",
]

TIMEOUT = 5


class SSLChecker:
    def __init__(self, target: str, recon_data: dict):
        self.target = target
        self.recon_data = recon_data
        self.findings = []

    def check(self) -> list:
        ssl_ports = self._find_ssl_ports()
        if not ssl_ports:
            print("  [*] No se detectaron puertos SSL/TLS.")
            return []

        for ip, port, hostname in ssl_ports:
            print(f"\n  [*] Analizando SSL/TLS en {ip}:{port}")
            self._analyze(ip, port, hostname)

        return self.findings

    def _find_ssl_ports(self) -> list:
        ports = []
        for host in self.recon_data.get("hosts", []):
            if host["estado"] != "up":
                continue
            ip = host["ip"]
            hostname = host["hostname"] if host["hostname"] != ip else ip
            for p in host["puertos"]:
                svc = p["servicio"].lower()
                port = p["puerto"]
                if "https" in svc or "ssl" in svc or "tls" in svc or port in (443, 8443, 465, 993, 995, 636):
                    ports.append((ip, port, hostname))
        return ports

    def _analyze(self, ip: str, port: int, hostname: str):
        # ── Obtener certificado y conexión con TLS por defecto ────────────────
        cert_info = self._get_cert(ip, port, hostname)
        if not cert_info:
            print(f"  [!] No se pudo establecer conexión SSL con {ip}:{port}")
            return

        cert, tls_version, cipher_name = cert_info
        print(f"  [+] Versión TLS: {tls_version}")
        print(f"  [+] Cipher: {cipher_name}")

        # ── Check versión TLS ─────────────────────────────────────────────────
        if tls_version in WEAK_VERSIONS:
            self._add(ip, port, f"Versión TLS débil: {tls_version}",
                      f"El servidor negoció {tls_version}, considerado inseguro.",
                      "HIGH",
                      "Deshabilitar versiones TLS < 1.2 en la configuración del servidor.")
        else:
            print(f"  [OK] Versión TLS aceptable ({tls_version})")

        # ── Check versiones antiguas por separado ─────────────────────────────
        for weak_ver in ("TLSv1", "TLSv1.1"):
            self._probe_weak_version(ip, port, hostname, weak_ver)

        # ── Check cipher débil ────────────────────────────────────────────────
        for kw in WEAK_CIPHER_KEYWORDS:
            if kw in cipher_name.upper():
                self._add(ip, port, f"Cipher débil: {cipher_name}",
                          f"El servidor usa el cipher {cipher_name} considerado inseguro.",
                          "HIGH",
                          "Configurar la lista de cifrados del servidor para excluir RC4, DES, 3DES y EXPORT.")
                print(f"  [WARN] Cipher débil detectado: {cipher_name}")
                break

        # ── Check certificado ─────────────────────────────────────────────────
        self._check_cert(ip, port, cert, hostname)

    def _get_cert(self, ip: str, port: int, hostname: str):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((ip, port), timeout=TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    version = ssock.version()
                    cipher = ssock.cipher()[0] if ssock.cipher() else "Desconocido"
                    return cert, version, cipher
        except Exception as e:
            print(f"  [!] Error SSL: {e}")
            return None

    def _probe_weak_version(self, ip: str, port: int, hostname: str, version_str: str):
        """Intenta forzar una versión TLS antigua para ver si el servidor la acepta."""
        import signal

        def _timeout_handler(signum, frame):
            raise TimeoutError("SSL probe timeout")

        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            ver_map = {
                "TLSv1":   ssl.TLSVersion.TLSv1,
                "TLSv1.1": ssl.TLSVersion.TLSv1_1,
            }
            if version_str not in ver_map:
                return

            ctx.maximum_version = ver_map[version_str]
            ctx.minimum_version = ver_map[version_str]

            signal.signal(signal.SIGALRM, _timeout_handler)
            signal.alarm(TIMEOUT + 2)
            try:
                with socket.create_connection((ip, port), timeout=TIMEOUT) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname):
                        self._add(ip, port, f"Versión TLS débil soportada: {version_str}",
                                  f"El servidor acepta conexiones {version_str}.",
                                  "HIGH",
                                  f"Deshabilitar {version_str} en la configuración TLS del servidor.")
                        print(f"  [WARN] Servidor acepta {version_str}")
            finally:
                signal.alarm(0)
        except ssl.SSLError:
            print(f"  [OK] Servidor rechaza {version_str}")
        except (AttributeError, TimeoutError):
            pass
        except Exception:
            pass

    def _check_cert(self, ip: str, port: int, cert: dict, hostname: str):
        if not cert:
            self._add(ip, port, "Certificado no obtenido",
                      "No se pudo obtener el certificado del servidor.",
                      "MEDIUM", "Verificar la configuración SSL del servidor.")
            return

        # ── Expiración ────────────────────────────────────────────────────────
        not_after = cert.get("notAfter", "")
        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                expiry = expiry.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_left = (expiry - now).days
                print(f"  [+] Cert expira: {not_after} ({days_left} días)")

                if days_left < 0:
                    self._add(ip, port, "Certificado EXPIRADO",
                              f"El certificado expiró hace {abs(days_left)} días ({not_after}).",
                              "CRITICAL",
                              "Renovar el certificado SSL/TLS inmediatamente.")
                elif days_left < 30:
                    self._add(ip, port, "Certificado próximo a expirar",
                              f"El certificado expira en {days_left} días ({not_after}).",
                              "HIGH",
                              "Renovar el certificado SSL/TLS antes de la expiración.")
                elif days_left < 90:
                    self._add(ip, port, "Certificado vence en menos de 90 días",
                              f"Expira en {days_left} días ({not_after}).",
                              "LOW",
                              "Planificar la renovación del certificado pronto.")
            except Exception:
                pass

        # ── Autofirmado ───────────────────────────────────────────────────────
        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        if issuer == subject:
            self._add(ip, port, "Certificado autofirmado",
                      "El certificado está autofirmado — no validado por una CA de confianza.",
                      "MEDIUM",
                      "Obtener un certificado firmado por una CA reconocida (ej: Let's Encrypt).")
            print("  [WARN] Certificado autofirmado")

        # ── CN vs hostname ────────────────────────────────────────────────────
        cn = subject.get("commonName", "")
        san_list = [v for _, v in cert.get("subjectAltName", [])]
        all_names = san_list or ([cn] if cn else [])

        if hostname and not any(self._match_hostname(hostname, name) for name in all_names):
            self._add(ip, port, "Mismatch de hostname",
                      f"El hostname '{hostname}' no coincide con el CN/SAN del certificado: {all_names[:5]}",
                      "MEDIUM",
                      "Obtener un certificado válido para el hostname correcto.")
            print(f"  [WARN] Hostname mismatch — cert: {all_names[:3]}")
        else:
            print(f"  [OK] Hostname coincide con el certificado")

    def _match_hostname(self, hostname: str, pattern: str) -> bool:
        if pattern.startswith("*."):
            suffix = pattern[2:]
            return hostname.endswith("." + suffix) or hostname == suffix
        return hostname == pattern

    def _add(self, ip, port, nombre, descripcion, severidad, recomendacion):
        self.findings.append({
            "ip": ip, "puerto": port,
            "nombre": nombre,
            "descripcion": descripcion,
            "severidad": severidad,
            "recomendacion": recomendacion,
        })
        print(f"  [{severidad}] {nombre}")
