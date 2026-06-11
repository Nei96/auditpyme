"""
Módulo OSINT externo — AuditPyme
Recopila información pública sin necesidad de acceso a la red del cliente.
Fuentes: crt.sh, WHOIS, Shodan (opcional), HaveIBeenPwned (opcional).
"""

import socket
import json
import requests
import urllib3
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
TIMEOUT = 20


class OSINTScanner:
    def __init__(self, target: str, shodan_key: str = None, hibp_key: str = None):
        self.target = target
        self.domain = self._extract_domain(target)
        self.shodan_key = shodan_key
        self.hibp_key = hibp_key
        self.findings = []

    def scan(self) -> list:
        print(f"\n  [*] OSINT externo para: {self.target}")

        self._cert_transparency()
        self._whois_info()

        if self.shodan_key:
            self._shodan_scan()
        else:
            print("  [*] Shodan omitido (--shodan-key no proporcionada)")

        if self.hibp_key and self.domain:
            self._hibp_check()
        else:
            print("  [*] HaveIBeenPwned omitido (--hibp-key no proporcionada)")

        self._check_exposed_services()

        return self.findings

    # ── Certificate Transparency (crt.sh) — sin API key ──────────────────────

    def _cert_transparency(self):
        if not self.domain:
            return

        print(f"  [*] Buscando subdominios via Certificate Transparency (crt.sh)...")
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            resp = requests.get(url, timeout=TIMEOUT, headers={"Accept": "application/json"})
            if resp.status_code != 200:
                return

            entries = resp.json()
            subdomains = set()
            for e in entries:
                name = e.get("name_value", "")
                for sub in name.splitlines():
                    sub = sub.strip().lstrip("*.")
                    if sub.endswith(self.domain) and sub != self.domain:
                        subdomains.add(sub)

            if not subdomains:
                print("  [+] No se encontraron subdominios en crt.sh")
                return

            # Verificar cuáles resuelven
            activos = []
            inactivos = []
            for sub in sorted(subdomains)[:50]:
                try:
                    ip = socket.gethostbyname(sub)
                    activos.append(f"{sub} → {ip}")
                except socket.gaierror:
                    inactivos.append(sub)

            print(f"  [CT] {len(activos)} subdominios activos, {len(inactivos)} inactivos")

            if activos:
                self._add("MEDIUM", "SUBDOMINIOS (crt.sh)",
                          f"{len(activos)} subdominios activos encontrados en registros de certificados",
                          f"Subdominios activos:\n" + "\n".join(f"  • {s}" for s in activos[:20]),
                          "Revisar cada subdominio. Los no utilizados deben eliminarse "
                          "(riesgo de subdomain takeover). Verificar que todos tienen certificado válido.")

            if inactivos:
                takeover_risk = [s for s in inactivos if any(
                    kw in s for kw in ["dev", "staging", "test", "old", "beta", "demo", "qa"]
                )]
                if takeover_risk:
                    self._add("HIGH", "SUBDOMAIN TAKEOVER",
                              f"{len(takeover_risk)} subdominios de entorno aparecen en certificados pero no resuelven",
                              f"Subdominios sin DNS activo (riesgo de takeover):\n" +
                              "\n".join(f"  • {s}" for s in takeover_risk),
                              "Eliminar los registros DNS/certificados de subdominios que ya no se usan "
                              "para evitar que terceros los registren y los usen en ataques de phishing.")

        except Exception as e:
            print(f"  [!] Error consultando crt.sh: {e}")

    # ── WHOIS ─────────────────────────────────────────────────────────────────

    def _whois_info(self):
        if not self.domain:
            return

        print(f"  [*] Consultando WHOIS...")
        try:
            import subprocess
            result = subprocess.run(
                ["whois", self.domain],
                capture_output=True, text=True, timeout=15
            )
            output = result.stdout

            info = {}
            for line in output.splitlines():
                line_lower = line.lower()
                if "registrant" in line_lower and ":" in line and not info.get("registrant"):
                    info["registrant"] = line.split(":", 1)[1].strip()
                if "expir" in line_lower and ":" in line and not info.get("expiry"):
                    info["expiry"] = line.split(":", 1)[1].strip()
                if "registrar" in line_lower and ":" in line and not info.get("registrar"):
                    info["registrar"] = line.split(":", 1)[1].strip()
                if ("name server" in line_lower or "nserver" in line_lower) and ":" in line:
                    ns = line.split(":", 1)[1].strip().lower()
                    if ns and "nameservers" not in info:
                        info.setdefault("nameservers", []).append(ns)

            if not info:
                return

            # Comprobar privacidad WHOIS
            registrant = info.get("registrant", "")
            privacy_keywords = ["privacy", "redacted", "withheld", "protect", "private", "gdpr"]
            if any(kw in registrant.lower() for kw in privacy_keywords):
                self._add("INFO", "WHOIS",
                          "Datos WHOIS protegidos por privacidad",
                          f"El registrante usa un servicio de privacidad WHOIS. "
                          f"Registrar: {info.get('registrar', 'N/A')}",
                          "")
                print("  [OK] WHOIS con privacidad activada")
            elif registrant:
                self._add("LOW", "WHOIS",
                          "Datos del registrante expuestos en WHOIS",
                          f"Registrante: {registrant}\nRegistrar: {info.get('registrar', 'N/A')}\n"
                          f"Expiración: {info.get('expiry', 'N/A')}",
                          "Activar protección de privacidad WHOIS en el registrador del dominio "
                          "para no exponer datos personales o corporativos.")
                print(f"  [LOW] WHOIS expone datos del registrante: {registrant[:60]}")

            # Expiración del dominio
            expiry_str = info.get("expiry", "")
            if expiry_str:
                for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d", "%d-%b-%Y", "%Y/%m/%d"):
                    try:
                        expiry_date = datetime.strptime(expiry_str[:19], fmt[:len(expiry_str[:19])])
                        days_left = (expiry_date - datetime.now()).days
                        if days_left < 0:
                            self._add("CRITICAL", "DOMINIO",
                                      "Dominio EXPIRADO",
                                      f"El dominio expiró hace {abs(days_left)} días ({expiry_str}). "
                                      f"Puede ser registrado por terceros.",
                                      "Renovar el dominio inmediatamente.")
                        elif days_left < 30:
                            self._add("HIGH", "DOMINIO",
                                      f"Dominio expira en {days_left} días",
                                      f"El dominio expira el {expiry_str}. Riesgo de pérdida.",
                                      "Renovar el dominio de inmediato.")
                        elif days_left < 90:
                            self._add("MEDIUM", "DOMINIO",
                                      f"Dominio expira en {days_left} días",
                                      f"El dominio expira el {expiry_str}.",
                                      "Planificar la renovación del dominio pronto.")
                        break
                    except Exception:
                        continue

        except Exception as e:
            print(f"  [!] WHOIS no disponible: {e}")

    # ── Shodan (requiere API key) ─────────────────────────────────────────────

    def _shodan_scan(self):
        print(f"  [*] Consultando Shodan...")
        try:
            # Resolver IP del dominio
            target_ip = self.target
            if self.domain:
                try:
                    target_ip = socket.gethostbyname(self.domain)
                except Exception:
                    pass

            resp = requests.get(
                f"https://api.shodan.io/shodan/host/{target_ip}?key={self.shodan_key}",
                timeout=TIMEOUT
            )
            if resp.status_code == 404:
                print(f"  [+] IP {target_ip} no indexada en Shodan")
                return
            if resp.status_code != 200:
                print(f"  [!] Shodan error: {resp.status_code}")
                return

            data = resp.json()
            ports = data.get("ports", [])
            vulns = data.get("vulns", [])
            org = data.get("org", "N/A")
            isp = data.get("isp", "N/A")
            country = data.get("country_name", "N/A")
            hostnames = data.get("hostnames", [])

            print(f"  [Shodan] IP: {target_ip} | Org: {org} | Puertos: {ports}")

            self._add("INFO", "SHODAN",
                      f"Perfil público en Shodan — {len(ports)} puertos indexados",
                      f"IP: {target_ip}\nOrganización: {org}\nISP: {isp}\nPaís: {country}\n"
                      f"Hostnames: {', '.join(hostnames[:5]) or 'N/A'}\n"
                      f"Puertos visibles en internet: {', '.join(str(p) for p in sorted(ports))}",
                      "Revisar que los puertos expuestos son los estrictamente necesarios.")

            if vulns:
                self._add("CRITICAL", "SHODAN — CVEs PÚBLICOS",
                          f"{len(vulns)} CVEs asociados a esta IP en Shodan",
                          f"Vulnerabilidades conocidas públicamente:\n" +
                          "\n".join(f"  • {v}" for v in sorted(vulns)[:15]),
                          "Aplicar parches para los CVEs listados con urgencia. "
                          "Esta información es pública y cualquier atacante puede verla.")

        except Exception as e:
            print(f"  [!] Error Shodan: {e}")

    # ── HaveIBeenPwned ────────────────────────────────────────────────────────

    def _hibp_check(self):
        print(f"  [*] Consultando HaveIBeenPwned para dominio {self.domain}...")
        try:
            resp = requests.get(
                f"https://haveibeenpwned.com/api/v3/breacheddomain/{self.domain}",
                headers={
                    "hibp-api-key": self.hibp_key,
                    "User-Agent": "AuditPyme-SecurityScanner/1.0"
                },
                timeout=TIMEOUT
            )

            if resp.status_code == 404:
                self._add("INFO", "HIBP",
                          "Dominio no encontrado en filtraciones conocidas",
                          f"No se encontraron filtraciones de cuentas de {self.domain} en "
                          f"la base de datos de HaveIBeenPwned.", "")
                print(f"  [OK] Dominio {self.domain} sin filtraciones conocidas")
                return

            if resp.status_code == 200:
                data = resp.json()
                total_cuentas = sum(len(v) for v in data.values()) if isinstance(data, dict) else 0
                brechas = list(data.keys())[:10] if isinstance(data, dict) else []

                self._add("HIGH", "FILTRACIÓN DE DATOS (HIBP)",
                          f"Cuentas del dominio encontradas en {len(brechas)} filtraciones",
                          f"Se encontraron credenciales de empleados/clientes de {self.domain} "
                          f"en filtraciones conocidas:\n" +
                          "\n".join(f"  • {b}" for b in brechas),
                          "Forzar cambio de contraseñas para las cuentas afectadas. "
                          "Activar autenticación en dos factores. "
                          "Revisar si alguna de estas contraseñas filtradas se reutiliza en sistemas internos.")
                print(f"  [HIGH] {len(brechas)} filtraciones con datos del dominio")

        except Exception as e:
            print(f"  [!] Error HIBP: {e}")

    # ── Servicios expuestos innecesariamente ──────────────────────────────────

    def _check_exposed_services(self):
        if not self.domain:
            return

        print("  [*] Comprobando servicios sensibles expuestos públicamente...")
        RISKY_PORTS = {
            21:    ("FTP", "HIGH",    "FTP expuesto — protocolo sin cifrado, credenciales en texto plano."),
            23:    ("Telnet", "CRITICAL", "Telnet expuesto — protocolo completamente inseguro."),
            445:   ("SMB", "CRITICAL", "SMB expuesto a internet — vector principal de ransomware (WannaCry, EternalBlue)."),
            3389:  ("RDP", "HIGH",    "RDP expuesto a internet — objetivo frecuente de ataques de fuerza bruta."),
            3306:  ("MySQL", "CRITICAL","Base de datos MySQL accesible desde internet."),
            5432:  ("PostgreSQL", "CRITICAL", "Base de datos PostgreSQL accesible desde internet."),
            27017: ("MongoDB", "CRITICAL", "MongoDB accesible desde internet — historial de bases de datos sin autenticación."),
            6379:  ("Redis", "CRITICAL", "Redis accesible desde internet — frecuentemente sin autenticación."),
            9200:  ("Elasticsearch", "CRITICAL", "Elasticsearch accesible desde internet."),
            5900:  ("VNC", "HIGH",    "VNC expuesto — acceso remoto al escritorio."),
            8080:  ("HTTP alternativo", "MEDIUM", "Puerto HTTP alternativo expuesto."),
            8443:  ("HTTPS alternativo", "MEDIUM", "Puerto HTTPS alternativo expuesto."),
        }

        try:
            target_ip = socket.gethostbyname(self.domain)
        except Exception:
            return

        # Detectar si hay CDN/WAF por delante (Cloudflare, Akamai, Fastly...)
        behind_cdn = self._detect_cdn(target_ip)
        if behind_cdn:
            print(f"  [INFO] CDN/WAF detectado ({behind_cdn}) — puertos filtrados por el proxy")

        exposed = []
        for port, (service, severity, desc) in RISKY_PORTS.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target_ip, port))
                sock.close()
                if result == 0:
                    if behind_cdn and port in (8080, 8443):
                        continue
                    exposed.append((port, service, severity, desc))
                    print(f"  [{severity}] Puerto {port} ({service}) accesible desde internet")
            except Exception:
                pass

        for port, service, severity, desc in exposed:
            self._add(severity, "SERVICIO EXPUESTO",
                      f"{service} (puerto {port}) accesible desde internet",
                      desc,
                      f"Restringir el acceso al puerto {port} mediante firewall. "
                      f"Solo debe ser accesible desde IPs autorizadas o mediante VPN.")

        if not exposed:
            print("  [OK] No se detectaron servicios críticos expuestos públicamente")

    def _detect_cdn(self, ip: str) -> str:
        """Detecta si la IP pertenece a un CDN/WAF conocido."""
        try:
            hostname = socket.gethostbyaddr(ip)[0].lower()
            if "cloudflare" in hostname:
                return "Cloudflare"
            if "akamai" in hostname or "edgesuite" in hostname:
                return "Akamai"
            if "fastly" in hostname:
                return "Fastly"
            if "amazonaws" in hostname:
                return "AWS CloudFront"
            if "azureedge" in hostname:
                return "Azure CDN"
        except Exception:
            pass
        # Rangos Cloudflare conocidos (simplificado)
        try:
            first_octet = int(ip.split(".")[0])
            second_octet = int(ip.split(".")[1])
            if ip.startswith("104.16.") or ip.startswith("104.17.") or ip.startswith("104.18.") or \
               ip.startswith("104.19.") or ip.startswith("172.64.") or ip.startswith("172.65.") or \
               ip.startswith("162.158.") or ip.startswith("198.41.") or ip.startswith("190.93.") or \
               ip.startswith("188.114.") or ip.startswith("197.234.") or ip.startswith("216.24."):
                return "Cloudflare"
        except Exception:
            pass
        return ""

        if not exposed:
            print("  [OK] No se detectaron servicios críticos expuestos públicamente")

    # ── Utilidades ────────────────────────────────────────────────────────────

    def _add(self, severidad, tipo, nombre, descripcion, recomendacion):
        self.findings.append({
            "severidad":     severidad,
            "tipo":          tipo,
            "nombre":        nombre,
            "descripcion":   descripcion,
            "recomendacion": recomendacion,
        })

    def _extract_domain(self, target: str) -> str:
        try:
            socket.inet_aton(target)
            return None
        except socket.error:
            pass
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        parts = domain.split(".")
        return domain if len(parts) >= 2 else None
