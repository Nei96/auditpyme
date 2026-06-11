"""
Módulo de enumeración DNS
Comprueba: registros A/MX/NS/TXT, transferencia de zona, SPF, DMARC
y subdominios comunes. Requiere dnspython.
"""

import socket


# Subdominios comunes a probar
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
    "remote", "vpn", "rdp", "ssh", "admin", "portal", "panel",
    "api", "dev", "staging", "test", "qa", "beta", "demo",
    "app", "apps", "mobile", "web", "secure", "login",
    "ns1", "ns2", "dns", "mx", "mx1", "mx2",
    "intranet", "internal", "corp", "citrix",
    "backup", "db", "database", "sql", "mysql", "oracle",
    "monitor", "nagios", "grafana", "kibana", "jenkins",
    "gitlab", "github", "jira", "confluence", "wiki",
    "shop", "store", "pay", "payment", "billing",
    "cdn", "static", "assets", "media", "img",
    "old", "legacy", "v1", "v2", "new",
]


class DNSEnumerator:
    def __init__(self, target: str):
        self.target = target
        self.domain = self._extract_domain(target)
        self.findings = []

    def enumerate(self) -> list:
        if not self.domain:
            print("  [*] El objetivo es una IP — omitiendo enumeración DNS.")
            return []

        try:
            import dns.resolver
            import dns.zone
            import dns.query
            import dns.exception
        except ImportError:
            print("  [!] dnspython no instalado — omitiendo DNS. pip3 install dnspython")
            return []

        print(f"\n  [*] Enumerando DNS para: {self.domain}")

        self._get_records(dns)
        self._check_zone_transfer(dns)
        self._check_spf_dmarc(dns)
        self._brute_subdomains()

        return self.findings

    # ── Registros principales ─────────────────────────────────────────────────

    def _get_records(self, dns):
        import dns.resolver
        import dns.exception

        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "SOA"):
            try:
                answers = dns.resolver.resolve(self.domain, rtype, lifetime=5)
                values = [str(r) for r in answers]
                print(f"  [DNS] {rtype}: {', '.join(values[:5])}")
                self.findings.append({
                    "tipo": "REGISTRO DNS",
                    "nombre": f"{rtype} records",
                    "descripcion": f"{rtype}: {', '.join(values[:5])}",
                    "severidad": "INFO",
                    "recomendacion": "",
                })
            except (dns.exception.DNSException, Exception):
                pass

    # ── Transferencia de zona ─────────────────────────────────────────────────

    def _check_zone_transfer(self, dns):
        import dns.resolver
        import dns.zone
        import dns.query
        import dns.exception

        try:
            ns_records = dns.resolver.resolve(self.domain, "NS", lifetime=5)
            nameservers = [str(ns).rstrip(".") for ns in ns_records]
        except Exception:
            return

        for ns in nameservers:
            try:
                ns_ip = socket.gethostbyname(ns)
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, self.domain, timeout=8))
                names = [str(n) for n in zone.nodes.keys()]
                print(f"  [!!!] TRANSFERENCIA DE ZONA exitosa en {ns} — {len(names)} registros")
                self.findings.append({
                    "tipo": "TRANSFERENCIA DE ZONA",
                    "nombre": f"AXFR permitido en {ns}",
                    "descripcion": f"El servidor DNS {ns} permite transferencia de zona. "
                                   f"Se obtuvieron {len(names)} registros: {', '.join(names[:10])}",
                    "severidad": "CRITICAL",
                    "recomendacion": "Restringir las transferencias de zona (AXFR) solo a servidores DNS secundarios autorizados.",
                })
            except Exception:
                print(f"  [OK] {ns} rechaza transferencia de zona")

    # ── SPF y DMARC ───────────────────────────────────────────────────────────

    def _check_spf_dmarc(self, dns):
        import dns.resolver
        import dns.exception

        # SPF
        spf_found = False
        try:
            answers = dns.resolver.resolve(self.domain, "TXT", lifetime=5)
            for r in answers:
                txt = str(r).strip('"')
                if txt.startswith("v=spf1"):
                    spf_found = True
                    print(f"  [SPF] {txt[:100]}")
                    if "~all" in txt:
                        self.findings.append({
                            "tipo": "SPF",
                            "nombre": "SPF con modo softfail (~all)",
                            "descripcion": "El registro SPF usa ~all (softfail) — no bloquea emails spoofing de forma estricta.",
                            "severidad": "LOW",
                            "recomendacion": "Cambiar ~all por -all para rechazar emails no autorizados.",
                        })
                    elif "+all" in txt:
                        self.findings.append({
                            "tipo": "SPF",
                            "nombre": "SPF con +all — cualquier servidor puede enviar",
                            "descripcion": "El registro SPF usa +all, lo que permite a cualquier servidor enviar como este dominio.",
                            "severidad": "HIGH",
                            "recomendacion": "Cambiar +all por -all de inmediato.",
                        })
                    break
        except Exception:
            pass

        if not spf_found:
            self.findings.append({
                "tipo": "SPF",
                "nombre": "Registro SPF ausente",
                "descripcion": "No se encontró registro SPF — el dominio es vulnerable a email spoofing.",
                "severidad": "MEDIUM",
                "recomendacion": "Crear un registro TXT con la política SPF del dominio.",
            })
            print("  [WARN] SPF no configurado")

        # DMARC
        dmarc_found = False
        try:
            answers = dns.resolver.resolve(f"_dmarc.{self.domain}", "TXT", lifetime=5)
            for r in answers:
                txt = str(r).strip('"')
                if txt.startswith("v=DMARC1"):
                    dmarc_found = True
                    print(f"  [DMARC] {txt[:100]}")
                    if "p=none" in txt:
                        self.findings.append({
                            "tipo": "DMARC",
                            "nombre": "DMARC en modo monitor (p=none)",
                            "descripcion": "DMARC configurado en p=none — solo monitoriza, no bloquea.",
                            "severidad": "LOW",
                            "recomendacion": "Cambiar a p=quarantine o p=reject para protección efectiva.",
                        })
                    break
        except Exception:
            pass

        if not dmarc_found:
            self.findings.append({
                "tipo": "DMARC",
                "nombre": "Registro DMARC ausente",
                "descripcion": "No se encontró registro DMARC — el dominio es vulnerable a phishing y spoofing.",
                "severidad": "MEDIUM",
                "recomendacion": "Crear registro _dmarc con al menos p=quarantine.",
            })
            print("  [WARN] DMARC no configurado")

    # ── Fuerza bruta de subdominios ───────────────────────────────────────────

    def _brute_subdomains(self):
        print(f"  [*] Buscando subdominios ({len(COMMON_SUBDOMAINS)} candidatos)...")
        encontrados = []

        for sub in COMMON_SUBDOMAINS:
            fqdn = f"{sub}.{self.domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                encontrados.append((fqdn, ip))
                print(f"  [SUB] {fqdn} → {ip}")
            except socket.gaierror:
                pass

        if encontrados:
            lista = ", ".join(f"{fqdn} ({ip})" for fqdn, ip in encontrados[:20])
            self.findings.append({
                "tipo": "SUBDOMINIOS",
                "nombre": f"{len(encontrados)} subdominios encontrados",
                "descripcion": lista,
                "severidad": "INFO",
                "recomendacion": "Revisar cada subdominio — los no usados deben ser eliminados (subdomain takeover).",
            })
        else:
            print("  [+] No se encontraron subdominios comunes.")

    # ── Utilidades ─────────────────────────────────────────────────────────────

    def _extract_domain(self, target: str) -> str:
        """Devuelve el dominio si el objetivo es un hostname, None si es una IP."""
        try:
            socket.inet_aton(target)
            return None  # Es una IP
        except socket.error:
            pass
        # Limpiar protocolo si lo incluyeron
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        # Extraer dominio base (últimas 2 partes)
        parts = domain.split(".")
        if len(parts) >= 2:
            return domain
        return None
