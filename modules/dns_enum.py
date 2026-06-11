"""
Módulo de enumeración DNS
Comprueba: registros A/MX/NS/TXT, transferencia de zona, SPF, DMARC,
subdominios comunes y subdomain takeover via CNAME dangling + HTTP fingerprints.
"""

import socket
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
TIMEOUT = 8
UA = "Mozilla/5.0 (compatible; AuditPyme/1.0)"


# Fingerprints de servicios cloud que indican subdominio sin reclamar
# Formato: (cadena_en_body, nombre_servicio)
TAKEOVER_FINGERPRINTS = [
    ("There isn't a GitHub Pages site here",    "GitHub Pages"),
    ("For root URLs (like http://www.example.com/) you can only use",  "GitHub Pages"),
    ("No such app",                              "Heroku"),
    ("herokucdn.com/error-pages/no-such-app",   "Heroku"),
    ("NoSuchBucket",                             "Amazon S3"),
    ("The specified bucket does not exist",      "Amazon S3"),
    ("NoSuchKey",                                "Amazon S3"),
    ("404 Web Site not found",                   "Azure Web App"),
    ("ErrorCode: DomainNotFound",               "Azure"),
    ("Fastly error: unknown domain",             "Fastly CDN"),
    ("Sorry, this shop is currently unavailable","Shopify"),
    ("project not found",                        "Surge.sh"),
    ("The gods are wise, but do not know",       "Pantheon"),
    ("You are being redirected",                 "StatusPage.io"),
    ("Help Center Closed",                       "Zendesk"),
    ("This UserVoice subdomain is currently available", "UserVoice"),
    ("This page is reserved for future",         "Tave"),
    ("Double check the URL",                     "Campaign Monitor"),
    ("Uh oh. The page you requested could not be found", "Mailchimp"),
    ("There's nothing here",                     "Tumblr"),
    ("Domain not configured",                    "Ghost"),
    ("does not exist",                           "HubSpot"),
    ("Uh oh. That page doesn't exist",           "Intercom"),
    ("We could not find what you're looking for","Helpjuice"),
    ("Sorry, We Couldn't Find That Page",        "Desk.com"),
    ("It looks like you may have taken a wrong turn", "LaunchRock"),
]

# CNAMEs de servicios cloud (si el destino no resuelve → takeover posible)
CLOUD_CNAME_PATTERNS = [
    "github.io", "githubapp.com",
    "herokussl.com", "herokuapp.com",
    "s3.amazonaws.com", "s3-website",
    "azurewebsites.net", "cloudapp.net", "azure.com",
    "fastly.net",
    "shopify.com",
    "surge.sh",
    "pantheonsite.io",
    "statuspage.io", "stspg-customer.com",
    "zendesk.com",
    "uservoice.com",
    "mailchimp.com",
    "tumblr.com",
    "ghost.io",
    "hubspot.com", "hs-sites.com",
    "intercom.io",
    "helpjuice.com",
    "netlify.app", "netlify.com",
    "pages.dev",           # Cloudflare Pages
    "vercel.app",
    "render.com",
    "fly.dev",
    "readthedocs.io",
    "launchrock.com",
    "cargo.site",
]

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
        subdomains = self._brute_subdomains()
        self._check_takeover(dns, subdomains)

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

    def _brute_subdomains(self) -> list:
        """Resuelve subdominios comunes. Devuelve lista de FQDNs encontrados."""
        print(f"  [*] Buscando subdominios ({len(COMMON_SUBDOMAINS)} candidatos)...")
        encontrados = []

        for sub in COMMON_SUBDOMAINS:
            fqdn = f"{sub}.{self.domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                encontrados.append(fqdn)
                print(f"  [SUB] {fqdn} → {ip}")
            except socket.gaierror:
                pass

        if encontrados:
            lista = ", ".join(encontrados[:20])
            self.findings.append({
                "tipo": "SUBDOMINIOS",
                "nombre": f"{len(encontrados)} subdominios encontrados",
                "descripcion": lista,
                "severidad": "INFO",
                "recomendacion": "Revisar cada subdominio — los no usados deben ser eliminados.",
            })
        else:
            print("  [+] No se encontraron subdominios comunes.")
        return encontrados

    # ── Subdomain Takeover ────────────────────────────────────────────────────

    def _check_takeover(self, dns, subdomains: list):
        """
        Detecta subdomain takeover por dos vías:
        1. CNAME dangling: subdominio apunta vía CNAME a servicio cloud que no resuelve.
        2. HTTP fingerprint: subdominio resuelve pero el servicio cloud no está reclamado.
        También evalúa subdominios que NO resolvieron (NXDOMAIN con CNAME activo).
        """
        import dns.resolver
        import dns.exception

        print(f"  [*] Comprobando subdomain takeover ({len(COMMON_SUBDOMAINS)} candidatos)...")
        vulnerables = 0

        all_candidates = list(COMMON_SUBDOMAINS)  # probar todos, resuelvan o no
        for sub in all_candidates:
            fqdn = f"{sub}.{self.domain}"
            cname_target = self._get_cname(dns, fqdn)
            if not cname_target:
                continue  # Sin CNAME → no aplica

            # ¿El CNAME apunta a un servicio cloud conocido?
            cloud_service = next(
                (svc for pat, svc in [
                    (p, p.split(".")[0].capitalize()) for p in CLOUD_CNAME_PATTERNS
                ] if pat in cname_target),
                None
            )
            if not cloud_service:
                # Buscar con nombre más descriptivo
                for pat in CLOUD_CNAME_PATTERNS:
                    if pat in cname_target:
                        cloud_service = pat
                        break
            if not cloud_service:
                continue

            # Vector 1: ¿El destino del CNAME resuelve?
            try:
                socket.gethostbyname(cname_target.rstrip("."))
                cname_resuelve = True
            except socket.gaierror:
                cname_resuelve = False

            if not cname_resuelve:
                self._add_takeover(fqdn, cname_target, cloud_service,
                                   "CNAME dangling — el servicio cloud fue eliminado")
                vulnerables += 1
                continue

            # Vector 2: HTTP fingerprint — servicio activo pero no reclamado
            for proto in ("https", "http"):
                try:
                    r = requests.get(
                        f"{proto}://{fqdn}",
                        timeout=TIMEOUT,
                        verify=False,
                        allow_redirects=True,
                        headers={"User-Agent": UA},
                    )
                    body = r.text
                    for fingerprint, servicio in TAKEOVER_FINGERPRINTS:
                        if fingerprint.lower() in body.lower():
                            self._add_takeover(fqdn, cname_target, servicio,
                                               f"Página de '{servicio}' sin reclamar detectada")
                            vulnerables += 1
                            break
                    break  # Si https funcionó no probar http
                except Exception:
                    continue

        if vulnerables == 0:
            print("  [OK] No se detectaron subdominios con riesgo de takeover")

    def _get_cname(self, dns, fqdn: str) -> str | None:
        """Devuelve el destino del registro CNAME si existe, o None."""
        try:
            answers = dns.resolver.resolve(fqdn, "CNAME", lifetime=4)
            return str(answers[0].target)
        except Exception:
            return None

    def _add_takeover(self, fqdn: str, cname: str, servicio: str, motivo: str):
        nombre = f"Subdomain Takeover posible: {fqdn}"
        for f in self.findings:
            if f.get("nombre") == nombre:
                return
        print(f"  [CRITICAL] Takeover en {fqdn} → {cname} ({servicio})")
        self.findings.append({
            "tipo": "SUBDOMAIN TAKEOVER",
            "nombre": nombre,
            "descripcion": (
                f"{motivo}. El subdominio '{fqdn}' apunta mediante CNAME a '{cname}' "
                f"({servicio}), pero ese recurso ya no está activo o no está reclamado. "
                f"Cualquier atacante puede registrar ese recurso en {servicio} y "
                f"servir contenido malicioso desde un subdominio oficial de la empresa."
            ),
            "severidad": "CRITICAL",
            "recomendacion": (
                f"Eliminar el registro CNAME '{fqdn}' del DNS de forma urgente, o "
                f"registrar el recurso en {servicio} para reclamarlo. "
                f"El subdominio no debe existir en DNS si el servicio ya no se usa."
            ),
        })

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
