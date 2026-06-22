"""
Módulo de Subdomain Takeover — AuditPyme
Detecta subdominios que apuntan a servicios cloud no reclamados.
"""

import socket
import requests
import urllib3
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
TIMEOUT = 8
UA = "Mozilla/5.0 (compatible; AuditPyme/1.0)"

# Fingerprints de servicios con subdomain takeover conocido
# (cname_pattern, http_fingerprint, service_name, severidad)
TAKEOVER_FINGERPRINTS = [
    # AWS S3
    ("s3.amazonaws.com",         "NoSuchBucket",                    "AWS S3",           "CRITICAL"),
    ("s3-website",               "NoSuchBucket",                    "AWS S3 Website",   "CRITICAL"),
    ("amazonaws.com",            "The specified bucket does not exist", "AWS S3",        "CRITICAL"),
    # GitHub Pages
    ("github.io",                "There isn't a GitHub Pages site here", "GitHub Pages", "HIGH"),
    ("githubusercontent.com",    "There isn't a GitHub Pages site here", "GitHub Pages", "HIGH"),
    # Heroku
    ("herokussl.com",            "No such app",                     "Heroku",           "HIGH"),
    ("herokudns.com",            "No such app",                     "Heroku",           "HIGH"),
    ("herokuapp.com",            "No such app",                     "Heroku",           "HIGH"),
    # Netlify
    ("netlify.com",              "Not found",                       "Netlify",          "HIGH"),
    ("netlify.app",              "Not found",                       "Netlify",          "HIGH"),
    # Vercel
    ("vercel.app",               "The deployment could not be found","Vercel",           "HIGH"),
    ("now.sh",                   "The deployment could not be found","Vercel",           "HIGH"),
    # Azure
    ("azurewebsites.net",        "404 Web Site not found",          "Azure Web App",    "HIGH"),
    ("cloudapp.net",             "404 Web Site not found",          "Azure Cloud App",  "HIGH"),
    ("blob.core.windows.net",    "BlobNotFound",                    "Azure Blob",       "CRITICAL"),
    ("azure-api.net",            "Gateway not found",               "Azure API",        "HIGH"),
    # Shopify
    ("myshopify.com",            "Sorry, this shop is currently unavailable", "Shopify", "MEDIUM"),
    # Ghost
    ("ghost.io",                 "Domain not configured",           "Ghost",            "MEDIUM"),
    # Tumblr
    ("tumblr.com",               "There's nothing here",            "Tumblr",           "MEDIUM"),
    # WordPress.com
    ("wordpress.com",            "Do you want to register",         "WordPress.com",    "MEDIUM"),
    # Cargo
    ("cargocollective.com",      "404 Not Found",                   "Cargo",            "MEDIUM"),
    # Fastly
    ("fastly.net",               "Fastly error: unknown domain",    "Fastly CDN",       "HIGH"),
    # Pantheon
    ("pantheonsite.io",          "The gods are wise",               "Pantheon",         "MEDIUM"),
    # ReadMe
    ("readme.io",                "Project doesnt exist",            "ReadMe",           "MEDIUM"),
    # Zendesk
    ("zendesk.com",              "Help Center Closed",              "Zendesk",          "MEDIUM"),
    # Freshdesk
    ("freshdesk.com",            "There is no helpdesk",            "Freshdesk",        "MEDIUM"),
    # DigitalOcean Spaces
    ("digitaloceanspaces.com",   "NoSuchBucket",                    "DigitalOcean Spaces","CRITICAL"),
    # Surge.sh
    ("surge.sh",                 "project not found",               "Surge.sh",         "HIGH"),
    # Webflow
    ("webflow.io",               "The page you are looking for doesn't exist", "Webflow","MEDIUM"),
    # LaunchRock
    ("launchrock.com",           "It looks like you may have taken",  "LaunchRock",     "MEDIUM"),
    # HubSpot
    ("hs-sites.com",             "does not exist",                  "HubSpot",          "MEDIUM"),
    # Unbounce
    ("unbouncepages.com",        "The requested URL was not found", "Unbounce",         "MEDIUM"),
]

# Subdominios comunes a probar si no hay lista del DNS scanner
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "imap",
    "api", "api2", "dev", "staging", "test", "uat",
    "blog", "shop", "store", "cdn", "static", "media", "assets",
    "app", "portal", "admin", "panel", "dashboard",
    "beta", "demo", "preview", "old", "new",
    "docs", "help", "support", "status",
    "m", "mobile", "wap",
    "vpn", "remote", "intranet",
    "ns1", "ns2", "mx", "mx1", "mx2",
    "img", "images", "video", "download", "uploads",
    "git", "gitlab", "jenkins", "jira", "confluence",
    "backup", "bak", "tmp",
]


class SubdomainTakeoverScanner:

    def __init__(self, target: str, recon_data: dict = None, dns_findings: list = None):
        self.target = target
        self.recon_data = recon_data or {}
        self.dns_findings = dns_findings or []
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA})
        self.session.verify = False
        self._base_domain = self._extract_base_domain(target)

    def scan(self) -> list:
        print(f"\n  [*] Subdomain Takeover scan: {self.target}")
        subdomains = self._collect_subdomains()
        print(f"  [*] {len(subdomains)} subdominios a verificar")

        for subdomain in subdomains:
            self._check_takeover(subdomain)

        if not self.findings:
            print("  [OK] No se detectaron subdominios vulnerables a takeover")
        return self.findings

    def _collect_subdomains(self) -> list:
        """Reúne subdominios de DNS findings y genera lista común."""
        subdomains = set()

        # Extraer de findings DNS existentes
        for f in self.dns_findings:
            desc = f.get("descripcion", "") + " " + f.get("nombre", "")
            for m in re.finditer(r'([a-zA-Z0-9_\-]+\.' + re.escape(self._base_domain) + r')', desc):
                sub = m.group(1).lower()
                if sub != self._base_domain:
                    subdomains.add(sub)

        # Generar subdominios comunes
        for prefix in COMMON_SUBDOMAINS:
            subdomains.add(f"{prefix}.{self._base_domain}")

        return list(subdomains)

    def _check_takeover(self, subdomain: str):
        """Verifica si el subdominio apunta a un servicio no reclamado."""
        # Resolver CNAME
        cname = self._resolve_cname(subdomain)
        if not cname:
            return

        # Buscar fingerprint matching
        for cname_pattern, http_fp, service, sev in TAKEOVER_FINGERPRINTS:
            if cname_pattern.lower() in cname.lower():
                # Confirmar via HTTP
                confirmed = self._confirm_via_http(subdomain, http_fp)
                if confirmed:
                    self._add(
                        sev,
                        f"Subdomain Takeover — {subdomain} ({service})",
                        f"El subdominio {subdomain} tiene CNAME → {cname} "
                        f"({service}) pero el recurso no está reclamado. "
                        f"Fingerprint de confirmación encontrada: '{http_fp[:60]}'",
                        f"Un atacante puede registrar el recurso en {service} "
                        f"y servir contenido arbitrario desde {subdomain}. "
                        f"Esto permite: phishing desde dominio legítimo, robo de cookies "
                        f"del dominio principal (si SameSite no está configurado), "
                        f"bypass de CSP, y ataques de confianza sobre usuarios.",
                        f"Eliminar el registro DNS de {subdomain} si el servicio ya no se usa. "
                        f"Si se necesita, reclamar el recurso en {service} inmediatamente. "
                        f"Auditar regularmente los registros DNS para detectar CNAMEs huérfanos."
                    )
                    print(f"  [CRITICAL] Subdomain takeover: {subdomain} → {cname} ({service})")
                    return

    def _resolve_cname(self, subdomain: str) -> str:
        """Resuelve el CNAME de un subdominio."""
        try:
            import subprocess
            result = subprocess.run(
                ["dig", "+short", "CNAME", subdomain],
                capture_output=True, text=True, timeout=5
            )
            cname = result.stdout.strip().rstrip(".")
            if cname and cname != subdomain:
                return cname
        except Exception:
            pass

        try:
            answers = socket.getaddrinfo(subdomain, None)
            return subdomain
        except Exception:
            pass
        return ""

    def _confirm_via_http(self, subdomain: str, fingerprint: str) -> bool:
        """Confirma el takeover haciendo una petición HTTP al subdominio."""
        for proto in ("https", "http"):
            url = f"{proto}://{subdomain}"
            try:
                r = self.session.get(url, timeout=TIMEOUT, allow_redirects=True)
                if fingerprint.lower() in r.text.lower():
                    return True
            except Exception:
                pass
        return False

    def _extract_base_domain(self, target: str) -> str:
        parts = target.rstrip(".").split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return target

    def _add(self, severidad, nombre, descripcion, impacto, recomendacion):
        for f in self.findings:
            if f["nombre"] == nombre:
                return
        self.findings.append({
            "severidad": severidad, "tipo": "Subdomain Takeover",
            "nombre": nombre, "descripcion": descripcion,
            "impacto": impacto, "recomendacion": recomendacion,
        })
