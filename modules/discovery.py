"""
Módulo de descubrimiento inteligente de sitio web.
Analiza el objetivo para detectar qué funcionalidades existen
y auto-omitir módulos irrelevantes.
"""

import re
import warnings
import requests
from urllib.parse import urljoin

warnings.filterwarnings("ignore")

TIMEOUT = 8

ECOMMERCE_SIGNALS = [
    "woocommerce", "add-to-cart", "addtocart", "wc-cart", "wc-checkout",
    "prestashop", "opencart", "magento", "mage-cache",
    "checkout", "carrito", "cesta de la compra", "shopping-cart",
    "precio", "precio_unitario", "buy-now", "comprar ahora",
    "product-price", "product_price", "cart-icon",
]

LOGIN_PATHS = [
    "/login", "/login.php", "/login.aspx", "/signin",
    "/wp-login.php", "/admin/login", "/administrator/",
    "/acceso", "/entrar", "/user/login", "/cuenta/login",
    "/auth/login", "/panel", "/cp",
]

GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/wp/graphql",
    "/gql", "/query", "/index.php?graphql",
]

API_PATHS = [
    "/api/", "/api/v1/", "/api/v2/",
    "/wp-json/", "/rest/", "/v1/", "/v2/",
]

UPLOAD_PATHS_TO_CHECK = [
    "/upload", "/uploads", "/media/upload", "/files/upload",
    "/wp-admin/media-new.php", "/admin/upload",
]


class SiteDiscovery:
    def __init__(self, target: str, recon_data: dict):
        self.target = target
        self.recon_data = recon_data
        self.session = requests.Session()
        self.session.headers["User-Agent"] = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
        )
        self.base_urls = self._build_base_urls()
        self.profile = {
            "cms":              None,
            "has_login":        False,
            "login_urls":       [],
            "has_file_upload":  False,
            "upload_urls":      [],
            "has_ecommerce":    False,
            "has_graphql":      False,
            "graphql_urls":     [],
            "has_rest_api":     False,
            "api_urls":         [],
            "has_forms":        False,
            "js_files_count":   0,
            "technologies":     [],
        }

    def discover(self) -> dict:
        if not self.base_urls:
            print("  [!] No se encontraron URLs web para analizar")
            return self.profile

        print(f"  [*] Descubriendo funcionalidades en: {self.target}")
        for base_url in self.base_urls[:2]:
            self._analyze_base(base_url)

        self._print_profile()
        return self.profile

    # ── construcción de URLs ──────────────────────────────────────────────────

    def _build_base_urls(self) -> list:
        urls = []
        for host in self.recon_data.get("hosts", []):
            if host["estado"] != "up":
                continue
            for p in host["puertos"]:
                port = p["puerto"]
                svc  = p["servicio"].lower()
                if "http" in svc or port in (80, 443, 8080, 8443):
                    proto = "https" if port in (443, 8443) else "http"
                    base  = (f"{proto}://{self.target}"
                             if port in (80, 443)
                             else f"{proto}://{self.target}:{port}")
                    if base not in urls:
                        urls.append(base)
        return urls or [f"http://{self.target}"]

    # ── análisis de una URL base ──────────────────────────────────────────────

    def _analyze_base(self, base_url: str):
        resp = self._get(base_url)
        if resp is None:
            # Intentar con IP directa si el hostname falla
            ip = self._get_ip()
            if ip and ip != self.target:
                alt = base_url.replace(self.target, ip)
                resp = self._get(alt)
        if resp is None:
            return

        html      = resp.text
        html_low  = html.lower()

        self._detect_cms(resp, html_low)
        self._detect_technologies(resp)
        self._analyze_forms(base_url, html, html_low)
        self._count_js(html)

        # Ecommerce desde página principal
        for sig in ECOMMERCE_SIGNALS:
            if sig in html_low:
                self.profile["has_ecommerce"] = True
                break

        # PrestaShop y Magento siempre son ecommerce
        if self.profile["cms"] in ("prestashop", "magento", "shopify", "opencart"):
            self.profile["has_ecommerce"] = True

        # Login path activo
        if not self.profile["has_login"]:
            self._probe_login_paths(base_url)

        # GraphQL
        if not self.profile["has_graphql"]:
            self._probe_graphql(base_url)

        # REST API
        if not self.profile["has_rest_api"]:
            self._probe_api(base_url)

        # Upload form en paths comunes
        if not self.profile["has_file_upload"]:
            self._probe_upload_paths(base_url)

    # ── detección de CMS ──────────────────────────────────────────────────────

    def _detect_cms(self, resp, html_low: str):
        if self.profile["cms"]:
            return

        server   = resp.headers.get("X-Generator", "").lower()
        powered  = resp.headers.get("X-Powered-By", "").lower()
        cookies  = str(resp.cookies).lower()

        signals = {
            "wordpress":  ["wp-content", "wp-includes", "wordpress", "/wp-json/"],
            "joomla":     ["joomla", "/media/jui/", "mosconfig", "com_content"],
            "prestashop": ["prestashop", "/themes/classic/", "id_product", "id_cart"],
            "drupal":     ["drupal", "drupal.settings", "/sites/default/files/"],
            "magento":    ["magento", "mage/", "varien/", "mage-cache"],
            "laravel":    ["laravel", "laravel_session"],
            "shopify":    ["shopify", "cdn.shopify.com", "myshopify"],
            "wix":        ["wix.com", "wixsite"],
            "opencart":   ["opencart", "route=common"],
        }

        for cms, patterns in signals.items():
            for p in patterns:
                if p in html_low or p in server or p in powered or p in cookies:
                    self.profile["cms"] = cms
                    return

    # ── detección de tecnologías ──────────────────────────────────────────────

    def _detect_technologies(self, resp):
        server  = resp.headers.get("Server", "").lower()
        powered = resp.headers.get("X-Powered-By", "").lower()

        for tech in ("nginx", "apache", "iis", "litespeed", "cloudflare", "openresty"):
            if tech in server and tech not in self.profile["technologies"]:
                self.profile["technologies"].append(tech)

        for tech in ("php", "asp.net", "ruby", "python", "java", "node.js"):
            if tech in powered and tech not in self.profile["technologies"]:
                self.profile["technologies"].append(tech)

    # ── análisis de formularios en HTML ──────────────────────────────────────

    def _analyze_forms(self, base_url: str, html: str, html_low: str):
        forms = re.findall(r"<form[^>]*>", html, re.I)
        if forms:
            self.profile["has_forms"] = True

        # Password input → login
        if re.search(r'type=["\']password["\']', html, re.I):
            self.profile["has_login"] = True
            if base_url not in self.profile["login_urls"]:
                self.profile["login_urls"].append(base_url)

        # File input → upload
        if re.search(r'type=["\']file["\']', html, re.I):
            self.profile["has_file_upload"] = True
            if base_url not in self.profile["upload_urls"]:
                self.profile["upload_urls"].append(base_url)

    # ── conteo de archivos JS ─────────────────────────────────────────────────

    def _count_js(self, html: str):
        js = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html, re.I)
        self.profile["js_files_count"] += len(js)

    # ── sondeos activos ───────────────────────────────────────────────────────

    def _probe_login_paths(self, base_url: str):
        for path in LOGIN_PATHS:
            url = urljoin(base_url + "/", path.lstrip("/"))
            resp = self._get(url, timeout=5)
            if resp and resp.status_code == 200:
                if re.search(r'type=["\']password["\']', resp.text, re.I):
                    self.profile["has_login"] = True
                    if url not in self.profile["login_urls"]:
                        self.profile["login_urls"].append(url)
                    return

    def _probe_graphql(self, base_url: str):
        for path in GRAPHQL_PATHS:
            url = urljoin(base_url + "/", path.lstrip("/"))
            try:
                resp = self.session.post(
                    url, json={"query": "{__typename}"},
                    timeout=5, verify=False
                )
                if resp.status_code in (200, 400) and (
                    '"data"' in resp.text or '"errors"' in resp.text
                ):
                    self.profile["has_graphql"] = True
                    self.profile["graphql_urls"].append(url)
                    return
            except Exception:
                continue

    def _probe_api(self, base_url: str):
        for path in API_PATHS:
            url = urljoin(base_url + "/", path.lstrip("/"))
            resp = self._get(url, timeout=5,
                             headers={"Accept": "application/json"})
            if resp and resp.status_code < 404:
                ct = resp.headers.get("Content-Type", "")
                if "json" in ct:
                    self.profile["has_rest_api"] = True
                    if url not in self.profile["api_urls"]:
                        self.profile["api_urls"].append(url)
                    return

    def _probe_upload_paths(self, base_url: str):
        for path in UPLOAD_PATHS_TO_CHECK:
            url = urljoin(base_url + "/", path.lstrip("/"))
            resp = self._get(url, timeout=5)
            if resp and resp.status_code == 200:
                if re.search(r'type=["\']file["\']', resp.text, re.I):
                    self.profile["has_file_upload"] = True
                    if url not in self.profile["upload_urls"]:
                        self.profile["upload_urls"].append(url)
                    return

    # ── helpers ───────────────────────────────────────────────────────────────

    def _get(self, url: str, timeout: int = TIMEOUT, headers: dict = None) -> requests.Response | None:
        try:
            h = dict(self.session.headers)
            if headers:
                h.update(headers)
            return self.session.get(url, timeout=timeout, verify=False,
                                    allow_redirects=True, headers=h)
        except Exception:
            return None

    def _get_ip(self) -> str | None:
        for host in self.recon_data.get("hosts", []):
            if host.get("ip"):
                return host["ip"]
        return None

    # ── resumen ───────────────────────────────────────────────────────────────

    def _print_profile(self):
        cms = self.profile["cms"] or "desconocido"
        tech = ", ".join(self.profile["technologies"]) or "—"
        print(f"  [+] CMS/Framework  : {cms}")
        print(f"  [+] Tecnologías    : {tech}")
        print(f"  [+] Login          : {'SÍ → ' + self.profile['login_urls'][0] if self.profile['has_login'] else 'NO detectado'}")
        print(f"  [+] Subida archivos: {'SÍ' if self.profile['has_file_upload'] else 'NO'}")
        print(f"  [+] E-commerce     : {'SÍ' if self.profile['has_ecommerce'] else 'NO'}")
        print(f"  [+] GraphQL        : {'SÍ → ' + self.profile['graphql_urls'][0] if self.profile['has_graphql'] else 'NO'}")
        print(f"  [+] API REST       : {'SÍ' if self.profile['has_rest_api'] else 'NO'}")
        print(f"  [+] Archivos JS    : {self.profile['js_files_count']}")
