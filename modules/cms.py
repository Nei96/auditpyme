"""
Módulo de fingerprinting de CMS — AuditPyme
Detecta WordPress, Joomla, PrestaShop, Laravel/Symfony y versiones.
Enumera plugins/módulos activos y correlaciona con CVEs conocidos de 2024-2025.
"""

import requests
import urllib3
import re
import socket

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
TIMEOUT = 10
UA = "Mozilla/5.0 (compatible; AuditPyme/1.0)"

# CVEs activos 2024-2025 por CMS y componente
CMS_CVES = {
    "wordpress": [
        {"cve": "CVE-2025-7384", "componente": "plugin genérico", "cvss": 9.8,
         "desc": "RCE sin autenticación en plugin popular. Más de 131.000 intentos de explotación registrados.",
         "check": None},
        {"cve": "CVE-2025-2011", "componente": "Depicter Slider", "cvss": 9.8,
         "desc": "SQLi sin autenticación vía parámetro 's' en acciones del plugin (90.000+ instalaciones).",
         "check": "/?action=depicter&request=search&s=1"},
        {"cve": "CVE-2025-27007", "componente": "OttoKit <=1.0.82", "cvss": 9.8,
         "desc": "Privilege escalation sin autenticación → RCE vía REST API.",
         "check": "/wp-json/sure-triggers/v1/connection/create-wp-connection"},
    ],
    "joomla": [
        {"cve": "CVE-2025-22213", "componente": "Media Manager 4.0-4.4.11 / 5.0-5.2.4", "cvss": 8.8,
         "desc": "Upload de archivos PHP ejecutables vía Media Manager con permisos de edición.",
         "check": None},
    ],
    "prestashop": [
        {"cve": "CVE-2024-36680", "componente": "pkfacebook/facebookConnect", "cvss": 9.8,
         "desc": "SQLi sin autenticación. Post-explotación: card skimmer que roba tarjetas de clientes.",
         "check": "/modules/pkfacebook/facebookConnect.php"},
        {"cve": "CVE-2024-28392", "componente": "Abandoned Cart Reminder Pro <=2.0.11", "cvss": 9.8,
         "desc": "SQLi sin autenticación en método setEmailVisualized().",
         "check": None},
        {"cve": "CVE-2025-25691", "componente": "PrestaShop 8.2.0", "cvss": 9.8,
         "desc": "PHAR deserialization → RCE completo sin credenciales.",
         "check": None},
    ],
    "laravel": [
        {"cve": "CVE-2024-55556", "componente": ".env expuesto", "cvss": 9.8,
         "desc": "APP_KEY expuesta permite forjar cookies serializadas con gadget chain PHPGGC → RCE.",
         "check": "/.env"},
    ],
}

# Plugins WordPress de alto riesgo a verificar
WP_PLUGINS_RIESGO = [
    ("depicter", "/wp-content/plugins/depicter/"),
    ("sure-triggers", "/wp-content/plugins/sure-triggers/"),
    ("wp-file-manager", "/wp-content/plugins/wp-file-manager/"),
    ("contact-form-7", "/wp-content/plugins/contact-form-7/"),
    ("elementor", "/wp-content/plugins/elementor/"),
    ("woocommerce", "/wp-content/plugins/woocommerce/"),
    ("yoast-seo", "/wp-content/plugins/wordpress-seo/"),
    ("wpforms-lite", "/wp-content/plugins/wpforms-lite/"),
]

# Módulos PrestaShop de alto riesgo
PS_MODULES_RIESGO = [
    ("pkfacebook", "/modules/pkfacebook/"),
    ("amazzingpopup", "/modules/amazzingpopup/"),
    ("blockreassurance", "/modules/blockreassurance/"),
    ("ps_facetedsearch", "/modules/ps_facetedsearch/"),
]


class CMSDetector:
    def __init__(self, target: str, recon_data: dict = None):
        self.target = target
        self.recon_data = recon_data or {}
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA})
        self.session.verify = False
        self._base_urls = self._build_base_urls()

    def scan(self) -> list:
        print(f"\n  [*] Fingerprinting CMS en: {self.target}")
        for base_url in self._base_urls:
            cms = self._detect_cms(base_url)
            if cms:
                print(f"  [+] CMS detectado: {cms['nombre']} {cms.get('version', '')} en {base_url}")
                self._correlate_cves(cms, base_url)
                if cms["tipo"] == "wordpress":
                    self._scan_wp_plugins(base_url)
                    self._check_wp_exposure(base_url)
                elif cms["tipo"] == "prestashop":
                    self._scan_ps_modules(base_url)
                elif cms["tipo"] == "laravel":
                    self._check_env_exposure(base_url)
        if not self.findings:
            print("  [OK] No se detectó CMS conocido o no hay hallazgos de riesgo")
        return self.findings

    # ── Detección de CMS ──────────────────────────────────────────────────────

    def _detect_cms(self, base_url: str) -> dict | None:
        try:
            resp = self.session.get(base_url, timeout=TIMEOUT, allow_redirects=True)
            html = resp.text
            headers = {k.lower(): v for k, v in resp.headers.items()}

            # WordPress
            if any(sig in html for sig in ["/wp-content/", "/wp-includes/", "wp-json"]):
                version = self._extract_wp_version(html, base_url)
                return {"tipo": "wordpress", "nombre": "WordPress", "version": version}

            # Joomla
            if any(sig in html for sig in ["/media/jui/", "Joomla!", "/components/com_"]):
                version = self._extract_joomla_version(html, base_url)
                return {"tipo": "joomla", "nombre": "Joomla", "version": version}

            # PrestaShop
            if any(sig in html for sig in ["/modules/", "prestashop", "id_product", "fc=module"]):
                version = self._extract_ps_version(html, headers)
                return {"tipo": "prestashop", "nombre": "PrestaShop", "version": version}

            # Laravel
            if any(sig in html for sig in ["laravel_session", "XSRF-TOKEN", "Laravel"]):
                return {"tipo": "laravel", "nombre": "Laravel/PHP Framework", "version": ""}

            # Symfony
            if any(sig in html for sig in ["symfony", "_sf2_attributes"]):
                return {"tipo": "symfony", "nombre": "Symfony", "version": ""}

        except Exception:
            pass
        return None

    def _extract_wp_version(self, html: str, base_url: str) -> str:
        # Meta generator
        m = re.search(r'<meta name="generator" content="WordPress ([0-9.]+)"', html, re.IGNORECASE)
        if m:
            return m.group(1)
        # readme.html
        try:
            r = self.session.get(base_url + "/readme.html", timeout=TIMEOUT)
            m = re.search(r'Version ([0-9.]+)', r.text)
            if m:
                return m.group(1)
        except Exception:
            pass
        return "desconocida"

    def _extract_joomla_version(self, html: str, base_url: str) -> str:
        try:
            r = self.session.get(base_url + "/administrator/manifests/files/joomla.xml", timeout=TIMEOUT)
            m = re.search(r'<version>([0-9.]+)</version>', r.text)
            if m:
                return m.group(1)
        except Exception:
            pass
        return "desconocida"

    def _extract_ps_version(self, html: str, headers: dict) -> str:
        m = re.search(r'PrestaShop[/ ]([0-9.]+)', html, re.IGNORECASE)
        if m:
            return m.group(1)
        return "desconocida"

    # ── Correlación de CVEs ───────────────────────────────────────────────────

    def _correlate_cves(self, cms: dict, base_url: str):
        tipo = cms["tipo"]
        cves = CMS_CVES.get(tipo, [])
        for cve_info in cves:
            # Si tiene endpoint de verificación, comprobar si responde
            activo = True
            if cve_info.get("check"):
                try:
                    r = self.session.get(base_url + cve_info["check"], timeout=TIMEOUT)
                    activo = r.status_code not in (404,)
                except Exception:
                    activo = False
            if activo:
                self._add("CRITICAL" if cve_info["cvss"] >= 9.0 else "HIGH",
                          f"{cve_info['cve']} — {cms['nombre']}",
                          f"{cve_info['cve']} en {cve_info['componente']} (CVSS {cve_info['cvss']})",
                          cve_info["desc"],
                          f"Actualizar {cms['nombre']} y todos sus plugins/módulos. "
                          f"Verificar si {cve_info['componente']} está instalado y actualizar a la versión parcheada.")
                print(f"    [CVE] {cve_info['cve']} — {cve_info['componente']} (CVSS {cve_info['cvss']})")

    # ── WordPress: plugins y exposición ──────────────────────────────────────

    def _scan_wp_plugins(self, base_url: str):
        print("  [*] Enumerando plugins WordPress activos...")
        encontrados = []
        for nombre, path in WP_PLUGINS_RIESGO:
            try:
                r = self.session.get(base_url + path, timeout=TIMEOUT)
                if r.status_code in (200, 403):
                    encontrados.append(nombre)
                    print(f"    [PLUGIN] {nombre} detectado")
            except Exception:
                pass
        if encontrados:
            self._add("MEDIUM", "Plugins WordPress detectados",
                      f"{len(encontrados)} plugins de alto riesgo activos: {', '.join(encontrados)}",
                      "Los plugins detectados tienen historial de vulnerabilidades críticas. "
                      "Mantenerlos actualizados es esencial — el 89% de los CVEs de WordPress son de plugins.",
                      "Actualizar todos los plugins a su última versión. Eliminar los que no se usen.")

    def _check_wp_exposure(self, base_url: str):
        checks = [
            ("/wp-config.php.bak", "CRITICAL", "wp-config.php.bak expuesto — credenciales de BD en texto plano"),
            ("/wp-config.php~", "CRITICAL", "Backup de wp-config.php expuesto"),
            ("/wp-json/wp/v2/users", "MEDIUM", "API REST expone lista de usuarios (enumeración de usuarios)"),
            ("/?author=1", "LOW", "Enumeración de usuarios via ?author="),
            ("/xmlrpc.php", "MEDIUM", "xmlrpc.php accesible — vector de fuerza bruta y DDoS"),
        ]
        for path, sev, desc in checks:
            try:
                r = self.session.get(base_url + path, timeout=TIMEOUT, allow_redirects=True)
                if r.status_code == 200 and len(r.text) > 10:
                    self._add(sev, "WordPress — Exposición", desc, desc,
                              f"Bloquear acceso a {path} o eliminarlo si no es necesario.")
                    print(f"    [{sev}] {path} accesible")
            except Exception:
                pass

    # ── PrestaShop: módulos vulnerables ──────────────────────────────────────

    def _scan_ps_modules(self, base_url: str):
        print("  [*] Verificando módulos PrestaShop de riesgo...")
        for nombre, path in PS_MODULES_RIESGO:
            try:
                r = self.session.get(base_url + path, timeout=TIMEOUT)
                if r.status_code in (200, 403):
                    self._add("HIGH", f"Módulo PrestaShop de riesgo: {nombre}",
                              f"Módulo '{nombre}' detectado en {base_url + path}",
                              f"El módulo '{nombre}' tiene vulnerabilidades SQLi conocidas "
                              f"que permiten acceso sin autenticación a la base de datos.",
                              f"Actualizar el módulo '{nombre}' a la última versión o desinstalarlo si no se usa.")
                    print(f"    [HIGH] Módulo de riesgo: {nombre}")
            except Exception:
                pass

    # ── Laravel: .env expuesto ────────────────────────────────────────────────

    def _check_env_exposure(self, base_url: str):
        env_paths = ["/.env", "/.env.backup", "/.env.local", "/.env.production", "/.env.staging"]
        for path in env_paths:
            try:
                r = self.session.get(base_url + path, timeout=TIMEOUT)
                if r.status_code == 200 and ("APP_KEY" in r.text or "DB_PASSWORD" in r.text):
                    has_key = "APP_KEY" in r.text
                    self._add("CRITICAL", f"Archivo {path} expuesto",
                              f"{path} accesible públicamente — credenciales y claves expuestas",
                              f"El archivo {path} contiene configuración sensible. "
                              + ("APP_KEY expuesta → posible RCE via deserialización de cookie (gadget chain PHPGGC). " if has_key else "")
                              + "DB_PASSWORD, claves de API y otros secretos accesibles públicamente.",
                              f"Bloquear acceso a {path} en el servidor web (Nginx: deny all; Apache: Require all denied). "
                              "Rotar inmediatamente todas las claves expuestas.")
                    print(f"    [CRITICAL] {path} expuesto con credenciales")
            except Exception:
                pass

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _build_base_urls(self) -> list:
        urls = []
        for host in self.recon_data.get("hosts", []):
            if host["estado"] != "up":
                continue
            for p in host["puertos"]:
                port = p["puerto"]
                svc = p["servicio"].lower()
                if "http" in svc or port in (80, 443, 8080, 8443, 8888):
                    proto = "https" if port in (443, 8443) else "http"
                    base = self.target
                    url = f"{proto}://{base}:{port}" if port not in (80, 443) else f"{proto}://{base}"
                    if url not in urls:
                        urls.append(url)
        return urls or [f"https://{self.target}"]

    def _add(self, severidad, tipo, nombre, descripcion, recomendacion):
        for f in self.findings:
            if f["nombre"] == nombre:
                return
        self.findings.append({
            "severidad": severidad,
            "tipo": tipo,
            "nombre": nombre,
            "descripcion": descripcion,
            "recomendacion": recomendacion,
        })
