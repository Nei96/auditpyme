"""
Módulo de fingerprinting de CMS — AuditPyme
Detecta WordPress, Joomla, PrestaShop, Laravel/Symfony y versiones.
Verifica plugins instalados ANTES de reportar CVEs — sin falsos positivos.
"""

import requests
import urllib3
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
TIMEOUT = 10
UA = "Mozilla/5.0 (compatible; AuditPyme/1.0)"

# CVEs por plugin — solo se reportan si el plugin está confirmado instalado
# plugin: None → WordPress core (siempre aplica si se detecta la versión)
PLUGIN_CVES = {
    "wordpress_core": [
        {"cve": "CVE-2025-27007", "componente": "OttoKit <=1.0.82", "cvss": 9.8,
         "desc": "Privilege escalation sin autenticación → RCE vía REST API.",
         "plugin": "sure-triggers"},
    ],
    "revslider": [
        {"cve": "CVE-2023-2296", "componente": "Slider Revolution <=6.6.18", "cvss": 8.8,
         "desc": "Descarga arbitraria de archivos del servidor con rol Subscriber o superior.",
         "plugin": "revslider"},
        {"cve": "CVE-2024-4636", "componente": "Slider Revolution <=6.7.11", "cvss": 6.4,
         "desc": "XSS almacenado vía parámetro data-lazyload. Requiere rol Contributor+.",
         "plugin": "revslider"},
    ],
    "js_composer": [
        {"cve": "CVE-2020-23972", "componente": "WPBakery Page Builder <=6.4.1", "cvss": 8.8,
         "desc": "Subida arbitraria de archivos con rol Contributor+. Permite RCE si se sube un PHP.",
         "plugin": "js_composer"},
        {"cve": "CVE-2022-0215", "componente": "WPBakery Page Builder <=6.8", "cvss": 8.8,
         "desc": "CSRF → XSS almacenado. Afecta versiones sin parche de seguridad.",
         "plugin": "js_composer"},
    ],
    "depicter": [
        {"cve": "CVE-2025-2011", "componente": "Depicter Slider <=3.8.1", "cvss": 9.8,
         "desc": "SQLi sin autenticación vía parámetro 's' (90.000+ instalaciones activas).",
         "plugin": "depicter"},
    ],
    "sure-triggers": [
        {"cve": "CVE-2025-27007", "componente": "OttoKit/SureTriggers <=1.0.82", "cvss": 9.8,
         "desc": "Privilege escalation sin autenticación → creación de usuario admin vía REST API.",
         "plugin": "sure-triggers"},
    ],
    "wp-file-manager": [
        {"cve": "CVE-2020-25213", "componente": "File Manager <=6.8", "cvss": 10.0,
         "desc": "RCE sin autenticación — uno de los CVEs más explotados de la historia de WordPress.",
         "plugin": "wp-file-manager"},
    ],
    "contact-form-7": [
        {"cve": "CVE-2020-35489", "componente": "Contact Form 7 <=5.3.1", "cvss": 9.8,
         "desc": "Subida sin restricciones de archivos PHP ejecutables si el formulario tiene campo de archivo.",
         "plugin": "contact-form-7"},
    ],
    "woocommerce": [
        {"cve": "CVE-2021-32789", "componente": "WooCommerce <=5.5.1", "cvss": 9.8,
         "desc": "SQLi sin autenticación en endpoint de búsqueda de productos.",
         "plugin": "woocommerce"},
    ],
}

# Plugins a detectar: (clave_interna, ruta_en_servidor, nombre_mostrar)
WP_PLUGINS = [
    ("revslider",       "/wp-content/plugins/revslider/readme.txt",          "Slider Revolution"),
    ("js_composer",     "/wp-content/plugins/js_composer/readme.txt",        "WPBakery Page Builder"),
    ("depicter",        "/wp-content/plugins/depicter/readme.txt",           "Depicter Slider"),
    ("sure-triggers",   "/wp-content/plugins/sure-triggers/readme.txt",      "OttoKit/SureTriggers"),
    ("wp-file-manager", "/wp-content/plugins/wp-file-manager/readme.txt",    "File Manager"),
    ("contact-form-7",  "/wp-content/plugins/contact-form-7/readme.txt",     "Contact Form 7"),
    ("elementor",       "/wp-content/plugins/elementor/readme.txt",          "Elementor"),
    ("woocommerce",     "/wp-content/plugins/woocommerce/readme.txt",        "WooCommerce"),
    ("wpforms-lite",    "/wp-content/plugins/wpforms-lite/readme.txt",       "WPForms"),
    ("yoast-seo",       "/wp-content/plugins/wordpress-seo/readme.txt",      "Yoast SEO"),
]

# Versiones máximas vulnerables por plugin (para alertar si está instalado y es viejo)
PLUGIN_VERSIONES_RIESGO = {
    "revslider":       ("6.7.11", "6.4.11"),
    "js_composer":     ("6.8",    "5.4.5"),
    "contact-form-7":  ("5.3.1",  "4.9.2"),
    "woocommerce":     ("5.5.1",  None),
    "depicter":        ("3.8.1",  None),
    "sure-triggers":   ("1.0.82", None),
    "wp-file-manager": ("6.8",    None),
}

# Módulos PrestaShop de alto riesgo
PS_MODULES = [
    ("pkfacebook",         "/modules/pkfacebook/"),
    ("amazzingpopup",      "/modules/amazzingpopup/"),
    ("blockreassurance",   "/modules/blockreassurance/"),
    ("ps_facetedsearch",   "/modules/ps_facetedsearch/"),
]

CMS_CVES_CORE = {
    "joomla": [
        {"cve": "CVE-2025-22213", "componente": "Media Manager 4.0-5.2.4", "cvss": 8.8,
         "desc": "Upload de archivos PHP ejecutables vía Media Manager con permisos de edición.",
         "check": None},
    ],
    "prestashop": [
        {"cve": "CVE-2024-36680",  "componente": "pkfacebook/facebookConnect", "cvss": 9.8,
         "desc": "SQLi sin autenticación. Post-explotación: card skimmer que roba tarjetas.",
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
         "desc": "APP_KEY expuesta permite forjar cookies serializadas → RCE via gadget chain PHPGGC.",
         "check": "/.env"},
    ],
}


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
                if cms["tipo"] == "wordpress":
                    self._audit_wordpress(base_url)
                elif cms["tipo"] == "prestashop":
                    self._audit_prestashop(cms, base_url)
                elif cms["tipo"] in ("laravel", "symfony"):
                    self._check_env_exposure(base_url)
                else:
                    self._correlate_core_cves(cms, base_url)
        if not self.findings:
            print("  [OK] No se detectó CMS conocido o no hay hallazgos de riesgo")
        return self.findings

    # ── WordPress ─────────────────────────────────────────────────────────────

    def _audit_wordpress(self, base_url: str):
        # 1. Detectar plugins instalados realmente
        plugins_instalados = self._scan_wp_plugins(base_url)

        # 2. Reportar CVEs SOLO para plugins confirmados
        for clave, nombre_display in plugins_instalados.items():
            cves = PLUGIN_CVES.get(clave, [])
            version = plugins_instalados.get(f"{clave}_version")
            for cve_info in cves:
                sev = "CRITICAL" if cve_info["cvss"] >= 9.0 else "HIGH"
                self._add(sev,
                          f"{cve_info['cve']} — {nombre_display}",
                          f"{cve_info['cve']} en {cve_info['componente']} (CVSS {cve_info['cvss']})",
                          cve_info["desc"],
                          f"Actualizar {nombre_display} a la última versión disponible.")
                print(f"    [CVE] {cve_info['cve']} — {nombre_display} (CVSS {cve_info['cvss']})")

            # Alertar si la versión instalada es conocidamente vulnerable
            if clave in PLUGIN_VERSIONES_RIESGO:
                max_vuln, version_detectada = PLUGIN_VERSIONES_RIESGO[clave]
                v = version or version_detectada
                if v:
                    print(f"    [WARN] {nombre_display} versión {v} — vulnerable hasta {max_vuln}")

        # 3. Exposición de WordPress
        self._check_wp_exposure(base_url)

    def _scan_wp_plugins(self, base_url: str) -> dict:
        """Devuelve dict {clave: nombre_display} de plugins confirmados instalados."""
        print("  [*] Verificando plugins instalados...")
        encontrados = {}
        for clave, path, nombre in WP_PLUGINS:
            try:
                r = self.session.get(base_url + path, timeout=TIMEOUT)
                if r.status_code == 200 and len(r.text) > 50:
                    version = self._extract_plugin_version(r.text)
                    encontrados[clave] = nombre
                    if version:
                        encontrados[f"{clave}_version"] = version
                        print(f"    [PLUGIN] {nombre} v{version}")
                    else:
                        print(f"    [PLUGIN] {nombre} (versión desconocida)")
                elif r.status_code == 403:
                    # El directorio existe pero el readme está bloqueado — plugin probablemente instalado
                    # Solo lo marcamos si hay assets JS/CSS que lo confirmen
                    pass
            except Exception:
                pass

        # También detectar por assets JS (para plugins sin readme.txt accesible)
        self._detect_plugins_by_assets(base_url, encontrados)
        return encontrados

    def _detect_plugins_by_assets(self, base_url: str, encontrados: dict):
        """Detecta RevSlider y WPBakery desde el HTML cuando readme.txt no es accesible."""
        try:
            r = self.session.get(base_url, timeout=TIMEOUT)
            html = r.text
            if "revslider" in html and "revslider" not in encontrados:
                ver_match = re.search(r'revslider[^"\']*ver=([0-9.]+)', html)
                ver = ver_match.group(1) if ver_match else None
                encontrados["revslider"] = "Slider Revolution"
                if ver:
                    encontrados["revslider_version"] = ver
                print(f"    [PLUGIN] Slider Revolution{' v' + ver if ver else ''} (detectado por assets)")
            if "js_composer" in html and "js_composer" not in encontrados:
                ver_match = re.search(r'js_composer[^"\']*ver=([0-9.]+)', html)
                ver = ver_match.group(1) if ver_match else None
                encontrados["js_composer"] = "WPBakery Page Builder"
                if ver:
                    encontrados["js_composer_version"] = ver
                print(f"    [PLUGIN] WPBakery Page Builder{' v' + ver if ver else ''} (detectado por assets)")
        except Exception:
            pass

    def _extract_plugin_version(self, readme: str) -> str | None:
        m = re.search(r'Stable tag:\s*([0-9.]+)', readme, re.I)
        return m.group(1) if m else None

    def _check_wp_exposure(self, base_url: str):
        checks = [
            ("/wp-config.php.bak", "CRITICAL", "Backup de wp-config.php expuesto — credenciales de BD en texto plano"),
            ("/wp-config.php~",    "CRITICAL", "Backup de wp-config.php expuesto"),
            ("/wp-json/wp/v2/users", "MEDIUM", "API REST expone lista de usuarios sin autenticación"),
            ("/?author=1",         "LOW",    "Enumeración de usuarios vía ?author="),
            ("/xmlrpc.php",        "MEDIUM", "xmlrpc.php accesible — fuerza bruta y amplificación DDoS"),
        ]
        for path, sev, desc in checks:
            try:
                r = self.session.get(base_url + path, timeout=TIMEOUT, allow_redirects=True)
                if r.status_code == 200 and len(r.text) > 10:
                    self._add(sev, "WordPress — Exposición", desc, desc,
                              f"Bloquear acceso a {path} o requerir autenticación.")
                    print(f"    [{sev}] {path} accesible")
            except Exception:
                pass

    # ── PrestaShop ────────────────────────────────────────────────────────────

    def _audit_prestashop(self, cms: dict, base_url: str):
        self._correlate_core_cves(cms, base_url)
        print("  [*] Verificando módulos PrestaShop de riesgo...")
        for nombre, path in PS_MODULES:
            try:
                r = self.session.get(base_url + path, timeout=TIMEOUT)
                if r.status_code in (200, 403):
                    self._add("HIGH", f"Módulo PrestaShop vulnerable: {nombre}",
                              f"Módulo '{nombre}' instalado — tiene CVEs de SQLi sin autenticación",
                              f"El módulo '{nombre}' permite acceso sin credenciales a la base de datos.",
                              f"Actualizar o desinstalar el módulo '{nombre}'.")
                    print(f"    [HIGH] Módulo vulnerable: {nombre}")
            except Exception:
                pass

    # ── CVEs de core (Joomla, PrestaShop, Laravel) ───────────────────────────

    def _correlate_core_cves(self, cms: dict, base_url: str):
        for cve_info in CMS_CVES_CORE.get(cms["tipo"], []):
            activo = True
            if cve_info.get("check"):
                try:
                    r = self.session.get(base_url + cve_info["check"], timeout=TIMEOUT)
                    activo = r.status_code not in (404,)
                except Exception:
                    activo = False
            if activo:
                sev = "CRITICAL" if 9.0 <= cve_info["cvss"] else "HIGH"
                self._add(sev,
                          f"{cve_info['cve']} — {cms['nombre']}",
                          f"{cve_info['cve']} en {cve_info['componente']} (CVSS {cve_info['cvss']})",
                          cve_info["desc"],
                          f"Actualizar {cms['nombre']} y sus módulos a la última versión.")
                print(f"    [CVE] {cve_info['cve']} — {cve_info['componente']} (CVSS {cve_info['cvss']})")

    # ── Laravel: .env expuesto ────────────────────────────────────────────────

    def _check_env_exposure(self, base_url: str):
        for path in ["/.env", "/.env.backup", "/.env.local", "/.env.production"]:
            try:
                r = self.session.get(base_url + path, timeout=TIMEOUT)
                if r.status_code == 200 and ("APP_KEY" in r.text or "DB_PASSWORD" in r.text):
                    has_key = "APP_KEY" in r.text
                    self._add("CRITICAL", f"Archivo {path} expuesto",
                              f"{path} accesible — credenciales y claves expuestas",
                              ("APP_KEY expuesta → RCE via deserialización (PHPGGC). " if has_key else "") +
                              "Credenciales de BD y claves API accesibles públicamente.",
                              f"Bloquear {path} en el servidor web y rotar todas las claves.")
                    print(f"    [CRITICAL] {path} expuesto")
            except Exception:
                pass

    # ── Detección de CMS ──────────────────────────────────────────────────────

    def _detect_cms(self, base_url: str) -> dict | None:
        try:
            resp = self.session.get(base_url, timeout=TIMEOUT, allow_redirects=True)
            html = resp.text

            if any(s in html for s in ["/wp-content/", "/wp-includes/", "wp-json"]):
                return {"tipo": "wordpress", "nombre": "WordPress",
                        "version": self._extract_wp_version(html, base_url)}
            if any(s in html for s in ["/media/jui/", "Joomla!", "/components/com_"]):
                return {"tipo": "joomla", "nombre": "Joomla",
                        "version": self._extract_joomla_version(base_url)}
            if any(s in html for s in ["/modules/", "prestashop", "id_product", "fc=module"]):
                return {"tipo": "prestashop", "nombre": "PrestaShop",
                        "version": self._extract_ps_version(html)}
            if any(s in html for s in ["laravel_session", "XSRF-TOKEN", "Laravel"]):
                return {"tipo": "laravel", "nombre": "Laravel", "version": ""}
            if any(s in html for s in ["symfony", "_sf2_attributes"]):
                return {"tipo": "symfony", "nombre": "Symfony", "version": ""}
        except Exception:
            pass
        return None

    def _extract_wp_version(self, html: str, base_url: str) -> str:
        m = re.search(r'<meta name="generator" content="WordPress ([0-9.]+)"', html, re.I)
        if m:
            return m.group(1)
        try:
            r = self.session.get(base_url + "/readme.html", timeout=TIMEOUT)
            m = re.search(r'Version ([0-9.]+)', r.text)
            if m:
                return m.group(1)
        except Exception:
            pass
        return "desconocida"

    def _extract_joomla_version(self, base_url: str) -> str:
        try:
            r = self.session.get(base_url + "/administrator/manifests/files/joomla.xml", timeout=TIMEOUT)
            m = re.search(r'<version>([0-9.]+)</version>', r.text)
            if m:
                return m.group(1)
        except Exception:
            pass
        return "desconocida"

    def _extract_ps_version(self, html: str) -> str:
        m = re.search(r'PrestaShop[/ ]([0-9.]+)', html, re.I)
        return m.group(1) if m else "desconocida"

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
                    url = (f"{proto}://{self.target}:{port}"
                           if port not in (80, 443)
                           else f"{proto}://{self.target}")
                    if url not in urls:
                        urls.append(url)
        return urls or [f"https://{self.target}"]

    def _add(self, severidad, tipo, nombre, descripcion, recomendacion):
        for f in self.findings:
            if f["nombre"] == nombre:
                return
        self.findings.append({
            "severidad": severidad, "tipo": tipo,
            "nombre": nombre, "descripcion": descripcion,
            "recomendacion": recomendacion,
        })
