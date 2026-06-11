"""
Módulo de análisis web — Fase 2 (complemento)
Analiza cabeceras HTTP de seguridad, robots.txt y rutas sensibles expuestas.
"""

import requests
import urllib3
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 8

# Cabeceras de seguridad que deben estar presentes
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "descripcion": "HSTS no configurado — el navegador no fuerza HTTPS.",
        "severidad": "MEDIUM",
        "recomendacion": "Añadir: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "Content-Security-Policy": {
        "descripcion": "CSP no configurado — riesgo de XSS y carga de recursos maliciosos.",
        "severidad": "MEDIUM",
        "recomendacion": "Implementar política CSP restrictiva para fuentes de scripts y recursos.",
    },
    "X-Frame-Options": {
        "descripcion": "X-Frame-Options ausente — posible riesgo de Clickjacking.",
        "severidad": "MEDIUM",
        "recomendacion": "Añadir: X-Frame-Options: DENY o SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "descripcion": "X-Content-Type-Options ausente — el navegador puede inferir el tipo MIME.",
        "severidad": "LOW",
        "recomendacion": "Añadir: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "descripcion": "Referrer-Policy no definida — puede filtrar URLs internas.",
        "severidad": "LOW",
        "recomendacion": "Añadir: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "descripcion": "Permissions-Policy ausente — APIs del navegador sin restricciones.",
        "severidad": "LOW",
        "recomendacion": "Definir Permissions-Policy para restringir acceso a cámara, geolocalización, etc.",
    },
}

# Cabeceras que NO deben estar presentes (revelan info del servidor)
DISCLOSURE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version",
                      "X-AspNetMvc-Version", "X-Generator"]

# Rutas sensibles a comprobar
SENSITIVE_PATHS = [
    ("/.env",                "HIGH",   "Archivo .env expuesto — puede contener credenciales y claves API."),
    ("/.git/config",         "CRITICAL","Repositorio Git expuesto — acceso al código fuente."),
    ("/.git/HEAD",           "CRITICAL","Repositorio Git expuesto — acceso al código fuente."),
    ("/backup",              "HIGH",   "Directorio backup expuesto."),
    ("/backup.zip",          "HIGH",   "Archivo de backup expuesto."),
    ("/backup.sql",          "CRITICAL","Dump SQL expuesto — posible acceso a base de datos."),
    ("/db.sql",              "CRITICAL","Dump SQL expuesto."),
    ("/admin",               "MEDIUM", "Panel de administración accesible."),
    ("/administrator",       "MEDIUM", "Panel de administración accesible."),
    ("/wp-admin",            "MEDIUM", "Panel WordPress accesible."),
    ("/wp-login.php",        "MEDIUM", "Login WordPress expuesto — objetivo de fuerza bruta."),
    ("/phpmyadmin",          "HIGH",   "phpMyAdmin expuesto — acceso directo a base de datos."),
    ("/phpmyadmin/",         "HIGH",   "phpMyAdmin expuesto."),
    ("/pma",                 "HIGH",   "phpMyAdmin (ruta alternativa) expuesto."),
    ("/cpanel",              "HIGH",   "Panel de control cPanel accesible."),
    ("/webmail",             "MEDIUM", "Webmail expuesto."),
    ("/api",                 "LOW",    "Endpoint API expuesto — verificar autenticación."),
    ("/api/v1",              "LOW",    "Endpoint API v1 expuesto."),
    ("/api/v2",              "LOW",    "Endpoint API v2 expuesto."),
    ("/swagger",             "MEDIUM", "Swagger UI expuesto — documentación de API accesible."),
    ("/swagger-ui.html",     "MEDIUM", "Swagger UI expuesto."),
    ("/api-docs",            "MEDIUM", "Documentación de API expuesta."),
    ("/actuator",            "HIGH",   "Spring Boot Actuator expuesto — métricas y gestión internas."),
    ("/actuator/health",     "MEDIUM", "Spring Boot health endpoint expuesto."),
    ("/actuator/env",        "CRITICAL","Spring Boot env endpoint — expone variables de entorno."),
    ("/server-status",       "MEDIUM", "Apache server-status expuesto — revela info del servidor."),
    ("/nginx_status",        "MEDIUM", "Nginx status expuesto."),
    ("/config.php",          "HIGH",   "Archivo de configuración PHP expuesto."),
    ("/config.yml",          "HIGH",   "Archivo de configuración YAML expuesto."),
    ("/config.yaml",         "HIGH",   "Archivo de configuración YAML expuesto."),
    ("/robots.txt",          "INFO",   "robots.txt encontrado — revisar rutas desindexadas."),
    ("/sitemap.xml",         "INFO",   "sitemap.xml encontrado."),
    ("/.htaccess",           "HIGH",   "Archivo .htaccess expuesto — configuración del servidor."),
    ("/web.config",          "HIGH",   "web.config expuesto — configuración IIS."),
]


class WebAnalyzer:
    def __init__(self, target: str, recon_data: dict, stealth: bool = False):
        self.target = target
        self.recon_data = recon_data
        self.delay = 1.0 if stealth else 0
        self.findings = []

    def analyze(self) -> list:
        urls = self._build_urls()
        if not urls:
            print("  [*] No se detectaron servicios web activos.")
            return []

        for url in urls:
            print(f"\n  [*] Analizando: {url}")
            self._check_headers(url)
            self._check_paths(url)

        return self.findings

    def _build_urls(self) -> list:
        urls = []
        for host in self.recon_data.get("hosts", []):
            if host["estado"] != "up":
                continue
            ip = host["ip"]
            hostname = host["hostname"] if host["hostname"] != ip else None

            for p in host["puertos"]:
                port = p["puerto"]
                svc = p["servicio"].lower()

                if "http" in svc or port in (80, 443, 8080, 8443, 8888):
                    proto = "https" if port in (443, 8443) else "http"
                    base = hostname or ip
                    url = f"{proto}://{base}:{port}" if port not in (80, 443) else f"{proto}://{base}"
                    if url not in urls:
                        urls.append(url)

        return urls

    def _check_headers(self, url: str):
        try:
            resp = requests.get(url, timeout=TIMEOUT, verify=False,
                                allow_redirects=True,
                                headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)"})
        except Exception as e:
            print(f"  [!] No se pudo conectar a {url}: {e}")
            return

        headers = {k.title(): v for k, v in resp.headers.items()}
        print(f"  [+] Respuesta: HTTP {resp.status_code}")

        # Cabeceras de seguridad ausentes
        for header, info in SECURITY_HEADERS.items():
            if header not in headers:
                self._add(url, "CABECERA AUSENTE", header,
                          info["descripcion"], info["severidad"],
                          info["recomendacion"])
                print(f"    [MISS] {header} — {info['severidad']}")

        # Cabeceras que revelan información
        for header in DISCLOSURE_HEADERS:
            if header in headers:
                valor = headers[header]
                self._add(url, "INFO DISCLOSURE", header,
                          f"Header '{header}' revela: {valor}",
                          "LOW",
                          f"Eliminar o enmascarar el header '{header}' en la configuración del servidor.")
                print(f"    [DISC] {header}: {valor}")

        # Verificar HTTPS redirect si es HTTP
        if url.startswith("http://"):
            if resp.url.startswith("https://"):
                print(f"  [INFO] Redirige a HTTPS correctamente.")
            else:
                self._add(url, "CONFIGURACIÓN", "Sin redirect HTTPS",
                          "El servidor HTTP no redirige a HTTPS.",
                          "MEDIUM",
                          "Configurar redirección 301 de HTTP a HTTPS en el servidor web.")

    def _check_paths(self, url: str):
        base = url.rstrip("/")
        print(f"  [*] Comprobando {len(SENSITIVE_PATHS)} rutas sensibles...")
        encontradas = 0

        for path, severidad, descripcion in SENSITIVE_PATHS:
            full_url = base + path
            try:
                time.sleep(self.delay)
                resp = requests.get(full_url, timeout=TIMEOUT, verify=False,
                                    allow_redirects=False,
                                    headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)"})

                if resp.status_code in (200, 401, 403):
                    # Filtrar falsos positivos de CDN/WAF (Cloudflare, etc.)
                    # que devuelven 200 con páginas de error genéricas
                    if resp.status_code == 200 and self._is_cdn_error(resp):
                        continue

                    estado = "ACCESIBLE" if resp.status_code == 200 else f"PROTEGIDO ({resp.status_code})"
                    sev_real = severidad if resp.status_code == 200 else "LOW"
                    self._add(full_url, "RUTA SENSIBLE", path,
                              f"{descripcion} [{estado}]",
                              sev_real,
                              f"Bloquear acceso a {path} o eliminar el recurso si no es necesario.")
                    print(f"    [{sev_real}] {path} → HTTP {resp.status_code}")
                    encontradas += 1

                    if path == "/robots.txt" and resp.status_code == 200:
                        for line in resp.text.splitlines()[:10]:
                            if "disallow" in line.lower() or "allow" in line.lower():
                                print(f"           {line.strip()}")

            except Exception:
                pass

        if encontradas == 0:
            print("  [+] No se encontraron rutas sensibles expuestas.")

    def _is_cdn_error(self, resp) -> bool:
        """Detecta páginas de error genéricas de CDN/WAF que devuelven HTTP 200."""
        content_type = resp.headers.get("Content-Type", "")
        if "text/html" not in content_type and "text/plain" not in content_type:
            return False
        body = resp.text[:2000].lower()
        # Señales típicas de páginas de error de Cloudflare, WAF o servidor
        cdn_patterns = [
            "error 404", "not found", "page not found", "404 not found",
            "access denied", "403 forbidden", "this page doesn't exist",
            "cloudflare", "ray id:", "cf-ray",
            "nothing here", "no existe", "página no encontrada",
            "under construction", "coming soon", "domain parked",
        ]
        hits = sum(1 for p in cdn_patterns if p in body)
        # Si el body es muy pequeño o tiene muchas señales de error, es falso positivo
        if hits >= 2 or (len(resp.text.strip()) < 200 and hits >= 1):
            return True
        return False

    def _add(self, url, tipo, nombre, descripcion, severidad, recomendacion):
        self.findings.append({
            "url":           url,
            "tipo":          tipo,
            "nombre":        nombre,
            "descripcion":   descripcion,
            "severidad":     severidad,
            "recomendacion": recomendacion,
        })
