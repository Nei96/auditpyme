"""
Módulo de análisis web — Fase 2 (complemento)
Analiza cabeceras HTTP de seguridad, robots.txt y rutas sensibles expuestas.
"""

import requests
import urllib3
import time
import hashlib
import os

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
    # ── Credenciales y configuración ─────────────────────────────────────────
    ("/.env",                    "HIGH",    "Archivo .env expuesto — puede contener credenciales y claves API."),
    ("/.env.backup",             "HIGH",    "Backup de .env expuesto."),
    ("/.env.local",              "HIGH",    "Archivo .env.local expuesto."),
    ("/.env.production",         "CRITICAL","Archivo .env.production expuesto — credenciales de producción."),
    ("/.env.staging",            "HIGH",    "Archivo .env.staging expuesto."),
    ("/config.php",              "HIGH",    "Archivo de configuración PHP expuesto."),
    ("/config.php.bak",          "CRITICAL","Backup de config.php expuesto — credenciales en texto plano."),
    ("/config.php.old",          "CRITICAL","Versión antigua de config.php expuesta."),
    ("/config.yml",              "HIGH",    "Archivo de configuración YAML expuesto."),
    ("/config.yaml",             "HIGH",    "Archivo de configuración YAML expuesto."),
    ("/configuration.php",       "HIGH",    "Archivo de configuración Joomla expuesto."),
    ("/settings.py",             "HIGH",    "Archivo settings.py Django expuesto — SECRET_KEY y BD."),
    ("/app/config/parameters.yml","HIGH",   "Parámetros Symfony expuestos — credenciales de BD."),
    ("/.htaccess",               "HIGH",    "Archivo .htaccess expuesto — configuración del servidor."),
    ("/web.config",              "HIGH",    "web.config expuesto — configuración IIS."),
    ("/wp-config.php.bak",       "CRITICAL","Backup de wp-config.php expuesto — credenciales de BD."),
    ("/wp-config.php~",          "CRITICAL","Backup temporal de wp-config.php expuesto."),
    ("/wp-config.php.old",       "CRITICAL","Versión antigua de wp-config.php expuesta."),

    # ── Repositorios de código ───────────────────────────────────────────────
    ("/.git/HEAD",               "CRITICAL","Repositorio Git expuesto — código fuente descargable."),
    ("/.git/config",             "CRITICAL","Configuración Git expuesta — URLs y credenciales del repo."),
    ("/.git/COMMIT_EDITMSG",     "HIGH",    "Historial de commits Git expuesto."),
    ("/.git/logs/HEAD",          "HIGH",    "Log de commits Git expuesto."),
    ("/.svn/entries",            "CRITICAL","Repositorio SVN expuesto — código fuente descargable."),
    ("/.hg/hgrc",                "CRITICAL","Repositorio Mercurial expuesto."),

    # ── Dumps de base de datos ───────────────────────────────────────────────
    ("/backup.sql",              "CRITICAL","Dump SQL expuesto — acceso completo a la base de datos."),
    ("/db.sql",                  "CRITICAL","Dump de base de datos expuesto."),
    ("/dump.sql",                "CRITICAL","Dump SQL expuesto."),
    ("/database.sql",            "CRITICAL","Dump SQL expuesto."),
    ("/mysql.sql",               "CRITICAL","Dump MySQL expuesto."),
    ("/db_backup.sql",           "CRITICAL","Backup de BD expuesto."),
    ("/data.sql",                "CRITICAL","Dump de datos SQL expuesto."),
    ("/export.sql",              "CRITICAL","Export SQL expuesto."),
    ("/db/backup.sql",           "CRITICAL","Dump SQL en subdirectorio expuesto."),

    # ── Archivos de backup y archives ────────────────────────────────────────
    ("/backup.zip",              "CRITICAL","Archive de backup expuesto — posible código fuente y BD."),
    ("/backup.tar.gz",           "CRITICAL","Archive tar.gz de backup expuesto."),
    ("/backup.tar",              "CRITICAL","Archive tar de backup expuesto."),
    ("/backup.rar",              "CRITICAL","Archive RAR de backup expuesto."),
    ("/backup.7z",               "CRITICAL","Archive 7zip de backup expuesto."),
    ("/www.zip",                 "CRITICAL","Archive del directorio web expuesto."),
    ("/htdocs.zip",              "CRITICAL","Archive htdocs expuesto."),
    ("/public_html.zip",         "CRITICAL","Archive public_html expuesto."),
    ("/site.zip",                "CRITICAL","Archive del sitio expuesto."),
    ("/web.zip",                 "CRITICAL","Archive web expuesto."),
    ("/backup",                  "HIGH",    "Directorio backup accesible."),
    ("/backups",                 "HIGH",    "Directorio backups accesible."),
    ("/old",                     "MEDIUM",  "Directorio 'old' accesible — posible versión antigua del sitio."),

    # ── Logs y debug ─────────────────────────────────────────────────────────
    ("/storage/logs/laravel.log","CRITICAL","Log de Laravel expuesto — stack traces con rutas, queries y datos."),
    ("/logs/error.log",          "HIGH",    "Log de errores expuesto — stack traces y datos internos."),
    ("/logs/debug.log",          "HIGH",    "Log de debug expuesto."),
    ("/log/error.log",           "HIGH",    "Log de errores expuesto."),
    ("/error.log",               "HIGH",    "Log de errores expuesto."),
    ("/debug.log",               "HIGH",    "Log de debug expuesto."),
    ("/application.log",         "HIGH",    "Log de aplicación expuesto."),
    ("/phpinfo.php",             "HIGH",    "phpinfo() expuesto — configuración completa de PHP/servidor."),
    ("/info.php",                "HIGH",    "phpinfo() expuesto."),
    ("/test.php",                "MEDIUM",  "Archivo de test PHP expuesto."),
    ("/debug.php",               "HIGH",    "Archivo de debug PHP expuesto."),

    # ── Paneles de administración ────────────────────────────────────────────
    ("/admin",                   "MEDIUM",  "Panel de administración accesible."),
    ("/administrator",           "MEDIUM",  "Panel de administración accesible."),
    ("/wp-admin",                "MEDIUM",  "Panel WordPress accesible."),
    ("/wp-login.php",            "MEDIUM",  "Login WordPress expuesto — objetivo de fuerza bruta."),
    ("/phpmyadmin",              "HIGH",    "phpMyAdmin expuesto — acceso directo a base de datos."),
    ("/pma",                     "HIGH",    "phpMyAdmin (ruta alternativa) expuesto."),
    ("/adminer.php",             "HIGH",    "Adminer (gestor BD web) expuesto."),
    ("/adminer",                 "HIGH",    "Adminer expuesto."),
    ("/cpanel",                  "HIGH",    "Panel de control cPanel accesible."),
    ("/webmail",                 "MEDIUM",  "Webmail expuesto."),

    # ── APIs y documentación ─────────────────────────────────────────────────
    ("/api/v1",                  "LOW",     "API v1 expuesta — verificar autenticación."),
    ("/api/v2",                  "LOW",     "API v2 expuesta."),
    ("/swagger",                 "MEDIUM",  "Swagger UI expuesto — documentación de API accesible."),
    ("/swagger-ui.html",         "MEDIUM",  "Swagger UI expuesto."),
    ("/api-docs",                "MEDIUM",  "Documentación de API expuesta."),
    ("/graphql",                 "MEDIUM",  "Endpoint GraphQL expuesto — probar introspección."),
    ("/graphiql",                "MEDIUM",  "GraphiQL IDE expuesto — exploración de API GraphQL."),
    ("/actuator/env",            "CRITICAL","Spring Boot env — expone variables de entorno y credenciales."),
    ("/actuator/health",         "MEDIUM",  "Spring Boot health endpoint expuesto."),
    ("/server-status",           "MEDIUM",  "Apache server-status expuesto."),
    ("/nginx_status",            "MEDIUM",  "Nginx status expuesto."),

    # ── Dependencias y metadatos de desarrollo ───────────────────────────────
    ("/composer.json",           "LOW",     "composer.json expuesto — revela dependencias PHP y versiones."),
    ("/composer.lock",           "MEDIUM",  "composer.lock expuesto — versiones exactas con CVEs potenciales."),
    ("/package.json",            "LOW",     "package.json expuesto — dependencias Node.js."),
    ("/yarn.lock",               "LOW",     "yarn.lock expuesto — árbol de dependencias completo."),
    ("/Gemfile",                 "LOW",     "Gemfile Ruby expuesto."),
    ("/requirements.txt",        "LOW",     "requirements.txt Python expuesto."),
    ("/.DS_Store",               "MEDIUM",  ".DS_Store expuesto — revela estructura de directorios (macOS)."),
    ("/.idea/workspace.xml",     "MEDIUM",  "Proyecto JetBrains IDE expuesto — rutas y configuración local."),
    ("/Dockerfile",              "MEDIUM",  "Dockerfile expuesto — arquitectura e infraestructura del sistema."),
    ("/docker-compose.yml",      "HIGH",    "docker-compose.yml expuesto — credenciales y arquitectura."),
    ("/docker-compose.yaml",     "HIGH",    "docker-compose.yaml expuesto."),

    # ── Informativo ──────────────────────────────────────────────────────────
    ("/robots.txt",              "INFO",    "robots.txt encontrado — revisar rutas desindexadas."),
    ("/sitemap.xml",             "INFO",    "sitemap.xml encontrado."),
    ("/.well-known/security.txt","INFO",    "security.txt encontrado — política de divulgación responsable."),
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
            self._check_domain_backups(url)
            self._check_directory_listing(url)

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

    def _get_wildcard_baseline(self, base: str) -> dict:
        """Petición a ruta inventada para detectar servidores que responden igual a cualquier ruta."""
        canary = f"/canary-{os.urandom(8).hex()}-test"
        baseline = {"wildcard_codes": set()}
        try:
            resp = requests.get(base + canary, timeout=TIMEOUT, verify=False,
                                allow_redirects=True,
                                headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)"})
            baseline["wildcard_codes"].add(resp.status_code)
            if resp.status_code == 200:
                body = resp.text
                baseline["size"]    = len(body)
                baseline["hash"]    = hashlib.md5(body.encode()).hexdigest()
                baseline["snippet"] = body[:300]
        except Exception:
            pass
        return baseline

    def _is_wildcard_hit(self, resp, baseline: dict) -> bool:
        """Devuelve True si la respuesta es un falso positivo por wildcard."""
        if resp.status_code in baseline.get("wildcard_codes", set()):
            # Para 200: comparar contenido
            if resp.status_code == 200 and "hash" in baseline:
                body = resp.text
                if hashlib.md5(body.encode()).hexdigest() == baseline["hash"]:
                    return True
                size = len(body)
                if baseline["size"] > 0 and abs(size - baseline["size"]) / baseline["size"] < 0.05:
                    return True
                if body[:200] == baseline["snippet"][:200]:
                    return True
                return False
            # Para 403/401: si el canary ya devolvió ese código, todo es wildcard
            return True
        return False

    def _check_paths(self, url: str):
        base = url.rstrip("/")
        print(f"  [*] Comprobando {len(SENSITIVE_PATHS)} rutas sensibles...")

        baseline = self._get_wildcard_baseline(base)
        if baseline["wildcard_codes"]:
            codes = ", ".join(str(c) for c in baseline["wildcard_codes"])
            print(f"  [!] Wildcard detectado (HTTP {codes} para rutas inexistentes) — se filtrarán falsos positivos")

        encontradas = 0

        for path, severidad, descripcion in SENSITIVE_PATHS:
            full_url = base + path
            try:
                time.sleep(self.delay)
                resp = requests.get(full_url, timeout=TIMEOUT, verify=False,
                                    allow_redirects=False,
                                    headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)"})

                if resp.status_code in (200, 401, 403):
                    if self._is_wildcard_hit(resp, baseline):
                        continue
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

                    # Si .git está expuesto, intentar extraer datos sensibles
                    if path in ("/.git/HEAD", "/.git/config") and resp.status_code == 200:
                        self._check_git_exposure(base)

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

    def _check_domain_backups(self, url: str):
        """Prueba nombres de backup específicos del dominio objetivo (empresa.zip, empresa.sql...)."""
        base = url.rstrip("/")
        # Extraer nombre corto del dominio (empresa.com → empresa)
        domain = self.target.replace("https://", "").replace("http://", "").split("/")[0]
        name = domain.split(".")[0]  # solo la parte antes del primer punto
        if not name or len(name) < 2:
            return

        candidates = [
            f"/{name}.zip",         f"/{name}.tar.gz",   f"/{name}.sql",
            f"/{name}_backup.zip",  f"/{name}_backup.sql",
            f"/{name}.bak",         f"/{domain}.zip",
            f"/{domain}.sql",       f"/{domain}.tar.gz",
        ]

        baseline = self._get_wildcard_baseline(base)
        for path in candidates:
            try:
                time.sleep(self.delay)
                resp = requests.get(base + path, timeout=TIMEOUT, verify=False,
                                    allow_redirects=False,
                                    headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)"})
                if resp.status_code == 200 and not self._is_wildcard_hit(resp, baseline):
                    self._add(base + path, "BACKUP EXPUESTO", path,
                              f"Archivo de backup con nombre del dominio accesible: {path} "
                              f"({len(resp.content)} bytes). Puede contener código fuente o volcado de BD.",
                              "CRITICAL",
                              f"Eliminar {path} del servidor web inmediatamente. "
                              "Los backups deben almacenarse fuera del webroot con acceso restringido.")
                    print(f"  [CRITICAL] Backup del dominio expuesto: {path}")
            except Exception:
                pass

    def _check_directory_listing(self, url: str):
        """Detecta si el servidor tiene directory listing habilitado en directorios comunes."""
        base = url.rstrip("/")
        dirs_to_check = ["/uploads", "/images", "/files", "/documents", "/backup", "/backups",
                         "/logs", "/tmp", "/temp", "/assets", "/media", "/static"]
        for path in dirs_to_check:
            try:
                time.sleep(self.delay)
                resp = requests.get(base + path + "/", timeout=TIMEOUT, verify=False,
                                    allow_redirects=True,
                                    headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)"})
                if resp.status_code == 200:
                    body = resp.text.lower()
                    # Firmas de directory listing de Apache/Nginx
                    if any(sig in body for sig in ["index of /", "directory listing", "parent directory",
                                                    "[dir]", "[txt]", "last modified"]):
                        self._add(base + path, "DIRECTORY LISTING", path,
                                  f"El directorio {path}/ muestra su contenido públicamente. "
                                  "Cualquier visitante puede ver y descargar todos los archivos.",
                                  "HIGH",
                                  f"Deshabilitar directory listing: añadir 'Options -Indexes' en .htaccess "
                                  f"o 'autoindex off;' en Nginx para el directorio {path}.")
                        print(f"  [HIGH] Directory listing activo: {path}/")
            except Exception:
                pass

    def _check_git_exposure(self, base_url: str):
        """Cuando .git está expuesto, intenta extraer credenciales y datos sensibles."""
        git_files = [
            ("/.git/config",        self._parse_git_config),
            ("/.git/COMMIT_EDITMSG", self._parse_git_commit),
            ("/.git/logs/HEAD",     self._parse_git_log),
        ]
        found_sensitive = []
        for path, parser in git_files:
            try:
                resp = requests.get(base_url + path, timeout=TIMEOUT, verify=False,
                                    headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)"})
                if resp.status_code == 200 and len(resp.text) > 5:
                    result = parser(resp.text)
                    if result:
                        found_sensitive.append(result)
            except Exception:
                pass

        if found_sensitive:
            self._add(base_url + "/.git", "GIT EXPUESTO", "Datos sensibles en repositorio Git",
                      "Se extrajo información sensible del repositorio Git expuesto: " +
                      " | ".join(found_sensitive[:3]),
                      "CRITICAL",
                      "Bloquear acceso a /.git/ inmediatamente (deny from all en .htaccess o "
                      "location ~* /\\.git { deny all; } en Nginx). "
                      "Revocar y rotar todas las credenciales que hayan estado en el repositorio.")
            print(f"  [CRITICAL] Datos sensibles extraídos de .git: {found_sensitive[0][:80]}")

    def _parse_git_config(self, text: str) -> str:
        """Extrae URLs y posibles credenciales de .git/config."""
        lines = []
        for line in text.splitlines():
            line = line.strip()
            if "url = " in line:
                # URLs con credenciales embebidas: https://user:pass@github.com/...
                if "@" in line and "://" in line:
                    lines.append(f"Credencial en URL remota: {line}")
                else:
                    lines.append(f"Repo remoto: {line}")
            if any(k in line.lower() for k in ("password", "token", "secret", "key", "passwd")):
                lines.append(f"Posible credencial: {line[:80]}")
        return " | ".join(lines[:3]) if lines else ""

    def _parse_git_commit(self, text: str) -> str:
        commit_msg = text.strip()[:120]
        if commit_msg:
            return f"Último commit: '{commit_msg}'"
        return ""

    def _parse_git_log(self, text: str) -> str:
        lines = [l for l in text.splitlines() if l.strip()]
        if lines:
            return f"Historial de {len(lines)} commits expuesto"
        return ""

    def _add(self, url, tipo, nombre, descripcion, severidad, recomendacion):
        self.findings.append({
            "url":           url,
            "tipo":          tipo,
            "nombre":        nombre,
            "descripcion":   descripcion,
            "severidad":     severidad,
            "recomendacion": recomendacion,
        })
