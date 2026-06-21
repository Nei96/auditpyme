"""
Módulo de recursos expuestos — AuditPyme
Detecta paneles de administración accesibles, archivos sensibles y endpoints de debug.
"""

import requests
import urllib3
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
TIMEOUT = 10
UA = "Mozilla/5.0 (compatible; AuditPyme/1.0)"

# ── Paneles de administración ─────────────────────────────────────────────────

ADMIN_PANELS = [
    # (ruta_o_puerto, nombre, tipo, severidad)
    # phpMyAdmin — gestión de bases de datos MySQL
    ("/phpmyadmin/",       "phpMyAdmin",   "db",      "CRITICAL"),
    ("/phpmyadmin",        "phpMyAdmin",   "db",      "CRITICAL"),
    ("/pma/",              "phpMyAdmin",   "db",      "CRITICAL"),
    ("/pma",               "phpMyAdmin",   "db",      "CRITICAL"),
    ("/myadmin/",          "phpMyAdmin",   "db",      "CRITICAL"),
    ("/myadmin",           "phpMyAdmin",   "db",      "CRITICAL"),
    ("/mysql/",            "phpMyAdmin",   "db",      "CRITICAL"),
    ("/db/",               "phpMyAdmin",   "db",      "CRITICAL"),
    ("/dbadmin/",          "phpMyAdmin",   "db",      "CRITICAL"),
    # Adminer — gestor de BD en un solo fichero PHP
    ("/adminer.php",       "Adminer",      "db",      "CRITICAL"),
    ("/adminer/",          "Adminer",      "db",      "CRITICAL"),
    ("/adminer",           "Adminer",      "db",      "CRITICAL"),
    ("/db.php",            "Adminer",      "db",      "CRITICAL"),
    # Paneles de hosting
    ("/cpanel",            "cPanel",       "hosting", "HIGH"),
    ("/whm",               "WHM",          "hosting", "HIGH"),
    ("/plesk",             "Plesk",        "hosting", "HIGH"),
    ("/webmin",            "Webmin",       "hosting", "HIGH"),
    # Paneles genéricos de CMS
    ("/wp-admin/",         "WordPress Admin",   "cms",  "HIGH"),
    ("/administrator/",    "Joomla Admin",      "cms",  "HIGH"),
    ("/admin/",            "Panel Admin",       "cms",  "MEDIUM"),
    ("/admin",             "Panel Admin",       "cms",  "MEDIUM"),
    ("/manager/",          "Tomcat Manager",    "java", "CRITICAL"),
    ("/manager/html",      "Tomcat Manager",    "java", "CRITICAL"),
    ("/host-manager/html", "Tomcat Host Manager","java","CRITICAL"),
    # Herramientas de observabilidad
    ("/grafana",           "Grafana",      "monitoring", "HIGH"),
    ("/kibana",            "Kibana",       "monitoring", "HIGH"),
    ("/_plugin/kibana",    "Kibana",       "monitoring", "HIGH"),
    # Swagger / API docs (exposición de endpoints)
    ("/swagger-ui.html",   "Swagger UI",   "api",     "MEDIUM"),
    ("/swagger-ui/",       "Swagger UI",   "api",     "MEDIUM"),
    ("/api/docs",          "API Docs",     "api",     "MEDIUM"),
    ("/api/swagger.json",  "Swagger JSON", "api",     "MEDIUM"),
    ("/openapi.json",      "OpenAPI JSON", "api",     "MEDIUM"),
    ("/v1/swagger.json",   "Swagger v1",   "api",     "MEDIUM"),
    ("/v2/api-docs",       "Swagger v2",   "api",     "MEDIUM"),
    # phpinfo
    ("/phpinfo.php",       "phpinfo()",    "debug",   "HIGH"),
    ("/info.php",          "phpinfo()",    "debug",   "HIGH"),
    ("/php_info.php",      "phpinfo()",    "debug",   "HIGH"),
    ("/test.php",          "test.php",     "debug",   "MEDIUM"),
    # Server-status / server-info (Apache)
    ("/server-status",     "Apache server-status", "debug", "HIGH"),
    ("/server-info",       "Apache server-info",   "debug", "MEDIUM"),
    # Actuator Spring Boot
    ("/actuator",          "Spring Actuator",      "java",  "HIGH"),
    ("/actuator/env",      "Spring Actuator /env", "java",  "CRITICAL"),
    ("/actuator/heapdump", "Spring Heapdump",      "java",  "CRITICAL"),
    ("/actuator/mappings", "Spring Mappings",      "java",  "MEDIUM"),
]

# Puertos de paneles que corren en puerto propio
ADMIN_PANEL_PORTS = [
    (2082,  "http",  "/",    "cPanel HTTP"),
    (2083,  "https", "/",    "cPanel HTTPS"),
    (2086,  "http",  "/",    "WHM HTTP"),
    (2087,  "https", "/",    "WHM HTTPS"),
    (10000, "https", "/",    "Webmin"),
    (8880,  "http",  "/",    "Plesk HTTP"),
    (8443,  "https", "/",    "Plesk HTTPS"),
    (9000,  "http",  "/",    "Portainer / PHP-FPM"),
    (3000,  "http",  "/",    "Grafana"),
    (5601,  "http",  "/",    "Kibana"),
    (8161,  "http",  "/admin/", "ActiveMQ Admin"),
    (4848,  "https", "/",    "GlassFish Admin"),
    (9200,  "http",  "/",    "Elasticsearch API"),
    (6379,  "tcp",   None,   "Redis sin auth"),
    (27017, "tcp",   None,   "MongoDB sin auth"),
]

# Credenciales por defecto por panel
PANEL_DEFAULT_CREDS = {
    "phpMyAdmin":   [("root", ""), ("root", "root"), ("root", "toor"),
                     ("admin", "admin"), ("pma", "pma")],
    "Adminer":      [("root", ""), ("root", "root"), ("admin", "admin")],
    "Tomcat Manager": [("admin", "admin"), ("tomcat", "tomcat"), ("admin", ""),
                       ("manager", "manager"), ("role1", "role1")],
    "Grafana":      [("admin", "admin"), ("admin", "")],
    "Kibana":       [("elastic", "changeme"), ("elastic", "elastic")],
    "Portainer":    [("admin", "admin"), ("admin", "portainer")],
}

# ── Archivos sensibles ────────────────────────────────────────────────────────

SENSITIVE_FILES = [
    # Configuración con credenciales
    ("/.env",                    "CRITICAL", "Variables de entorno — credenciales y claves API",
     lambda t: any(k in t for k in ("DB_PASSWORD", "APP_KEY", "SECRET", "API_KEY", "PASSWORD"))),
    ("/.env.local",              "CRITICAL", "Variables de entorno local",
     lambda t: any(k in t for k in ("DB_", "APP_", "SECRET", "KEY", "PASS"))),
    ("/.env.production",         "CRITICAL", "Variables de entorno de producción",
     lambda t: any(k in t for k in ("DB_", "APP_", "SECRET", "KEY", "PASS"))),
    ("/.env.backup",             "CRITICAL", "Backup de variables de entorno",
     lambda t: len(t) > 20),
    ("/config.php",              "CRITICAL", "Archivo de configuración PHP",
     lambda t: any(k in t for k in ("password", "db_pass", "mysql_pass", "secret"))),
    ("/configuration.php",       "CRITICAL", "Configuración Joomla con credenciales",
     lambda t: "password" in t.lower()),
    ("/database.yml",            "CRITICAL", "Configuración de BD Ruby on Rails",
     lambda t: "password" in t.lower()),
    ("/config/database.php",     "CRITICAL", "Configuración de BD Laravel/CodeIgniter",
     lambda t: "password" in t.lower()),
    ("/settings.py",             "HIGH",     "Settings Django — SECRET_KEY, BD",
     lambda t: "SECRET_KEY" in t or "DATABASES" in t),
    ("/app/config/parameters.yml","HIGH",    "Parámetros Symfony",
     lambda t: "password" in t.lower()),
    # WordPress
    ("/wp-config.php.bak",       "CRITICAL", "Backup de wp-config.php — credenciales MySQL",
     lambda t: len(t) > 100),
    ("/wp-config.php~",          "CRITICAL", "Backup de wp-config.php",
     lambda t: len(t) > 100),
    ("/wp-config.php.old",       "CRITICAL", "Backup wp-config.php antiguo",
     lambda t: len(t) > 100),
    ("/wp-config.txt",           "CRITICAL", "wp-config.php guardado como .txt",
     lambda t: "DB_PASSWORD" in t),
    # Git / Control de versiones
    ("/.git/config",             "HIGH",     "Repositorio Git expuesto — acceso al código fuente",
     lambda t: "[core]" in t or "repositoryformatversion" in t),
    ("/.git/HEAD",               "HIGH",     "Repositorio Git expuesto",
     lambda t: "ref:" in t or "HEAD" in t),
    ("/.svn/entries",            "HIGH",     "Repositorio SVN expuesto",
     lambda t: len(t) > 10),
    # Backups
    ("/backup.zip",              "CRITICAL", "Backup del sitio expuesto",
     lambda t: t[:4] in ("PK\x03\x04", b"PK\x03\x04") or len(t) > 1000),
    ("/backup.sql",              "CRITICAL", "Dump SQL expuesto — datos de la base de datos",
     lambda t: any(k in t for k in ("INSERT INTO", "CREATE TABLE", "DROP TABLE"))),
    ("/backup.tar.gz",           "CRITICAL", "Backup tar.gz del sitio",
     lambda t: len(t) > 100),
    ("/db_backup.sql",           "CRITICAL", "Backup SQL de la BD",
     lambda t: any(k in t for k in ("INSERT INTO", "CREATE TABLE"))),
    ("/dump.sql",                "CRITICAL", "Dump SQL expuesto",
     lambda t: any(k in t for k in ("INSERT INTO", "CREATE TABLE"))),
    ("/site.sql",                "CRITICAL", "SQL del sitio expuesto",
     lambda t: any(k in t for k in ("INSERT INTO", "CREATE TABLE"))),
    # Logs
    ("/error_log",               "HIGH",     "Log de errores PHP expuesto — rutas y stack traces",
     lambda t: any(k in t for k in ("PHP", "Error", "Warning", "Fatal"))),
    ("/php_error.log",           "HIGH",     "Log de errores PHP",
     lambda t: "PHP" in t or "Error" in t),
    ("/logs/error.log",          "HIGH",     "Log de errores del servidor",
     lambda t: len(t) > 10),
    ("/storage/logs/laravel.log","HIGH",     "Log de Laravel — stack traces y variables",
     lambda t: "Exception" in t or "Error" in t),
    # Credenciales adicionales
    ("/.htpasswd",               "CRITICAL", "Archivo htpasswd expuesto — hashes de contraseñas",
     lambda t: re.search(r'\w+:\$', t) is not None),
    ("/sftp-config.json",        "CRITICAL", "Credenciales SFTP de Sublime Text",
     lambda t: "password" in t.lower() or "remote_path" in t),
    ("/ftpsync.settings",        "HIGH",     "Credenciales FTP de Sublime SFTP",
     lambda t: "password" in t.lower()),
    # Debug / info
    ("/phpinfo.php",             "HIGH",     "phpinfo() expuesto — configuración completa del servidor",
     lambda t: "PHP Version" in t),
    ("/info.php",                "HIGH",     "phpinfo() expuesto",
     lambda t: "PHP Version" in t),
    # Composer / npm — revelan dependencias y versiones
    ("/composer.json",           "LOW",      "composer.json expuesto — dependencias y versiones",
     lambda t: '"require"' in t or '"name"' in t),
    ("/composer.lock",           "MEDIUM",   "composer.lock expuesto — versiones exactas de dependencias",
     lambda t: '"packages"' in t),
    ("/package.json",            "LOW",      "package.json expuesto",
     lambda t: '"dependencies"' in t or '"name"' in t),
    # macOS artefacto
    ("/.DS_Store",               "LOW",      ".DS_Store expuesto — lista de archivos del directorio",
     lambda t: "\x00\x00\x00\x01\x42\x75" in t or "Bud1" in t),
]

# ── Detección de fingerprints de paneles ──────────────────────────────────────

PANEL_FINGERPRINTS = {
    "phpMyAdmin":      ["phpMyAdmin", "pma_", "PMA_", "phpmyadmin"],
    "Adminer":         ["adminer", "Adminer", "db_structure"],
    "Tomcat Manager":  ["Apache Tomcat", "Tomcat Web Application Manager"],
    "Grafana":         ["Grafana", "grafana"],
    "Kibana":          ["Kibana", "kibana"],
    "Spring Actuator": ["org.springframework", "UP", "diskSpace"],
    "Elasticsearch":   ['"cluster_name"', '"status"', '"tagline"'],
    "cPanel":          ["cPanel", "cpanel", "WHM"],
    "Webmin":          ["Webmin", "webmin"],
    "Plesk":           ["Plesk", "plesk"],
    "Swagger UI":      ["swagger-ui", "Swagger UI", "swaggerUi", "openapi"],
    "WordPress Admin": ["wp-login", "wp-admin", "WordPress"],
}


class ExposedScanner:
    """Detecta paneles de administración expuestos y archivos sensibles."""

    def __init__(self, target: str, recon_data: dict = None, stealth: bool = False):
        self.target = target
        self.recon_data = recon_data or {}
        self.findings = []
        self.delay_s = 0.5 if stealth else 0
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA})
        self.session.verify = False
        self._base_urls = self._build_base_urls()

    def scan(self) -> list:
        print(f"\n  [*] Buscando paneles expuestos y archivos sensibles: {self.target}")
        for base in self._base_urls:
            self._scan_admin_paths(base)
            self._scan_sensitive_files(base)
        self._scan_admin_ports()

        if not self.findings:
            print("  [OK] No se detectaron paneles ni archivos sensibles expuestos")
        return self.findings

    # ── Paneles admin por ruta ────────────────────────────────────────────────

    def _scan_admin_paths(self, base_url: str):
        print("  [*] Comprobando rutas de paneles de administración...")
        seen: set[str] = set()

        for path, name, tipo, sev in ADMIN_PANELS:
            url = base_url + path
            try:
                r = self.session.get(url, timeout=TIMEOUT, allow_redirects=True)
                if r.status_code not in (200, 401, 403):
                    continue
                if not self._fingerprint_panel(name, r.text, r.headers):
                    continue
                if name in seen:
                    continue
                seen.add(name)

                accessible = r.status_code == 200
                self._add_panel(sev, name, tipo, url, accessible)

                # Probar credenciales por defecto si es accesible y tenemos creds
                if accessible and name in PANEL_DEFAULT_CREDS:
                    self._try_default_creds(name, url, r.text)

            except Exception:
                pass

    def _fingerprint_panel(self, name: str, html: str, headers: dict) -> bool:
        """Verifica que la respuesta realmente corresponde al panel esperado."""
        fingerprints = PANEL_FINGERPRINTS.get(name, [])
        if not fingerprints:
            return True
        return any(fp in html for fp in fingerprints)

    def _try_default_creds(self, panel_name: str, url: str, login_html: str):
        """Intenta login con credenciales por defecto según el tipo de panel."""
        creds = PANEL_DEFAULT_CREDS.get(panel_name, [])
        if not creds:
            return

        if "phpMyAdmin" in panel_name or "Adminer" in panel_name:
            self._try_phpmyadmin_creds(url, creds, panel_name)
        elif "Tomcat" in panel_name:
            self._try_basic_auth_creds(url, creds, panel_name)
        elif "Grafana" in panel_name:
            self._try_grafana_creds(url, creds)

    def _try_phpmyadmin_creds(self, url: str, creds: list, panel_name: str):
        import json
        print(f"    [*] Probando credenciales por defecto en {panel_name}...")
        for user, pwd in creds:
            try:
                # phpMyAdmin usa POST a index.php con pma_username/pma_password
                r = self.session.post(url.rstrip("/") + "/index.php", data={
                    "pma_username": user, "pma_password": pwd,
                    "server": "1", "lang": "es",
                }, timeout=TIMEOUT, allow_redirects=True)
                if r.status_code == 200 and "pma_token" in r.text:
                    self._add(
                        "CRITICAL",
                        f"{panel_name} — Credenciales por defecto válidas ({user}/{pwd})",
                        f"Acceso completo a phpMyAdmin con {user}:{pwd} en {url}. "
                        "Un atacante puede leer/modificar/eliminar toda la base de datos "
                        "y ejecutar comandos SQL arbitrarios (SELECT INTO OUTFILE → webshell).",
                        f"Cambiar las credenciales inmediatamente. Restringir el acceso a "
                        f"{panel_name} por IP o moverlo a una URL no predecible."
                    )
                    print(f"    [CRITICAL] {panel_name} login exitoso: {user}:{pwd}")
                    return
            except Exception:
                pass

    def _try_basic_auth_creds(self, url: str, creds: list, panel_name: str):
        print(f"    [*] Probando credenciales Basic Auth en {panel_name}...")
        for user, pwd in creds:
            try:
                r = self.session.get(url, auth=(user, pwd), timeout=TIMEOUT)
                if r.status_code == 200:
                    self._add(
                        "CRITICAL",
                        f"{panel_name} — Credenciales por defecto válidas ({user}/{pwd})",
                        f"Acceso completo a {panel_name} con {user}:{pwd} en {url}.",
                        f"Cambiar las credenciales por defecto de {panel_name} inmediatamente."
                    )
                    print(f"    [CRITICAL] {panel_name} login exitoso: {user}:{pwd}")
                    return
            except Exception:
                pass

    def _try_grafana_creds(self, url: str, creds: list):
        import json
        print("    [*] Probando credenciales por defecto en Grafana...")
        api_url = url.rstrip("/") + "/api/login"
        for user, pwd in creds:
            try:
                r = self.session.post(api_url,
                                      json={"user": user, "password": pwd},
                                      timeout=TIMEOUT)
                if r.status_code == 200 and "Logged in" in r.text:
                    self._add(
                        "CRITICAL",
                        f"Grafana — Credenciales por defecto válidas ({user}/{pwd})",
                        f"Acceso completo a Grafana con {user}:{pwd} en {url}. "
                        "Permite extraer datasources (credenciales de BBDD), crear alertas "
                        "y ejecutar consultas contra las fuentes de datos configuradas.",
                        "Cambiar la contraseña por defecto de Grafana y habilitar 2FA."
                    )
                    print(f"    [CRITICAL] Grafana login exitoso: {user}:{pwd}")
                    return
            except Exception:
                pass

    def _add_panel(self, sev: str, name: str, tipo: str, url: str, accessible: bool):
        estado = "accesible sin autenticación" if accessible else "con pantalla de login"
        impacto_map = {
            "db":      "Acceso completo a la base de datos: lectura, modificación, eliminación de datos y posible RCE via SQL.",
            "hosting": "Control total del hosting: crear cuentas, acceder a todos los dominios, modificar DNS y archivos.",
            "cms":     "Control del CMS: instalar plugins maliciosos, modificar contenido y ejecutar PHP.",
            "java":    "Despliegue de WAR maliciosos → RCE completo en el servidor de aplicaciones.",
            "monitoring": "Acceso a métricas, logs y potencialmente credenciales de datasources.",
            "api":     "Exposición completa de la superficie de ataque de la API.",
            "debug":   "Información sensible del servidor: versiones, rutas, configuración y variables.",
        }
        self._add(
            sev,
            f"Panel expuesto — {name}",
            f"{name} {estado} en {url}",
            impacto_map.get(tipo, "Acceso no autorizado a funcionalidades de administración."),
            f"Restringir el acceso a {url} por IP mediante firewall o .htaccess. "
            f"Si no se usa, desactivarlo o cambiar la ruta a una no predecible. "
            f"Habilitar autenticación fuerte y 2FA."
        )
        print(f"    [{sev}] Panel expuesto: {name} en {url}")

    # ── Paneles por puerto ────────────────────────────────────────────────────

    def _scan_admin_ports(self):
        """Detecta paneles que corren en puertos no estándar."""
        print("  [*] Comprobando puertos de paneles de administración...")
        for port, proto, path, name in ADMIN_PANEL_PORTS:
            if proto == "tcp":
                self._check_raw_port(port, name)
                continue
            url = f"{proto}://{self.target}:{port}{path or '/'}"
            try:
                r = self.session.get(url, timeout=5, allow_redirects=True)
                if r.status_code in (200, 401, 403):
                    self._add(
                        "HIGH",
                        f"Puerto de administración expuesto — {name} (:{port})",
                        f"{name} accesible en {url} (estado HTTP {r.status_code})",
                        "Paneles de administración expuestos a internet permiten ataques de "
                        "fuerza bruta y explotación de vulnerabilidades del panel.",
                        f"Filtrar el acceso al puerto {port} por firewall para permitir "
                        f"solo IPs autorizadas. No exponer {name} a internet."
                    )
                    print(f"    [HIGH] {name} accesible en puerto {port}")
            except Exception:
                pass

    def _check_raw_port(self, port: int, name: str):
        """Verifica si un servicio TCP sin HTTP responde (Redis, MongoDB)."""
        import socket
        try:
            s = socket.create_connection((self.target, port), timeout=3)
            s.close()
            self._add(
                "CRITICAL",
                f"Servicio expuesto sin autenticación — {name} (:{port})",
                f"{name} responde en {self.target}:{port} sin requerir autenticación",
                f"{name} expuesto a internet sin autenticación permite acceso completo "
                "a todos los datos almacenados y posible RCE.",
                f"Deshabilitar el acceso externo al puerto {port} mediante firewall. "
                f"Configurar autenticación obligatoria en {name}. "
                "Enlazar el servicio solo a 127.0.0.1 si no necesita acceso remoto."
            )
            print(f"    [CRITICAL] {name} expuesto en puerto {port} sin auth")
        except Exception:
            pass

    # ── Archivos sensibles ────────────────────────────────────────────────────

    def _scan_sensitive_files(self, base_url: str):
        print("  [*] Buscando archivos sensibles expuestos...")
        for path, sev, desc, validator in SENSITIVE_FILES:
            url = base_url + path
            try:
                r = self.session.get(url, timeout=TIMEOUT)
                if r.status_code != 200 or len(r.text) < 5:
                    continue
                if not validator(r.text):
                    continue

                # Extraer preview seguro (sin mostrar credenciales reales)
                preview = self._safe_preview(r.text, path)
                self._add(
                    sev,
                    f"Archivo sensible expuesto — {path}",
                    f"{desc}. URL: {url}\nPreview: {preview}",
                    self._get_file_impact(path, r.text),
                    self._get_file_remediation(path)
                )
                print(f"    [{sev}] {path} accesible")
            except Exception:
                pass

    def _safe_preview(self, content: str, path: str) -> str:
        """Genera un preview que confirma el hallazgo sin revelar credenciales."""
        if ".env" in path or "config" in path.lower():
            # Mostrar solo las claves, no los valores
            keys = re.findall(r'^([A-Z_]+)=', content, re.MULTILINE)
            return f"Variables: {', '.join(keys[:8])}{'...' if len(keys) > 8 else ''}"
        if ".sql" in path or "dump" in path:
            tables = re.findall(r'CREATE TABLE `?(\w+)`?', content)
            return f"Tablas: {', '.join(tables[:6])}{'...' if len(tables) > 6 else ''}"
        if ".git" in path:
            return content[:80].strip().replace("\n", " ")
        return content[:100].strip().replace("\n", " ")

    def _get_file_impact(self, path: str, content: str) -> str:
        if "wp-config" in path:
            return ("Contiene DB_NAME, DB_USER, DB_PASSWORD y claves secretas de WordPress. "
                    "Acceso total a la base de datos y posible RCE via serialización.")
        if ".env" in path:
            has_key = "APP_KEY" in content
            return (("APP_KEY expuesta → RCE via deserialización PHP (PHPGGC chain). " if has_key else "") +
                    "Credenciales de base de datos, servicios externos y claves API accesibles.")
        if ".git" in path:
            return ("El repositorio Git completo puede descargarse, exponiendo todo el código fuente, "
                    "historial de commits (con posibles credenciales antiguas) y estructura interna.")
        if ".sql" in path or "dump" in path or "backup" in path:
            return "Todos los datos de la base de datos expuestos: usuarios, contraseñas, datos de clientes."
        if ".htpasswd" in path:
            return "Hashes de contraseñas expuestos — crackeables offline con hashcat/john."
        if "phpinfo" in path or "info.php" in path:
            return ("Configuración completa del servidor: versión PHP, extensiones, rutas del sistema, "
                    "variables de entorno y cabeceras HTTP — información esencial para explotar vulnerabilidades.")
        if "sftp" in path or "ftpsync" in path:
            return "Credenciales FTP/SFTP en texto plano — acceso directo a los archivos del servidor."
        if "error_log" in path or ".log" in path:
            return "Stack traces y rutas del sistema filtran información sobre la arquitectura interna."
        return "Información sensible accesible públicamente."

    def _get_file_remediation(self, path: str) -> str:
        if "wp-config" in path:
            return ("Eliminar el archivo de backup inmediatamente. "
                    "Añadir en .htaccess: '<Files wp-config.php><Order deny,allow><Deny from all></Files>'. "
                    "Rotar todas las credenciales y claves de WordPress.")
        if ".env" in path:
            return ("Eliminar el archivo .env del directorio web accesible. "
                    "Moverlo fuera del DocumentRoot o bloquearlo en .htaccess/nginx.conf. "
                    "Rotar todas las claves y credenciales expuestas.")
        if ".git" in path:
            return ("Bloquear el acceso al directorio .git en el servidor web. "
                    "Nginx: 'location ~ /\\.git { deny all; }'. "
                    "Apache: 'RedirectMatch 404 /\\.git'. "
                    "Eliminar el repositorio del directorio web o usar .gitignore correctamente.")
        if ".sql" in path or "backup" in path:
            return ("Eliminar el archivo de backup del directorio web. "
                    "Guardar backups fuera del DocumentRoot o en almacenamiento privado (S3 con ACL privada).")
        if ".htpasswd" in path:
            return ("Mover .htpasswd fuera del DocumentRoot. "
                    "Añadir en .htaccess: '<Files .htpasswd><Order deny,allow><Deny from all></Files>'.")
        return (f"Bloquear el acceso a {path} en el servidor web. "
                "Eliminar el archivo si no es necesario.")

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
                           if port not in (80, 443) else f"{proto}://{self.target}")
                    if url not in urls:
                        urls.append(url)
        return urls or [f"https://{self.target}"]

    def _add(self, severidad: str, nombre: str, descripcion: str,
             impacto: str, recomendacion: str = ""):
        for f in self.findings:
            if f["nombre"] == nombre:
                return
        self.findings.append({
            "severidad":     severidad,
            "tipo":          "Exposed",
            "nombre":        nombre,
            "descripcion":   descripcion,
            "impacto":       impacto,
            "recomendacion": recomendacion,
        })
