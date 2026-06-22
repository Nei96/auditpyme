"""
Módulo de Cloud Storage Misconfiguration — AuditPyme
Detecta buckets S3, Azure Blob, GCP y DigitalOcean Spaces mal configurados.
"""

import requests
import urllib3
import re
import socket

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
TIMEOUT = 8
UA = "Mozilla/5.0 (compatible; AuditPyme/1.0)"

# Regiones S3 a probar
S3_REGIONS = [
    "s3", "s3.eu-west-1", "s3.eu-west-2", "s3.eu-west-3",
    "s3.eu-central-1", "s3.eu-south-1", "s3.us-east-1",
    "s3.us-west-1", "s3.us-west-2", "s3.ap-southeast-1",
]

# Sufijos de nombre de bucket a generar desde el dominio
BUCKET_SUFFIXES = [
    "", "-backup", "-backups", "-bak", "-assets", "-static",
    "-media", "-files", "-uploads", "-images", "-docs",
    "-documents", "-data", "-logs", "-dev", "-staging",
    "-prod", "-production", "-test", "-public", "-private",
    ".com", ".es", "-bucket", "-storage", "-web", "-cdn",
]

# Prefijos adicionales a probar
BUCKET_PREFIXES = [
    "", "backup-", "backups-", "static-", "assets-",
    "media-", "files-", "uploads-", "dev-", "staging-",
]


class CloudStorageScanner:

    def __init__(self, target: str, recon_data: dict = None):
        self.target = target
        self.recon_data = recon_data or {}
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA})
        self.session.verify = False
        self._base_name = self._extract_base_name(target)
        self._candidates = self._generate_candidates()

    def scan(self) -> list:
        print(f"\n  [*] Cloud Storage scan: {self.target} ({len(self._candidates)} candidatos)")
        for name in self._candidates:
            self._check_s3(name)
            self._check_azure(name)
            self._check_gcp(name)
            self._check_digitalocean(name)

        # También buscar buckets referenciados en el HTML del sitio
        self._find_buckets_in_html()

        if not self.findings:
            print("  [OK] No se detectaron buckets cloud mal configurados")
        return self.findings

    # ── Generación de candidatos ──────────────────────────────────────────────

    def _generate_candidates(self) -> list:
        names = set()
        base = self._base_name
        # Reemplazar puntos por guiones (S3 no acepta puntos en nombres con HTTPS)
        base_clean = base.replace(".", "-").replace("_", "-")

        for prefix in BUCKET_PREFIXES:
            for suffix in BUCKET_SUFFIXES:
                for b in (base, base_clean):
                    name = f"{prefix}{b}{suffix}".lower()
                    name = re.sub(r'[^a-z0-9\-]', '-', name).strip('-')
                    if 3 <= len(name) <= 63:
                        names.add(name)
        return list(names)[:80]

    # ── AWS S3 ────────────────────────────────────────────────────────────────

    def _check_s3(self, bucket_name: str):
        for region in S3_REGIONS[:4]:
            url = f"https://{bucket_name}.{region}.amazonaws.com"
            try:
                r = self.session.get(url, timeout=TIMEOUT)
                status = r.status_code

                if status == 200:
                    # Bucket público con listado activo
                    content = self._parse_s3_listing(r.text)
                    self._add(
                        "CRITICAL",
                        f"AWS S3 — Bucket público con listado activo: {bucket_name}",
                        f"El bucket s3://{bucket_name} es públicamente accesible y lista su contenido. "
                        f"URL: {url}\n"
                        f"Archivos encontrados ({len(content)}): {', '.join(content[:5])}{'...' if len(content) > 5 else ''}",
                        "Acceso público a todos los archivos del bucket: documentos, backups, "
                        "código fuente, imágenes, datos de clientes. Potencial RCE si contiene "
                        "archivos de configuración con credenciales o claves API.",
                        "Deshabilitar el acceso público en la consola AWS S3: "
                        "'Block all public access'. "
                        "Usar IAM policies para restringir el acceso. "
                        "Revisar todos los archivos del bucket para detectar datos sensibles."
                    )
                    print(f"  [CRITICAL] S3 público con listado: {bucket_name} ({len(content)} archivos)")
                    return

                elif status == 403:
                    # Bucket existe pero acceso denegado — reportar como info
                    self._add(
                        "LOW",
                        f"AWS S3 — Bucket existe: {bucket_name}",
                        f"El bucket s3://{bucket_name} existe pero el acceso está denegado (HTTP 403). "
                        f"URL: {url}",
                        "El bucket existe y está asociado al objetivo. "
                        "Aunque el acceso público está bloqueado, confirma la presencia "
                        "de infraestructura cloud que puede tener otras configuraciones débiles.",
                        "Verificar que el bucket tenga 'Block all public access' activado. "
                        "Auditar las IAM policies y ACLs del bucket."
                    )
                    print(f"  [LOW] S3 existe (403): {bucket_name}")
                    return

                elif "NoSuchBucket" in r.text:
                    continue  # No existe

            except Exception:
                pass

    def _parse_s3_listing(self, xml_text: str) -> list:
        return re.findall(r'<Key>([^<]+)</Key>', xml_text)

    # ── Azure Blob Storage ────────────────────────────────────────────────────

    def _check_azure(self, name: str):
        # Contenedores Azure comunes
        containers = ["", "$web", "public", "files", "backups", "assets", "media", "uploads"]
        base_url = f"https://{name}.blob.core.windows.net"

        # Primero verificar si la cuenta existe
        try:
            r = self.session.get(base_url, timeout=TIMEOUT)
            if "The specified resource does not exist" in r.text or r.status_code == 404:
                return
            if r.status_code not in (200, 400, 403, 409):
                return
        except Exception:
            return

        for container in containers:
            url = f"{base_url}/{container}?restype=container&comp=list" if container else \
                  f"{base_url}?comp=list&include=metadata"
            try:
                r = self.session.get(url, timeout=TIMEOUT)
                if r.status_code == 200 and ("<EnumerationResults" in r.text or "<Blobs>" in r.text):
                    blobs = re.findall(r'<Name>([^<]+)</Name>', r.text)
                    container_display = container or "(root)"
                    self._add(
                        "CRITICAL",
                        f"Azure Blob — Contenedor público accesible: {name}/{container_display}",
                        f"El contenedor Azure Blob '{container_display}' en la cuenta '{name}' "
                        f"es públicamente accesible y lista su contenido. URL: {url}\n"
                        f"Blobs encontrados ({len(blobs)}): {', '.join(blobs[:5])}{'...' if len(blobs) > 5 else ''}",
                        "Acceso público a todos los blobs del contenedor. "
                        "Puede contener backups, documentos de clientes, código fuente, "
                        "archivos de configuración con credenciales.",
                        "En Azure Portal: Storage Account → Containers → Change access level to 'Private'. "
                        "Activar 'Allow Blob public access: Disabled' en la cuenta de almacenamiento. "
                        "Revisar todos los blobs para detectar datos sensibles expuestos."
                    )
                    print(f"  [CRITICAL] Azure Blob público: {name}/{container_display} ({len(blobs)} blobs)")
                    return
            except Exception:
                pass

    # ── Google Cloud Storage ──────────────────────────────────────────────────

    def _check_gcp(self, name: str):
        urls = [
            f"https://storage.googleapis.com/{name}",
            f"https://{name}.storage.googleapis.com",
        ]
        for url in urls:
            try:
                r = self.session.get(url, timeout=TIMEOUT)
                if r.status_code == 200 and "ListBucketResult" in r.text:
                    objects = re.findall(r'<Key>([^<]+)</Key>', r.text)
                    self._add(
                        "CRITICAL",
                        f"GCP Cloud Storage — Bucket público: {name}",
                        f"El bucket GCS gs://{name} es públicamente accesible. "
                        f"URL: {url}\n"
                        f"Objetos encontrados ({len(objects)}): {', '.join(objects[:5])}{'...' if len(objects) > 5 else ''}",
                        "Acceso público a todos los objetos del bucket de Google Cloud Storage.",
                        "En GCP Console: Cloud Storage → Bucket → Permissions → "
                        "Eliminar 'allUsers' y 'allAuthenticatedUsers'. "
                        "Activar Uniform Bucket-Level Access."
                    )
                    print(f"  [CRITICAL] GCP Storage público: {name} ({len(objects)} objetos)")
                    return
                elif r.status_code == 403 and "AccessDenied" not in r.text:
                    # Bucket existe
                    self._add(
                        "LOW",
                        f"GCP Cloud Storage — Bucket existe: {name}",
                        f"El bucket gs://{name} existe pero el acceso está restringido (HTTP 403). URL: {url}",
                        "Bucket GCS asociado al objetivo. Acceso actualmente restringido.",
                        "Verificar permisos IAM y eliminar acceso público si existe."
                    )
                    return
            except Exception:
                pass

    # ── DigitalOcean Spaces ───────────────────────────────────────────────────

    def _check_digitalocean(self, name: str):
        regions = ["nyc3", "ams3", "sgp1", "fra1", "sfo3"]
        for region in regions[:3]:
            url = f"https://{name}.{region}.digitaloceanspaces.com"
            try:
                r = self.session.get(url, timeout=TIMEOUT)
                if r.status_code == 200 and "ListBucketResult" in r.text:
                    objects = re.findall(r'<Key>([^<]+)</Key>', r.text)
                    self._add(
                        "CRITICAL",
                        f"DigitalOcean Spaces — Space público: {name}",
                        f"El Space DO '{name}' en región {region} es públicamente accesible. "
                        f"URL: {url}\nObjetos: {', '.join(objects[:5])}",
                        "Acceso público a todos los archivos del Space de DigitalOcean.",
                        "En DO Control Panel: Spaces → Settings → File Listing: Disabled. "
                        "Revisar los permisos de cada objeto individual."
                    )
                    print(f"  [CRITICAL] DO Spaces público: {name} ({len(objects)} objetos)")
                    return
            except Exception:
                pass

    # ── Búsqueda en HTML del sitio ────────────────────────────────────────────

    def _find_buckets_in_html(self):
        """Busca URLs de buckets cloud referenciadas en el HTML del sitio."""
        bucket_patterns = [
            r'https?://([a-z0-9\-]+)\.s3[a-z0-9\-]*\.amazonaws\.com',
            r'https?://s3[a-z0-9\-]*\.amazonaws\.com/([a-z0-9\-]+)',
            r'https?://([a-z0-9\-]+)\.blob\.core\.windows\.net',
            r'https?://storage\.googleapis\.com/([a-z0-9\-]+)',
            r'https?://([a-z0-9\-]+)\.storage\.googleapis\.com',
            r'https?://([a-z0-9\-]+)\.[a-z0-9]+\.digitaloceanspaces\.com',
        ]

        for base_url in self._build_base_urls():
            try:
                r = self.session.get(base_url, timeout=TIMEOUT)
                for pattern in bucket_patterns:
                    for m in re.finditer(pattern, r.text, re.IGNORECASE):
                        bucket = m.group(1)
                        full_url = m.group(0)
                        # Verificar si el bucket referenciado es accesible
                        try:
                            br = self.session.get(full_url, timeout=TIMEOUT)
                            if br.status_code == 200 and (
                                "ListBucketResult" in br.text or "BucketResult" in br.text
                            ):
                                self._add(
                                    "HIGH",
                                    f"Bucket cloud referenciado y público — {bucket}",
                                    f"El bucket '{bucket}' está referenciado en el HTML del sitio "
                                    f"y es públicamente accesible con listado activo. URL: {full_url}",
                                    "Bucket con listado público referenciado directamente desde el sitio. "
                                    "Facilita el acceso a todos sus contenidos.",
                                    "Deshabilitar el listado público del bucket. "
                                    "Usar URLs firmadas (presigned URLs) para acceso temporal."
                                )
                                print(f"  [HIGH] Bucket referenciado y público: {bucket}")
                        except Exception:
                            pass
            except Exception:
                pass

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _extract_base_name(self, target: str) -> str:
        # Eliminar protocolo y www
        name = re.sub(r'^https?://', '', target).split("/")[0]
        name = re.sub(r'^www\.', '', name)
        return name.lower()

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
            "severidad": severidad, "tipo": "Cloud Storage",
            "nombre": nombre, "descripcion": descripcion,
            "impacto": impacto, "recomendacion": recomendacion,
        })
