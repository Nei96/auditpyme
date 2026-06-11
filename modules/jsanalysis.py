"""
Módulo de análisis de JavaScript — AuditPyme
Detecta: claves API y secretos hardcodeados, source maps expuestos,
endpoints internos y tokens en archivos JS públicos.
"""

import requests
import urllib3
import re
from urllib.parse import urljoin, urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
TIMEOUT = 12
UA = "Mozilla/5.0 (compatible; AuditPyme/1.0)"
MAX_JS_SIZE  = 2 * 1024 * 1024   # 2 MB por archivo
MAX_JS_FILES = 20                  # máximo archivos JS a analizar

# ── Patrones de secretos en código JS ────────────────────────────────────────
# Cada entrada: (nombre, regex, severidad, descripción del impacto)
SECRET_PATTERNS = [
    # AWS
    ("AWS Access Key",      r'AKIA[0-9A-Z]{16}',                                          "CRITICAL",
     "Clave de acceso AWS hardcodeada → acceso completo a la infraestructura cloud (S3, EC2, RDS...)."),
    ("AWS Secret Key",      r'(?i)aws.{0,20}secret.{0,20}["\'][0-9a-zA-Z/+]{40}["\']',   "CRITICAL",
     "AWS Secret Key expuesta → control total de la cuenta AWS."),

    # Stripe
    ("Stripe Secret Key",   r'sk_live_[0-9a-zA-Z]{24,}',                                  "CRITICAL",
     "Stripe Secret Key en producción → cargos a tarjetas, devoluciones, acceso a datos de pago."),
    ("Stripe Restricted",   r'rk_live_[0-9a-zA-Z]{24,}',                                  "HIGH",
     "Stripe Restricted Key expuesta."),
    ("Stripe Test Key",     r'sk_test_[0-9a-zA-Z]{24,}',                                  "MEDIUM",
     "Stripe Test Key expuesta — confirmar que no se usa en producción."),

    # Google
    ("Google API Key",      r'AIza[0-9A-Za-z\-_]{35}',                                   "HIGH",
     "Google API Key expuesta → posibles cargos por uso excesivo de Maps/Vision/Translate."),
    ("Firebase API Key",    r'(?i)firebase.{0,30}apiKey.{0,10}["\'][A-Za-z0-9\-_]{35,}', "HIGH",
     "Firebase API Key expuesta → acceso a base de datos Firestore si las reglas son permisivas."),
    ("Google OAuth",        r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',    "MEDIUM",
     "Google OAuth Client ID expuesto."),

    # Twilio / SendGrid / Mailgun
    ("Twilio Account SID",  r'AC[a-z0-9]{32}',                                            "HIGH",
     "Twilio SID expuesto → envío de SMS/llamadas a cargo de la empresa."),
    ("Twilio Auth Token",   r'(?i)twilio.{0,20}["\'][a-z0-9]{32}["\']',                  "CRITICAL",
     "Twilio Auth Token → control total de la cuenta de comunicaciones."),
    ("SendGrid API Key",    r'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}',               "HIGH",
     "SendGrid API Key → envío de emails masivos desde el dominio de la empresa (phishing)."),
    ("Mailgun API Key",     r'key-[0-9a-zA-Z]{32}',                                       "HIGH",
     "Mailgun API Key expuesta → envío de emails fraudulentos."),

    # GitHub / GitLab
    ("GitHub Token",        r'gh[pousr]_[A-Za-z0-9_]{36,}',                              "CRITICAL",
     "GitHub Personal Access Token → acceso a repositorios privados, posible push de código malicioso."),
    ("GitHub Classic Token",r'ghp_[A-Za-z0-9]{36}',                                      "CRITICAL",
     "GitHub Classic Token expuesto."),
    ("GitLab Token",        r'glpat-[A-Za-z0-9\-_]{20}',                                 "CRITICAL",
     "GitLab Personal Access Token expuesto."),

    # PayPal / Braintree
    ("PayPal Client Secret",r'(?i)paypal.{0,30}secret.{0,10}["\'][A-Za-z0-9\-_]{20,}',  "CRITICAL",
     "PayPal Client Secret → acceso a pagos y datos de clientes."),
    ("Braintree Token",     r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',     "CRITICAL",
     "Braintree Production Token expuesto → acceso completo a pagos."),

    # JWT / tokens genéricos
    ("JWT Token",           r'eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*',
     "MEDIUM", "JWT hardcodeado — puede contener datos de usuario o ser usado para autenticarse."),

    # Credenciales genéricas en código
    ("Password hardcoded",
     r'(?i)(?:password|passwd|pwd|contraseña)\s*[:=]\s*["\'][^"\']{6,}["\']',
     "HIGH", "Contraseña hardcodeada en código JS → credenciales de base de datos, API o admin."),
    ("API Key genérica",
     r'(?i)(?:api_key|apikey|api-key)\s*[:=]\s*["\'][a-zA-Z0-9\-_]{16,}["\']',
     "HIGH", "Clave de API genérica hardcodeada."),
    ("Secret genérico",
     r'(?i)(?:secret|token|auth_token|access_token)\s*[:=]\s*["\'][a-zA-Z0-9\-_./+]{16,}["\']',
     "HIGH", "Token o secret hardcodeado en código JS."),

    # Endpoints internos / IPs privadas
    ("IP privada en JS",
     r'(?:https?://)?(?:192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)\d{1,3}\.\d{1,3}',
     "MEDIUM", "Dirección IP de red interna expuesta en JS — revela arquitectura de infraestructura."),
    ("Endpoint interno",
     r'https?://(?:internal|intranet|admin|api\.internal|backend|staging|dev)\.[a-z0-9.\-]+',
     "MEDIUM", "Endpoint interno o de staging referenciado en JS público."),
]

# Extensiones de archivos de mapa de fuentes
SOURCE_MAP_PATTERN = re.compile(r'//# sourceMappingURL=(.+\.map)\s*$', re.MULTILINE)


class JSAnalyzer:
    def __init__(self, target: str, recon_data: dict = None):
        self.target = target
        self.recon_data = recon_data or {}
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA})
        self.session.verify = False
        self._base_urls = self._build_base_urls()

    def scan(self) -> list:
        print(f"\n  [*] Análisis de JavaScript en: {self.target}")
        for base_url in self._base_urls:
            js_urls = self._collect_js_urls(base_url)
            if not js_urls:
                print(f"  [-] No se encontraron archivos JS en {base_url}")
                continue
            print(f"  [+] {len(js_urls)} archivos JS encontrados — analizando...")
            for js_url in js_urls[:MAX_JS_FILES]:
                self._analyze_js_file(js_url, base_url)

        if not self.findings:
            print("  [OK] No se detectaron secretos ni endpoints sensibles en JS")
        return self.findings

    # ── Recolección de URLs de JS ─────────────────────────────────────────────

    def _collect_js_urls(self, base_url: str) -> list:
        """Descarga la página principal y extrae todas las URLs de scripts JS."""
        js_urls = []
        try:
            resp = self.session.get(base_url, timeout=TIMEOUT, allow_redirects=True)
            html = resp.text
            final_url = resp.url

            # src="..." en tags <script>
            for match in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
                src = match.group(1)
                full = urljoin(final_url, src)
                if self._is_same_domain(full, base_url) and full not in js_urls:
                    js_urls.append(full)

            # También buscar imports dinámicos y referencias en el HTML
            for match in re.finditer(r'["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', html):
                src = match.group(1)
                if src.startswith("/") or src.startswith("./"):
                    full = urljoin(final_url, src)
                    if self._is_same_domain(full, base_url) and full not in js_urls:
                        js_urls.append(full)
        except Exception as e:
            print(f"  [!] Error cargando {base_url}: {e}")
        return js_urls

    # ── Análisis de un archivo JS ─────────────────────────────────────────────

    def _analyze_js_file(self, js_url: str, base_url: str):
        try:
            resp = self.session.get(js_url, timeout=TIMEOUT, stream=True)
            if resp.status_code != 200:
                return
            # Leer máximo MAX_JS_SIZE bytes
            content = b""
            for chunk in resp.iter_content(8192):
                content += chunk
                if len(content) >= MAX_JS_SIZE:
                    break
            js_text = content.decode("utf-8", errors="replace")
        except Exception:
            return

        filename = urlparse(js_url).path.split("/")[-1][:50]
        found_in_file = []

        # Buscar cada patrón de secreto
        for name, pattern, severity, impact in SECRET_PATTERNS:
            matches = re.findall(pattern, js_text)
            for match in matches[:3]:  # máximo 3 ocurrencias por patrón
                # Evitar falsos positivos de placeholders obvios
                match_str = match if isinstance(match, str) else match[0]
                if self._is_placeholder(match_str):
                    continue
                snippet = self._get_snippet(js_text, match_str)
                finding_name = f"{name} en {filename}"
                self._add(severity, finding_name,
                           f"{name} encontrado en {js_url}\nContexto: {snippet}",
                           impact,
                           "Eliminar el secreto del código fuente inmediatamente. "
                           "Usar variables de entorno del servidor (process.env / $_ENV). "
                           "Revocar y regenerar el secreto expuesto — asumir que está comprometido.")
                found_in_file.append(f"{name}: {match_str[:20]}...")
                print(f"  [{severity}] {name} en {filename}: {match_str[:30]}...")

        # Detectar source maps expuestos
        map_refs = SOURCE_MAP_PATTERN.findall(js_text)
        for map_ref in map_refs:
            map_url = urljoin(js_url, map_ref)
            try:
                r = self.session.get(map_url, timeout=TIMEOUT)
                if r.status_code == 200 and len(r.content) > 100:
                    size_kb = len(r.content) // 1024
                    self._add("HIGH", f"Source map expuesto: {map_ref.split('/')[-1]}",
                               f"Source map accesible en {map_url} ({size_kb} KB). "
                               "Contiene el código fuente original sin minificar.",
                               "Un atacante puede descargar el código fuente completo de la aplicación, "
                               "incluyendo lógica de negocio, validaciones del servidor y comentarios internos.",
                               f"Eliminar los archivos .map del servidor de producción o bloquear su acceso. "
                               "En webpack: devtool: false en producción.")
                    print(f"  [HIGH] Source map expuesto: {map_url} ({size_kb} KB)")
            except Exception:
                pass

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _is_placeholder(self, value: str) -> bool:
        """Filtra valores que son claramente placeholders o ejemplos."""
        placeholders = [
            "YOUR_", "your_", "INSERT_", "REPLACE_", "EXAMPLE_", "SAMPLE_",
            "xxxxxxxx", "XXXXXXXX", "placeholder", "undefined", "null",
            "test123", "password123", "changeme", "TODO", "FIXME",
        ]
        return any(p in value for p in placeholders) or len(value) < 8

    def _get_snippet(self, text: str, match: str) -> str:
        """Devuelve el contexto de 80 chars alrededor del match."""
        idx = text.find(match)
        if idx == -1:
            return match[:40]
        start = max(0, idx - 30)
        end = min(len(text), idx + len(match) + 30)
        snippet = text[start:end].replace("\n", " ").replace("\r", "")
        return f"...{snippet}..."

    def _is_same_domain(self, url: str, base_url: str) -> bool:
        try:
            u = urlparse(url)
            b = urlparse(base_url)
            return u.netloc == b.netloc or u.netloc == ""
        except Exception:
            return False

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
            "tipo":          "JS / SECRETOS",
            "nombre":        nombre,
            "descripcion":   descripcion,
            "impacto":       impacto,
            "recomendacion": recomendacion,
        })
