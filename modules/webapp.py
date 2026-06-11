"""
Módulo de análisis de aplicación web — AuditPyme v1.0
Comprobaciones OWASP Top 10 básicas para pymes.
REQUIERE autorización escrita del cliente antes de usar.

Checks disponibles:
  - sqli     : Inyección SQL (error-based y time-based)
  - xss      : Cross-Site Scripting reflejado
  - lfi      : Local File Inclusion
  - redirect : Open Redirect
  - cmdi     : Inyección de comandos
  - idor     : Insecure Direct Object Reference
  - csrf     : Ausencia de tokens CSRF en formularios
  - headers  : Cabeceras de seguridad (ya en web.py, aquí más profundo)
"""

import requests
import urllib3
import time
import re
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 10
UA = "Mozilla/5.0 (compatible; AuditPyme/1.0)"

# ── Payloads ──────────────────────────────────────────────────────────────────

SQLI_ERROR_PAYLOADS = [
    "'", '"', "' OR '1'='1", "' OR 1=1--", "\" OR 1=1--",
    "' AND 1=2--", "1' ORDER BY 1--", "1 UNION SELECT NULL--",
    "'; WAITFOR DELAY '0:0:3'--",
]
SQLI_ERROR_SIGNS = [
    "sql syntax", "mysql_fetch", "ora-", "syntax error",
    "unclosed quotation", "quoted string not properly terminated",
    "you have an error in your sql", "warning: mysql",
    "pg_query", "supplied argument is not a valid mysql",
    "microsoft jet database", "odbc microsoft access",
]
SQLI_TIME_PAYLOAD = "' AND SLEEP(4)--"
SQLI_TIME_PAYLOAD_MSSQL = "'; WAITFOR DELAY '0:0:4'--"

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
]
XSS_SIGNS = [
    "<script>alert('xss')</script>",
    "<script>alert(1)</script>",
    "onerror=alert(1)",
    "<svg onload=alert(1)>",
]

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../etc/passwd%00",
    "....//....//....//etc/passwd",
    "%2F%2F%2F%2Fetc%2Fpasswd",
    "../../../../windows/win.ini",
]
LFI_SIGNS = [
    "root:x:0:0", "bin:x:", "daemon:x:",
    "[extensions]", "for 16-bit app support",
]

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "////evil.com",
    "https://evil.com%2F@gestorialopez.es",
]

CMDI_PAYLOADS = [
    "; sleep 4",
    "| sleep 4",
    "`sleep 4`",
    "$(sleep 4)",
    "; ping -c 4 127.0.0.1",
]

IDOR_PATTERNS = [
    r'[?&](id|user_id|account|order|file|doc|record|item)=(\d+)',
    r'/(\d{3,10})(?:/|\?|$)',
    r'[?&](uuid|guid)=([a-f0-9\-]{32,36})',
]


class WebAppScanner:
    def __init__(self, target: str, checks: list = None):
        self.target = self._normalize_url(target)
        self.checks = checks or ["sqli", "xss", "lfi", "redirect", "cmdi", "csrf", "idor"]
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA})
        self.session.verify = False
        self._visited = set()
        self._forms = []
        self._params = []

    def scan(self) -> list:
        print(f"\n  [*] WebApp scan: {self.target}")
        print(f"  [*] Checks activos: {', '.join(self.checks)}")

        self._crawl(self.target, depth=2)
        print(f"\n  [*] Encontrados: {len(self._forms)} formularios, {len(self._params)} URLs con parámetros")

        if "csrf" in self.checks:
            self._check_csrf()
        if "sqli" in self.checks:
            self._check_sqli()
        if "xss" in self.checks:
            self._check_xss()
        if "lfi" in self.checks:
            self._check_lfi()
        if "redirect" in self.checks:
            self._check_redirect()
        if "cmdi" in self.checks:
            self._check_cmdi()
        if "idor" in self.checks:
            self._check_idor()

        return self.findings

    # ── Crawler ───────────────────────────────────────────────────────────────

    def _crawl(self, url: str, depth: int):
        if depth == 0 or url in self._visited or len(self._visited) > 50:
            return
        if not url.startswith(self.target):
            return

        self._visited.add(url)
        try:
            resp = self.session.get(url, timeout=TIMEOUT, allow_redirects=True)
        except Exception:
            return

        # Extraer formularios
        forms = re.findall(
            r'<form[^>]*action=["\']?([^"\'> ]*)["\']?[^>]*>(.*?)</form>',
            resp.text, re.IGNORECASE | re.DOTALL
        )
        for action, body in forms:
            form_url = urljoin(url, action) if action else url
            method = "post" if 'method="post"' in body.lower() or "method='post'" in body.lower() else "get"
            inputs = re.findall(
                r'<input[^>]*name=["\']([^"\']+)["\'][^>]*(?:value=["\']([^"\']*)["\'])?',
                body, re.IGNORECASE
            )
            fields = {name: value or "test" for name, value in inputs if name.lower() not in ("submit", "_token", "csrf")}
            csrf_token = any(n.lower() in ("csrf_token", "_token", "csrf", "token") for n, _ in inputs)
            if fields:
                self._forms.append({
                    "url": form_url, "method": method,
                    "fields": fields, "has_csrf": csrf_token,
                    "page": url
                })

        # Extraer URLs con parámetros
        links = re.findall(r'href=["\']([^"\'#]+)["\']', resp.text, re.IGNORECASE)
        for link in links:
            full = urljoin(url, link)
            parsed = urlparse(full)
            if parsed.query and full not in self._visited:
                params = parse_qs(parsed.query)
                self._params.append({"url": full, "params": params, "parsed": parsed})
            if depth > 1 and full.startswith(self.target) and full not in self._visited:
                self._crawl(full, depth - 1)

    # ── CSRF ──────────────────────────────────────────────────────────────────

    def _check_csrf(self):
        print("\n  [*] Comprobando CSRF...")
        vulns = [f for f in self._forms if f["method"] == "post" and not f["has_csrf"]]
        if vulns:
            for f in vulns[:5]:
                self._add("MEDIUM", "CSRF",
                          f"Formulario POST sin token CSRF: {f['url']}",
                          f"El formulario en {f['page']} envía datos por POST sin token CSRF. "
                          f"Un atacante puede engañar a un usuario autenticado para que realice "
                          f"acciones no deseadas (cambiar contraseña, realizar pedidos, etc.).",
                          "Implementar tokens CSRF en todos los formularios POST. "
                          "Frameworks como WordPress, Laravel o Django los incluyen de serie.")
                print(f"    [MEDIUM] CSRF — {f['url']}")
        else:
            print("  [OK] Formularios POST con protección CSRF")

    # ── SQL Injection ─────────────────────────────────────────────────────────

    def _check_sqli(self):
        print("\n  [*] Comprobando SQL Injection...")
        tested = 0

        # En formularios
        for form in self._forms[:10]:
            for field in form["fields"]:
                for payload in SQLI_ERROR_PAYLOADS[:4]:
                    data = {**form["fields"], field: payload}
                    try:
                        if form["method"] == "post":
                            resp = self.session.post(form["url"], data=data, timeout=TIMEOUT)
                        else:
                            resp = self.session.get(form["url"], params=data, timeout=TIMEOUT)
                        if any(s in resp.text.lower() for s in SQLI_ERROR_SIGNS):
                            self._add("CRITICAL", "SQL INJECTION",
                                      f"SQL Injection (error-based) en {form['url']} — campo '{field}'",
                                      f"El campo '{field}' del formulario en {form['url']} es vulnerable "
                                      f"a inyección SQL. Un atacante puede leer, modificar o eliminar "
                                      f"toda la base de datos, incluyendo datos de clientes y contraseñas.\n"
                                      f"Payload: {payload}",
                                      "Usar consultas preparadas (prepared statements) en el código. "
                                      "Nunca concatenar variables de usuario directamente en SQL.")
                            print(f"    [CRITICAL] SQLi en {form['url']} campo='{field}'")
                            tested += 1
                            break
                    except Exception:
                        pass

        # Time-based en parámetros URL
        for p in self._params[:10]:
            for param in p["params"]:
                try:
                    url_parts = list(p["parsed"])
                    new_params = {**{k: v[0] for k, v in p["params"].items()}, param: SQLI_TIME_PAYLOAD}
                    url_parts[4] = urlencode(new_params)
                    test_url = urlunparse(url_parts)
                    t0 = time.time()
                    self.session.get(test_url, timeout=8)
                    elapsed = time.time() - t0
                    if elapsed >= 3.5:
                        self._add("CRITICAL", "SQL INJECTION",
                                  f"SQL Injection (time-based) en parámetro '{param}'",
                                  f"El parámetro '{param}' en {p['url']} introduce un retraso de "
                                  f"{elapsed:.1f}s al inyectar SLEEP(4), lo que confirma ejecución "
                                  f"de código SQL arbitrario en el servidor.",
                                  "Usar consultas preparadas (prepared statements). "
                                  "Validar y escapar todos los parámetros de entrada.")
                        print(f"    [CRITICAL] SQLi time-based — {param} ({elapsed:.1f}s)")
                except Exception:
                    pass

        if tested == 0:
            print("  [OK] No se detectó SQL Injection en los formularios analizados")

    # ── XSS ──────────────────────────────────────────────────────────────────

    def _check_xss(self):
        print("\n  [*] Comprobando XSS...")
        found = 0

        for form in self._forms[:10]:
            for field in form["fields"]:
                for payload in XSS_PAYLOADS[:3]:
                    data = {**form["fields"], field: payload}
                    try:
                        if form["method"] == "post":
                            resp = self.session.post(form["url"], data=data, timeout=TIMEOUT)
                        else:
                            resp = self.session.get(form["url"], params=data, timeout=TIMEOUT)
                        if any(s in resp.text.lower() for s in XSS_SIGNS):
                            self._add("HIGH", "XSS REFLEJADO",
                                      f"Cross-Site Scripting reflejado en {form['url']} — campo '{field}'",
                                      f"El campo '{field}' devuelve el payload XSS sin sanitizar. "
                                      f"Un atacante puede enviar un enlace malicioso a un usuario "
                                      f"y robar su sesión, redirigirle a una web falsa o ejecutar "
                                      f"código en su navegador.\nPayload: {payload}",
                                      "Sanitizar y escapar todas las entradas de usuario antes de "
                                      "mostrarlas en HTML. Usar funciones como htmlspecialchars() en PHP "
                                      "o el sistema de plantillas del framework.")
                            print(f"    [HIGH] XSS en {form['url']} campo='{field}'")
                            found += 1
                            break
                    except Exception:
                        pass

        for p in self._params[:10]:
            for param in p["params"]:
                for payload in XSS_PAYLOADS[:2]:
                    try:
                        url_parts = list(p["parsed"])
                        new_params = {**{k: v[0] for k, v in p["params"].items()}, param: payload}
                        url_parts[4] = urlencode(new_params)
                        test_url = urlunparse(url_parts)
                        resp = self.session.get(test_url, timeout=TIMEOUT)
                        if any(s in resp.text.lower() for s in XSS_SIGNS):
                            self._add("HIGH", "XSS REFLEJADO",
                                      f"XSS reflejado en parámetro '{param}'",
                                      f"El parámetro '{param}' en la URL refleja el payload XSS sin "
                                      f"escapar. Riesgo de robo de sesión y phishing.\n"
                                      f"URL: {test_url[:100]}",
                                      "Escapar todos los valores antes de incluirlos en el HTML.")
                            print(f"    [HIGH] XSS en parámetro '{param}'")
                            found += 1
                            break
                    except Exception:
                        pass

        if found == 0:
            print("  [OK] No se detectó XSS reflejado")

    # ── LFI ──────────────────────────────────────────────────────────────────

    def _check_lfi(self):
        print("\n  [*] Comprobando LFI (Local File Inclusion)...")
        found = 0

        for p in self._params[:15]:
            for param, values in p["params"].items():
                if not any(kw in param.lower() for kw in
                           ("page", "file", "path", "include", "load", "template",
                            "view", "doc", "lang", "module", "content")):
                    continue
                for payload in LFI_PAYLOADS:
                    try:
                        url_parts = list(p["parsed"])
                        new_params = {**{k: v[0] for k, v in p["params"].items()}, param: payload}
                        url_parts[4] = urlencode(new_params)
                        test_url = urlunparse(url_parts)
                        resp = self.session.get(test_url, timeout=TIMEOUT)
                        if any(s in resp.text for s in LFI_SIGNS):
                            self._add("CRITICAL", "LFI — LOCAL FILE INCLUSION",
                                      f"Inclusión de archivos locales en parámetro '{param}'",
                                      f"El parámetro '{param}' permite leer archivos del servidor. "
                                      f"Se pudo leer /etc/passwd con el payload: {payload}\n"
                                      f"Un atacante puede leer archivos de configuración, "
                                      f"credenciales y código fuente del servidor.",
                                      "Validar y restringir los valores permitidos en parámetros "
                                      "de inclusión de archivos. Nunca usar entrada del usuario "
                                      "directamente en funciones include/require.")
                            print(f"    [CRITICAL] LFI en '{param}' — {p['url'][:60]}")
                            found += 1
                            break
                    except Exception:
                        pass

        if found == 0:
            print("  [OK] No se detectó LFI")

    # ── Open Redirect ─────────────────────────────────────────────────────────

    def _check_redirect(self):
        print("\n  [*] Comprobando Open Redirect...")
        found = 0

        for p in self._params[:15]:
            for param, values in p["params"].items():
                if not any(kw in param.lower() for kw in
                           ("redirect", "url", "next", "return", "goto",
                            "target", "redir", "destination", "forward")):
                    continue
                for payload in REDIRECT_PAYLOADS:
                    try:
                        url_parts = list(p["parsed"])
                        new_params = {**{k: v[0] for k, v in p["params"].items()}, param: payload}
                        url_parts[4] = urlencode(new_params)
                        test_url = urlunparse(url_parts)
                        resp = self.session.get(test_url, timeout=TIMEOUT, allow_redirects=False)
                        location = resp.headers.get("Location", "")
                        if "evil.com" in location or payload in location:
                            self._add("HIGH", "OPEN REDIRECT",
                                      f"Redirección abierta en parámetro '{param}'",
                                      f"El parámetro '{param}' redirige a cualquier URL externa. "
                                      f"Un atacante puede usar enlaces legítimos de este dominio "
                                      f"para redirigir a páginas de phishing.\n"
                                      f"URL: {test_url[:100]}\nRedirige a: {location}",
                                      "Validar que las URLs de redirección pertenecen al dominio propio. "
                                      "Usar listas blancas de destinos permitidos.")
                            print(f"    [HIGH] Open Redirect en '{param}'")
                            found += 1
                            break
                    except Exception:
                        pass

        if found == 0:
            print("  [OK] No se detectó Open Redirect")

    # ── Command Injection ─────────────────────────────────────────────────────

    def _check_cmdi(self):
        print("\n  [*] Comprobando Command Injection...")
        found = 0

        for form in self._forms[:5]:
            for field in form["fields"]:
                for payload in CMDI_PAYLOADS:
                    data = {**form["fields"], field: f"test{payload}"}
                    try:
                        t0 = time.time()
                        if form["method"] == "post":
                            resp = self.session.post(form["url"], data=data, timeout=8)
                        else:
                            resp = self.session.get(form["url"], params=data, timeout=8)
                        elapsed = time.time() - t0
                        if elapsed >= 3.5 and "sleep" in payload:
                            self._add("CRITICAL", "COMMAND INJECTION",
                                      f"Inyección de comandos OS en {form['url']} — campo '{field}'",
                                      f"El campo '{field}' ejecuta comandos del sistema operativo. "
                                      f"Se detectó un retraso de {elapsed:.1f}s con payload sleep. "
                                      f"Un atacante puede tomar control total del servidor.",
                                      "Nunca ejecutar comandos del sistema con entrada del usuario. "
                                      "Si es imprescindible, usar listas blancas estrictas y escapado.")
                            print(f"    [CRITICAL] CMDi en {form['url']} campo='{field}'")
                            found += 1
                    except Exception:
                        pass

        if found == 0:
            print("  [OK] No se detectó Command Injection")

    # ── IDOR ─────────────────────────────────────────────────────────────────

    def _check_idor(self):
        print("\n  [*] Comprobando IDOR...")
        found = 0

        for p in self._params:
            url = p["url"]
            for pattern in IDOR_PATTERNS:
                match = re.search(pattern, url, re.IGNORECASE)
                if match:
                    param_name = match.group(1)
                    param_val  = match.group(2)
                    try:
                        orig_resp = self.session.get(url, timeout=TIMEOUT)
                        if orig_resp.status_code != 200:
                            continue

                        # Intentar acceder al recurso anterior y siguiente
                        for delta in [-1, 1, 999, 1000]:
                            try:
                                new_val = str(int(param_val) + delta)
                            except ValueError:
                                continue
                            test_url = url.replace(f"{param_name}={param_val}", f"{param_name}={new_val}")
                            test_resp = self.session.get(test_url, timeout=TIMEOUT)
                            if test_resp.status_code == 200 and len(test_resp.text) > 200:
                                if test_resp.text[:500] != orig_resp.text[:500]:
                                    self._add("HIGH", "IDOR",
                                              f"Posible IDOR en parámetro '{param_name}'",
                                              f"Cambiando el parámetro '{param_name}' de {param_val} "
                                              f"a {new_val} se obtiene contenido diferente (HTTP 200). "
                                              f"Puede indicar acceso a recursos de otros usuarios.\n"
                                              f"URL original: {url[:80]}\n"
                                              f"URL modificada: {test_url[:80]}",
                                              "Verificar autorización en el servidor para cada recurso. "
                                              "No confiar en que el usuario solo conoce sus propios IDs. "
                                              "Usar UUIDs en lugar de IDs secuenciales.")
                                    print(f"    [HIGH] Posible IDOR — {param_name}={param_val} → {new_val}")
                                    found += 1
                                    break
                    except Exception:
                        pass

        if found == 0:
            print("  [OK] No se detectó IDOR obvio")

    # ── Utilidades ────────────────────────────────────────────────────────────

    def _add(self, severidad, tipo, nombre, descripcion, recomendacion):
        # Evitar duplicados
        for f in self.findings:
            if f["nombre"] == nombre:
                return
        self.findings.append({
            "url":           self.target,
            "tipo":          tipo,
            "nombre":        nombre,
            "descripcion":   descripcion,
            "severidad":     severidad,
            "recomendacion": recomendacion,
        })

    def _normalize_url(self, url: str) -> str:
        if not url.startswith("http"):
            url = "https://" + url
        return url.rstrip("/")
