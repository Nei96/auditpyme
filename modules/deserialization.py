"""
Módulo de Deserialización Insegura — AuditPyme
Detecta PHP unserialize, Java deserialization, Python pickle y Node prototype pollution.
"""

import requests
import urllib3
import re
import base64
import json
import time
from urllib.parse import urljoin, parse_qs, urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
TIMEOUT = 12
UA = "Mozilla/5.0 (compatible; AuditPyme/1.0)"

# ── PHP Serialización ─────────────────────────────────────────────────────────

# Payloads PHP serializados que provocan errores detectables (sin RCE real)
# Objetivo: ver si el servidor llama a unserialize() en el input
PHP_SERIALIZED_PROBES = [
    # Objeto con clase inexistente → PHP Warning si unserialize() está activo
    ('O:7:"AuditPy":1:{s:4:"test";s:4:"pwnd";}',
     ["PHP Warning", "unserialize", "__PHP_Incomplete_Class", "AuditPy"],
     "Objeto PHP con clase inexistente"),

    # Array serializado normal — diferencia de comportamiento vs string plano
    ('a:2:{i:0;s:5:"admin";i:1;s:8:"password";}',
     ["array", "Array"],
     "Array PHP serializado"),

    # String serializado
    ('s:4:"test";',
     [],
     "String PHP serializado"),

    # Objeto con __destruct (detección de error)
    ('O:8:"stdClass":1:{s:4:"test";O:7:"AuditPy":0:{}}',
     ["__PHP_Incomplete_Class", "unserialize", "PHP Warning"],
     "Objeto anidado PHP"),
]

# Cookies y parámetros comunes donde PHP serializa datos
PHP_SERIAL_LOCATIONS = [
    # Cookies
    ("cookie", "PHPSESSID"),
    ("cookie", "session"),
    ("cookie", "sess"),
    ("cookie", "data"),
    ("cookie", "user"),
    ("cookie", "cart"),
    ("cookie", "prefs"),
    ("cookie", "settings"),
    # Parámetros GET/POST
    ("param", "data"),
    ("param", "object"),
    ("param", "payload"),
    ("param", "session"),
    ("param", "user"),
    ("param", "token"),
    ("param", "state"),
    ("param", "cart"),
    ("param", "prefs"),
]

# ── Java Serialización ────────────────────────────────────────────────────────

# Magic bytes de Java serialization (0xACED 0x0005)
JAVA_MAGIC = b'\xac\xed\x00\x05'
JAVA_MAGIC_B64 = base64.b64encode(JAVA_MAGIC).decode()  # "rO0ABQ=="

# Patrones en respuestas que indican Java deserialización
JAVA_ERROR_PATTERNS = [
    r"java\.io\.IOException",
    r"java\.lang\.ClassNotFoundException",
    r"InvalidClassException",
    r"StreamCorruptedException",
    r"ClassCastException",
    r"java\.io\.ObjectInputStream",
    r"deserialization",
    r"Serializable",
    r"SerialVersionUID",
]

# Endpoints Java comunes donde se deserializa
JAVA_ENDPOINTS = [
    "/api/deserialize",
    "/rmi",
    "/jndi",
    "/ws",
    "/service",
    "/remoting",
    "/invoke",
    "/execute",
    "/deserialize",
    "/object",
    "/data",
]

# ── Python Pickle ─────────────────────────────────────────────────────────────

# Patrones de pickle en cookies (base64)
PICKLE_COOKIE_PATTERNS = [
    r'^gASV',     # Protocol 4 pickle
    r'^KGRxA',    # Protocol 0 pickle (dict)
    r'^gAJd',     # Protocol 2 list
    r'^gAJ}',     # Protocol 2 dict
    r'^\x80\x04', # Protocol 4 raw
]

# Payload pickle inofensivo que imprime algo (para detección sin RCE)
# import os; os.system('') → retorna 0 (entero), detectado si la respuesta cambia
PICKLE_PROBE_B64 = base64.b64encode(
    b'\x80\x04\x95\x17\x00\x00\x00\x00\x00\x00\x00\x8c\x08builtins\x94\x8c\x03int\x94\x93\x8c\x010\x94\x85\x94R\x94.'
).decode()

# ── Node.js Prototype Pollution ───────────────────────────────────────────────

PROTO_POLLUTION_PAYLOADS = [
    # JSON con __proto__
    '{"__proto__":{"polluted":"auditpyme_7x9z"}}',
    '{"constructor":{"prototype":{"polluted":"auditpyme_7x9z"}}}',
    # Nested
    '{"__proto__":{"isAdmin":true}}',
    '{"__proto__":{"role":"admin"}}',
]

PROTO_POLLUTION_MARKERS = [
    "auditpyme_7x9z",
    '"polluted"',
    "isAdmin",
]


class DeserializationScanner:

    def __init__(self, target: str, recon_data: dict = None, stealth: bool = False):
        self.target = target
        self.recon_data = recon_data or {}
        self.findings = []
        self.delay = 0.5 if stealth else 0.1
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA})
        self.session.verify = False
        self._base_urls = self._build_base_urls()

    def scan(self) -> list:
        print(f"\n  [*] Deserialización insegura scan: {self.target}")
        for base in self._base_urls:
            self._check_php_deserialization(base)
            self._check_java_deserialization(base)
            self._check_python_pickle(base)
            self._check_prototype_pollution(base)

        if not self.findings:
            print("  [OK] No se detectó deserialización insegura")
        return self.findings

    # ── PHP unserialize ───────────────────────────────────────────────────────

    def _check_php_deserialization(self, base: str):
        print("  [*] Probando PHP unserialize...")
        urls_to_test = self._collect_urls(base)

        for url in urls_to_test[:10]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            # Probar en parámetros GET
            for param in list(params.keys())[:5]:
                for payload, error_patterns, label in PHP_SERIALIZED_PROBES[:2]:
                    self._test_php_param(url, param, payload, error_patterns, label, "GET")

        # Probar en cookies comunes
        for _, cookie_name in [l for l in PHP_SERIAL_LOCATIONS if l[0] == "cookie"][:5]:
            for payload, error_patterns, label in PHP_SERIALIZED_PROBES[:2]:
                self._test_php_cookie(base, cookie_name, payload, error_patterns, label)

    def _test_php_param(self, url: str, param: str, payload: str,
                        error_patterns: list, label: str, method: str):
        try:
            time.sleep(self.delay)
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[param] = [payload]

            # Probar también base64-encoded (algunos apps decodifican antes de unserialize)
            for test_payload in [payload, base64.b64encode(payload.encode()).decode()]:
                params[param] = [test_payload]
                from urllib.parse import urlencode
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode({k: v[0] for k, v in params.items()})}"
                r = self.session.get(test_url, timeout=TIMEOUT)

                if self._php_hit(r.text, error_patterns):
                    self._add_php(url, f"parámetro GET '{param}'", test_payload, label)
                    return
        except Exception:
            pass

    def _test_php_cookie(self, base: str, cookie_name: str, payload: str,
                         error_patterns: list, label: str):
        try:
            time.sleep(self.delay)
            for test_payload in [payload, base64.b64encode(payload.encode()).decode()]:
                cookies = {cookie_name: test_payload}
                r = self.session.get(base, cookies=cookies, timeout=TIMEOUT)
                if self._php_hit(r.text, error_patterns):
                    self._add_php(base, f"cookie '{cookie_name}'", test_payload, label)
                    return
        except Exception:
            pass

    def _php_hit(self, text: str, error_patterns: list) -> bool:
        for pattern in error_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        # Detección genérica de errores PHP de deserialización
        generic = [r"unserialize\(\)", r"__PHP_Incomplete_Class", r"O:\d+:\"AuditPy\""]
        for g in generic:
            if re.search(g, text, re.IGNORECASE):
                return True
        return False

    def _add_php(self, url: str, location: str, payload: str, label: str):
        self._add(
            "CRITICAL",
            f"PHP Deserialización Insegura — {location}",
            f"El servidor llama a unserialize() sobre input controlado por el usuario en {location}. "
            f"URL: {url}\nPayload: {payload[:80]} ({label})",
            "PHP unserialize() sobre input no confiable permite RCE mediante PHP Object Injection. "
            "Con PHPGGC (gadget chains) un atacante puede ejecutar comandos arbitrarios en el servidor "
            "explotando clases de frameworks populares (Laravel, Symfony, Yii, CodeIgniter).",
            "Nunca llamar a unserialize() sobre datos del usuario. "
            "Usar JSON (json_decode) en su lugar. "
            "Si es imprescindible, usar allowed_classes=false: unserialize($data, ['allowed_classes'=>false]). "
            "Actualizar todos los frameworks PHP a la última versión (menos gadget chains disponibles)."
        )
        print(f"  [CRITICAL] PHP unserialize en {location}")

    # ── Java Deserialization ──────────────────────────────────────────────────

    def _check_java_deserialization(self, base: str):
        print("  [*] Buscando deserialización Java...")

        # Buscar magic bytes en cookies existentes
        for name, val in self.session.cookies.items():
            try:
                decoded = base64.b64decode(val + "==")
                if decoded[:4] == JAVA_MAGIC:
                    self._add(
                        "CRITICAL",
                        f"Java Deserialization — Magic bytes en cookie '{name}'",
                        f"La cookie '{name}' contiene datos serializados Java "
                        f"(magic bytes 0xACED 0x0005 en base64). URL: {base}",
                        "Cookies con datos Java serializados son vectores clásicos de RCE. "
                        "Herramientas como ysoserial permiten generar payloads para CommonCollections, "
                        "Spring, Hibernate y otros frameworks para ejecutar comandos arbitrarios.",
                        "No serializar objetos Java en cookies. Usar JWT con datos simples. "
                        "Si es necesario, implementar una allowlist de clases deserializables. "
                        "Actualizar todas las dependencias Java (commons-collections, spring, etc.)."
                    )
                    print(f"  [CRITICAL] Java magic bytes en cookie '{name}'")
            except Exception:
                pass

        # Probar endpoints Java comunes con payload de detección
        for path in JAVA_ENDPOINTS:
            url = base.rstrip("/") + path
            try:
                # Enviar magic bytes Java serialized en body
                probe = JAVA_MAGIC + b'\x73\x72\x00\x0bAuditPyTest'
                r = self.session.post(url, data=probe,
                                      headers={"Content-Type": "application/x-java-serialized-object"},
                                      timeout=TIMEOUT)
                for pattern in JAVA_ERROR_PATTERNS:
                    if re.search(pattern, r.text, re.IGNORECASE):
                        self._add(
                            "CRITICAL",
                            f"Java Deserialization — Endpoint activo: {path}",
                            f"El endpoint {url} acepta y procesa datos Java serializados "
                            f"(Content-Type: application/x-java-serialized-object). "
                            f"Error detectado: {re.search(pattern, r.text).group(0)[:80]}",
                            "Endpoint Java que deserializa datos externos. "
                            "Explotable con ysoserial para RCE si hay gadget chains en el classpath.",
                            "Reemplazar la serialización Java por JSON/XML. "
                            "Implementar un ObjectInputFilter que rechace clases no permitidas. "
                            "Actualizar commons-collections, spring-core y otras dependencias."
                        )
                        print(f"  [CRITICAL] Java deserialization activa en {path}")
                        break
            except Exception:
                pass

    # ── Python Pickle ─────────────────────────────────────────────────────────

    def _check_python_pickle(self, base: str):
        print("  [*] Buscando Python pickle en cookies/headers...")

        # Obtener cookies del sitio
        try:
            r = self.session.get(base, timeout=TIMEOUT)
        except Exception:
            return

        for name, val in self.session.cookies.items():
            # Comprobar si parece pickle base64
            for pattern in PICKLE_COOKIE_PATTERNS:
                if re.match(pattern, val):
                    self._add(
                        "CRITICAL",
                        f"Python Pickle en cookie '{name}'",
                        f"La cookie '{name}' contiene datos que parecen pickle de Python "
                        f"(patrón: {pattern}). URL: {base}\nValor: {val[:60]}",
                        "Cookies pickle de Python permiten RCE con una sola petición. "
                        "El atacante reemplaza la cookie por un payload pickle que ejecute "
                        "os.system('command') al ser deserializado por el servidor.",
                        "Nunca usar pickle para datos de sesión de usuario. "
                        "Usar JSON con firma HMAC (itsdangerous en Flask) o JWT. "
                        "Si se usa Flask: SECRET_KEY debe ser aleatoria y larga (32+ bytes)."
                    )
                    print(f"  [CRITICAL] Posible pickle en cookie '{name}'")

            # Probar si el servidor acepta y deserializa un pickle inofensivo
            try:
                time.sleep(self.delay)
                old_val = self.session.cookies.get(name, "")
                self.session.cookies.set(name, PICKLE_PROBE_B64)
                r2 = self.session.get(base, timeout=TIMEOUT)
                self.session.cookies.set(name, old_val)

                # Si la respuesta cambia significativamente → pickle se está deserializando
                if abs(len(r2.text) - len(r.text)) > len(r.text) * 0.1:
                    self._add(
                        "CRITICAL",
                        f"Python Pickle activo — cookie '{name}' deserializada",
                        f"El servidor parece deserializar el contenido de la cookie '{name}'. "
                        f"La respuesta cambió al inyectar un pickle de prueba. URL: {base}",
                        "Pickle activo en sesión — cualquier visitante puede ejecutar código arbitrario "
                        "en el servidor reemplazando su cookie de sesión por un payload pickle.",
                        "Reemplazar pickle por JSON con firma HMAC o JWT firmado. "
                        "En Flask: usar flask-session con almacenamiento en Redis/DB."
                    )
                    print(f"  [CRITICAL] Pickle activo en cookie '{name}'")
            except Exception:
                pass

    # ── Node.js Prototype Pollution ───────────────────────────────────────────

    def _check_prototype_pollution(self, base: str):
        print("  [*] Probando Prototype Pollution (Node.js)...")
        for base_url in self._base_urls:
            # Buscar endpoints que acepten JSON
            api_paths = ["/api", "/api/v1", "/api/v2", "/api/users",
                         "/api/settings", "/api/profile", "/api/update"]
            for path in api_paths:
                url = base_url.rstrip("/") + path
                for payload_str in PROTO_POLLUTION_PAYLOADS[:2]:
                    try:
                        time.sleep(self.delay)
                        r = self.session.post(
                            url,
                            data=payload_str,
                            headers={"Content-Type": "application/json"},
                            timeout=TIMEOUT
                        )
                        if any(m in r.text for m in PROTO_POLLUTION_MARKERS):
                            self._add(
                                "HIGH",
                                f"Prototype Pollution — {path}",
                                f"El endpoint {url} refleja propiedades inyectadas vía __proto__ "
                                f"en la respuesta. Payload: {payload_str[:80]}",
                                "Prototype pollution permite modificar el prototipo base de todos los "
                                "objetos JavaScript del servidor, causando DoS, bypass de autenticación, "
                                "XSS almacenado y en algunos casos RCE (via gadget chains en Node.js).",
                                "Usar Object.freeze(Object.prototype) al inicio de la aplicación. "
                                "Sanitizar el input con: JSON.parse(JSON.stringify(obj)). "
                                "Usar lodash>=4.17.21, jquery>=3.5.0. "
                                "Validar y rechazar claves '__proto__', 'constructor', 'prototype'."
                            )
                            print(f"  [HIGH] Prototype Pollution en {path}")
                            return
                    except Exception:
                        pass

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _collect_urls(self, base: str) -> list:
        urls = [base]
        try:
            r = self.session.get(base, timeout=TIMEOUT)
            for href in re.findall(r'href=["\']([^"\'#]+)["\']', r.text):
                if not href.startswith("http"):
                    href = urljoin(base, href)
                if "?" in href and base in href:
                    urls.append(href)
        except Exception:
            pass
        return list(set(urls))[:15]

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

    def _add(self, severidad, nombre, descripcion, impacto, recomendacion):
        for f in self.findings:
            if f["nombre"] == nombre:
                return
        self.findings.append({
            "severidad": severidad, "tipo": "Deserialization",
            "nombre": nombre, "descripcion": descripcion,
            "impacto": impacto, "recomendacion": recomendacion,
        })
