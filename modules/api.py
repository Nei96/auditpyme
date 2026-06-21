"""
Módulo de auditoría de APIs REST — AuditPyme
BOLA/IDOR, Mass Assignment, BFLA, versioning, excessive data exposure.
"""

import requests
import urllib3
import re
import json
import time
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse, quote

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
TIMEOUT = 12
UA = "Mozilla/5.0 (compatible; AuditPyme/1.0)"

# Rutas de documentación API a buscar
API_DOC_PATHS = [
    "/swagger.json", "/swagger-ui.html", "/swagger-ui/",
    "/api/docs", "/api/swagger.json", "/api/swagger",
    "/openapi.json", "/openapi.yaml", "/openapi.yml",
    "/v1/swagger.json", "/v2/swagger.json", "/v3/swagger.json",
    "/v1/api-docs", "/v2/api-docs",
    "/api/v1/swagger.json", "/api/v2/swagger.json",
    "/.well-known/openid-configuration",
    "/api/schema", "/api/schema.json",
    "/graphql/schema",
    "/api/explorer",
    "/api-docs",
    "/redoc",
]

# Rutas de API comunes a explorar
API_BASE_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3",
    "/rest", "/rest/v1", "/rest/v2",
    "/services", "/service",
    "/api/public", "/api/private",
]

# Endpoints de admin a probar (BFLA)
ADMIN_API_PATHS = [
    "/api/admin", "/api/v1/admin", "/api/v2/admin",
    "/api/admin/users", "/api/v1/admin/users",
    "/api/admin/settings", "/api/v1/admin/settings",
    "/api/admin/config", "/api/v1/admin/config",
    "/api/management", "/api/v1/management",
    "/api/internal", "/api/v1/internal",
    "/api/system", "/api/v1/system",
    "/admin/api", "/admin/api/v1",
    "/api/users/all", "/api/v1/users/all",
    "/api/debug", "/api/v1/debug",
    "/api/metrics", "/actuator", "/actuator/env",
]

# Campos sensibles para mass assignment
MASS_ASSIGNMENT_FIELDS = [
    {"role": "admin"},
    {"role": "administrator"},
    {"is_admin": True},
    {"is_admin": 1},
    {"admin": True},
    {"admin": 1},
    {"isAdmin": True},
    {"isAdmin": 1},
    {"privilege": "admin"},
    {"group": "admin"},
    {"permission": "superuser"},
    {"balance": 99999},
    {"credit": 99999},
    {"verified": True},
    {"email_verified": True},
    {"active": True},
    {"status": "admin"},
    {"type": "admin"},
    {"account_type": "premium"},
    {"subscription": "enterprise"},
]

# Versiones de API antiguas a probar
API_VERSION_PATTERNS = {
    "v1": ["v0", "v2", "v3", "beta", "alpha", "old", "legacy"],
    "v2": ["v1", "v0", "v3", "beta", "old", "legacy"],
    "v3": ["v2", "v1", "v0", "beta", "old", "legacy"],
}


class APIScanner:
    """Auditoría profunda de APIs REST: BOLA, mass assignment, BFLA, versioning."""

    def __init__(self, target: str, recon_data: dict = None,
                 auth_user: str = None, auth_pass: str = None,
                 auth_url: str = None, stealth: bool = False):
        self.target = target
        self.recon_data = recon_data or {}
        self.findings = []
        self.delay = 0.5 if stealth else 0.1
        self.auth_user = auth_user
        self.auth_pass = auth_pass
        self.auth_url = auth_url
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA})
        self.session.verify = False
        self._base_urls = self._build_base_urls()
        self._discovered_endpoints: list[dict] = []
        self._auth_token: str | None = None
        self._api_base: str | None = None

    def scan(self) -> list:
        print(f"\n  [*] Auditoría API REST en: {self.target}")

        # Autenticar si hay credenciales
        if self.auth_user and self.auth_pass:
            self._authenticate()

        for base in self._base_urls:
            # 1. Descubrir endpoints
            self._discover_endpoints(base)

            # 2. BOLA / IDOR
            self._check_bola(base)

            # 3. Mass Assignment
            self._check_mass_assignment(base)

            # 4. BFLA — acceso a endpoints de admin
            self._check_bfla(base)

            # 5. API versioning — acceso a versiones antiguas
            self._check_api_versioning(base)

            # 6. Excessive data exposure
            self._check_excessive_data(base)

        if not self.findings:
            print("  [OK] No se detectaron vulnerabilidades críticas en la API")
        return self.findings

    # ── Autenticación ─────────────────────────────────────────────────────────

    def _authenticate(self):
        """Intenta obtener un token JWT autenticándose en la API."""
        login_endpoints = [
            "/api/login", "/api/auth/login", "/api/v1/auth/login",
            "/api/v1/login", "/api/v2/login", "/auth/token",
            "/api/token", "/login", "/api/auth",
        ]
        for base in self._base_urls:
            for path in login_endpoints:
                url = base.rstrip("/") + path
                for payload in [
                    {"username": self.auth_user, "password": self.auth_pass},
                    {"email": self.auth_user, "password": self.auth_pass},
                    {"user": self.auth_user, "pass": self.auth_pass},
                ]:
                    try:
                        r = self.session.post(url, json=payload, timeout=TIMEOUT)
                        if r.status_code in (200, 201):
                            data = r.json() if r.text else {}
                            token = (data.get("token") or data.get("access_token") or
                                     data.get("jwt") or data.get("accessToken"))
                            if token:
                                self._auth_token = token
                                self.session.headers["Authorization"] = f"Bearer {token}"
                                print(f"  [+] Autenticado en API: {url}")
                                return
                    except Exception:
                        pass

    # ── 1. Descubrimiento de endpoints ────────────────────────────────────────

    def _discover_endpoints(self, base: str):
        """Descubre endpoints desde Swagger/OpenAPI, HTML y rutas comunes."""
        print(f"  [*] Descubriendo endpoints API en {base}...")

        # Buscar documentación Swagger/OpenAPI
        for path in API_DOC_PATHS:
            url = base.rstrip("/") + path
            try:
                r = self.session.get(url, timeout=TIMEOUT)
                if r.status_code != 200 or len(r.text) < 100:
                    continue

                # Intentar parsear como JSON (Swagger/OpenAPI)
                try:
                    spec = r.json()
                    self._parse_openapi_spec(spec, base)
                    print(f"  [+] Especificación OpenAPI encontrada: {url}")
                    self._add(
                        "MEDIUM",
                        f"Documentación API expuesta — {path}",
                        f"Especificación OpenAPI/Swagger accesible en {url}. "
                        f"Endpoints descubiertos: {len(self._discovered_endpoints)}",
                        "La documentación expuesta revela todos los endpoints, parámetros, "
                        "métodos y esquemas de datos. Facilita enormemente el reconocimiento "
                        "y permite a un atacante mapear toda la superficie de ataque en segundos.",
                        "Restringir el acceso a la documentación por IP o requerir autenticación. "
                        "En producción, deshabilitar Swagger UI o protegerlo con básica auth."
                    )
                except Exception:
                    pass
            except Exception:
                pass

        # Extraer endpoints de archivos JS del sitio
        self._extract_endpoints_from_js(base)

        # Probar rutas base conocidas
        for api_path in API_BASE_PATHS:
            url = base.rstrip("/") + api_path
            try:
                r = self.session.get(url, timeout=TIMEOUT)
                if r.status_code in (200, 401, 403) and len(r.text) > 10:
                    self._api_base = url
                    # Intentar parsear respuesta JSON para descubrir más endpoints
                    try:
                        data = r.json()
                        self._extract_endpoints_from_json(data, base, api_path)
                    except Exception:
                        pass
            except Exception:
                pass

        print(f"  [+] {len(self._discovered_endpoints)} endpoints descubiertos")

    def _parse_openapi_spec(self, spec: dict, base: str):
        """Extrae endpoints de una especificación OpenAPI 2.x o 3.x."""
        # OpenAPI 3.x
        paths = spec.get("paths", {})
        servers = spec.get("servers", [{"url": base}])
        api_base = servers[0].get("url", base) if servers else base
        if not api_base.startswith("http"):
            api_base = base.rstrip("/") + "/" + api_base.lstrip("/")

        for path, methods in paths.items():
            for method, details in methods.items():
                if method.lower() not in ("get", "post", "put", "patch", "delete"):
                    continue
                full_url = api_base.rstrip("/") + path
                params = details.get("parameters", [])
                request_body = details.get("requestBody", {})
                schema = {}
                if request_body:
                    content = request_body.get("content", {})
                    for ct, ct_data in content.items():
                        schema = ct_data.get("schema", {}).get("properties", {})
                        break

                self._discovered_endpoints.append({
                    "url": full_url,
                    "method": method.upper(),
                    "params": [p.get("name") for p in params if p.get("in") in ("path", "query")],
                    "body_schema": list(schema.keys()),
                    "has_id": any("{" in path and "id" in path.lower()
                                 for _ in [None]),
                    "path_template": path,
                })

    def _extract_endpoints_from_js(self, base: str):
        """Extrae endpoints de archivos JavaScript del frontend."""
        try:
            r = self.session.get(base, timeout=TIMEOUT)
            js_urls = re.findall(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', r.text)
        except Exception:
            return

        api_pattern = re.compile(
            r'["\`\']((?:/api/|/v\d/|/rest/)[^\s"\'`<>{}|\\^]+)["\`\']',
            re.IGNORECASE
        )

        for js_path in js_urls[:10]:
            js_url = urljoin(base, js_path)
            try:
                r = self.session.get(js_url, timeout=TIMEOUT)
                for m in api_pattern.finditer(r.text):
                    endpoint = m.group(1)
                    full_url = base.rstrip("/") + endpoint
                    method = "GET"
                    if any(word in r.text[max(0, m.start()-50):m.end()+50].lower()
                           for word in ("post", "put", "patch", "delete")):
                        method = "POST"
                    if not any(e["url"] == full_url for e in self._discovered_endpoints):
                        self._discovered_endpoints.append({
                            "url": full_url, "method": method,
                            "params": [], "body_schema": [], "has_id": "{id}" in endpoint,
                            "path_template": endpoint,
                        })
            except Exception:
                pass

    def _extract_endpoints_from_json(self, data, base: str, prefix: str):
        """Extrae URLs de una respuesta JSON de descubrimiento de API."""
        if isinstance(data, dict):
            for key, val in data.items():
                if isinstance(val, str) and val.startswith("/"):
                    full = base.rstrip("/") + val
                    self._discovered_endpoints.append({
                        "url": full, "method": "GET", "params": [],
                        "body_schema": [], "has_id": False, "path_template": val,
                    })
                elif isinstance(val, (dict, list)):
                    self._extract_endpoints_from_json(val, base, prefix)
        elif isinstance(data, list):
            for item in data[:20]:
                self._extract_endpoints_from_json(item, base, prefix)

    # ── 2. BOLA / IDOR ────────────────────────────────────────────────────────

    def _check_bola(self, base: str):
        """Broken Object Level Authorization — accede a recursos de otros usuarios."""
        print("  [*] Probando BOLA/IDOR en endpoints con ID...")

        # Endpoints a probar: descubiertos + comunes con ID
        endpoints_with_id = [
            e for e in self._discovered_endpoints
            if any(p in e.get("path_template", "") for p in ("{id}", "{user_id}", "{userId}"))
               or re.search(r'/\d+', e["url"])
        ]

        # Añadir endpoints comunes con ID
        common_id_paths = [
            "/api/v1/users/{id}", "/api/users/{id}", "/api/v1/profile/{id}",
            "/api/v1/orders/{id}", "/api/orders/{id}",
            "/api/v1/account/{id}", "/api/account/{id}",
            "/api/v1/documents/{id}", "/api/documents/{id}",
            "/api/v1/invoices/{id}", "/api/invoices/{id}",
            "/api/v1/files/{id}", "/api/files/{id}",
            "/api/v1/posts/{id}", "/api/posts/{id}",
            "/api/v1/messages/{id}", "/api/messages/{id}",
        ]
        for path_tmpl in common_id_paths:
            endpoints_with_id.append({
                "url": base.rstrip("/") + path_tmpl.replace("{id}", "1"),
                "method": "GET", "params": [], "body_schema": [],
                "has_id": True, "path_template": path_tmpl,
            })

        seen_paths: set[str] = set()
        for ep in endpoints_with_id[:20]:
            path_tmpl = ep.get("path_template", "")
            if path_tmpl in seen_paths:
                continue
            seen_paths.add(path_tmpl)
            self._test_bola_endpoint(base, ep)

    def _test_bola_endpoint(self, base: str, ep: dict):
        """Prueba IDOR en un endpoint concreto con variación de IDs."""
        ids_to_try = [1, 2, 3, 0, -1, 9999, 100, 999999]
        responses = {}

        for id_val in ids_to_try[:5]:
            url = re.sub(r'\{[^}]+\}', str(id_val), ep["url"])
            url = re.sub(r'/\d+', f'/{id_val}', url)
            try:
                time.sleep(self.delay)
                r = self.session.get(url, timeout=TIMEOUT)
                responses[id_val] = {
                    "status": r.status_code,
                    "len": len(r.text),
                    "has_data": r.status_code == 200 and len(r.text) > 50,
                    "text": r.text[:200] if r.status_code == 200 else "",
                }
            except Exception:
                pass

        # IDOR confirmado si: múltiples IDs devuelven 200 con datos distintos
        success_ids = [i for i, d in responses.items() if d["has_data"]]
        if len(success_ids) >= 2:
            # Verificar que los datos son distintos (distintos usuarios/recursos)
            texts = [responses[i]["text"] for i in success_ids[:3]]
            if len(set(texts)) >= 2:
                self._add(
                    "CRITICAL",
                    f"BOLA/IDOR — Acceso a recursos de otros usuarios ({ep['path_template']})",
                    f"El endpoint {ep['path_template']} devuelve datos para IDs {success_ids[:3]} "
                    f"sin verificar autorización. IDs probados: {list(responses.keys())}",
                    "Un atacante puede acceder a los datos de cualquier usuario simplemente "
                    "cambiando el ID en la URL. Esto expone información personal, historial "
                    "de pedidos, documentos privados, mensajes y cualquier otro recurso del sistema.",
                    "Verificar en cada petición que el usuario autenticado tiene acceso al recurso solicitado. "
                    "Nunca confiar en el ID del objeto de la URL — comparar con el ID del usuario de la sesión. "
                    "Usar IDs no predecibles (UUID v4) para dificultar la enumeración. "
                    "Implementar autorización a nivel de objeto en cada endpoint (no solo a nivel de ruta)."
                )
                print(f"  [CRITICAL] BOLA/IDOR en {ep['path_template']} — IDs {success_ids[:3]} accesibles")

    # ── 3. Mass Assignment ────────────────────────────────────────────────────

    def _check_mass_assignment(self, base: str):
        """Prueba si el servidor acepta campos extra en POST/PUT que no debería."""
        print("  [*] Probando Mass Assignment en endpoints POST/PUT...")

        # Endpoints de registro/update de usuario
        update_endpoints = [
            e for e in self._discovered_endpoints
            if e["method"] in ("POST", "PUT", "PATCH")
        ]

        common_update_paths = [
            ("/api/v1/users/register", "POST"),
            ("/api/register", "POST"),
            ("/api/users", "POST"),
            ("/api/v1/profile", "PUT"),
            ("/api/profile", "PUT"),
            ("/api/v1/account", "PUT"),
            ("/api/account", "PATCH"),
            ("/api/v1/me", "PUT"),
            ("/api/me", "PATCH"),
        ]
        for path, method in common_update_paths:
            update_endpoints.append({
                "url": base.rstrip("/") + path,
                "method": method,
                "params": [], "body_schema": [],
                "has_id": False, "path_template": path,
            })

        seen: set[str] = set()
        for ep in update_endpoints[:15]:
            key = f"{ep['method']}:{ep.get('path_template', ep['url'])}"
            if key in seen:
                continue
            seen.add(key)
            self._test_mass_assignment(ep)

    def _test_mass_assignment(self, ep: dict):
        """Envía campos sensibles extra y verifica si son aceptados."""
        # Payload base legítimo
        base_payload = {
            "username": "auditpyme_test",
            "email": "test@auditpyme.local",
            "password": "TestPass123!",
            "name": "AuditPyme Test",
        }

        try:
            # Petición base sin campos sensibles
            time.sleep(self.delay)
            base_resp = self.session.request(
                ep["method"], ep["url"],
                json=base_payload, timeout=TIMEOUT
            )
        except Exception:
            return

        # Ahora añadir campos sensibles uno a uno
        for extra_field in MASS_ASSIGNMENT_FIELDS:
            test_payload = {**base_payload, **extra_field}
            field_name = list(extra_field.keys())[0]
            field_val = list(extra_field.values())[0]
            try:
                time.sleep(self.delay)
                r = self.session.request(
                    ep["method"], ep["url"],
                    json=test_payload, timeout=TIMEOUT
                )
                # Hit si: respuesta 200/201 y el campo aparece en la respuesta
                if r.status_code in (200, 201):
                    resp_text = r.text.lower()
                    field_reflected = (
                        str(field_val).lower() in resp_text and
                        field_name.lower() in resp_text and
                        r.text != base_resp.text
                    )
                    if field_reflected:
                        self._add(
                            "HIGH",
                            f"Mass Assignment — campo '{field_name}' aceptado en {ep['method']} {ep.get('path_template', ep['url'])}",
                            f"El servidor aceptó el campo '{field_name}': {field_val} en {ep['url']}. "
                            f"El campo aparece reflejado en la respuesta.",
                            f"Un atacante puede elevar sus propios privilegios enviando '{field_name}': true/admin "
                            "en el registro o actualización de perfil. Permite escalar a administrador "
                            "sin necesitar ninguna vulnerabilidad adicional.",
                            "Usar un DTO (Data Transfer Object) con allowlist de campos aceptados. "
                            "Nunca pasar el body de la petición directamente al ORM. "
                            "En Rails: usar strong parameters. En Django: especificar 'fields' en el serializer. "
                            "En Node: usar joi/zod para validar y filtrar el body."
                        )
                        print(f"  [HIGH] Mass Assignment: '{field_name}'={field_val} aceptado en {ep['method']} {ep['url'][:60]}")
                        return
            except Exception:
                pass

    # ── 4. BFLA — Broken Function Level Authorization ─────────────────────────

    def _check_bfla(self, base: str):
        """Accede a endpoints de administración con token de usuario normal."""
        print("  [*] Probando BFLA — acceso a endpoints de admin...")

        headers_to_try = [{}]
        if self._auth_token:
            headers_to_try.append({"Authorization": f"Bearer {self._auth_token}"})

        for admin_path in ADMIN_API_PATHS:
            url = base.rstrip("/") + admin_path
            for headers in headers_to_try:
                try:
                    time.sleep(self.delay)
                    # Probar GET primero
                    r = self.session.get(url, headers=headers, timeout=TIMEOUT)
                    if r.status_code in (200, 201):
                        try:
                            data = r.json()
                        except Exception:
                            data = {}
                        if len(r.text) > 50 and not any(
                            w in r.text.lower() for w in
                            ("unauthorized", "forbidden", "access denied", "not found")
                        ):
                            auth_context = "con token de usuario" if headers else "sin autenticación"
                            self._add(
                                "CRITICAL" if headers else "HIGH",
                                f"BFLA — Endpoint de admin accesible {auth_context} ({admin_path})",
                                f"El endpoint {url} devolvió HTTP 200 {auth_context}. "
                                f"Respuesta: {r.text[:150].strip()}",
                                "Acceso a funciones administrativas sin autorización. "
                                "Puede permitir ver todos los usuarios, modificar configuración del sistema, "
                                "acceder a datos internos o ejecutar operaciones privilegiadas.",
                                "Implementar autorización a nivel de función en cada endpoint de admin. "
                                "No confiar solo en que la ruta 'parece de admin' — verificar el rol del token. "
                                "Aplicar principio de mínimo privilegio: los endpoints de admin solo "
                                "deben ser accesibles por roles explícitamente autorizados."
                            )
                            auth_str = "autenticado" if headers else "sin auth"
                            print(f"  [{'CRITICAL' if headers else 'HIGH'}] BFLA: {admin_path} ({auth_str})")
                            break
                except Exception:
                    pass

    # ── 5. API Versioning — versiones antiguas sin parchear ──────────────────

    def _check_api_versioning(self, base: str):
        """Detecta versiones antiguas de la API que pueden estar sin parchear."""
        print("  [*] Buscando versiones antiguas de la API...")

        # Detectar la versión actual de la API
        current_versions = set()
        for ep in self._discovered_endpoints:
            m = re.search(r'/v(\d+)/', ep.get("path_template", ep["url"]))
            if m:
                current_versions.add(f"v{m.group(1)}")

        if not current_versions:
            current_versions = {"v1"}  # asumir v1 si no se detectó

        for current_ver in current_versions:
            alt_versions = API_VERSION_PATTERNS.get(current_ver, ["v1", "v2", "beta"])
            for alt_ver in alt_versions:
                # Reemplazar la versión en los endpoints conocidos
                for ep in self._discovered_endpoints[:10]:
                    old_url = ep["url"].replace(f"/{current_ver}/", f"/{alt_ver}/")
                    if old_url == ep["url"]:
                        continue
                    try:
                        time.sleep(self.delay)
                        r = self.session.get(old_url, timeout=TIMEOUT)
                        if r.status_code in (200, 401) and len(r.text) > 20:
                            self._add(
                                "HIGH",
                                f"API versión antigua accesible — /{alt_ver}/ ({old_url})",
                                f"La versión /{alt_ver}/ de la API responde en {old_url} "
                                f"(HTTP {r.status_code}). La versión actual es /{current_ver}/.",
                                "Las versiones antiguas de la API suelen tener menos controles de seguridad, "
                                "pueden carecer de autenticación en algunos endpoints, y contienen "
                                "vulnerabilidades ya parcheadas en versiones nuevas.",
                                f"Deshabilitar la versión /{alt_ver}/ si no es necesaria. "
                                "Si debe mantenerse por compatibilidad, aplicar los mismos controles "
                                "de seguridad que la versión actual. "
                                "Devolver 410 Gone en lugar de 200 para versiones discontinuadas."
                            )
                            print(f"  [HIGH] API versión antigua: /{alt_ver}/ accesible ({old_url})")
                            break
                    except Exception:
                        pass

    # ── 6. Excessive Data Exposure ────────────────────────────────────────────

    def _check_excessive_data(self, base: str):
        """Detecta endpoints que devuelven más datos de los necesarios."""
        print("  [*] Comprobando exposición excesiva de datos en respuestas API...")

        # Campos sensibles que no deberían aparecer en respuestas de API
        sensitive_fields = [
            "password", "passwd", "pwd", "hash", "salt",
            "secret", "private_key", "api_key", "api_secret",
            "token", "access_token", "refresh_token",
            "ssn", "social_security", "credit_card", "card_number",
            "cvv", "pin", "bank_account",
            "internal_id", "system_id",
        ]

        for ep in self._discovered_endpoints[:20]:
            if ep["method"] != "GET":
                continue
            try:
                time.sleep(self.delay)
                r = self.session.get(ep["url"], timeout=TIMEOUT)
                if r.status_code != 200 or len(r.text) < 20:
                    continue
                try:
                    data = r.json()
                except Exception:
                    continue

                # Buscar campos sensibles en la respuesta
                data_str = json.dumps(data).lower()
                found_sensitive = [f for f in sensitive_fields if f'"' + f + '"' in data_str]

                if found_sensitive:
                    self._add(
                        "HIGH",
                        f"Exposición excesiva de datos — {ep.get('path_template', ep['url'])}",
                        f"El endpoint {ep['url']} devuelve campos sensibles: {found_sensitive}. "
                        f"Respuesta (preview): {r.text[:200]}",
                        "Los campos sensibles en respuestas API exponen información que los clientes "
                        "no necesitan y que puede ser explotada: hashes de contraseñas permiten "
                        "ataques offline, tokens activos permiten suplantación.",
                        "Usar un serializer/DTO que incluya explícitamente solo los campos necesarios. "
                        "Nunca devolver campos de password (ni hashed). "
                        "Filtrar tokens y secrets de las respuestas. "
                        "Principio de mínimo privilegio también en los datos retornados."
                    )
                    print(f"  [HIGH] Datos sensibles en respuesta: {ep['url'][:60]} — {found_sensitive}")
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
            "tipo":          "API",
            "nombre":        nombre,
            "descripcion":   descripcion,
            "impacto":       impacto,
            "recomendacion": recomendacion,
        })
