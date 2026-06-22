"""
Módulo de WebSocket Security — AuditPyme
Detecta: falta de autenticación, validación de Origin débil, inyección en mensajes.
"""

import re
import socket
import ssl
import base64
import hashlib
import os
import json
import time
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
TIMEOUT = 10
UA = "Mozilla/5.0 (compatible; AuditPyme/1.0)"
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# Payloads de inyección para mensajes WebSocket
WS_INJECTION_PAYLOADS = [
    # XSS
    ('{"message": "<script>alert(1)</script>"}', "XSS en mensaje WS"),
    ('{"username": "admin\' OR \'1\'=\'1"}', "SQLi en campo usuario"),
    ('{"cmd": "ls -la"}', "Command injection"),
    ('{"path": "../../../etc/passwd"}', "Path traversal"),
    ('{"template": "{{7*7}}"}', "SSTI"),
    ('{"query": "__import__(\'os\').system(\'id\')"}', "Python injection"),
    # Prototype pollution (Node.js)
    ('{"__proto__": {"polluted": "ws_audit"}}', "Prototype Pollution"),
    # JSON injection
    ('{"key": "val", "admin": true}', "Mass assignment via WS"),
    ('{"id": "1 OR 1=1"}', "SQLi en ID"),
]

# Rutas comunes de WebSocket
WS_PATHS = [
    "/ws", "/websocket", "/socket", "/socket.io/",
    "/ws/chat", "/ws/notifications", "/ws/live",
    "/api/ws", "/api/websocket", "/stream",
    "/live", "/realtime", "/push",
    "/chat", "/notifications", "/updates",
    "/signalr/negotiate", "/sockjs/",
    "/cable",           # ActionCable (Rails)
    "/faye",            # Faye
]


class WebSocketScanner:

    def __init__(self, target: str, recon_data: dict = None, stealth: bool = False):
        self.target = target
        self.recon_data = recon_data or {}
        self.findings = []
        self.delay = 0.5 if stealth else 0.1
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA})
        self.session.verify = False
        self._base_urls = self._build_base_urls()
        self._ws_endpoints = []

    def scan(self) -> list:
        print(f"\n  [*] WebSocket Security scan: {self.target}")
        self._discover_ws_endpoints()

        if not self._ws_endpoints:
            print("  [!] No se encontraron endpoints WebSocket")
            return self.findings

        print(f"  [*] {len(self._ws_endpoints)} endpoints WS encontrados")
        for ws_url, proto, host, port, path in self._ws_endpoints:
            self._check_origin_validation(ws_url, proto, host, port, path)
            self._check_authentication(ws_url, proto, host, port, path)
            self._check_injection(ws_url, proto, host, port, path)

        if not self.findings:
            print("  [OK] No se detectaron vulnerabilidades WebSocket evidentes")
        return self.findings

    # ── Descubrimiento de endpoints WS ───────────────────────────────────────

    def _discover_ws_endpoints(self):
        """Busca endpoints WS en el HTML, JS y prueba rutas comunes."""
        for base in self._base_urls:
            # Extraer de HTML/JS
            try:
                r = self.session.get(base, timeout=TIMEOUT)
                # Buscar URLs ws:// y wss://
                ws_urls = re.findall(r'["\']?(wss?://[^\s"\'<>]+)["\']?', r.text)
                for ws_url in ws_urls:
                    ws_url = ws_url.rstrip("/'\"")
                    parsed = self._parse_ws_url(ws_url)
                    if parsed and parsed not in self._ws_endpoints:
                        self._ws_endpoints.append(parsed)
                        print(f"  [+] WS encontrado en HTML: {ws_url}")

                # Buscar en archivos JS referenciados
                scripts = re.findall(r'<script[^>]+src=["\']([^"\']+\.js)["\']', r.text)
                for script in scripts[:8]:
                    if not script.startswith("http"):
                        script = base.rstrip("/") + "/" + script.lstrip("/")
                    try:
                        js_r = self.session.get(script, timeout=TIMEOUT)
                        ws_in_js = re.findall(r'["\']?(wss?://[^\s"\'<>]+)["\']?', js_r.text)
                        for ws_url in ws_in_js:
                            ws_url = ws_url.rstrip("/'\"")
                            parsed = self._parse_ws_url(ws_url)
                            if parsed and parsed not in self._ws_endpoints:
                                self._ws_endpoints.append(parsed)
                                print(f"  [+] WS encontrado en JS: {ws_url}")
                        # Buscar también new WebSocket(url) con variables
                        dynamic = re.findall(r'new WebSocket\(["\']([^"\']+)["\']', js_r.text)
                        for ws_url in dynamic:
                            parsed = self._parse_ws_url(ws_url)
                            if parsed and parsed not in self._ws_endpoints:
                                self._ws_endpoints.append(parsed)
                    except Exception:
                        pass
            except Exception:
                pass

            # Probar rutas comunes
            for path in WS_PATHS:
                proto_ws = "wss" if "https" in base else "ws"
                host = self.target
                port = 443 if "https" in base else 80
                ws_url = f"{proto_ws}://{host}{path}"
                if self._ws_is_available(host, port, proto_ws, path):
                    entry = (ws_url, proto_ws, host, port, path)
                    if entry not in self._ws_endpoints:
                        self._ws_endpoints.append(entry)
                        print(f"  [+] WS disponible en: {ws_url}")

    def _ws_is_available(self, host: str, port: int, proto: str, path: str) -> bool:
        """Verifica si un endpoint WS existe via HTTP Upgrade."""
        try:
            key = base64.b64encode(os.urandom(16)).decode()
            response = self._do_ws_handshake(host, port, proto, path, key,
                                             origin=f"https://{host}")
            return response and "101" in response[:50]
        except Exception:
            return False

    def _parse_ws_url(self, url: str):
        """Parsea una URL ws/wss a (ws_url, proto, host, port, path)."""
        try:
            m = re.match(r'(wss?)://([^/:]+)(?::(\d+))?(/?[^?#]*)', url)
            if not m:
                return None
            proto, host, port_str, path = m.groups()
            port = int(port_str) if port_str else (443 if proto == "wss" else 80)
            path = path or "/"
            return (url, proto, host, port, path)
        except Exception:
            return None

    # ── Validación de Origin ──────────────────────────────────────────────────

    def _check_origin_validation(self, ws_url, proto, host, port, path):
        """Comprueba si el servidor acepta conexiones WS desde cualquier Origin."""
        evil_origins = [
            "https://evil.com",
            "https://attacker.example.com",
            "null",
            "file://",
        ]
        key = base64.b64encode(os.urandom(16)).decode()
        for evil_origin in evil_origins:
            try:
                response = self._do_ws_handshake(host, port, proto, path, key,
                                                 origin=evil_origin)
                if response and "101 Switching Protocols" in response:
                    self._add(
                        "HIGH",
                        f"WebSocket — Origin no validado: {ws_url}",
                        f"El servidor acepta conexiones WebSocket desde Origin arbitrario. "
                        f"Origin de prueba: {evil_origin}\nURL: {ws_url}\n"
                        f"Respuesta: HTTP 101 Switching Protocols",
                        "Sin validación de Origin, cualquier sitio web malicioso puede abrir "
                        "una conexión WebSocket al servidor en nombre de un usuario autenticado "
                        "(CSRF sobre WebSocket). Permite leer datos del servidor y enviar "
                        "mensajes arbitrarios como si fuera el usuario legítimo.",
                        "Validar la cabecera Origin en el handshake WebSocket. "
                        "Comparar contra una whitelist de dominios permitidos. "
                        "En Node.js (ws): verificar en el callback 'verifyClient'. "
                        "Ejemplo: if (info.origin !== 'https://midominio.com') return false;"
                    )
                    print(f"  [HIGH] WS sin validación de Origin: {ws_url}")
                    return
            except Exception:
                pass

    # ── Autenticación ─────────────────────────────────────────────────────────

    def _check_authentication(self, ws_url, proto, host, port, path):
        """Comprueba si el WS requiere autenticación (sin token/cookie)."""
        try:
            key = base64.b64encode(os.urandom(16)).decode()
            # Handshake sin cookies ni Authorization
            response = self._do_ws_handshake(host, port, proto, path, key,
                                             origin=f"https://{host}",
                                             extra_headers=[])
            if response and "101 Switching Protocols" in response:
                # Intentar leer el primer mensaje del servidor
                ws_conn = self._open_ws_connection(host, port, proto, path, key)
                if ws_conn:
                    data = self._ws_recv(ws_conn)
                    ws_conn.close()
                    if data:
                        self._add(
                            "HIGH",
                            f"WebSocket — Sin autenticación requerida: {ws_url}",
                            f"El endpoint WebSocket acepta conexiones y envía datos "
                            f"sin requerir autenticación (sin token ni cookie de sesión). "
                            f"URL: {ws_url}\n"
                            f"Primer mensaje recibido: {str(data)[:200]}",
                            "Endpoint WebSocket accesible sin autenticación. "
                            "Un atacante puede conectarse y recibir/enviar datos en tiempo real "
                            "sin credenciales: notificaciones de otros usuarios, datos de negocio, "
                            "mensajes de chat privados, actualizaciones de estado.",
                            "Requerir autenticación antes de aceptar el handshake WS. "
                            "Validar el token JWT o la cookie de sesión en el handshake. "
                            "En Socket.io: usar middleware de autenticación. "
                            "En ws (Node.js): usar verifyClient para validar la sesión. "
                            "Alternativa: enviar el token en el primer mensaje y cerrar si no es válido."
                        )
                        print(f"  [HIGH] WS sin autenticación: {ws_url}")
        except Exception:
            pass

    # ── Inyección en mensajes ─────────────────────────────────────────────────

    def _check_injection(self, ws_url, proto, host, port, path):
        """Envía payloads de inyección a través del WebSocket."""
        key = base64.b64encode(os.urandom(16)).decode()
        ws_conn = self._open_ws_connection(host, port, proto, path, key)
        if not ws_conn:
            return

        try:
            for payload, label in WS_INJECTION_PAYLOADS[:4]:
                try:
                    time.sleep(self.delay)
                    self._ws_send(ws_conn, payload)
                    response = self._ws_recv(ws_conn)
                    if response:
                        resp_str = str(response)
                        # XSS: el payload se refleja sin escapar
                        if "<script>" in resp_str.lower() and "alert" in resp_str.lower():
                            self._add(
                                "HIGH",
                                f"WebSocket — XSS Reflejado en mensajes: {ws_url}",
                                f"El servidor refleja código JavaScript sin escapar en las "
                                f"respuestas WebSocket. Payload: {payload[:80]}\n"
                                f"Respuesta: {resp_str[:200]}",
                                "XSS en WebSocket permite ejecutar JavaScript en el contexto "
                                "de todos los clientes conectados si el mensaje se broadcast.",
                                "Escapar HTML en todos los mensajes WS antes de enviarlos. "
                                "Usar una CSP estricta. Sanitizar el input del usuario."
                            )
                            print(f"  [HIGH] WS XSS: {ws_url}")
                        # SQLi: errores de base de datos
                        elif any(e in resp_str.lower() for e in
                                 ["sql syntax", "mysql error", "pg error",
                                  "sqlite", "ora-", "unclosed quotation"]):
                            self._add(
                                "HIGH",
                                f"WebSocket — SQL Injection en mensajes: {ws_url}",
                                f"El servidor devuelve errores de base de datos al procesar "
                                f"mensajes WS malformados. Payload: {payload[:80]}\n"
                                f"Respuesta: {resp_str[:200]}",
                                "SQLi vía WebSocket permite extraer datos de la base de datos "
                                "y potencialmente RCE según el motor de base de datos.",
                                "Usar prepared statements/parameterized queries. "
                                "Nunca interpolar input WS directamente en queries SQL."
                            )
                            print(f"  [HIGH] WS SQLi: {ws_url}")
                        # SSTI: 49 como resultado de 7*7
                        elif "49" in resp_str and "{{7*7}}" not in resp_str:
                            self._add(
                                "CRITICAL",
                                f"WebSocket — SSTI en mensajes: {ws_url}",
                                f"El servidor evalúa expresiones de template en mensajes WS "
                                f"({{{{7*7}}}} → 49). URL: {ws_url}",
                                "SSTI vía WebSocket permite RCE en el servidor.",
                                "No renderizar templates con input de usuario. "
                                "Usar engines con sandboxing o escapar el input."
                            )
                            print(f"  [CRITICAL] WS SSTI: {ws_url}")
                except Exception:
                    pass
        finally:
            try:
                ws_conn.close()
            except Exception:
                pass

    # ── WebSocket handshake y framing ─────────────────────────────────────────

    def _do_ws_handshake(self, host: str, port: int, proto: str, path: str,
                          key: str, origin: str = None, extra_headers: list = None) -> str:
        """Realiza el handshake HTTP→WebSocket y devuelve la respuesta HTTP."""
        try:
            sock = socket.create_connection((host, port), timeout=TIMEOUT)
            if proto == "wss":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)

            headers = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
                f"User-Agent: {UA}\r\n"
            )
            if origin:
                headers += f"Origin: {origin}\r\n"
            headers += "\r\n"

            sock.sendall(headers.encode())
            response = b""
            sock.settimeout(5)
            try:
                while b"\r\n\r\n" not in response:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass
            sock.close()
            return response.decode("latin-1", errors="replace")
        except Exception:
            return ""

    def _open_ws_connection(self, host, port, proto, path, key):
        """Abre una conexión WebSocket y devuelve el socket si el handshake fue exitoso."""
        try:
            sock = socket.create_connection((host, port), timeout=TIMEOUT)
            if proto == "wss":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)

            handshake = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
                f"User-Agent: {UA}\r\n"
                f"Origin: https://{host}\r\n"
                f"\r\n"
            )
            sock.sendall(handshake.encode())
            response = b""
            sock.settimeout(5)
            try:
                while b"\r\n\r\n" not in response:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass

            if b"101 Switching Protocols" in response:
                return sock
            sock.close()
        except Exception:
            pass
        return None

    def _ws_send(self, sock, message: str):
        """Envía un frame WebSocket (text frame, sin masking para pruebas)."""
        data = message.encode("utf-8")
        length = len(data)
        mask_key = os.urandom(4)
        masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(data))

        frame = bytearray()
        frame.append(0x81)  # FIN + opcode text

        if length < 126:
            frame.append(0x80 | length)  # MASK bit set
        elif length < 65536:
            frame.append(0x80 | 126)
            frame += length.to_bytes(2, "big")
        else:
            frame.append(0x80 | 127)
            frame += length.to_bytes(8, "big")

        frame += mask_key
        frame += masked
        sock.sendall(bytes(frame))

    def _ws_recv(self, sock) -> str:
        """Lee un frame WebSocket y devuelve el payload como string."""
        try:
            sock.settimeout(3)
            header = sock.recv(2)
            if len(header) < 2:
                return ""
            opcode = header[0] & 0x0F
            length = header[1] & 0x7F

            if length == 126:
                length = int.from_bytes(sock.recv(2), "big")
            elif length == 127:
                length = int.from_bytes(sock.recv(8), "big")

            payload = b""
            while len(payload) < length:
                chunk = sock.recv(min(4096, length - len(payload)))
                if not chunk:
                    break
                payload += chunk

            return payload.decode("utf-8", errors="replace")
        except Exception:
            return ""

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

    def _add(self, severidad, nombre, descripcion, impacto, recomendacion):
        for f in self.findings:
            if f["nombre"] == nombre:
                return
        self.findings.append({
            "severidad": severidad, "tipo": "WebSocket",
            "nombre": nombre, "descripcion": descripcion,
            "impacto": impacto, "recomendacion": recomendacion,
        })
