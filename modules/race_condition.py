"""
Módulo de Race Conditions — AuditPyme
Detecta TOCTOU y condiciones de carrera en endpoints de e-commerce, cupones, pagos y votos.
"""

import requests
import urllib3
import re
import threading
import time
from collections import Counter
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
TIMEOUT = 12
UA = "Mozilla/5.0 (compatible; AuditPyme/1.0)"
CONCURRENT = 15  # peticiones concurrentes por prueba

# Patrones de endpoints típicamente vulnerables a race conditions
RACE_ENDPOINT_PATTERNS = [
    # E-commerce / cupones
    (r"/coupon", "coupon", "Cupón/Descuento"),
    (r"/promo", "promo", "Promoción"),
    (r"/redeem", "redeem", "Canjear recompensa"),
    (r"/voucher", "voucher", "Vale/Voucher"),
    (r"/gift[\-_]?card", "gift_card", "Tarjeta regalo"),
    (r"/discount", "discount", "Descuento"),
    # Pagos / transferencias
    (r"/payment", "payment", "Pago"),
    (r"/transfer", "transfer", "Transferencia"),
    (r"/withdraw", "withdraw", "Retirada de fondos"),
    (r"/checkout", "checkout", "Checkout"),
    (r"/order", "order", "Pedido"),
    # Votos / likes / límites
    (r"/vote", "vote", "Sistema de votos"),
    (r"/like", "like", "Sistema de likes"),
    (r"/upvote", "upvote", "Upvote"),
    (r"/rate", "rate", "Sistema de puntuación"),
    # Registros y límites únicos
    (r"/register", "register", "Registro de usuario"),
    (r"/signup", "signup", "Alta de usuario"),
    (r"/invite", "invite", "Sistema de invitaciones"),
    (r"/referral", "referral", "Programa de referidos"),
    # Límites de uso
    (r"/download", "download", "Descarga con límite"),
    (r"/export", "export", "Exportación de datos"),
    (r"/reset[\-_]?password", "password_reset", "Restablecimiento de contraseña"),
    (r"/confirm", "confirm", "Confirmación de acción"),
    (r"/2fa", "2fa", "Verificación 2FA"),
]

# Claves de respuesta que indican éxito/doble gasto
SUCCESS_INDICATORS = [
    '"success"', '"ok"', '"applied"', '"redeemed"', '"confirmed"',
    '"credited"', '"created"', '"activated"', '"accepted"',
    '"status":"success"', '"status":"ok"', '"status":200',
    '"error":false', '"valid":true',
]

DUPLICATE_INDICATORS = [
    '"already"', '"duplicate"', '"only once"', '"limit"',
    '"used"', '"expired"', '"invalid"', '"one per"',
]


class RaceConditionScanner:

    def __init__(self, target: str, recon_data: dict = None, stealth: bool = False):
        self.target = target
        self.recon_data = recon_data or {}
        self.findings = []
        self.stealth = stealth
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA})
        self.session.verify = False
        self._base_urls = self._build_base_urls()
        self._crawled_urls = []

    def scan(self) -> list:
        print(f"\n  [*] Race Condition scan: {self.target}")
        self._crawl_for_endpoints()

        if not self._crawled_urls:
            print("  [!] No se encontraron URLs para analizar")
            return self.findings

        print(f"  [*] Analizando {len(self._crawled_urls)} endpoints")
        for url, method, label in self._crawled_urls:
            self._test_race_condition(url, method, label)

        # Prueba adicional: endpoints de transferencia/pago con IDs de prueba
        for base in self._base_urls:
            self._test_generic_race(base)

        if not self.findings:
            print("  [OK] No se detectaron condiciones de carrera evidentes")
        return self.findings

    # ── Crawling de endpoints vulnerables ────────────────────────────────────

    def _crawl_for_endpoints(self):
        """Descubre endpoints en el sitio que coincidan con patrones de riesgo."""
        for base in self._base_urls:
            try:
                r = self.session.get(base, timeout=TIMEOUT)
                links = re.findall(r'(?:href|action)=["\']([^"\']+)["\']', r.text)
                for link in links:
                    if not link.startswith("http"):
                        link = urljoin(base, link)
                    if self.target in link:
                        self._categorize_url(link)

                # Extraer de JS
                scripts = re.findall(r'<script[^>]*src=["\']([^"\']+\.js)["\']', r.text)
                for script in scripts[:5]:
                    if not script.startswith("http"):
                        script = urljoin(base, script)
                    try:
                        js = self.session.get(script, timeout=TIMEOUT)
                        js_urls = re.findall(r'["\']/([\w\-/]+)["\']', js.text)
                        for jurl in js_urls:
                            full = urljoin(base, "/" + jurl)
                            self._categorize_url(full)
                    except Exception:
                        pass
            except Exception:
                pass

    def _categorize_url(self, url: str):
        parsed = urlparse(url)
        path = parsed.path.lower()
        for pattern, key, label in RACE_ENDPOINT_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                # Determinar si POST o GET
                method = "POST" if any(x in path for x in ("redeem", "payment", "transfer",
                                                             "coupon", "promo", "withdraw",
                                                             "register", "signup", "vote",
                                                             "like", "confirm")) else "GET"
                entry = (url, method, label)
                if entry not in self._crawled_urls:
                    self._crawled_urls.append(entry)
                return

    # ── Test de race condition ────────────────────────────────────────────────

    def _test_race_condition(self, url: str, method: str, label: str):
        """Lanza CONCURRENT peticiones simultáneas y analiza las respuestas."""
        print(f"  [*] Probando race condition en {label}: {url}")

        results = []
        lock = threading.Lock()
        barrier = threading.Barrier(CONCURRENT)

        def _worker():
            try:
                barrier.wait(timeout=5)  # Sincronizar todas las peticiones
                if method == "POST":
                    r = self.session.post(url, json={}, timeout=TIMEOUT)
                else:
                    r = self.session.get(url, timeout=TIMEOUT)
                with lock:
                    results.append((r.status_code, r.text[:500]))
            except Exception as e:
                with lock:
                    results.append((0, str(e)[:100]))

        threads = [threading.Thread(target=_worker) for _ in range(CONCURRENT)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)

        self._analyze_results(url, label, results)

    def _test_generic_race(self, base: str):
        """Prueba endpoints típicos de transferencia con parámetros de prueba."""
        test_endpoints = [
            (f"{base}/api/redeem", "POST", {"coupon": "RACE_TEST_9X8Z", "amount": 1}),
            (f"{base}/api/coupon/apply", "POST", {"code": "RACE_TEST_9X8Z"}),
            (f"{base}/api/transfer", "POST", {"to": "test", "amount": 0.01}),
        ]
        for url, method, data in test_endpoints:
            results = []
            lock = threading.Lock()
            barrier = threading.Barrier(CONCURRENT)

            def _worker(u=url, d=data):
                try:
                    barrier.wait(timeout=5)
                    r = self.session.post(u, json=d, timeout=TIMEOUT)
                    with lock:
                        results.append((r.status_code, r.text[:500]))
                except Exception:
                    pass

            threads = [threading.Thread(target=_worker) for _ in range(CONCURRENT)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=15)

            if results:
                self._analyze_results(url, "Endpoint genérico", results)

    def _analyze_results(self, url: str, label: str, results: list):
        """Analiza las respuestas para detectar double-spend."""
        if not results:
            return

        status_counts = Counter(r[0] for r in results)
        success_count = sum(
            1 for _, text in results
            if any(ind.lower() in text.lower() for ind in SUCCESS_INDICATORS)
        )
        error_count = sum(
            1 for _, text in results
            if any(ind.lower() in text.lower() for ind in DUPLICATE_INDICATORS)
        )
        ok_200 = status_counts.get(200, 0)

        # Race condition detectada: múltiples respuestas de éxito para acción que debería ser única
        if success_count > 1 and (error_count == 0 or success_count > error_count // 2):
            self._add(
                "HIGH",
                f"Race Condition — {label}: {url}",
                f"Se enviaron {CONCURRENT} peticiones simultáneas al endpoint '{label}'. "
                f"Se recibieron {success_count} respuestas de éxito — una acción que debería "
                f"ejecutarse una sola vez se ejecutó {success_count} veces. "
                f"URL: {url}\n"
                f"Distribución de estados: {dict(status_counts)}",
                f"Un atacante puede explotar esta condición de carrera para: "
                f"canjear un cupón múltiples veces, transferir fondos duplicados, "
                f"votar/dar like más de una vez, saltarse límites de uso único. "
                f"El impacto económico depende del endpoint afectado.",
                "Implementar bloqueos a nivel de base de datos (SELECT FOR UPDATE). "
                "Usar transacciones ACID con aislamiento SERIALIZABLE. "
                "Añadir campo 'processed_at' con índice único en la tabla. "
                "Usar Redis SETNX para locks distribuidos con TTL. "
                "Implementar Idempotency Keys en las peticiones de pago."
            )
            print(f"  [HIGH] Race condition detectada: {success_count}/{CONCURRENT} éxitos en {label}")

        elif ok_200 > CONCURRENT // 2 and success_count == 0:
            # Muchos 200 pero sin texto de éxito claro — posible vulnerable
            self._add(
                "MEDIUM",
                f"Posible Race Condition — {label}: {url}",
                f"El endpoint '{label}' devolvió {ok_200}/{CONCURRENT} respuestas HTTP 200 "
                f"a peticiones concurrentes. Requiere verificación manual. URL: {url}",
                "Si el endpoint no implementa bloqueos de concurrencia, "
                "puede ser explotable para duplicar acciones de valor.",
                "Revisar el código del endpoint para verificar el uso de transacciones "
                "y bloqueos de concurrencia en operaciones de negocio críticas."
            )
            print(f"  [MEDIUM] Posible race condition en {label} — verificar manualmente")

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
            "severidad": severidad, "tipo": "Race Condition",
            "nombre": nombre, "descripcion": descripcion,
            "impacto": impacto, "recomendacion": recomendacion,
        })
