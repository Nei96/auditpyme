"""
Módulo de lógica de negocio — AuditPyme
Detecta: manipulación de precios, cantidades negativas, bypass de cupones,
parameter pollution, mass assignment y CORS en endpoints autenticados.
"""

import requests
import urllib3
import re
import json
import time
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
TIMEOUT = 12
UA = "Mozilla/5.0 (compatible; AuditPyme/1.0)"

# Cupones comunes que se suelen olvidar en producción
COMMON_COUPONS = [
    "TEST", "test", "PRUEBA", "prueba", "DEMO", "demo",
    "ADMIN", "admin", "DESCUENTO", "descuento",
    "FREE", "free", "GRATIS", "gratis",
    "DISCOUNT10", "DISCOUNT20", "DISCOUNT50", "DISCOUNT100",
    "10OFF", "20OFF", "50OFF", "100OFF",
    "SAVE10", "SAVE20", "SAVE50",
    "2024", "2025", "VIP", "STAFF",
    "EMPLOYEE", "EMPLEADO", "INTERNO", "INTERNAL",
    "DEBUG", "DEV", "DEVELOPMENT",
]

# Campos que suelen contener precios o totales
PRICE_FIELD_PATTERNS = re.compile(
    r'(?i)(price|precio|amount|importe|total|cost|coste|subtotal|'
    r'product_price|item_price|unit_price|valor|value)',
)

# Campos de cantidad
QTY_FIELD_PATTERNS = re.compile(
    r'(?i)(qty|quantity|cantidad|count|amount|num|numero|units)',
)

# Patrones de éxito en respuesta (precio aceptado / pedido creado)
SUCCESS_PATTERNS = [
    "order", "pedido", "confirmado", "confirmed", "success",
    "éxito", "procesado", "processed", "thank you", "gracias",
    "cart", "carrito", "added", "añadido",
]

# Indicadores de que el campo de precio fue validado correctamente
PRICE_VALIDATED = [
    "precio no válido", "invalid price", "price mismatch",
    "precio incorrecto", "amount mismatch", "total incorrecto",
]


class BusinessLogicAuditor:
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
        print(f"\n  [*] Análisis de lógica de negocio en: {self.target}")
        for base_url in self._base_urls:
            self._check_cors(base_url)
            forms = self._find_ecommerce_forms(base_url)
            if forms:
                print(f"  [+] {len(forms)} formulario(s) de e-commerce encontrado(s)")
                for form in forms:
                    self._check_price_manipulation(form)
                    self._check_negative_quantity(form)
                    self._check_parameter_pollution(form)
                    self._check_mass_assignment(form)
            self._check_coupon_bypass(base_url)
            self._check_api_mass_assignment(base_url)

        if not self.findings:
            print("  [OK] No se detectaron problemas de lógica de negocio")
        return self.findings

    # ── CORS misconfiguration ─────────────────────────────────────────────────

    def _check_cors(self, base_url: str):
        """Detecta CORS mal configurado que permite peticiones cross-origin con credenciales."""
        print(f"  [*] Comprobando CORS en {base_url}...")
        endpoints = [base_url, base_url + "/api/v1", base_url + "/wp-json/wp/v2/users"]

        for endpoint in endpoints:
            try:
                # Test 1: Origin reflection (el servidor refleja cualquier origen)
                evil_origin = "https://attacker-auditpyme.com"
                r = self.session.get(endpoint, timeout=TIMEOUT,
                                     headers={"Origin": evil_origin, "User-Agent": UA})
                acao = r.headers.get("Access-Control-Allow-Origin", "")
                acac = r.headers.get("Access-Control-Allow-Credentials", "")

                if acao == evil_origin:
                    if acac.lower() == "true":
                        self._add(
                            "CRITICAL",
                            f"CORS: Origin reflection con credenciales en {endpoint}",
                            f"El servidor refleja cualquier Origin en Access-Control-Allow-Origin "
                            f"y además permite credenciales (ACAC: true). "
                            f"Endpoint: {endpoint}",
                            "Un atacante puede crear una página web maliciosa que haga peticiones "
                            "autenticadas a la API de la empresa con las cookies del usuario víctima, "
                            "extrayendo datos privados sin que el usuario lo sepa.",
                            "Usar una whitelist explícita de orígenes permitidos. "
                            "Nunca combinar Access-Control-Allow-Credentials: true con origen dinámico. "
                            "Si se necesita CORS público, usar solo para endpoints sin datos sensibles."
                        )
                        print(f"  [CRITICAL] CORS reflection + credenciales: {endpoint}")
                    else:
                        self._add(
                            "MEDIUM",
                            f"CORS: Origin reflection en {endpoint}",
                            f"El servidor acepta cualquier origen (refleja el header Origin). "
                            f"Endpoint: {endpoint}",
                            "Permite lectura cross-origin de respuestas públicas. "
                            "Si el endpoint requiere autenticación y tiene ACAC:true, es crítico.",
                            "Definir una whitelist explícita de dominios permitidos."
                        )
                        print(f"  [MEDIUM] CORS origin reflection: {endpoint}")
                    break  # un hallazgo por base_url es suficiente

                # Test 2: null origin (iframes, data: URIs)
                r2 = self.session.get(endpoint, timeout=TIMEOUT,
                                      headers={"Origin": "null", "User-Agent": UA})
                acao2 = r2.headers.get("Access-Control-Allow-Origin", "")
                if acao2 == "null":
                    self._add(
                        "HIGH",
                        f"CORS: null origin permitido en {endpoint}",
                        f"El servidor acepta Origin: null, que puede ser enviado desde "
                        f"iframes con sandbox o URIs data:. Endpoint: {endpoint}",
                        "Permite a un atacante embeber la página en un iframe sandboxed "
                        "y leer la respuesta cross-origin.",
                        "No permitir Origin: null en producción."
                    )
                    print(f"  [HIGH] CORS null origin permitido: {endpoint}")
                    break

            except Exception:
                continue

    # ── Búsqueda de formularios e-commerce ───────────────────────────────────

    def _find_ecommerce_forms(self, base_url: str) -> list:
        """Busca formularios con campos de precio o cantidad."""
        forms = []
        pages = [base_url]

        for path in ["/cart", "/carrito", "/checkout", "/pago", "/compra",
                     "/shop", "/tienda", "/product", "/producto",
                     "/?add-to-cart=1", "/index.php?controller=cart"]:
            pages.append(base_url.rstrip("/") + path)

        for url in pages[:10]:
            try:
                r = self.session.get(url, timeout=TIMEOUT, allow_redirects=True)
                if r.status_code != 200:
                    continue
                page_forms = self._parse_ecommerce_forms(r.text, r.url)
                for f in page_forms:
                    if f["action"] not in [x["action"] for x in forms]:
                        forms.append(f)
                        print(f"  [FORM] E-commerce en: {f['action']}")
            except Exception:
                continue
        return forms

    def _parse_ecommerce_forms(self, html: str, page_url: str) -> list:
        forms = []
        form_blocks = re.finditer(
            r'(<form[^>]*>)(.*?)(</form>)', html, re.IGNORECASE | re.DOTALL
        )
        for match in form_blocks:
            form_tag  = match.group(1)
            form_body = match.group(2)

            # Extraer todos los inputs
            inputs = {}
            for tag in re.findall(r'<input[^>]+>', form_body, re.IGNORECASE):
                n = re.search(r'name=["\']([^"\']+)["\']', tag, re.IGNORECASE)
                v = re.search(r'value=["\']([^"\']*)["\']', tag, re.IGNORECASE)
                t = re.search(r'type=["\']([^"\']+)["\']', tag, re.IGNORECASE)
                if n:
                    inputs[n.group(1)] = {
                        "value": v.group(1) if v else "",
                        "type":  t.group(1).lower() if t else "text",
                    }

            # ¿Hay campos de precio o cantidad?
            price_fields = [k for k in inputs if PRICE_FIELD_PATTERNS.search(k)]
            qty_fields   = [k for k in inputs if QTY_FIELD_PATTERNS.search(k)]
            if not price_fields and not qty_fields:
                continue

            # Action del form
            action_m = re.search(r'action=["\']([^"\']*)["\']', form_tag, re.IGNORECASE)
            action = urljoin(page_url, action_m.group(1)) if action_m else page_url

            forms.append({
                "action":       action,
                "inputs":       inputs,
                "price_fields": price_fields,
                "qty_fields":   qty_fields,
                "page_url":     page_url,
            })
        return forms

    # ── Check 1: Manipulación de precios ──────────────────────────────────────

    def _check_price_manipulation(self, form: dict):
        if not form["price_fields"]:
            return
        print(f"  [*] Probando manipulación de precio en {form['action']}...")
        data_original = {k: v["value"] for k, v in form["inputs"].items()
                         if v["type"] != "submit"}
        data_manipulated = dict(data_original)

        for field in form["price_fields"]:
            original_val = data_original.get(field, "100")
            # Probar precio 0, 1 céntimo, y negativo
            for tampered in ["0", "0.01", "1", "-1", "0.00"]:
                data_manipulated[field] = tampered
                time.sleep(self.delay)
                try:
                    r = self.session.post(form["action"], data=data_manipulated,
                                         timeout=TIMEOUT, allow_redirects=True)
                    body = r.text.lower()
                    if (r.status_code in (200, 302) and
                            any(s in body for s in SUCCESS_PATTERNS) and
                            not any(e in body for e in PRICE_VALIDATED)):
                        self._add(
                            "CRITICAL",
                            f"Manipulación de precio aceptada — campo '{field}'",
                            f"El formulario en {form['action']} aceptó el campo '{field}' "
                            f"con valor '{tampered}' (original: '{original_val}'). "
                            f"La respuesta indica éxito (HTTP {r.status_code}).",
                            "Un atacante puede completar compras modificando el precio en el "
                            "formulario del navegador. Puede adquirir cualquier producto por 0€ "
                            "o con descuentos arbitrarios.",
                            "NUNCA confiar en precios enviados desde el cliente. "
                            "El precio siempre debe calcularse en el servidor usando el ID del producto "
                            "y la lista de precios oficial. Ignorar cualquier campo 'price' del POST."
                        )
                        print(f"  [CRITICAL] Precio manipulado: {field}={tampered} aceptado")
                        return
                except Exception:
                    continue

    # ── Check 2: Cantidad negativa ────────────────────────────────────────────

    def _check_negative_quantity(self, form: dict):
        if not form["qty_fields"]:
            return
        print(f"  [*] Probando cantidad negativa en {form['action']}...")
        data = {k: v["value"] for k, v in form["inputs"].items()
                if v["type"] != "submit"}

        for field in form["qty_fields"]:
            for qty in ["-1", "-100", "0", "9999999"]:
                data[field] = qty
                time.sleep(self.delay)
                try:
                    r = self.session.post(form["action"], data=data,
                                         timeout=TIMEOUT, allow_redirects=True)
                    body = r.text.lower()
                    # Cantidad negativa aceptada → posible crédito/descuento no autorizado
                    if r.status_code in (200, 302) and any(s in body for s in SUCCESS_PATTERNS):
                        sev  = "CRITICAL" if qty in ("-1", "-100") else "HIGH"
                        desc = "saldo negativo → crédito fraudulento" if qty.startswith("-") else "overflow de cantidad"
                        self._add(
                            sev,
                            f"Cantidad inválida aceptada — campo '{field}' = {qty}",
                            f"El formulario en {form['action']} aceptó '{field}={qty}'. "
                            f"Posible {desc}.",
                            "Cantidad negativa → el sistema puede generar crédito o descuento no autorizado. "
                            "Overflow → puede afectar a inventario o precios por desbordamiento de entero.",
                            f"Validar en el servidor que '{field}' sea un entero positivo entre 1 y el stock máximo. "
                            "Rechazar cualquier valor <= 0 con un error explícito."
                        )
                        print(f"  [{sev}] Cantidad {field}={qty} aceptada")
                        break
                except Exception:
                    continue

    # ── Check 3: HTTP Parameter Pollution ────────────────────────────────────

    def _check_parameter_pollution(self, form: dict):
        """Envía el mismo parámetro dos veces con valores distintos."""
        if not form["price_fields"] and not form["qty_fields"]:
            return
        target_fields = (form["price_fields"] + form["qty_fields"])[:2]
        base_data = {k: v["value"] for k, v in form["inputs"].items()
                     if v["type"] != "submit"}

        for field in target_fields:
            original = base_data.get(field, "100")
            # Construir query string con el parámetro duplicado
            params = [(k, v) for k, v in base_data.items()]
            params.append((field, "0"))  # segundo valor malicioso
            time.sleep(self.delay)
            try:
                r = self.session.post(form["action"],
                                      data=urlencode(params),
                                      timeout=TIMEOUT,
                                      allow_redirects=True,
                                      headers={**self.session.headers,
                                               "Content-Type": "application/x-www-form-urlencoded"})
                if r.status_code in (200, 302) and any(s in r.text.lower() for s in SUCCESS_PATTERNS):
                    self._add(
                        "HIGH",
                        f"HTTP Parameter Pollution en '{field}'",
                        f"El formulario acepta '{field}' duplicado con valores distintos. "
                        f"Enviado: {field}={original}&{field}=0 en {form['action']}.",
                        "Dependiendo del framework, el servidor puede usar el primero o el último valor. "
                        "Si usa el último (=0), el atacante puede manipular el precio sin cambiar el primero.",
                        "Rechazar requests con parámetros duplicados o usar solo el primero siempre. "
                        "En PHP: $_POST usa el último valor — validar explícitamente."
                    )
                    print(f"  [HIGH] Parameter pollution en {field}")
            except Exception:
                continue

    # ── Check 4: Mass assignment ──────────────────────────────────────────────

    def _check_mass_assignment(self, form: dict):
        """Añade campos no esperados (admin, role, discount) al formulario."""
        data = {k: v["value"] for k, v in form["inputs"].items()
                if v["type"] != "submit"}
        extra_fields = {
            "is_admin": "1", "admin": "1", "role": "admin",
            "discount": "100", "coupon_discount": "100",
            "price_override": "0", "free_shipping": "1",
            "loyalty_points": "99999",
        }
        data_with_extra = {**data, **extra_fields}
        time.sleep(self.delay)
        try:
            r = self.session.post(form["action"], data=data_with_extra,
                                  timeout=TIMEOUT, allow_redirects=True)
            # Si la respuesta contiene alguno de estos campos reflejados, hubo mass assignment
            body = r.text.lower()
            reflected = [k for k in extra_fields if k in body]
            if reflected and any(s in body for s in SUCCESS_PATTERNS):
                self._add(
                    "MEDIUM",
                    f"Posible Mass Assignment en {form['action']}",
                    f"El formulario aceptó campos no esperados que aparecen reflejados en la respuesta: "
                    f"{', '.join(reflected)}.",
                    "Si el backend asigna directamente los campos del POST a un objeto de BD "
                    "(ORM mass assignment), el atacante puede modificar campos protegidos "
                    "como rol, descuento, o privilegios.",
                    "Usar una whitelist explícita de campos permitidos en cada endpoint. "
                    "En Laravel: $fillable. En Django: fields en el serializer. "
                    "Nunca usar $request->all() directamente para crear/actualizar modelos."
                )
                print(f"  [MEDIUM] Mass assignment: campos reflejados {reflected}")
        except Exception:
            pass

    # ── Check 5: Bypass de cupones ────────────────────────────────────────────

    def _check_coupon_bypass(self, base_url: str):
        """Busca endpoints de cupones y prueba códigos comunes."""
        print(f"  [*] Probando bypass de cupones en {base_url}...")
        coupon_endpoints = [
            base_url + "/?wc-ajax=apply_coupon",           # WooCommerce
            base_url + "/cart/coupon",
            base_url + "/api/v1/coupon/apply",
        ]
        for endpoint in coupon_endpoints:
            for code in COMMON_COUPONS[:8]:
                time.sleep(self.delay)
                try:
                    for method, kwargs in [
                        ("POST", {"data": {"coupon_code": code, "code": code}}),
                    ]:
                        r = self.session.request(method, endpoint, timeout=TIMEOUT,
                                                 allow_redirects=True, **kwargs)
                        body = r.text.lower()
                        if r.status_code == 200 and any(
                            w in body for w in ["discount", "descuento", "coupon applied",
                                                "cupón aplicado", "valid", "válido", "success"]
                        ) and not any(
                            w in body for w in ["invalid", "inválido", "expired",
                                                "not found", "no encontrado", "error"]
                        ):
                            self._add(
                                "HIGH",
                                f"Cupón de descuento válido encontrado: '{code}'",
                                f"El código de cupón '{code}' fue aceptado en {endpoint} "
                                f"(HTTP {r.status_code}, método {method}).",
                                "Cupones de prueba, empleados o desarrollo activos en producción. "
                                "Cualquier cliente puede obtener descuentos no autorizados.",
                                f"Desactivar el cupón '{code}' en producción. "
                                "Revisar todos los cupones activos y eliminar los de prueba/desarrollo."
                            )
                            print(f"  [HIGH] Cupón válido: '{code}' en {endpoint}")
                            return
                except Exception:
                    continue

    # ── Check 6: Mass assignment en JSON API ─────────────────────────────────

    def _check_api_mass_assignment(self, base_url: str):
        """Prueba mass assignment en APIs JSON REST."""
        api_endpoints = [
            (base_url + "/api/v1/users/me",    "PATCH"),
            (base_url + "/api/users/profile",  "PUT"),
            (base_url + "/api/account",        "PUT"),
            (base_url + "/wp-json/wp/v2/users/1", "PUT"),
        ]
        extra_fields = {"role": "administrator", "is_admin": True,
                        "admin": True, "balance": 99999}

        for endpoint, method in api_endpoints:
            time.sleep(self.delay)
            try:
                r = self.session.request(
                    method, endpoint,
                    json=extra_fields,
                    timeout=TIMEOUT,
                    headers={**self.session.headers, "Content-Type": "application/json"}
                )
                if r.status_code in (200, 201):
                    body = r.text
                    accepted = [k for k in extra_fields if str(k) in body]
                    if accepted:
                        self._add(
                            "HIGH",
                            f"Mass Assignment en API JSON: {endpoint}",
                            f"El endpoint {method} {endpoint} aceptó y reflejó campos privilegiados: "
                            f"{', '.join(accepted)}.",
                            "Un atacante puede elevar sus privilegios a administrador o "
                            "modificar su saldo/crédito enviando campos adicionales en el JSON.",
                            "Usar serializers/DTOs con campos explícitos. "
                            "Nunca mapear automáticamente todos los campos JSON a modelos de BD."
                        )
                        print(f"  [HIGH] Mass assignment API: {', '.join(accepted)} aceptados en {endpoint}")
            except Exception:
                continue

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _build_base_urls(self) -> list:
        urls = []
        for host in self.recon_data.get("hosts", []):
            if host["estado"] != "up":
                continue
            for p in host["puertos"]:
                port = p["puerto"]
                svc  = p["servicio"].lower()
                if "http" in svc or port in (80, 443, 8080, 8443):
                    proto = "https" if port in (443, 8443) else "http"
                    url   = (f"{proto}://{self.target}:{port}"
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
            "tipo":          "LÓGICA DE NEGOCIO",
            "nombre":        nombre,
            "descripcion":   descripcion,
            "impacto":       impacto,
            "recomendacion": recomendacion,
        })
