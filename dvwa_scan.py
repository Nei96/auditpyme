#!/usr/bin/env python3
"""Validación de webapp.py contra DVWA (security=low)"""
import re, requests, time, sys
sys.path.insert(0, '/home/nathan/Proyectos/auditoria_pymes')

from modules.webapp import WebAppScanner, SQLI_ERROR_PAYLOADS, SQLI_ERROR_SIGNS
from modules.webapp import XSS_PAYLOADS, XSS_SIGNS, LFI_PAYLOADS, LFI_SIGNS, LFI_PARAM_KEYWORDS
from modules.report import ReportGenerator
from datetime import datetime
from urllib.parse import urlencode, urlunparse

TARGET = "http://localhost:8080"
s = requests.Session()
s.headers.update({"User-Agent": "Mozilla/5.0 (compatible; AuditPyme/1.0)"})
s.verify = False

resp = s.get(f"{TARGET}/login.php")
token_m = re.search(r"value=['\"]([a-f0-9]{20,})['\"]", resp.text)
token_val = token_m.group(1) if token_m else ""
r_login = s.post(f"{TARGET}/login.php",
    data={"username":"admin","password":"password","Login":"Login","user_token":token_val},
    allow_redirects=True)
s.cookies.set("security","low")
print("Login:", "OK" if "login.php" not in r_login.url else "FAIL")

scanner = WebAppScanner(TARGET, checks=[])
scanner.session = s
scanner._crawl(TARGET, depth=2)
print(f"Formularios: {len(scanner._forms)}  |  Params URL: {len(scanner._params)}")

findings = []
SKIP = scanner._SKIP_INJECT_PATHS

def add(sev, tipo, nombre, desc, rec):
    if not any(f["nombre"] == nombre for f in findings):
        findings.append({"url":TARGET,"tipo":tipo,"nombre":nombre,
                         "descripcion":desc,"severidad":sev,"recomendacion":rec})
        print(f"  [{sev}] {tipo} — {nombre[:55]}")

print("\n[1/5] SQLi error-based...")
for form in scanner._forms[:10]:
    if any(p in form["url"] for p in SKIP): continue
    for field in form["fields"]:
        for payload in SQLI_ERROR_PAYLOADS[:6]:
            data = {**form["fields"], **form.get("fixed",{}), field: payload}
            try:
                r = s.post(form["url"],data=data,timeout=8) if form["method"]=="post" \
                    else s.get(form["url"],params=data,timeout=8)
                if any(sg in r.text.lower() for sg in SQLI_ERROR_SIGNS):
                    add("CRITICAL","SQL INJECTION",
                        f"SQL Injection en {form['url']} campo '{field}'",
                        f"Campo '{field}' vulnerable a SQLi. Payload: {payload}",
                        "Usar prepared statements. No concatenar variables en SQL.")
                    break
            except: pass

print("[2/5] XSS reflejado...")
for form in scanner._forms[:10]:
    if any(p in form["url"] for p in SKIP): continue
    for field in form["fields"]:
        for payload in XSS_PAYLOADS[:3]:
            data = {**form["fields"], **form.get("fixed",{}), field: payload}
            try:
                r = s.post(form["url"],data=data,timeout=8) if form["method"]=="post" \
                    else s.get(form["url"],params=data,timeout=8)
                if any(sg in r.text.lower() for sg in XSS_SIGNS):
                    add("HIGH","XSS REFLEJADO",
                        f"XSS reflejado en {form['url']} campo '{field}'",
                        f"Campo '{field}' devuelve payload sin sanitizar. Riesgo robo sesion.",
                        "Escapar con htmlspecialchars(). Configurar CSP.")
                    break
            except: pass

print("[3/5] LFI...")
seen = set()
for p in scanner._params[:20]:
    for param, values in p["params"].items():
        if not any(kw in param.lower() for kw in LFI_PARAM_KEYWORDS): continue
        for payload in LFI_PAYLOADS[:15]:
            try:
                parts = list(p["parsed"])
                parts[4] = urlencode({**{k:v[0] for k,v in p["params"].items()}, param: payload})
                r = s.get(urlunparse(parts), timeout=8)
                if any(sg in r.text for sg in LFI_SIGNS):
                    nombre = f"LFI en parametro '{param}'"
                    if nombre not in seen:
                        seen.add(nombre)
                        add("CRITICAL","LFI — LOCAL FILE INCLUSION", nombre,
                            f"'{param}' permite leer archivos del servidor. Payload: {payload}",
                            "Validar y restringir valores. No usar entrada de usuario en include().")
                    break
            except: pass

print("[4/5] CMDi time-based (exec page)...")
exec_url = f"{TARGET}/vulnerabilities/exec/"
for payload in ["; sleep 4", "| sleep 4", "; ping -c 4 127.0.0.1"]:
    t0 = time.time()
    try:
        s.post(exec_url, data={"ip": f"127.0.0.1{payload}", "Submit":"Submit"}, timeout=10)
    except: pass
    elapsed = time.time() - t0
    print(f"  {payload!r:30}  {elapsed:.1f}s")
    if elapsed >= 3.0:
        add("CRITICAL","COMMAND INJECTION",
            f"Inyeccion de comandos OS en {exec_url} campo 'ip'",
            f"Campo 'ip' ejecuta comandos OS. Delay {elapsed:.1f}s con '{payload}'.",
            "No ejecutar comandos con entrada del usuario. Usar listas blancas estrictas.")
        break

print("[5/5] CSRF...")
for form in scanner._forms:
    if form["method"]=="post" and not form["has_csrf"] \
       and not any(p in form["url"] for p in SKIP):
        add("MEDIUM","CSRF",
            f"CSRF — formulario POST sin token en {form['url']}",
            f"Formulario POST en {form['url']} sin token CSRF.",
            "Implementar tokens CSRF en todos los formularios POST.")

fin = datetime.now().strftime("%d/%m/%Y %H:%M")
print(f"\n{'='*62}")
print(f"TOTAL: {len(findings)} hallazgos  |  {fin}")
print('='*62)
for f in findings:
    print(f"  [{f['severidad']:8}] {f['tipo']:22} — {f['nombre'][:50]}")

print("\n--- Cobertura vs DVWA (security=low) ---")
for v in ["SQL INJECTION","XSS REFLEJADO","LFI","COMMAND INJECTION","CSRF"]:
    print(f"  {'✓' if any(v in f['tipo'] for f in findings) else '✗'} {v}")

resultado = {
    "target": "localhost:8080 (DVWA)",
    "empresa": "DVWA Lab — Validacion AuditPyme v1.0",
    "auditor": "",
    "fecha_inicio": datetime.now().strftime("%d/%m/%Y %H:%M"),
    "fecha_fin": fin,
    "hallazgos": findings,
    "webapp": findings,
}
ReportGenerator(resultado).generate("informes/dvwa_validacion_final")
print("\n[+] Informe: informes/dvwa_validacion_final (.html / .pdf)")
