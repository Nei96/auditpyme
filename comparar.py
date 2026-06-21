#!/usr/bin/env python3
"""
AuditPyme — Comparativa histórica entre auditorías del mismo cliente.
Uso: python3 comparar.py <auditoría_anterior.json> <auditoría_nueva.json> [-o salida]
     python3 comparar.py aud1.json aud2.json aud3.json   (serie temporal)
"""

import argparse
import json
import sys
from datetime import datetime

try:
    from weasyprint import HTML as WP_HTML
    _WEASYPRINT = True
except ImportError:
    _WEASYPRINT = False

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4, "INFO": 5}
SEVERITY_COLOR = {
    "CRITICAL": "#c0392b",
    "HIGH":     "#e67e22",
    "MEDIUM":   "#d4ac0d",
    "LOW":      "#2980b9",
    "UNKNOWN":  "#7f8c8d",
    "INFO":     "#95a5a6",
}
SEVERITY_ES = {
    "CRITICAL": "Crítico",
    "HIGH":     "Alto",
    "MEDIUM":   "Medio",
    "LOW":      "Bajo",
    "INFO":     "Info",
}

FINDING_KEYS = [
    "vulns", "misconfigs", "web", "ssl", "dns",
    "email", "osint", "webapp", "wifi", "cms",
    "auth", "js", "graphql", "fileupload", "bizlogic",
]


# ── Utilidades ────────────────────────────────────────────────────────────────

def _finding_id(f: dict) -> str:
    """Clave única de un hallazgo para comparar entre auditorías."""
    nombre = f.get("nombre", "").strip()
    tipo   = f.get("tipo", "").strip()
    return f"{tipo}::{nombre}" if tipo else nombre


def _all_findings(results: dict) -> list:
    findings = []
    for key in FINDING_KEYS:
        for f in results.get(key, []):
            f = dict(f)
            f["_source"] = key
            findings.append(f)
    for c in results.get("creds", []):
        if c.get("acceso"):
            c = dict(c)
            c["_source"] = "creds"
            c.setdefault("nombre", f"Acceso — {c.get('servicio','')}")
            c.setdefault("tipo", "Credenciales por defecto")
            c.setdefault("severidad", "CRITICAL")
            findings.append(c)
    return findings


def _counts(results: dict) -> dict:
    all_f = _all_findings(results)
    recon = results.get("recon") or {}
    hosts = recon.get("hosts", [])
    return {
        "critical": sum(1 for f in all_f if f.get("severidad") == "CRITICAL"),
        "high":     sum(1 for f in all_f if f.get("severidad") == "HIGH"),
        "medium":   sum(1 for f in all_f if f.get("severidad") == "MEDIUM"),
        "low":      sum(1 for f in all_f if f.get("severidad") == "LOW"),
        "total":    len([f for f in all_f if f.get("severidad") not in ("INFO", None)]),
        "hosts":    len([h for h in hosts if h.get("estado") == "up"]),
        "puertos":  recon.get("total_puertos", 0),
        "accesos":  len([c for c in results.get("creds", []) if c.get("acceso")]),
    }


def _risk_label(counts: dict) -> tuple:
    if counts["critical"] > 0 or counts["accesos"] > 0:
        return "CRÍTICO", "#c0392b"
    if counts["high"] > 0:
        return "ALTO", "#e67e22"
    if counts["medium"] > 0:
        return "MEDIO", "#d4ac0d"
    return "BAJO", "#27ae60"


def _score(counts: dict) -> int:
    """Puntuación de riesgo 0-100 (mayor = peor)."""
    return min(100, counts["critical"] * 20 + counts["high"] * 8 +
               counts["medium"] * 3 + counts["low"] + counts["accesos"] * 25)


def _diff(prev: dict, curr: dict) -> dict:
    """Compara dos auditorías y devuelve hallazgos categorizados."""
    prev_map = {_finding_id(f): f for f in _all_findings(prev)}
    curr_map = {_finding_id(f): f for f in _all_findings(curr)}

    nuevos    = []
    resueltos = []
    persistentes = []
    empeorados = []
    mejorados  = []

    for fid, f in curr_map.items():
        sev_curr = f.get("severidad", "UNKNOWN")
        if sev_curr == "INFO":
            continue
        if fid not in prev_map:
            nuevos.append(f)
        else:
            sev_prev = prev_map[fid].get("severidad", "UNKNOWN")
            ord_prev = SEVERITY_ORDER.get(sev_prev, 99)
            ord_curr = SEVERITY_ORDER.get(sev_curr, 99)
            if ord_curr < ord_prev:
                empeorados.append({"prev": prev_map[fid], "curr": f})
            elif ord_curr > ord_prev:
                mejorados.append({"prev": prev_map[fid], "curr": f})
            else:
                persistentes.append(f)

    for fid, f in prev_map.items():
        if f.get("severidad") == "INFO":
            continue
        if fid not in curr_map:
            resueltos.append(f)

    for lst in (nuevos, resueltos, persistentes):
        lst.sort(key=lambda x: SEVERITY_ORDER.get(x.get("severidad", "UNKNOWN"), 99))

    return {
        "nuevos":       nuevos,
        "resueltos":    resueltos,
        "persistentes": persistentes,
        "empeorados":   empeorados,
        "mejorados":    mejorados,
    }


# ── HTML ─────────────────────────────────────────────────────────────────────

LOGO_SVG = """<svg width="48" height="54" viewBox="0 0 60 68" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path d="M30 3L5 14V33C5 48.5 16 62 30 67C44 62 55 48.5 55 33V14L30 3Z"
        fill="#0f2a4a" stroke="#4a9eff" stroke-width="2.2"/>
  <path d="M30 10L11 19V33C11 44.5 19.5 55 30 59C40.5 55 49 44.5 49 33V19L30 10Z"
        fill="#0d1f38" opacity="0.7"/>
  <text x="30" y="40" text-anchor="middle" fill="#4a9eff"
        font-family="'Segoe UI',Arial,sans-serif" font-size="17" font-weight="800" letter-spacing="1">AP</text>
</svg>"""


def _css() -> str:
    return """<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', Arial, sans-serif; background: #f0f2f5; color: #2c3e50; }

.header {
  background: linear-gradient(135deg, #0d1117 0%, #161b22 60%, #1a3a5c 100%);
  color: white; padding: 36px 56px;
}
.header-inner { display: flex; align-items: center; gap: 28px; }
.header h1 { font-size: 1.7rem; letter-spacing: 3px; font-weight: 300; }
.header h1 strong { font-weight: 700; }
.header .subtitle { color: #8b9ec0; margin-top: 6px; font-size: 0.85rem; letter-spacing: 1px; }
.header .meta { margin-top: 18px; display: flex; gap: 32px; flex-wrap: wrap; }
.header .meta-item { font-size: 0.8rem; color: #8b9ec0; }
.header .meta-item strong { color: #e0e8f0; display: block; font-size: 0.92rem; }

.container { max-width: 1200px; margin: 24px auto; padding: 0 24px; }

.section {
  background: white; border-radius: 10px; margin-bottom: 20px;
  box-shadow: 0 2px 12px rgba(0,0,0,0.07); overflow: hidden;
}
.section-header {
  background: #1e2936; color: white; padding: 12px 20px;
  font-size: 0.82rem; font-weight: 700; letter-spacing: 2px; text-transform: uppercase;
}
.section-body { padding: 18px 20px; }

/* Tarjetas de resumen por auditoría */
.audit-cards { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 20px; }
.audit-card {
  flex: 1; min-width: 220px; background: #f8f9fb;
  border-radius: 10px; padding: 18px; border-left: 5px solid #ccc;
}
.audit-card h3 { font-size: 0.85rem; color: #888; margin-bottom: 10px;
                  text-transform: uppercase; letter-spacing: 1px; }
.audit-card .empresa { font-size: 1.1rem; font-weight: 700; color: #2c3e50; }
.audit-card .fecha { font-size: 0.8rem; color: #aaa; margin-top: 2px; }
.audit-card .risk-badge {
  display: inline-block; padding: 4px 14px; border-radius: 20px;
  color: white; font-size: 0.78rem; font-weight: 800; letter-spacing: 1px; margin-top: 10px;
}
.count-row { display: flex; gap: 10px; margin-top: 12px; flex-wrap: wrap; }
.count-item { text-align: center; min-width: 44px; }
.count-item .num { font-size: 1.5rem; font-weight: 800; }
.count-item .lbl { font-size: 0.65rem; color: #888; text-transform: uppercase; letter-spacing: 1px; }

/* Score bar */
.score-section { margin-bottom: 20px; }
.score-bar-wrap { display: flex; align-items: center; gap: 16px; margin-top: 8px; }
.score-label { font-size: 0.82rem; color: #666; min-width: 120px; }
.score-bar-bg { flex: 1; background: #f0f0f0; border-radius: 6px; height: 28px; position: relative; }
.score-bar-fill { height: 28px; border-radius: 6px; }
.score-num { font-size: 0.9rem; font-weight: 800; min-width: 40px; }
.score-delta { font-size: 0.8rem; font-weight: 700; min-width: 60px; }

/* Tablas de diff */
table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
th { background: #2c3e50; color: white; padding: 9px 13px; text-align: left;
     font-size: 0.78rem; letter-spacing: 1px; text-transform: uppercase; }
td { padding: 8px 13px; border-bottom: 1px solid #f0f0f0; vertical-align: top; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: #f8f9fb; }

.badge {
  display: inline-block; padding: 2px 9px; border-radius: 20px;
  color: white; font-size: 0.7rem; font-weight: 700; letter-spacing: 0.5px;
}

.ok { color: #27ae60; font-weight: 600; padding: 8px 0; font-size: 0.9rem; }
.arrow { font-size: 1rem; font-weight: 800; }

/* Sección vacía */
.empty { color: #27ae60; font-size: 0.9rem; padding: 10px 0; }

.footer { text-align: center; padding: 24px; color: #aaa; font-size: 0.78rem; }

@media print {
  body { background: white; }
  .section { box-shadow: none; border: 1px solid #ddd; }
}
</style>"""


def _badge(sev: str) -> str:
    color = SEVERITY_COLOR.get(sev, "#999")
    label = SEVERITY_ES.get(sev, sev)
    return f'<span class="badge" style="background:{color};">{label}</span>'


def _finding_row(f: dict) -> str:
    sev = f.get("severidad", "UNKNOWN")
    nombre = f.get("nombre", "—")
    tipo   = f.get("tipo", f.get("_source", "—"))
    desc   = f.get("descripcion", "")[:160]
    return f"""<tr>
      <td>{_badge(sev)}</td>
      <td><strong>{nombre}</strong></td>
      <td style="color:#888;font-size:0.8rem;">{tipo}</td>
      <td style="font-size:0.8rem;color:#555;">{desc}</td>
    </tr>"""


def _diff_row_changed(item: dict, direction: str) -> str:
    prev = item["prev"]
    curr = item["curr"]
    sev_prev = prev.get("severidad", "UNKNOWN")
    sev_curr = curr.get("severidad", "UNKNOWN")
    nombre = curr.get("nombre", "—")
    tipo   = curr.get("tipo", curr.get("_source", "—"))
    arrow_color = "#c0392b" if direction == "worse" else "#27ae60"
    arrow = "▲" if direction == "worse" else "▼"
    return f"""<tr>
      <td>{_badge(sev_prev)} <span class="arrow" style="color:{arrow_color};">{arrow}</span> {_badge(sev_curr)}</td>
      <td><strong>{nombre}</strong></td>
      <td style="color:#888;font-size:0.8rem;">{tipo}</td>
    </tr>"""


def _section(title: str, body: str) -> str:
    return f"""
  <div class="section">
    <div class="section-header">{title}</div>
    <div class="section-body">{body}</div>
  </div>"""


def _table(rows: str) -> str:
    return f"""<table><thead><tr>
      <th>Severidad</th><th>Hallazgo</th><th>Módulo</th><th>Descripción</th>
    </tr></thead><tbody>{rows}</tbody></table>"""


def _table_changed(rows: str) -> str:
    return f"""<table><thead><tr>
      <th>Cambio</th><th>Hallazgo</th><th>Módulo</th>
    </tr></thead><tbody>{rows}</tbody></table>"""


def _score_bar(label: str, score: int, color: str, delta: int | None = None) -> str:
    delta_html = ""
    if delta is not None:
        sign = "+" if delta > 0 else ""
        delta_color = "#c0392b" if delta > 0 else "#27ae60" if delta < 0 else "#888"
        delta_html = f'<span class="score-delta" style="color:{delta_color};">{sign}{delta}</span>'
    return f"""
  <div class="score-bar-wrap">
    <div class="score-label">{label}</div>
    <div class="score-bar-bg">
      <div class="score-bar-fill" style="width:{score}%;background:{color};"></div>
    </div>
    <div class="score-num" style="color:{color};">{score}</div>
    {delta_html}
  </div>"""


def _audit_card(r: dict, n: int, color: str) -> str:
    counts = _counts(r)
    label, risk_color = _risk_label(counts)
    empresa = r.get("empresa") or r.get("target", "—")
    fecha   = r.get("fecha_inicio", "—")
    target  = r.get("target", "")
    return f"""
  <div class="audit-card" style="border-color:{risk_color};">
    <h3>Auditoría #{n}</h3>
    <div class="empresa">{empresa}</div>
    <div class="fecha">{target} · {fecha}</div>
    <div class="risk-badge" style="background:{risk_color};">{label}</div>
    <div class="count-row">
      <div class="count-item"><div class="num" style="color:#c0392b;">{counts['critical']}</div><div class="lbl">Críticos</div></div>
      <div class="count-item"><div class="num" style="color:#e67e22;">{counts['high']}</div><div class="lbl">Altos</div></div>
      <div class="count-item"><div class="num" style="color:#d4ac0d;">{counts['medium']}</div><div class="lbl">Medios</div></div>
      <div class="count-item"><div class="num" style="color:#2980b9;">{counts['low']}</div><div class="lbl">Bajos</div></div>
      <div class="count-item"><div class="num" style="color:#c0392b;">{counts['accesos']}</div><div class="lbl">Accesos</div></div>
    </div>
  </div>"""


def build_html(reports: list, auditor: str = "") -> str:
    """Genera el HTML completo de comparativa. `reports` es lista de dicts results."""
    n = len(reports)
    empresa = reports[-1].get("empresa") or reports[-1].get("target", "—")
    fecha_gen = datetime.now().strftime("%d/%m/%Y %H:%M")

    # ── Cabecera ──────────────────────────────────────────────────────────────
    header = f"""
<div class="header">
  <div class="header-inner">
    <div>{LOGO_SVG}</div>
    <div>
      <h1><strong>COMPARATIVA</strong> DE AUDITORÍAS — EVOLUCIÓN DE RIESGOS</h1>
      <div class="subtitle">AuditPyme v1.0 · {empresa} · {n} auditorías comparadas</div>
      <div class="meta">
        <div class="meta-item"><strong>{empresa}</strong>Cliente</div>
        <div class="meta-item"><strong>{n}</strong>Auditorías</div>
        <div class="meta-item"><strong>{fecha_gen}</strong>Generado</div>
      </div>
    </div>
  </div>
</div>"""

    body_parts = []

    # ── Tarjetas resumen ──────────────────────────────────────────────────────
    cards_html = '<div class="audit-cards">'
    colors = ["#2980b9", "#8e44ad", "#16a085", "#d35400", "#c0392b"]
    for i, r in enumerate(reports):
        cards_html += _audit_card(r, i + 1, colors[i % len(colors)])
    cards_html += "</div>"

    # ── Evolución de puntuación ────────────────────────────────────────────────
    scores = [_score(_counts(r)) for r in reports]
    score_bars = ""
    for i, (r, sc) in enumerate(zip(reports, scores)):
        fecha = r.get("fecha_inicio", f"Auditoría #{i+1}")
        pct_color = "#c0392b" if sc >= 60 else "#e67e22" if sc >= 30 else "#27ae60"
        delta = (sc - scores[i - 1]) if i > 0 else None
        score_bars += _score_bar(f"#{i+1} · {fecha}", sc, pct_color, delta)

    evoluc_html = cards_html + f"""
<div style="margin-top:8px;">
  <div style="font-size:0.82rem;color:#888;margin-bottom:6px;font-weight:600;text-transform:uppercase;letter-spacing:1px;">
    Puntuación de riesgo (0 = sin riesgos, 100 = máximo riesgo)
  </div>
  {score_bars}
</div>"""

    body_parts.append(_section("Resumen comparativo", evoluc_html))

    # ── Comparativas entre pares consecutivos ─────────────────────────────────
    for i in range(1, n):
        prev = reports[i - 1]
        curr = reports[i]
        diff = _diff(prev, curr)

        prev_fecha = prev.get("fecha_inicio", f"Auditoría #{i}")
        curr_fecha = curr.get("fecha_inicio", f"Auditoría #{i+1}")
        titulo_base = f"Auditoría #{i} → #{i+1}  ·  {prev_fecha} → {curr_fecha}"

        # Nuevas vulnerabilidades
        if diff["nuevos"]:
            rows = "".join(_finding_row(f) for f in diff["nuevos"])
            body_parts.append(_section(
                f"{titulo_base} — NUEVAS VULNERABILIDADES ({len(diff['nuevos'])})",
                f'<p style="font-size:0.85rem;color:#c0392b;margin-bottom:10px;font-weight:600;">'
                f'Hallazgos que no existían en la auditoría anterior. Requieren atención inmediata.</p>'
                + _table(rows)
            ))
        else:
            body_parts.append(_section(
                f"{titulo_base} — Nuevas vulnerabilidades",
                '<p class="empty">✓ No se detectaron vulnerabilidades nuevas respecto a la auditoría anterior.</p>'
            ))

        # Resueltas
        if diff["resueltos"]:
            rows = "".join(_finding_row(f) for f in diff["resueltos"])
            body_parts.append(_section(
                f"{titulo_base} — RESUELTAS / DESAPARECIDAS ({len(diff['resueltos'])})",
                f'<p style="font-size:0.85rem;color:#27ae60;margin-bottom:10px;font-weight:600;">'
                f'Hallazgos que ya no aparecen en la auditoría más reciente. Buen trabajo.</p>'
                + _table(rows)
            ))

        # Empeoradas
        if diff["empeorados"]:
            rows = "".join(_diff_row_changed(it, "worse") for it in diff["empeorados"])
            body_parts.append(_section(
                f"{titulo_base} — EMPEORADAS ({len(diff['empeorados'])})",
                f'<p style="font-size:0.85rem;color:#c0392b;margin-bottom:10px;font-weight:600;">'
                f'Hallazgos que han aumentado de severidad. Prioridad alta.</p>'
                + _table_changed(rows)
            ))

        # Mejoradas
        if diff["mejorados"]:
            rows = "".join(_diff_row_changed(it, "better") for it in diff["mejorados"])
            body_parts.append(_section(
                f"{titulo_base} — Severidad reducida ({len(diff['mejorados'])})",
                _table_changed(rows)
            ))

        # Persistentes
        if diff["persistentes"]:
            rows = "".join(_finding_row(f) for f in diff["persistentes"])
            body_parts.append(_section(
                f"{titulo_base} — SIN CAMBIO / PERSISTENTES ({len(diff['persistentes'])})",
                f'<p style="font-size:0.85rem;color:#e67e22;margin-bottom:10px;font-weight:600;">'
                f'Hallazgos que llevan más de una auditoría sin resolverse.</p>'
                + _table(rows)
            ))
        else:
            body_parts.append(_section(
                f"{titulo_base} — Hallazgos persistentes",
                '<p class="empty">✓ No hay hallazgos sin resolver que persistan entre auditorías.</p>'
            ))

    # ── Conclusión ────────────────────────────────────────────────────────────
    first_score = scores[0]
    last_score  = scores[-1]
    delta_total = last_score - first_score
    if delta_total < -10:
        concl_color = "#27ae60"
        concl_text = (f"La postura de seguridad ha <strong>mejorado significativamente</strong> "
                      f"desde la primera auditoría (puntuación: {first_score} → {last_score}). "
                      f"Los controles implementados están teniendo efecto.")
    elif delta_total > 10:
        concl_color = "#c0392b"
        concl_text = (f"La postura de seguridad ha <strong>empeorado</strong> "
                      f"desde la primera auditoría (puntuación: {first_score} → {last_score}). "
                      f"Se recomienda revisar los procesos de aplicación de parches y configuración.")
    else:
        concl_color = "#e67e22"
        concl_text = (f"La postura de seguridad se mantiene <strong>estable</strong> "
                      f"entre auditorías (puntuación: {first_score} → {last_score}). "
                      f"Se recomienda priorizar los hallazgos persistentes.")

    body_parts.append(_section(
        "Conclusión y tendencia",
        f'<p style="line-height:1.8;font-size:0.92rem;border-left:4px solid {concl_color};'
        f'padding-left:14px;">{concl_text}</p>'
    ))

    footer = f"""
<div class="footer">
  <strong style="color:#2c3e50;">AuditPyme</strong> v1.0 &nbsp;·&nbsp;
  Comparativa generada el {fecha_gen}{f" &nbsp;·&nbsp; {auditor}" if auditor else ""}
</div>"""

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AuditPyme — Comparativa de auditorías — {empresa}</title>
{_css()}
</head>
<body>
{header}
<div class="container">
{"".join(body_parts)}
</div>
{footer}
</body>
</html>"""


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="AuditPyme — Comparativa histórica entre auditorías",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "json_files", nargs="+",
        help="Archivos _results.json en orden cronológico (mínimo 2)"
    )
    parser.add_argument(
        "-o", "--output", default=None,
        help="Nombre base del informe de salida (sin extensión)"
    )
    parser.add_argument("--no-pdf", action="store_true", help="Solo HTML, sin PDF")
    parser.add_argument("--auditor", default="", help="Nombre del auditor (aparece en el informe)")
    args = parser.parse_args()

    if len(args.json_files) < 2:
        print("[!] Se necesitan al menos 2 archivos JSON para comparar.")
        sys.exit(1)

    reports = []
    for path in args.json_files:
        try:
            with open(path, encoding="utf-8") as f:
                reports.append(json.load(f))
            print(f"[+] Cargado: {path}")
        except Exception as e:
            print(f"[!] Error leyendo {path}: {e}")
            sys.exit(1)

    base = args.output or "comparativa_" + datetime.now().strftime("%Y%m%d_%H%M%S")
    base = base.replace(".html", "").replace(".pdf", "")

    html_content = build_html(reports, auditor=args.auditor)

    html_file = base + ".html"
    with open(html_file, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"[+] Informe HTML: {html_file}")

    if not args.no_pdf:
        if _WEASYPRINT:
            pdf_file = base + ".pdf"
            try:
                WP_HTML(string=html_content).write_pdf(pdf_file)
                print(f"[+] Informe PDF:  {pdf_file}")
            except Exception as e:
                print(f"[!] PDF no generado: {e}")
        else:
            print("[!] weasyprint no disponible — solo se genera HTML")


if __name__ == "__main__":
    main()
