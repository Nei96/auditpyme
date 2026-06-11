"""
Módulo de reporte — AuditPyme v1.0
Genera informe HTML profesional y exporta a PDF via weasyprint.
"""

from datetime import datetime

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

# Impacto real en el negocio por tipo de hallazgo
# Formato: palabra_clave_en_nombre → (icono, impacto en lenguaje de negocio)
BUSINESS_IMPACT = {
    # Email
    "spf ausente":              ("💸", "Cualquiera puede enviar emails haciéndose pasar por tu empresa. Tus clientes pueden recibir facturas falsas o peticiones de datos en tu nombre."),
    "dmarc ausente":            ("💸", "Sin política de rechazo, los emails fraudulentos de tu dominio llegan a los clientes sin aviso. Riesgo directo de phishing contra tus contactos."),
    "dkim":                     ("📧", "Tus emails legítimos pueden ser modificados en tránsito o acabar en spam, dañando la comunicación con clientes."),
    "spf permite":              ("💸", "Configuración errónea — cualquier servidor del mundo puede suplantar tu dominio. Peor que no tener SPF."),
    # SSL/TLS
    "certificado expirado":     ("🔴", "El navegador mostrará un aviso de 'Sitio no seguro' a todos tus clientes. Perderás visitas y credibilidad inmediatamente."),
    "próximo a expirar":        ("⏰", "En pocos días tu web mostrará error de seguridad a los visitantes. Los clientes la abandonarán."),
    "versión tls débil":        ("🔓", "Las comunicaciones entre tu web y los clientes pueden ser interceptadas. Datos de formularios y contraseñas en riesgo."),
    # WiFi
    "red wifi abierta":         ("📡", "Cualquier persona en el edificio o la calle puede interceptar todo el tráfico de internet de la empresa: contraseñas, emails y datos de clientes."),
    "wep":                      ("📡", "El cifrado WiFi puede romperse en menos de 5 minutos con herramientas gratuitas. La red no ofrece protección real."),
    "wpa (tkip)":               ("📡", "Protocolo WiFi obsoleto y vulnerable. Un atacante puede recuperar la clave de la red con equipamiento básico."),
    "wps habilitado":           ("📡", "La función WPS permite obtener la contraseña WiFi sin fuerza bruta. Un atacante cercano puede entrar a la red en minutos."),
    "rogue ap":                 ("📡", "Punto de acceso falso detectado. Un atacante puede estar interceptando todo el tráfico WiFi de los empleados sin que lo sepan."),
    "evil twin":                ("📡", "Red WiFi suplantada detectada. Los empleados pueden estar conectándose a una red controlada por un atacante."),
    "red local expuesta":       ("📡", "Cualquier cliente o visitante conectado a la WiFi puede ver y atacar los dispositivos internos de la empresa: impresoras, servidores, PCs."),
    "dispositivos visibles":    ("📡", "La red interna de la empresa está al alcance de cualquier persona con WiFi. Un atacante desde la calle puede intentar acceder a todos estos sistemas."),
    "expuesto en red local":    ("🖥️", "Este dispositivo interno es accesible desde la WiFi pública. Un visitante malintencionado puede intentar entrar sin levantar sospechas."),
    "telnet sin cifrado":       ("🔓", "Las contraseñas de este dispositivo viajan visibles por la red. Cualquiera en la misma WiFi puede capturarlas con herramientas gratuitas."),
    "tkip activo":              ("📡", "El router acepta cifrado TKIP, roto desde 2012. Un atacante puede recuperar la clave de la red aunque el AP anuncie WPA2."),
    "tramas de gestión":        ("📡", "Sin PMF, un atacante puede expulsar a los empleados de la WiFi y capturar sus contraseñas cuando se reconectan. No requiere estar dentro del edificio."),
    "modo transición":          ("📡", "La red admite WPA2 y WPA3 a la vez. Un atacante puede forzar a los dispositivos a conectarse con WPA2 (más débil) y capturar el handshake."),
    # Credenciales
    "credenciales por defecto": ("🔑", "Acceso directo al sistema sin necesidad de atacar nada. Un script automático puede entrar en minutos."),
    # Bases de datos
    "mysql":                    ("🗄️", "Base de datos accesible desde internet. Todos los datos de clientes, pedidos y contraseñas expuestos."),
    "mongodb":                  ("🗄️", "Base de datos sin autenticación accesible desde internet. Datos expuestos o borrados en minutos por bots automáticos."),
    "redis":                    ("🗄️", "Caché de datos accesible desde internet. Puede usarse para tomar control del servidor."),
    "postgresql":               ("🗄️", "Base de datos accesible desde internet. Todos los datos del negocio expuestos."),
    "elasticsearch":            ("🗄️", "Motor de búsqueda con datos expuestos públicamente sin autenticación."),
    # Servicios críticos
    "smb expuesto":             ("💀", "Vector principal de ransomware (WannaCry, EternalBlue). Un atacante puede cifrar todos los archivos de la empresa."),
    "rdp expuesto":             ("🖥️", "Acceso remoto al escritorio expuesto. Objetivo de ataques de fuerza bruta continuos. Si la contraseña es débil, acceso total al sistema."),
    "telnet":                   ("🔓", "Protocolo sin cifrado. Usuario y contraseña viajan en texto plano por internet."),
    "ftp anónimo":              ("📂", "Acceso a archivos del servidor sin contraseña. Cualquiera puede leer o subir archivos."),
    # Web
    "git expuesto":             ("💻", "Código fuente de la web accesible públicamente. Puede contener contraseñas, claves API y lógica interna."),
    "backup.sql":               ("🗄️", "Copia de la base de datos descargable sin contraseña. Todos los datos del negocio expuestos."),
    ".env expuesto":            ("🔑", "Archivo de configuración con contraseñas y claves API accesible públicamente."),
    "phpmyadmin":               ("🗄️", "Panel de gestión de base de datos expuesto. Objetivo frecuente de ataques automatizados."),
    "actuator/env":             ("🔑", "Variables de entorno del servidor expuestas — pueden contener contraseñas y claves de acceso."),
    # OSINT
    "filtr":                    ("📋", "Credenciales de empleados o clientes en bases de datos de hackers. Pueden usarse para acceder a sistemas internos."),
    "subdomain takeover":       ("🌐", "Un atacante puede registrar subdominios de tu empresa y usarlos para phishing o malware bajo tu nombre."),
    "dominio expira":           ("⏰", "Si el dominio caduca, cualquiera puede registrarlo y hacerse pasar por tu empresa."),
    "eternalblue":              ("💀", "Vulnerabilidad crítica usada en el ataque de ransomware WannaCry. Riesgo de pérdida total de datos."),
}


class ReportGenerator:
    def __init__(self, results: dict):
        self.r = results
        self._all_findings = (
            self.r.get("vulns", []) +
            self.r.get("misconfigs", []) +
            self.r.get("web", []) +
            self.r.get("ssl", []) +
            self.r.get("dns", []) +
            self.r.get("email", []) +
            self.r.get("osint", []) +
            self.r.get("webapp", []) +
            self.r.get("wifi", []) +
            self.r.get("cms", []) +
            self.r.get("auth", []) +
            self.r.get("js", []) +
            self.r.get("graphql", []) +
            self.r.get("fileupload", []) +
            self.r.get("bizlogic", [])
        )

    def generate(self, output_path: str):
        html = self._build_html()
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

    def generate_pdf(self, output_path: str):
        from weasyprint import HTML as WP_HTML
        html = self._build_html()
        WP_HTML(string=html).write_pdf(output_path)

    # ── HTML principal ─────────────────────────────────────────────────────────

    def _build_html(self) -> str:
        risk = self._risk_data()
        counts = self._counts()

        return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Auditoría de Seguridad — {self.r.get('target','')}</title>
{self._css()}
</head>
<body>

{self._header(risk)}
{self._risk_banner(risk)}

<div class="container">
  {self._executive_summary(counts, risk)}
  {self._chart_svg(counts)}
  {self._section_osint()}
  {self._section_email()}
  {self._section_cms()}
  {self._section_js()}
  {self._section_graphql()}
  {self._section_fileupload()}
  {self._section_bizlogic()}
  {self._section_auth()}
  {self._section_webapp()}
  {self._section_recon()}
  {self._section_wifi()}
  {self._section_misconfigs()}
  {self._section_cves()}
  {self._section_web()}
  {self._section_ssl()}
  {self._section_dns()}
  {self._section_creds()}
  {self._section_recommendations()}
  {self._section_lopdgdd()}
  {self._section_legal()}
</div>

<div class="footer">
  Generado por AuditPyme v1.0 · {self.r.get('fecha_fin', '')}
</div>
</body>
</html>"""

    # ── CSS ────────────────────────────────────────────────────────────────────

    def _css(self) -> str:
        return """<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', Arial, sans-serif; background: #f0f2f5; color: #2c3e50; }

.header {
  background: linear-gradient(135deg, #0d1117 0%, #161b22 60%, #1a3a5c 100%);
  color: white; padding: 44px 64px;
}
.header h1 { font-size: 1.9rem; letter-spacing: 3px; font-weight: 300; }
.header h1 strong { font-weight: 700; }
.header .subtitle { color: #8b9ec0; margin-top: 6px; font-size: 0.88rem; letter-spacing: 1px; }
.header .meta { margin-top: 22px; display: flex; gap: 36px; flex-wrap: wrap; }
.header .meta-item { font-size: 0.82rem; color: #8b9ec0; }
.header .meta-item strong { color: #e0e8f0; display: block; font-size: 0.95rem; }

.risk-banner {
  padding: 18px 64px; display: flex; align-items: center; gap: 18px;
  font-size: 1rem; font-weight: 600; border-bottom: 3px solid;
}
.risk-badge {
  padding: 7px 22px; border-radius: 30px; color: white;
  font-size: 1rem; font-weight: 800; letter-spacing: 2px;
}
.risk-desc { font-size: 0.88rem; font-weight: 400; color: #555; }

.container { max-width: 1200px; margin: 28px auto; padding: 0 28px; }

.section {
  background: white; border-radius: 10px; margin-bottom: 22px;
  box-shadow: 0 2px 12px rgba(0,0,0,0.07); overflow: hidden;
}
.section-header {
  background: #1e2936; color: white; padding: 13px 22px;
  font-size: 0.85rem; font-weight: 700; letter-spacing: 2px; text-transform: uppercase;
}
.section-body { padding: 20px 22px; }

/* Cards */
.cards { display: flex; gap: 14px; flex-wrap: wrap; }
.card {
  flex: 1; min-width: 110px; background: #f8f9fb;
  border-radius: 10px; padding: 16px; text-align: center;
  border-top: 4px solid #ddd; transition: transform 0.2s;
}
.card:hover { transform: translateY(-2px); }
.card .num { font-size: 2.2rem; font-weight: 800; }
.card .label { font-size: 0.72rem; color: #888; margin-top: 4px;
               text-transform: uppercase; letter-spacing: 1px; }

/* Tables */
table { width: 100%; border-collapse: collapse; font-size: 0.87rem; }
th { background: #2c3e50; color: white; padding: 10px 14px; text-align: left;
     font-size: 0.8rem; letter-spacing: 1px; text-transform: uppercase; }
td { padding: 9px 14px; border-bottom: 1px solid #f0f0f0; vertical-align: top; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: #f8f9fb; }

/* Badges */
.badge {
  display: inline-block; padding: 3px 10px; border-radius: 20px;
  color: white; font-size: 0.72rem; font-weight: 700; letter-spacing: 0.5px;
}

/* Code / MSF */
.msf {
  background: #0d1117; color: #00e676; padding: 5px 10px;
  border-radius: 4px; font-family: 'Courier New', monospace;
  font-size: 0.78rem; white-space: nowrap; overflow-x: auto;
  display: block; margin-top: 4px;
}
code { background: #f0f0f0; padding: 2px 6px; border-radius: 3px;
       font-family: monospace; font-size: 0.85rem; }

/* Links */
a.cve { color: #2980b9; text-decoration: none; font-weight: 600; }
a.cve:hover { text-decoration: underline; }

/* No findings */
.ok { color: #27ae60; font-weight: 600; padding: 8px 0; }

/* Executive summary text */
.exec-text {
  line-height: 1.75; color: #444; font-size: 0.92rem;
  border-left: 4px solid #2c3e50; padding-left: 16px;
  margin-bottom: 20px;
}

/* Chart container */
.chart-wrap { padding: 16px 0 8px; }
.chart-label { font-size: 0.78rem; color: #666; margin-bottom: 10px; }
.bar-row { display: flex; align-items: center; margin-bottom: 10px; gap: 12px; }
.bar-sev { width: 70px; font-size: 0.8rem; font-weight: 700; text-align: right; }
.bar-bg { flex: 1; background: #f0f0f0; border-radius: 4px; height: 22px; position: relative; }
.bar-fill { height: 22px; border-radius: 4px; transition: width 0.5s; }
.bar-count { font-size: 0.82rem; font-weight: 700; min-width: 24px; }

/* Footer */
.footer { text-align: center; padding: 28px; color: #aaa; font-size: 0.8rem; }

@media print {
  body { background: white; }
  .section { box-shadow: none; border: 1px solid #ddd; }
}
</style>"""

    # ── Header ─────────────────────────────────────────────────────────────────

    def _header(self, risk: dict) -> str:
        empresa = self.r.get("empresa") or "No especificada"
        auditor = self.r.get("auditor") or "No especificado"
        return f"""
<div class="header">
  <h1><strong>INFORME</strong> DE AUDITORÍA DE SEGURIDAD</h1>
  <div class="subtitle">AuditPyme v1.0 · Reconocimiento · Vulnerabilidades · Análisis Web · SSL · DNS</div>
  <div class="meta">
    <div class="meta-item"><strong>{self.r.get('target','')}</strong>Objetivo</div>
    <div class="meta-item"><strong>{empresa}</strong>Empresa auditada</div>
    <div class="meta-item"><strong>{auditor}</strong>Auditor</div>
    <div class="meta-item"><strong>{self.r.get('fecha_inicio','')}</strong>Inicio</div>
    <div class="meta-item"><strong>{self.r.get('fecha_fin','')}</strong>Fin</div>
  </div>
</div>"""

    def _risk_banner(self, risk: dict) -> str:
        return f"""
<div class="risk-banner" style="background:{risk['color']}11; border-color:{risk['color']};">
  <span>Nivel de riesgo global:</span>
  <span class="risk-badge" style="background:{risk['color']};">{risk['label']}</span>
  <span class="risk-desc">{risk['desc']}</span>
</div>"""

    # ── Resumen ejecutivo ──────────────────────────────────────────────────────

    def _executive_summary(self, counts: dict, risk: dict) -> str:
        text = self._generate_exec_text(counts, risk)
        cards_html = f"""
    <div class="cards" style="margin-top:20px;">
      <div class="card" style="border-color:#7f8c8d;">
        <div class="num">{counts['hosts']}</div><div class="label">Hosts activos</div></div>
      <div class="card" style="border-color:#2980b9;">
        <div class="num">{counts['puertos']}</div><div class="label">Puertos abiertos</div></div>
      <div class="card" style="border-color:#c0392b;">
        <div class="num" style="color:#c0392b;">{counts['critical']}</div><div class="label">Críticos</div></div>
      <div class="card" style="border-color:#e67e22;">
        <div class="num" style="color:#e67e22;">{counts['high']}</div><div class="label">Altos</div></div>
      <div class="card" style="border-color:#d4ac0d;">
        <div class="num" style="color:#d4ac0d;">{counts['medium']}</div><div class="label">Medios</div></div>
      <div class="card" style="border-color:#2980b9;">
        <div class="num" style="color:#2980b9;">{counts['low']}</div><div class="label">Bajos</div></div>
      <div class="card" style="border-color:#c0392b;">
        <div class="num" style="color:#c0392b;">{counts['creds']}</div><div class="label">Accesos obtenidos</div></div>
    </div>"""

        return f"""
  <div class="section">
    <div class="section-header">Resumen Ejecutivo</div>
    <div class="section-body">
      <p class="exec-text">{text}</p>
      {cards_html}
    </div>
  </div>"""

    def _generate_exec_text(self, counts: dict, risk: dict) -> str:
        target = self.r.get("target", "el objetivo")
        empresa = self.r.get("empresa", "")
        empresa_str = f" de {empresa}" if empresa else ""
        fecha = self.r.get("fecha_inicio", "")

        cred_str = ""
        if counts["creds"] > 0:
            cred_str = (f" Se obtuvieron <strong>{counts['creds']} accesos directos</strong> "
                        f"mediante credenciales por defecto, lo que indica una exposición crítica inmediata.")

        web_str = ""
        if counts["web"] > 0:
            web_str = (f" El análisis de la capa web reveló {counts['web']} hallazgos, "
                       f"incluyendo cabeceras de seguridad ausentes y rutas sensibles expuestas.")

        ssl_str = ""
        if counts["ssl"] > 0:
            ssl_str = f" Se detectaron {counts['ssl']} problemas en la configuración SSL/TLS."

        dns_str = ""
        if counts["dns"] > 0:
            dns_str = f" La enumeración DNS expuso {counts['dns']} hallazgos relevantes."

        if counts["critical"] > 0:
            conclusion = (f"La infraestructura{empresa_str} presenta <strong>vulnerabilidades críticas que requieren "
                          f"atención inmediata</strong>. Un atacante con acceso a la red podría comprometer "
                          f"sistemas clave sin necesidad de técnicas avanzadas.")
        elif counts["high"] > 0:
            conclusion = (f"La infraestructura{empresa_str} presenta <strong>vulnerabilidades de riesgo alto</strong> "
                          f"que deben mitigarse en el corto plazo para reducir la superficie de ataque.")
        elif counts["medium"] > 0:
            conclusion = (f"La infraestructura{empresa_str} presenta un <strong>nivel de riesgo medio</strong>. "
                          f"Se recomienda planificar la mitigación de los hallazgos encontrados.")
        else:
            conclusion = (f"La infraestructura{empresa_str} no presenta vulnerabilidades críticas conocidas. "
                          f"Se recomienda revisar los hallazgos menores y mantener actualizaciones al día.")

        return (
            f"El presente informe recoge los resultados de la auditoría de seguridad realizada el {fecha} "
            f"sobre <strong>{target}</strong>. Durante el análisis se identificaron "
            f"<strong>{counts['hosts']} host(s) activo(s)</strong> con "
            f"<strong>{counts['puertos']} puerto(s) abierto(s)</strong>. "
            f"Se encontraron <strong>{counts['critical']} hallazgo(s) crítico(s)</strong>, "
            f"{counts['high']} alto(s), {counts['medium']} medio(s) y {counts['low']} bajo(s)."
            f"{cred_str}{web_str}{ssl_str}{dns_str} {conclusion}"
        )

    # ── Gráfica SVG de barras ──────────────────────────────────────────────────

    def _chart_svg(self, counts: dict) -> str:
        data = [
            ("CRITICAL", counts["critical"], "#c0392b"),
            ("HIGH",     counts["high"],     "#e67e22"),
            ("MEDIUM",   counts["medium"],   "#d4ac0d"),
            ("LOW",      counts["low"],      "#2980b9"),
        ]
        total = max(sum(v for _, v, _ in data), 1)
        bars = ""
        for label, value, color in data:
            pct = int((value / total) * 100)
            bars += f"""
    <div class="bar-row">
      <div class="bar-sev" style="color:{color};">{label}</div>
      <div class="bar-bg">
        <div class="bar-fill" style="width:{pct}%; background:{color};"></div>
      </div>
      <div class="bar-count" style="color:{color};">{value}</div>
    </div>"""

        return f"""
  <div class="section">
    <div class="section-header">Distribución de Hallazgos por Severidad</div>
    <div class="section-body">
      <div class="chart-wrap">{bars}</div>
    </div>
  </div>"""

    # ── Fase 1: Reconocimiento ─────────────────────────────────────────────────

    def _section_recon(self) -> str:
        recon = self.r.get("recon", {}) or {}
        hosts = recon.get("hosts", [])
        if not hosts:
            return ""

        rows = ""
        for host in hosts:
            if host["estado"] != "up":
                continue
            os_str = host["os"]["nombre"]
            if host["os"]["precision"]:
                os_str += f" ({host['os']['precision']}%)"
            for p in host["puertos"]:
                version = f"{p['producto']} {p['version']}".strip()
                notas_html = ""
                for sev, nota in p.get("notas", []):
                    c = SEVERITY_COLOR.get(sev, "#999")
                    notas_html += f'<div style="margin-top:4px;font-size:0.78rem;color:{c};">⚠ {nota}</div>'
                rows += f"""
        <tr>
          <td>{host['ip']}</td>
          <td style="color:#666;font-size:0.82rem;">{host['hostname']}</td>
          <td><strong>{p['puerto']}</strong>/{p['protocolo']}</td>
          <td>{p['servicio']}</td>
          <td>{version or '—'}</td>
          <td>{os_str}</td>
          <td>{notas_html or '—'}</td>
        </tr>"""

        return self._wrap_section(
            "FASE 1 — Puertos y Servicios Descubiertos",
            f"""<table><thead><tr>
              <th>IP</th><th>Hostname</th><th>Puerto</th>
              <th>Servicio</th><th>Versión</th><th>OS</th><th>Notas nmap</th>
            </tr></thead><tbody>{rows}</tbody></table>"""
        )

    # ── Fase 2: Malas configuraciones ──────────────────────────────────────────

    def _section_misconfigs(self) -> str:
        items = sorted(self.r.get("misconfigs", []),
                       key=lambda x: SEVERITY_ORDER.get(x.get("severidad", "UNKNOWN"), 99))
        if not items:
            return self._wrap_section(
                "FASE 2 — Malas Configuraciones",
                '<p class="ok">No se detectaron malas configuraciones conocidas.</p>'
            )

        rows = ""
        for m in items:
            sev = m.get("severidad", "UNKNOWN")
            color = SEVERITY_COLOR.get(sev, "#999")
            msf = f'<span class="msf">msf6 &gt; use {m["msf"]}</span>' if m.get("msf") else "—"
            rows += f"""
      <tr>
        <td><span class="badge" style="background:{color};">{sev}</span></td>
        <td>{m['ip']}:{m['puerto']}</td>
        <td>{m['servicio']}</td>
        <td>{m['descripcion']}</td>
        <td>{msf}</td>
      </tr>"""

        return self._wrap_section(
            "FASE 2 — Malas Configuraciones Detectadas",
            f"""<table><thead><tr>
              <th>Severidad</th><th>Host:Puerto</th><th>Servicio</th>
              <th>Descripción</th><th>Módulo Metasploit</th>
            </tr></thead><tbody>{rows}</tbody></table>"""
        )

    # ── Fase 2: CVEs ───────────────────────────────────────────────────────────

    def _section_cves(self) -> str:
        cves = sorted(self.r.get("vulns", []),
                      key=lambda x: SEVERITY_ORDER.get(x.get("severidad", "UNKNOWN"), 99))
        if not cves:
            return self._wrap_section(
                "FASE 2 — CVEs (NVD)",
                '<p class="ok">No se encontraron CVEs para los servicios detectados.</p>'
            )

        rows = ""
        for c in cves:
            sev = c.get("severidad", "UNKNOWN")
            color = SEVERITY_COLOR.get(sev, "#999")
            rows += f"""
      <tr>
        <td>
          <span class="badge" style="background:{color};">{sev}</span>
          <div style="font-size:0.75rem;color:#888;margin-top:3px;">Score: {c.get('puntuacion',0)}</div>
        </td>
        <td><a class="cve" href="{c['url']}" target="_blank">{c['cve_id']}</a></td>
        <td>{c['ip']}:{c['puerto']}</td>
        <td>{c['producto']}</td>
        <td style="font-size:0.82rem;color:#555;">{c['descripcion']}</td>
      </tr>"""

        return self._wrap_section(
            "FASE 2 — CVEs Encontrados (NVD)",
            f"""<table><thead><tr>
              <th>Severidad</th><th>CVE ID</th><th>Host:Puerto</th>
              <th>Producto</th><th>Descripción</th>
            </tr></thead><tbody>{rows}</tbody></table>"""
        )

    # ── Web ────────────────────────────────────────────────────────────────────

    def _section_web(self) -> str:
        items = sorted(self.r.get("web", []),
                       key=lambda x: SEVERITY_ORDER.get(x.get("severidad", "UNKNOWN"), 99))
        if not items:
            return ""

        rows = ""
        for w in items:
            sev = w.get("severidad", "INFO")
            color = SEVERITY_COLOR.get(sev, "#999")
            rows += f"""
      <tr>
        <td><span class="badge" style="background:{color};">{sev}</span></td>
        <td style="font-size:0.8rem;color:#555;">{w['url']}</td>
        <td>{w['tipo']}</td>
        <td>{w['nombre']}</td>
        <td style="font-size:0.82rem;">{w['descripcion']}</td>
      </tr>"""

        return self._wrap_section(
            "FASE 2 — Análisis Web (Cabeceras y Rutas Sensibles)",
            f"""<table><thead><tr>
              <th>Severidad</th><th>URL</th><th>Tipo</th><th>Hallazgo</th><th>Descripción</th>
            </tr></thead><tbody>{rows}</tbody></table>"""
        )

    # ── SSL ────────────────────────────────────────────────────────────────────

    def _section_ssl(self) -> str:
        items = sorted(self.r.get("ssl", []),
                       key=lambda x: SEVERITY_ORDER.get(x.get("severidad", "UNKNOWN"), 99))
        if not items:
            return ""

        rows = ""
        for s in items:
            if s.get("severidad") == "INFO":
                continue
            sev = s.get("severidad", "UNKNOWN")
            color = SEVERITY_COLOR.get(sev, "#999")
            rows += f"""
      <tr>
        <td><span class="badge" style="background:{color};">{sev}</span></td>
        <td>{s['ip']}:{s['puerto']}</td>
        <td>{s['nombre']}</td>
        <td style="font-size:0.82rem;">{s['descripcion']}</td>
        <td style="font-size:0.82rem;color:#555;">{s.get('recomendacion','')}</td>
      </tr>"""

        if not rows:
            return ""

        return self._wrap_section(
            "FASE 2 — Análisis SSL/TLS",
            f"""<table><thead><tr>
              <th>Severidad</th><th>Host:Puerto</th><th>Hallazgo</th>
              <th>Descripción</th><th>Recomendación</th>
            </tr></thead><tbody>{rows}</tbody></table>"""
        )

    # ── DNS ────────────────────────────────────────────────────────────────────

    def _section_dns(self) -> str:
        items = [d for d in self.r.get("dns", []) if d.get("severidad") != "INFO"]
        items = sorted(items, key=lambda x: SEVERITY_ORDER.get(x.get("severidad", "UNKNOWN"), 99))
        if not items:
            return ""

        rows = ""
        for d in items:
            sev = d.get("severidad", "INFO")
            color = SEVERITY_COLOR.get(sev, "#999")
            rows += f"""
      <tr>
        <td><span class="badge" style="background:{color};">{sev}</span></td>
        <td>{d['tipo']}</td>
        <td>{d['nombre']}</td>
        <td style="font-size:0.82rem;">{d['descripcion'][:200]}</td>
        <td style="font-size:0.82rem;color:#555;">{d.get('recomendacion','')}</td>
      </tr>"""

        return self._wrap_section(
            "FASE 2 — Enumeración DNS",
            f"""<table><thead><tr>
              <th>Severidad</th><th>Tipo</th><th>Hallazgo</th>
              <th>Descripción</th><th>Recomendación</th>
            </tr></thead><tbody>{rows}</tbody></table>"""
        )

    # ── Credenciales ───────────────────────────────────────────────────────────

    def _section_creds(self) -> str:
        accesos = [c for c in self.r.get("creds", []) if c.get("acceso")]
        if not accesos:
            creds = self.r.get("creds", [])
            if not creds:
                return ""
            return self._wrap_section(
                "FASE 3 — Credenciales por Defecto",
                '<p class="ok">Ningún servicio acepta credenciales por defecto conocidas.</p>'
            )

        rows = ""
        for c in accesos:
            extra = f'<div style="font-size:0.78rem;color:#888;">{c.get("extra","")}</div>' if c.get("extra") else ""
            rows += f"""
      <tr>
        <td><span class="badge" style="background:#c0392b;">CRITICAL</span></td>
        <td>{c['ip']}:{c['puerto']}</td>
        <td>{c['servicio']}</td>
        <td><code>{c['usuario']}</code></td>
        <td><code>{c['password'] or '(vacía)'}</code></td>
        <td>{extra}</td>
      </tr>"""

        return self._wrap_section(
            "FASE 3 — Accesos con Credenciales por Defecto",
            f"""<table><thead><tr>
              <th>Severidad</th><th>Host:Puerto</th><th>Servicio</th>
              <th>Usuario</th><th>Contraseña</th><th>Info</th>
            </tr></thead><tbody>{rows}</tbody></table>"""
        )

    # ── Recomendaciones ────────────────────────────────────────────────────────

    def _section_recommendations(self) -> str:
        recs = []
        seen = set()

        all_sources = (
            self.r.get("email", []) +
            self.r.get("osint", []) +
            self.r.get("misconfigs", []) +
            self.r.get("web", []) +
            self.r.get("ssl", []) +
            self.r.get("dns", []) +
            self.r.get("wifi", []) +
            self.r.get("webapp", []) +
            self.r.get("cms", []) +
            self.r.get("auth", []) +
            self.r.get("js", []) +
            self.r.get("graphql", []) +
            self.r.get("fileupload", []) +
            self.r.get("bizlogic", [])
        )
        # Solo CRITICAL y HIGH — nada de ruido
        all_sources = [f for f in all_sources
                       if f.get("severidad") in ("CRITICAL", "HIGH")]
        all_sources = sorted(all_sources,
                             key=lambda x: SEVERITY_ORDER.get(x.get("severidad", "UNKNOWN"), 99))

        for item in all_sources:
            rec = item.get("recomendacion", "")
            if not rec or rec in seen:
                continue
            seen.add(rec)
            sev = item.get("severidad", "UNKNOWN")
            color = SEVERITY_COLOR.get(sev, "#999")
            sev_es = SEVERITY_ES.get(sev, sev)

            icon, impact = self._get_business_impact(item)
            impact_html = ""
            if impact:
                impact_html = f"""
                <div style="margin-top:6px;padding:8px 12px;background:#fff8f0;
                            border-left:3px solid {color};border-radius:4px;
                            font-size:0.82rem;color:#333;">
                  <strong>{icon} Impacto real:</strong> {impact}
                </div>"""

            afecta = ""
            if "ip" in item and "puerto" in item:
                afecta = f"{item['ip']}:{item['puerto']}"
            elif "url" in item:
                afecta = item["url"][:60]
            elif "tipo" in item:
                afecta = item["tipo"]

            recs.append(f"""
      <tr>
        <td style="vertical-align:top;">
          <span class="badge" style="background:{color};">{sev_es}</span>
        </td>
        <td style="vertical-align:top;font-size:0.82rem;color:#555;">{afecta}</td>
        <td style="vertical-align:top;">
          <strong>{item.get('nombre','')}</strong>
          {impact_html}
        </td>
        <td style="vertical-align:top;font-size:0.85rem;">{rec}</td>
      </tr>""")

        for c in [c for c in self.r.get("creds", []) if c.get("acceso")]:
            icon, impact = "🔑", "Acceso directo al sistema sin necesidad de atacar nada. Un script automático puede entrar en minutos y tomar control total."
            recs.append(f"""
      <tr>
        <td style="vertical-align:top;">
          <span class="badge" style="background:#c0392b;">Crítico</span>
        </td>
        <td style="vertical-align:top;font-size:0.82rem;color:#555;">{c['ip']}:{c['puerto']}</td>
        <td style="vertical-align:top;">
          <strong>Credenciales por defecto — {c['servicio']}</strong>
          <div style="margin-top:6px;padding:8px 12px;background:#fff8f0;
                      border-left:3px solid #c0392b;border-radius:4px;
                      font-size:0.82rem;color:#333;">
            <strong>{icon} Impacto real:</strong> {impact}
          </div>
        </td>
        <td style="vertical-align:top;font-size:0.85rem;">
          Cambiar las credenciales por defecto inmediatamente (usuario: <code>{c['usuario']}</code>).
        </td>
      </tr>""")

        if not recs:
            return self._wrap_section(
                "Hallazgos que requieren acción",
                '<p class="ok">✓ No se detectaron vulnerabilidades de impacto real significativo.</p>'
            )

        intro = f"""<p style="font-size:0.88rem;color:#555;margin-bottom:16px;
                              padding:12px;background:#f8f9fb;border-radius:6px;">
            Se muestran únicamente los hallazgos con impacto real potencial para el negocio.
            Cada uno incluye una explicación en lenguaje no técnico de qué puede ocurrir si no se corrige.
            </p>"""

        return self._wrap_section(
            "Hallazgos que requieren acción — con impacto real",
            intro + f"""<table><thead><tr>
              <th>Prioridad</th><th>Área</th><th>Hallazgo e impacto</th><th>Cómo corregirlo</th>
            </tr></thead><tbody>{''.join(recs)}</tbody></table>"""
        )

    # ── Email ──────────────────────────────────────────────────────────────────

    def _section_email(self) -> str:
        items = sorted(self.r.get("email", []),
                       key=lambda x: SEVERITY_ORDER.get(x.get("severidad", "UNKNOWN"), 99))
        if not items:
            return ""

        rows = ""
        for e in items:
            sev = e.get("severidad", "INFO")
            color = SEVERITY_COLOR.get(sev, "#999")
            desc = e.get("descripcion", "").replace("\n", "<br>")
            rows += f"""
      <tr>
        <td><span class="badge" style="background:{color};">{SEVERITY_ES.get(sev, sev)}</span></td>
        <td><strong>{e.get('tipo','')}</strong></td>
        <td>{e.get('nombre','')}</td>
        <td style="font-size:0.82rem;">{desc}</td>
        <td style="font-size:0.82rem;color:#555;">{e.get('recomendacion','')}</td>
      </tr>"""

        return self._wrap_section(
            "Seguridad de Email — SPF · DKIM · DMARC · MTA-STS",
            f"""<table><thead><tr>
              <th>Severidad</th><th>Tipo</th><th>Hallazgo</th>
              <th>Descripción</th><th>Recomendación</th>
            </tr></thead><tbody>{rows}</tbody></table>"""
        )

    # ── OSINT ──────────────────────────────────────────────────────────────────

    def _section_osint(self) -> str:
        items = sorted(self.r.get("osint", []),
                       key=lambda x: SEVERITY_ORDER.get(x.get("severidad", "UNKNOWN"), 99))
        if not items:
            return ""

        rows = ""
        for o in items:
            sev = o.get("severidad", "INFO")
            color = SEVERITY_COLOR.get(sev, "#999")
            desc = o.get("descripcion", "").replace("\n", "<br>")
            rows += f"""
      <tr>
        <td><span class="badge" style="background:{color};">{SEVERITY_ES.get(sev, sev)}</span></td>
        <td><strong>{o.get('tipo','')}</strong></td>
        <td>{o.get('nombre','')}</td>
        <td style="font-size:0.82rem;">{desc}</td>
        <td style="font-size:0.82rem;color:#555;">{o.get('recomendacion','')}</td>
      </tr>"""

        return self._wrap_section(
            "OSINT — Información Pública Expuesta",
            f"""<table><thead><tr>
              <th>Severidad</th><th>Fuente</th><th>Hallazgo</th>
              <th>Descripción</th><th>Recomendación</th>
            </tr></thead><tbody>{rows}</tbody></table>"""
        )

    # ── WebApp OWASP ───────────────────────────────────────────────────────────

    def _section_webapp(self) -> str:
        items = sorted(self.r.get("webapp", []),
                       key=lambda x: SEVERITY_ORDER.get(x.get("severidad", "UNKNOWN"), 99))
        if not items:
            return ""

        rows = ""
        for f in items:
            sev = f.get("severidad", "INFO")
            color = SEVERITY_COLOR.get(sev, "#999")
            desc = f.get("descripcion", "").replace("\n", "<br>")
            icon, impact = self._get_business_impact(f)
            impact_html = f'<div style="margin-top:5px;font-size:0.78rem;color:#c0392b;"><strong>{icon} Impacto:</strong> {impact}</div>' if impact else ""
            rows += f"""
      <tr>
        <td><span class="badge" style="background:{color};">{SEVERITY_ES.get(sev, sev)}</span></td>
        <td><strong>{f.get('tipo','')}</strong></td>
        <td>{f.get('nombre','')}{impact_html}</td>
        <td style="font-size:0.82rem;">{desc}</td>
        <td style="font-size:0.82rem;color:#555;">{f.get('recomendacion','')}</td>
      </tr>"""

        return self._wrap_section(
            "Análisis OWASP — Inyecciones y Vulnerabilidades Web",
            f"""<table><thead><tr>
              <th>Severidad</th><th>Tipo</th><th>Hallazgo</th>
              <th>Descripción</th><th>Solución</th>
            </tr></thead><tbody>{rows}</tbody></table>"""
        )

    # ── JavaScript / Secretos ─────────────────────────────────────────────────

    def _section_js(self) -> str:
        items = sorted(self.r.get("js", []),
                       key=lambda x: SEVERITY_ORDER.get(x.get("severidad", "UNKNOWN"), 99))
        if not items:
            return ""
        rows = ""
        for f in items:
            sev = f.get("severidad", "INFO")
            color = SEVERITY_COLOR.get(sev, "#999")
            impacto = f.get("impacto", "")
            impacto_html = (
                f'<div style="margin-top:5px;font-size:0.78rem;color:#c0392b;">'
                f'<strong>⚠ Impacto:</strong> {impacto}</div>'
            ) if impacto else ""
            desc = f.get("descripcion", "").replace("\n", "<br>")
            rows += f"""
      <tr>
        <td><span class="badge" style="background:{color};">{SEVERITY_ES.get(sev, sev)}</span></td>
        <td><strong>{f.get('nombre','')}</strong>{impacto_html}</td>
        <td style="font-size:0.82rem;">{desc}</td>
        <td style="font-size:0.82rem;color:#555;">{f.get('recomendacion','')}</td>
      </tr>"""
        return self._wrap_section(
            "Análisis JavaScript — API Keys · Secretos · Source Maps",
            f"""<table><thead><tr>
              <th>Severidad</th><th>Hallazgo</th>
              <th>Descripción</th><th>Solución</th>
            </tr></thead><tbody>{rows}</tbody></table>"""
        )

    # ── Lógica de negocio ─────────────────────────────────────────────────────

    def _section_bizlogic(self) -> str:
        items = sorted(self.r.get("bizlogic", []),
                       key=lambda x: SEVERITY_ORDER.get(x.get("severidad", "UNKNOWN"), 99))
        if not items:
            return ""
        rows = ""
        for f in items:
            sev = f.get("severidad", "INFO")
            color = SEVERITY_COLOR.get(sev, "#999")
            impacto = f.get("impacto", "")
            impacto_html = (
                f'<div style="margin-top:5px;font-size:0.78rem;color:#c0392b;">'
                f'<strong>⚠ Impacto:</strong> {impacto}</div>'
            ) if impacto else ""
            rows += f"""
      <tr>
        <td><span class="badge" style="background:{color};">{SEVERITY_ES.get(sev, sev)}</span></td>
        <td><strong>{f.get('nombre','')}</strong>{impacto_html}</td>
        <td style="font-size:0.82rem;">{f.get('descripcion','')}</td>
        <td style="font-size:0.82rem;color:#555;">{f.get('recomendacion','')}</td>
      </tr>"""
        return self._wrap_section(
            "Lógica de Negocio — Precios · Cupones · CORS · Mass Assignment",
            f"""<table><thead><tr>
              <th>Severidad</th><th>Hallazgo</th>
              <th>Descripción</th><th>Solución</th>
            </tr></thead><tbody>{rows}</tbody></table>"""
        )

    # ── File Upload ───────────────────────────────────────────────────────────

    def _section_fileupload(self) -> str:
        items = sorted(self.r.get("fileupload", []),
                       key=lambda x: SEVERITY_ORDER.get(x.get("severidad", "UNKNOWN"), 99))
        if not items:
            return ""
        rows = ""
        for f in items:
            sev = f.get("severidad", "INFO")
            color = SEVERITY_COLOR.get(sev, "#999")
            impacto = f.get("impacto", "")
            impacto_html = (
                f'<div style="margin-top:5px;font-size:0.78rem;color:#c0392b;">'
                f'<strong>⚠ Impacto:</strong> {impacto}</div>'
            ) if impacto else ""
            rows += f"""
      <tr>
        <td><span class="badge" style="background:{color};">{SEVERITY_ES.get(sev, sev)}</span></td>
        <td><strong>{f.get('nombre','')}</strong>{impacto_html}</td>
        <td style="font-size:0.82rem;">{f.get('descripcion','')}</td>
        <td style="font-size:0.82rem;color:#555;">{f.get('recomendacion','')}</td>
      </tr>"""
        return self._wrap_section(
            "Subida de Archivos — RCE · Bypass · Zip Slip",
            f"""<table><thead><tr>
              <th>Severidad</th><th>Hallazgo</th>
              <th>Descripción</th><th>Solución</th>
            </tr></thead><tbody>{rows}</tbody></table>"""
        )

    # ── GraphQL ───────────────────────────────────────────────────────────────

    def _section_graphql(self) -> str:
        items = sorted(self.r.get("graphql", []),
                       key=lambda x: SEVERITY_ORDER.get(x.get("severidad", "UNKNOWN"), 99))
        if not items:
            return ""
        rows = ""
        for f in items:
            sev = f.get("severidad", "INFO")
            color = SEVERITY_COLOR.get(sev, "#999")
            impacto = f.get("impacto", "")
            impacto_html = (
                f'<div style="margin-top:5px;font-size:0.78rem;color:#c0392b;">'
                f'<strong>⚠ Impacto:</strong> {impacto}</div>'
            ) if impacto else ""
            rows += f"""
      <tr>
        <td><span class="badge" style="background:{color};">{SEVERITY_ES.get(sev, sev)}</span></td>
        <td><strong>{f.get('nombre','')}</strong>{impacto_html}</td>
        <td style="font-size:0.82rem;">{f.get('descripcion','')}</td>
        <td style="font-size:0.82rem;color:#555;">{f.get('recomendacion','')}</td>
      </tr>"""
        return self._wrap_section(
            "Auditoría GraphQL — Introspección · Autenticación · DoS",
            f"""<table><thead><tr>
              <th>Severidad</th><th>Hallazgo</th>
              <th>Descripción</th><th>Solución</th>
            </tr></thead><tbody>{rows}</tbody></table>"""
        )

    # ── Autenticación ──────────────────────────────────────────────────────────

    def _section_auth(self) -> str:
        items = sorted(self.r.get("auth", []),
                       key=lambda x: SEVERITY_ORDER.get(x.get("severidad", "UNKNOWN"), 99))
        if not items:
            return ""
        rows = ""
        for f in items:
            sev = f.get("severidad", "INFO")
            color = SEVERITY_COLOR.get(sev, "#999")
            impacto = f.get("impacto", "")
            impacto_html = (
                f'<div style="margin-top:5px;font-size:0.78rem;color:#c0392b;">'
                f'<strong>⚠ Impacto:</strong> {impacto}</div>'
            ) if impacto else ""
            rows += f"""
      <tr>
        <td><span class="badge" style="background:{color};">{SEVERITY_ES.get(sev, sev)}</span></td>
        <td><strong>{f.get('nombre','')}</strong>{impacto_html}</td>
        <td style="font-size:0.82rem;">{f.get('descripcion','')}</td>
        <td style="font-size:0.82rem;color:#555;">{f.get('recomendacion','')}</td>
      </tr>"""
        return self._wrap_section(
            "Auditoría de Autenticación — Login Bypass · Fuerza Bruta · Sesión",
            f"""<table><thead><tr>
              <th>Severidad</th><th>Hallazgo</th>
              <th>Descripción</th><th>Solución</th>
            </tr></thead><tbody>{rows}</tbody></table>"""
        )

    # ── CMS ────────────────────────────────────────────────────────────────────

    def _section_cms(self) -> str:
        items = sorted(self.r.get("cms", []),
                       key=lambda x: SEVERITY_ORDER.get(x.get("severidad", "UNKNOWN"), 99))
        if not items:
            return ""

        rows = ""
        for f in items:
            sev = f.get("severidad", "INFO")
            color = SEVERITY_COLOR.get(sev, "#999")
            icon, impact = self._get_business_impact(f)
            impact_html = (
                f'<div style="margin-top:5px;font-size:0.78rem;color:#c0392b;">'
                f'<strong>{icon} Impacto:</strong> {impact}</div>'
            ) if impact else ""
            rows += f"""
      <tr>
        <td><span class="badge" style="background:{color};">{SEVERITY_ES.get(sev, sev)}</span></td>
        <td><strong>{f.get('nombre','')}</strong>{impact_html}</td>
        <td style="font-size:0.82rem;">{f.get('descripcion','')}</td>
        <td style="font-size:0.82rem;color:#555;">{f.get('recomendacion','')}</td>
      </tr>"""

        return self._wrap_section(
            "Fingerprinting CMS — WordPress · Joomla · PrestaShop · Laravel",
            f"""<table><thead><tr>
              <th>Severidad</th><th>Hallazgo</th>
              <th>Descripción</th><th>Solución</th>
            </tr></thead><tbody>{rows}</tbody></table>"""
        )

    # ── WiFi ───────────────────────────────────────────────────────────────────

    def _section_wifi(self) -> str:
        items = sorted(self.r.get("wifi", []),
                       key=lambda x: SEVERITY_ORDER.get(x.get("severidad", "UNKNOWN"), 99))
        if not items:
            return ""

        rows = ""
        for f in items:
            sev = f.get("severidad", "INFO")
            color = SEVERITY_COLOR.get(sev, "#999")
            icon, impact = self._get_business_impact(f)
            impact_html = (
                f'<div style="margin-top:5px;font-size:0.78rem;color:#c0392b;">'
                f'<strong>{icon} Impacto:</strong> {impact}</div>'
            ) if impact else ""
            rows += f"""
      <tr>
        <td><span class="badge" style="background:{color};">{SEVERITY_ES.get(sev, sev)}</span></td>
        <td><strong>{f.get('nombre','')}</strong>{impact_html}</td>
        <td style="font-size:0.82rem;">{f.get('descripcion','')}</td>
        <td style="font-size:0.82rem;color:#555;">{f.get('recomendacion','')}</td>
      </tr>"""

        return self._wrap_section(
            "Auditoría WiFi — Redes Inalámbricas",
            f"""<table><thead><tr>
              <th>Severidad</th><th>Hallazgo</th>
              <th>Descripción</th><th>Solución</th>
            </tr></thead><tbody>{rows}</tbody></table>"""
        )

    # ── LOPDGDD / ENS ──────────────────────────────────────────────────────────

    def _section_lopdgdd(self) -> str:
        all_f = self._all_findings
        counts = self._counts()

        checks = []

        # Datos personales expuestos
        db_exposed = any(
            any(kw in f.get("nombre", "").lower() for kw in ["mysql", "postgresql", "mongodb", "redis", "elasticsearch", "base de datos"])
            for f in all_f if f.get("severidad") in ("CRITICAL", "HIGH")
        )
        checks.append(("Base de datos / datos personales accesibles",
                        "CRITICAL" if db_exposed else "OK",
                        "Art. 32 RGPD — Medidas técnicas de seguridad",
                        "Base de datos accesible desde internet sin autenticación robusta."
                        if db_exposed else "No se detectaron bases de datos expuestas.",
                        "Restricción de acceso, cifrado en reposo y tránsito, control de acceso." if db_exposed else ""))

        # Email spoofing
        email_spoof = any(
            "spf" in f.get("tipo", "").lower() and f.get("severidad") in ("HIGH", "CRITICAL")
            or "dmarc" in f.get("tipo", "").lower() and f.get("severidad") in ("HIGH", "MEDIUM")
            for f in self.r.get("email", [])
        )
        checks.append(("Protección contra suplantación de identidad (phishing)",
                        "HIGH" if email_spoof else "OK",
                        "Art. 32 RGPD — Integridad y confidencialidad",
                        "SPF/DMARC no configurados: el dominio puede ser suplantado para phishing."
                        if email_spoof else "SPF y DMARC configurados correctamente.",
                        "Configurar SPF con -all y DMARC con p=reject." if email_spoof else ""))

        # SSL/TLS
        ssl_issues = [s for s in self.r.get("ssl", []) if s.get("severidad") in ("CRITICAL", "HIGH")]
        checks.append(("Cifrado de comunicaciones (SSL/TLS)",
                        "HIGH" if ssl_issues else "OK",
                        "Art. 32 RGPD — Cifrado de datos personales",
                        f"{len(ssl_issues)} problemas críticos/altos en SSL/TLS detectados."
                        if ssl_issues else "Sin problemas críticos de SSL/TLS.",
                        "Actualizar a TLS 1.2+ y eliminar cifrados débiles." if ssl_issues else ""))

        # Credenciales por defecto
        creds_ok = [c for c in self.r.get("creds", []) if c.get("acceso")]
        checks.append(("Control de acceso y credenciales",
                        "CRITICAL" if creds_ok else "OK",
                        "Art. 32 RGPD — Control de acceso",
                        f"Se obtuvieron {len(creds_ok)} accesos con credenciales por defecto."
                        if creds_ok else "No se detectaron credenciales por defecto.",
                        "Cambiar todas las credenciales por defecto inmediatamente." if creds_ok else ""))

        # Filtraciones
        hibp = [o for o in self.r.get("osint", []) if "filtración" in o.get("tipo", "").lower() or "hibp" in o.get("tipo", "").lower()]
        checks.append(("Gestión de brechas de seguridad (notificación)",
                        "HIGH" if hibp else "OK",
                        "Art. 33-34 RGPD — Notificación de brechas",
                        "Se encontraron datos del dominio en filtraciones conocidas (HIBP)."
                        if hibp else "No se encontraron filtraciones conocidas del dominio.",
                        "Notificar a la AEPD si hay brecha de datos personales (plazo: 72h)." if hibp else ""))

        rows = ""
        for name, status, articulo, desc, accion in checks:
            if status == "OK":
                color, badge, badge_color = "#27ae60", "CUMPLE", "#27ae60"
            elif status == "CRITICAL":
                color, badge, badge_color = "#c0392b", "CRÍTICO", "#c0392b"
            elif status == "HIGH":
                color, badge, badge_color = "#e67e22", "REVISAR", "#e67e22"
            else:
                color, badge, badge_color = "#d4ac0d", "REVISAR", "#d4ac0d"

            rows += f"""
      <tr>
        <td><span class="badge" style="background:{badge_color};">{badge}</span></td>
        <td>{name}</td>
        <td style="font-size:0.78rem;color:#888;">{articulo}</td>
        <td style="font-size:0.82rem;">{desc}</td>
        <td style="font-size:0.82rem;color:#555;">{accion}</td>
      </tr>"""

        nota = """<p style="font-size:0.8rem;color:#888;margin-top:12px;">
            Esta tabla es una evaluación técnica orientativa basada en los hallazgos de la auditoría.
            No constituye asesoramiento jurídico. Para una evaluación legal completa del cumplimiento
            del RGPD/LOPDGDD consulte con un Delegado de Protección de Datos (DPD).
            </p>"""

        return self._wrap_section(
            "Cumplimiento RGPD / LOPDGDD — Evaluación orientativa",
            f"""<table><thead><tr>
              <th>Estado</th><th>Área</th><th>Referencia legal</th>
              <th>Hallazgo</th><th>Acción</th>
            </tr></thead><tbody>{rows}</tbody></table>{nota}"""
        )

    # ── Aviso legal ────────────────────────────────────────────────────────────

    def _section_legal(self) -> str:
        return self._wrap_section(
            "Aviso Legal y Confidencialidad",
            """<p style="font-size:0.85rem;color:#666;line-height:1.75;">
            Este informe ha sido generado en el contexto de una auditoría de seguridad expresamente
            autorizada por el titular de los sistemas analizados. La información contenida es
            <strong>estrictamente confidencial</strong> y está destinada exclusivamente al receptor autorizado.
            Queda prohibida su reproducción, distribución o uso fuera del ámbito de esta auditoría.
            El uso no autorizado de las vulnerabilidades descritas en este documento puede constituir
            un delito tipificado en el Código Penal español (Art. 197 bis y siguientes) y en la
            legislación aplicable en la jurisdicción del receptor.
            </p>"""
        )

    # ── Utilidades ─────────────────────────────────────────────────────────────

    def _get_business_impact(self, finding: dict) -> tuple:
        """Devuelve (icono, texto de impacto real) para un hallazgo. '' si no aplica."""
        nombre = finding.get("nombre", "").lower()
        tipo   = finding.get("tipo", "").lower()
        desc   = finding.get("descripcion", "").lower()
        combined = nombre + " " + tipo + " " + desc

        for keyword, (icon, impact) in BUSINESS_IMPACT.items():
            if keyword in combined:
                return icon, impact
        return "", ""

    def _wrap_section(self, title: str, body: str) -> str:
        return f"""
  <div class="section">
    <div class="section-header">{title}</div>
    <div class="section-body">{body}</div>
  </div>"""

    def _counts(self) -> dict:
        recon = self.r.get("recon", {}) or {}
        hosts = recon.get("hosts", [])

        all_f = self._all_findings
        creds_ok = [c for c in self.r.get("creds", []) if c.get("acceso")]

        return {
            "hosts":    len([h for h in hosts if h["estado"] == "up"]),
            "puertos":  recon.get("total_puertos", 0),
            "critical": sum(1 for f in all_f if f.get("severidad") == "CRITICAL"),
            "high":     sum(1 for f in all_f if f.get("severidad") == "HIGH"),
            "medium":   sum(1 for f in all_f if f.get("severidad") == "MEDIUM"),
            "low":      sum(1 for f in all_f if f.get("severidad") == "LOW"),
            "creds":    len(creds_ok),
            "web":      len(self.r.get("web", [])),
            "ssl":      len([s for s in self.r.get("ssl", []) if s.get("severidad") != "INFO"]),
            "dns":      len([d for d in self.r.get("dns", []) if d.get("severidad") != "INFO"]),
        }

    def _risk_data(self) -> dict:
        all_f = self._all_findings
        creds_ok = [c for c in self.r.get("creds", []) if c.get("acceso")]

        has_crit = any(f.get("severidad") == "CRITICAL" for f in all_f) or len(creds_ok) > 0
        has_high = any(f.get("severidad") == "HIGH" for f in all_f)
        has_med  = any(f.get("severidad") == "MEDIUM" for f in all_f)

        if has_crit:
            return {"label": "CRÍTICO", "color": "#c0392b",
                    "desc": "Vulnerabilidades críticas detectadas. Acción inmediata requerida."}
        elif has_high:
            return {"label": "ALTO", "color": "#e67e22",
                    "desc": "Vulnerabilidades de alto riesgo. Mitigación urgente."}
        elif has_med:
            return {"label": "MEDIO", "color": "#d4ac0d",
                    "desc": "Vulnerabilidades de riesgo medio. Planificar mitigación."}
        else:
            return {"label": "BAJO", "color": "#27ae60",
                    "desc": "No se detectaron vulnerabilidades críticas o altas."}
