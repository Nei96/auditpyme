"""
Módulo de vulnerabilidades — Fase 2
1. Consulta CVEs en la API de NVD (NIST) por servicio y versión.
2. Detecta malas configuraciones conocidas.
3. Sugiere módulos de Metasploit relevantes.
"""

import requests
import time


# ── Malas configuraciones conocidas por puerto/servicio ───────────────────────
MISCONFIG_RULES = [
    {
        "servicio": "ftp",
        "puerto": 21,
        "descripcion": "FTP activo — protocolo sin cifrado, credenciales en texto plano.",
        "severidad": "HIGH",
        "recomendacion": "Migrar a SFTP (SSH) o FTPS. Deshabilitar FTP si no se usa.",
        "msf": "auxiliary/scanner/ftp/ftp_login",
    },
    {
        "servicio": "telnet",
        "puerto": 23,
        "descripcion": "Telnet activo — protocolo obsoleto sin cifrado. Acceso remoto en texto plano.",
        "severidad": "CRITICAL",
        "recomendacion": "Deshabilitar Telnet inmediatamente. Usar SSH.",
        "msf": "auxiliary/scanner/telnet/telnet_login",
    },
    {
        "servicio": "smtp",
        "puerto": 25,
        "descripcion": "SMTP expuesto públicamente — posible relay abierto.",
        "severidad": "MEDIUM",
        "recomendacion": "Restringir acceso SMTP a IPs autorizadas. Verificar configuración de relay.",
        "msf": "auxiliary/scanner/smtp/smtp_relay",
    },
    {
        "servicio": "dns",
        "puerto": 53,
        "descripcion": "DNS expuesto — posible transferencia de zona o amplificación DDoS.",
        "severidad": "MEDIUM",
        "recomendacion": "Restringir transferencias de zona. Deshabilitar recursión para IPs externas.",
        "msf": "auxiliary/gather/dns_info",
    },
    {
        "servicio": "http",
        "puerto": 80,
        "descripcion": "HTTP sin cifrado activo — tráfico web expuesto en texto plano.",
        "severidad": "MEDIUM",
        "recomendacion": "Implementar HTTPS (TLS 1.2+) y redirigir HTTP a HTTPS.",
        "msf": "auxiliary/scanner/http/http_header",
    },
    {
        "servicio": "msrpc",
        "puerto": 135,
        "descripcion": "RPC de Windows expuesto — vector de ataque remoto histórico.",
        "severidad": "HIGH",
        "recomendacion": "Restringir acceso al puerto 135 mediante firewall.",
        "msf": "exploit/windows/dcerpc/ms03_026_dcom",
    },
    {
        "servicio": "netbios",
        "puerto": 139,
        "descripcion": "NetBIOS activo — expone información de la red Windows.",
        "severidad": "MEDIUM",
        "recomendacion": "Deshabilitar NetBIOS si no es necesario. Usar SMBv3.",
        "msf": "auxiliary/scanner/netbios/nbname",
    },
    {
        "servicio": "microsoft-ds",
        "puerto": 445,
        "descripcion": "SMB expuesto — vector principal de ataques como EternalBlue (MS17-010).",
        "severidad": "CRITICAL",
        "recomendacion": "Aplicar parche MS17-010. Deshabilitar SMBv1. Restringir acceso por firewall.",
        "msf": "exploit/windows/smb/ms17_010_eternalblue",
    },
    {
        "servicio": "smb",
        "puerto": 445,
        "descripcion": "SMB expuesto — vector principal de ataques como EternalBlue (MS17-010).",
        "severidad": "CRITICAL",
        "recomendacion": "Aplicar parche MS17-010. Deshabilitar SMBv1. Restringir acceso por firewall.",
        "msf": "exploit/windows/smb/ms17_010_eternalblue",
    },
    {
        "servicio": "mssql",
        "puerto": 1433,
        "descripcion": "MS SQL Server expuesto — base de datos accesible desde la red.",
        "severidad": "HIGH",
        "recomendacion": "Restringir acceso a IPs autorizadas. Deshabilitar SA si no se usa.",
        "msf": "auxiliary/scanner/mssql/mssql_login",
    },
    {
        "servicio": "mysql",
        "puerto": 3306,
        "descripcion": "MySQL expuesto públicamente — base de datos accesible desde la red.",
        "severidad": "HIGH",
        "recomendacion": "Bind MySQL a localhost (127.0.0.1). Restringir acceso externo.",
        "msf": "auxiliary/scanner/mysql/mysql_login",
    },
    {
        "servicio": "ms-wbt-server",
        "puerto": 3389,
        "descripcion": "RDP expuesto — vector de ataques de fuerza bruta y BlueKeep (CVE-2019-0708).",
        "severidad": "HIGH",
        "recomendacion": "Implementar NLA. Usar VPN para acceso remoto. Aplicar parche BlueKeep.",
        "msf": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
    },
    {
        "servicio": "postgresql",
        "puerto": 5432,
        "descripcion": "PostgreSQL expuesto — base de datos accesible desde la red.",
        "severidad": "HIGH",
        "recomendacion": "Restringir pg_hba.conf a IPs autorizadas. No exponer a internet.",
        "msf": "auxiliary/scanner/postgres/postgres_login",
    },
    {
        "servicio": "vnc",
        "puerto": 5900,
        "descripcion": "VNC expuesto — acceso remoto de escritorio sin cifrado robusto.",
        "severidad": "HIGH",
        "recomendacion": "Deshabilitar VNC. Usar SSH con X11 forwarding o VPN.",
        "msf": "auxiliary/scanner/vnc/vnc_login",
    },
    {
        "servicio": "redis",
        "puerto": 6379,
        "descripcion": "Redis expuesto sin autenticación — acceso directo a la base de datos en memoria.",
        "severidad": "CRITICAL",
        "recomendacion": "Configurar requirepass en redis.conf. Bind a 127.0.0.1.",
        "msf": "auxiliary/scanner/redis/redis_login",
    },
    {
        "servicio": "http-alt",
        "puerto": 8080,
        "descripcion": "Puerto HTTP alternativo expuesto — posible panel de administración.",
        "severidad": "MEDIUM",
        "recomendacion": "Verificar qué servicio usa este puerto. Restringir acceso si es admin.",
        "msf": "auxiliary/scanner/http/http_header",
    },
    {
        "servicio": "mongodb",
        "puerto": 27017,
        "descripcion": "MongoDB expuesto sin autenticación — acceso directo a todas las bases de datos.",
        "severidad": "CRITICAL",
        "recomendacion": "Habilitar autenticación en mongod.conf. Bind a 127.0.0.1.",
        "msf": "auxiliary/scanner/mongodb/mongodb_login",
    },
    {
        "servicio": "snmp",
        "puerto": 161,
        "descripcion": "SNMP v1/v2 expuesto — community string 'public' permite lectura de configuración.",
        "severidad": "MEDIUM",
        "recomendacion": "Migrar a SNMPv3 con autenticación. Cambiar community string.",
        "msf": "auxiliary/scanner/snmp/snmp_enum",
    },
]


class VulnScanner:
    NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, recon_data: dict, nvd_key: str = None):
        self.recon_data = recon_data
        self.nvd_key = nvd_key
        self.cves = []
        self.misconfigs = []

    def scan(self) -> dict:
        for host in self.recon_data.get("hosts", []):
            if host["estado"] != "up":
                continue
            for puerto in host["puertos"]:
                self._check_misconfig(host["ip"], puerto)
                self._fetch_cves(host["ip"], puerto)

        return {"cves": self.cves, "misconfigs": self.misconfigs}

    def _check_misconfig(self, ip: str, puerto: dict):
        port_num = puerto["puerto"]
        servicio = puerto["servicio"].lower()

        for rule in MISCONFIG_RULES:
            match_puerto = rule["puerto"] == port_num
            match_servicio = rule["servicio"] in servicio

            if match_puerto or match_servicio:
                # Evitar duplicados
                ya_existe = any(
                    m["ip"] == ip and m["puerto"] == port_num and m["descripcion"] == rule["descripcion"]
                    for m in self.misconfigs
                )
                if not ya_existe:
                    misconfig = {
                        "ip": ip,
                        "puerto": port_num,
                        "servicio": puerto["servicio"],
                        "descripcion": rule["descripcion"],
                        "severidad": rule["severidad"],
                        "recomendacion": rule["recomendacion"],
                        "msf": rule.get("msf", ""),
                    }
                    self.misconfigs.append(misconfig)
                    sev = rule["severidad"]
                    print(f"  [MISCONFIG {sev}] {ip}:{port_num} — {rule['descripcion'][:60]}...")
                break

    def _fetch_cves(self, ip: str, puerto: dict):
        producto = puerto.get("producto", "").strip()
        version = puerto.get("version", "").strip()

        if not producto:
            return

        keyword = f"{producto} {version}".strip()
        print(f"  [CVE] Buscando CVEs para: {keyword}")

        headers = {}
        if self.nvd_key:
            headers["apiKey"] = self.nvd_key

        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 5,
        }

        try:
            resp = requests.get(self.NVD_URL, params=params, headers=headers, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                for vuln in data.get("vulnerabilities", []):
                    cve_data = vuln.get("cve", {})
                    cve_id = cve_data.get("id", "N/A")
                    descripcion = self._get_description(cve_data)
                    severidad, puntuacion = self._get_severity(cve_data)

                    cve_entry = {
                        "ip": ip,
                        "puerto": puerto["puerto"],
                        "servicio": puerto["servicio"],
                        "producto": keyword,
                        "cve_id": cve_id,
                        "descripcion": descripcion,
                        "severidad": severidad,
                        "puntuacion": puntuacion,
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    }
                    self.cves.append(cve_entry)

                    if severidad in ("CRITICAL", "HIGH"):
                        print(f"    [{severidad}] {cve_id} (score: {puntuacion})")
            elif resp.status_code == 403:
                print("  [!] NVD API: límite de peticiones alcanzado. Usa --nvd-key.")
            else:
                print(f"  [!] NVD API: error {resp.status_code}")
        except requests.exceptions.Timeout:
            print("  [!] Timeout al consultar NVD API.")
        except Exception as e:
            print(f"  [!] Error consultando CVEs: {e}")

        # Rate limit: sin API key, NVD permite 5 req/30s
        time.sleep(1 if self.nvd_key else 6)

    def _get_description(self, cve_data: dict) -> str:
        descriptions = cve_data.get("descriptions", [])
        for d in descriptions:
            if d.get("lang") == "en":
                return d.get("value", "Sin descripción")[:300]
        return "Sin descripción"

    def _get_severity(self, cve_data: dict) -> tuple:
        metrics = cve_data.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m = metrics[key][0]
                cvss = m.get("cvssData", {})
                score = cvss.get("baseScore", 0.0)
                sev = cvss.get("baseSeverity", "")
                if not sev:
                    sev = self._score_to_severity(score)
                return sev.upper(), score
        return "UNKNOWN", 0.0

    def _score_to_severity(self, score: float) -> str:
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0:
            return "LOW"
        return "UNKNOWN"
