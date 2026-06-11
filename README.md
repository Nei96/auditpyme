# AuditPyme

Herramienta profesional de auditoría de ciberseguridad para pymes. Genera informes en lenguaje de negocio (HTML + PDF) con solo los hallazgos que tienen impacto real.

## Módulos

| Módulo | Qué analiza |
|--------|-------------|
| OSINT | crt.sh, WHOIS, Shodan, HIBP, puertos expuestos, detección CDN |
| Email | SPF, DKIM (25 selectores), DMARC, MTA-STS |
| Reconocimiento | nmap, detección de OS (requiere root) |
| Vulnerabilidades | CVEs via NVD API + malas configuraciones |
| Web | Cabeceras de seguridad, rutas sensibles |
| SSL/TLS | Versiones débiles, certificado, expiración |
| DNS | Transferencia de zona, subdominios |
| Credenciales | Credenciales por defecto en servicios comunes |
| WebApp OWASP | SQLi, XSS, LFI, Open Redirect, CMDi, CSRF, IDOR |
| WiFi | WEP/WPS/PMF/Rogue AP/Evil Twin, escaneo red local |
| Informe | HTML + PDF, impacto en negocio, sección LOPDGDD |

## Uso

```bash
# Demo gratuita — solo OSINT y email, no toca la red del cliente
python3 main.py empresa.com --empresa "Nombre Empresa" --perfil externo -o informes/empresa

# Auditoría completa
sudo python3 main.py empresa.com --empresa "Nombre Empresa" -o informes/empresa

# Solo algunos checks OWASP
sudo python3 main.py empresa.com --webapp-checks sqli,xss -o informes/empresa
```

## Perfiles

| Perfil | Descripción |
|--------|-------------|
| `externo` | OSINT + email — sin tocar la red (demo gratuita) |
| `rapido` | Recon + email + OSINT |
| `completo` | Todo (por defecto) |

## APIs opcionales

```bash
--shodan-key TU_KEY   # Servicios indexados por internet
--hibp-key TU_KEY     # Filtraciones de emails del dominio
--nvd-key TU_KEY      # Búsqueda de CVEs más rápida
```

## Docker

```bash
# Build
sudo docker build -t auditpyme:1.0 .

# Perfil externo
sudo docker run --rm -v ~/informes:/informes \
  auditpyme:1.0 empresa.com --empresa "Nombre" --perfil externo -o /informes/empresa

# Auditoría completa
sudo docker run --rm --cap-add NET_RAW --cap-add NET_ADMIN --network host \
  -v ~/informes:/informes \
  auditpyme:1.0 empresa.com --empresa "Nombre" -o /informes/empresa
```

## Instalación local

```bash
git clone https://github.com/Nei96/auditpyme.git
cd auditpyme
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

## Requisitos

- Python 3.8+
- nmap
- Para WiFi (opcional): airmon-ng, scapy, wash, arp-scan
