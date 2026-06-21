# AuditPyme — Notas del proyecto
**Auditor:** Nathan Matos Paes  
**Ubicación:** Las Palmas de Gran Canaria  
**Objetivo:** Herramienta de auditoría de ciberseguridad para pymes, vendible como producto profesional.

---

## Lo que se ha construido

### Módulos activos
| Módulo | Archivo | Qué hace |
|---|---|---|
| OSINT externo | `modules/osint.py` | crt.sh, WHOIS, Shodan (opcional), HIBP (opcional), puertos expuestos, detección CDN |
| Seguridad email | `modules/email_sec.py` | SPF, DKIM (25 selectores), DMARC, MTA-STS |
| Reconocimiento | `modules/recon.py` | nmap sin root (sin -O), con root detecta OS |
| Vulnerabilidades | `modules/vulns.py` | CVEs via NVD API + malas configuraciones |
| Web | `modules/web.py` | Cabeceras seguridad, rutas sensibles, detección falsos positivos CDN |
| SSL/TLS | `modules/ssl_check.py` | Versiones débiles, certificado, expiración, mismatch |
| DNS | `modules/dns_enum.py` | Transferencia de zona, SPF/DMARC, subdominios |
| Credenciales | `modules/credentials.py` | Credenciales por defecto en servicios comunes |
| WebApp OWASP | `modules/webapp.py` | SQLi, XSS, LFI, Open Redirect, CMDi, CSRF, IDOR |
| WiFi | `modules/wifi.py` | Escaneo redes (Scapy/nmcli/iw), detección WEP/WPS/PMF/Rogue AP/Evil Twin; red local ARP+puertos; monitor mode context manager |
| Informe | `modules/report.py` | HTML + PDF, impacto real en lenguaje de negocio, LOPDGDD |

### Perfiles de escaneo
```bash
--perfil externo   # Solo OSINT y email — no toca la red del cliente (para demos gratuitas)
--perfil rapido    # Recon + email + OSINT (sin credenciales)
--perfil completo  # Todo (por defecto)
```

### Checks OWASP disponibles
```bash
--webapp-checks sqli,xss,lfi,redirect,cmdi,csrf,idor
--skip-webapp   # Si el cliente no contrata este módulo
```

### Informe
- Genera **HTML + PDF** automáticamente
- Sección **"Impacto real"** en lenguaje de negocio (no jerga técnica)
- Solo muestra **CRÍTICOS y ALTOS** en recomendaciones — sin ruido
- Sección **LOPDGDD/RGPD** con evaluación orientativa
- Auditor por defecto: Nathan Matos Paes

---

## Cómo ejecutar

### Sin Docker (desarrollo)
```bash
cd ~/Proyectos/auditoria_pymes

# Perfil externo (demo gratuita, no toca la red)
python3 main.py empresa.com --empresa "Nombre Empresa" --perfil externo -o informes/empresa

# Auditoría completa
sudo python3 main.py empresa.com --empresa "Nombre Empresa" -o informes/empresa

# Solo algunos checks OWASP
sudo python3 main.py empresa.com --webapp-checks sqli,xss -o informes/empresa
```

### Con Docker (producción / en casa del cliente)
```bash
# Build (solo la primera vez o tras cambios)
sudo docker build -t auditpyme:1.0 ~/Proyectos/auditoria_pymes/

# Perfil externo
sudo docker run --rm -v ~/Proyectos/auditoria_pymes/informes:/informes \
  auditpyme:1.0 empresa.com --empresa "Nombre" --perfil externo -o /informes/empresa

# Auditoría completa (con detección de OS)
sudo docker run --rm --cap-add NET_RAW --cap-add NET_ADMIN --network host \
  -v ~/Proyectos/auditoria_pymes/informes:/informes \
  auditpyme:1.0 empresa.com --empresa "Nombre" -o /informes/empresa
```

### APIs opcionales que mejoran los resultados
```bash
--shodan-key TU_KEY    # Shodan: ver qué servicios indexa internet del objetivo
--hibp-key TU_KEY      # HaveIBeenPwned: filtraciones de emails del dominio
--nvd-key TU_KEY       # NVD: búsqueda de CVEs más rápida
```

---

## Dictado por voz (nerd-dictation)
```bash
voz      # Iniciar dictado (alias en ~/.bashrc)
vozstop  # Parar dictado
# Si los alias no funcionan:
cd ~/nerd-dictation && ./nerd-dictation begin --vosk-model-dir=./model &
cd ~/nerd-dictation && ./nerd-dictation end
```

---

## Decisiones tomadas durante el desarrollo

### Filosofía del producto
- **No inflar el informe** — solo hallazgos con impacto real en el negocio
- **Lenguaje de negocio** — el dueño de la empresa debe entender el informe sin ser técnico
- **Impacto en 4 categorías**: dinero, datos, reputación, operación
- Si un hallazgo no toca ninguna de las 4 → no va en el informe principal

### Lecciones aprendidas en pruebas reales
- **Cloudflare devuelve HTTP 200** en rutas que no existen → implementado `_is_cdn_error()` para filtrar falsos positivos
- **Puertos 8080/8443** detrás de Cloudflare son LOW, no MEDIUM → implementado `_detect_cdn()`
- **Gmail bloquea spoofing** desde IPs sin PTR record → desde VPS sí funcionaría
- **nmap -O requiere root** → implementado fallback sin detección de OS si no hay root
- **webapp.py — 3 bugs corregidos el 12/06/2026** (validación DVWA):
  1. El crawler visitaba `/logout.php` → cerraba sesión antes de los checks → 0 detecciones
  2. Botones Submit se filtraban del request → PHP no procesaba el formulario → SQLi/XSS/CMDi no disparaban
  3. `method="post"` se buscaba en el body del form, no en el tag → forms POST se enviaban como GET
- **DVWA no representa a un cliente real** — sin WAF, sin WordPress, sin Cloudflare. Los bugs corregidos son más relevantes para clientes con PHP custom, PrestaShop o Joomla sin CDN.

### Dominios verificados como prueba
- `gohomephysio.es` — propiedad de Nathan, sin email configurado, Cloudflare
- `customseda.com` — DMARC en p=none (mal configurado), sin SPF ni DKIM
- `scanme.nmap.org` — servidor oficial nmap autorizado para escaneos

---

## Roadmap pendiente
- [x] Módulo WiFi (seguridad inalámbrica — del curso BAG)
- [x] Logo y marca propia en el informe PDF (escudo SVG "AP" inline en report.py)
- [x] Laboratorio DVWA/WebGoat en docker-compose (dvwa:8080, webgoat:8888)
- [x] Validar webapp.py contra DVWA — 6/6 hallazgos detectados (SQLi×2, XSS×2, LFI, CMDi)
- [x] Comparativa histórica entre auditorías del mismo cliente (17/06/2026)
- [ ] Módulo Active Directory / LDAP (para mediana empresa)
- [ ] Registrar `auditpyme.es` para demo de spoofing
- [ ] Dashboard web multi-cliente (fase avanzada)

---

## Comparativa histórica (17/06/2026)

**Cómo funciona:**
- Cada auditoría ahora guarda automáticamente `<output>_results.json` con todos los datos crudos
- `comparar.py` carga 2+ JSONs y genera un informe HTML+PDF de evolución

**Uso:**
```bash
# Comparar dos auditorías del mismo cliente
python3 comparar.py informes/cliente_20260601_results.json informes/cliente_20260617_results.json

# Comparar serie histórica (3+)
python3 comparar.py aud_enero.json aud_marzo.json aud_junio.json -o informes/evolucion_cliente

# Solo HTML sin PDF
python3 comparar.py aud1.json aud2.json --no-pdf
```

**Qué muestra el informe:**
- Tarjetas resumen de cada auditoría (críticos/altos/medios/bajos/accesos)
- Puntuación de riesgo 0-100 con barra de evolución y delta entre auditorías
- Vulnerabilidades **nuevas** (aparecieron) — rojo
- Vulnerabilidades **resueltas** (desaparecieron) — verde
- Hallazgos que **empeoraron** de severidad — rojo oscuro
- Hallazgos que **mejoraron** de severidad — amarillo
- Hallazgos **persistentes** (sin resolver en varias auditorías) — naranja
- Conclusión automática: mejorado / estable / empeorado con justificación

**Identificación de hallazgos:** por clave `tipo::nombre` — robusto ante pequeños cambios de descripción.

---

## Estrategia de ventas acordada
1. **Demo gratuita** con `--perfil externo` — escaneo de OSINT y email sin tocar la red
2. **Informe de muestra** listo: `informes/muestra_gestoria_lopez.pdf`
3. **Primera auditoría** a precio simbólico (100-200€) a cambio de referencia
4. **Precio objetivo**: 500-1.500€/auditoría pyme, 2.000-5.000€ mediana empresa
5. **Canales**: Cámara de Comercio Las Palmas, Clúster TIC Canarias, colegios profesionales

---

## Estructura de carpetas
```
~/Proyectos/
  auditoria_pymes/    ← AuditPyme (este proyecto)
  bvbot/              ← Bot predicciones vóley playa
  sentinel_ndvi/      ← Proyecto NDVI La Palma (TFG)

~/Expedientes/
  Voley_Playa/        ← Expediente TAD + Orihuela

~/Documentos/
  TFG/                ← Borradores TFG
  Curso Especialización Cyberseguridad/  ← Apuntes del curso (BAG, HAJ, HIC, NOB, PUK)
```
