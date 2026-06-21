#!/usr/bin/env python3
"""Genera informe DVWA con los hallazgos verificados en la sesion de validacion 12/06/2026"""
import sys
sys.path.insert(0, '/home/nathan/Proyectos/auditoria_pymes')
from modules.report import ReportGenerator
from datetime import datetime

findings = [
    {
        "url": "http://localhost:8080",
        "tipo": "SQL INJECTION",
        "nombre": "SQL Injection (error-based) en /vulnerabilities/sqli/ campo 'id'",
        "descripcion": (
            "El campo 'id' del formulario en /vulnerabilities/sqli/ es vulnerable a "
            "inyeccion SQL error-based. Payload ' devuelve error MySQL visible en la "
            "respuesta: 'You have an error in your SQL syntax'.\n"
            "Un atacante puede leer, modificar o eliminar toda la base de datos, "
            "incluyendo datos de usuarios y contrasenas."
        ),
        "severidad": "CRITICAL",
        "recomendacion": "Usar consultas preparadas (prepared statements). Nunca concatenar variables de usuario en SQL.",
    },
    {
        "url": "http://localhost:8080",
        "tipo": "SQL INJECTION",
        "nombre": "SQL Injection (error-based) en /vulnerabilities/brute/ campo 'username'",
        "descripcion": (
            "El campo 'username' del formulario de fuerza bruta es vulnerable a SQLi. "
            "Payload ' devuelve error MySQL. Un atacante puede bypassear la autenticacion "
            "con payload ' OR '1'='1'-- y acceder sin contrasena."
        ),
        "severidad": "CRITICAL",
        "recomendacion": "Usar prepared statements. Validar y escapar todas las entradas de usuario.",
    },
    {
        "url": "http://localhost:8080",
        "tipo": "XSS REFLEJADO",
        "nombre": "XSS reflejado en /vulnerabilities/xss_r/ campo 'name'",
        "descripcion": (
            "El campo 'name' devuelve el payload <script>alert(1)</script> sin sanitizar. "
            "Un atacante puede enviar un enlace malicioso a un usuario autenticado y "
            "robar su cookie de sesion o redirigirle a una pagina de phishing."
        ),
        "severidad": "HIGH",
        "recomendacion": "Sanitizar con htmlspecialchars(). Configurar Content-Security-Policy.",
    },
    {
        "url": "http://localhost:8080",
        "tipo": "XSS REFLEJADO",
        "nombre": "XSS reflejado en /vulnerabilities/sqli/ campo 'id'",
        "descripcion": (
            "El campo 'id' tambien refleja payloads XSS. Al ser un campo SQLi, "
            "la combinacion permite ataques encadenados SQLi+XSS."
        ),
        "severidad": "HIGH",
        "recomendacion": "Sanitizar y escapar todas las entradas antes de mostrarlas en HTML.",
    },
    {
        "url": "http://localhost:8080",
        "tipo": "LFI — LOCAL FILE INCLUSION",
        "nombre": "LFI en parametro 'page' — /vulnerabilities/fi/",
        "descripcion": (
            "El parametro 'page' permite incluir archivos del servidor. "
            "Con payload ../../../../etc/passwd se obtuvo contenido del archivo de usuarios "
            "del sistema (firma: 'root:x:0:0'). "
            "Un atacante puede leer archivos de configuracion, credenciales y codigo fuente."
        ),
        "severidad": "CRITICAL",
        "recomendacion": (
            "Validar y restringir los valores permitidos. Nunca usar entrada del usuario "
            "directamente en funciones include/require. Usar lista blanca de archivos permitidos."
        ),
    },
    {
        "url": "http://localhost:8080",
        "tipo": "COMMAND INJECTION",
        "nombre": "Inyeccion de comandos OS en /vulnerabilities/exec/ campo 'ip'",
        "descripcion": (
            "El campo 'ip' ejecuta el valor directamente como parte de un comando shell. "
            "Con payload '127.0.0.1; sleep 4' se obtuvo un retraso de 7.0 segundos, "
            "confirmando ejecucion de codigo arbitrario en el servidor. "
            "Un atacante puede obtener shell remoto, exfiltrar datos o instalar malware."
        ),
        "severidad": "CRITICAL",
        "recomendacion": (
            "Nunca ejecutar comandos del sistema con entrada del usuario. "
            "Si es imprescindible, usar lista blanca estricta de valores permitidos "
            "y escapado con escapeshellarg()."
        ),
    },
]

resultado = {
    "target": "localhost:8080 (DVWA)",
    "empresa": "DVWA Lab — Validacion AuditPyme v1.0",
    "auditor": "",
    "fecha_inicio": "12/06/2026 20:00",
    "fecha_fin": "12/06/2026 23:59",
    "hallazgos": findings,
    "webapp": findings,
}

rg = ReportGenerator(resultado)
rg.generate("informes/dvwa_validacion_final")
print(f"Informe generado con {len(findings)} hallazgos")
print("  -> informes/dvwa_validacion_final.html")
print("  -> informes/dvwa_validacion_final.pdf")
