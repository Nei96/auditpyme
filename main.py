#!/usr/bin/env python3
"""
AuditPyme v1.0 — Herramienta de auditoría de ciberseguridad para pymes.
Uso: sudo python3 main.py <target> [opciones]
"""

import argparse
import sys
import os
import json
from datetime import datetime

from modules.recon import Recon
from modules.vulns import VulnScanner
from modules.credentials import CredChecker
from modules.web import WebAnalyzer
from modules.ssl_check import SSLChecker
from modules.dns_enum import DNSEnumerator
from modules.email_sec import EmailSecChecker
from modules.osint import OSINTScanner
from modules.webapp import WebAppScanner
from modules.wifi import WiFiAuditor, RedLocalAuditor
from modules.cms import CMSDetector
from modules.auth import AuthAuditor
from modules.jsanalysis import JSAnalyzer
from modules.graphql import GraphQLAuditor
from modules.fileupload import FileUploadAuditor
from modules.business_logic import BusinessLogicAuditor
from modules.discovery import SiteDiscovery
from modules.active_directory import ActiveDirectoryAuditor
from modules.ssti import SSTIScanner
from modules.jwt_audit import JWTAuditor
from modules.injection import InjectionScanner
from modules.exposed import ExposedScanner
from modules.wp_exploit import WordPressExploiter
from modules.api import APIScanner
from modules.subdomain_takeover import SubdomainTakeoverScanner
from modules.cloud_storage import CloudStorageScanner
from modules.deserialization import DeserializationScanner
from modules.race_condition import RaceConditionScanner
from modules.smuggling import SmugglingScanner
from modules.websocket import WebSocketScanner
from modules.supply_chain import SupplyChainScanner
from modules.report import ReportGenerator

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║                  A U D I T P Y M E   v 1 . 0                ║
║         Auditoría de ciberseguridad para empresas            ║
║                                                              ║
║  Módulos: Recon · CVE · Web · SSL · DNS · Email · OSINT · WiFi ║
║                                                              ║
║  AVISO LEGAL: Solo para uso en entornos autorizados.         ║
║  El escaneo sin autorización escrita es ilegal.              ║
╚══════════════════════════════════════════════════════════════╝
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="AuditPyme — Auditoría de ciberseguridad para empresas",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "target",
        help="IP, hostname o rango CIDR\nEjemplos:\n  192.168.1.1\n  empresa.com\n  192.168.1.0/24"
    )
    parser.add_argument("-o", "--output", default=None,
                        help="Archivo de salida (sin extensión — se generan .html y .pdf)")
    parser.add_argument("--nvd-key", default=None,
                        help="API key de NVD para búsqueda de CVEs")
    parser.add_argument("--shodan-key", default=None,
                        help="API key de Shodan para OSINT")
    parser.add_argument("--hibp-key", default=None,
                        help="API key de HaveIBeenPwned para detección de filtraciones")
    parser.add_argument("--ports",
                        default="1-1024,3306,3389,5432,5900,6379,8080,8443,8888,27017",
                        help="Puertos a escanear (por defecto: top 1024 + servicios comunes)")
    parser.add_argument("--empresa", default="", help="Nombre de la empresa auditada")
    parser.add_argument("--auditor", default="", help="Nombre del auditor (aparece en el informe)")
    parser.add_argument("--perfil", default="completo",
                        choices=["externo", "rapido", "completo"],
                        help=(
                            "externo  — solo OSINT y email (sin acceso a la red)\n"
                            "rapido   — recon + email + OSINT (sin credenciales)\n"
                            "completo — todas las fases (por defecto)"
                        ))
    parser.add_argument("--skip-creds",  action="store_true")
    parser.add_argument("--skip-web",    action="store_true")
    parser.add_argument("--skip-ssl",    action="store_true")
    parser.add_argument("--skip-dns",    action="store_true")
    parser.add_argument("--skip-email",  action="store_true")
    parser.add_argument("--skip-osint",  action="store_true")
    parser.add_argument("--skip-webapp", action="store_true",
                        help="Omitir análisis de vulnerabilidades web (OWASP)")
    parser.add_argument("--skip-wifi",  action="store_true",
                        help="Omitir auditoría de redes WiFi")
    parser.add_argument("--wifi-iface", default=None,
                        help="Interfaz WiFi a usar (por defecto: autodetección)")
    parser.add_argument("--wifi-red-local", action="store_true",
                        help="Escanear la red local desde una WiFi abierta del cliente\n"
                             "(ejecutar conectado a la WiFi del cliente)")
    parser.add_argument("--wifi-subred", default=None,
                        help="Subred a escanear en modo red-local (ej: 192.168.1.0/24)\n"
                             "Por defecto: autodetección desde la interfaz WiFi")
    parser.add_argument("--webapp-checks", default="sqli,xss,lfi,redirect,cmdi,csrf,idor,ssrf,xxe",
                        help="Checks OWASP a ejecutar (separados por coma)\n"
                             "Disponibles: sqli, xss, lfi, redirect, cmdi, csrf, idor, ssrf, xxe")
    parser.add_argument("--no-pdf",      action="store_true",
                        help="No generar PDF, solo HTML")
    parser.add_argument("--stealth", action="store_true",
                        help="Modo sigiloso: nmap T2 + scan-delay 1s, pausas entre peticiones web")
    parser.add_argument("--webapp-url", default=None,
                        help="URL base para el análisis OWASP (ej: http://localhost:8888/WebGoat/)\n"
                             "Por defecto: se infiere de los puertos web detectados por nmap")
    parser.add_argument("--webapp-user", default=None, help="Usuario para autenticación en la webapp")
    parser.add_argument("--webapp-pass", default=None, help="Contraseña para autenticación en la webapp")
    parser.add_argument("--webapp-login-url", default=None, help="URL del formulario de login (si es distinta a /login)")
    parser.add_argument("--skip-js",        action="store_true", help="Omitir análisis de JavaScript")
    parser.add_argument("--skip-graphql",   action="store_true", help="Omitir auditoría GraphQL")
    parser.add_argument("--skip-fileupload",action="store_true", help="Omitir análisis de subida de archivos")
    parser.add_argument("--skip-bizlogic",  action="store_true", help="Omitir análisis de lógica de negocio")
    parser.add_argument("--skip-auth",      action="store_true", help="Omitir auditoría de autenticación")
    parser.add_argument("--skip-ssti",      action="store_true", help="Omitir detección de SSTI")
    parser.add_argument("--skip-jwt",       action="store_true", help="Omitir auditoría JWT")
    parser.add_argument("--skip-injection", action="store_true",
                        help="Omitir inyecciones avanzadas (NoSQL, LDAP, XPath, CRLF, HPP)")
    parser.add_argument("--skip-exposed",   action="store_true",
                        help="Omitir búsqueda de paneles expuestos y archivos sensibles")
    parser.add_argument("--skip-wp-exploit", action="store_true",
                        help="Omitir explotación profunda WordPress (git dump, multicall brute, brute force)")
    parser.add_argument("--skip-api",     action="store_true",
                        help="Omitir auditoría profunda de API REST (BOLA, mass assignment, BFLA)")
    parser.add_argument("--skip-subdomain-takeover", action="store_true",
                        help="Omitir detección de subdomain takeover")
    parser.add_argument("--skip-cloud",     action="store_true",
                        help="Omitir búsqueda de buckets cloud mal configurados (S3, Azure, GCP)")
    parser.add_argument("--skip-deserialization", action="store_true",
                        help="Omitir detección de deserialización insegura (PHP, Java, Pickle)")
    parser.add_argument("--skip-race",      action="store_true",
                        help="Omitir detección de race conditions (TOCTOU, double-spend)")
    parser.add_argument("--skip-smuggling", action="store_true",
                        help="Omitir detección de HTTP Request Smuggling (CL.TE, TE.CL)")
    parser.add_argument("--skip-websocket", action="store_true",
                        help="Omitir auditoría de WebSockets (Origin, auth, inyección)")
    parser.add_argument("--skip-supply-chain", action="store_true",
                        help="Omitir detección de dependency confusion y supply chain")
    parser.add_argument("--skip-cms",       action="store_true", help="Omitir fingerprinting de CMS")
    parser.add_argument("--skip-ad",        action="store_true", help="Omitir auditoría Active Directory / LDAP")
    parser.add_argument("--ad-user",   default=None, help="Usuario de dominio para auditoría AD (ej: jperez)")
    parser.add_argument("--ad-pass",   default=None, help="Contraseña del usuario de dominio")
    parser.add_argument("--ad-domain", default=None, help="Nombre de dominio AD (ej: empresa.local)")
    parser.add_argument("--skip-discovery", action="store_true",
                        help="Omitir descubrimiento inteligente (deshabilita el auto-skip de módulos)")
    parser.add_argument("--force-all", action="store_true",
                        help="Forzar todos los módulos aunque discovery no los detecte")
    return parser.parse_args()


def print_phase(n, name: str):
    print(f"\n{'='*64}")
    print(f"  FASE {n}: {name.upper()}")
    print(f"{'='*64}")


def check_root():
    if os.geteuid() != 0:
        print("[!] AVISO: Sin permisos de root. La detección de OS estará limitada.")
        print("    Recomendamos ejecutar con: sudo python3 main.py <target>\n")


def apply_profile(args):
    if args.perfil == "externo":
        args.skip_web = True
        args.skip_ssl = True
        args.skip_dns = True
        args.skip_creds = True
        print("[*] Perfil EXTERNO: solo OSINT y email (sin acceso a la red del cliente)")
    elif args.perfil == "rapido":
        args.skip_creds = True
        print("[*] Perfil RÁPIDO: recon + email + OSINT (sin credenciales)")


def _build_webapp_targets(target: str, recon: dict) -> list:
    """Construye URLs web desde los puertos HTTP detectados por nmap."""
    urls = []
    for host in recon.get("hosts", []):
        if host["estado"] != "up":
            continue
        for p in host["puertos"]:
            port = p["puerto"]
            svc = p["servicio"].lower()
            if "http" in svc or port in (80, 443, 8080, 8443, 8888):
                proto = "https" if port in (443, 8443) else "http"
                base = target
                url = f"{proto}://{base}:{port}" if port not in (80, 443) else f"{proto}://{base}"
                if url not in urls:
                    urls.append(url)
    return urls or [target]


def _apply_autoskip(args, profile: dict):
    """Auto-omite módulos que no tienen sentido según el perfil del sitio."""
    skipped = []

    # JS: solo vale la pena si hay archivos JS
    if not args.skip_js and profile.get("js_files_count", 0) == 0:
        args.skip_js = True
        skipped.append("JS (sin archivos JS detectados)")

    # GraphQL: solo si existe endpoint
    if not args.skip_graphql and not profile.get("has_graphql"):
        args.skip_graphql = True
        skipped.append("GraphQL (sin endpoint detectado)")

    # File Upload: solo si hay formulario de subida
    if not args.skip_fileupload and not profile.get("has_file_upload"):
        args.skip_fileupload = True
        skipped.append("File Upload (sin formulario de subida)")

    # Lógica de negocio: solo si hay e-commerce
    if not args.skip_bizlogic and not profile.get("has_ecommerce"):
        args.skip_bizlogic = True
        skipped.append("Lógica de negocio (sin e-commerce detectado)")

    # Autenticación: solo si hay login
    if not args.skip_auth and not profile.get("has_login"):
        args.skip_auth = True
        skipped.append("Auth (sin formulario de login detectado)")

    if skipped:
        print(f"\n  [AUTO-SKIP] Módulos omitidos por no ser relevantes para este sitio:")
        for s in skipped:
            print(f"    · {s}")
    else:
        print("  [*] Todos los módulos son relevantes para este sitio")


def main():
    print(BANNER)
    args = parse_args()
    apply_profile(args)
    check_root()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = args.output or f"auditpyme_{timestamp}"
    base_name = base_name.replace(".html", "").replace(".pdf", "")

    results = {
        "target":       args.target,
        "empresa":      args.empresa,
        "auditor":      args.auditor,
        "fecha_inicio": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        "perfil":       args.perfil,
        "recon":        None,
        "vulns":        [],
        "misconfigs":   [],
        "creds":        [],
        "web":          [],
        "ssl":          [],
        "dns":          [],
        "email":        [],
        "osint":        [],
        "webapp":       [],
        "wifi":         [],
        "ad":           [],
        "cms":          [],
        "auth":         [],
        "js":           [],
        "graphql":      [],
        "fileupload":   [],
        "bizlogic":     [],
        "ssti":         [],
        "jwt":          [],
        "injection":             [],
        "exposed":               [],
        "wp_exploit":            [],
        "api":                   [],
        "subdomain_takeover":    [],
        "cloud_storage":         [],
        "deserialization":       [],
        "race_condition":        [],
        "smuggling":             [],
        "websocket":             [],
        "supply_chain":          [],
    }

    # ── FASE 0: OSINT externo ─────────────────────────────────────────────────
    if not args.skip_osint:
        print_phase("0", "OSINT externo — información pública")
        osint = OSINTScanner(args.target, shodan_key=args.shodan_key, hibp_key=args.hibp_key)
        results["osint"] = osint.scan()
        print(f"\n[+] Hallazgos OSINT: {len([f for f in results['osint'] if f.get('severidad') != 'INFO'])}")
    else:
        print("\n[*] OSINT omitido (--skip-osint)")

    # ── FASE 0b: Seguridad de email ───────────────────────────────────────────
    if not args.skip_email:
        print_phase("0b", "Seguridad de email — SPF · DKIM · DMARC · MTA-STS")
        email_checker = EmailSecChecker(args.target)
        results["email"] = email_checker.check()
        print(f"\n[+] Hallazgos email: {len([f for f in results['email'] if f.get('severidad') != 'INFO'])}")
    else:
        print("\n[*] Análisis de email omitido (--skip-email)")

    # ── Fases de red ──────────────────────────────────────────────────────────
    if args.perfil != "externo":

        print_phase(1, "Reconocimiento — nmap")
        recon = Recon(args.target, ports=args.ports, stealth=args.stealth)
        results["recon"] = recon.scan()

        if not results["recon"]["hosts"] and args.perfil == "completo":
            print("\n[-] No se encontraron hosts activos.")
            sys.exit(1)

        hosts_up = len([h for h in results["recon"]["hosts"] if h["estado"] == "up"])
        print(f"\n[+] Hosts activos: {hosts_up} | Puertos: {results['recon']['total_puertos']}")

        print_phase(2, "Vulnerabilidades — CVEs y configuraciones")
        vuln_scanner = VulnScanner(results["recon"], nvd_key=args.nvd_key)
        vuln_results = vuln_scanner.scan()
        results["vulns"]      = vuln_results["cves"]
        results["misconfigs"] = vuln_results["misconfigs"]
        print(f"\n[+] CVEs: {len(results['vulns'])} | Configuraciones: {len(results['misconfigs'])}")

        # ── FASE 2a: Descubrimiento inteligente ──────────────────────────────────
        site_profile = {}
        if not args.skip_discovery:
            print_phase("2a", "Descubrimiento de sitio — funcionalidades y tecnologías")
            discovery = SiteDiscovery(args.target, results["recon"])
            site_profile = discovery.discover()
            results["profile"] = site_profile

            if not args.force_all:
                _apply_autoskip(args, site_profile)
        else:
            print("\n[*] Descubrimiento omitido (--skip-discovery)")

        if not args.skip_web:
            print_phase("2b", "Análisis web")
            results["web"] = WebAnalyzer(args.target, results["recon"], stealth=args.stealth).analyze()
            print(f"\n[+] Hallazgos web: {len(results['web'])}")

        if not args.skip_exposed:
            print_phase("2a2", "Paneles expuestos y archivos sensibles — phpMyAdmin · Adminer · .env · backups")
            exp = ExposedScanner(args.target, results["recon"], stealth=args.stealth)
            results["exposed"] = exp.scan()
            criticos_exp = len([f for f in results["exposed"] if f.get("severidad") in ("CRITICAL", "HIGH")])
            print(f"\n[+] Paneles/archivos sensibles críticos/altos: {criticos_exp}")

        if not args.skip_cms:
            print_phase("2b2", "Fingerprinting CMS — WordPress · Joomla · PrestaShop · Laravel")
            cms_detector = CMSDetector(args.target, results["recon"])
            results["cms"] = cms_detector.scan()
            print(f"\n[+] Hallazgos CMS: {len([f for f in results['cms'] if f.get('severidad') in ('CRITICAL','HIGH')])}")

        if not args.skip_ssl:
            print_phase("2c", "Análisis SSL/TLS")
            results["ssl"] = SSLChecker(args.target, results["recon"]).check()
            print(f"\n[+] Problemas SSL: {len([s for s in results['ssl'] if s.get('severidad') != 'INFO'])}")

        if not args.skip_dns:
            print_phase("2d", "Enumeración DNS")
            results["dns"] = DNSEnumerator(args.target).enumerate()
            print(f"\n[+] Hallazgos DNS: {len([d for d in results['dns'] if d.get('severidad') != 'INFO'])}")

        if not args.skip_creds:
            print_phase(3, "Credenciales por defecto")
            results["creds"] = CredChecker(args.target, results["recon"]).check()
            print(f"\n[+] Accesos obtenidos: {len([c for c in results['creds'] if c['acceso']])}")

        if not args.skip_wifi:
            print_phase("3c", "Auditoría WiFi — redes inalámbricas")
            wifi = WiFiAuditor(empresa=args.empresa, iface=args.wifi_iface)
            results["wifi"] = wifi.scan()
            criticos_wifi = len([f for f in results["wifi"] if f.get("severidad") in ("CRITICAL", "HIGH")])
            print(f"\n[+] Hallazgos WiFi críticos/altos: {criticos_wifi}")

        if args.wifi_red_local:
            print_phase("3d", "Red local WiFi — visibilidad desde red abierta")
            red_local = RedLocalAuditor(iface=args.wifi_iface, subred=args.wifi_subred)
            rl_result  = red_local.scan()
            results["wifi"] += rl_result["findings"]
            # Fusionar hosts descubiertos con creds para que CredChecker los analice
            if not args.skip_creds and rl_result["recon"]["hosts"]:
                print_phase("3e", "Credenciales en red local WiFi")
                creds_local = CredChecker("red-local", rl_result["recon"]).check()
                results["creds"] += creds_local
                accesos = len([c for c in creds_local if c["acceso"]])
                print(f"\n[+] Accesos obtenidos en red local: {accesos}")

        if not args.skip_js:
            print_phase("2b3", "Análisis JavaScript — secretos, API keys, source maps")
            js_analyzer = JSAnalyzer(args.target, results["recon"])
            results["js"] = js_analyzer.scan()
            print(f"\n[+] Hallazgos JS críticos/altos: {len([f for f in results['js'] if f.get('severidad') in ('CRITICAL','HIGH')])}")

        if not args.skip_graphql:
            print_phase("2b4", "Auditoría GraphQL — introspección, auth, profundidad")
            gql = GraphQLAuditor(args.target, results["recon"])
            results["graphql"] = gql.scan()
            print(f"\n[+] Hallazgos GraphQL: {len([f for f in results['graphql'] if f.get('severidad') in ('CRITICAL','HIGH')])}")

        if not args.skip_fileupload:
            print_phase("2b5", "Subida de archivos — bypass extensión, RCE, Zip Slip")
            fu = FileUploadAuditor(args.target, results["recon"], stealth=args.stealth)
            results["fileupload"] = fu.scan()
            print(f"\n[+] Hallazgos subida de archivos: {len([f for f in results['fileupload'] if f.get('severidad') in ('CRITICAL','HIGH')])}")

        if not args.skip_bizlogic:
            print_phase("2b6", "Lógica de negocio — precios, cupones, CORS, mass assignment")
            biz = BusinessLogicAuditor(args.target, results["recon"], stealth=args.stealth)
            results["bizlogic"] = biz.scan()
            print(f"\n[+] Hallazgos lógica de negocio: {len([f for f in results['bizlogic'] if f.get('severidad') in ('CRITICAL','HIGH')])}")

        if not args.skip_wp_exploit:
            print_phase("2b9", "Explotación WordPress — git dump · xmlrpc multicall · brute force dirigido")
            wp_exp = WordPressExploiter(args.target, results["recon"], stealth=args.stealth)
            results["wp_exploit"] = wp_exp.scan()
            print(f"\n[+] Hallazgos WP exploit: {len([f for f in results['wp_exploit'] if f.get('severidad') == 'CRITICAL'])}")

        if not args.skip_api:
            print_phase("2b10", "Auditoría API REST — BOLA · Mass Assignment · BFLA · Versioning")
            api = APIScanner(args.target, results["recon"],
                             auth_user=args.webapp_user, auth_pass=args.webapp_pass,
                             auth_url=args.webapp_login_url, stealth=args.stealth)
            results["api"] = api.scan()
            print(f"\n[+] Hallazgos API: {len([f for f in results['api'] if f.get('severidad') in ('CRITICAL','HIGH')])}")

        if not args.skip_ssti:
            print_phase("2b7", "SSTI — Server-Side Template Injection")
            ssti = SSTIScanner(args.target, results["recon"], stealth=args.stealth)
            results["ssti"] = ssti.scan()
            print(f"\n[+] Hallazgos SSTI: {len([f for f in results['ssti'] if f.get('severidad') in ('CRITICAL','HIGH')])}")

        if not args.skip_injection:
            print_phase("2b8", "Inyecciones avanzadas — NoSQL · LDAP · XPath · CRLF · HPP")
            inj = InjectionScanner(args.target, results["recon"], stealth=args.stealth)
            results["injection"] = inj.scan()
            criticos_inj = len([f for f in results["injection"] if f.get("severidad") in ("CRITICAL", "HIGH")])
            print(f"\n[+] Hallazgos inyecciones avanzadas: {criticos_inj}")

        if not args.skip_auth:
            print_phase("3a", "Auditoría de autenticación — bypass, fuerza bruta, sesión, password reset")
            auth = AuthAuditor(args.target, results["recon"], stealth=args.stealth)
            results["auth"] = auth.scan()
            criticos_auth = len([f for f in results["auth"] if f.get("severidad") in ("CRITICAL", "HIGH")])
            print(f"\n[+] Hallazgos autenticación críticos/altos: {criticos_auth}")

        if not args.skip_jwt:
            print_phase("3a2", "Auditoría JWT — alg:none, secreto débil, JWKS")
            jwt_auditor = JWTAuditor(args.target, results["recon"],
                                     auth_user=args.webapp_user,
                                     auth_pass=args.webapp_pass,
                                     auth_url=args.webapp_login_url)
            results["jwt"] = jwt_auditor.scan()
            print(f"\n[+] Hallazgos JWT: {len([f for f in results['jwt'] if f.get('severidad') in ('CRITICAL','HIGH')])}")

        if not args.skip_webapp:
            print_phase("3b", "Análisis OWASP — inyecciones y vulnerabilidades web")
            checks = [c.strip() for c in args.webapp_checks.split(",")]
            # Usar URL explícita si se proporciona, si no construir desde recon
            if args.webapp_url:
                webapp_targets = [args.webapp_url]
            else:
                webapp_targets = _build_webapp_targets(args.target, results["recon"])
            for webapp_target in webapp_targets:
                scanner = WebAppScanner(webapp_target, checks=checks, stealth=args.stealth,
                                       auth_user=args.webapp_user, auth_pass=args.webapp_pass,
                                       auth_url=args.webapp_login_url)
                results["webapp"] += scanner.scan()
            print(f"\n[+] Hallazgos OWASP: {len([f for f in results['webapp'] if f.get('severidad') in ('CRITICAL','HIGH')])}")

        if not args.skip_ad:
            print_phase("3d", "Active Directory / LDAP")
            ad = ActiveDirectoryAuditor(
                args.target, results["recon"],
                ad_user=args.ad_user, ad_pass=args.ad_pass,
                ad_domain=args.ad_domain or args.target
            )
            results["ad"] = ad.scan()
            criticos_ad = len([f for f in results["ad"] if f.get("severidad") in ("CRITICAL", "HIGH")])
            print(f"\n[+] Hallazgos AD críticos/altos: {criticos_ad}")

        if not args.skip_subdomain_takeover:
            print_phase("2c1", "Subdomain Takeover — CNAMEs huérfanos en S3, GitHub Pages, Heroku, Azure...")
            st = SubdomainTakeoverScanner(args.target, results["recon"],
                                         dns_findings=results["dns"])
            results["subdomain_takeover"] = st.scan()
            criticos_st = len([f for f in results["subdomain_takeover"]
                                if f.get("severidad") in ("CRITICAL", "HIGH")])
            print(f"\n[+] Subdomain takeover hallazgos: {criticos_st}")

        if not args.skip_cloud:
            print_phase("2c2", "Cloud Storage — S3, Azure Blob, GCP, DigitalOcean Spaces")
            cs = CloudStorageScanner(args.target, results["recon"])
            results["cloud_storage"] = cs.scan()
            criticos_cs = len([f for f in results["cloud_storage"]
                                if f.get("severidad") in ("CRITICAL", "HIGH")])
            print(f"\n[+] Cloud storage hallazgos: {criticos_cs}")

        if not args.skip_deserialization:
            print_phase("2c3", "Deserialización insegura — PHP unserialize · Java · Python pickle")
            deser = DeserializationScanner(args.target, results["recon"], stealth=args.stealth)
            results["deserialization"] = deser.scan()
            criticos_de = len([f for f in results["deserialization"]
                                if f.get("severidad") in ("CRITICAL", "HIGH")])
            print(f"\n[+] Deserialización hallazgos: {criticos_de}")

        if not args.skip_race:
            print_phase("2c4", "Race Conditions — TOCTOU · double-spend · cupones · pagos")
            race = RaceConditionScanner(args.target, results["recon"], stealth=args.stealth)
            results["race_condition"] = race.scan()
            criticos_rc = len([f for f in results["race_condition"]
                                if f.get("severidad") in ("CRITICAL", "HIGH")])
            print(f"\n[+] Race condition hallazgos: {criticos_rc}")

        if not args.skip_smuggling:
            print_phase("2c5", "HTTP Request Smuggling — CL.TE · TE.CL · CL.0 · TE obfuscation")
            smug = SmugglingScanner(args.target, results["recon"], stealth=args.stealth)
            results["smuggling"] = smug.scan()
            criticos_sm = len([f for f in results["smuggling"]
                                if f.get("severidad") in ("CRITICAL", "HIGH")])
            print(f"\n[+] HTTP Smuggling hallazgos: {criticos_sm}")

        if not args.skip_websocket:
            print_phase("2c6", "WebSocket Security — Origin · autenticación · inyección")
            ws = WebSocketScanner(args.target, results["recon"], stealth=args.stealth)
            results["websocket"] = ws.scan()
            criticos_ws = len([f for f in results["websocket"]
                                if f.get("severidad") in ("CRITICAL", "HIGH")])
            print(f"\n[+] WebSocket hallazgos: {criticos_ws}")

        if not args.skip_supply_chain:
            print_phase("2c7", "Supply Chain — Dependency Confusion · npm · pip · Composer")
            sc = SupplyChainScanner(args.target, results["recon"], stealth=args.stealth)
            results["supply_chain"] = sc.scan()
            criticos_sc = len([f for f in results["supply_chain"]
                                if f.get("severidad") in ("CRITICAL", "HIGH")])
            print(f"\n[+] Supply chain hallazgos: {criticos_sc}")

    # ── FASE 4: Informe ───────────────────────────────────────────────────────
    print_phase(4, "Generando informe")
    results["fecha_fin"] = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    report = ReportGenerator(results)

    html_file = base_name + ".html"
    report.generate(html_file)
    print(f"\n[+] Informe HTML: {html_file}")

    if not args.no_pdf:
        pdf_file = base_name + ".pdf"
        try:
            report.generate_pdf(pdf_file)
            print(f"[+] Informe PDF:  {pdf_file}")
        except Exception as e:
            print(f"[!] PDF no generado: {e}")

    json_file = base_name + "_results.json"
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2, default=str)
    print(f"[+] Datos JSON:   {json_file}")

    # ── Resumen ───────────────────────────────────────────────────────────────
    all_findings = (results["vulns"] + results["misconfigs"] + results["web"] +
                    results["ssl"] + results["dns"] + results["email"] +
                    results["osint"] + results["webapp"] + results["wifi"] +
                    results["cms"] + results["auth"] + results["js"] +
                    results["graphql"] + results["fileupload"] + results["bizlogic"] +
                    results["ssti"] + results["jwt"] + results["ad"] +
                    results["injection"] + results["exposed"] +
                    results["wp_exploit"] + results["api"] +
                    results["subdomain_takeover"] + results["cloud_storage"] +
                    results["deserialization"] + results["race_condition"] +
                    results["smuggling"] + results["websocket"] +
                    results["supply_chain"])
    criticos = sum(1 for f in all_findings if f.get("severidad") == "CRITICAL")
    altos    = sum(1 for f in all_findings if f.get("severidad") == "HIGH")
    medios   = sum(1 for f in all_findings if f.get("severidad") == "MEDIUM")
    accesos  = len([c for c in results["creds"] if c.get("acceso")])

    print(f"\n{'='*64}")
    print(f"  RESUMEN — {args.empresa or args.target}")
    print(f"{'='*64}")
    print(f"  Críticos : {criticos}")
    print(f"  Altos    : {altos}")
    print(f"  Medios   : {medios}")
    print(f"  Accesos  : {accesos}")
    print(f"{'='*64}\n")


if __name__ == "__main__":
    main()
