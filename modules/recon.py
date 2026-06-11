"""
Módulo de reconocimiento — Fase 1
Usa nmap para descubrir hosts, puertos abiertos, servicios, OS y banners.
Extrae resultados de scripts nmap: SMB signing, SSL cert, HTTP title, etc.
"""

import nmap
import socket


class Recon:
    def __init__(self, target: str, ports: str = "1-1024,3306,3389,5432,5900,6379,8080,8443,8888,27017",
                 stealth: bool = False):
        self.target = target
        self.ports = ports
        self.stealth = stealth
        self.nm = nmap.PortScanner()

    def scan(self) -> dict:
        print(f"[*] Escaneando: {self.target}")
        print(f"[*] Puertos: {self.ports}")
        if self.stealth:
            print("[*] Modo sigiloso: timing T2, scan-delay 1s, paralelismo reducido")
        print("[*] Esto puede tardar varios minutos...\n")

        import os
        is_root = os.geteuid() == 0
        if self.stealth:
            args = "-sV -sC -T2 --scan-delay 1s --max-parallelism 10 --open" + (" -O" if is_root else "")
        else:
            args = "-sV -sC -T3 --open" + (" -O" if is_root else "")

        try:
            self.nm.scan(hosts=self.target, ports=self.ports, arguments=args)
        except nmap.PortScannerError as e:
            print(f"[!] Error de nmap: {e}")
            print("[!] Asegúrate de tener nmap instalado: sudo apt install nmap")
            return {"hosts": [], "total_puertos": 0}
        except Exception as e:
            print(f"[!] Error inesperado en reconocimiento: {e}")
            return {"hosts": [], "total_puertos": 0}

        hosts = []
        total_puertos = 0

        for host in self.nm.all_hosts():
            hostname = self._resolve_hostname(host)
            estado = self.nm[host].state()
            os_info = self._get_os(host)
            puertos = []

            for proto in self.nm[host].all_protocols():
                for port in sorted(self.nm[host][proto].keys()):
                    svc = self.nm[host][proto][port]
                    if svc["state"] != "open":
                        continue

                    scripts = self._get_scripts(host, proto, port)
                    notas = self._extract_script_notes(scripts, port)

                    puerto_info = {
                        "puerto":    port,
                        "protocolo": proto,
                        "estado":    svc["state"],
                        "servicio":  svc.get("name", "desconocido"),
                        "version":   svc.get("version", ""),
                        "producto":  svc.get("product", ""),
                        "extra":     svc.get("extrainfo", ""),
                        "cpe":       svc.get("cpe", ""),
                        "scripts":   scripts,
                        "notas":     notas,
                    }
                    puertos.append(puerto_info)
                    total_puertos += 1
                    self._print_port(puerto_info)

            hosts.append({
                "ip":       host,
                "hostname": hostname,
                "estado":   estado,
                "os":       os_info,
                "puertos":  puertos,
            })

        print(f"\n[+] Reconocimiento completado. Puertos abiertos: {total_puertos}")
        return {"hosts": hosts, "total_puertos": total_puertos}

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _resolve_hostname(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return self.nm[ip].hostname() or ip

    def _get_os(self, host: str) -> dict:
        os_info = {"nombre": "Desconocido", "precision": 0, "familia": ""}
        try:
            matches = self.nm[host].get("osmatch", [])
            if matches:
                mejor = matches[0]
                os_info["nombre"]    = mejor.get("name", "Desconocido")
                os_info["precision"] = int(mejor.get("accuracy", 0))
                clases = mejor.get("osclass", [])
                if clases:
                    os_info["familia"] = clases[0].get("osfamily", "")
        except Exception:
            pass
        return os_info

    def _get_scripts(self, host: str, proto: str, port: int) -> dict:
        scripts = {}
        try:
            raw = self.nm[host][proto][port].get("script", {})
            for name, output in raw.items():
                scripts[name] = output[:800]
        except Exception:
            pass
        return scripts

    def _extract_script_notes(self, scripts: dict, port: int) -> list:
        """
        Interpreta scripts de nmap y devuelve notas legibles para el reporte.
        """
        notas = []

        # SMB signing
        smb_sec = scripts.get("smb-security-mode", "")
        smb2    = scripts.get("smb2-security-mode", "")
        if smb_sec or smb2:
            if "message_signing: disabled" in smb_sec.lower() or \
               "signing: disabled" in smb2.lower() or \
               "not required" in (smb_sec + smb2).lower():
                notas.append(("HIGH", "SMB Signing deshabilitado — vulnerable a ataques NTLM relay."))
            else:
                notas.append(("INFO", "SMB Signing habilitado."))

        # SMBv1
        if "smb-vuln-ms17-010" in scripts:
            out = scripts["smb-vuln-ms17-010"]
            if "VULNERABLE" in out.upper():
                notas.append(("CRITICAL", "EternalBlue (MS17-010) — host VULNERABLE. Parche urgente."))

        # SSL cert info
        ssl_cert = scripts.get("ssl-cert", "")
        if ssl_cert:
            if "self-signed" in ssl_cert.lower():
                notas.append(("MEDIUM", "Certificado SSL autofirmado detectado."))
            # Buscar fecha de expiración
            for line in ssl_cert.splitlines():
                if "not valid after" in line.lower():
                    notas.append(("INFO", f"SSL cert expira: {line.strip()}"))
                    break

        # HTTP title
        http_title = scripts.get("http-title", "")
        if http_title and "did not follow redirect" not in http_title.lower():
            notas.append(("INFO", f"HTTP Title: {http_title.strip()[:80]}"))

        # HTTP server header
        http_server = scripts.get("http-server-header", "")
        if http_server:
            notas.append(("LOW", f"Server header expuesto: {http_server.strip()[:80]}"))

        # Anonymous FTP
        ftp_anon = scripts.get("ftp-anon", "")
        if ftp_anon and "anonymous ftp login allowed" in ftp_anon.lower():
            notas.append(("CRITICAL", "FTP anónimo permitido — acceso sin credenciales."))

        # Telnet
        if port == 23 and scripts.get("telnet-ntlm-info") or scripts.get("telnet-encryption"):
            notas.append(("CRITICAL", "Telnet activo — protocolo sin cifrado."))

        return notas

    def _print_port(self, p: dict):
        version = f"{p['producto']} {p['version']}".strip()
        version_str = f"  [{version}]" if version else ""
        print(f"  [OPEN] {p['puerto']}/{p['protocolo']}  {p['servicio']}{version_str}")
        for sev, nota in p.get("notas", []):
            print(f"         └─ [{sev}] {nota}")
