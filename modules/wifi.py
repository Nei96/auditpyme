"""
Módulo WiFi — Auditoría de redes inalámbricas

Modos de escaneo (en orden de capacidad):
  1. Scapy + monitor mode  — cifrado exacto, PMF, WPA3, WPS desde frames 802.11
  2. nmcli                 — escaneo básico sin root (fallback automático)
  3. iw dev scan           — fallback si nmcli no disponible

Herramientas externas opcionales (mejoran resultados si están instaladas):
  - airmon-ng  — activa modo monitor de forma limpia
  - wash       — detección WPS más fiable que iw
  - arp-scan   — descubrimiento LAN más rápido que nmap
"""

import ipaddress
import re
import struct
import subprocess
from collections import defaultdict

try:
    from scapy.all import (
        Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp, RadioTap,
        conf as scapy_conf, sniff,
    )
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# ── Constantes RSN IE ─────────────────────────────────────────────────────────

_CIPHER = {
    1: "WEP-40", 2: "TKIP", 3: "WRAP", 4: "CCMP",
    5: "WEP-104", 8: "GCMP-128", 9: "GCMP-256",
}
_AKM = {
    1: "Enterprise", 2: "PSK", 3: "FT-Enterprise", 4: "FT-PSK",
    5: "Enterprise-SHA256", 6: "PSK-SHA256", 8: "SAE", 18: "OWE",
}

SSIDS_OPERADOR = [
    "MOVISTAR_", "MOVISTAR-", "VODAFONE", "ONO_", "JAZZTEL_",
    "ORANGE_", "ORANGE-", "LIVEBOX", "DMAX_", "MIFIBRA-",
    "WLAN_", "DEFAULT", "LINKSYS", "NETGEAR", "DLINK", "TPLINK",
    "TP-LINK_", "ASUS", "ARCHER", "DIR-", "TL-", "BELKIN", "BUFFALO",
]

# ── Helpers de módulo ─────────────────────────────────────────────────────────

def _cmd_existe(cmd: str) -> bool:
    try:
        return bool(subprocess.check_output(
            ["which", cmd], stderr=subprocess.DEVNULL, text=True
        ).strip())
    except Exception:
        return False


def _iface_existe(iface: str) -> bool:
    try:
        out = subprocess.check_output(
            ["ip", "link", "show", iface],
            text=True, stderr=subprocess.DEVNULL, timeout=3
        )
        return bool(out.strip())
    except Exception:
        return False


def _parse_rsn_ie(data: bytes) -> dict:
    """
    Parsea el RSN Information Element (IE ID=48) de un beacon frame.
    Extrae: cipher suites, AKM suites, PMF capable/required.

    Estructura RSN IE:
      2  bytes  versión
      4  bytes  group cipher suite (OUI 3B + type 1B)
      2  bytes  pairwise count
      4N bytes  pairwise cipher suites
      2  bytes  AKM count
      4N bytes  AKM suites
      2  bytes  RSN capabilities (bit6=MFPR, bit7=MFPC)
    """
    result = {"ciphers": [], "akms": [], "pmf_capable": False, "pmf_required": False}
    try:
        offset = 2  # saltar versión
        if len(data) < offset + 4:
            return result
        offset += 4  # saltar group cipher suite

        if len(data) < offset + 2:
            return result
        count = struct.unpack_from("<H", data, offset)[0]
        offset += 2
        for _ in range(count):
            if len(data) < offset + 4:
                return result
            t = data[offset + 3]
            result["ciphers"].append(_CIPHER.get(t, f"type{t}"))
            offset += 4

        if len(data) < offset + 2:
            return result
        count = struct.unpack_from("<H", data, offset)[0]
        offset += 2
        for _ in range(count):
            if len(data) < offset + 4:
                return result
            t = data[offset + 3]
            result["akms"].append(_AKM.get(t, f"type{t}"))
            offset += 4

        # RSN Capabilities: bit 6 = MFPR (required), bit 7 = MFPC (capable)
        if len(data) >= offset + 2:
            caps = struct.unpack_from("<H", data, offset)[0]
            result["pmf_required"] = bool(caps & (1 << 6))
            result["pmf_capable"]  = bool(caps & (1 << 7))
    except Exception:
        pass
    return result


# ── Monitor Mode ──────────────────────────────────────────────────────────────

class MonitorMode:
    """
    Context manager que activa modo monitor en la interfaz WiFi.
    Intenta airmon-ng primero (más limpio), luego iw como fallback.
    Restaura modo managed al salir aunque haya excepciones.

    Uso:
        with MonitorMode("wlan0") as mon:
            if mon:
                # mon == "wlan0mon" o "wlan0"
    """

    def __init__(self, iface: str):
        self.iface     = iface
        self.mon_iface = None
        self._method   = None

    def __enter__(self):
        self.mon_iface = self._enable()
        return self.mon_iface

    def __exit__(self, *_):
        if self.mon_iface and self._method:
            self._disable()

    def _enable(self):
        # ── Método 1: airmon-ng ───────────────────────────────────────────────
        if _cmd_existe("airmon-ng"):
            try:
                subprocess.run(["airmon-ng", "check", "kill"],
                               capture_output=True, timeout=10)
                out = subprocess.check_output(
                    ["airmon-ng", "start", self.iface],
                    text=True, stderr=subprocess.STDOUT, timeout=15
                )
                # Buscar el nombre de la interfaz monitor en la salida
                m = re.search(
                    r"(?:monitor mode (?:vif enabled on|enabled on|enabled)\s+|"
                    r"monitor mode enabled on\s+)(\S+?)[\)\s\n]", out
                )
                mon = m.group(1) if m else self.iface + "mon"
                if _iface_existe(mon):
                    self._method = "airmon-ng"
                    print(f"[+] Monitor mode activado: {mon} (airmon-ng)")
                    return mon
            except Exception:
                pass

        # ── Método 2: iw ─────────────────────────────────────────────────────
        try:
            for cmd in [
                ["ip", "link", "set", self.iface, "down"],
                ["iw", "dev", self.iface, "set", "type", "monitor"],
                ["ip", "link", "set", self.iface, "up"],
            ]:
                subprocess.run(cmd, capture_output=True, timeout=5, check=True)
            self._method = "iw"
            print(f"[+] Monitor mode activado: {self.iface} (iw)")
            return self.iface
        except Exception:
            pass

        print(f"[!] No se pudo activar modo monitor en {self.iface}.")
        print("[!] Requiere root + adaptador compatible. Usando nmcli como fallback.")
        return None

    def _disable(self):
        try:
            if self._method == "airmon-ng":
                subprocess.run(["airmon-ng", "stop", self.mon_iface],
                               capture_output=True, timeout=10)
            elif self._method == "iw":
                subprocess.run(["ip", "link", "set", self.iface, "down"],
                               capture_output=True, timeout=5)
                subprocess.run(["iw", "dev", self.iface, "set", "type", "managed"],
                               capture_output=True, timeout=5)
                subprocess.run(["ip", "link", "set", self.iface, "up"],
                               capture_output=True, timeout=5)
            # Reiniciar NetworkManager para recuperar conexión
            subprocess.run(["systemctl", "restart", "NetworkManager"],
                           capture_output=True, timeout=15)
            print(f"[+] Monitor mode desactivado. Interfaz {self.iface} restaurada.")
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
# WiFiAuditor — escaneo de redes cercanas
# ══════════════════════════════════════════════════════════════════════════════

class WiFiAuditor:
    def __init__(self, empresa: str = "", iface: str = None, timeout_scapy: int = 15):
        self.empresa       = empresa.lower().strip()
        self.iface         = iface or self._detect_iface()
        self.timeout_scapy = timeout_scapy
        self.findings      = []

    def scan(self) -> list:
        print(f"[*] Interfaz WiFi: {self.iface or 'no detectada'}")

        redes = self._get_networks()
        if not redes:
            self._add("INFO", "WiFi: sin redes detectadas",
                      "No se detectaron redes WiFi cercanas o no hay interfaz disponible.",
                      "Verificar que la interfaz WiFi está activa y en rango.")
            return self.findings

        print(f"[*] Redes detectadas: {len(redes)}\n")
        for red in redes:
            self._analizar_red(red)

        self._detectar_rogues(redes)
        self._resumen(redes)
        return self.findings

    # ── Detección de interfaz ─────────────────────────────────────────────────

    def _detect_iface(self) -> str:
        try:
            out = subprocess.check_output(["iw", "dev"], text=True,
                                          stderr=subprocess.DEVNULL, timeout=5)
            m = re.search(r"Interface\s+(\S+)", out)
            if m:
                return m.group(1)
        except Exception:
            pass
        try:
            out = subprocess.check_output(
                ["nmcli", "-t", "-f", "DEVICE,TYPE", "device"],
                text=True, stderr=subprocess.DEVNULL, timeout=5
            )
            for line in out.splitlines():
                parts = line.split(":")
                if len(parts) >= 2 and parts[1].strip() == "wifi":
                    return parts[0].strip()
        except Exception:
            pass
        return None

    # ── Escaneo de redes ──────────────────────────────────────────────────────

    def _get_networks(self) -> list:
        """
        Prioridad:
          1. Scapy en monitor mode  — datos completos (cifrado exacto, PMF, WPA3)
          2. nmcli                  — datos básicos sin root
          3. iw dev scan            — fallback final
        WPS siempre se enriquece con wash (si disponible) o iw.
        """
        redes = []

        # ── Intento 1: Scapy + monitor mode ──────────────────────────────────
        if SCAPY_OK and self.iface:
            with MonitorMode(self.iface) as mon:
                if mon:
                    redes = self._scan_scapy(mon)
                    wps_bssids = self._get_wps_wash(mon) or self._get_wps_iw_raw(mon)
                    for r in redes:
                        if r.get("bssid") in wps_bssids:
                            r["wps"] = True
                    if redes:
                        print(f"[+] Scapy: {len(redes)} redes capturadas en modo monitor.")
                        return redes

        # ── Intento 2: nmcli ──────────────────────────────────────────────────
        redes = self._scan_nmcli()

        # ── Intento 3: iw ────────────────────────────────────────────────────
        if not redes and self.iface:
            redes = self._scan_iw()

        # Enriquecer WPS via iw (sin monitor mode)
        if redes and self.iface:
            wps_bssids = self._detect_wps_iw()
            for r in redes:
                if r.get("bssid") in wps_bssids:
                    r["wps"] = True

        return redes

    # ── Scapy — sniff beacons en monitor mode ─────────────────────────────────

    def _scan_scapy(self, mon_iface: str) -> list:
        redes = {}

        def procesar(pkt):
            if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
                return
            bssid = pkt[Dot11].addr3
            if not bssid:
                return

            rssi = ""
            try:
                rssi = str(pkt[RadioTap].dBm_AntSignal)
            except Exception:
                pass

            ssid, canal, security, wps = "", "", "", False
            rsn_info = {}

            ie = pkt.getlayer(Dot11Elt)
            while ie is not None:
                try:
                    if ie.ID == 0:
                        ssid = ie.info.decode("utf-8", errors="replace").strip()
                    elif ie.ID == 3 and ie.info:
                        canal = str(ie.info[0])
                    elif ie.ID == 48:
                        rsn_info = _parse_rsn_ie(bytes(ie.info))
                        akms = rsn_info.get("akms", [])
                        if "SAE" in akms and any(k in akms for k in ("PSK", "PSK-SHA256")):
                            security = "WPA3-Transition"
                        elif "SAE" in akms:
                            security = "WPA3"
                        elif "OWE" in akms:
                            security = "OWE"
                        else:
                            security = "WPA2"
                    elif ie.ID == 221 and ie.info[:4] == b'\x00\x50\xf2\x01':
                        if not security:
                            security = "WPA"
                    elif ie.ID == 221 and ie.info[:4] == b'\x00\x50\xf2\x04':
                        wps = True
                except Exception:
                    pass
                try:
                    ie = ie.payload.getlayer(Dot11Elt)
                except Exception:
                    break

            # WEP: Privacy flag sin IE RSN
            if not security:
                try:
                    cap = pkt[Dot11Beacon].cap
                    if cap.privacy:
                        security = "WEP"
                except Exception:
                    pass

            if bssid not in redes:
                redes[bssid] = {
                    "ssid":            ssid,
                    "bssid":           bssid,
                    "canal":           canal,
                    "signal":          rssi,
                    "security":        security,
                    "wps":             wps,
                    "cipher":          ", ".join(rsn_info.get("ciphers", [])),
                    "akm":             ", ".join(rsn_info.get("akms", [])),
                    "pmf_capable":     rsn_info.get("pmf_capable", False),
                    "pmf_required":    rsn_info.get("pmf_required", False),
                    "wpa3_transition": security == "WPA3-Transition",
                    "fuente":          "scapy",
                }
            else:
                r = redes[bssid]
                if not r["ssid"] and ssid:
                    r["ssid"] = ssid
                if not r["canal"] and canal:
                    r["canal"] = canal
                if wps:
                    r["wps"] = True

        print(f"[*] Capturando beacons con Scapy ({self.timeout_scapy}s)...")
        try:
            scapy_conf.verb = 0
            sniff(iface=mon_iface, prn=procesar,
                  timeout=self.timeout_scapy, store=False)
        except Exception as e:
            print(f"[!] Scapy sniff error: {e}")
            return []

        return list(redes.values())

    # ── WPS via wash ──────────────────────────────────────────────────────────

    def _get_wps_wash(self, mon_iface: str) -> set:
        """
        Detecta BSSIDs con WPS usando wash (reaver).
        Más fiable que parsear iw scan — distingue WPS bloqueado/desbloqueado.
        """
        wps_bssids = set()
        if not _cmd_existe("wash"):
            return wps_bssids
        try:
            proc = subprocess.Popen(
                ["wash", "-i", mon_iface, "-C"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
            )
            try:
                out, _ = proc.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
                out, _ = proc.communicate()
            for line in out.splitlines():
                parts = line.split()
                if parts and re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", parts[0]):
                    bssid = parts[0].upper()
                    # Columna 4 (índice 3) = "Lck" — Yes/No
                    bloqueado = parts[3].lower() == "yes" if len(parts) > 3 else False
                    wps_bssids.add(bssid)
                    if bloqueado:
                        # Guardar info de bloqueo para usar en el análisis
                        wps_bssids.add(f"LOCKED:{bssid}")
        except Exception:
            pass
        return wps_bssids

    def _get_wps_iw_raw(self, mon_iface: str) -> set:
        """WPS detection via iw scan (fallback de wash)."""
        return self._detect_wps_iw(iface_override=mon_iface)

    def _detect_wps_iw(self, iface_override: str = None) -> set:
        iface = iface_override or self.iface
        wps_bssids = set()
        try:
            out = subprocess.check_output(
                ["iw", "dev", iface, "scan"],
                text=True, stderr=subprocess.DEVNULL, timeout=30
            )
            current = None
            for line in out.splitlines():
                s = line.strip()
                if s.startswith("BSS "):
                    current = s.split()[1].split("(")[0]
                elif ("* WPS:" in s or s.startswith("WPS:")) and current:
                    wps_bssids.add(current)
        except Exception:
            pass
        return wps_bssids

    # ── Fallbacks nmcli / iw ──────────────────────────────────────────────────

    def _scan_nmcli(self) -> list:
        try:
            subprocess.run(["nmcli", "dev", "wifi", "rescan"],
                           capture_output=True, timeout=10)
        except Exception:
            pass
        try:
            out = subprocess.check_output(
                ["nmcli", "-t", "-e", "yes", "-f",
                 "SSID,BSSID,CHAN,SIGNAL,SECURITY",
                 "dev", "wifi", "list"],
                text=True, stderr=subprocess.DEVNULL, timeout=20
            )
        except Exception:
            return []

        redes, seen = [], set()
        for line in out.strip().splitlines():
            parts = re.split(r'(?<!\\):', line)
            parts = [p.replace(r'\:', ':') for p in parts]
            if len(parts) < 5:
                continue
            ssid, bssid, chan, signal, security = (
                parts[0], parts[1], parts[2], parts[3], parts[4]
            )
            key = (ssid.strip(), bssid.strip())
            if key in seen:
                continue
            seen.add(key)
            redes.append({
                "ssid": ssid.strip(), "bssid": bssid.strip(),
                "canal": chan.strip(), "signal": signal.strip(),
                "security": security.strip(), "wps": False,
                "cipher": "", "akm": "",
                "pmf_capable": False, "pmf_required": False,
                "wpa3_transition": False, "fuente": "nmcli",
            })
        return redes

    def _scan_iw(self) -> list:
        try:
            out = subprocess.check_output(
                ["iw", "dev", self.iface, "scan"],
                text=True, stderr=subprocess.DEVNULL, timeout=30
            )
            return self._parse_iw_output(out)
        except subprocess.CalledProcessError:
            print("[!] iw scan requiere root para escaneo completo.")
            return []
        except Exception:
            return []

    def _parse_iw_output(self, output: str) -> list:
        redes, current = [], {}
        for line in output.splitlines():
            s = line.strip()
            if s.startswith("BSS "):
                if current.get("bssid"):
                    redes.append(current)
                bssid = s.split()[1].split("(")[0]
                current = {
                    "bssid": bssid, "ssid": "", "security": "",
                    "canal": "", "signal": "", "wps": False,
                    "cipher": "", "akm": "",
                    "pmf_capable": False, "pmf_required": False,
                    "wpa3_transition": False, "fuente": "iw",
                }
            elif s.startswith("SSID:"):
                current["ssid"] = s.split(":", 1)[1].strip()
            elif "DS Parameter set: channel" in s:
                m = re.search(r"channel (\d+)", s)
                if m:
                    current["canal"] = m.group(1)
            elif s.startswith("signal:"):
                current["signal"] = s.split(":", 1)[1].strip().split()[0]
            elif "* WPS:" in s or s.startswith("WPS:"):
                current["wps"] = True
            elif "RSN:" in s:
                current["security"] = "WPA2"
            elif "WPA:" in s and not current.get("security"):
                current["security"] = "WPA"
            elif "Privacy" in s and not current.get("security"):
                current["security"] = "WEP"
        if current.get("bssid"):
            redes.append(current)
        return redes

    # ── Análisis de cada red ──────────────────────────────────────────────────

    def _analizar_red(self, red: dict):
        ssid     = red.get("ssid", "").strip() or "(oculto)"
        security = red.get("security", "").upper().strip()
        wps      = red.get("wps", False)
        signal   = red.get("signal", "")
        bssid    = red.get("bssid", "")
        cipher   = red.get("cipher", "")
        pmf_req  = red.get("pmf_required", False)
        pmf_cap  = red.get("pmf_capable", False)
        wpa3_tr  = red.get("wpa3_transition", False)

        seg_display = security if security and security not in ("--", "NONE") else "NINGUNA"
        extras = []
        if wps:       extras.append("WPS")
        if wpa3_tr:   extras.append("WPA3-Trans")
        if pmf_req:   extras.append("PMF✓")
        extras_str = f"  [{' '.join(extras)}]" if extras else ""
        print(f"  [WIFI] {ssid:<28} {bssid}  {seg_display}{extras_str}  señal={signal}")

        # ── Red abierta ───────────────────────────────────────────────────────
        if not security or security in ("--", "NONE", ""):
            self._add("CRITICAL",
                      f"Red WiFi abierta: {ssid}",
                      f"La red '{ssid}' ({bssid}) no tiene cifrado. Cualquier persona "
                      "cercana puede interceptar todo el tráfico: contraseñas, emails, "
                      "datos bancarios.",
                      "Activar WPA2 con contraseña robusta (mínimo 12 caracteres) o WPA3.")
            return

        # ── WEP ───────────────────────────────────────────────────────────────
        if "WEP" in security:
            self._add("CRITICAL",
                      f"Red WiFi con WEP: {ssid}",
                      f"'{ssid}' ({bssid}) usa WEP, roto desde 2001. "
                      "Se crackea en menos de 5 minutos con herramientas gratuitas.",
                      "Migrar urgentemente a WPA2-AES o WPA3.")
            return

        # ── WPA/TKIP puro ─────────────────────────────────────────────────────
        if security == "WPA" or ("WPA" in security
                                  and "WPA2" not in security
                                  and "WPA3" not in security):
            self._add("HIGH",
                      f"Red WiFi con WPA (TKIP) obsoleto: {ssid}",
                      f"'{ssid}' usa WPA-TKIP, protocolo deprecado desde 2012 y vulnerable "
                      "a ataques de recuperación de clave.",
                      "Actualizar a WPA2-AES o WPA3 en la configuración del router.")

        # ── TKIP detectado en RSN (Scapy) — más preciso que el nombre ─────────
        elif cipher and "TKIP" in cipher and "WPA2" in security:
            self._add("HIGH",
                      f"Cifrado TKIP activo en WPA2: {ssid}",
                      f"'{ssid}' anuncia WPA2 pero usa TKIP como cipher suite "
                      f"({cipher}). TKIP es vulnerable a ataques de recuperación de clave "
                      "y está deprecado. El router acepta conexiones con cifrado débil.",
                      "Configurar el router en modo WPA2-AES (CCMP) puro, "
                      "sin compatibilidad con TKIP.")

        # ── WPA3 Transition Mode ──────────────────────────────────────────────
        if wpa3_tr:
            self._add("MEDIUM",
                      f"WPA3 en modo transición (vulnerable a downgrade): {ssid}",
                      f"'{ssid}' anuncia simultáneamente WPA3 y WPA2 (modo transición). "
                      "Un atacante puede crear un rogue AP que solo anuncie WPA2, "
                      "forzando al cliente a conectarse con el protocolo más débil "
                      "y capturar el handshake WPA2 (ataque DragonShift/downgrade).",
                      "Configurar el AP en modo WPA3-SAE exclusivo si todos los dispositivos "
                      "son compatibles. Si no, al menos habilitar PMF obligatorio.")

        # ── WPS habilitado ────────────────────────────────────────────────────
        if wps:
            bloqueado = red.get("wps_locked", False)
            if bloqueado:
                self._add("MEDIUM",
                          f"WPS habilitado (bloqueado temporalmente): {ssid}",
                          f"'{ssid}' tiene WPS activo pero actualmente bloqueado "
                          "por intentos previos. El bloqueo suele ser temporal — "
                          "el vector sigue presente.",
                          "Deshabilitar WPS permanentemente en la configuración del router.")
            else:
                self._add("HIGH",
                          f"WPS habilitado: {ssid}",
                          f"'{ssid}' ({bssid}) tiene WPS activo y accesible. "
                          "Un atacante puede obtener la contraseña WiFi mediante "
                          "Pixie Dust o fuerza bruta al PIN (máx. 11.000 intentos reales).",
                          "Deshabilitar WPS completamente en la configuración del router.")

        # ── PMF no requerido en WPA2 ──────────────────────────────────────────
        if "WPA2" in security and not wpa3_tr:
            if not pmf_req:
                pmf_detalle = (
                    "PMF no soportado" if not pmf_cap else "PMF opcional (no forzado)"
                )
                self._add("MEDIUM",
                          f"Sin protección de tramas de gestión (PMF): {ssid}",
                          f"'{ssid}' no requiere PMF ({pmf_detalle}). "
                          "Un atacante puede enviar paquetes de desautenticación falsos "
                          "para expulsar clientes de la red y capturar el handshake WPA2 "
                          "cuando se reconectan. También hace la red vulnerable a "
                          "ataques de denegación de servicio WiFi.",
                          "Activar 'Management Frame Protection Required' (PMF/802.11w) "
                          "en la configuración del AP. Compatible con la mayoría de "
                          "dispositivos desde 2014.")

        # ── SSID revela nombre de empresa ─────────────────────────────────────
        if self.empresa and len(self.empresa) >= 3 and self.empresa in ssid.lower():
            self._add("LOW",
                      f"SSID identifica a la empresa: {ssid}",
                      f"El SSID '{ssid}' contiene el nombre de la empresa, "
                      "facilitando la identificación del objetivo y ataques dirigidos.",
                      "Usar un SSID neutro que no identifique a la empresa ni su sector.")

        # ── SSID de operador/fabricante ───────────────────────────────────────
        ssid_upper = ssid.upper()
        for patron in SSIDS_OPERADOR:
            if ssid_upper.startswith(patron):
                self._add("MEDIUM",
                          f"SSID de operador/fabricante genérico: {ssid}",
                          f"'{ssid}' tiene el nombre predeterminado del operador o fabricante. "
                          "Estos routers suelen usar contraseñas derivadas del SSID o BSSID, "
                          "vulnerables a diccionarios específicos.",
                          "Cambiar el SSID y la contraseña WiFi a valores únicos y robustos.")
                break

        # ── SSID oculto ───────────────────────────────────────────────────────
        if not red.get("ssid", "").strip():
            self._add("LOW",
                      f"SSID oculto detectado ({bssid})",
                      "Red con SSID oculto. La ocultación no aporta seguridad real — "
                      "cualquier escáner básico lo revela cuando un cliente se conecta.",
                      "No confiar en la ocultación del SSID como medida de seguridad.")

    # ── Rogue AP / Evil Twin ──────────────────────────────────────────────────

    def _detectar_rogues(self, redes: list):
        ssid_map = defaultdict(list)
        for r in redes:
            ssid = r.get("ssid", "").strip()
            if ssid:
                ssid_map[ssid].append(r.get("bssid", ""))

        for ssid, bssids in ssid_map.items():
            unicos = list({b for b in bssids if b})
            if len(unicos) > 1:
                self._add("HIGH",
                          f"Posible Rogue AP / Evil Twin: '{ssid}'",
                          f"La red '{ssid}' emite desde {len(unicos)} MACs distintas: "
                          f"{', '.join(unicos)}. Puede indicar un AP falso instalado "
                          "para interceptar el tráfico de los empleados.",
                          "Verificar físicamente qué dispositivos emiten este SSID. "
                          "Considerar un sistema WIDS para monitorización continua.")

    # ── Resumen ───────────────────────────────────────────────────────────────

    def _resumen(self, redes: list):
        abiertas = sum(1 for r in redes
                       if not r.get("security")
                       or r["security"].upper() in ("--", "NONE", ""))
        wep   = sum(1 for r in redes if "WEP"  in r.get("security", "").upper())
        wpa2  = sum(1 for r in redes if "WPA2" in r.get("security", "").upper())
        wpa3  = sum(1 for r in redes if "WPA3" in r.get("security", "").upper())
        wps   = sum(1 for r in redes if r.get("wps"))
        pmf   = sum(1 for r in redes if r.get("pmf_required"))
        fuente = redes[0].get("fuente", "?") if redes else "?"
        print(
            f"\n[+] WiFi [{fuente}] — Total: {len(redes)} | "
            f"Abiertas: {abiertas} | WEP: {wep} | WPA2: {wpa2} | "
            f"WPA3: {wpa3} | WPS: {wps} | PMF obligatorio: {pmf}"
        )

    # ── Helper ────────────────────────────────────────────────────────────────

    def _add(self, severidad, nombre, descripcion, recomendacion):
        self.findings.append({
            "severidad":     severidad,
            "nombre":        nombre,
            "descripcion":   descripcion,
            "recomendacion": recomendacion,
        })
        icon = {"CRITICAL": "[!]", "HIGH": "[!]", "MEDIUM": "[*]",
                "LOW": "[-]", "INFO": "[i]"}.get(severidad, "[?]")
        print(f"  {icon} [{severidad}] {nombre}")


# ══════════════════════════════════════════════════════════════════════════════
# Red Local desde WiFi abierta
# ══════════════════════════════════════════════════════════════════════════════

PUERTOS_LOCAL = "21,22,23,25,80,443,445,3389,8080,8443,3306,5432,27017,6379,5900,161,8888,9200,1883"

DISPOSITIVOS = {
    5900:  ("Escritorio remoto VNC",   "HIGH",    "Escritorio del PC accesible remotamente desde la WiFi."),
    3389:  ("Escritorio remoto RDP",   "HIGH",    "Escritorio Windows accesible remotamente desde la WiFi."),
    22:    ("SSH",                      "MEDIUM",  "Acceso por consola al dispositivo desde la WiFi."),
    23:    ("Telnet",                   "CRITICAL","Telnet activo — credenciales viajan sin cifrar."),
    445:   ("Carpetas compartidas SMB", "HIGH",    "Archivos compartidos de empresa accesibles desde la WiFi."),
    80:    ("Panel web (HTTP)",         "MEDIUM",  "Panel de administración web sin HTTPS."),
    443:   ("Panel web (HTTPS)",        "LOW",     "Panel de administración web con HTTPS."),
    8080:  ("Panel web alternativo",    "MEDIUM",  "Panel web secundario accesible desde la WiFi."),
    8443:  ("Panel web alternativo",    "LOW",     "Panel web seguro secundario accesible desde la WiFi."),
    3306:  ("Base de datos MySQL",      "CRITICAL","Base de datos accesible directamente desde la WiFi."),
    5432:  ("Base de datos PostgreSQL", "CRITICAL","Base de datos accesible directamente desde la WiFi."),
    27017: ("Base de datos MongoDB",    "CRITICAL","Base de datos accesible directamente desde la WiFi."),
    6379:  ("Base de datos Redis",      "CRITICAL","Base de datos en memoria accesible desde la WiFi."),
    9200:  ("Elasticsearch",            "CRITICAL","Motor de búsqueda con posibles datos expuestos."),
    21:    ("FTP",                      "HIGH",    "Transferencia de archivos accesible desde la WiFi."),
    161:   ("SNMP",                     "HIGH",    "Gestión de red — puede revelar info del dispositivo."),
    1883:  ("MQTT (IoT)",               "MEDIUM",  "Broker IoT accesible — posibles sensores/dispositivos conectados."),
    25:    ("SMTP (correo)",            "MEDIUM",  "Servidor de correo interno accesible desde la WiFi."),
}


class RedLocalAuditor:
    """
    Escanea la red local cuando el auditor está conectado a la WiFi del cliente.
    Muestra exactamente lo que vería cualquier atacante conectado a esa red.
    """

    def __init__(self, iface: str = None, subred: str = None):
        self.iface  = iface or self._detect_wifi_iface()
        self.subred = subred or (self._get_subred() if self.iface else None)
        self.findings = []

    def scan(self) -> dict:
        if not self.subred:
            print("[!] No se pudo determinar la subred WiFi. Usa --wifi-subred 192.168.x.0/24")
            self._add("INFO", "Red local: subred no detectada",
                      "No se pudo determinar la subred. Especifica --wifi-subred manualmente.",
                      "Ejecutar conectado a la red WiFi del cliente.")
            return {"findings": self.findings, "recon": {"hosts": []}}

        print(f"[*] Escaneando red local: {self.subred}")
        print("[*] Buscando dispositivos activos (puede tardar 1-2 min)...\n")

        hosts_activos = self._discover_hosts()
        if not hosts_activos:
            self._add("INFO", "Red local: ningún dispositivo encontrado",
                      f"No se detectaron dispositivos en {self.subred}.",
                      "Verificar que la conexión WiFi está activa y en el segmento correcto.")
            return {"findings": self.findings, "recon": {"hosts": []}}

        print(f"[+] Dispositivos activos: {len(hosts_activos)}\n")

        self._add(
            "HIGH" if len(hosts_activos) > 2 else "MEDIUM",
            f"Red local expuesta: {len(hosts_activos)} dispositivos visibles desde la WiFi",
            f"Cualquier persona conectada a esta red WiFi puede ver "
            f"{len(hosts_activos)} dispositivos internos: "
            f"{', '.join(hosts_activos[:6])}{'...' if len(hosts_activos) > 6 else ''}. "
            "Un atacante con acceso a la WiFi tiene visibilidad directa de la red interna.",
            "Segmentar la WiFi de clientes/invitados en una VLAN separada sin acceso "
            "a la red interna de la empresa."
        )

        recon_hosts = []
        for ip in hosts_activos:
            host_data = self._scan_host(ip)
            if host_data["puertos"]:
                recon_hosts.append(host_data)
                self._analizar_host(host_data)

        print(f"\n[+] Red local completada. Hallazgos: {len(self.findings)}")
        return {"findings": self.findings, "recon": {"hosts": recon_hosts}}

    def _detect_wifi_iface(self) -> str:
        try:
            out = subprocess.check_output(["iw", "dev"], text=True,
                                          stderr=subprocess.DEVNULL, timeout=5)
            m = re.search(r"Interface\s+(\S+)", out)
            if m:
                return m.group(1)
        except Exception:
            pass
        try:
            out = subprocess.check_output(
                ["nmcli", "-t", "-f", "DEVICE,TYPE", "device"],
                text=True, stderr=subprocess.DEVNULL, timeout=5
            )
            for line in out.splitlines():
                parts = line.split(":")
                if len(parts) >= 2 and parts[1].strip() == "wifi":
                    return parts[0].strip()
        except Exception:
            pass
        return None

    def _get_subred(self) -> str:
        try:
            out = subprocess.check_output(
                ["ip", "-o", "addr", "show", self.iface],
                text=True, stderr=subprocess.DEVNULL, timeout=5
            )
            m = re.search(r"inet\s+([\d.]+/\d+)", out)
            if m:
                return str(ipaddress.IPv4Interface(m.group(1)).network)
        except Exception:
            pass
        return None

    def _discover_hosts(self) -> list:
        hosts = set()
        if _cmd_existe("arp-scan"):
            try:
                out = subprocess.check_output(
                    ["arp-scan", "--localnet", "--interface", self.iface or ""],
                    text=True, stderr=subprocess.DEVNULL, timeout=30
                )
                for line in out.splitlines():
                    m = re.match(r"^(\d+\.\d+\.\d+\.\d+)", line)
                    if m:
                        hosts.add(m.group(1))
            except Exception:
                pass

        if not hosts or len(hosts) < 2:
            try:
                import nmap
                nm = nmap.PortScanner()
                nm.scan(hosts=self.subred, arguments="-sn -T4 --host-timeout 8s")
                for h in nm.all_hosts():
                    if nm[h].state() == "up":
                        hosts.add(h)
            except Exception as e:
                print(f"[!] Error en descubrimiento de hosts: {e}")

        hosts.discard(self._ip_propia())
        return sorted(hosts)

    def _ip_propia(self) -> str:
        try:
            out = subprocess.check_output(
                ["ip", "-o", "addr", "show", self.iface],
                text=True, stderr=subprocess.DEVNULL, timeout=5
            )
            m = re.search(r"inet\s+([\d.]+)/", out)
            if m:
                return m.group(1)
        except Exception:
            pass
        return ""

    def _scan_host(self, ip: str) -> dict:
        print(f"  [*] Escaneando {ip}...")
        host_data = {"ip": ip, "hostname": ip, "estado": "up", "os": {}, "puertos": []}
        try:
            import nmap
            nm = nmap.PortScanner()
            nm.scan(hosts=ip, ports=PUERTOS_LOCAL,
                    arguments="-sV -T4 --open --host-timeout 30s")
            if ip not in nm.all_hosts():
                return host_data
            for proto in nm[ip].all_protocols():
                for port in sorted(nm[ip][proto].keys()):
                    svc = nm[ip][proto][port]
                    if svc["state"] != "open":
                        continue
                    puerto = {
                        "puerto":    port,
                        "protocolo": proto,
                        "estado":    "open",
                        "servicio":  svc.get("name", "desconocido"),
                        "version":   svc.get("version", ""),
                        "producto":  svc.get("product", ""),
                        "extra":     svc.get("extrainfo", ""),
                        "cpe":       svc.get("cpe", ""),
                        "scripts":   {},
                        "notas":     [],
                    }
                    host_data["puertos"].append(puerto)
                    vs = f"{puerto['producto']} {puerto['version']}".strip()
                    print(f"    [OPEN] {port}/{proto}  {puerto['servicio']}"
                          + (f"  [{vs}]" if vs else ""))
        except Exception as e:
            print(f"  [!] Error escaneando {ip}: {e}")
        return host_data

    def _analizar_host(self, host: dict):
        ip      = host["ip"]
        puertos = host["puertos"]
        if not puertos:
            return

        nombres = [f"{p['puerto']}/{p['servicio']}" for p in puertos]
        print(f"\n  [→] {ip} — puertos abiertos: {', '.join(nombres)}")

        for p in puertos:
            port = p["puerto"]
            svc  = p["servicio"].lower()
            if port in DISPOSITIVOS:
                label, sev, desc = DISPOSITIVOS[port]
            else:
                match = next(
                    (DISPOSITIVOS[k] for k in DISPOSITIVOS
                     if any(kw in svc for kw in [
                         "ftp", "ssh", "telnet", "http", "mysql", "postgres",
                         "mongo", "redis", "vnc", "rdp", "smb", "snmp",
                     ] if kw in DISPOSITIVOS.get(k, ("",))[0].lower())),
                    None
                )
                if not match:
                    continue
                label, sev, desc = match

            vs = f"{p.get('producto','')} {p.get('version','')}".strip()
            self._add(
                sev,
                f"{label} expuesto en red local: {ip}:{port}",
                f"{desc} Detectado en {ip}:{port}"
                + (f" ({vs})" if vs else "") +
                ". Cualquier dispositivo en la WiFi puede intentar acceder.",
                self._rec_puerto(port)
            )

        if any(p["puerto"] == 23 for p in puertos):
            self._add("CRITICAL", f"Telnet sin cifrado en {ip}",
                      f"{ip} tiene Telnet activo. Las contraseñas viajan en texto plano "
                      "y son visibles para cualquiera en la misma WiFi.",
                      "Deshabilitar Telnet inmediatamente. Usar SSH.")

    def _rec_puerto(self, port: int) -> str:
        return {
            5900:  "Deshabilitar VNC o restringir con contraseña robusta y VPN.",
            3389:  "No exponer RDP directamente. Usar VPN para acceso remoto.",
            22:    "Deshabilitar login por contraseña en SSH, usar solo claves.",
            23:    "Deshabilitar Telnet inmediatamente. Usar SSH.",
            445:   "No exponer SMB a redes no confiables. Revisar carpetas compartidas.",
            80:    "Implementar HTTPS. Proteger el panel con contraseña robusta.",
            8080:  "Proteger el panel con autenticación.",
            3306:  "Nunca exponer bases de datos a la WiFi. Restringir a localhost.",
            5432:  "Nunca exponer bases de datos a la WiFi. Restringir a localhost.",
            27017: "Nunca exponer MongoDB a redes no confiables. Habilitar autenticación.",
            6379:  "Redis no debe ser accesible sin contraseña desde WiFi.",
            9200:  "Elasticsearch requiere autenticación. Usar X-Pack Security.",
            21:    "Deshabilitar FTP y usar SFTP/FTPS.",
            161:   "Restringir SNMP a IPs de gestión. Cambiar community string 'public'.",
            1883:  "Proteger broker MQTT con autenticación.",
        }.get(port, "Restringir acceso a este servicio a la red interna o VPN.")

    def _add(self, severidad, nombre, descripcion, recomendacion):
        self.findings.append({
            "severidad":     severidad,
            "nombre":        nombre,
            "descripcion":   descripcion,
            "recomendacion": recomendacion,
        })
        icon = {"CRITICAL": "[!]", "HIGH": "[!]", "MEDIUM": "[*]",
                "LOW": "[-]", "INFO": "[i]"}.get(severidad, "[?]")
        print(f"  {icon} [{severidad}] {nombre}")
