"""
Módulo de credenciales por defecto — Fase 3
Comprueba credenciales por defecto en: FTP, SSH, HTTP Basic,
MySQL, PostgreSQL, MongoDB, Redis y SNMP community strings.
Solo para uso en entornos autorizados.
"""

import ftplib
import socket
import subprocess
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 5

DEFAULT_CREDS = {
    "ftp": [
        ("anonymous", "anonymous"), ("anonymous", ""),
        ("admin", "admin"), ("admin", ""), ("root", "root"), ("ftp", "ftp"),
    ],
    "ssh": [
        ("root", "root"), ("root", "toor"), ("root", ""),
        ("admin", "admin"), ("admin", "password"), ("admin", "1234"), ("admin", ""),
        ("user", "user"), ("ubuntu", "ubuntu"), ("pi", "raspberry"),
        ("vagrant", "vagrant"), ("test", "test"),
    ],
    "http": [
        ("admin", "admin"), ("admin", "password"), ("admin", "1234"),
        ("admin", ""), ("root", "root"), ("administrator", "administrator"),
        ("guest", "guest"), ("operator", "operator"),
    ],
    "mysql": [
        ("root", ""), ("root", "root"), ("root", "password"),
        ("root", "mysql"), ("admin", "admin"), ("mysql", "mysql"),
    ],
    "postgres": [
        ("postgres", ""), ("postgres", "postgres"), ("postgres", "password"),
        ("admin", "admin"), ("root", "root"),
    ],
    "mongo": [
        # MongoDB sin auth es acceso directo (no necesita usuario/pass)
        ("", ""),
        ("admin", "admin"), ("root", "root"),
    ],
    "redis": [
        ("", ""),           # Sin contraseña
        ("", "redis"),
        ("", "password"),
        ("", "admin"),
        ("", "123456"),
    ],
    "snmp": [
        "public", "private", "community", "admin", "manager",
        "snmp", "cisco", "secret", "default", "monitor",
    ],
}


class CredChecker:
    def __init__(self, target: str, recon_data: dict):
        self.target = target
        self.recon_data = recon_data
        self.results = []

    def check(self) -> list:
        for host in self.recon_data.get("hosts", []):
            if host["estado"] != "up":
                continue
            ip = host["ip"]
            for puerto in host["puertos"]:
                svc = puerto["servicio"].lower()
                port = puerto["puerto"]

                if "ftp" in svc:
                    self._check_ftp(ip, port)
                elif "ssh" in svc:
                    self._check_ssh(ip, port)
                elif "mysql" in svc or port == 3306:
                    self._check_mysql(ip, port)
                elif "postgres" in svc or port == 5432:
                    self._check_postgres(ip, port)
                elif "mongodb" in svc or port == 27017:
                    self._check_mongo(ip, port)
                elif "redis" in svc or port == 6379:
                    self._check_redis(ip, port)
                elif "snmp" in svc or port == 161:
                    self._check_snmp(ip, port)
                elif "http" in svc and port in (80, 443, 8080, 8443):
                    self._check_http(ip, port)

        accesos = [r for r in self.results if r["acceso"]]
        print(f"\n[+] Verificación completada. Accesos obtenidos: {len(accesos)}")
        return self.results

    # ── FTP ───────────────────────────────────────────────────────────────────

    def _check_ftp(self, ip: str, port: int):
        print(f"  [*] FTP {ip}:{port}")
        for user, pwd in DEFAULT_CREDS["ftp"]:
            try:
                ftp = ftplib.FTP()
                ftp.connect(ip, port, timeout=TIMEOUT)
                ftp.login(user, pwd)
                ftp.quit()
                print(f"  [!!!] ACCESO FTP — {user}:{pwd or '(vacío)'}")
                self._add(ip, port, "FTP", user, pwd, True, "CRITICAL")
                return
            except ftplib.error_perm:
                pass
            except Exception:
                break
        self._add(ip, port, "FTP", "-", "-", False, "INFO")

    # ── SSH ───────────────────────────────────────────────────────────────────

    def _check_ssh(self, ip: str, port: int):
        try:
            import paramiko
        except ImportError:
            print("  [!] paramiko no instalado — omitiendo SSH. pip3 install paramiko")
            return

        print(f"  [*] SSH {ip}:{port}")
        for user, pwd in DEFAULT_CREDS["ssh"]:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(ip, port=port, username=user, password=pwd,
                               timeout=TIMEOUT, allow_agent=False, look_for_keys=False)
                client.close()
                print(f"  [!!!] ACCESO SSH — {user}:{pwd or '(vacío)'}")
                self._add(ip, port, "SSH", user, pwd, True, "CRITICAL")
                return
            except paramiko.AuthenticationException:
                pass
            except Exception:
                break
        self._add(ip, port, "SSH", "-", "-", False, "INFO")

    # ── MySQL ─────────────────────────────────────────────────────────────────

    def _check_mysql(self, ip: str, port: int):
        try:
            import pymysql
        except ImportError:
            print("  [!] pymysql no instalado — omitiendo MySQL. pip3 install pymysql")
            return

        print(f"  [*] MySQL {ip}:{port}")
        for user, pwd in DEFAULT_CREDS["mysql"]:
            try:
                conn = pymysql.connect(
                    host=ip, port=port, user=user, password=pwd,
                    connect_timeout=TIMEOUT, read_timeout=TIMEOUT,
                )
                conn.close()
                print(f"  [!!!] ACCESO MySQL — {user}:{pwd or '(vacío)'}")
                self._add(ip, port, "MySQL", user, pwd, True, "CRITICAL")
                return
            except pymysql.err.OperationalError as e:
                if "Access denied" in str(e):
                    continue
                break
            except Exception:
                break
        self._add(ip, port, "MySQL", "-", "-", False, "INFO")

    # ── PostgreSQL ────────────────────────────────────────────────────────────

    def _check_postgres(self, ip: str, port: int):
        try:
            import psycopg2
        except ImportError:
            print("  [!] psycopg2 no instalado — omitiendo PostgreSQL. pip3 install psycopg2-binary")
            return

        print(f"  [*] PostgreSQL {ip}:{port}")
        for user, pwd in DEFAULT_CREDS["postgres"]:
            try:
                conn = psycopg2.connect(
                    host=ip, port=port, user=user, password=pwd,
                    dbname="postgres", connect_timeout=TIMEOUT,
                )
                conn.close()
                print(f"  [!!!] ACCESO PostgreSQL — {user}:{pwd or '(vacío)'}")
                self._add(ip, port, "PostgreSQL", user, pwd, True, "CRITICAL")
                return
            except psycopg2.OperationalError as e:
                if "password authentication failed" in str(e) or \
                   "role" in str(e) or "pg_hba" in str(e):
                    continue
                break
            except Exception:
                break
        self._add(ip, port, "PostgreSQL", "-", "-", False, "INFO")

    # ── MongoDB ───────────────────────────────────────────────────────────────

    def _check_mongo(self, ip: str, port: int):
        try:
            from pymongo import MongoClient
            from pymongo.errors import OperationFailure, ServerSelectionTimeoutError
        except ImportError:
            print("  [!] pymongo no instalado — omitiendo MongoDB. pip3 install pymongo")
            return

        print(f"  [*] MongoDB {ip}:{port}")

        # Intento sin autenticación (caso más común de exposición)
        try:
            client = MongoClient(ip, port, serverSelectionTimeoutMS=TIMEOUT * 1000)
            dbs = client.list_database_names()
            client.close()
            print(f"  [!!!] ACCESO MongoDB SIN AUTH — bases de datos: {dbs[:5]}")
            self._add(ip, port, "MongoDB", "(sin auth)", "", True, "CRITICAL",
                      extra=f"Bases de datos: {', '.join(dbs[:5])}")
            return
        except Exception:
            pass

        # Intentar con credenciales
        for user, pwd in DEFAULT_CREDS["mongo"]:
            if not user:
                continue
            try:
                uri = f"mongodb://{user}:{pwd}@{ip}:{port}/?authSource=admin"
                client = MongoClient(uri, serverSelectionTimeoutMS=TIMEOUT * 1000)
                client.list_database_names()
                client.close()
                print(f"  [!!!] ACCESO MongoDB — {user}:{pwd}")
                self._add(ip, port, "MongoDB", user, pwd, True, "CRITICAL")
                return
            except Exception:
                pass

        self._add(ip, port, "MongoDB", "-", "-", False, "INFO")

    # ── Redis ─────────────────────────────────────────────────────────────────

    def _check_redis(self, ip: str, port: int):
        try:
            import redis as redis_lib
        except ImportError:
            print("  [!] redis no instalado — omitiendo Redis. pip3 install redis")
            return

        print(f"  [*] Redis {ip}:{port}")
        for _, pwd in DEFAULT_CREDS["redis"]:
            try:
                kwargs = {"host": ip, "port": port, "socket_timeout": TIMEOUT, "socket_connect_timeout": TIMEOUT}
                if pwd:
                    kwargs["password"] = pwd
                r = redis_lib.Redis(**kwargs)
                info = r.ping()
                if info:
                    print(f"  [!!!] ACCESO Redis — password: '{pwd or '(sin contraseña)'}'")
                    self._add(ip, port, "Redis", "-", pwd, True, "CRITICAL")
                    return
            except redis_lib.exceptions.AuthenticationError:
                continue
            except Exception:
                break
        self._add(ip, port, "Redis", "-", "-", False, "INFO")

    # ── SNMP ──────────────────────────────────────────────────────────────────

    def _check_snmp(self, ip: str, port: int):
        print(f"  [*] SNMP {ip}:{port} — probando community strings")
        snmpget = self._which("snmpget")
        if not snmpget:
            print("  [!] snmpget no encontrado — omitiendo SNMP. sudo apt install snmp")
            return

        for community in DEFAULT_CREDS["snmp"]:
            try:
                result = subprocess.run(
                    [snmpget, "-v2c", "-c", community, "-t", "3", "-r", "1",
                     ip, "1.3.6.1.2.1.1.1.0"],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode == 0 and "STRING:" in result.stdout:
                    sysinfo = result.stdout.strip()[:120]
                    print(f"  [!!!] SNMP community '{community}' ACEPTA — {sysinfo}")
                    self._add(ip, port, "SNMP", community, "", True, "HIGH",
                              extra=sysinfo)
                    return
            except Exception:
                pass
        self._add(ip, port, "SNMP", "-", "-", False, "INFO")

    # ── HTTP Basic Auth ───────────────────────────────────────────────────────

    def _check_http(self, ip: str, port: int):
        proto = "https" if port in (443, 8443) else "http"
        url = f"{proto}://{ip}:{port}"
        print(f"  [*] HTTP Basic Auth {url}")

        try:
            resp = requests.get(url, timeout=TIMEOUT, verify=False, allow_redirects=True)
            if resp.status_code != 401:
                return
        except Exception:
            return

        for user, pwd in DEFAULT_CREDS["http"]:
            try:
                resp = requests.get(url, auth=(user, pwd), timeout=TIMEOUT,
                                    verify=False, allow_redirects=True)
                if resp.status_code == 200:
                    print(f"  [!!!] ACCESO HTTP Basic — {user}:{pwd or '(vacío)'}")
                    self._add(ip, port, "HTTP", user, pwd, True, "CRITICAL")
                    return
            except Exception:
                break
        self._add(ip, port, "HTTP", "-", "-", False, "INFO")

    # ── Utilidades ────────────────────────────────────────────────────────────

    def _add(self, ip, port, servicio, user, pwd, acceso, severidad, extra=""):
        self.results.append({
            "ip": ip, "puerto": port, "servicio": servicio,
            "usuario": user, "password": pwd,
            "acceso": acceso, "severidad": severidad,
            "extra": extra,
        })

    def _which(self, cmd: str) -> str:
        try:
            result = subprocess.run(["which", cmd], capture_output=True, text=True)
            path = result.stdout.strip()
            return path if path else ""
        except Exception:
            return ""
