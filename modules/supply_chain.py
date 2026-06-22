"""
Módulo de Supply Chain / Dependency Confusion — AuditPyme
Detecta paquetes internos que podrían ser suplantados en registros públicos.
"""

import re
import json
import requests
import urllib3
import time
from urllib.parse import urljoin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
TIMEOUT = 10
UA = "Mozilla/5.0 (compatible; AuditPyme/1.0)"

# Versiones de paquetes en registros públicos que podrían colisionar
NPM_REGISTRY = "https://registry.npmjs.org"
PYPI_REGISTRY = "https://pypi.org/pypi"
PACKAGIST_REGISTRY = "https://packagist.org/packages"
RUBYGEMS_REGISTRY = "https://rubygems.org/api/v1/gems"

# Archivos que revelan dependencias del proyecto
PACKAGE_FILES = [
    ("package.json", "npm"),
    ("package-lock.json", "npm"),
    ("yarn.lock", "npm"),
    (".npmrc", "npm"),
    ("requirements.txt", "pip"),
    ("Pipfile", "pip"),
    ("setup.py", "pip"),
    ("pyproject.toml", "pip"),
    ("composer.json", "packagist"),
    ("composer.lock", "packagist"),
    ("Gemfile", "rubygems"),
    ("Gemfile.lock", "rubygems"),
    ("go.mod", "go"),
    ("go.sum", "go"),
    ("pom.xml", "maven"),
    ("build.gradle", "gradle"),
    ("Cargo.toml", "cargo"),
]

# Rutas donde pueden estar expuestos archivos de dependencias
PACKAGE_PATHS = [
    "/{file}",
    "/src/{file}",
    "/app/{file}",
    "/api/{file}",
    "/backend/{file}",
    "/frontend/{file}",
    "/client/{file}",
    "/server/{file}",
    "/public/{file}",
    "/.github/{file}",
]

# Patrones de nombres de paquetes "internos" (señales de paquete privado)
INTERNAL_PATTERNS = [
    r'@[a-z0-9\-]+/',              # Scoped npm: @empresa/paquete
    r'^internal[\-_]',             # internal-*
    r'^private[\-_]',              # private-*
    r'^corp[\-_]',                 # corp-*
    r'^company[\-_]',
    r'[\-_]internal$',
    r'[\-_]private$',
    r'[\-_]local$',
    r'^lib[\-_][a-z0-9]{3,}',     # lib-*
    r'^pkg[\-_][a-z0-9]{3,}',     # pkg-*
]

# Indicadores de versión privada/interna
INTERNAL_VERSION_PATTERNS = [
    r'file:',           # file: protocol → paquete local
    r'git\+',           # git+https://... → paquete de git privado
    r'workspace:',      # yarn workspaces
    r'link:',           # yarn link
    r'portal:',
    r'^0\.0\.0',        # versión placeholder interna
    r'\.internal\.',    # dominio interno en la URL
    r'\.corp\.',
    r'\.local\.',
]


class SupplyChainScanner:

    def __init__(self, target: str, recon_data: dict = None, stealth: bool = False):
        self.target = target
        self.recon_data = recon_data or {}
        self.findings = []
        self.delay = 0.5 if stealth else 0.15
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA})
        self.session.verify = False
        self._base_urls = self._build_base_urls()
        self._packages = {}  # {"npm": ["paquete1", "paquete2"], "pip": [...]}

    def scan(self) -> list:
        print(f"\n  [*] Supply Chain / Dependency Confusion scan: {self.target}")
        self._fetch_package_files()

        if not any(self._packages.values()):
            print("  [!] No se encontraron archivos de dependencias expuestos")
            return self.findings

        print(f"  [*] Paquetes encontrados: "
              f"{sum(len(v) for v in self._packages.values())} en total")
        self._check_npm_confusion()
        self._check_pip_confusion()
        self._check_packagist_confusion()
        self._check_exposed_sensitive_files()

        if not self.findings:
            print("  [OK] No se detectaron vulnerabilidades de supply chain")
        return self.findings

    # ── Obtener archivos de dependencias expuestos ────────────────────────────

    def _fetch_package_files(self):
        for base in self._base_urls:
            for filename, ecosystem in PACKAGE_FILES:
                for path_tpl in PACKAGE_PATHS[:4]:
                    url = base.rstrip("/") + path_tpl.format(file=filename)
                    try:
                        time.sleep(self.delay)
                        r = self.session.get(url, timeout=TIMEOUT)
                        if r.status_code != 200 or len(r.text) < 10:
                            continue

                        # Verificar que parece un archivo de dependencias real
                        if not self._looks_like_package_file(r.text, ecosystem):
                            continue

                        print(f"  [+] Archivo expuesto: {url}")
                        packages = self._extract_packages(r.text, ecosystem)

                        if ecosystem not in self._packages:
                            self._packages[ecosystem] = []

                        self._packages[ecosystem].extend(packages)

                        # Reportar el archivo expuesto en sí
                        self._add(
                            "MEDIUM",
                            f"Archivo de dependencias expuesto — {filename}",
                            f"El archivo '{filename}' ({ecosystem}) es accesible públicamente. "
                            f"URL: {url}\nPaquetes identificados: {len(packages)}",
                            "Los archivos de dependencias revelan la stack tecnológica completa, "
                            "versiones exactas de paquetes (útil para buscar CVEs conocidos), "
                            "nombres de paquetes internos (vector de dependency confusion), "
                            "y posibles URLs de repositorios privados.",
                            f"Bloquear el acceso público a '{filename}' en el servidor web. "
                            f"En Nginx: location ~* package\\.json {{ deny all; }} "
                            f"En Apache: <FilesMatch 'package\\.json'> Require all denied </FilesMatch>"
                        )
                        print(f"  [MEDIUM] Dependencias expuestas: {url}")
                    except Exception:
                        pass

    def _looks_like_package_file(self, text: str, ecosystem: str) -> bool:
        """Verificación básica de que el contenido parece un archivo de paquetes."""
        if ecosystem == "npm":
            return '"dependencies"' in text or '"name"' in text or '"version"' in text
        elif ecosystem == "pip":
            return re.search(r'^[\w\-]+[><=!]=?[\d.]', text, re.MULTILINE) is not None or \
                   "install_requires" in text or "[tool.poetry" in text
        elif ecosystem == "packagist":
            return '"require"' in text or '"require-dev"' in text
        elif ecosystem == "rubygems":
            return "gem " in text or "Gem::Specification" in text
        elif ecosystem in ("go", "maven", "gradle", "cargo"):
            return True
        return False

    # ── Extracción de nombres de paquetes ─────────────────────────────────────

    def _extract_packages(self, text: str, ecosystem: str) -> list:
        packages = []
        if ecosystem == "npm":
            try:
                data = json.loads(text)
                for section in ("dependencies", "devDependencies",
                                "peerDependencies", "optionalDependencies"):
                    if section in data:
                        packages.extend(data[section].keys())
            except Exception:
                # Fallback: extraer con regex
                for m in re.finditer(r'"([@\w\-/]+)":\s*"([^"]+)"', text):
                    packages.append(m.group(1))
        elif ecosystem == "pip":
            for line in text.splitlines():
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("-"):
                    pkg = re.split(r'[>=<!;\s]', line)[0].strip()
                    if pkg:
                        packages.append(pkg)
        elif ecosystem == "packagist":
            try:
                data = json.loads(text)
                for section in ("require", "require-dev"):
                    if section in data:
                        packages.extend(data[section].keys())
            except Exception:
                pass
        elif ecosystem == "rubygems":
            for m in re.finditer(r"gem ['\"]([^'\"]+)['\"]", text):
                packages.append(m.group(1))
        elif ecosystem == "go":
            for m in re.finditer(r'^\s+([^\s]+)\s+v[\d.]+', text, re.MULTILINE):
                packages.append(m.group(1))

        return list(set(packages))

    # ── Comprobación en registros públicos ────────────────────────────────────

    def _check_npm_confusion(self):
        packages = self._packages.get("npm", [])
        if not packages:
            return
        print(f"  [*] Verificando {len(packages)} paquetes npm en registro público...")
        for pkg in packages[:30]:
            self._check_package_in_registry(pkg, "npm", self._is_private_npm_name(pkg))

    def _check_pip_confusion(self):
        packages = self._packages.get("pip", [])
        if not packages:
            return
        print(f"  [*] Verificando {len(packages)} paquetes PyPI...")
        for pkg in packages[:30]:
            self._check_package_in_registry(pkg, "pip", self._is_private_pip_name(pkg))

    def _check_packagist_confusion(self):
        packages = self._packages.get("packagist", [])
        if not packages:
            return
        print(f"  [*] Verificando {len(packages)} paquetes Composer...")
        for pkg in packages[:20]:
            if "/" in pkg:  # vendor/package format
                self._check_package_in_registry(pkg, "packagist",
                                               self._is_private_composer_name(pkg))

    def _check_package_in_registry(self, pkg_name: str, ecosystem: str, is_internal_hint: bool):
        """Verifica si el paquete existe en el registro público."""
        try:
            time.sleep(self.delay)
            exists_public, public_version = self._query_registry(pkg_name, ecosystem)
            is_internal = is_internal_hint or self._name_looks_internal(pkg_name)

            if is_internal and not exists_public:
                # Paquete interno NO registrado públicamente → vector de dependency confusion
                self._add(
                    "CRITICAL",
                    f"Dependency Confusion — {ecosystem}: {pkg_name}",
                    f"El paquete '{pkg_name}' (ecosistema: {ecosystem}) parece ser un paquete "
                    f"interno/privado pero NO está registrado en el registro público. "
                    f"Un atacante puede registrar '{pkg_name}' en el registro público con "
                    f"una versión mayor que la privada para forzar su instalación.",
                    "Dependency Confusion / Namespace Confusion: un atacante registra el paquete "
                    "interno en el registro público con versión 9.9.9 (mayor que la interna). "
                    "npm/pip instalan la versión más alta disponible — si no está configurado "
                    "correctamente el registro privado, se instala el paquete malicioso. "
                    "Permite RCE en la pipeline de CI/CD y en todos los desarrolladores del equipo.",
                    f"Registrar inmediatamente '{pkg_name}' en el registro público ({ecosystem}) "
                    f"con una versión alta y sin contenido ejecutable malicioso. "
                    f"Configurar el gestor de paquetes para que SOLO use el registro privado para "
                    f"paquetes internos. En npm: usar .npmrc con scopes privados. "
                    f"En pip: usar --index-url apuntando solo al repositorio privado. "
                    f"En Composer: usar 'repositories' con 'packagist: false'."
                )
                print(f"  [CRITICAL] Dependency Confusion: {ecosystem}/{pkg_name} (no registrado públicamente)")

            elif is_internal and exists_public:
                # Paquete interno YA existe en público → posible squatting existente
                self._add(
                    "HIGH",
                    f"Posible Namespace Collision — {ecosystem}: {pkg_name}",
                    f"El paquete '{pkg_name}' existe en el registro público ({ecosystem}) "
                    f"con versión {public_version}. Si también existe como paquete interno, "
                    f"puede haber ambigüedad en la resolución. URL: {self._registry_url(pkg_name, ecosystem)}",
                    "Si el paquete interno y el público tienen el mismo nombre, "
                    "la pipeline de CI/CD puede instalar la versión pública (potencialmente "
                    "maliciosa si fue registrada por un tercero) en lugar de la interna.",
                    f"Verificar que '{pkg_name}' en {ecosystem} pertenece a la organización. "
                    f"Si no es vuestro paquete, reportar a los mantenedores del registro. "
                    f"Configurar scopes privados para todos los paquetes internos."
                )
                print(f"  [HIGH] Namespace collision: {ecosystem}/{pkg_name} ya existe públicamente")
        except Exception:
            pass

    def _query_registry(self, pkg: str, ecosystem: str) -> tuple:
        """Consulta si el paquete existe en el registro público."""
        try:
            time.sleep(self.delay)
            if ecosystem == "npm":
                url = f"{NPM_REGISTRY}/{pkg}"
                r = self.session.get(url, timeout=TIMEOUT)
                if r.status_code == 200:
                    data = r.json()
                    version = data.get("dist-tags", {}).get("latest", "?")
                    return True, version
                return False, None

            elif ecosystem == "pip":
                # Normalizar nombre
                pkg_norm = re.sub(r'[-_.]+', '-', pkg).lower()
                url = f"{PYPI_REGISTRY}/{pkg_norm}/json"
                r = self.session.get(url, timeout=TIMEOUT)
                if r.status_code == 200:
                    data = r.json()
                    version = data.get("info", {}).get("version", "?")
                    return True, version
                return False, None

            elif ecosystem == "packagist":
                url = f"{PACKAGIST_REGISTRY}/{pkg}.json"
                r = self.session.get(url, timeout=TIMEOUT)
                return r.status_code == 200, "?"

        except Exception:
            pass
        return False, None

    def _registry_url(self, pkg: str, ecosystem: str) -> str:
        if ecosystem == "npm":
            return f"https://www.npmjs.com/package/{pkg}"
        elif ecosystem == "pip":
            return f"https://pypi.org/project/{pkg}/"
        elif ecosystem == "packagist":
            return f"https://packagist.org/packages/{pkg}"
        return "#"

    # ── Detección de nombres internos ─────────────────────────────────────────

    def _name_looks_internal(self, name: str) -> bool:
        name_lower = name.lower()
        for pattern in INTERNAL_PATTERNS:
            if re.search(pattern, name_lower):
                return True
        # Contiene nombre del target
        target_base = re.sub(r'^www\.', '', self.target).split(".")[0].lower()
        if target_base in name_lower and len(target_base) > 3:
            return True
        return False

    def _is_private_npm_name(self, name: str) -> bool:
        """Detecta paquetes npm con señales de ser privados."""
        if name.startswith("@"):
            # Scoped: @empresa/paquete — verificar si el scope existe en npm
            return True
        for pattern in INTERNAL_VERSION_PATTERNS:
            if re.search(pattern, name):
                return True
        return self._name_looks_internal(name)

    def _is_private_pip_name(self, name: str) -> bool:
        return self._name_looks_internal(name)

    def _is_private_composer_name(self, name: str) -> bool:
        parts = name.split("/")
        if len(parts) == 2:
            vendor = parts[0].lower()
            # Vendor que coincide con el target → probablemente interno
            target_base = re.sub(r'^www\.', '', self.target).split(".")[0].lower()
            if vendor == target_base or len(vendor) > 3 and vendor in self.target.lower():
                return True
        return self._name_looks_internal(name)

    # ── Archivos sensibles adicionales ────────────────────────────────────────

    def _check_exposed_sensitive_files(self):
        """Verifica archivos adicionales de CI/CD y configuración de build."""
        sensitive_ci_files = [
            (".github/workflows/deploy.yml", "GitHub Actions workflow"),
            (".github/workflows/build.yml", "GitHub Actions build"),
            (".travis.yml", "Travis CI config"),
            ("Jenkinsfile", "Jenkins pipeline"),
            (".circleci/config.yml", "CircleCI config"),
            ("docker-compose.yml", "Docker Compose"),
            ("docker-compose.prod.yml", "Docker Compose producción"),
            (".env.example", "Variables de entorno de ejemplo"),
            ("webpack.config.js", "Webpack config"),
            ("babel.config.js", "Babel config"),
            (".babelrc", "Babel config"),
        ]

        for base in self._base_urls:
            for filename, label in sensitive_ci_files:
                url = base.rstrip("/") + "/" + filename
                try:
                    time.sleep(self.delay)
                    r = self.session.get(url, timeout=TIMEOUT)
                    if r.status_code == 200 and len(r.text) > 50:
                        # Buscar secretos en CI/CD
                        secrets_found = []
                        for pattern, secret_label in [
                            (r'AWS_SECRET', "AWS Secret Key"),
                            (r'PRIVATE_KEY', "Clave privada"),
                            (r'DATABASE_URL', "URL de base de datos"),
                            (r'REGISTRY_TOKEN', "Token de registro"),
                            (r'NPM_TOKEN', "Token npm"),
                            (r'DOCKER_PASSWORD', "Contraseña Docker"),
                            (r'api_key\s*[:=]', "API Key"),
                        ]:
                            if re.search(pattern, r.text, re.IGNORECASE):
                                secrets_found.append(secret_label)

                        sev = "CRITICAL" if secrets_found else "MEDIUM"
                        self._add(
                            sev,
                            f"Archivo CI/CD expuesto — {filename}",
                            f"El archivo '{label}' está públicamente accesible. "
                            f"URL: {url}"
                            + (f"\nSecretos detectados: {', '.join(secrets_found)}"
                               if secrets_found else ""),
                            "Los archivos de CI/CD revelan la pipeline de despliegue, "
                            "secretos y tokens de autenticación, imágenes de contenedores "
                            "usadas, y pasos del proceso de build (útil para supply chain attacks).",
                            f"Bloquear el acceso público a '{filename}'. "
                            f"Usar variables de entorno cifradas en el CI/CD (secrets vault). "
                            f"Nunca incluir secretos en texto plano en archivos de configuración."
                        )
                        print(f"  [{sev}] CI/CD expuesto: {url}")
                except Exception:
                    pass

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _build_base_urls(self) -> list:
        urls = []
        for host in self.recon_data.get("hosts", []):
            if host["estado"] != "up":
                continue
            for p in host["puertos"]:
                port = p["puerto"]
                svc = p["servicio"].lower()
                if "http" in svc or port in (80, 443, 8080, 8443, 8888):
                    proto = "https" if port in (443, 8443) else "http"
                    url = (f"{proto}://{self.target}:{port}"
                           if port not in (80, 443) else f"{proto}://{self.target}")
                    if url not in urls:
                        urls.append(url)
        return urls or [f"https://{self.target}"]

    def _add(self, severidad, nombre, descripcion, impacto, recomendacion):
        for f in self.findings:
            if f["nombre"] == nombre:
                return
        self.findings.append({
            "severidad": severidad, "tipo": "Supply Chain",
            "nombre": nombre, "descripcion": descripcion,
            "impacto": impacto, "recomendacion": recomendacion,
        })
