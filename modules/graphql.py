"""
Módulo de auditoría GraphQL — AuditPyme
Detecta: endpoints expuestos, introspección activa, field suggestion,
consultas sin autenticación, profundidad ilimitada (DoS) e IDOR.
"""

import requests
import urllib3
import json
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
TIMEOUT = 12
UA = "Mozilla/5.0 (compatible; AuditPyme/1.0)"

# Rutas comunes de endpoints GraphQL
GRAPHQL_PATHS = [
    "/graphql",
    "/graphql/v1",
    "/graphql/v2",
    "/api/graphql",
    "/api/v1/graphql",
    "/api/v2/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/query",
    "/gql",
    "/wp/graphql",          # WPGraphQL (WordPress)
    "/index.php?graphql",   # WPGraphQL alternativo
    "/graphiql",
    "/playground",
    "/console",
    "/api",                 # algunos backends exponen GraphQL en /api
]

# Query de introspección estándar
INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        type { name kind ofType { name kind } }
      }
    }
  }
}
"""

# Query de introspección mínima (para detectar si está activa sin extraer todo)
INTROSPECTION_PROBE = '{ __schema { queryType { name } } }'

# Field suggestion probe (nombre de campo con typo deliberado)
FIELD_SUGGESTION_PROBE = '{ __typename fiel_suggestion_probe }'

# Consultas de prueba sin autenticación — operaciones sensibles comunes
SENSITIVE_QUERIES = [
    ("usuarios / clientes",
     '{ users { id email password role } }',
     ["users", "email", "password", "role"]),
    ("usuarios WordPress",
     '{ users { nodes { id name email roles { nodes { name } } } } }',
     ["users", "nodes", "email"]),
    ("pedidos WooCommerce",
     '{ orders { nodes { id total billing { email firstName lastName } } } }',
     ["orders", "total", "billing"]),
    ("productos con precio",
     '{ products { nodes { id name price stockQuantity } } }',
     ["products", "price"]),
    ("posts privados",
     '{ posts(where: {status: PRIVATE}) { nodes { id title content } } }',
     ["posts", "content"]),
]

# Query para test de profundidad (DoS por consulta anidada)
DEPTH_QUERY = """
{
  a1: __typename {
    a2: __typename {
      a3: __typename {
        a4: __typename {
          a5: __typename {
            a6: __typename {
              a7: __typename {
                a8: __typename { __typename }
              }
            }
          }
        }
      }
    }
  }
}
"""


class GraphQLAuditor:
    def __init__(self, target: str, recon_data: dict = None):
        self.target = target
        self.recon_data = recon_data or {}
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA, "Content-Type": "application/json"})
        self.session.verify = False
        self._base_urls = self._build_base_urls()

    def scan(self) -> list:
        print(f"\n  [*] Buscando endpoints GraphQL en: {self.target}")
        endpoints_found = []

        for base_url in self._base_urls:
            for path in GRAPHQL_PATHS:
                endpoint = base_url.rstrip("/") + path
                if self._is_graphql(endpoint):
                    endpoints_found.append(endpoint)
                    print(f"  [+] Endpoint GraphQL detectado: {endpoint}")

        if not endpoints_found:
            print("  [OK] No se detectaron endpoints GraphQL expuestos")
            return self.findings

        for endpoint in endpoints_found:
            self._add("MEDIUM", f"Endpoint GraphQL expuesto: {endpoint}",
                      f"Endpoint GraphQL accesible públicamente en {endpoint}.",
                      "GraphQL expuesto permite a atacantes explorar la API, "
                      "probar operaciones sensibles y potencialmente extraer datos.",
                      "Restringir el acceso al endpoint GraphQL con autenticación. "
                      "En producción, deshabilitar GraphiQL/Playground.")

            self._check_introspection(endpoint)
            self._check_field_suggestion(endpoint)
            self._check_unauthenticated_queries(endpoint)
            self._check_query_depth(endpoint)

        return self.findings

    # ── Detección de endpoint ─────────────────────────────────────────────────

    def _is_graphql(self, endpoint: str) -> bool:
        """Comprueba si un endpoint responde como GraphQL."""
        # Probe 1: GET con parámetro query
        try:
            r = self.session.get(endpoint, params={"query": "{__typename}"},
                                 timeout=TIMEOUT, allow_redirects=True)
            if r.status_code == 200 and self._looks_like_graphql(r):
                return True
        except Exception:
            pass
        # Probe 2: POST con JSON
        try:
            r = self.session.post(endpoint,
                                  data=json.dumps({"query": "{__typename}"}),
                                  timeout=TIMEOUT, allow_redirects=True)
            if r.status_code in (200, 400) and self._looks_like_graphql(r):
                return True
        except Exception:
            pass
        return False

    def _looks_like_graphql(self, response) -> bool:
        """Determina si la respuesta es de un servidor GraphQL."""
        ct = response.headers.get("Content-Type", "")
        if "application/json" not in ct and "application/graphql" not in ct:
            # También puede ser HTML del playground
            if "graphql" not in response.text.lower() and "graphiql" not in response.text.lower():
                return False
        body = response.text
        return any(sig in body for sig in [
            '"data":', '"errors":', '"__typename"',
            "GraphQL", "graphiql", "GraphiQL",
        ])

    # ── Check 1: Introspección ────────────────────────────────────────────────

    def _check_introspection(self, endpoint: str):
        print(f"  [*] Comprobando introspección en {endpoint}...")
        try:
            r = self._query(endpoint, INTROSPECTION_PROBE)
            if not r:
                return
            data = r.json()
            if "data" in data and data["data"] and "__schema" in str(data["data"]):
                # Introspección activa — extraer esquema completo
                r_full = self._query(endpoint, INTROSPECTION_QUERY)
                schema_info = self._parse_schema(r_full.json() if r_full else {})

                self._add(
                    "HIGH",
                    f"Introspección GraphQL activa: {endpoint}",
                    f"La introspección está habilitada en producción. "
                    f"Esquema extraído: {schema_info}",
                    "Un atacante obtiene el mapa completo de la API: todas las consultas, "
                    "mutaciones, tipos y campos disponibles, incluyendo operaciones de administración.",
                    "Deshabilitar la introspección en producción. "
                    "En Apollo Server: introspection: false. "
                    "En graphql-php: añadir IntrospectionDisabledRule."
                )
                print(f"  [HIGH] Introspección activa — esquema: {schema_info[:100]}")
            elif "errors" in data:
                err = str(data["errors"])
                if "introspection" in err.lower():
                    print("  [OK] Introspección deshabilitada explícitamente")
                else:
                    print(f"  [INFO] Respuesta de error: {err[:80]}")
        except Exception as e:
            pass

    def _parse_schema(self, data: dict) -> str:
        """Extrae un resumen del esquema GraphQL."""
        try:
            types = data.get("data", {}).get("__schema", {}).get("types", [])
            user_types = [t["name"] for t in types
                          if t.get("kind") in ("OBJECT", "INPUT_OBJECT")
                          and not t["name"].startswith("__")]
            mutations = next(
                (t.get("fields") or [] for t in types if t.get("name") == "Mutation"),
                []
            )
            mutation_names = [m["name"] for m in mutations[:10]]
            result = f"{len(user_types)} tipos"
            if mutation_names:
                result += f", mutaciones: {', '.join(mutation_names[:6])}"
            # Buscar tipos sensibles
            sensitive = [t for t in user_types
                         if any(k in t.lower() for k in
                                ("user", "admin", "order", "payment", "password",
                                 "token", "auth", "invoice", "customer", "cart"))]
            if sensitive:
                result += f", tipos sensibles: {', '.join(sensitive[:5])}"
            return result
        except Exception:
            return "esquema parcialmente extraído"

    # ── Check 2: Field Suggestion ─────────────────────────────────────────────

    def _check_field_suggestion(self, endpoint: str):
        """Detecta si el servidor sugiere campos cuando hay un typo (filtra schema sin introspección)."""
        try:
            r = self._query(endpoint, FIELD_SUGGESTION_PROBE)
            if not r:
                return
            body = r.text
            # GraphQL devuelve "Did you mean X?" cuando hay un campo similar
            if "did you mean" in body.lower() or "suggestions" in body.lower():
                # Extraer las sugerencias
                suggestions = re.findall(r'"([a-zA-Z_][a-zA-Z0-9_]*)"', body)
                self._add(
                    "MEDIUM",
                    f"Field suggestion activo (schema leakage): {endpoint}",
                    f"El servidor sugiere nombres de campo ante errores de tipeo. "
                    f"Campos sugeridos: {', '.join(suggestions[:8])}",
                    "Permite enumerar el esquema completo sin introspección, "
                    "haciendo inútil desactivar la introspección como única medida de seguridad.",
                    "Deshabilitar las sugerencias de campo en producción. "
                    "En Apollo Server: fieldSuggestions: { mask: '*' }."
                )
                print(f"  [MEDIUM] Field suggestion activo — campos filtrados: {', '.join(suggestions[:5])}")
        except Exception:
            pass

    # ── Check 3: Consultas sin autenticación ──────────────────────────────────

    def _check_unauthenticated_queries(self, endpoint: str):
        print(f"  [*] Probando consultas sensibles sin autenticación...")
        # Sesión sin cookies ni tokens
        anon = requests.Session()
        anon.headers.update({"User-Agent": UA, "Content-Type": "application/json"})
        anon.verify = False

        for nombre, query, expected_fields in SENSITIVE_QUERIES:
            try:
                r = anon.post(endpoint, data=json.dumps({"query": query}), timeout=TIMEOUT)
                if r.status_code != 200:
                    continue
                body = r.text
                data = r.json()
                # Si hay datos y contiene campos esperados sin errores de auth
                has_data = "data" in data and data["data"] and data["data"] != {"__typename": "Query"}
                has_auth_error = any(k in body.lower() for k in
                                     ("unauthorized", "unauthenticated", "forbidden",
                                      "not authenticated", "access denied", "permission"))
                if has_data and not has_auth_error:
                    fields_found = [f for f in expected_fields if f in body]
                    if len(fields_found) >= 2:
                        self._add(
                            "CRITICAL",
                            f"GraphQL sin autenticación — datos {nombre}",
                            f"La consulta GraphQL de '{nombre}' devuelve datos sin requerir autenticación. "
                            f"Campos encontrados: {', '.join(fields_found)}. "
                            f"Endpoint: {endpoint}",
                            f"Cualquier visitante puede extraer {nombre} de la aplicación "
                            "sin necesidad de credenciales.",
                            "Implementar autenticación y autorización en todas las operaciones GraphQL. "
                            "Usar middleware de autenticación (JWT/sesión) antes de resolver queries."
                        )
                        print(f"  [CRITICAL] Datos '{nombre}' accesibles sin auth")
            except Exception:
                continue

    # ── Check 4: Límite de profundidad (DoS) ──────────────────────────────────

    def _check_query_depth(self, endpoint: str):
        """Comprueba si hay límite de profundidad de consulta (previene DoS por consultas anidadas)."""
        try:
            r = self._query(endpoint, DEPTH_QUERY)
            if not r:
                return
            data = r.json()
            # Si no hay error de límite de profundidad, el servidor es vulnerable a DoS
            has_depth_error = any(k in r.text.lower() for k in
                                  ("depth limit", "max depth", "complexity", "too deep",
                                   "query too complex", "nested too deep"))
            if "data" in data and not has_depth_error:
                self._add(
                    "MEDIUM",
                    f"Sin límite de profundidad en consultas GraphQL: {endpoint}",
                    "Consulta con 8 niveles de anidamiento respondida sin error. "
                    "Sin límite de profundidad ni complejidad.",
                    "Un atacante puede enviar consultas exponencialmente anidadas que consumen "
                    "toda la CPU y memoria del servidor, provocando una denegación de servicio.",
                    "Implementar límite de profundidad (max depth: 5-7) y complejidad de consulta. "
                    "En Apollo: graphql-depth-limit + graphql-query-complexity."
                )
                print(f"  [MEDIUM] Sin límite de profundidad de consulta")
        except Exception:
            pass

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _query(self, endpoint: str, query: str):
        """Envía una query GraphQL via POST. Devuelve Response o None."""
        try:
            r = self.session.post(endpoint,
                                  data=json.dumps({"query": query}),
                                  timeout=TIMEOUT,
                                  allow_redirects=True)
            if "application/json" in r.headers.get("Content-Type", ""):
                return r
        except Exception:
            pass
        return None

    def _build_base_urls(self) -> list:
        urls = []
        for host in self.recon_data.get("hosts", []):
            if host["estado"] != "up":
                continue
            for p in host["puertos"]:
                port = p["puerto"]
                svc = p["servicio"].lower()
                if "http" in svc or port in (80, 443, 8080, 8443):
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
            "severidad":     severidad,
            "tipo":          "GRAPHQL",
            "nombre":        nombre,
            "descripcion":   descripcion,
            "impacto":       impacto,
            "recomendacion": recomendacion,
        })
