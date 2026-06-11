"""
Test unitario de subdomain takeover — simula DNS sin acceso real.
Prueba los dos vectores: CNAME dangling y HTTP fingerprint.
"""

from unittest.mock import patch, MagicMock
import socket
from modules.dns_enum import DNSEnumerator


def fake_resolve(fqdn, rtype, lifetime=5):
    """Simula registros CNAME para subdominios de test."""
    if rtype != "CNAME":
        raise Exception("no record")
    # shop → Shopify abandonado
    if fqdn == "shop.victima.com":
        m = MagicMock()
        m.target = "mi-tienda-abandonada.myshopify.com."
        return [m]
    # dev → GitHub Pages abandonado
    if fqdn == "dev.victima.com":
        m = MagicMock()
        m.target = "old-project.github.io."
        return [m]
    # api → subdominio normal (sin cloud, no debe disparar)
    raise Exception("no CNAME")


def fake_gethostbyname(host):
    """Simula que los destinos cloud NO resuelven (NXDOMAIN = dangling)."""
    if "myshopify.com" in host or "github.io" in host:
        raise socket.gaierror("NXDOMAIN")
    return "93.184.216.34"


class FakeDNS:
    class resolver:
        @staticmethod
        def resolve(fqdn, rtype, lifetime=5):
            return fake_resolve(fqdn, rtype, lifetime)


def run_test():
    print("=" * 60)
    print("  TEST — Subdomain Takeover Detection")
    print("=" * 60)

    d = DNSEnumerator("victima.com")

    with patch("socket.gethostbyname", side_effect=fake_gethostbyname):
        d._check_takeover(FakeDNS, ["shop", "dev", "api"])

    takeovers = [f for f in d.findings if f["tipo"] == "SUBDOMAIN TAKEOVER"]

    print(f"\nResultados:")
    print(f"  Takeovers detectados: {len(takeovers)}")
    for t in takeovers:
        print(f"\n  [{t['severidad']}] {t['nombre']}")
        print(f"  {t['descripcion'][:200]}")

    assert len(takeovers) == 2, f"ERROR: esperaba 2 takeovers, encontró {len(takeovers)}"
    nombres = [t["nombre"] for t in takeovers]
    assert any("shop.victima.com" in n for n in nombres), "ERROR: no detectó shop.victima.com"
    assert any("dev.victima.com" in n for n in nombres),  "ERROR: no detectó dev.victima.com"

    print("\n  [OK] Todos los tests pasaron")
    print("=" * 60)


if __name__ == "__main__":
    run_test()
