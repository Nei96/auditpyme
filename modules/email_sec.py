"""
Módulo de seguridad de email — AuditPyme
Comprueba SPF, DKIM (selectores comunes), DMARC, MTA-STS y MX.
No requiere acceso a la red del cliente — solo consultas DNS públicas.
"""

import socket

DKIM_SELECTORS = [
    "default", "google", "mail", "smtp", "dkim", "email",
    "k1", "k2", "s1", "s2", "selector1", "selector2",
    "mandrill", "mailchimp", "sendgrid", "amazonses",
    "protonmail", "zoho", "office365", "exchange",
    "cm", "pm", "mg", "sg", "mta",
]


class EmailSecChecker:
    def __init__(self, domain: str):
        self.domain = self._clean_domain(domain)
        self.findings = []

    def check(self) -> list:
        if not self.domain:
            return []

        try:
            import dns.resolver
            import dns.exception
            self._dns = dns
        except ImportError:
            print("  [!] dnspython no instalado. pip3 install dnspython")
            return []

        print(f"\n  [*] Analizando seguridad de email para: {self.domain}")

        self._check_mx()
        self._check_spf()
        self._check_dmarc()
        self._check_dkim()
        self._check_mta_sts()

        return self.findings

    def _check_mx(self):
        try:
            answers = self._dns.resolver.resolve(self.domain, "MX", lifetime=5)
            mx_list = sorted(answers, key=lambda r: r.preference)
            servers = [str(r.exchange).rstrip(".") for r in mx_list]
            print(f"  [MX] Servidores: {', '.join(servers[:3])}")
            self._add("INFO", "MX", "Servidores de correo",
                      f"Servidores MX: {', '.join(servers[:5])}", "")
        except Exception:
            self._add("HIGH", "MX", "Sin registros MX",
                      "No se encontraron servidores de correo para este dominio.",
                      "Verificar la configuración DNS del dominio.")
            print("  [WARN] No se encontraron registros MX")

    def _check_spf(self):
        spf_record = None
        try:
            answers = self._dns.resolver.resolve(self.domain, "TXT", lifetime=5)
            for r in answers:
                txt = str(r).strip('"')
                if txt.startswith("v=spf1"):
                    spf_record = txt
                    break
        except Exception:
            pass

        if not spf_record:
            self._add("HIGH", "SPF", "Registro SPF ausente",
                      "El dominio no tiene registro SPF. Cualquier servidor puede enviar emails "
                      "suplantando esta dirección — vector principal de phishing.",
                      "Crear registro TXT: v=spf1 include:<proveedor> -all")
            print("  [HIGH] SPF ausente — dominio vulnerable a spoofing")
            return

        print(f"  [SPF] {spf_record[:100]}")

        if "+all" in spf_record:
            self._add("CRITICAL", "SPF", "SPF permite cualquier servidor (+all)",
                      f"El registro SPF usa +all: cualquier servidor del mundo puede enviar "
                      f"emails como este dominio. Configuración extremadamente peligrosa.\nRegistro: {spf_record}",
                      "Cambiar +all por -all de inmediato.")
        elif "?all" in spf_record:
            self._add("MEDIUM", "SPF", "SPF en modo neutral (?all)",
                      f"El registro SPF usa ?all — no rechaza ni acepta explícitamente. "
                      f"Proporciona poca protección real.\nRegistro: {spf_record}",
                      "Cambiar ?all por -all para rechazar servidores no autorizados.")
        elif "~all" in spf_record:
            self._add("LOW", "SPF", "SPF en modo softfail (~all)",
                      f"El registro SPF usa ~all (softfail) — marca los emails sospechosos "
                      f"pero no los rechaza. Depende de que el receptor aplique la política.\nRegistro: {spf_record}",
                      "Considerar cambiar ~all por -all para protección estricta.")
        elif "-all" in spf_record:
            self._add("INFO", "SPF", "SPF configurado correctamente (-all)",
                      f"El registro SPF está en modo estricto: rechaza servidores no autorizados.\nRegistro: {spf_record}",
                      "")
            print("  [OK] SPF con -all correcto")

        # Demasiados lookups DNS en SPF
        lookups = sum(1 for term in spf_record.split()
                      if any(term.startswith(p) for p in ("include:", "a:", "mx:", "exists:", "redirect=")))
        if lookups > 10:
            self._add("MEDIUM", "SPF", f"SPF con demasiados lookups DNS ({lookups}/10)",
                      f"El registro SPF supera el límite de 10 lookups DNS — algunos clientes de "
                      f"correo lo rechazarán como inválido.",
                      "Simplificar el registro SPF o usar un servicio de aplanamiento SPF.")

    def _check_dmarc(self):
        dmarc_record = None
        try:
            answers = self._dns.resolver.resolve(f"_dmarc.{self.domain}", "TXT", lifetime=5)
            for r in answers:
                txt = str(r).strip('"')
                if txt.startswith("v=DMARC1"):
                    dmarc_record = txt
                    break
        except Exception:
            pass

        if not dmarc_record:
            self._add("HIGH", "DMARC", "Registro DMARC ausente",
                      "Sin DMARC, no hay política que indique a los receptores qué hacer con "
                      "emails que fallen SPF/DKIM. El dominio es vulnerable a phishing directo.",
                      "Crear registro TXT en _dmarc." + self.domain + " con al menos: v=DMARC1; p=quarantine; rua=mailto:dmarc@" + self.domain)
            print("  [HIGH] DMARC ausente")
            return

        print(f"  [DMARC] {dmarc_record[:120]}")

        if "p=none" in dmarc_record:
            self._add("MEDIUM", "DMARC", "DMARC en modo monitor (p=none)",
                      f"DMARC está configurado pero en p=none — solo monitoriza, no bloquea ni "
                      f"pone en cuarentena emails fraudulentos.\nRegistro: {dmarc_record}",
                      "Cambiar a p=quarantine o p=reject una vez verificado el tráfico legítimo.")
        elif "p=quarantine" in dmarc_record:
            self._add("LOW", "DMARC", "DMARC en cuarentena (p=quarantine)",
                      f"DMARC manda a spam los emails fraudulentos. Buen nivel, pero p=reject "
                      f"es el objetivo final.\nRegistro: {dmarc_record}",
                      "Evaluar migrar a p=reject cuando el tráfico legítimo esté estabilizado.")
            print("  [OK] DMARC en quarantine")
        elif "p=reject" in dmarc_record:
            self._add("INFO", "DMARC", "DMARC en modo rechazo total (p=reject)",
                      f"DMARC rechaza directamente los emails que no superen SPF/DKIM. "
                      f"Nivel máximo de protección.\nRegistro: {dmarc_record}", "")
            print("  [OK] DMARC en reject — protección máxima")

        if "rua=" not in dmarc_record:
            self._add("LOW", "DMARC", "DMARC sin dirección de informes (rua)",
                      "Sin rua= no recibirás informes agregados sobre quién intenta suplantar tu dominio.",
                      "Añadir rua=mailto:dmarc@" + self.domain + " para recibir informes.")

    def _check_dkim(self):
        print(f"  [*] Buscando selectores DKIM ({len(DKIM_SELECTORS)} candidatos)...")
        found = []

        for selector in DKIM_SELECTORS:
            record = f"{selector}._domainkey.{self.domain}"
            try:
                answers = self._dns.resolver.resolve(record, "TXT", lifetime=3)
                for r in answers:
                    txt = str(r).strip('"')
                    if "p=" in txt or "v=DKIM1" in txt:
                        found.append(selector)
                        print(f"  [DKIM] Selector encontrado: {selector}")
                        break
            except Exception:
                pass

        if not found:
            self._add("HIGH", "DKIM", "No se encontraron selectores DKIM",
                      f"No se detectó ningún registro DKIM en {len(DKIM_SELECTORS)} selectores comunes. "
                      f"Sin DKIM, los emails del dominio no pueden ser verificados criptográficamente.",
                      "Configurar DKIM en el servidor de correo y publicar el registro TXT correspondiente.")
            print("  [HIGH] DKIM no detectado")
        else:
            self._add("INFO", "DKIM", f"DKIM activo ({len(found)} selector(es))",
                      f"Selectores DKIM encontrados: {', '.join(found)}", "")
            print(f"  [OK] DKIM activo — selectores: {', '.join(found)}")

    def _check_mta_sts(self):
        try:
            answers = self._dns.resolver.resolve(f"_mta-sts.{self.domain}", "TXT", lifetime=5)
            for r in answers:
                txt = str(r).strip('"')
                if "v=STSv1" in txt:
                    self._add("INFO", "MTA-STS", "MTA-STS configurado",
                              f"El dominio tiene MTA-STS — fuerza conexiones TLS entre servidores de correo.\nRegistro: {txt}", "")
                    print("  [OK] MTA-STS configurado")
                    return
        except Exception:
            pass

        self._add("LOW", "MTA-STS", "MTA-STS no configurado",
                  "MTA-STS fuerza que los servidores de correo usen TLS al entregar emails. "
                  "Sin él, el tráfico SMTP puede ser interceptado (downgrade attack).",
                  "Implementar MTA-STS publicando _mta-sts." + self.domain + " y el archivo de política en https://mta-sts." + self.domain + "/.well-known/mta-sts.txt")

    def _add(self, severidad, tipo, nombre, descripcion, recomendacion):
        self.findings.append({
            "severidad":     severidad,
            "tipo":          tipo,
            "nombre":        nombre,
            "descripcion":   descripcion,
            "recomendacion": recomendacion,
        })

    def _clean_domain(self, target: str) -> str:
        try:
            socket.inet_aton(target)
            return None
        except socket.error:
            pass
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        parts = domain.split(".")
        return domain if len(parts) >= 2 else None
