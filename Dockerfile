FROM python:3.12-slim

LABEL maintainer="AuditPyme" \
      version="1.0" \
      description="Herramienta de auditoría de ciberseguridad para pymes"

# Dependencias del sistema
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    whois \
    dnsutils \
    # WeasyPrint deps
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-xlib-2.0-0 \
    libffi8 \
    libcairo2 \
    fonts-liberation \
    fonts-dejavu \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /auditpyme

# Instalar dependencias Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código fuente
COPY main.py .
COPY modules/ modules/

# Volumen para los informes generados
VOLUME ["/informes"]

# Necesita privilegios para nmap -O (detección de OS)
# Se ejecuta con --cap-add=NET_RAW NET_ADMIN en docker run
ENTRYPOINT ["python3", "main.py"]
CMD ["--help"]
