FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for comprehensive SNMP monitoring and network discovery
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    nmap \
    iputils-ping \
    net-tools \
    snmp \
    arping \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Run the discovery service with enhanced SNMP monitoring
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]
