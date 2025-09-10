FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for comprehensive SNMP monitoring
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

# Copy requirements from root directory
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend application code
COPY backend/ .

# Create non-root user
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Run the application
CMD ["python", "servers/working_server.py"]
