#!/bin/bash
# CHM Production Security Hardening Script

set -e

echo "Starting CHM Production Security Hardening..."

# Function to check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        echo "ERROR: This script should not be run as root for security reasons"
        exit 1
    fi
}

# Function to create secure directories
create_secure_directories() {
    echo "Creating secure directories..."
    
    # Create application directories with proper permissions
    mkdir -p /app/{logs,data,reports,models,backups}
    chmod 755 /app
    chmod 750 /app/{logs,data,reports,models,backups}
    
    # Create SSL directory
    mkdir -p /etc/nginx/ssl
    chmod 700 /etc/nginx/ssl
    
    echo "Secure directories created"
}

# Function to generate secure SSL certificates
generate_ssl_certificates() {
    echo "Generating SSL certificates..."
    
    if [[ ! -f /etc/nginx/ssl/cert.pem ]] || [[ ! -f /etc/nginx/ssl/key.pem ]]; then
        # Generate self-signed certificate for development
        # In production, use certificates from a trusted CA
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /etc/nginx/ssl/key.pem \
            -out /etc/nginx/ssl/cert.pem \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=chm.local"
        
        chmod 600 /etc/nginx/ssl/key.pem
        chmod 644 /etc/nginx/ssl/cert.pem
        chown root:root /etc/nginx/ssl/*
        
        echo "SSL certificates generated"
    else
        echo "INFO: SSL certificates already exist"
    fi
}

# Function to configure firewall
configure_firewall() {
    echo "Configuring firewall..."
    
    # Check if ufw is available
    if command -v ufw &> /dev/null; then
        # Reset firewall rules
        ufw --force reset
        
        # Default policies
        ufw default deny incoming
        ufw default allow outgoing
        
        # Allow SSH (be careful with this in production)
        ufw allow 22/tcp
        
        # Allow HTTP and HTTPS
        ufw allow 80/tcp
        ufw allow 443/tcp
        
        # Allow internal Docker network
        ufw allow from 172.20.0.0/16
        
        # Enable firewall
        ufw --force enable
        
        echo "Firewall configured"
    else
        echo "WARNING: UFW not available, skipping firewall configuration"
    fi
}

# Function to secure system configuration
secure_system_config() {
    echo "Securing system configuration..."
    
    # Disable unnecessary services
    systemctl disable --now bluetooth 2>/dev/null || true
    systemctl disable --now cups 2>/dev/null || true
    systemctl disable --now avahi-daemon 2>/dev/null || true
    
    # Configure kernel parameters for security
    cat >> /etc/sysctl.conf << EOF

# CHM Security Hardening
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
EOF
    
    # Apply sysctl changes
    sysctl -p
    
    echo "System configuration secured"
}

# Function to configure log rotation
configure_log_rotation() {
    echo "Configuring log rotation..."
    
    cat > /etc/logrotate.d/chm << EOF
/app/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 chm chm
    postrotate
        /bin/kill -USR1 \$(cat /var/run/nginx.pid 2>/dev/null) 2>/dev/null || true
    endscript
}
EOF
    
    echo "Log rotation configured"
}

# Function to set up monitoring
setup_monitoring() {
    echo "Setting up monitoring..."
    
    # Create monitoring directories
    mkdir -p /app/monitoring/{prometheus,grafana,alerts}
    
    # Set proper permissions
    chmod 755 /app/monitoring
    chmod 750 /app/monitoring/{prometheus,grafana,alerts}
    
    echo "Monitoring setup completed"
}

# Function to create backup script
create_backup_script() {
    echo "Creating backup script..."
    
    cat > /app/scripts/backup.sh << 'EOF'
#!/bin/bash
# CHM Database Backup Script

set -e

BACKUP_DIR="/app/backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="chm_backup_${DATE}.sql"
RETENTION_DAYS=30

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

# Create database backup
echo "Creating database backup..."
pg_dump -h postgres -U chm_user -d chm_db > "$BACKUP_DIR/$BACKUP_FILE"

# Compress backup
gzip "$BACKUP_DIR/$BACKUP_FILE"

# Remove old backups
find "$BACKUP_DIR" -name "chm_backup_*.sql.gz" -mtime +$RETENTION_DAYS -delete

echo "Backup completed: $BACKUP_FILE.gz"
EOF
    
    chmod +x /app/scripts/backup.sh
    
    echo "Backup script created"
}

# Function to create security monitoring script
create_security_monitoring() {
    echo "Creating security monitoring script..."
    
    cat > /app/scripts/security-monitor.sh << 'EOF'
#!/bin/bash
# CHM Security Monitoring Script

LOG_FILE="/app/logs/security-monitor.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

# Function to log security events
log_security_event() {
    echo "[$DATE] $1" >> "$LOG_FILE"
}

# Check for failed login attempts
check_failed_logins() {
    FAILED_ATTEMPTS=$(grep "Failed password" /var/log/auth.log 2>/dev/null | wc -l)
    if [ "$FAILED_ATTEMPTS" -gt 10 ]; then
        log_security_event "WARNING: High number of failed login attempts: $FAILED_ATTEMPTS"
    fi
}

# Check for suspicious network connections
check_network_connections() {
    SUSPICIOUS_CONNECTIONS=$(netstat -an | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -1 | awk '{print $1}')
    if [ "$SUSPICIOUS_CONNECTIONS" -gt 100 ]; then
        log_security_event "WARNING: High number of connections from single IP: $SUSPICIOUS_CONNECTIONS"
    fi
}

# Check disk usage
check_disk_usage() {
    DISK_USAGE=$(df /app | tail -1 | awk '{print $5}' | sed 's/%//')
    if [ "$DISK_USAGE" -gt 80 ]; then
        log_security_event "WARNING: High disk usage: ${DISK_USAGE}%"
    fi
}

# Run security checks
check_failed_logins
check_network_connections
check_disk_usage

echo "Security monitoring completed at $DATE"
EOF
    
    chmod +x /app/scripts/security-monitor.sh
    
    echo "Security monitoring script created"
}

# Function to create systemd service for security monitoring
create_security_service() {
    echo "Creating security monitoring service..."
    
    cat > /etc/systemd/system/chm-security-monitor.service << EOF
[Unit]
Description=CHM Security Monitor
After=network.target

[Service]
Type=oneshot
User=chm
Group=chm
ExecStart=/app/scripts/security-monitor.sh
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    # Create timer for the service
    cat > /etc/systemd/system/chm-security-monitor.timer << EOF
[Unit]
Description=Run CHM Security Monitor every 5 minutes
Requires=chm-security-monitor.service

[Timer]
OnCalendar=*:0/5
Persistent=true

[Install]
WantedBy=timers.target
EOF
    
    # Enable and start the timer
    systemctl daemon-reload
    systemctl enable chm-security-monitor.timer
    systemctl start chm-security-monitor.timer
    
    echo "Security monitoring service created"
}

# Main execution
main() {
    echo "CHM Production Security Hardening Started"
    echo "=============================================="
    
    check_root
    create_secure_directories
    generate_ssl_certificates
    configure_firewall
    secure_system_config
    configure_log_rotation
    setup_monitoring
    create_backup_script
    create_security_monitoring
    create_security_service
    
    echo ""
    echo "CHM Production Security Hardening Completed!"
    echo "=============================================="
    echo ""
    echo "Security measures implemented:"
    echo "  - Secure directory structure"
    echo "  - SSL certificates generated"
    echo "  - Firewall configured"
    echo "  - System parameters hardened"
    echo "  - Log rotation configured"
    echo "  - Monitoring setup"
    echo "  - Backup system created"
    echo "  - Security monitoring enabled"
    echo ""
    echo "Important next steps:"
    echo "  1. Update SSL certificates with trusted CA certificates"
    echo "  2. Configure external monitoring and alerting"
    echo "  3. Set up regular security updates"
    echo "  4. Test backup and restore procedures"
    echo "  5. Review and customize security policies"
    echo ""
}

# Run main function
main "$@"
