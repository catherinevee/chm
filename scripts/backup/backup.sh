#!/bin/bash
# CHM Backup Script - Comprehensive backup solution for CHM application

set -e

# Configuration
BACKUP_DIR="${BACKUP_DIR:-/backups}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="chm_backup_${TIMESTAMP}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
S3_BUCKET="${S3_BUCKET:-}"
AZURE_CONTAINER="${AZURE_CONTAINER:-}"
GCS_BUCKET="${GCS_BUCKET:-}"
ENCRYPTION_KEY="${ENCRYPTION_KEY:-}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1" >&2
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_section() {
    echo -e "${BLUE}[=====]${NC} $1 ${BLUE}[=====]${NC}"
}

# Create backup directory
create_backup_dir() {
    log_section "Creating Backup Directory"
    
    FULL_BACKUP_DIR="${BACKUP_DIR}/${BACKUP_NAME}"
    mkdir -p "${FULL_BACKUP_DIR}"
    
    log_info "Backup directory created: ${FULL_BACKUP_DIR}"
}

# Backup PostgreSQL Database
backup_postgres() {
    log_section "Backing up PostgreSQL Database"
    
    # Get database credentials
    DB_HOST="${DB_HOST:-localhost}"
    DB_PORT="${DB_PORT:-5432}"
    DB_NAME="${DB_NAME:-chm_db}"
    DB_USER="${DB_USER:-chm_user}"
    DB_PASSWORD="${DB_PASSWORD:-chm_password}"
    
    # Export password for pg_dump
    export PGPASSWORD="${DB_PASSWORD}"
    
    # Create database backup
    log_info "Dumping database ${DB_NAME}..."
    pg_dump \
        -h "${DB_HOST}" \
        -p "${DB_PORT}" \
        -U "${DB_USER}" \
        -d "${DB_NAME}" \
        --no-password \
        --verbose \
        --format=custom \
        --compress=9 \
        --file="${FULL_BACKUP_DIR}/postgres_${DB_NAME}.dump"
    
    # Also create SQL format for easier inspection
    pg_dump \
        -h "${DB_HOST}" \
        -p "${DB_PORT}" \
        -U "${DB_USER}" \
        -d "${DB_NAME}" \
        --no-password \
        --format=plain \
        --file="${FULL_BACKUP_DIR}/postgres_${DB_NAME}.sql"
    
    # Backup database roles and permissions
    pg_dumpall \
        -h "${DB_HOST}" \
        -p "${DB_PORT}" \
        -U "${DB_USER}" \
        --no-password \
        --roles-only \
        --file="${FULL_BACKUP_DIR}/postgres_roles.sql"
    
    unset PGPASSWORD
    
    log_info "PostgreSQL backup completed"
}

# Backup Redis Data
backup_redis() {
    log_section "Backing up Redis Data"
    
    REDIS_HOST="${REDIS_HOST:-localhost}"
    REDIS_PORT="${REDIS_PORT:-6379}"
    REDIS_PASSWORD="${REDIS_PASSWORD:-}"
    
    # Trigger Redis BGSAVE
    log_info "Triggering Redis background save..."
    if [ -n "${REDIS_PASSWORD}" ]; then
        redis-cli -h "${REDIS_HOST}" -p "${REDIS_PORT}" -a "${REDIS_PASSWORD}" BGSAVE
    else
        redis-cli -h "${REDIS_HOST}" -p "${REDIS_PORT}" BGSAVE
    fi
    
    # Wait for background save to complete
    log_info "Waiting for Redis save to complete..."
    while [ $(redis-cli -h "${REDIS_HOST}" -p "${REDIS_PORT}" LASTSAVE) -eq $(redis-cli -h "${REDIS_HOST}" -p "${REDIS_PORT}" LASTSAVE) ]; do
        sleep 1
    done
    
    # Copy Redis dump file
    if [ -f /var/lib/redis/dump.rdb ]; then
        cp /var/lib/redis/dump.rdb "${FULL_BACKUP_DIR}/redis_dump.rdb"
        log_info "Redis backup completed"
    else
        log_warning "Redis dump file not found at expected location"
    fi
}

# Backup Kubernetes Resources
backup_kubernetes() {
    log_section "Backing up Kubernetes Resources"
    
    NAMESPACE="${NAMESPACE:-chm}"
    
    # Check if kubectl is available
    if ! command -v kubectl &> /dev/null; then
        log_warning "kubectl not found, skipping Kubernetes backup"
        return
    fi
    
    # Create Kubernetes backup directory
    K8S_BACKUP_DIR="${FULL_BACKUP_DIR}/kubernetes"
    mkdir -p "${K8S_BACKUP_DIR}"
    
    # Backup all resources in namespace
    log_info "Backing up Kubernetes resources in namespace ${NAMESPACE}..."
    
    # List of resource types to backup
    RESOURCES=(
        "deployments"
        "statefulsets"
        "services"
        "configmaps"
        "secrets"
        "persistentvolumeclaims"
        "ingresses"
        "horizontalpodautoscalers"
        "poddisruptionbudgets"
        "networkpolicies"
        "serviceaccounts"
        "roles"
        "rolebindings"
    )
    
    for resource in "${RESOURCES[@]}"; do
        log_info "Backing up ${resource}..."
        kubectl get "${resource}" -n "${NAMESPACE}" -o yaml > "${K8S_BACKUP_DIR}/${resource}.yaml" 2>/dev/null || true
    done
    
    # Backup custom resources
    log_info "Backing up custom resources..."
    kubectl get crd -o yaml > "${K8S_BACKUP_DIR}/customresourcedefinitions.yaml" 2>/dev/null || true
    
    log_info "Kubernetes backup completed"
}

# Backup Application Files
backup_application() {
    log_section "Backing up Application Files"
    
    APP_DIR="${APP_DIR:-/app}"
    
    if [ -d "${APP_DIR}" ]; then
        log_info "Backing up application files from ${APP_DIR}..."
        
        # Create application backup
        tar -czf "${FULL_BACKUP_DIR}/application.tar.gz" \
            -C "${APP_DIR}" \
            --exclude='*.pyc' \
            --exclude='__pycache__' \
            --exclude='.venv' \
            --exclude='node_modules' \
            --exclude='.git' \
            .
        
        log_info "Application backup completed"
    else
        log_warning "Application directory ${APP_DIR} not found"
    fi
}

# Backup Persistent Volumes
backup_volumes() {
    log_section "Backing up Persistent Volumes"
    
    # Audit logs
    if [ -d "/app/logs/audit" ]; then
        log_info "Backing up audit logs..."
        tar -czf "${FULL_BACKUP_DIR}/audit_logs.tar.gz" -C /app/logs audit/
    fi
    
    # Application logs
    if [ -d "/app/logs" ]; then
        log_info "Backing up application logs..."
        tar -czf "${FULL_BACKUP_DIR}/app_logs.tar.gz" \
            -C /app/logs \
            --exclude='audit' \
            .
    fi
    
    # Uploaded files
    if [ -d "/app/uploads" ]; then
        log_info "Backing up uploaded files..."
        tar -czf "${FULL_BACKUP_DIR}/uploads.tar.gz" -C /app uploads/
    fi
    
    log_info "Volume backup completed"
}

# Create backup metadata
create_metadata() {
    log_section "Creating Backup Metadata"
    
    cat > "${FULL_BACKUP_DIR}/metadata.json" <<EOF
{
    "backup_name": "${BACKUP_NAME}",
    "timestamp": "${TIMESTAMP}",
    "date": "$(date -Iseconds)",
    "hostname": "$(hostname)",
    "backup_type": "full",
    "components": {
        "postgres": $([ -f "${FULL_BACKUP_DIR}/postgres_${DB_NAME}.dump" ] && echo "true" || echo "false"),
        "redis": $([ -f "${FULL_BACKUP_DIR}/redis_dump.rdb" ] && echo "true" || echo "false"),
        "kubernetes": $([ -d "${FULL_BACKUP_DIR}/kubernetes" ] && echo "true" || echo "false"),
        "application": $([ -f "${FULL_BACKUP_DIR}/application.tar.gz" ] && echo "true" || echo "false"),
        "volumes": $([ -f "${FULL_BACKUP_DIR}/audit_logs.tar.gz" ] && echo "true" || echo "false")
    },
    "environment": {
        "namespace": "${NAMESPACE:-chm}",
        "database": "${DB_NAME:-chm_db}",
        "app_version": "${APP_VERSION:-unknown}"
    }
}
EOF
    
    log_info "Metadata created"
}

# Compress backup
compress_backup() {
    log_section "Compressing Backup"
    
    cd "${BACKUP_DIR}"
    
    log_info "Creating compressed archive..."
    tar -czf "${BACKUP_NAME}.tar.gz" "${BACKUP_NAME}/"
    
    # Calculate checksum
    log_info "Calculating checksum..."
    sha256sum "${BACKUP_NAME}.tar.gz" > "${BACKUP_NAME}.tar.gz.sha256"
    
    # Encrypt if encryption key is provided
    if [ -n "${ENCRYPTION_KEY}" ]; then
        log_info "Encrypting backup..."
        openssl enc -aes-256-cbc \
            -salt \
            -in "${BACKUP_NAME}.tar.gz" \
            -out "${BACKUP_NAME}.tar.gz.enc" \
            -pass pass:"${ENCRYPTION_KEY}"
        
        # Remove unencrypted file
        rm "${BACKUP_NAME}.tar.gz"
        mv "${BACKUP_NAME}.tar.gz.enc" "${BACKUP_NAME}.tar.gz"
        
        log_info "Backup encrypted"
    fi
    
    # Remove uncompressed directory
    rm -rf "${BACKUP_NAME}/"
    
    log_info "Compression completed"
}

# Upload to cloud storage
upload_to_cloud() {
    log_section "Uploading to Cloud Storage"
    
    BACKUP_FILE="${BACKUP_DIR}/${BACKUP_NAME}.tar.gz"
    
    # Upload to AWS S3
    if [ -n "${S3_BUCKET}" ]; then
        log_info "Uploading to S3 bucket ${S3_BUCKET}..."
        aws s3 cp "${BACKUP_FILE}" "s3://${S3_BUCKET}/backups/${BACKUP_NAME}.tar.gz" \
            --storage-class STANDARD_IA
        aws s3 cp "${BACKUP_FILE}.sha256" "s3://${S3_BUCKET}/backups/${BACKUP_NAME}.tar.gz.sha256"
    fi
    
    # Upload to Azure Blob Storage
    if [ -n "${AZURE_CONTAINER}" ]; then
        log_info "Uploading to Azure container ${AZURE_CONTAINER}..."
        az storage blob upload \
            --container-name "${AZURE_CONTAINER}" \
            --name "backups/${BACKUP_NAME}.tar.gz" \
            --file "${BACKUP_FILE}"
    fi
    
    # Upload to Google Cloud Storage
    if [ -n "${GCS_BUCKET}" ]; then
        log_info "Uploading to GCS bucket ${GCS_BUCKET}..."
        gsutil cp "${BACKUP_FILE}" "gs://${GCS_BUCKET}/backups/${BACKUP_NAME}.tar.gz"
        gsutil cp "${BACKUP_FILE}.sha256" "gs://${GCS_BUCKET}/backups/${BACKUP_NAME}.tar.gz.sha256"
    fi
    
    log_info "Cloud upload completed"
}

# Clean old backups
cleanup_old_backups() {
    log_section "Cleaning Old Backups"
    
    log_info "Removing backups older than ${RETENTION_DAYS} days..."
    
    # Local cleanup
    find "${BACKUP_DIR}" -name "chm_backup_*.tar.gz" -type f -mtime +${RETENTION_DAYS} -delete
    find "${BACKUP_DIR}" -name "chm_backup_*.tar.gz.sha256" -type f -mtime +${RETENTION_DAYS} -delete
    
    # S3 cleanup
    if [ -n "${S3_BUCKET}" ]; then
        aws s3 ls "s3://${S3_BUCKET}/backups/" | while read -r line; do
            createDate=$(echo $line | awk '{print $1" "$2}')
            createDate=$(date -d "$createDate" +%s)
            olderThan=$(date -d "${RETENTION_DAYS} days ago" +%s)
            if [[ $createDate -lt $olderThan ]]; then
                fileName=$(echo $line | awk '{print $4}')
                if [[ $fileName == chm_backup_* ]]; then
                    aws s3 rm "s3://${S3_BUCKET}/backups/$fileName"
                fi
            fi
        done
    fi
    
    log_info "Cleanup completed"
}

# Send notification
send_notification() {
    local status=$1
    local message=$2
    
    # Slack notification
    if [ -n "${SLACK_WEBHOOK}" ]; then
        curl -X POST "${SLACK_WEBHOOK}" \
            -H 'Content-Type: application/json' \
            -d "{
                \"text\": \"CHM Backup ${status}\",
                \"attachments\": [{
                    \"color\": \"$([ \"$status\" = \"SUCCESS\" ] && echo \"good\" || echo \"danger\")\",
                    \"fields\": [{
                        \"title\": \"Backup Name\",
                        \"value\": \"${BACKUP_NAME}\",
                        \"short\": true
                    }, {
                        \"title\": \"Message\",
                        \"value\": \"${message}\",
                        \"short\": false
                    }]
                }]
            }"
    fi
    
    # Email notification
    if [ -n "${EMAIL_TO}" ]; then
        echo "${message}" | mail -s "CHM Backup ${status}: ${BACKUP_NAME}" "${EMAIL_TO}"
    fi
}

# Main backup process
main() {
    log_section "Starting CHM Backup Process"
    log_info "Backup name: ${BACKUP_NAME}"
    
    # Trap errors
    trap 'handle_error $? $LINENO' ERR
    
    # Create backup directory
    create_backup_dir
    
    # Perform backups
    backup_postgres
    backup_redis
    backup_kubernetes
    backup_application
    backup_volumes
    
    # Create metadata
    create_metadata
    
    # Compress backup
    compress_backup
    
    # Upload to cloud
    upload_to_cloud
    
    # Cleanup old backups
    cleanup_old_backups
    
    # Success notification
    log_section "Backup Completed Successfully"
    log_info "Backup saved to: ${BACKUP_DIR}/${BACKUP_NAME}.tar.gz"
    
    # Calculate backup size
    BACKUP_SIZE=$(du -h "${BACKUP_DIR}/${BACKUP_NAME}.tar.gz" | cut -f1)
    log_info "Backup size: ${BACKUP_SIZE}"
    
    send_notification "SUCCESS" "Backup ${BACKUP_NAME} completed successfully. Size: ${BACKUP_SIZE}"
}

# Error handler
handle_error() {
    local exit_code=$1
    local line_number=$2
    
    log_error "Backup failed at line ${line_number} with exit code ${exit_code}"
    send_notification "FAILURE" "Backup ${BACKUP_NAME} failed at line ${line_number} with exit code ${exit_code}"
    
    # Cleanup partial backup
    if [ -n "${FULL_BACKUP_DIR}" ] && [ -d "${FULL_BACKUP_DIR}" ]; then
        rm -rf "${FULL_BACKUP_DIR}"
    fi
    
    exit ${exit_code}
}

# Run main function
main "$@"