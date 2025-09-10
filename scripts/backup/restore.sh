#!/bin/bash
# CHM Restore Script - Disaster recovery and restore procedures

set -e

# Configuration
BACKUP_DIR="${BACKUP_DIR:-/backups}"
RESTORE_POINT="${1:-latest}"
ENCRYPTION_KEY="${ENCRYPTION_KEY:-}"
S3_BUCKET="${S3_BUCKET:-}"
AZURE_CONTAINER="${AZURE_CONTAINER:-}"
GCS_BUCKET="${GCS_BUCKET:-}"

# Colors
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

# Find backup to restore
find_backup() {
    log_section "Finding Backup to Restore"
    
    if [ "${RESTORE_POINT}" = "latest" ]; then
        # Find latest backup
        BACKUP_FILE=$(ls -t "${BACKUP_DIR}"/chm_backup_*.tar.gz 2>/dev/null | head -n1)
        
        if [ -z "${BACKUP_FILE}" ]; then
            # Try to download from cloud
            download_from_cloud_latest
        fi
    else
        # Use specified backup
        BACKUP_FILE="${BACKUP_DIR}/${RESTORE_POINT}"
        
        if [ ! -f "${BACKUP_FILE}" ]; then
            # Try to download from cloud
            download_from_cloud "${RESTORE_POINT}"
        fi
    fi
    
    if [ ! -f "${BACKUP_FILE}" ]; then
        log_error "Backup file not found: ${BACKUP_FILE}"
        exit 1
    fi
    
    log_info "Using backup: ${BACKUP_FILE}"
}

# Download backup from cloud storage
download_from_cloud() {
    local backup_name=$1
    
    log_info "Attempting to download backup from cloud storage..."
    
    # Download from S3
    if [ -n "${S3_BUCKET}" ]; then
        log_info "Downloading from S3..."
        aws s3 cp "s3://${S3_BUCKET}/backups/${backup_name}" "${BACKUP_DIR}/${backup_name}"
        BACKUP_FILE="${BACKUP_DIR}/${backup_name}"
        return
    fi
    
    # Download from Azure
    if [ -n "${AZURE_CONTAINER}" ]; then
        log_info "Downloading from Azure..."
        az storage blob download \
            --container-name "${AZURE_CONTAINER}" \
            --name "backups/${backup_name}" \
            --file "${BACKUP_DIR}/${backup_name}"
        BACKUP_FILE="${BACKUP_DIR}/${backup_name}"
        return
    fi
    
    # Download from GCS
    if [ -n "${GCS_BUCKET}" ]; then
        log_info "Downloading from GCS..."
        gsutil cp "gs://${GCS_BUCKET}/backups/${backup_name}" "${BACKUP_DIR}/${backup_name}"
        BACKUP_FILE="${BACKUP_DIR}/${backup_name}"
        return
    fi
}

# Download latest backup from cloud
download_from_cloud_latest() {
    log_info "Finding latest backup in cloud storage..."
    
    # Get latest from S3
    if [ -n "${S3_BUCKET}" ]; then
        latest=$(aws s3 ls "s3://${S3_BUCKET}/backups/" | grep "chm_backup_" | sort | tail -n1 | awk '{print $4}')
        if [ -n "${latest}" ]; then
            download_from_cloud "${latest}"
            return
        fi
    fi
    
    # Get latest from Azure
    if [ -n "${AZURE_CONTAINER}" ]; then
        latest=$(az storage blob list \
            --container-name "${AZURE_CONTAINER}" \
            --prefix "backups/chm_backup_" \
            --query "[-1].name" -o tsv | basename)
        if [ -n "${latest}" ]; then
            download_from_cloud "${latest}"
            return
        fi
    fi
    
    # Get latest from GCS
    if [ -n "${GCS_BUCKET}" ]; then
        latest=$(gsutil ls "gs://${GCS_BUCKET}/backups/chm_backup_*" | sort | tail -n1 | basename)
        if [ -n "${latest}" ]; then
            download_from_cloud "${latest}"
            return
        fi
    fi
}

# Verify backup integrity
verify_backup() {
    log_section "Verifying Backup Integrity"
    
    # Check if checksum file exists
    if [ -f "${BACKUP_FILE}.sha256" ]; then
        log_info "Verifying checksum..."
        sha256sum -c "${BACKUP_FILE}.sha256"
        log_info "Checksum verification passed"
    else
        log_warning "No checksum file found, skipping verification"
    fi
}

# Extract backup
extract_backup() {
    log_section "Extracting Backup"
    
    RESTORE_DIR="${BACKUP_DIR}/restore_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "${RESTORE_DIR}"
    
    # Decrypt if encrypted
    if [ -n "${ENCRYPTION_KEY}" ]; then
        log_info "Decrypting backup..."
        openssl enc -aes-256-cbc \
            -d \
            -in "${BACKUP_FILE}" \
            -out "${RESTORE_DIR}/decrypted.tar.gz" \
            -pass pass:"${ENCRYPTION_KEY}"
        
        tar -xzf "${RESTORE_DIR}/decrypted.tar.gz" -C "${RESTORE_DIR}"
        rm "${RESTORE_DIR}/decrypted.tar.gz"
    else
        tar -xzf "${BACKUP_FILE}" -C "${RESTORE_DIR}"
    fi
    
    # Find extracted directory
    EXTRACTED_DIR=$(find "${RESTORE_DIR}" -maxdepth 1 -type d -name "chm_backup_*" | head -n1)
    
    if [ -z "${EXTRACTED_DIR}" ]; then
        log_error "Failed to find extracted backup directory"
        exit 1
    fi
    
    log_info "Backup extracted to: ${EXTRACTED_DIR}"
}

# Restore PostgreSQL database
restore_postgres() {
    log_section "Restoring PostgreSQL Database"
    
    DB_HOST="${DB_HOST:-localhost}"
    DB_PORT="${DB_PORT:-5432}"
    DB_NAME="${DB_NAME:-chm_db}"
    DB_USER="${DB_USER:-chm_user}"
    DB_PASSWORD="${DB_PASSWORD:-chm_password}"
    
    export PGPASSWORD="${DB_PASSWORD}"
    
    # Check if dump file exists
    if [ ! -f "${EXTRACTED_DIR}/postgres_${DB_NAME}.dump" ]; then
        log_warning "PostgreSQL dump not found in backup"
        return
    fi
    
    # Create backup of current database
    log_info "Creating backup of current database..."
    pg_dump \
        -h "${DB_HOST}" \
        -p "${DB_PORT}" \
        -U "${DB_USER}" \
        -d "${DB_NAME}" \
        --no-password \
        --format=custom \
        --file="${BACKUP_DIR}/pre_restore_${DB_NAME}_$(date +%Y%m%d_%H%M%S).dump" || true
    
    # Drop and recreate database
    log_info "Recreating database ${DB_NAME}..."
    psql \
        -h "${DB_HOST}" \
        -p "${DB_PORT}" \
        -U "${DB_USER}" \
        -d postgres \
        --no-password \
        -c "DROP DATABASE IF EXISTS ${DB_NAME};"
    
    psql \
        -h "${DB_HOST}" \
        -p "${DB_PORT}" \
        -U "${DB_USER}" \
        -d postgres \
        --no-password \
        -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};"
    
    # Restore roles if available
    if [ -f "${EXTRACTED_DIR}/postgres_roles.sql" ]; then
        log_info "Restoring database roles..."
        psql \
            -h "${DB_HOST}" \
            -p "${DB_PORT}" \
            -U "${DB_USER}" \
            -d postgres \
            --no-password \
            -f "${EXTRACTED_DIR}/postgres_roles.sql" || true
    fi
    
    # Restore database
    log_info "Restoring database from backup..."
    pg_restore \
        -h "${DB_HOST}" \
        -p "${DB_PORT}" \
        -U "${DB_USER}" \
        -d "${DB_NAME}" \
        --no-password \
        --verbose \
        --no-owner \
        --no-privileges \
        "${EXTRACTED_DIR}/postgres_${DB_NAME}.dump"
    
    unset PGPASSWORD
    
    log_info "PostgreSQL restore completed"
}

# Restore Redis data
restore_redis() {
    log_section "Restoring Redis Data"
    
    REDIS_HOST="${REDIS_HOST:-localhost}"
    REDIS_PORT="${REDIS_PORT:-6379}"
    REDIS_PASSWORD="${REDIS_PASSWORD:-}"
    
    if [ ! -f "${EXTRACTED_DIR}/redis_dump.rdb" ]; then
        log_warning "Redis dump not found in backup"
        return
    fi
    
    # Stop Redis to replace dump file
    log_info "Stopping Redis..."
    if command -v systemctl &> /dev/null; then
        sudo systemctl stop redis || true
    else
        sudo service redis stop || true
    fi
    
    # Backup current Redis data
    if [ -f /var/lib/redis/dump.rdb ]; then
        sudo cp /var/lib/redis/dump.rdb "/var/lib/redis/dump.rdb.pre_restore_$(date +%Y%m%d_%H%M%S)"
    fi
    
    # Copy new dump file
    log_info "Copying Redis dump file..."
    sudo cp "${EXTRACTED_DIR}/redis_dump.rdb" /var/lib/redis/dump.rdb
    sudo chown redis:redis /var/lib/redis/dump.rdb
    
    # Start Redis
    log_info "Starting Redis..."
    if command -v systemctl &> /dev/null; then
        sudo systemctl start redis
    else
        sudo service redis start
    fi
    
    # Verify Redis is running
    sleep 2
    if [ -n "${REDIS_PASSWORD}" ]; then
        redis-cli -h "${REDIS_HOST}" -p "${REDIS_PORT}" -a "${REDIS_PASSWORD}" ping
    else
        redis-cli -h "${REDIS_HOST}" -p "${REDIS_PORT}" ping
    fi
    
    log_info "Redis restore completed"
}

# Restore Kubernetes resources
restore_kubernetes() {
    log_section "Restoring Kubernetes Resources"
    
    if [ ! -d "${EXTRACTED_DIR}/kubernetes" ]; then
        log_warning "Kubernetes backup not found"
        return
    fi
    
    if ! command -v kubectl &> /dev/null; then
        log_warning "kubectl not found, skipping Kubernetes restore"
        return
    fi
    
    NAMESPACE="${NAMESPACE:-chm}"
    
    # Create namespace if it doesn't exist
    kubectl create namespace "${NAMESPACE}" 2>/dev/null || true
    
    # Restore resources in order
    RESOURCES=(
        "serviceaccounts"
        "roles"
        "rolebindings"
        "configmaps"
        "secrets"
        "persistentvolumeclaims"
        "services"
        "deployments"
        "statefulsets"
        "horizontalpodautoscalers"
        "poddisruptionbudgets"
        "networkpolicies"
        "ingresses"
    )
    
    for resource in "${RESOURCES[@]}"; do
        if [ -f "${EXTRACTED_DIR}/kubernetes/${resource}.yaml" ]; then
            log_info "Restoring ${resource}..."
            kubectl apply -f "${EXTRACTED_DIR}/kubernetes/${resource}.yaml" -n "${NAMESPACE}" || true
        fi
    done
    
    log_info "Kubernetes restore completed"
}

# Restore application files
restore_application() {
    log_section "Restoring Application Files"
    
    APP_DIR="${APP_DIR:-/app}"
    
    if [ ! -f "${EXTRACTED_DIR}/application.tar.gz" ]; then
        log_warning "Application backup not found"
        return
    fi
    
    # Backup current application
    if [ -d "${APP_DIR}" ]; then
        log_info "Backing up current application..."
        tar -czf "${BACKUP_DIR}/pre_restore_app_$(date +%Y%m%d_%H%M%S).tar.gz" -C "${APP_DIR}" .
    fi
    
    # Extract application files
    log_info "Restoring application files..."
    mkdir -p "${APP_DIR}"
    tar -xzf "${EXTRACTED_DIR}/application.tar.gz" -C "${APP_DIR}"
    
    log_info "Application restore completed"
}

# Restore volumes
restore_volumes() {
    log_section "Restoring Volumes"
    
    # Restore audit logs
    if [ -f "${EXTRACTED_DIR}/audit_logs.tar.gz" ]; then
        log_info "Restoring audit logs..."
        mkdir -p /app/logs
        tar -xzf "${EXTRACTED_DIR}/audit_logs.tar.gz" -C /app/logs
    fi
    
    # Restore application logs
    if [ -f "${EXTRACTED_DIR}/app_logs.tar.gz" ]; then
        log_info "Restoring application logs..."
        mkdir -p /app/logs
        tar -xzf "${EXTRACTED_DIR}/app_logs.tar.gz" -C /app/logs
    fi
    
    # Restore uploads
    if [ -f "${EXTRACTED_DIR}/uploads.tar.gz" ]; then
        log_info "Restoring uploaded files..."
        mkdir -p /app
        tar -xzf "${EXTRACTED_DIR}/uploads.tar.gz" -C /app
    fi
    
    log_info "Volume restore completed"
}

# Verify restore
verify_restore() {
    log_section "Verifying Restore"
    
    # Check PostgreSQL
    log_info "Checking PostgreSQL..."
    export PGPASSWORD="${DB_PASSWORD}"
    psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -c "SELECT COUNT(*) FROM information_schema.tables;" || log_warning "PostgreSQL verification failed"
    unset PGPASSWORD
    
    # Check Redis
    log_info "Checking Redis..."
    redis-cli -h "${REDIS_HOST}" -p "${REDIS_PORT}" ping || log_warning "Redis verification failed"
    
    # Check Kubernetes
    if command -v kubectl &> /dev/null; then
        log_info "Checking Kubernetes resources..."
        kubectl get all -n "${NAMESPACE}" || log_warning "Kubernetes verification failed"
    fi
    
    log_info "Restore verification completed"
}

# Cleanup
cleanup() {
    log_section "Cleaning Up"
    
    if [ -n "${RESTORE_DIR}" ] && [ -d "${RESTORE_DIR}" ]; then
        log_info "Removing temporary restore directory..."
        rm -rf "${RESTORE_DIR}"
    fi
    
    log_info "Cleanup completed"
}

# Main restore process
main() {
    log_section "Starting CHM Restore Process"
    
    # Find backup to restore
    find_backup
    
    # Verify backup
    verify_backup
    
    # Extract backup
    extract_backup
    
    # Read metadata
    if [ -f "${EXTRACTED_DIR}/metadata.json" ]; then
        log_info "Backup metadata:"
        cat "${EXTRACTED_DIR}/metadata.json"
    fi
    
    # Confirm restore
    echo -e "${YELLOW}WARNING: This will restore from backup and may overwrite current data!${NC}"
    read -p "Do you want to continue? (yes/no): " confirm
    if [ "${confirm}" != "yes" ]; then
        log_info "Restore cancelled"
        cleanup
        exit 0
    fi
    
    # Perform restore
    restore_postgres
    restore_redis
    restore_kubernetes
    restore_application
    restore_volumes
    
    # Verify restore
    verify_restore
    
    # Cleanup
    cleanup
    
    log_section "Restore Completed Successfully"
    log_info "System restored from backup: ${BACKUP_FILE}"
}

# Run main function
main "$@"