#!/bin/bash
# CHM Production Deployment Script

set -e

# Configuration
PROJECT_NAME="chm"
ENVIRONMENT="production"
DOCKER_COMPOSE_FILE="docker-compose.yml"
ENV_FILE=".env"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    # Check if Docker Compose is installed
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    # Check if .env file exists
    if [[ ! -f "$ENV_FILE" ]]; then
        print_error "Environment file $ENV_FILE not found. Please copy env.example to .env and configure it."
        exit 1
    fi
    
    # Check if docker-compose.yml exists
    if [[ ! -f "$DOCKER_COMPOSE_FILE" ]]; then
        print_error "Docker Compose file $DOCKER_COMPOSE_FILE not found."
        exit 1
    fi
    
    print_success "Prerequisites check passed"
}

# Function to validate environment configuration
validate_environment() {
    print_status "Validating environment configuration..."
    
    # Source environment variables
    source "$ENV_FILE"
    
    # Check required environment variables
    REQUIRED_VARS=(
        "POSTGRES_PASSWORD"
        "REDIS_PASSWORD"
        "SECRET_KEY"
        "JWT_SECRET_KEY"
        "GRAFANA_PASSWORD"
    )
    
    for var in "${REQUIRED_VARS[@]}"; do
        if [[ -z "${!var}" ]] || [[ "${!var}" == "your_"* ]]; then
            print_error "Environment variable $var is not properly configured"
            exit 1
        fi
    done
    
    print_success "Environment configuration validated"
}

# Function to create necessary directories
create_directories() {
    print_status "Creating necessary directories..."
    
    # Create directories for volumes
    mkdir -p logs data reports models backups
    mkdir -p nginx/ssl
    mkdir -p monitoring/{prometheus,grafana/{dashboards,datasources},logstash/pipeline}
    
    # Set proper permissions
    chmod 755 logs data reports models backups
    chmod 700 nginx/ssl
    chmod 755 monitoring
    
    print_success "Directories created"
}

# Function to generate SSL certificates if not present
generate_ssl_certificates() {
    print_status "Checking SSL certificates..."
    
    if [[ ! -f "nginx/ssl/cert.pem" ]] || [[ ! -f "nginx/ssl/key.pem" ]]; then
        print_warning "SSL certificates not found. Generating self-signed certificates..."
        
        # Generate self-signed certificate
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout nginx/ssl/key.pem \
            -out nginx/ssl/cert.pem \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
        
        chmod 600 nginx/ssl/key.pem
        chmod 644 nginx/ssl/cert.pem
        
        print_warning "Self-signed certificates generated. Replace with trusted CA certificates in production!"
    else
        print_success "SSL certificates found"
    fi
}

# Function to build Docker images
build_images() {
    print_status "Building Docker images..."
    
    # Build the main application image
    docker-compose -f "$DOCKER_COMPOSE_FILE" build --no-cache chm-app
    
    print_success "Docker images built"
}

# Function to start services
start_services() {
    print_status "Starting services..."
    
    # Start services in order
    docker-compose -f "$DOCKER_COMPOSE_FILE" up -d postgres redis
    
    # Wait for database to be ready
    print_status "Waiting for database to be ready..."
    sleep 30
    
    # Start the main application
    docker-compose -f "$DOCKER_COMPOSE_FILE" up -d chm-app
    
    # Wait for application to be ready
    print_status "Waiting for application to be ready..."
    sleep 30
    
    # Start remaining services
    docker-compose -f "$DOCKER_COMPOSE_FILE" up -d nginx prometheus grafana elasticsearch kibana logstash
    
    print_success "Services started"
}

# Function to run database migrations
run_migrations() {
    print_status "Running database migrations..."
    
    # Wait for application to be ready
    sleep 10
    
    # Run migrations
    docker-compose -f "$DOCKER_COMPOSE_FILE" exec chm-app python -m alembic upgrade head
    
    print_success "Database migrations completed"
}

# Function to create initial data
create_initial_data() {
    print_status "Creating initial data..."
    
    # Create initial admin user
    docker-compose -f "$DOCKER_COMPOSE_FILE" exec chm-app python -c "
from services.auth_service import AuthService
from models.user import User
import asyncio

async def create_admin():
    auth_service = AuthService()
    await auth_service.create_user(
        username='admin',
        email='admin@chm.local',
        password='admin123',
        is_admin=True
    )
    print('Admin user created')

asyncio.run(create_admin())
"
    
    print_success "Initial data created"
}

# Function to check service health
check_health() {
    print_status "Checking service health..."
    
    # Check main application
    if curl -f http://localhost:8000/health &> /dev/null; then
        print_success "CHM Application is healthy"
    else
        print_error "CHM Application health check failed"
        return 1
    fi
    
    # Check Nginx
    if curl -f http://localhost/health &> /dev/null; then
        print_success "Nginx is healthy"
    else
        print_error "Nginx health check failed"
        return 1
    fi
    
    # Check Prometheus
    if curl -f http://localhost:9090/-/healthy &> /dev/null; then
        print_success "Prometheus is healthy"
    else
        print_error "Prometheus health check failed"
        return 1
    fi
    
    # Check Grafana
    if curl -f http://localhost:3000/api/health &> /dev/null; then
        print_success "Grafana is healthy"
    else
        print_error "Grafana health check failed"
        return 1
    fi
    
    print_success "All services are healthy"
}

# Function to display deployment information
display_deployment_info() {
    print_success "CHM Production Deployment Completed!"
    echo ""
    echo "Application URLs:"
    echo "  - Main Application: https://localhost"
    echo "  - API Documentation: https://localhost/docs"
    echo "  - Grafana Dashboard: http://localhost:3000"
    echo "  - Prometheus Metrics: http://localhost:9090"
    echo "  - Kibana Logs: http://localhost:5601"
    echo ""
    echo "Default Credentials:"
    echo "  - Admin User: admin / admin123"
    echo "  - Grafana: admin / (check .env file)"
    echo ""
    echo "Monitoring:"
    echo "  - Application Metrics: https://localhost/metrics"
    echo "  - Health Check: https://localhost/health"
    echo ""
    echo "Management Commands:"
    echo "  - View logs: docker-compose logs -f"
    echo "  - Stop services: docker-compose down"
    echo "  - Restart services: docker-compose restart"
    echo "  - Update services: docker-compose pull && docker-compose up -d"
    echo ""
    echo "Important Security Notes:"
    echo "  - Change default passwords immediately"
    echo "  - Replace self-signed SSL certificates with trusted CA certificates"
    echo "  - Configure firewall rules for your environment"
    echo "  - Set up regular backups"
    echo "  - Monitor logs for security events"
    echo ""
}

# Function to handle deployment errors
handle_error() {
    print_error "Deployment failed at step: $1"
    print_status "Cleaning up..."
    
    # Stop services
    docker-compose -f "$DOCKER_COMPOSE_FILE" down
    
    print_error "Deployment cleanup completed. Please check the logs and try again."
    exit 1
}

# Main deployment function
main() {
    echo "CHM Production Deployment Started"
    echo "====================================="
    echo ""
    
    # Set error trap
    trap 'handle_error "Unknown"' ERR
    
    # Execute deployment steps
    check_prerequisites
    validate_environment
    create_directories
    generate_ssl_certificates
    build_images
    start_services
    run_migrations
    create_initial_data
    check_health
    display_deployment_info
    
    echo ""
    print_success "CHM Production Deployment Completed Successfully!"
}

# Parse command line arguments
case "${1:-}" in
    "stop")
        print_status "Stopping CHM services..."
        docker-compose -f "$DOCKER_COMPOSE_FILE" down
        print_success "Services stopped"
        ;;
    "restart")
        print_status "Restarting CHM services..."
        docker-compose -f "$DOCKER_COMPOSE_FILE" restart
        print_success "Services restarted"
        ;;
    "logs")
        docker-compose -f "$DOCKER_COMPOSE_FILE" logs -f
        ;;
    "status")
        docker-compose -f "$DOCKER_COMPOSE_FILE" ps
        ;;
    "update")
        print_status "Updating CHM services..."
        docker-compose -f "$DOCKER_COMPOSE_FILE" pull
        docker-compose -f "$DOCKER_COMPOSE_FILE" up -d
        print_success "Services updated"
        ;;
    "backup")
        print_status "Creating backup..."
        docker-compose -f "$DOCKER_COMPOSE_FILE" exec postgres pg_dump -U chm_user chm_db > "backup_$(date +%Y%m%d_%H%M%S).sql"
        print_success "Backup created"
        ;;
    *)
        main
        ;;
esac
