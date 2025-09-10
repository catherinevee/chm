#!/bin/bash
# Kubernetes deployment script for CHM application

set -e

# Configuration
NAMESPACE="${NAMESPACE:-chm}"
ENVIRONMENT="${ENVIRONMENT:-production}"
KUBECTL="${KUBECTL:-kubectl}"
HELM="${HELM:-helm}"
DRY_RUN="${DRY_RUN:-false}"
DEPLOYMENT_METHOD="${DEPLOYMENT_METHOD:-kubectl}" # kubectl, kustomize, or helm

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_step "Checking prerequisites..."
    
    # Check kubectl
    if ! command -v $KUBECTL &> /dev/null; then
        log_error "kubectl is not installed"
        exit 1
    fi
    
    # Check cluster connection
    if ! $KUBECTL cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    # Check if namespace exists
    if ! $KUBECTL get namespace $NAMESPACE &> /dev/null; then
        log_warning "Namespace $NAMESPACE does not exist. Creating..."
        $KUBECTL create namespace $NAMESPACE
    fi
    
    log_info "Prerequisites check passed"
}

# Deploy using kubectl
deploy_kubectl() {
    log_step "Deploying with kubectl..."
    
    K8S_DIR="k8s"
    
    if [ ! -d "$K8S_DIR" ]; then
        log_error "Kubernetes manifests directory not found: $K8S_DIR"
        exit 1
    fi
    
    # Apply manifests in order
    MANIFESTS=(
        "namespace.yaml"
        "rbac.yaml"
        "network-policy.yaml"
        "postgres.yaml"
        "redis.yaml"
        "deployment.yaml"
        "celery.yaml"
        "ingress.yaml"
        "monitoring.yaml"
        "hpa.yaml"
        "pod-disruption-budget.yaml"
    )
    
    for manifest in "${MANIFESTS[@]}"; do
        if [ -f "$K8S_DIR/$manifest" ]; then
            log_info "Applying $manifest..."
            if [ "$DRY_RUN" = "true" ]; then
                $KUBECTL apply -f "$K8S_DIR/$manifest" --dry-run=client
            else
                $KUBECTL apply -f "$K8S_DIR/$manifest"
            fi
        else
            log_warning "Manifest not found: $manifest"
        fi
    done
}

# Deploy using Kustomize
deploy_kustomize() {
    log_step "Deploying with Kustomize..."
    
    K8S_DIR="k8s"
    
    if [ ! -f "$K8S_DIR/kustomization.yaml" ]; then
        log_error "Kustomization file not found"
        exit 1
    fi
    
    # Apply environment-specific overlay if exists
    if [ -d "$K8S_DIR/overlays/$ENVIRONMENT" ]; then
        log_info "Using environment overlay: $ENVIRONMENT"
        KUSTOMIZE_DIR="$K8S_DIR/overlays/$ENVIRONMENT"
    else
        KUSTOMIZE_DIR="$K8S_DIR"
    fi
    
    if [ "$DRY_RUN" = "true" ]; then
        log_info "Running dry-run..."
        $KUBECTL kustomize $KUSTOMIZE_DIR | $KUBECTL apply --dry-run=client -f -
    else
        log_info "Applying Kustomize configuration..."
        $KUBECTL apply -k $KUSTOMIZE_DIR
    fi
}

# Deploy using Helm
deploy_helm() {
    log_step "Deploying with Helm..."
    
    CHART_DIR="helm/chm"
    RELEASE_NAME="chm"
    
    if [ ! -d "$CHART_DIR" ]; then
        log_error "Helm chart not found: $CHART_DIR"
        exit 1
    fi
    
    # Check if Helm is installed
    if ! command -v $HELM &> /dev/null; then
        log_error "Helm is not installed"
        exit 1
    fi
    
    # Update dependencies
    log_info "Updating Helm dependencies..."
    $HELM dependency update $CHART_DIR
    
    # Set values file based on environment
    VALUES_FILE="$CHART_DIR/values-$ENVIRONMENT.yaml"
    if [ ! -f "$VALUES_FILE" ]; then
        VALUES_FILE="$CHART_DIR/values.yaml"
    fi
    
    if [ "$DRY_RUN" = "true" ]; then
        log_info "Running Helm dry-run..."
        $HELM upgrade --install $RELEASE_NAME $CHART_DIR \
            --namespace $NAMESPACE \
            --values $VALUES_FILE \
            --dry-run --debug
    else
        log_info "Installing/Upgrading Helm release..."
        $HELM upgrade --install $RELEASE_NAME $CHART_DIR \
            --namespace $NAMESPACE \
            --values $VALUES_FILE \
            --wait --timeout 10m
    fi
}

# Wait for deployment
wait_for_deployment() {
    log_step "Waiting for deployment to be ready..."
    
    # Wait for main app
    log_info "Waiting for CHM application..."
    $KUBECTL rollout status deployment/chm-app -n $NAMESPACE --timeout=5m
    
    # Wait for database
    log_info "Waiting for PostgreSQL..."
    $KUBECTL wait --for=condition=ready pod -l app=postgres -n $NAMESPACE --timeout=5m
    
    # Wait for Redis
    log_info "Waiting for Redis..."
    $KUBECTL wait --for=condition=ready pod -l app=redis -n $NAMESPACE --timeout=5m
    
    # Wait for Celery workers
    log_info "Waiting for Celery workers..."
    $KUBECTL rollout status deployment/celery-worker -n $NAMESPACE --timeout=5m
    
    log_info "All components are ready!"
}

# Verify deployment
verify_deployment() {
    log_step "Verifying deployment..."
    
    # Check pod status
    log_info "Pod status:"
    $KUBECTL get pods -n $NAMESPACE
    
    # Check services
    log_info "Services:"
    $KUBECTL get services -n $NAMESPACE
    
    # Check ingress
    log_info "Ingress:"
    $KUBECTL get ingress -n $NAMESPACE
    
    # Test health endpoint
    log_info "Testing health endpoint..."
    POD=$($KUBECTL get pod -n $NAMESPACE -l app=chm,component=backend -o jsonpath='{.items[0].metadata.name}')
    if [ -n "$POD" ]; then
        $KUBECTL exec -n $NAMESPACE $POD -- curl -s http://localhost:8000/health || true
    fi
    
    log_info "Deployment verification complete"
}

# Show access information
show_access_info() {
    log_step "Access Information"
    
    # Get ingress URL
    INGRESS_HOST=$($KUBECTL get ingress -n $NAMESPACE chm-ingress -o jsonpath='{.spec.rules[0].host}' 2>/dev/null || echo "Not configured")
    
    echo ""
    echo "========================================="
    echo "CHM Deployment Complete!"
    echo "========================================="
    echo "Namespace: $NAMESPACE"
    echo "Environment: $ENVIRONMENT"
    echo ""
    echo "Access URLs:"
    echo "  API: https://$INGRESS_HOST"
    echo "  Metrics: https://$INGRESS_HOST/metrics"
    echo ""
    echo "Port Forwarding (for local access):"
    echo "  kubectl port-forward -n $NAMESPACE service/chm-service 8000:8000"
    echo ""
    echo "View logs:"
    echo "  kubectl logs -n $NAMESPACE deployment/chm-app"
    echo ""
    echo "========================================="
}

# Main deployment flow
main() {
    log_info "CHM Kubernetes Deployment Script"
    log_info "Environment: $ENVIRONMENT"
    log_info "Namespace: $NAMESPACE"
    log_info "Deployment Method: $DEPLOYMENT_METHOD"
    
    if [ "$DRY_RUN" = "true" ]; then
        log_warning "Running in DRY-RUN mode"
    fi
    
    # Check prerequisites
    check_prerequisites
    
    # Deploy based on method
    case $DEPLOYMENT_METHOD in
        "kubectl")
            deploy_kubectl
            ;;
        "kustomize")
            deploy_kustomize
            ;;
        "helm")
            deploy_helm
            ;;
        *)
            log_error "Unknown deployment method: $DEPLOYMENT_METHOD"
            exit 1
            ;;
    esac
    
    # Only wait and verify if not dry-run
    if [ "$DRY_RUN" != "true" ]; then
        wait_for_deployment
        verify_deployment
        show_access_info
    fi
    
    log_info "Deployment completed successfully!"
}

# Run main function
main