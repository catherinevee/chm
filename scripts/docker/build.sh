#!/bin/bash
# Docker build script for CHM application

set -e

# Configuration
IMAGE_NAME="${IMAGE_NAME:-chm}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
REGISTRY="${REGISTRY:-}"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64}"
BUILD_TYPE="${BUILD_TYPE:-production}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    log_error "Docker is not installed"
    exit 1
fi

# Check if we're in the right directory
if [ ! -f "Dockerfile" ]; then
    log_error "Dockerfile not found. Please run this script from the CHM project root"
    exit 1
fi

# Build arguments
BUILD_ARGS=""
if [ -n "$HTTP_PROXY" ]; then
    BUILD_ARGS="$BUILD_ARGS --build-arg HTTP_PROXY=$HTTP_PROXY"
fi
if [ -n "$HTTPS_PROXY" ]; then
    BUILD_ARGS="$BUILD_ARGS --build-arg HTTPS_PROXY=$HTTPS_PROXY"
fi

# Full image name with registry
if [ -n "$REGISTRY" ]; then
    FULL_IMAGE_NAME="$REGISTRY/$IMAGE_NAME:$IMAGE_TAG"
else
    FULL_IMAGE_NAME="$IMAGE_NAME:$IMAGE_TAG"
fi

log_info "Building Docker image: $FULL_IMAGE_NAME"
log_info "Build type: $BUILD_TYPE"
log_info "Target platforms: $PLATFORMS"

# Enable Docker BuildKit
export DOCKER_BUILDKIT=1

# Build based on type
case $BUILD_TYPE in
    "production")
        log_info "Building production image..."
        docker build \
            --target production \
            --platform $PLATFORMS \
            --tag $FULL_IMAGE_NAME \
            --tag $IMAGE_NAME:latest \
            $BUILD_ARGS \
            --file Dockerfile \
            .
        ;;
    
    "development")
        log_info "Building development image..."
        docker build \
            --target development \
            --platform linux/amd64 \
            --tag $FULL_IMAGE_NAME-dev \
            $BUILD_ARGS \
            --file Dockerfile \
            .
        ;;
    
    "test")
        log_info "Building test image..."
        docker build \
            --target test \
            --platform linux/amd64 \
            --tag $FULL_IMAGE_NAME-test \
            $BUILD_ARGS \
            --file Dockerfile \
            .
        ;;
    
    *)
        log_error "Unknown build type: $BUILD_TYPE"
        exit 1
        ;;
esac

# Verify the build
if [ $? -eq 0 ]; then
    log_info "Docker image built successfully: $FULL_IMAGE_NAME"
    
    # Show image info
    docker images | grep $IMAGE_NAME
    
    # Run security scan if trivy is available
    if command -v trivy &> /dev/null; then
        log_info "Running security scan with Trivy..."
        trivy image --severity HIGH,CRITICAL $FULL_IMAGE_NAME
    else
        log_warning "Trivy not found. Skipping security scan."
    fi
    
    # Test the image
    log_info "Testing the image..."
    docker run --rm $FULL_IMAGE_NAME python -c "import fastapi; print('FastAPI imported successfully')"
    
    if [ $? -eq 0 ]; then
        log_info "Image test passed"
    else
        log_error "Image test failed"
        exit 1
    fi
else
    log_error "Docker build failed"
    exit 1
fi

# Push to registry if specified
if [ -n "$REGISTRY" ] && [ "$PUSH_IMAGE" = "true" ]; then
    log_info "Pushing image to registry: $REGISTRY"
    docker push $FULL_IMAGE_NAME
    
    if [ $? -eq 0 ]; then
        log_info "Image pushed successfully"
    else
        log_error "Failed to push image"
        exit 1
    fi
fi

log_info "Build completed successfully!"