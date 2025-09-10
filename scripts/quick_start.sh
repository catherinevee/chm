#!/bin/bash

# CHM Badges Quick Start Script
# This script automates the initial setup process for CHM badges

set -e  # Exit on any error

echo " CHM Badges Quick Start Script"
echo "================================="

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

# Check if we're in the right directory
if [ ! -f "chm/README.md" ]; then
    print_error "This script must be run from the root directory of the project"
    exit 1
fi

print_status "Starting CHM badges setup..."

# Step 1: Check prerequisites
print_status "Checking prerequisites..."

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is required but not installed"
    exit 1
fi

# Check if git is available
if ! command -v git &> /dev/null; then
    print_error "Git is required but not installed"
    exit 1
fi

# Check if we're in a git repository
if [ ! -d ".git" ]; then
    print_error "This directory is not a git repository"
    exit 1
fi

print_success "Prerequisites check passed"

# Step 2: Get GitHub username
print_status "Getting GitHub username..."

# Try to get username from git config
GITHUB_USERNAME=$(git config --get user.name 2>/dev/null || echo "")

if [ -z "$GITHUB_USERNAME" ]; then
    read -p "Enter your GitHub username: " GITHUB_USERNAME
fi

if [ -z "$GITHUB_USERNAME" ]; then
    print_error "GitHub username is required"
    exit 1
fi

print_success "GitHub username: $GITHUB_USERNAME"

# Step 3: Update configuration files
print_status "Updating configuration files with your GitHub username..."

# Update all configuration files
find . -type f \( -name "*.yml" -o -name "*.json" -o -name "*.md" \) -exec sed -i "s/username/$GITHUB_USERNAME/g" {} \;

print_success "Configuration files updated"

# Step 4: Run the Python setup script
print_status "Running external services setup script..."

cd chm/scripts

if [ -f "setup_external_services.py" ]; then
    python3 setup_external_services.py update-username "$GITHUB_USERNAME"
    python3 setup_external_services.py generate-secrets-script
    python3 setup_external_services.py generate-setup
else
    print_error "Setup script not found"
    exit 1
fi

cd ../..

print_success "External services setup completed"

# Step 5: Generate badges
print_status "Generating badges in README..."

if [ -f "chm/scripts/generate_badges.py" ]; then
    cd chm/scripts
    python3 generate_badges.py
    cd ../..
    print_success "Badges generated in README"
else
    print_warning "Badge generator script not found - badges may not be displayed correctly"
fi

# Step 6: Check if GitHub CLI is available
print_status "Checking GitHub CLI availability..."

if command -v gh &> /dev/null; then
    print_success "GitHub CLI is available"
    
    # Check if authenticated
    if gh auth status &> /dev/null; then
        print_success "GitHub CLI is authenticated"
        
        # Offer to set up secrets
        read -p "Would you like to set up GitHub secrets now? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_status "Setting up GitHub secrets..."
            ./setup_github_secrets.sh
        fi
    else
        print_warning "GitHub CLI is not authenticated. Run 'gh auth login' to authenticate."
    fi
else
    print_warning "GitHub CLI is not installed. You'll need to set up secrets manually."
    print_status "Install GitHub CLI: https://cli.github.com/"
fi

# Step 7: Final instructions
echo
echo " CHM Badges Setup Complete!"
echo "=============================="
echo
echo "Next steps:"
echo "1. Set up external services:"
echo "   - Codecov: https://codecov.io"
echo "   - Codacy: https://app.codacy.com"
echo "   - Snyk: https://snyk.io"
echo
echo "2. Configure GitHub secrets:"
echo "   - SNYK_TOKEN"
echo "   - CODECOV_TOKEN"
echo "   - CODACY_PROJECT_TOKEN"
echo
echo "3. Test the setup:"
echo "   git add ."
echo "   git commit -m 'Configure CHM badges'"
echo "   git push origin main"
echo
echo "4. Monitor the CI/CD pipeline:"
echo "   - Go to Actions tab in your repository"
echo "   - Check that all jobs complete successfully"
echo "   - Verify badges are displaying correctly"
echo
echo " Documentation:"
echo "- Setup Guide: chm/SETUP_EXTERNAL_SERVICES.md"
echo "- Deployment Checklist: chm/DEPLOYMENT_CHECKLIST.md"
echo "- Badge Summary: chm/badge_implementation_summary.md"
echo
echo " Need help? Run: python3 chm/scripts/setup_external_services.py interactive"

# Make the setup script executable
if [ -f "setup_github_secrets.sh" ]; then
    chmod +x setup_github_secrets.sh
    print_success "GitHub secrets setup script is ready: ./setup_github_secrets.sh"
fi

print_success "Setup complete! "
