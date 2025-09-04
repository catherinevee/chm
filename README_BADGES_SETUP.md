# CHM Badges Setup Guide

This guide explains how to set up and use the comprehensive badge system for the CHM (Catalyst Health Monitor) project.

## 🎯 Overview

The CHM project now includes a complete badge infrastructure that provides real-time status information for:
- **Build Status** - CI/CD pipeline status
- **Code Coverage** - Test coverage percentage
- **Code Quality** - Code quality grade (A-F)
- **Security** - Vulnerability scan status
- **Performance** - Performance metrics and benchmarks
- **Documentation** - Documentation quality and coverage
- **Community** - Contributing guidelines and support

## 🚀 Quick Start

### Option 1: Automated Setup (Recommended)
```bash
# Run the automated setup script
./scripts/quick_start.sh
```

### Option 2: Manual Setup
```bash
# Update GitHub username in all files
cd chm/scripts
python setup_external_services.py update-username YOUR_USERNAME

# Generate setup commands
python setup_external_services.py generate-setup

# Generate GitHub secrets script
python setup_external_services.py generate-secrets-script
```

## 📋 Prerequisites

- **GitHub Repository**: `username/chm` (public or with service access)
- **GitHub Actions**: Enabled
- **Python 3.9+**: For setup scripts
- **Git**: For version control
- **GitHub CLI** (optional): For automated secret management

## 🔧 External Services Required

### 1. Codecov (Code Coverage)
- **Purpose**: Track and display test coverage
- **Setup**: [https://codecov.io](https://codecov.io)
- **Required**: ✅ Yes
- **Badge**: Shows coverage percentage

### 2. Codacy (Code Quality)
- **Purpose**: Analyze code quality and provide grades
- **Setup**: [https://app.codacy.com](https://app.codacy.com)
- **Required**: ✅ Yes
- **Badge**: Shows quality grade (A-F)

### 3. Snyk (Security)
- **Purpose**: Scan for security vulnerabilities
- **Setup**: [https://snyk.io](https://snyk.io)
- **Required**: ✅ Yes
- **Badge**: Shows security status

### 4. Discord (Community)
- **Purpose**: Community chat and support
- **Setup**: Create Discord server
- **Required**: ❌ No (optional)
- **Badge**: Community invitation link

## 🛠️ Setup Process

### Step 1: Update Configuration
```bash
# Replace 'username' with your actual GitHub username
find . -type f -name "*.yml" -o -name "*.json" -o -name "*.md" | xargs sed -i 's/username/YOUR_USERNAME/g'
```

### Step 2: Set up External Services
Follow the detailed setup guide: [SETUP_EXTERNAL_SERVICES.md](SETUP_EXTERNAL_SERVICES.md)

### Step 3: Configure GitHub Secrets
```bash
# Using GitHub CLI
gh secret set SNYK_TOKEN --body "your-snyk-token"
gh secret set CODECOV_TOKEN --body "your-codecov-token"
gh secret set CODACY_PROJECT_TOKEN --body "your-codacy-token"

# Or manually via GitHub web interface
# Repository → Settings → Secrets and variables → Actions
```

### Step 4: Test the Pipeline
```bash
git add .
git commit -m "Configure CHM badges"
git push origin main
```

## 📁 File Structure

```
chm/
├── .github/
│   ├── workflows/
│   │   └── ci-cd.yml          # CI/CD pipeline
│   └── badges.json            # Badge configuration
├── scripts/
│   ├── setup_external_services.py  # Setup automation
│   ├── generate_badges.py          # Badge generation
│   ├── calculate_quality_score.py  # Quality scoring
│   ├── check_api_docs.py           # Documentation checking
│   └── quick_start.sh              # Automated setup
├── backend/
│   ├── tests/                      # Test suite
│   └── pytest.ini                 # Test configuration
├── frontend/
│   ├── package.json                # Frontend dependencies
│   ├── .eslintrc.js               # Linting configuration
│   └── .prettierrc.json           # Formatting configuration
├── .pre-commit-config.yaml         # Pre-commit hooks
├── Makefile                        # Development commands
├── requirements-dev.txt            # Development dependencies
├── SETUP_EXTERNAL_SERVICES.md      # Detailed setup guide
├── DEPLOYMENT_CHECKLIST.md         # Deployment checklist
└── README.md                       # Main README with badges
```

## 🎮 Available Commands

### Makefile Commands
```bash
# Development
make install          # Install dependencies
make test            # Run all tests
make test-coverage   # Run tests with coverage
make lint            # Run linting
make format          # Format code
make security        # Run security scans

# Quality Assurance
make quality-score   # Calculate quality score
make badges          # Generate/update badges
make docs            # Build documentation

# CI/CD
make ci-backend      # Run backend CI checks
make ci-frontend     # Run frontend CI checks
make ci-all          # Run all CI checks

# Deployment
make deploy-staging  # Deploy to staging
make docker-build    # Build Docker images
```

### Python Script Commands
```bash
# Setup and configuration
python scripts/setup_external_services.py interactive
python scripts/setup_external_services.py update-username YOUR_USERNAME
python scripts/setup_external_services.py validate-urls
python scripts/setup_external_services.py check-secrets

# Badge management
python scripts/generate_badges.py
python scripts/calculate_quality_score.py
python scripts/check_api_docs.py
```

## 🔍 Monitoring and Maintenance

### Daily Checks (First Week)
- Verify all badges are displaying
- Check GitHub Actions workflow status
- Monitor external service status

### Weekly Checks
- Review coverage trends
- Check quality grade changes
- Monitor security scan results

### Monthly Checks
- Verify API token validity
- Check service status and updates
- Review and update configurations

## 🚨 Troubleshooting

### Common Issues

**Badge not displaying:**
- Check if service is properly configured
- Verify repository is public or service has access
- Ensure API tokens are valid

**Workflow failures:**
- Check GitHub Secrets are properly configured
- Verify API tokens are not expired
- Review service-specific error logs

**Coverage not updating:**
- Verify Codecov token is correct
- Check if coverage reports are being generated
- Ensure coverage file path is correct

### Debug Commands
```bash
# Check workflow status
gh run list --workflow=ci-cd.yml

# View workflow logs
gh run view --log

# Validate badge URLs
python scripts/setup_external_services.py validate-urls

# Check required secrets
python scripts/setup_external_services.py check-secrets
```

## 📊 Expected Results

After successful setup:

### Badges Displaying
- **Build Status**: ✅ Green (passing) or ❌ Red (failing)
- **Code Coverage**: Percentage (e.g., 95%)
- **Code Quality**: Grade (A, B, C, D, or F)
- **Security**: Status (e.g., "No known vulnerabilities")

### Reports Accessible
- **Codecov**: Detailed coverage reports
- **Codacy**: Code quality analysis
- **Snyk**: Security vulnerability reports
- **GitHub Actions**: Complete CI/CD pipeline logs

### Automated Updates
- Badges update automatically with each commit
- Coverage percentages reflect current code state
- Quality grades update based on latest analysis

## 🔄 CI/CD Pipeline

The GitHub Actions workflow includes:

1. **Backend Testing**: Python linting, security, pytest with coverage
2. **Frontend Testing**: Node.js linting, formatting, Jest with coverage
3. **Docker Build**: Image building and Trivy vulnerability scanning
4. **Security Scan**: Snyk security analysis
5. **Performance Test**: Benchmarks and load testing
6. **Documentation**: Quality checks and builds
7. **Quality Score**: Overall project quality calculation
8. **Deployment**: Staging and production deployment

## 📚 Additional Resources

- [External Services Setup Guide](SETUP_EXTERNAL_SERVICES.md)
- [Deployment Checklist](DEPLOYMENT_CHECKLIST.md)
- [Badge Implementation Summary](badge_implementation_summary.md)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Codecov Documentation](https://docs.codecov.io/)
- [Codacy Documentation](https://docs.codacy.com/)
- [Snyk Documentation](https://docs.snyk.io/)

## 🆘 Support

If you encounter issues:

1. Check the troubleshooting section above
2. Review service-specific documentation
3. Check GitHub Actions logs for detailed error messages
4. Verify all secrets and configurations are correct
5. Run the interactive setup wizard: `python scripts/setup_external_services.py interactive`

## 🎯 Success Criteria

The setup is successful when:

1. **All required badges display correctly** with real-time data
2. **CI/CD pipeline runs successfully** on every push
3. **External services are properly integrated** and reporting
4. **Badges update automatically** with code changes
5. **All links point to correct reports** and dashboards
6. **Quality metrics are accurate** and up-to-date

---

**Note**: This badge system demonstrates genuine quality and capabilities, making CHM suitable for enterprise use and professional presentation. Every badge is backed by actual implementation and automated testing! 🚀
