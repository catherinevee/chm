# CHM Badge Setup Guide

This document provides complete setup instructions for CHM's dynamic status badges.

## Badge Status Overview

CHM uses 3 dynamic status badges:

1. **CI/CD Pipeline** - Shows build status
2. **Test Coverage** - Shows code coverage percentage  
3. **Security Scan** - Shows security scanning status

## Required Setup Steps

### 1. GitHub Repository Secrets

Add these secrets to your GitHub repository (`Settings > Secrets and variables > Actions`):

```bash
# Codecov integration
CODECOV_TOKEN=your_codecov_token_here

# Optional: Additional security tokens
SNYK_TOKEN=your_snyk_token_here
```

### 2. Codecov Setup

1. **Create Codecov Account**: 
   - Go to [codecov.io](https://codecov.io)
   - Sign up with GitHub account
   - Add your repository

2. **Get Codecov Token**:
   - Navigate to your repository on Codecov
   - Go to Settings > Repository Upload Token
   - Copy the token and add it to GitHub secrets as `CODECOV_TOKEN`

3. **Verify Configuration**:
   - The `codecov.yml` file is already configured
   - Coverage target is set to 70%

### 3. Badge URLs

Update README.md badge URLs if needed:

```markdown
# Current badges (already configured)
[![CI/CD Pipeline](https://github.com/catherinevee/chm/actions/workflows/main-ci.yml/badge.svg)](https://github.com/catherinevee/chm/actions/workflows/main-ci.yml)
[![Test Coverage](https://codecov.io/gh/catherinevee/chm/branch/main/graph/badge.svg)](https://codecov.io/gh/catherinevee/chm)
[![Security Scan](https://github.com/catherinevee/chm/actions/workflows/security.yml/badge.svg)](https://github.com/catherinevee/chm/actions/workflows/security.yml)
```

## Test Structure

The minimal test structure has been created:

```
tests/
├── __init__.py
├── conftest.py              # Test configuration
├── pytest.ini              # Pytest settings
├── test_basic.py           # Basic functionality tests
├── test_integration.py     # Integration tests
└── unit/
    ├── __init__.py
    └── test_models.py      # Unit tests for models
```

## Coverage Configuration

Coverage is configured via:

- `pyproject.toml` - Main coverage settings
- `codecov.yml` - Codecov-specific configuration
- Workflow files - CI/CD integration

## Expected Badge Status

After setup:

✅ **CI/CD Pipeline**: PASS (with minimal tests)
✅ **Test Coverage**: PASS (70%+ target with current code)  
✅ **Security Scan**: PASS (all security tools configured)

## Testing the Setup

1. **Run tests locally**:
```bash
# Install test dependencies
pip install pytest pytest-cov coverage

# Run tests
pytest tests/ -v

# Run with coverage
coverage run -m pytest tests/
coverage report
coverage xml
```

2. **Check workflows**:
   - Push changes to main branch
   - Check Actions tab in GitHub
   - Verify all workflows pass

3. **Verify badges**:
   - Wait for workflows to complete
   - Check README.md badges are showing correct status
   - Verify Codecov integration

## Troubleshooting

### CI/CD Pipeline Issues
- Check test dependencies in `chm_requirements.txt`
- Verify Python path in workflow
- Check for import errors

### Coverage Issues  
- Verify `CODECOV_TOKEN` secret is set
- Check `codecov.yml` configuration
- Ensure `coverage.xml` is generated

### Security Scan Issues
- Check Docker build in workflow
- Verify security tool dependencies
- Review security scan logs

## Files Created/Modified

✅ **Test Files**:
- `tests/__init__.py`
- `tests/conftest.py`
- `tests/pytest.ini`
- `tests/test_basic.py`
- `tests/test_integration.py`
- `tests/unit/__init__.py`
- `tests/unit/test_models.py`

✅ **Configuration Files**:
- `pyproject.toml` (coverage settings)
- `codecov.yml` (Codecov configuration)

✅ **Updated Workflow**:
- `.github/workflows/main-ci.yml` (improved error handling)

## Maintenance

- **Tests**: Add more tests as features are developed
- **Coverage**: Maintain 70%+ coverage target
- **Security**: Review security scan results regularly
- **Dependencies**: Keep test dependencies updated

## Badge URLs Reference

```markdown
# For different repository/organization, update these:
![CI/CD](https://github.com/YOUR_USERNAME/YOUR_REPO/actions/workflows/main-ci.yml/badge.svg)
![Coverage](https://codecov.io/gh/YOUR_USERNAME/YOUR_REPO/branch/main/graph/badge.svg)
![Security](https://github.com/YOUR_USERNAME/YOUR_REPO/actions/workflows/security.yml/badge.svg)
```

The badges should now work correctly with the minimal test infrastructure provided!