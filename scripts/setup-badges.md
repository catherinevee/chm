# Badge Setup Guide

This guide explains how to set up the badges in the README to show "passing" status.

## Required GitHub Secrets

To make the badges work properly, you need to set up the following secrets in your GitHub repository:

### 1. Trivy Security Scan
- Trivy is integrated directly into the GitHub Actions workflow
- No additional setup required - it runs automatically
- Results are uploaded to GitHub Security tab

### 2. FOSSA License Compliance
- Go to [FOSSA.com](https://fossa.com) and create an account
- Create a new project for your repository
- Get your API key from the project settings
- Add it as a repository secret named `FOSSA_API_KEY`

### 3. Codecov Code Coverage (Optional)
- Go to [Codecov.io](https://codecov.io) and create an account
- Connect your GitHub repository
- Get your upload token
- Add it as a repository secret named `CODECOV_TOKEN`

## Setting Up GitHub Secrets

1. Go to your GitHub repository: `https://github.com/cathe/chm2`
2. Click on "Settings" tab
3. In the left sidebar, click "Secrets and variables" → "Actions"
4. Click "New repository secret"
5. Add each secret with the name and value from above

## Badge Status

Once you've set up the secrets and pushed the code:

- **Build Status**: Will show "passing" when the CI/CD workflow runs successfully
- **Security Scan**: Shows "Trivy Scan" (static badge linking to workflow)
- **FOSSA Status**: Will show "passing" when license compliance check passes
- **License**: Always shows "MIT" (static badge)
- **Code Quality**: Shows "Black + Flake8 + MyPy" (static badge)

## Testing the Badges

1. Push your code to the `main` branch
2. The CI/CD workflow will automatically run
3. Check the Actions tab to see the workflow status
4. The badges should update within a few minutes

## Troubleshooting

If badges don't show "passing":

1. Check the Actions tab for failed workflows
2. Verify all required secrets are set
3. Ensure the repository URL in the badges matches your actual repository
4. Check that the workflow files are in the correct location (`.github/workflows/`)

## Current Badge URLs

- Build Status: `https://github.com/cathe/chm2/actions/workflows/ci-cd.yml/badge.svg`
- Security Scan: `https://img.shields.io/badge/Security-Trivy%20Scan-blue.svg`
- FOSSA Status: `https://app.fossa.com/api/projects/git%2Bgithub.com%2Fcathe%2Fchm.svg?type=shield`
- License: `https://img.shields.io/badge/License-MIT-yellow.svg`
- Code Quality: `https://img.shields.io/badge/Quality-Black%20%2B%20Flake8%20%2B%20MyPy-blue.svg`
