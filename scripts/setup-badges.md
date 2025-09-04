# Badge Setup Guide

This guide explains how to set up the badges in the README to show "passing" status.

## Required GitHub Secrets

To make the badges work properly, you need to set up the following secrets in your GitHub repository:

### 1. Snyk Security Scan
- Go to [Snyk.io](https://snyk.io) and create an account
- Get your API token from the account settings
- Add it as a repository secret named `SNYK_TOKEN`

### 2. FOSSA License Compliance
- Go to [FOSSA.com](https://fossa.com) and create an account
- Create a new project for your repository
- Get your API key from the project settings
- Add it as a repository secret named `FOSSA_API_KEY`

### 3. Codecov (Optional)
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
- **Security Scan**: Will show "passing" when Snyk scan completes without high-severity issues
- **FOSSA Status**: Will show "passing" when license compliance check passes
- **License**: Always shows "MIT" (static badge)
- **Enterprise Ready**: Always shows "Production Ready" (static badge)

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
- Security Scan: `https://snyk.io/test/github/cathe/chm2/badge.svg`
- FOSSA Status: `https://app.fossa.com/api/projects/git%2Bgithub.com%2Fcathe%2Fchm2.svg?type=shield`
- License: `https://img.shields.io/badge/License-MIT-yellow.svg`
- Enterprise Ready: `https://img.shields.io/badge/Enterprise-Production%20Ready%20%2B%20SLA%20%2B%20Compliance%20%2B%20Support-purple.svg`
