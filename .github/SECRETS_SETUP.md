# GitHub Secrets Setup Guide

This document lists all the GitHub secrets required for CHM's CI/CD pipelines to function properly.

## Required Secrets

### 1. FOSSA Integration
- **`FOSSA_API_KEY`**: Your FOSSA API key
  - Get it from: https://app.fossa.com/account/settings/integrations/api_tokens
  - Required for: Security and license scanning
  - Used in: `security-scan.yml`

### 2. Docker Hub
- **`DOCKER_USERNAME`**: Your Docker Hub username
  - Example: `catherinevee`
  - Required for: Publishing Docker images
  - Used in: `docker-publish.yml`

- **`DOCKER_PASSWORD`**: Your Docker Hub access token (not password)
  - Get it from: https://hub.docker.com/settings/security
  - Required for: Docker Hub authentication
  - Used in: `docker-publish.yml`

### 3. Codecov
- **`CODECOV_TOKEN`**: Your Codecov upload token
  - Get it from: https://app.codecov.io/gh/catherinevee/chm/settings
  - Required for: Code coverage reporting
  - Used in: `test-coverage.yml`

## Optional Secrets

### 4. Notification Services (if using)
- **`SLACK_WEBHOOK_URL`**: Slack incoming webhook URL
  - For build notifications to Slack
  
- **`DISCORD_WEBHOOK_URL`**: Discord webhook URL
  - For build notifications to Discord

### 5. Additional Services
- **`SENTRY_DSN`**: Sentry error tracking DSN
  - For error monitoring in production

- **`HONEYBADGER_API_KEY`**: Honeybadger API key
  - Alternative error tracking service

## How to Add Secrets

1. Go to your repository on GitHub
2. Click on **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**
4. Add the secret name and value
5. Click **Add secret**

## Setting Up Services

### FOSSA Setup
1. Sign up at https://fossa.com
2. Add your repository
3. Generate an API token
4. Add `FOSSA_API_KEY` to GitHub secrets

### Docker Hub Setup
1. Create account at https://hub.docker.com
2. Create repository `catherinevee/chm`
3. Generate access token (not password!)
4. Add `DOCKER_USERNAME` and `DOCKER_PASSWORD` to GitHub secrets

### Codecov Setup
1. Sign up at https://codecov.io with GitHub
2. Add your repository
3. Copy the upload token
4. Add `CODECOV_TOKEN` to GitHub secrets

## Verification

After adding all secrets, you can verify they're working by:

1. Running the security scan workflow:
   ```bash
   gh workflow run security-scan.yml
   ```

2. Running the Docker publish workflow:
   ```bash
   gh workflow run docker-publish.yml
   ```

3. Running the test coverage workflow:
   ```bash
   gh workflow run test-coverage.yml
   ```

## Security Notes

- Never commit secrets to the repository
- Use GitHub secrets for all sensitive values
- Rotate tokens regularly
- Use least-privilege access tokens where possible
- Enable 2FA on all service accounts

## Troubleshooting

If workflows are failing due to missing secrets:

1. Check the workflow logs for specific error messages
2. Verify secret names match exactly (case-sensitive)
3. Ensure tokens haven't expired
4. Check service account permissions
5. Verify the secret values don't have extra spaces or newlines

## Support

For issues with secrets setup:
- GitHub Actions: https://docs.github.com/en/actions/security-guides/encrypted-secrets
- FOSSA: https://docs.fossa.com/docs/api-reference
- Docker Hub: https://docs.docker.com/docker-hub/access-tokens/
- Codecov: https://docs.codecov.com/docs/quick-start