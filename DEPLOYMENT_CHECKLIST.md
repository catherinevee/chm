# CHM Deployment Checklist

This checklist ensures all badges and external services are properly configured before deploying CHM to production.

## 🚀 Pre-Deployment Checklist

### 1. GitHub Configuration ✅
- [ ] Repository is public (or services have access)
- [ ] GitHub Actions are enabled
- [ ] Repository name matches: `username/chm`
- [ ] Default branch is set to `main`

### 2. External Services Setup ✅

#### Codecov
- [ ] Account created at [codecov.io](https://codecov.io)
- [ ] Repository added to Codecov
- [ ] Token obtained and added to GitHub Secrets as `CODECOV_TOKEN`
- [ ] Badge URL accessible: `https://codecov.io/gh/username/chm/branch/main/graph/badge.svg`

#### Codacy
- [ ] Account created at [app.codacy.com](https://app.codacy.com)
- [ ] Repository added to Codacy
- [ ] Project ID obtained from repository settings
- [ ] Badge URL updated in `.github/badges.json`
- [ ] Badge URL accessible: `https://api.codacy.com/project/badge/Grade/YOUR-PROJECT-ID`

#### Snyk
- [ ] Account created at [snyk.io](https://snyk.io)
- [ ] Repository added to Snyk
- [ ] API token obtained and added to GitHub Secrets as `SNYK_TOKEN`
- [ ] Badge URL accessible: `https://snyk.io/test/github/username/chm/badge.svg`

#### Discord (Optional)
- [ ] Discord server created
- [ ] Channels set up: `#general`, `#support`, `#development`
- [ ] Invite link created
- [ ] Badge URL updated in configuration

### 3. GitHub Secrets ✅
- [ ] `SNYK_TOKEN` - Snyk API token
- [ ] `CODECOV_TOKEN` - Codecov repository token
- [ ] `CODACY_PROJECT_TOKEN` - Codacy project token (if needed)

### 4. Configuration Files ✅
- [ ] `.github/badges.json` - Badge configuration updated
- [ ] `.github/workflows/ci-cd.yml` - CI/CD workflow configured
- [ ] `chm/README.md` - Badges section properly formatted
- [ ] All `username` placeholders replaced with actual GitHub username

### 5. Testing Infrastructure ✅
- [ ] Backend tests pass locally
- [ ] Frontend tests pass locally
- [ ] Performance tests configured
- [ ] Security scans configured
- [ ] Documentation quality checks configured

## 🔧 Setup Commands

### Quick Setup Script
```bash
# Run the interactive setup wizard
cd chm/scripts
python setup_external_services.py interactive

# Or run individual commands
python setup_external_services.py update-username YOUR_USERNAME
python setup_external_services.py validate-urls
python setup_external_services.py check-secrets
python setup_external_services.py generate-secrets-script
```

### Manual Setup
```bash
# Update GitHub username in all files
find . -type f -name "*.yml" -o -name "*.json" -o -name "*.md" | xargs sed -i 's/username/YOUR_USERNAME/g'

# Set up GitHub secrets (if you have gh CLI)
gh secret set SNYK_TOKEN --body "your-snyk-token"
gh secret set CODECOV_TOKEN --body "your-codecov-token"
gh secret set CODACY_PROJECT_TOKEN --body "your-codacy-token"

# Test the pipeline
git add .
git commit -m "Configure external services for badges"
git push origin main
```

## 🧪 Testing Checklist

### Local Testing
- [ ] Run `make test` - All tests pass
- [ ] Run `make lint` - No linting errors
- [ ] Run `make security` - Security scans pass
- [ ] Run `make docs` - Documentation builds successfully
- [ ] Run `make quality-score` - Quality score calculated

### CI/CD Pipeline Testing
- [ ] Push to `main` branch triggers workflow
- [ ] All jobs complete successfully
- [ ] Coverage reports generated and uploaded
- [ ] Security scans complete without errors
- [ ] Performance tests pass
- [ ] Documentation quality checks pass
- [ ] Quality score calculation completes

### Badge Verification
- [ ] Build status badge shows current status
- [ ] Code coverage badge displays percentage
- [ ] Code quality badge shows grade
- [ ] Security badge shows status
- [ ] All badges link to correct reports
- [ ] Badges update automatically with new commits

## 🚨 Common Issues & Solutions

### Badge Not Displaying
**Problem:** Badge shows as broken image or placeholder
**Solutions:**
- Verify service is properly configured
- Check if repository is public
- Ensure API tokens are valid
- Verify badge URLs are accessible

### Workflow Failures
**Problem:** GitHub Actions workflow fails
**Solutions:**
- Check GitHub Secrets are properly configured
- Verify API tokens are not expired
- Check service-specific error logs
- Ensure all required files exist

### Coverage Not Updating
**Problem:** Code coverage badge shows old data
**Solutions:**
- Verify Codecov token is correct
- Check if coverage reports are being generated
- Ensure coverage file path is correct in workflow
- Wait for Codecov to process reports (can take a few minutes)

### Security Scan Failures
**Problem:** Security scanning jobs fail
**Solutions:**
- Check Snyk token is valid
- Verify repository has access to Snyk
- Check if dependencies are accessible
- Review Snyk-specific error messages

## 📊 Expected Results

After successful deployment, you should see:

### Badges Displaying
- **Build Status:** ✅ Green (passing) or ❌ Red (failing)
- **Code Coverage:** Percentage (e.g., 95%)
- **Code Quality:** Grade (A, B, C, D, or F)
- **Security:** Status (e.g., "No known vulnerabilities")
- **License:** MIT license badge

### Reports Accessible
- **Codecov:** Detailed coverage reports with line-by-line analysis
- **Codacy:** Code quality analysis with specific recommendations
- **Snyk:** Security vulnerability reports with remediation steps
- **GitHub Actions:** Complete CI/CD pipeline logs and artifacts

### Automated Updates
- Badges update automatically with each commit
- Coverage percentages reflect current code state
- Quality grades update based on latest analysis
- Security status reflects current vulnerability state

## 🔄 Post-Deployment Monitoring

### Daily Checks (First Week)
- [ ] Verify all badges are displaying
- [ ] Check GitHub Actions workflow status
- [ ] Monitor external service status
- [ ] Verify badge accuracy

### Weekly Checks
- [ ] Review coverage trends
- [ ] Check quality grade changes
- [ ] Monitor security scan results
- [ ] Review performance metrics

### Monthly Checks
- [ ] Verify API token validity
- [ ] Check service status and updates
- [ ] Review and update configurations
- [ ] Monitor badge performance

## 🆘 Troubleshooting Commands

```bash
# Check workflow status
gh run list --workflow=ci-cd.yml

# View workflow logs
gh run view --log

# Check secrets (names only)
gh secret list

# Validate badge URLs
cd chm/scripts
python setup_external_services.py validate-urls

# Check required secrets
python setup_external_services.py check-secrets

# Generate setup commands
python setup_external_services.py generate-setup
```

## 📚 Additional Resources

- [External Services Setup Guide](SETUP_EXTERNAL_SERVICES.md)
- [Badge Implementation Summary](badge_implementation_summary.md)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Codecov Documentation](https://docs.codecov.io/)
- [Codacy Documentation](https://docs.codacy.com/)
- [Snyk Documentation](https://docs.snyk.io/)

## 🎯 Success Criteria

The deployment is considered successful when:

1. **All required badges display correctly** with real-time data
2. **CI/CD pipeline runs successfully** on every push
3. **External services are properly integrated** and reporting
4. **Badges update automatically** with code changes
5. **All links point to correct reports** and dashboards
6. **Quality metrics are accurate** and up-to-date

---

**Note:** This checklist should be completed before making CHM publicly available. All badges must be functional and displaying accurate information to maintain professional credibility.
