# External Services Setup Guide for CHM

This guide will help you set up all the external services required for the CHM project badges to display accurate information.

## 🚀 Quick Start

1. **Update GitHub Configuration**: Replace `username` with your actual GitHub username in all files
2. **Set up Codecov**: For code coverage badges
3. **Set up Codacy**: For code quality badges  
4. **Set up Snyk**: For security scanning badges
5. **Configure GitHub Secrets**: Add required API tokens
6. **Test the Pipeline**: Run the CI/CD workflow

## 📋 Prerequisites

- GitHub repository: `username/chm`
- GitHub Actions enabled
- Admin access to repository settings

## 🔧 Step-by-Step Setup

### 1. Update GitHub Configuration

**Files to update:**
- `.github/badges.json` (replace `username` with your GitHub username)
- `.github/workflows/ci-cd.yml` (replace `username` with your GitHub username)
- `chm/README.md` (replace `username` with your GitHub username)

**Command to update all files:**
```bash
# Replace 'username' with your actual GitHub username
find . -type f -name "*.yml" -o -name "*.json" -o -name "*.md" | xargs sed -i 's/username/your-actual-username/g'
```

### 2. Set up Codecov

**Purpose:** Code coverage reporting and badges

**Steps:**
1. Go to [https://codecov.io](https://codecov.io)
2. Sign in with your GitHub account
3. Click "Add new repository"
4. Select `username/chm`
5. Copy the repository token from the setup page

**Configuration:**
- **Badge URL:** `https://codecov.io/gh/username/chm/branch/main/graph/badge.svg`
- **Report URL:** `https://codecov.io/gh/username/chm`
- **Token:** Add to GitHub Secrets as `CODECOV_TOKEN`

**GitHub Secret Setup:**
1. Go to your repository → Settings → Secrets and variables → Actions
2. Click "New repository secret"
3. Name: `CODECOV_TOKEN`
4. Value: Your Codecov token

### 3. Set up Codacy

**Purpose:** Code quality analysis and grading

**Steps:**
1. Go to [https://app.codacy.com](https://app.codacy.com)
2. Sign in with your GitHub account
3. Click "Add repository"
4. Select `username/chm`
5. Get your project ID from the repository settings

**Configuration:**
- **Badge URL:** `https://api.codacy.com/project/badge/Grade/YOUR-PROJECT-ID`
- **Report URL:** `https://app.codacy.com/gh/username/chm`
- **Project ID:** Found in repository settings

**Update Badge Configuration:**
```json
"quality": {
  "url": "https://api.codacy.com/project/badge/Grade/YOUR-ACTUAL-PROJECT-ID",
  "link": "https://app.codacy.com/gh/username/chm"
}
```

### 4. Set up Snyk

**Purpose:** Security vulnerability scanning

**Steps:**
1. Go to [https://snyk.io](https://snyk.io)
2. Sign in with your GitHub account
3. Click "Add project"
4. Select `username/chm`
5. Get your API token from account settings

**Configuration:**
- **Badge URL:** `https://snyk.io/test/github/username/chm/badge.svg`
- **Report URL:** `https://snyk.io/test/github/username/chm`
- **Token:** Add to GitHub Secrets as `SNYK_TOKEN`

**GitHub Secret Setup:**
1. Go to your repository → Settings → Secrets and variables → Actions
2. Click "New repository secret"
3. Name: `SNYK_TOKEN`
4. Value: Your Snyk API token

### 5. Set up Discord (Optional)

**Purpose:** Community chat and support

**Steps:**
1. Create a new Discord server
2. Set up channels: `#general`, `#support`, `#development`
3. Create an invite link
4. Update the badge configuration

**Configuration:**
```json
"discord": {
  "badge_url": "https://img.shields.io/badge/Discord-Join%20Community-blue.svg?logo=discord",
  "link": "https://discord.gg/YOUR-ACTUAL-INVITE-LINK"
}
```

### 6. Configure GitHub Secrets

**Required Secrets:**
```bash
SNYK_TOKEN=your-snyk-api-token
CODECOV_TOKEN=your-codecov-token
CODACY_PROJECT_TOKEN=your-codacy-project-token
```

**Setup Commands:**
```bash
# Add secrets via GitHub CLI (if you have it installed)
gh secret set SNYK_TOKEN --body "your-snyk-api-token"
gh secret set CODECOV_TOKEN --body "your-codecov-token"
gh secret set CODACY_PROJECT_TOKEN --body "your-codacy-project-token"
```

**Manual Setup:**
1. Go to repository → Settings → Secrets and variables → Actions
2. Add each secret individually

### 7. Test the Pipeline

**Run the CI/CD workflow:**
```bash
# Push to trigger workflow
git add .
git commit -m "Configure external services for badges"
git push origin main
```

**Monitor the workflow:**
1. Go to Actions tab in your repository
2. Check the "CHM CI/CD Pipeline" workflow
3. Verify all jobs complete successfully

## 🔍 Verification Checklist

- [ ] Codecov badge displays coverage percentage
- [ ] Codacy badge shows quality grade (A-F)
- [ ] Snyk badge shows security status
- [ ] Build status badge shows workflow status
- [ ] All badges link to correct reports
- [ ] GitHub Actions workflow completes successfully

## 🛠️ Troubleshooting

### Common Issues

**Badge not displaying:**
- Check if the service is properly configured
- Verify the badge URL is accessible
- Ensure the repository is public or the service has access

**Workflow failures:**
- Check GitHub Secrets are properly configured
- Verify API tokens are valid and not expired
- Check service-specific error logs

**Coverage not updating:**
- Ensure Codecov token is correct
- Check if coverage reports are being generated
- Verify the coverage file path in the workflow

### Debug Commands

```bash
# Check workflow status
gh run list --workflow=ci-cd.yml

# View workflow logs
gh run view --log

# Check secrets (names only, not values)
gh secret list
```

## 📊 Expected Results

After successful setup, you should see:

- **Code Coverage Badge:** Shows current coverage percentage
- **Code Quality Badge:** Displays quality grade (A-F)
- **Security Badge:** Indicates vulnerability status
- **Build Status Badge:** Shows CI/CD pipeline status
- **All badges link to detailed reports**

## 🔄 Maintenance

**Regular Tasks:**
- Monitor API token expiration
- Check service status and updates
- Review and update badge configurations
- Monitor workflow performance

**Monthly:**
- Verify all services are working
- Check badge accuracy
- Update dependencies if needed
- Review security scan results

## 📚 Additional Resources

- [Codecov Documentation](https://docs.codecov.io/)
- [Codacy Documentation](https://docs.codacy.com/)
- [Snyk Documentation](https://docs.snyk.io/)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Shields.io Badge Generator](https://shields.io/)

## 🆘 Support

If you encounter issues:

1. Check the troubleshooting section above
2. Review service-specific documentation
3. Check GitHub Actions logs for detailed error messages
4. Verify all secrets and configurations are correct

---

**Note:** This setup is required for the badges to display accurate, real-time information. Without proper configuration, badges may show placeholder data or fail to display entirely.
