#!/bin/bash
# GitHub Secrets Setup Script for CHM
# Run this script to set up required secrets

echo "Setting up GitHub secrets for CHM project..."

# Check if gh CLI is installed
if ! command -v gh &> /dev/null; then
    echo " GitHub CLI (gh) is not installed."
    echo "Please install it first: https://cli.github.com/"
    exit 1
fi

# Check if authenticated
if ! gh auth status &> /dev/null; then
    echo " Not authenticated with GitHub CLI."
    echo "Please run: gh auth login"
    exit 1
fi

echo "PASS: GitHub CLI is ready"

# Set up secrets
echo "Setting up SNYK_TOKEN..."
read -p "Enter your Snyk API token: " SNYK_TOKEN
gh secret set SNYK_TOKEN --body "$SNYK_TOKEN"

echo "Setting up CODECOV_TOKEN..."
read -p "Enter your Codecov token: " CODECOV_TOKEN
gh secret set CODECOV_TOKEN --body "$CODECOV_TOKEN"

echo "Setting up CODACY_PROJECT_TOKEN..."
read -p "Enter your Codacy project token: " CODACY_PROJECT_TOKEN
gh secret set CODACY_PROJECT_TOKEN --body "$CODACY_PROJECT_TOKEN"

echo "PASS: All secrets have been set up!"
echo "You can now run the CI/CD pipeline."
