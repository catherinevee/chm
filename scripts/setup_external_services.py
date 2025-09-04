#!/usr/bin/env python3
"""
External Services Setup Script for CHM

This script helps automate the setup of external services required for CHM badges.
It can update configuration files, validate URLs, and guide through the setup process.
"""

import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional
import urllib.request
import urllib.error


class ExternalServicesSetup:
    """Manages the setup of external services for CHM badges."""
    
    def __init__(self, config_path: str = ".github/badges.json"):
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self.github_username = self.config.get("github_config", {}).get("username", "username")
        
    def _load_config(self) -> Dict:
        """Load the badge configuration file."""
        try:
            with open(self.config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"❌ Configuration file not found: {self.config_path}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"❌ Invalid JSON in configuration file: {e}")
            sys.exit(1)
    
    def update_github_username(self, new_username: str) -> None:
        """Update GitHub username in all configuration files."""
        print(f"🔄 Updating GitHub username from '{self.github_username}' to '{new_username}'")
        
        # Files to update
        files_to_update = [
            ".github/badges.json",
            ".github/workflows/ci-cd.yml",
            "chm/README.md"
        ]
        
        for file_path in files_to_update:
            if os.path.exists(file_path):
                self._update_file_username(file_path, new_username)
            else:
                print(f"⚠️  File not found: {file_path}")
        
        # Update config in memory
        self.github_username = new_username
        self.config["github_config"]["username"] = new_username
        
        print(f"✅ GitHub username updated to '{new_username}'")
    
    def _update_file_username(self, file_path: str, new_username: str) -> None:
        """Update username in a specific file."""
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Replace username in various formats
            old_content = content
            content = re.sub(r'username/chm', f'{new_username}/chm', content)
            content = re.sub(r'username/chm', f'{new_username}/chm', content)
            
            if content != old_content:
                with open(file_path, 'w') as f:
                    f.write(content)
                print(f"✅ Updated: {file_path}")
            else:
                print(f"ℹ️  No changes needed: {file_path}")
                
        except Exception as e:
            print(f"❌ Error updating {file_path}: {e}")
    
    def validate_badge_urls(self) -> Dict[str, bool]:
        """Validate that all badge URLs are accessible."""
        print("🔍 Validating badge URLs...")
        
        results = {}
        badges = self.config.get("badges", {})
        
        for badge_name, badge_config in badges.items():
            url = badge_config.get("url", "")
            if url.startswith("http"):
                try:
                    with urllib.request.urlopen(url, timeout=10) as response:
                        results[badge_name] = response.status == 200
                        status = "✅" if results[badge_name] else "❌"
                        print(f"{status} {badge_name}: {url}")
                except Exception as e:
                    results[badge_name] = False
                    print(f"❌ {badge_name}: {url} - Error: {e}")
            else:
                results[badge_name] = True
                print(f"ℹ️  {badge_name}: {url} (local anchor)")
        
        return results
    
    def check_required_secrets(self) -> List[str]:
        """Check which GitHub secrets are required and missing."""
        print("🔐 Checking required GitHub secrets...")
        
        required_secrets = self.config.get("github_config", {}).get("secrets_required", [])
        missing_secrets = []
        
        for secret in required_secrets:
            print(f"📋 Required: {secret}")
            # Note: We can't actually check if secrets exist, just list them
            missing_secrets.append(secret)
        
        return missing_secrets
    
    def generate_setup_commands(self) -> None:
        """Generate setup commands for external services."""
        print("🚀 Generating setup commands...")
        
        external_services = self.config.get("external_services", {})
        
        for service_name, service_config in external_services.items():
            print(f"\n📡 {service_config['name']}")
            print(f"   Purpose: {service_config['description']}")
            print(f"   Setup URL: {service_config['setup_url']}")
            
            if service_config.get("required", False):
                print("   ⚠️  REQUIRED for badges to work")
            
            print("   Setup steps:")
            for i, step in enumerate(service_config.get("setup_steps", []), 1):
                print(f"   {i}. {step}")
    
    def update_codacy_project_id(self, project_id: str) -> None:
        """Update Codacy project ID in configuration."""
        print(f"🔄 Updating Codacy project ID to: {project_id}")
        
        # Update badges.json
        if "quality" in self.config.get("badges", {}):
            quality_badge = self.config["badges"]["quality"]
            old_url = quality_badge["url"]
            new_url = f"https://api.codacy.com/project/badge/Grade/{project_id}"
            
            quality_badge["url"] = new_url
            print(f"✅ Updated Codacy badge URL: {new_url}")
        
        # Save updated config
        self._save_config()
    
    def _save_config(self) -> None:
        """Save the updated configuration to file."""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
            print("✅ Configuration saved")
        except Exception as e:
            print(f"❌ Error saving configuration: {e}")
    
    def generate_github_secrets_script(self) -> None:
        """Generate a script to set up GitHub secrets."""
        print("🔐 Generating GitHub secrets setup script...")
        
        script_content = """#!/bin/bash
# GitHub Secrets Setup Script for CHM
# Run this script to set up required secrets

echo "Setting up GitHub secrets for CHM project..."

# Check if gh CLI is installed
if ! command -v gh &> /dev/null; then
    echo "❌ GitHub CLI (gh) is not installed."
    echo "Please install it first: https://cli.github.com/"
    exit 1
fi

# Check if authenticated
if ! gh auth status &> /dev/null; then
    echo "❌ Not authenticated with GitHub CLI."
    echo "Please run: gh auth login"
    exit 1
fi

echo "✅ GitHub CLI is ready"

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

echo "✅ All secrets have been set up!"
echo "You can now run the CI/CD pipeline."
"""
        
        script_path = "setup_github_secrets.sh"
        with open(script_path, 'w') as f:
            f.write(script_content)
        
        os.chmod(script_path, 0o755)
        print(f"✅ Generated: {script_path}")
        print("   Run: ./setup_github_secrets.sh")
    
    def run_interactive_setup(self) -> None:
        """Run an interactive setup wizard."""
        print("🎯 CHM External Services Setup Wizard")
        print("=" * 50)
        
        # Update GitHub username
        current_username = self.github_username
        if current_username == "username":
            new_username = input(f"Enter your GitHub username (current: {current_username}): ").strip()
            if new_username and new_username != current_username:
                self.update_github_username(new_username)
        
        # Check badge URLs
        print("\n" + "=" * 50)
        self.validate_badge_urls()
        
        # Check required secrets
        print("\n" + "=" * 50)
        self.check_required_secrets()
        
        # Generate setup commands
        print("\n" + "=" * 50)
        self.generate_setup_commands()
        
        # Generate secrets script
        print("\n" + "=" * 50)
        self.generate_github_secrets_script()
        
        print("\n🎉 Setup wizard completed!")
        print("\nNext steps:")
        print("1. Run the generated setup script: ./setup_github_secrets.sh")
        print("2. Set up each external service following the instructions above")
        print("3. Test the CI/CD pipeline by pushing changes")
        print("4. Verify badges are displaying correctly")


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python setup_external_services.py [command]")
        print("\nCommands:")
        print("  interactive    Run interactive setup wizard")
        print("  update-username <username>  Update GitHub username")
        print("  validate-urls  Validate all badge URLs")
        print("  check-secrets  Check required GitHub secrets")
        print("  generate-setup Generate setup commands")
        print("  update-codacy <project-id>  Update Codacy project ID")
        print("  generate-secrets-script  Generate GitHub secrets setup script")
        return
    
    setup = ExternalServicesSetup()
    command = sys.argv[1]
    
    if command == "interactive":
        setup.run_interactive_setup()
    elif command == "update-username":
        if len(sys.argv) < 3:
            print("❌ Please provide a username")
            return
        setup.update_github_username(sys.argv[2])
    elif command == "validate-urls":
        setup.validate_badge_urls()
    elif command == "check-secrets":
        setup.check_required_secrets()
    elif command == "generate-setup":
        setup.generate_setup_commands()
    elif command == "update-codacy":
        if len(sys.argv) < 3:
            print("❌ Please provide a Codacy project ID")
            return
        setup.update_codacy_project_id(sys.argv[2])
    elif command == "generate-secrets-script":
        setup.generate_github_secrets_script()
    else:
        print(f"❌ Unknown command: {command}")


if __name__ == "__main__":
    main()
