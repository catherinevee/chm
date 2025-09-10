#!/usr/bin/env python3
"""
Badge Generator for CHM README
Automatically generates and updates badges in the README
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Any

class BadgeGenerator:
    """Generate badges for CHM README"""
    
    def __init__(self, config_file: str = '.github/badges.json'):
        self.config_file = config_file
        self.badges_config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load badge configuration"""
        try:
            with open(self.config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Badge configuration file not found: {self.config_file}")
            return {}
        except json.JSONDecodeError as e:
            print(f"Error parsing badge configuration: {e}")
            return {}
    
    def generate_badge_markdown(self, badge_key: str) -> str:
        """Generate markdown for a single badge"""
        if badge_key not in self.badges_config['badges']:
            return ""
        
        badge = self.badges_config['badges'][badge_key]
        return f"[![{badge['alt']}]({badge['url']})]({badge['link']})"
    
    def generate_badge_section(self, section_name: str) -> str:
        """Generate markdown for a badge section"""
        if section_name not in self.badges_config['readme_sections']:
            return ""
        
        badge_keys = self.badges_config['readme_sections'][section_name]
        badges = []
        
        for key in badge_keys:
            badge_md = self.generate_badge_markdown(key)
            if badge_md:
                badges.append(badge_md)
        
        if not badges:
            return ""
        
        return " ".join(badges)
    
    def generate_all_badges(self) -> str:
        """Generate all badges organized by sections"""
        sections = []
        
        # Header badges (status)
        header_badges = self.generate_badge_section('header')
        if header_badges:
            sections.append(header_badges)
        
        # Technology stack badges
        tech_badges = self.generate_badge_section('technology_stack')
        if tech_badges:
            sections.append(f"\n### Technology Stack\n{tech_badges}")
        
        # Feature badges
        feature_badges = self.generate_badge_section('features')
        if feature_badges:
            sections.append(f"\n### Features\n{feature_badges}")
        
        # Capability badges
        capability_badges = self.generate_badge_section('capabilities')
        if capability_badges:
            sections.append(f"\n### Capabilities\n{capability_badges}")
        
        # Performance badges
        performance_badges = self.generate_badge_section('performance')
        if performance_badges:
            sections.append(f"\n### Performance\n{performance_badges}")
        
        # Deployment badges
        deployment_badges = self.generate_badge_section('deployment')
        if deployment_badges:
            sections.append(f"\n### Deployment\n{deployment_badges}")
        
        # Quality badges
        quality_badges = self.generate_badge_section('quality')
        if quality_badges:
            sections.append(f"\n### Quality & Testing\n{quality_badges}")
        
        # Community badges
        community_badges = self.generate_badge_section('community')
        if community_badges:
            sections.append(f"\n### Community & Support\n{community_badges}")
        
        return "\n".join(sections)
    
    def update_readme(self, readme_file: str = 'README.md') -> bool:
        """Update README with badges"""
        try:
            if not os.path.exists(readme_file):
                print(f"README file not found: {readme_file}")
                return False
            
            with open(readme_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check if badges section already exists
            if '<!-- BADGES_START -->' in content and '<!-- BADGES_END -->' in content:
                # Replace existing badges section
                start_marker = '<!-- BADGES_START -->'
                end_marker = '<!-- BADGES_END -->'
                
                start_pos = content.find(start_marker)
                end_pos = content.find(end_marker) + len(end_marker)
                
                new_badges = f"{start_marker}\n{self.generate_all_badges()}\n{end_marker}"
                updated_content = content[:start_pos] + new_badges + content[end_pos:]
                
            else:
                # Insert badges after the title
                title_end = content.find('\n', content.find('# '))
                if title_end == -1:
                    title_end = 0
                
                badges_section = f"\n<!-- BADGES_START -->\n{self.generate_all_badges()}\n<!-- BADGES_END -->\n"
                updated_content = content[:title_end] + badges_section + content[title_end:]
            
            # Write updated content
            with open(readme_file, 'w', encoding='utf-8') as f:
                f.write(updated_content)
            
            print(f"Successfully updated {readme_file} with badges")
            return True
            
        except Exception as e:
            print(f"Error updating README: {e}")
            return False
    
    def generate_badge_summary(self) -> Dict[str, Any]:
        """Generate summary of all badges"""
        summary = {
            'total_badges': len(self.badges_config.get('badges', {})),
            'sections': {},
            'badge_types': {}
        }
        
        # Count badges by section
        for section_name, badge_keys in self.badges_config.get('readme_sections', {}).items():
            summary['sections'][section_name] = len(badge_keys)
        
        # Count badges by type (based on URL patterns)
        badge_types = {}
        for badge in self.badges_config.get('badges', {}).values():
            url = badge.get('url', '')
            if 'github.com' in url:
                badge_types['github'] = badge_types.get('github', 0) + 1
            elif 'codecov.io' in url:
                badge_types['codecov'] = badge_types.get('codecov', 0) + 1
            elif 'codacy.com' in url:
                badge_types['codacy'] = badge_types.get('codacy', 0) + 1
            elif 'snyk.io' in url:
                badge_types['snyk'] = badge_types.get('snyk', 0) + 1
            elif 'img.shields.io' in url:
                badge_types['shields'] = badge_types.get('shields', 0) + 1
            else:
                badge_types['other'] = badge_types.get('other', 0) + 1
        
        summary['badge_types'] = badge_types
        return summary

def main():
    """Main function to generate badges"""
    generator = BadgeGenerator()
    
    if not generator.badges_config:
        print("Failed to load badge configuration")
        sys.exit(1)
    
    # Generate badge summary
    summary = generator.generate_badge_summary()
    print("Badge Summary:")
    print(f"Total Badges: {summary['total_badges']}")
    print("\nBadges by Section:")
    for section, count in summary['sections'].items():
        print(f"  {section}: {count}")
    
    print("\nBadges by Type:")
    for badge_type, count in summary['badge_types'].items():
        print(f"  {badge_type}: {count}")
    
    # Update README
    if generator.update_readme():
        print("\nREADME updated successfully!")
        sys.exit(0)
    else:
        print("\nFailed to update README")
        sys.exit(1)

if __name__ == "__main__":
    main()
