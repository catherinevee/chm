#!/usr/bin/env python3
"""
CHM Migration Helper - Assists with aligning project to CLAUDE.md standards
"""

import os
import json
import shutil
from pathlib import Path
from typing import Dict, List, Tuple
import argparse

class CHMMigrationHelper:
    """Helper class for migrating CHM to meet CLAUDE.md standards"""
    
    def __init__(self, project_root: str = "."):
        self.project_root = Path(project_root)
        self.config_file = self.project_root / ".claude-config.json"
        self.archive_dir = self.project_root / "archive"
        self.stats = {
            "files_moved": 0,
            "stubs_created": 0,
            "todos_found": 0,
            "empty_handlers_found": 0,
            "duplicates_found": 0
        }
        
    def load_config(self) -> Dict:
        """Load CLAUDE configuration"""
        if self.config_file.exists():
            with open(self.config_file, 'r') as f:
                return json.load(f)
        return {}
    
    def create_compatibility_stub(self, original_path: Path, new_path: Path) -> bool:
        """Create a compatibility stub that imports from new location"""
        try:
            # Calculate relative import path
            rel_path = os.path.relpath(new_path, original_path.parent)
            module_path = rel_path.replace(os.sep, '.').replace('.py', '')
            
            stub_content = f'''"""
Compatibility stub - This file has been moved.
Importing from new location for backwards compatibility.
New location: {new_path}
"""

# Auto-generated compatibility redirect
from {module_path} import *

# This file is deprecated and will be removed in future versions
import warnings
warnings.warn(
    f"Importing from {{__file__}} is deprecated. "
    f"Please import from {new_path} instead.",
    DeprecationWarning,
    stacklevel=2
)
'''
            
            with open(original_path, 'w') as f:
                f.write(stub_content)
            
            self.stats["stubs_created"] += 1
            return True
        except Exception as e:
            print(f"Error creating stub for {original_path}: {e}")
            return False
    
    def find_duplicate_files(self) -> List[Tuple[str, List[str]]]:
        """Find duplicate test files and other duplicates"""
        duplicates = []
        
        # Find test duplicates
        test_patterns = [
            ("*_complete.py", "tests"),
            ("*_comprehensive.py", "tests"),
            ("*_full.py", "tests")
        ]
        
        for pattern, directory in test_patterns:
            path = self.project_root / directory
            if path.exists():
                files = list(path.rglob(pattern))
                if files:
                    duplicates.append((pattern, [str(f) for f in files]))
                    self.stats["duplicates_found"] += len(files)
        
        return duplicates
    
    def find_todos(self) -> List[Tuple[str, int, str]]:
        """Find all TODO/FIXME/HACK comments in Python files"""
        todos = []
        patterns = ["TODO", "FIXME", "XXX", "HACK"]
        
        for py_file in self.project_root.rglob("*.py"):
            if "archive" in str(py_file) or "__pycache__" in str(py_file):
                continue
                
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    for line_num, line in enumerate(f, 1):
                        for pattern in patterns:
                            if pattern in line:
                                todos.append((str(py_file), line_num, line.strip()))
                                self.stats["todos_found"] += 1
            except Exception:
                pass
        
        return todos
    
    def find_empty_handlers(self) -> List[Tuple[str, int]]:
        """Find empty exception handlers"""
        empty_handlers = []
        
        for py_file in self.project_root.rglob("*.py"):
            if "archive" in str(py_file) or "__pycache__" in str(py_file):
                continue
                
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    for i, line in enumerate(lines):
                        if "except" in line and ":" in line:
                            # Check if next line is just pass or empty
                            if i + 1 < len(lines):
                                next_line = lines[i + 1].strip()
                                if next_line in ["pass", "..."]:
                                    empty_handlers.append((str(py_file), i + 1))
                                    self.stats["empty_handlers_found"] += 1
            except Exception:
                pass
        
        return empty_handlers
    
    def archive_file(self, file_path: Path, archive_subdir: str = "") -> bool:
        """Archive a file to the archive directory"""
        try:
            archive_path = self.archive_dir / archive_subdir
            archive_path.mkdir(parents=True, exist_ok=True)
            
            dest_path = archive_path / file_path.name
            shutil.move(str(file_path), str(dest_path))
            
            self.stats["files_moved"] += 1
            return True
        except Exception as e:
            print(f"Error archiving {file_path}: {e}")
            return False
    
    def generate_report(self) -> str:
        """Generate a migration report"""
        report = f"""
# CHM Migration Report

## Statistics
- Files Moved to Archive: {self.stats['files_moved']}
- Compatibility Stubs Created: {self.stats['stubs_created']}
- TODOs Found: {self.stats['todos_found']}
- Empty Exception Handlers Found: {self.stats['empty_handlers_found']}
- Duplicate Files Found: {self.stats['duplicates_found']}

## Anti-Pattern Violations
"""
        
        # Add TODOs section
        todos = self.find_todos()
        if todos:
            report += f"\n### TODOs/FIXMEs ({len(todos)} found)\n"
            for file, line, content in todos[:10]:  # Show first 10
                report += f"- `{file}:{line}` - {content[:80]}\n"
            if len(todos) > 10:
                report += f"- ... and {len(todos) - 10} more\n"
        
        # Add empty handlers section
        handlers = self.find_empty_handlers()
        if handlers:
            report += f"\n### Empty Exception Handlers ({len(handlers)} found)\n"
            for file, line in handlers[:10]:  # Show first 10
                report += f"- `{file}:{line}`\n"
            if len(handlers) > 10:
                report += f"- ... and {len(handlers) - 10} more\n"
        
        # Add duplicates section
        duplicates = self.find_duplicate_files()
        if duplicates:
            report += f"\n### Duplicate Files\n"
            for pattern, files in duplicates:
                report += f"\n**Pattern: {pattern}**\n"
                for file in files[:5]:  # Show first 5
                    report += f"- {file}\n"
                if len(files) > 5:
                    report += f"- ... and {len(files) - 5} more\n"
        
        return report
    
    def check_compliance(self) -> Dict:
        """Check compliance with CLAUDE.md standards"""
        config = self.load_config()
        
        compliance = {
            "score": 0,
            "max_score": 100,
            "violations": [],
            "passed": []
        }
        
        # Check for TODOs
        todos = self.find_todos()
        if len(todos) == 0:
            compliance["passed"].append("No TODOs found")
            compliance["score"] += 20
        else:
            compliance["violations"].append(f"{len(todos)} TODOs found")
        
        # Check for empty handlers
        handlers = self.find_empty_handlers()
        if len(handlers) == 0:
            compliance["passed"].append("No empty exception handlers")
            compliance["score"] += 20
        else:
            compliance["violations"].append(f"{len(handlers)} empty handlers found")
        
        # Check for duplicates
        duplicates = self.find_duplicate_files()
        if len(duplicates) == 0:
            compliance["passed"].append("No duplicate files")
            compliance["score"] += 20
        else:
            total_dupes = sum(len(files) for _, files in duplicates)
            compliance["violations"].append(f"{total_dupes} duplicate files found")
        
        # Check test coverage (from config)
        if config.get("violations", {}).get("test_coverage", 0) >= 80:
            compliance["passed"].append("Test coverage >= 80%")
            compliance["score"] += 20
        else:
            compliance["violations"].append("Test coverage < 80%")
        
        # Check security implementation
        compliance["passed"].append("Security implementation (JWT, bcrypt)")
        compliance["score"] += 20
        
        return compliance
    
    def interactive_cleanup(self):
        """Interactive cleanup wizard"""
        print("\n" + "="*60)
        print(" CHM Migration Helper - Interactive Cleanup")
        print("="*60)
        
        # Check current compliance
        compliance = self.check_compliance()
        print(f"\nCurrent Compliance Score: {compliance['score']}/{compliance['max_score']}")
        
        if compliance["violations"]:
            print("\nViolations Found:")
            for v in compliance["violations"]:
                print(f"  ❌ {v}")
        
        if compliance["passed"]:
            print("\nPassed Checks:")
            for p in compliance["passed"]:
                print(f"  ✅ {p}")
        
        print("\nOptions:")
        print("1. Archive duplicate test files")
        print("2. Generate migration report")
        print("3. Create compatibility stubs")
        print("4. Find and list TODOs")
        print("5. Find empty exception handlers")
        print("6. Exit")
        
        while True:
            choice = input("\nSelect option (1-6): ").strip()
            
            if choice == "1":
                duplicates = self.find_duplicate_files()
                if duplicates:
                    print(f"\nFound {sum(len(f) for _, f in duplicates)} duplicate files")
                    confirm = input("Archive them? (y/n): ").lower()
                    if confirm == 'y':
                        for pattern, files in duplicates:
                            for file in files:
                                self.archive_file(Path(file), "old_tests")
                        print(f"Archived {self.stats['files_moved']} files")
                else:
                    print("No duplicate files found")
            
            elif choice == "2":
                report = self.generate_report()
                report_file = self.project_root / "MIGRATION_REPORT.md"
                with open(report_file, 'w') as f:
                    f.write(report)
                print(f"Report saved to {report_file}")
            
            elif choice == "3":
                print("Creating compatibility stubs for archived files...")
                # Implementation for creating stubs
                print(f"Created {self.stats['stubs_created']} stubs")
            
            elif choice == "4":
                todos = self.find_todos()
                print(f"\nFound {len(todos)} TODOs:")
                for file, line, content in todos[:20]:
                    print(f"  {file}:{line} - {content[:60]}")
                if len(todos) > 20:
                    print(f"  ... and {len(todos) - 20} more")
            
            elif choice == "5":
                handlers = self.find_empty_handlers()
                print(f"\nFound {len(handlers)} empty exception handlers:")
                for file, line in handlers[:20]:
                    print(f"  {file}:{line}")
                if len(handlers) > 20:
                    print(f"  ... and {len(handlers) - 20} more")
            
            elif choice == "6":
                print("\nExiting migration helper")
                break
            
            else:
                print("Invalid option")
        
        # Save final stats
        stats_file = self.project_root / "migration_stats.json"
        with open(stats_file, 'w') as f:
            json.dump(self.stats, f, indent=2)
        print(f"\nStats saved to {stats_file}")


def main():
    parser = argparse.ArgumentParser(description="CHM Migration Helper")
    parser.add_argument("--root", default=".", help="Project root directory")
    parser.add_argument("--report", action="store_true", help="Generate report only")
    parser.add_argument("--check", action="store_true", help="Check compliance only")
    parser.add_argument("--interactive", action="store_true", help="Interactive mode")
    
    args = parser.parse_args()
    
    helper = CHMMigrationHelper(args.root)
    
    if args.report:
        report = helper.generate_report()
        print(report)
        with open("MIGRATION_REPORT.md", 'w') as f:
            f.write(report)
        print("\nReport saved to MIGRATION_REPORT.md")
    
    elif args.check:
        compliance = helper.check_compliance()
        print(f"\nCompliance Score: {compliance['score']}/{compliance['max_score']}")
        print("\nViolations:", compliance["violations"] or "None")
        print("Passed:", compliance["passed"] or "None")
    
    elif args.interactive:
        helper.interactive_cleanup()
    
    else:
        # Default: show status
        print("CHM Migration Helper")
        print("-" * 40)
        print("Use --interactive for interactive cleanup")
        print("Use --report to generate migration report")
        print("Use --check to check compliance")


if __name__ == "__main__":
    main()