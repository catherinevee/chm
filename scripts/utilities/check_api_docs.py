#!/usr/bin/env python3
"""
API Documentation Checker for CHM
Checks API documentation coverage and completeness
"""

import os
import sys
import json
import ast
from pathlib import Path
from typing import Dict, List, Set, Any
import importlib.util

class APIDocumentationChecker:
    """Check API documentation coverage and completeness"""
    
    def __init__(self):
        self.api_endpoints = set()
        self.documented_endpoints = set()
        self.undocumented_endpoints = set()
        self.documentation_issues = []
        
    def scan_api_endpoints(self, api_dir: str) -> Set[str]:
        """Scan API directory for endpoints"""
        endpoints = set()
        
        try:
            for root, dirs, files in os.walk(api_dir):
                for file in files:
                    if file.endswith('.py'):
                        file_path = os.path.join(root, file)
                        endpoints.update(self._extract_endpoints_from_file(file_path))
        
        except Exception as e:
            print(f"Error scanning API endpoints: {e}")
        
        return endpoints
    
    def _extract_endpoints_from_file(self, file_path: str) -> Set[str]:
        """Extract API endpoints from a Python file"""
        endpoints = set()
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse the Python file
            tree = ast.parse(content)
            
            # Look for FastAPI route decorators
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Attribute):
                        if node.func.attr in ['get', 'post', 'put', 'delete', 'patch']:
                            # Extract route path
                            for arg in node.args:
                                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                                    endpoints.add(arg.value)
                
                # Look for router.add_api_route calls
                elif isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Attribute):
                        if node.func.attr == 'add_api_route':
                            for arg in node.args:
                                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                                    endpoints.add(arg.value)
        
        except Exception as e:
            print(f"Error parsing {file_path}: {e}")
        
        return endpoints
    
    def check_openapi_schema(self, schema_file: str) -> Dict[str, Any]:
        """Check OpenAPI schema completeness"""
        try:
            if not os.path.exists(schema_file):
                return {'error': 'OpenAPI schema file not found'}
            
            with open(schema_file, 'r') as f:
                schema = json.load(f)
            
            # Check required OpenAPI fields
            required_fields = ['openapi', 'info', 'paths']
            missing_fields = [field for field in required_fields if field not in schema]
            
            # Check info section
            info_issues = []
            if 'info' in schema:
                info = schema['info']
                if 'title' not in info:
                    info_issues.append('Missing title')
                if 'version' not in info:
                    info_issues.append('Missing version')
                if 'description' not in info:
                    info_issues.append('Missing description')
            
            # Check paths section
            path_issues = []
            if 'paths' in schema:
                paths = schema['paths']
                for path, methods in paths.items():
                    for method, details in methods.items():
                        if 'summary' not in details:
                            path_issues.append(f"Missing summary for {method.upper()} {path}")
                        if 'responses' not in details:
                            path_issues.append(f"Missing responses for {method.upper()} {path}")
            
            return {
                'schema_valid': len(missing_fields) == 0,
                'missing_fields': missing_fields,
                'info_issues': info_issues,
                'path_issues': path_issues,
                'total_paths': len(schema.get('paths', {})),
                'total_operations': sum(len(methods) for methods in schema.get('paths', {}).values())
            }
        
        except Exception as e:
            return {'error': f'Error checking OpenAPI schema: {e}'}
    
    def check_documentation_files(self, docs_dir: str) -> Dict[str, Any]:
        """Check documentation file completeness"""
        try:
            if not os.path.exists(docs_dir):
                return {'error': 'Documentation directory not found'}
            
            required_files = [
                'README.md',
                'API.md',
                'DEPLOYMENT.md',
                'CONTRIBUTING.md'
            ]
            
            optional_files = [
                'CHANGELOG.md',
                'SECURITY.md',
                'TROUBLESHOOTING.md'
            ]
            
            present_files = []
            missing_files = []
            
            for file in required_files:
                if os.path.exists(os.path.join(docs_dir, file)):
                    present_files.append(file)
                else:
                    missing_files.append(file)
            
            for file in optional_files:
                if os.path.exists(os.path.join(docs_dir, file)):
                    present_files.append(file)
            
            return {
                'required_files_present': len([f for f in present_files if f in required_files]),
                'total_required_files': len(required_files),
                'optional_files_present': len([f for f in present_files if f in optional_files]),
                'total_optional_files': len(optional_files),
                'present_files': present_files,
                'missing_files': missing_files
            }
        
        except Exception as e:
            return {'error': f'Error checking documentation files: {e}'}
    
    def check_code_documentation(self, backend_dir: str) -> Dict[str, Any]:
        """Check code documentation coverage"""
        try:
            total_files = 0
            documented_files = 0
            total_functions = 0
            documented_functions = 0
            total_classes = 0
            documented_classes = 0
            
            for root, dirs, files in os.walk(backend_dir):
                # Skip test directories
                if 'test' in root or 'tests' in root:
                    continue
                
                for file in files:
                    if file.endswith('.py'):
                        total_files += 1
                        file_path = os.path.join(root, file)
                        
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                        
                        # Check if file has module docstring
                        if content.strip().startswith('"""') or content.strip().startswith("'''"):
                            documented_files += 1
                        
                        # Parse file for functions and classes
                        try:
                            tree = ast.parse(content)
                            
                            for node in ast.walk(tree):
                                if isinstance(node, ast.FunctionDef):
                                    total_functions += 1
                                    if ast.get_docstring(node):
                                        documented_functions += 1
                                
                                elif isinstance(node, ast.ClassDef):
                                    total_classes += 1
                                    if ast.get_docstring(node):
                                        documented_classes += 1
                        
                        except SyntaxError:
                            # Skip files with syntax errors
                            continue
            
            return {
                'total_files': total_files,
                'documented_files': documented_files,
                'file_documentation_rate': (documented_files / total_files * 100) if total_files > 0 else 0,
                'total_functions': total_functions,
                'documented_functions': documented_functions,
                'function_documentation_rate': (documented_functions / total_functions * 100) if total_functions > 0 else 0,
                'total_classes': total_classes,
                'documented_classes': documented_classes,
                'class_documentation_rate': (documented_classes / total_classes * 100) if total_classes > 0 else 0
            }
        
        except Exception as e:
            return {'error': f'Error checking code documentation: {e}'}
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive documentation report"""
        try:
            # Check API endpoints
            api_dir = 'backend/api'
            if os.path.exists(api_dir):
                self.api_endpoints = self.scan_api_endpoints(api_dir)
            
            # Check OpenAPI schema
            openapi_schema = self.check_openapi_schema('backend/openapi.json')
            
            # Check documentation files
            docs_check = self.check_documentation_files('docs')
            
            # Check code documentation
            code_docs = self.check_code_documentation('backend')
            
            # Calculate overall documentation score
            scores = []
            
            # OpenAPI schema score
            if 'error' not in openapi_schema:
                schema_score = 100
                if openapi_schema.get('missing_fields'):
                    schema_score -= len(openapi_schema['missing_fields']) * 20
                if openapi_schema.get('info_issues'):
                    schema_score -= len(openapi_schema['info_issues']) * 10
                if openapi_schema.get('path_issues'):
                    schema_score -= len(openapi_schema['path_issues']) * 5
                scores.append(max(0, schema_score))
            else:
                scores.append(0)
            
            # Documentation files score
            if 'error' not in docs_check:
                docs_score = (docs_check['required_files_present'] / docs_check['total_required_files']) * 100
                scores.append(docs_score)
            else:
                scores.append(0)
            
            # Code documentation score
            if 'error' not in code_docs:
                code_score = (
                    code_docs['file_documentation_rate'] * 0.4 +
                    code_docs['function_documentation_rate'] * 0.4 +
                    code_docs['class_documentation_rate'] * 0.2
                )
                scores.append(code_score)
            else:
                scores.append(0)
            
            overall_score = sum(scores) / len(scores) if scores else 0
            
            report = {
                'overall_score': round(overall_score, 2),
                'api_endpoints_found': len(self.api_endpoints),
                'openapi_schema': openapi_schema,
                'documentation_files': docs_check,
                'code_documentation': code_docs,
                'recommendations': self._generate_recommendations(overall_score, openapi_schema, docs_check, code_docs)
            }
            
            return report
        
        except Exception as e:
            return {'error': f'Error generating report: {e}'}
    
    def _generate_recommendations(self, score: float, openapi_schema: Dict, docs_check: Dict, code_docs: Dict) -> List[str]:
        """Generate improvement recommendations"""
        recommendations = []
        
        if score < 80:
            recommendations.append("Overall documentation needs improvement")
        
        # OpenAPI schema recommendations
        if 'error' not in openapi_schema:
            if openapi_schema.get('missing_fields'):
                recommendations.append(f"Fix missing OpenAPI fields: {', '.join(openapi_schema['missing_fields'])}")
            if openapi_schema.get('info_issues'):
                recommendations.append(f"Fix OpenAPI info issues: {', '.join(openapi_schema['info_issues'])}")
            if openapi_schema.get('path_issues'):
                recommendations.append(f"Fix OpenAPI path issues: {len(openapi_schema['path_issues'])} issues found")
        
        # Documentation files recommendations
        if 'error' not in docs_check:
            if docs_check['missing_files']:
                recommendations.append(f"Create missing documentation files: {', '.join(docs_check['missing_files'])}")
        
        # Code documentation recommendations
        if 'error' not in code_docs:
            if code_docs['file_documentation_rate'] < 90:
                recommendations.append(f"Increase file documentation rate from {code_docs['file_documentation_rate']:.1f}% to 90%+")
            if code_docs['function_documentation_rate'] < 90:
                recommendations.append(f"Increase function documentation rate from {code_docs['function_documentation_rate']:.1f}% to 90%+")
            if code_docs['class_documentation_rate'] < 90:
                recommendations.append(f"Increase class documentation rate from {code_docs['class_documentation_rate']:.1f}% to 90%+")
        
        if not recommendations:
            recommendations.append("Excellent documentation! Keep up the good work!")
        
        return recommendations

def main():
    """Main function to check API documentation"""
    checker = APIDocumentationChecker()
    report = checker.generate_report()
    
    # Output to console
    print("=" * 60)
    print("CHM API Documentation Report")
    print("=" * 60)
    print(f"Overall Score: {report.get('overall_score', 'N/A')}/100")
    print(f"API Endpoints Found: {report.get('api_endpoints_found', 'N/A')}")
    
    print("\nOpenAPI Schema:")
    openapi = report.get('openapi_schema', {})
    if 'error' not in openapi:
        print(f"  Valid: {openapi.get('schema_valid', 'N/A')}")
        print(f"  Total Paths: {openapi.get('total_paths', 'N/A')}")
        print(f"  Total Operations: {openapi.get('total_operations', 'N/A')}")
    else:
        print(f"  Error: {openapi['error']}")
    
    print("\nDocumentation Files:")
    docs = report.get('documentation_files', {})
    if 'error' not in docs:
        print(f"  Required Files: {docs.get('required_files_present', 'N/A')}/{docs.get('total_required_files', 'N/A')}")
        print(f"  Optional Files: {docs.get('optional_files_present', 'N/A')}/{docs.get('total_optional_files', 'N/A')}")
    else:
        print(f"  Error: {docs['error']}")
    
    print("\nCode Documentation:")
    code = report.get('code_documentation', {})
    if 'error' not in code:
        print(f"  File Rate: {code.get('file_documentation_rate', 'N/A'):.1f}%")
        print(f"  Function Rate: {code.get('function_documentation_rate', 'N/A'):.1f}%")
        print(f"  Class Rate: {code.get('class_documentation_rate', 'N/A'):.1f}%")
    else:
        print(f"  Error: {code['error']}")
    
    print("\nRecommendations:")
    for rec in report.get('recommendations', []):
        print(f"  • {rec}")
    
    print("\n" + "=" * 60)
    
    # Save to file
    output_file = 'api-docs-report.json'
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"Detailed report saved to: {output_file}")
    
    # Exit with appropriate code
    if report.get('overall_score', 0) >= 80:
        sys.exit(0)  # Success
    else:
        sys.exit(1)  # Documentation threshold not met

if __name__ == "__main__":
    main()
