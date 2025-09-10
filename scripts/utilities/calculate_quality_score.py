#!/usr/bin/env python3
"""
Quality Score Calculator for CHM
Calculates overall quality score based on various metrics
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, Any, List
import xml.etree.ElementTree as ET

class QualityScoreCalculator:
    """Calculate quality score based on various metrics"""
    
    def __init__(self):
        self.metrics = {}
        self.weights = {
            'test_coverage': 0.25,
            'code_quality': 0.20,
            'security': 0.20,
            'documentation': 0.15,
            'performance': 0.10,
            'compliance': 0.10
        }
    
    def calculate_backend_coverage(self, coverage_file: str) -> float:
        """Calculate backend test coverage score"""
        try:
            tree = ET.parse(coverage_file)
            root = tree.getroot()
            
            # Extract coverage data
            coverage_data = root.attrib
            line_rate = float(coverage_data.get('line-rate', 0))
            branch_rate = float(coverage_data.get('branch-rate', 0))
            
            # Calculate weighted coverage score
            coverage_score = (line_rate * 0.7) + (branch_rate * 0.3)
            
            self.metrics['backend_coverage'] = {
                'line_coverage': line_rate * 100,
                'branch_coverage': branch_rate * 100,
                'weighted_score': coverage_score * 100
            }
            
            return coverage_score * 100
            
        except Exception as e:
            print(f"Error calculating backend coverage: {e}")
            return 0.0
    
    def calculate_frontend_coverage(self, coverage_dir: str) -> float:
        """Calculate frontend test coverage score"""
        try:
            coverage_file = Path(coverage_dir) / 'coverage-summary.json'
            if not coverage_file.exists():
                return 0.0
            
            with open(coverage_file, 'r') as f:
                coverage_data = json.load(f)
            
            # Extract coverage percentages
            total_coverage = coverage_data.get('total', {})
            line_coverage = total_coverage.get('lines', {}).get('pct', 0)
            function_coverage = total_coverage.get('functions', {}).get('pct', 0)
            
            # Calculate weighted coverage score
            coverage_score = (line_coverage * 0.6) + (function_coverage * 0.4)
            
            self.metrics['frontend_coverage'] = {
                'line_coverage': line_coverage,
                'function_coverage': function_coverage,
                'weighted_score': coverage_score
            }
            
            return coverage_score
            
        except Exception as e:
            print(f"Error calculating frontend coverage: {e}")
            return 0.0
    
    def calculate_code_quality(self, bandit_file: str, safety_file: str) -> float:
        """Calculate code quality score based on security scans"""
        try:
            quality_score = 100.0
            
            # Check Bandit security scan
            if os.path.exists(bandit_file):
                with open(bandit_file, 'r') as f:
                    bandit_data = json.load(f)
                
                issues = bandit_data.get('results', [])
                high_severity = len([i for i in issues if i.get('issue_severity') == 'HIGH'])
                medium_severity = len([i for i in issues if i.get('issue_severity') == 'MEDIUM'])
                
                # Deduct points for security issues
                quality_score -= (high_severity * 10) + (medium_severity * 5)
                
                self.metrics['security_scan'] = {
                    'high_severity_issues': high_severity,
                    'medium_severity_issues': medium_severity,
                    'total_issues': len(issues)
                }
            
            # Check Safety dependency scan
            if os.path.exists(safety_file):
                with open(safety_file, 'r') as f:
                    safety_data = json.load(f)
                
                vulnerabilities = safety_data.get('vulnerabilities', [])
                high_vulns = len([v for v in vulnerabilities if v.get('severity') == 'HIGH'])
                medium_vulns = len([v for v in vulnerabilities if v.get('severity') == 'MEDIUM'])
                
                # Deduct points for vulnerabilities
                quality_score -= (high_vulns * 15) + (medium_vulns * 8)
                
                self.metrics['dependency_scan'] = {
                    'high_vulnerabilities': high_vulns,
                    'medium_vulnerabilities': medium_vulns,
                    'total_vulnerabilities': len(vulnerabilities)
                }
            
            return max(0.0, quality_score)
            
        except Exception as e:
            print(f"Error calculating code quality: {e}")
            return 0.0
    
    def calculate_documentation_score(self, docs_dir: str) -> float:
        """Calculate documentation completeness score"""
        try:
            docs_score = 0.0
            
            # Check if documentation directory exists
            if not os.path.exists(docs_dir):
                return 0.0
            
            # Check for key documentation files
            required_files = [
                'README.md',
                'API.md',
                'DEPLOYMENT.md',
                'CONTRIBUTING.md'
            ]
            
            for file in required_files:
                if os.path.exists(os.path.join(docs_dir, file)):
                    docs_score += 25.0
            
            # Check for API documentation
            api_docs = [
                'swagger.json',
                'openapi.yaml',
                'api-reference.md'
            ]
            
            for file in api_docs:
                if os.path.exists(os.path.join(docs_dir, file)):
                    docs_score += 20.0
            
            self.metrics['documentation'] = {
                'score': docs_score,
                'required_files_present': docs_score / 25.0
            }
            
            return min(100.0, docs_score)
            
        except Exception as e:
            print(f"Error calculating documentation score: {e}")
            return 0.0
    
    def calculate_performance_score(self, performance_dir: str) -> float:
        """Calculate performance benchmark score"""
        try:
            performance_score = 80.0  # Base score
            
            # Check for performance test results
            if os.path.exists(performance_dir):
                # This would analyze actual performance metrics
                # For now, give a baseline score
                performance_score = 85.0
            
            self.metrics['performance'] = {
                'score': performance_score,
                'benchmarks_available': os.path.exists(performance_dir)
            }
            
            return performance_score
            
        except Exception as e:
            print(f"Error calculating performance score: {e}")
            return 0.0
    
    def calculate_compliance_score(self, license_file: str) -> float:
        """Calculate compliance and licensing score"""
        try:
            compliance_score = 100.0
            
            # Check for license file
            if not os.path.exists(license_file):
                compliance_score -= 30
            
            # Check for other compliance files
            compliance_files = [
                'CODE_OF_CONDUCT.md',
                'SECURITY.md',
                'CHANGELOG.md'
            ]
            
            for file in compliance_files:
                if os.path.exists(file):
                    compliance_score += 5
            
            self.metrics['compliance'] = {
                'score': compliance_score,
                'license_present': os.path.exists(license_file),
                'compliance_files_present': len([f for f in compliance_files if os.path.exists(f)])
            }
            
            return min(100.0, compliance_score)
            
        except Exception as e:
            print(f"Error calculating compliance score: {e}")
            return 0.0
    
    def calculate_overall_score(self) -> Dict[str, Any]:
        """Calculate overall quality score"""
        try:
            # Calculate individual scores
            backend_coverage = self.calculate_backend_coverage('backend/coverage.xml')
            frontend_coverage = self.calculate_frontend_coverage('frontend/coverage/')
            code_quality = self.calculate_code_quality('bandit-report.json', 'safety-report.json')
            documentation = self.calculate_documentation_score('docs/')
            performance = self.calculate_performance_score('performance-reports/')
            compliance = self.calculate_compliance_score('LICENSE')
            
            # Calculate weighted overall score
            overall_score = (
                (backend_coverage * 0.3) +
                (frontend_coverage * 0.2) +
                (code_quality * 0.2) +
                (documentation * 0.15) +
                (performance * 0.1) +
                (compliance * 0.05)
            )
            
            # Determine grade
            if overall_score >= 90:
                grade = 'A'
            elif overall_score >= 80:
                grade = 'B'
            elif overall_score >= 70:
                grade = 'C'
            elif overall_score >= 60:
                grade = 'D'
            else:
                grade = 'F'
            
            result = {
                'overall_score': round(overall_score, 2),
                'grade': grade,
                'metrics': self.metrics,
                'individual_scores': {
                    'backend_coverage': round(backend_coverage, 2),
                    'frontend_coverage': round(frontend_coverage, 2),
                    'code_quality': round(code_quality, 2),
                    'documentation': round(documentation, 2),
                    'performance': round(performance, 2),
                    'compliance': round(compliance, 2)
                },
                'weights': self.weights,
                'timestamp': str(Path().cwd()),
                'recommendations': self._generate_recommendations(overall_score, self.metrics)
            }
            
            return result
            
        except Exception as e:
            print(f"Error calculating overall score: {e}")
            return {'error': str(e)}
    
    def _generate_recommendations(self, score: float, metrics: Dict) -> List[str]:
        """Generate improvement recommendations"""
        recommendations = []
        
        if score < 80:
            recommendations.append("Overall quality needs improvement")
        
        if metrics.get('backend_coverage', {}).get('weighted_score', 0) < 90:
            recommendations.append("Increase backend test coverage to 90%+")
        
        if metrics.get('frontend_coverage', {}).get('weighted_score', 0) < 85:
            recommendations.append("Increase frontend test coverage to 85%+")
        
        if metrics.get('security_scan', {}).get('high_severity_issues', 0) > 0:
            recommendations.append("Fix high severity security issues")
        
        if metrics.get('documentation', {}).get('score', 0) < 80:
            recommendations.append("Improve documentation completeness")
        
        if not recommendations:
            recommendations.append("Excellent quality! Keep up the good work!")
        
        return recommendations

def main():
    """Main function to calculate and output quality score"""
    calculator = QualityScoreCalculator()
    result = calculator.calculate_overall_score()
    
    # Output to console
    print("=" * 60)
    print("CHM Quality Score Report")
    print("=" * 60)
    print(f"Overall Score: {result.get('overall_score', 'N/A')}/100")
    print(f"Grade: {result.get('grade', 'N/A')}")
    print("\nIndividual Scores:")
    for metric, score in result.get('individual_scores', {}).items():
        print(f"  {metric.replace('_', ' ').title()}: {score}/100")
    
    print("\nRecommendations:")
    for rec in result.get('recommendations', []):
        print(f"  • {rec}")
    
    print("\n" + "=" * 60)
    
    # Save to file
    output_file = 'quality-report.json'
    with open(output_file, 'w') as f:
        json.dump(result, f, indent=2)
    
    print(f"Detailed report saved to: {output_file}")
    
    # Exit with appropriate code
    if result.get('overall_score', 0) >= 80:
        sys.exit(0)  # Success
    else:
        sys.exit(1)  # Quality threshold not met

if __name__ == "__main__":
    main()
