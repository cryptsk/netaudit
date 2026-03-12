"""
CRYPTSK NetAudit - Scoring Engine Module
Security score calculation and report generation

Copyright (c) 2025 CRYPTSK Pvt Ltd
Website: https://cryptsk.com
Contact: info@cryptsk.com
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime
import json


class RiskLevel(Enum):
    """Risk level enumeration"""
    CRITICAL = 'critical'
    WARNING = 'warning'
    INFO = 'info'
    PASS = 'pass'


@dataclass
class CheckResult:
    """Individual check result"""
    category: str
    check_name: str
    status: str  # 'pass', 'fail', 'warning', 'info'
    message: str
    severity: str  # 'critical', 'warning', 'info'
    details: Dict[str, Any] = field(default_factory=dict)
    recommendation: str = ''
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AuditResult:
    """Complete audit result"""
    timestamp: str
    hostname: str
    overall_score: int
    grade: str
    categories: Dict[str, Dict[str, Any]]
    findings: List[CheckResult]
    summary: Dict[str, Any]
    recommendations: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'hostname': self.hostname,
            'overall_score': self.overall_score,
            'grade': self.grade,
            'categories': self.categories,
            'findings': [f.to_dict() for f in self.findings],
            'summary': self.summary,
            'recommendations': self.recommendations
        }
    
    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class ScoringEngine:
    """
    Calculate security scores based on check results
    """
    
    # Score weights for different severity levels
    SEVERITY_WEIGHTS = {
        'critical': 25,
        'warning': 10,
        'info': 0
    }
    
    # Grade thresholds
    GRADE_THRESHOLDS = [
        (90, 'A', 'Excellent'),
        (80, 'B', 'Good'),
        (70, 'C', 'Fair'),
        (60, 'D', 'Poor'),
        (0, 'F', 'Critical Issues')
    ]
    
    # Category weights for overall score
    CATEGORY_WEIGHTS = {
        'sysctl': 0.25,
        'firewall': 0.30,
        'network': 0.15,
        'security': 0.30
    }
    
    def __init__(self):
        self.findings: List[CheckResult] = []
        self.categories: Dict[str, Dict[str, Any]] = {}
    
    def add_findings(self, category: str, results: List[Any]) -> None:
        """Add check results from a category"""
        self.categories[category] = {
            'total': len(results),
            'passed': 0,
            'failed': 0,
            'warnings': 0,
            'info': 0,
            'critical_issues': 0
        }
        
        for result in results:
            # Convert result to CheckResult
            # Handle different result types (sysctl has 'parameter', others have 'check_name')
            check_name = 'unknown'
            if hasattr(result, 'check_name'):
                check_name = result.check_name
            elif hasattr(result, 'parameter'):
                check_name = result.parameter
            
            check_result = CheckResult(
                category=category,
                check_name=check_name,
                status=result.status if hasattr(result, 'status') else 'info',
                message=result.message if hasattr(result, 'message') else '',
                severity=result.severity if hasattr(result, 'severity') else 'info',
                details=result.details if hasattr(result, 'details') else {},
                recommendation=result.recommendation if hasattr(result, 'recommendation') else ''
            )
            
            self.findings.append(check_result)
            
            # Update category stats
            if check_result.status == 'pass':
                self.categories[category]['passed'] += 1
            elif check_result.status == 'fail':
                self.categories[category]['failed'] += 1
            elif check_result.status == 'warning':
                self.categories[category]['warnings'] += 1
            else:
                self.categories[category]['info'] += 1
            
            if check_result.severity == 'critical' and check_result.status in ['fail', 'warning']:
                self.categories[category]['critical_issues'] += 1
    
    def calculate_category_score(self, category: str) -> int:
        """Calculate score for a specific category"""
        if category not in self.categories:
            return 100
        
        cat = self.categories[category]
        total = cat['total']
        if total == 0:
            return 100
        
        # Base score starts at 100
        score = 100
        
        # Deduct points based on issues
        score -= cat['critical_issues'] * self.SEVERITY_WEIGHTS['critical']
        score -= (cat['failed'] - cat['critical_issues']) * self.SEVERITY_WEIGHTS['warning']
        score -= cat['warnings'] * 5  # Warnings deduct 5 points each
        
        return max(0, min(100, score))
    
    def calculate_overall_score(self) -> int:
        """Calculate overall security score"""
        if not self.categories:
            return 100
        
        weighted_score = 0
        total_weight = 0
        
        for category, weight in self.CATEGORY_WEIGHTS.items():
            if category in self.categories:
                cat_score = self.calculate_category_score(category)
                weighted_score += cat_score * weight
                total_weight += weight
        
        if total_weight == 0:
            return 100
        
        return int(weighted_score / total_weight)
    
    def get_grade(self, score: int) -> str:
        """Get letter grade for score"""
        for threshold, grade, _ in self.GRADE_THRESHOLDS:
            if score >= threshold:
                return grade
        return 'F'
    
    def get_grade_description(self, score: int) -> str:
        """Get grade description"""
        for threshold, _, description in self.GRADE_THRESHOLDS:
            if score >= threshold:
                return description
        return 'Critical Issues'
    
    def get_recommendations(self) -> List[str]:
        """Get prioritized recommendations"""
        recommendations = []
        
        # Critical issues first
        critical = [f for f in self.findings if f.severity == 'critical' and f.status in ['fail', 'warning']]
        for finding in critical:
            if finding.recommendation:
                recommendations.append(f"[CRITICAL] {finding.recommendation}")
        
        # Then warnings
        warnings = [f for f in self.findings if f.severity == 'warning' and f.status in ['fail', 'warning']]
        for finding in warnings:
            if finding.recommendation and finding.recommendation not in recommendations:
                recommendations.append(f"[WARNING] {finding.recommendation}")
        
        return recommendations[:20]  # Limit to 20 recommendations
    
    def get_risk_breakdown(self) -> Dict[str, int]:
        """Get risk level breakdown"""
        return {
            'critical': len([f for f in self.findings if f.severity == 'critical' and f.status in ['fail', 'warning']]),
            'warning': len([f for f in self.findings if f.severity == 'warning' and f.status in ['fail', 'warning']]),
            'info': len([f for f in self.findings if f.severity == 'info']),
            'passed': len([f for f in self.findings if f.status == 'pass'])
        }
    
    def generate_report(self, hostname: str = 'localhost') -> AuditResult:
        """Generate complete audit report"""
        import socket
        
        try:
            actual_hostname = socket.gethostname()
        except:
            actual_hostname = hostname
        
        overall_score = self.calculate_overall_score()
        
        return AuditResult(
            timestamp=datetime.utcnow().isoformat() + 'Z',
            hostname=actual_hostname,
            overall_score=overall_score,
            grade=self.get_grade(overall_score),
            categories={
                cat: {
                    **stats,
                    'score': self.calculate_category_score(cat)
                }
                for cat, stats in self.categories.items()
            },
            findings=self.findings,
            summary={
                'total_checks': len(self.findings),
                'passed': sum(1 for f in self.findings if f.status == 'pass'),
                'failed': sum(1 for f in self.findings if f.status == 'fail'),
                'warnings': sum(1 for f in self.findings if f.status == 'warning'),
                'info': sum(1 for f in self.findings if f.status == 'info'),
                'risk_breakdown': self.get_risk_breakdown()
            },
            recommendations=self.get_recommendations()
        )
    
    def clear(self) -> None:
        """Clear all findings"""
        self.findings = []
        self.categories = {}


def format_cli_output(result: AuditResult) -> str:
    """Format audit result for CLI output"""
    lines = []
    
    # Header
    lines.append("=" * 60)
    lines.append("  CRYPTSK NetAudit - Security Audit Report")
    lines.append("=" * 60)
    lines.append("")
    
    # Basic info
    lines.append(f"Timestamp: {result.timestamp}")
    lines.append(f"Hostname:  {result.hostname}")
    lines.append("")
    
    # Score
    lines.append("-" * 40)
    lines.append("  OVERALL SECURITY SCORE")
    lines.append("-" * 40)
    lines.append(f"  Score: {result.overall_score}/100")
    lines.append(f"  Grade: {result.grade} ({result.grade if hasattr(result, 'grade_description') else ''})")
    lines.append("")
    
    # Risk breakdown
    lines.append("-" * 40)
    lines.append("  RISK BREAKDOWN")
    lines.append("-" * 40)
    risk = result.summary.get('risk_breakdown', {})
    lines.append(f"  Critical Issues: {risk.get('critical', 0)}")
    lines.append(f"  Warnings:        {risk.get('warning', 0)}")
    lines.append(f"  Info:            {risk.get('info', 0)}")
    lines.append(f"  Passed:          {risk.get('passed', 0)}")
    lines.append("")
    
    # Category scores
    lines.append("-" * 40)
    lines.append("  CATEGORY SCORES")
    lines.append("-" * 40)
    for cat, data in result.categories.items():
        score = data.get('score', 100)
        lines.append(f"  {cat.capitalize():15} : {score:3}/100")
    lines.append("")
    
    # Findings by severity
    lines.append("-" * 40)
    lines.append("  CRITICAL ISSUES")
    lines.append("-" * 40)
    critical = [f for f in result.findings if f.severity == 'critical' and f.status in ['fail', 'warning']]
    if critical:
        for finding in critical:
            lines.append(f"  [!] {finding.check_name}")
            lines.append(f"      {finding.message}")
    else:
        lines.append("  No critical issues found")
    lines.append("")
    
    lines.append("-" * 40)
    lines.append("  WARNINGS")
    lines.append("-" * 40)
    warnings = [f for f in result.findings if f.severity == 'warning' and f.status in ['fail', 'warning']]
    if warnings:
        for finding in warnings[:10]:  # Limit output
            lines.append(f"  [w] {finding.check_name}")
            lines.append(f"      {finding.message}")
        if len(warnings) > 10:
            lines.append(f"  ... and {len(warnings) - 10} more warnings")
    else:
        lines.append("  No warnings found")
    lines.append("")
    
    # Recommendations
    lines.append("-" * 40)
    lines.append("  TOP RECOMMENDATIONS")
    lines.append("-" * 40)
    if result.recommendations:
        for i, rec in enumerate(result.recommendations[:10], 1):
            lines.append(f"  {i}. {rec}")
    else:
        lines.append("  No recommendations - system looks good!")
    lines.append("")
    
    lines.append("=" * 60)
    lines.append("  Audit completed successfully")
    lines.append("=" * 60)
    
    return "\n".join(lines)
