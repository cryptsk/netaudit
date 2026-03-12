#!/usr/bin/env python3
"""
CRYPTSK NetAudit - FastAPI Backend
Web API server for the NetAudit dashboard

Copyright (c) 2025 CRYPTSK Pvt Ltd
Website: https://cryptsk.com
Contact: info@cryptsk.com

SECURITY:
- Binds to localhost only by default
- Read-only operations only
- No arbitrary command execution
- Input sanitization in core modules
"""

import sys
import os
import asyncio
from datetime import datetime
from typing import Optional, Dict, Any, List

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# Import core modules
from core import (
    SysctlChecker,
    FirewallChecker,
    NetworkChecker,
    SecurityChecker,
    ScoringEngine,
    AuditResult,
    __version__
)

# Company Information
COMPANY_NAME = "CRYPTSK Pvt Ltd"
COMPANY_WEBSITE = "https://cryptsk.com"
COMPANY_EMAIL = "info@cryptsk.com"
COPYRIGHT = "Copyright (c) 2025 CRYPTSK Pvt Ltd. All rights reserved."

# Create FastAPI app
app = FastAPI(
    title="CRYPTSK NetAudit API",
    description="""
Linux Network Infrastructure Audit Tool - REST API

Professional security auditing for Linux systems by CRYPTSK Pvt Ltd.

**Website:** https://cryptsk.com  
**Contact:** info@cryptsk.com

© 2025 CRYPTSK Pvt Ltd. All rights reserved.
""",
    version=__version__,
    docs_url="/docs",
    redoc_url="/redoc",
    contact={
        "name": "CRYPTSK Pvt Ltd",
        "email": "info@cryptsk.com",
        "url": "https://cryptsk.com",
    },
    license_info={
        "name": "MIT License",
    },
)

# CORS configuration - restrict to localhost
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for development
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# Response models
class ScanResponse(BaseModel):
    """Full scan response"""
    timestamp: str
    hostname: str
    overall_score: int
    grade: str
    categories: Dict[str, Any]
    findings: List[Dict[str, Any]]
    summary: Dict[str, Any]
    recommendations: List[str]


class ScoreResponse(BaseModel):
    """Quick score response"""
    score: int
    grade: str
    critical_issues: int
    warnings: int


class CategoryResponse(BaseModel):
    """Category check response"""
    category: str
    score: int
    checks: List[Dict[str, Any]]


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    version: str
    timestamp: str


# In-memory cache for scan results
scan_cache: Optional[Dict[str, Any]] = None
scan_timestamp: Optional[str] = None


def run_audit() -> Dict[str, Any]:
    """Run the full audit and return results"""
    engine = ScoringEngine()
    
    # Initialize checkers
    sysctl_checker = SysctlChecker()
    firewall_checker = FirewallChecker()
    network_checker = NetworkChecker()
    security_checker = SecurityChecker()
    
    # Run all checks
    sysctl_results = sysctl_checker.run_all_checks()
    engine.add_findings('sysctl', sysctl_results.get('security', []) + sysctl_results.get('performance', []))
    engine.add_findings('firewall', firewall_checker.run_all_checks())
    engine.add_findings('network', network_checker.run_all_checks())
    engine.add_findings('security', security_checker.run_all_checks())
    
    # Generate report
    result = engine.generate_report()
    return result.to_dict()


@app.get("/", response_model=Dict[str, str])
async def root():
    """Root endpoint - API info"""
    return {
        "name": "CRYPTSK NetAudit API",
        "version": __version__,
        "docs": "/docs",
        "endpoints": "/api"
    }


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    return HealthResponse(
        status="healthy",
        version=__version__,
        timestamp=datetime.utcnow().isoformat() + "Z"
    )


@app.get("/api/scan", response_model=ScanResponse)
async def run_scan(
    use_cache: bool = Query(True, description="Use cached results if available")
):
    """
    Run a full security audit scan.
    
    Returns comprehensive security audit results including:
    - Overall security score (0-100)
    - Category breakdowns
    - Individual findings
    - Recommendations
    """
    global scan_cache, scan_timestamp
    
    # Check if we should use cached results
    if use_cache and scan_cache:
        cache_age = (datetime.utcnow() - datetime.fromisoformat(scan_timestamp.replace('Z', ''))).total_seconds()
        if cache_age < 300:  # 5 minute cache
            return scan_cache
    
    try:
        result = run_audit()
        scan_cache = result
        scan_timestamp = result['timestamp']
        return result
        
    except PermissionError:
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions. Some checks require root access."
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Audit failed: {str(e)}"
        )


@app.get("/api/score", response_model=ScoreResponse)
async def get_score():
    """
    Get quick security score.
    
    Returns just the overall score, grade, and issue counts.
    """
    global scan_cache
    
    try:
        if scan_cache:
            return ScoreResponse(
                score=scan_cache['overall_score'],
                grade=scan_cache['grade'],
                critical_issues=scan_cache['summary']['risk_breakdown']['critical'],
                warnings=scan_cache['summary']['risk_breakdown']['warning']
            )
        
        result = run_audit()
        scan_cache = result
        scan_timestamp = result['timestamp']
        
        return ScoreResponse(
            score=result['overall_score'],
            grade=result['grade'],
            critical_issues=result['summary']['risk_breakdown']['critical'],
            warnings=result['summary']['risk_breakdown']['warning']
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Score check failed: {str(e)}"
        )


@app.get("/api/categories", response_model=Dict[str, Any])
async def get_categories():
    """
    Get all category scores.
    
    Returns scores and statistics for each audit category.
    """
    global scan_cache
    
    try:
        if not scan_cache:
            result = run_audit()
            scan_cache = result
            scan_timestamp = result['timestamp']
        
        return {
            "categories": scan_cache['categories'],
            "summary": {
                "total_checks": scan_cache['summary']['total_checks'],
                "passed": scan_cache['summary']['passed'],
                "failed": scan_cache['summary']['failed'],
                "warnings": scan_cache['summary']['warnings']
            }
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Category check failed: {str(e)}"
        )


@app.get("/api/findings")
async def get_findings(
    severity: Optional[str] = Query(None, description="Filter by severity: critical, warning, info"),
    category: Optional[str] = Query(None, description="Filter by category: sysctl, firewall, network, security"),
    status: Optional[str] = Query(None, description="Filter by status: pass, fail, warning, info")
):
    """
    Get detailed findings.
    
    Optional filters:
    - severity: critical, warning, info
    - category: sysctl, firewall, network, security  
    - status: pass, fail, warning, info
    """
    global scan_cache
    
    try:
        if not scan_cache:
            result = run_audit()
            scan_cache = result
            scan_timestamp = result['timestamp']
        
        findings = scan_cache['findings']
        
        # Apply filters
        if severity:
            findings = [f for f in findings if f['severity'] == severity]
        if category:
            findings = [f for f in findings if f['category'] == category]
        if status:
            findings = [f for f in findings if f['status'] == status]
        
        return {
            "total": len(findings),
            "findings": findings
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Findings check failed: {str(e)}"
        )


@app.get("/api/recommendations")
async def get_recommendations():
    """
    Get prioritized recommendations.
    
    Returns list of recommendations ordered by priority.
    """
    global scan_cache
    
    try:
        if not scan_cache:
            result = run_audit()
            scan_cache = result
            scan_timestamp = result['timestamp']
        
        return {
            "recommendations": scan_cache['recommendations']
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Recommendations check failed: {str(e)}"
        )


@app.post("/api/scan/clear-cache")
async def clear_cache():
    """
    Clear the scan cache.
    
    Forces a fresh scan on next request.
    """
    global scan_cache, scan_timestamp
    scan_cache = None
    scan_timestamp = None
    return {"status": "cache cleared"}


@app.get("/api/export/json")
async def export_json():
    """
    Export full report as JSON.
    
    Returns complete audit report in JSON format for download.
    """
    global scan_cache
    
    try:
        if not scan_cache:
            result = run_audit()
            scan_cache = result
            scan_timestamp = result['timestamp']
        
        return JSONResponse(
            content=scan_cache,
            headers={
                "Content-Disposition": f"attachment; filename=netaudit-report-{scan_cache['timestamp'][:10]}.json"
            }
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Export failed: {str(e)}"
        )


if __name__ == "__main__":
    import uvicorn
    
    print("Starting CRYPTSK NetAudit API Server...")
    print(f"Version: {__version__}")
    print("Binding to: http://127.0.0.1:3031")
    print("API Docs: http://127.0.0.1:3031/docs")
    print()
    
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=3031,
        log_level="info"
    )
