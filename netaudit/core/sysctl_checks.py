"""
CRYPTSK NetAudit - Sysctl Checks Module
Kernel parameter security checks

Copyright (c) 2025 CRYPTSK Pvt Ltd
Website: https://cryptsk.com
Contact: info@cryptsk.com
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from .collectors import SysctlCollector


@dataclass
class SysctlCheckResult:
    """Result of a sysctl check"""
    parameter: str
    current_value: Optional[str]
    recommended_value: str
    recommendation_type: str  # 'security', 'performance', 'info'
    compliant: bool
    message: str
    severity: str  # 'critical', 'warning', 'info'


class SysctlChecker:
    """
    Check kernel sysctl parameters for security and performance
    """
    
    # Security-related sysctl parameters with recommendations
    SECURITY_PARAMS = {
        # IP Forwarding - Should typically be disabled unless acting as router
        'net.ipv4.ip_forward': {
            'recommended': '0',
            'type': 'security',
            'severity': 'warning',
            'message': 'IP forwarding should be disabled unless the system is a router',
            'router_allowed': True
        },
        # ICMP redirects
        'net.ipv4.conf.all.accept_redirects': {
            'recommended': '0',
            'type': 'security',
            'severity': 'warning',
            'message': 'ICMP redirects should be disabled to prevent MITM attacks'
        },
        'net.ipv4.conf.default.accept_redirects': {
            'recommended': '0',
            'type': 'security',
            'severity': 'warning',
            'message': 'ICMP redirects should be disabled for new interfaces'
        },
        # Send redirects
        'net.ipv4.conf.all.send_redirects': {
            'recommended': '0',
            'type': 'security',
            'severity': 'info',
            'message': 'Sending redirects should be disabled unless routing'
        },
        # Source routing
        'net.ipv4.conf.all.accept_source_route': {
            'recommended': '0',
            'type': 'security',
            'severity': 'critical',
            'message': 'Source routing should be disabled to prevent IP spoofing'
        },
        'net.ipv4.conf.default.accept_source_route': {
            'recommended': '0',
            'type': 'security',
            'severity': 'critical',
            'message': 'Source routing should be disabled for new interfaces'
        },
        # Reverse path filtering
        'net.ipv4.conf.all.rp_filter': {
            'recommended': '1',
            'type': 'security',
            'severity': 'warning',
            'message': 'Reverse path filtering should be enabled'
        },
        'net.ipv4.conf.default.rp_filter': {
            'recommended': '1',
            'type': 'security',
            'severity': 'warning',
            'message': 'Reverse path filtering should be enabled for new interfaces'
        },
        # ICMP echo requests (ping)
        'net.ipv4.icmp_echo_ignore_all': {
            'recommended': '0',
            'type': 'info',
            'severity': 'info',
            'message': 'Responding to pings is typically acceptable'
        },
        # ICMP broadcast echo
        'net.ipv4.icmp_echo_ignore_broadcasts': {
            'recommended': '1',
            'type': 'security',
            'severity': 'info',
            'message': 'Should ignore broadcast pings to prevent smurf attacks'
        },
        # SYN cookies
        'net.ipv4.tcp_syncookies': {
            'recommended': '1',
            'type': 'security',
            'severity': 'warning',
            'message': 'SYN cookies should be enabled for SYN flood protection'
        },
    }
    
    # Performance-related sysctl parameters
    PERFORMANCE_PARAMS = {
        # Connection tracking
        'net.netfilter.nf_conntrack_max': {
            'recommended': '262144',
            'type': 'performance',
            'severity': 'info',
            'message': 'Connection tracking table size - adjust based on traffic'
        },
        # Socket backlog
        'net.core.somaxconn': {
            'recommended': '65535',
            'type': 'performance',
            'severity': 'info',
            'message': 'Socket listen backlog - increase for high-traffic servers'
        },
        # TCP TIME_WAIT reuse
        'net.ipv4.tcp_tw_reuse': {
            'recommended': '1',
            'type': 'performance',
            'severity': 'info',
            'message': 'Reuse TIME_WAIT sockets for outgoing connections'
        },
        # TCP FIN timeout
        'net.ipv4.tcp_fin_timeout': {
            'recommended': '30',
            'type': 'performance',
            'severity': 'info',
            'message': 'Reduce FIN timeout to release sockets faster'
        },
        # TCP keepalive
        'net.ipv4.tcp_keepalive_time': {
            'recommended': '600',
            'type': 'performance',
            'severity': 'info',
            'message': 'TCP keepalive time in seconds'
        },
        # Buffer sizes
        'net.core.rmem_default': {
            'recommended': '262144',
            'type': 'performance',
            'severity': 'info',
            'message': 'Default socket receive buffer size'
        },
        'net.core.wmem_default': {
            'recommended': '262144',
            'type': 'performance',
            'severity': 'info',
            'message': 'Default socket send buffer size'
        },
        'net.core.rmem_max': {
            'recommended': '16777216',
            'type': 'performance',
            'severity': 'info',
            'message': 'Maximum socket receive buffer size'
        },
        'net.core.wmem_max': {
            'recommended': '16777216',
            'type': 'performance',
            'severity': 'info',
            'message': 'Maximum socket send buffer size'
        },
        # Max open files (affects socket limits)
        'fs.file-max': {
            'recommended': '1000000',
            'type': 'performance',
            'severity': 'info',
            'message': 'Maximum number of open file descriptors'
        },
    }
    
    def __init__(self):
        self.collector = SysctlCollector()
    
    def check_parameter(self, param: str, config: Dict[str, Any]) -> SysctlCheckResult:
        """Check a single sysctl parameter"""
        current = self.collector.get_parameter(param)
        
        if current is None:
            return SysctlCheckResult(
                parameter=param,
                current_value=None,
                recommended_value=config.get('recommended', 'unknown'),
                recommendation_type=config.get('type', 'info'),
                compliant=False,
                message=f"Unable to read parameter {param}",
                severity='warning'
            )
        
        # Compare values
        recommended = config.get('recommended', '')
        compliant = current == recommended
        
        # Some parameters have context-dependent recommendations
        if param == 'net.ipv4.ip_forward' and config.get('router_allowed'):
            # IP forwarding is acceptable if system is a router
            severity = 'info' if current == '1' else config.get('severity', 'info')
        else:
            severity = config.get('severity', 'info')
        
        return SysctlCheckResult(
            parameter=param,
            current_value=current,
            recommended_value=recommended,
            recommendation_type=config.get('type', 'info'),
            compliant=compliant,
            message=config.get('message', ''),
            severity=severity if not compliant else 'info'
        )
    
    def run_security_checks(self) -> List[SysctlCheckResult]:
        """Run all security-related sysctl checks"""
        results = []
        for param, config in self.SECURITY_PARAMS.items():
            results.append(self.check_parameter(param, config))
        return results
    
    def run_performance_checks(self) -> List[SysctlCheckResult]:
        """Run all performance-related sysctl checks"""
        results = []
        for param, config in self.PERFORMANCE_PARAMS.items():
            results.append(self.check_parameter(param, config))
        return results
    
    def run_all_checks(self) -> Dict[str, List[SysctlCheckResult]]:
        """Run all sysctl checks"""
        return {
            'security': self.run_security_checks(),
            'performance': self.run_performance_checks()
        }
    
    def get_critical_params(self) -> List[str]:
        """Get list of critical parameters that should be checked"""
        critical = []
        for param, config in self.SECURITY_PARAMS.items():
            if config.get('severity') == 'critical':
                critical.append(param)
        return critical
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of sysctl configuration"""
        all_params = {**self.SECURITY_PARAMS, **self.PERFORMANCE_PARAMS}
        
        summary = {
            'total_checked': len(all_params),
            'compliant': 0,
            'non_compliant': 0,
            'unavailable': 0,
            'critical_issues': 0,
            'warnings': 0,
            'info': 0
        }
        
        for param, config in all_params.items():
            current = self.collector.get_parameter(param)
            
            if current is None:
                summary['unavailable'] += 1
            elif current == config.get('recommended'):
                summary['compliant'] += 1
            else:
                summary['non_compliant'] += 1
                severity = config.get('severity', 'info')
                if severity == 'critical':
                    summary['critical_issues'] += 1
                elif severity == 'warning':
                    summary['warnings'] += 1
                else:
                    summary['info'] += 1
        
        return summary
