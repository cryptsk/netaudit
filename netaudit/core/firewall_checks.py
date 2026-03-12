"""
CRYPTSK NetAudit - Firewall Checks Module
Firewall configuration security checks

Copyright (c) 2025 CRYPTSK Pvt Ltd
Website: https://cryptsk.com
Contact: info@cryptsk.com
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from .collectors import CommandExecutor, PackageChecker


@dataclass
class FirewallCheckResult:
    """Result of a firewall check"""
    check_name: str
    status: str  # 'pass', 'fail', 'warning', 'info'
    message: str
    details: Dict[str, Any]
    severity: str  # 'critical', 'warning', 'info'


class FirewallChecker:
    """
    Check firewall configuration and status
    Supports nftables, iptables, and UFW
    """
    
    def __init__(self):
        self.executor = CommandExecutor
    
    def check_nftables_installed(self) -> FirewallCheckResult:
        """Check if nftables is installed"""
        installed = PackageChecker.is_installed('nftables')
        binary_exists = self.executor.check_command_exists('nft')
        
        return FirewallCheckResult(
            check_name='nftables_installed',
            status='pass' if (installed or binary_exists) else 'fail',
            message='nftables is installed' if (installed or binary_exists) else 'nftables is not installed',
            details={
                'package_installed': installed,
                'binary_exists': binary_exists
            },
            severity='warning'
        )
    
    def check_iptables_installed(self) -> FirewallCheckResult:
        """Check if iptables is installed (fallback)"""
        installed = PackageChecker.is_installed('iptables')
        binary_exists = self.executor.check_command_exists('iptables')
        
        return FirewallCheckResult(
            check_name='iptables_installed',
            status='pass' if (installed or binary_exists) else 'warning',
            message='iptables is installed' if (installed or binary_exists) else 'iptables is not installed',
            details={
                'package_installed': installed,
                'binary_exists': binary_exists
            },
            severity='info'
        )
    
    def check_nftables_rules(self) -> FirewallCheckResult:
        """Check nftables ruleset"""
        details = {
            'has_rules': False,
            'tables': [],
            'chains': [],
            'default_policy': 'unknown'
        }
        
        if not self.executor.check_command_exists('nft'):
            return FirewallCheckResult(
                check_name='nftables_rules',
                status='info',
                message='nftables binary not found',
                details=details,
                severity='info'
            )
        
        # List tables
        result = self.executor.run(['nft', 'list', 'ruleset'])
        if result.success and result.stdout.strip():
            details['has_rules'] = True
            
            # Parse for tables
            for line in result.stdout.split('\n'):
                if 'table ' in line and '{' in line:
                    table_match = line.strip()
                    details['tables'].append(table_match)
                if 'chain ' in line:
                    chain_match = line.strip()
                    details['chains'].append(chain_match)
        
        return FirewallCheckResult(
            check_name='nftables_rules',
            status='pass' if details['has_rules'] else 'warning',
            message='nftables rules configured' if details['has_rules'] else 'No nftables rules configured',
            details=details,
            severity='warning'
        )
    
    def check_iptables_default_policy(self) -> FirewallCheckResult:
        """Check iptables default policy"""
        details = {
            'input_policy': None,
            'forward_policy': None,
            'output_policy': None,
            'has_iptables': False
        }
        
        if not self.executor.check_command_exists('iptables'):
            return FirewallCheckResult(
                check_name='iptables_default_policy',
                status='info',
                message='iptables not available',
                details=details,
                severity='info'
            )
        
        details['has_iptables'] = True
        
        # Get INPUT chain policy
        result = self.executor.run(['iptables', '-L', 'INPUT', '-n'])
        if result.success:
            for line in result.stdout.split('\n'):
                if 'Chain INPUT' in line:
                    if 'DROP' in line:
                        details['input_policy'] = 'DROP'
                    elif 'ACCEPT' in line:
                        details['input_policy'] = 'ACCEPT'
                    break
        
        # Get FORWARD chain policy
        result = self.executor.run(['iptables', '-L', 'FORWARD', '-n'])
        if result.success:
            for line in result.stdout.split('\n'):
                if 'Chain FORWARD' in line:
                    if 'DROP' in line:
                        details['forward_policy'] = 'DROP'
                    elif 'ACCEPT' in line:
                        details['forward_policy'] = 'ACCEPT'
                    break
        
        # Get OUTPUT chain policy
        result = self.executor.run(['iptables', '-L', 'OUTPUT', '-n'])
        if result.success:
            for line in result.stdout.split('\n'):
                if 'Chain OUTPUT' in line:
                    if 'DROP' in line:
                        details['output_policy'] = 'DROP'
                    elif 'ACCEPT' in line:
                        details['output_policy'] = 'ACCEPT'
                    break
        
        # Evaluate security
        input_secure = details['input_policy'] == 'DROP'
        forward_secure = details['forward_policy'] in ['DROP', None]  # None is OK if not routing
        
        status = 'pass' if input_secure else 'fail'
        message = f"INPUT policy: {details['input_policy']} (should be DROP)"
        
        if input_secure:
            message = f"INPUT policy is DROP (secure)"
        
        return FirewallCheckResult(
            check_name='iptables_default_policy',
            status=status,
            message=message,
            details=details,
            severity='critical' if details['input_policy'] == 'ACCEPT' else 'info'
        )
    
    def check_iptables_input_chain(self) -> FirewallCheckResult:
        """Check INPUT chain for overly permissive rules"""
        details = {
            'rules': [],
            'has_accept_all': False,
            'has_permissive_rules': False
        }
        
        if not self.executor.check_command_exists('iptables'):
            return FirewallCheckResult(
                check_name='iptables_input_chain',
                status='info',
                message='iptables not available',
                details=details,
                severity='info'
            )
        
        result = self.executor.run(['iptables', '-L', 'INPUT', '-n', '--line-numbers'])
        if result.success:
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line and not line.startswith('Chain') and not line.startswith('num'):
                    details['rules'].append(line)
                    
                    # Check for dangerous rules
                    if 'ACCEPT' in line and '0.0.0.0/0' in line:
                        if 'dpt:' not in line:  # Accept all ports
                            details['has_accept_all'] = True
                        details['has_permissive_rules'] = True
        
        status = 'warning' if details['has_accept_all'] else 'pass'
        severity = 'critical' if details['has_accept_all'] else 'warning' if details['has_permissive_rules'] else 'info'
        
        message = 'INPUT chain has overly permissive ACCEPT all rules' if details['has_accept_all'] else \
                  'INPUT chain has some permissive rules' if details['has_permissive_rules'] else \
                  'INPUT chain rules look reasonable'
        
        return FirewallCheckResult(
            check_name='iptables_input_chain',
            status=status,
            message=message,
            details=details,
            severity=severity
        )
    
    def check_ufw_status(self) -> FirewallCheckResult:
        """Check UFW status"""
        details = {
            'installed': False,
            'active': False,
            'default_incoming': None,
            'default_outgoing': None
        }
        
        if not self.executor.check_command_exists('ufw'):
            return FirewallCheckResult(
                check_name='ufw_status',
                status='info',
                message='UFW not installed',
                details=details,
                severity='info'
            )
        
        details['installed'] = True
        
        result = self.executor.run(['ufw', 'status', 'verbose'])
        if result.success:
            details['active'] = 'Status: active' in result.stdout
            
            # Parse default policies
            for line in result.stdout.split('\n'):
                if 'Default:' in line:
                    if 'deny' in line.lower() or 'reject' in line.lower():
                        details['default_incoming'] = 'deny'
        
        status = 'pass' if details['active'] else 'warning'
        message = 'UFW is active' if details['active'] else 'UFW is inactive'
        
        return FirewallCheckResult(
            check_name='ufw_status',
            status=status,
            message=message,
            details=details,
            severity='warning'
        )
    
    def check_firewall_active(self) -> FirewallCheckResult:
        """Check if any firewall is active"""
        details = {
            'nftables_active': False,
            'iptables_active': False,
            'ufw_active': False,
            'firewalld_active': False
        }
        
        # Check nftables
        if self.executor.check_command_exists('nft'):
            result = self.executor.run(['nft', 'list', 'ruleset'])
            details['nftables_active'] = bool(result.success and result.stdout.strip())
        
        # Check iptables
        if self.executor.check_command_exists('iptables'):
            result = self.executor.run(['iptables', '-L', '-n'])
            details['iptables_active'] = bool(result.success and len(result.stdout.split('\n')) > 2)
        
        # Check UFW
        if self.executor.check_command_exists('ufw'):
            result = self.executor.run(['ufw', 'status'])
            details['ufw_active'] = 'Status: active' in result.stdout if result.success else False
        
        # Check firewalld
        if self.executor.check_command_exists('firewall-cmd'):
            result = self.executor.run(['firewall-cmd', '--state'])
            details['firewalld_active'] = result.success and 'running' in result.stdout
        
        any_active = any([
            details['nftables_active'],
            details['iptables_active'],
            details['ufw_active'],
            details['firewalld_active']
        ])
        
        return FirewallCheckResult(
            check_name='firewall_active',
            status='pass' if any_active else 'fail',
            message='Firewall is active' if any_active else 'No active firewall detected',
            details=details,
            severity='critical'
        )
    
    def run_all_checks(self) -> List[FirewallCheckResult]:
        """Run all firewall checks"""
        return [
            self.check_firewall_active(),
            self.check_nftables_installed(),
            self.check_iptables_installed(),
            self.check_nftables_rules(),
            self.check_iptables_default_policy(),
            self.check_iptables_input_chain(),
            self.check_ufw_status()
        ]
    
    def get_summary(self) -> Dict[str, Any]:
        """Get firewall security summary"""
        checks = self.run_all_checks()
        
        summary = {
            'total_checks': len(checks),
            'passed': 0,
            'failed': 0,
            'warnings': 0,
            'info': 0,
            'critical_issues': 0,
            'firewall_active': False
        }
        
        for check in checks:
            if check.status == 'pass':
                summary['passed'] += 1
            elif check.status == 'fail':
                summary['failed'] += 1
            elif check.status == 'warning':
                summary['warnings'] += 1
            else:
                summary['info'] += 1
            
            if check.severity == 'critical' and check.status in ['fail', 'warning']:
                summary['critical_issues'] += 1
            
            if check.check_name == 'firewall_active' and check.status == 'pass':
                summary['firewall_active'] = True
        
        return summary
