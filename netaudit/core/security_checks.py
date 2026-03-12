"""
CRYPTSK NetAudit - Security Checks Module
Security configuration checks (SSH, Fail2ban, UFW)

Copyright (c) 2025 CRYPTSK Pvt Ltd
Website: https://cryptsk.com
Contact: info@cryptsk.com
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from .collectors import (
    CommandExecutor, 
    PackageChecker, 
    ServiceChecker, 
    SSHConfigCollector
)


@dataclass
class SecurityCheckResult:
    """Result of a security check"""
    check_name: str
    status: str  # 'pass', 'fail', 'warning', 'info'
    message: str
    details: Dict[str, Any]
    severity: str  # 'critical', 'warning', 'info'
    recommendation: str = ''


class SecurityChecker:
    """
    Check security-related configurations
    """
    
    def __init__(self):
        self.executor = CommandExecutor
    
    def check_ssh_root_login(self) -> SecurityCheckResult:
        """Check if SSH root login is permitted"""
        details = {
            'permit_root_login': None,
            'config_file_exists': False
        }
        
        # Check if sshd_config exists
        result = self.executor.run(['test', '-f', '/etc/ssh/sshd_config'])
        details['config_file_exists'] = result.success
        
        if not details['config_file_exists']:
            return SecurityCheckResult(
                check_name='ssh_root_login',
                status='info',
                message='SSH config not found - SSH may not be installed',
                details=details,
                severity='info',
                recommendation='Install and configure SSH if remote access is needed'
            )
        
        # Get PermitRootLogin setting
        root_login = SSHConfigCollector.get_permit_root_login()
        details['permit_root_login'] = root_login
        
        # Check status
        if root_login in ['yes', 'without-password']:
            status = 'fail'
            severity = 'critical'
            message = f"SSH root login is permitted: {root_login}"
            recommendation = 'Set "PermitRootLogin no" in /etc/ssh/sshd_config'
        elif root_login == 'prohibit-password':
            status = 'warning'
            severity = 'warning'
            message = 'SSH root login with key only (prohibit-password)'
            recommendation = 'Consider "PermitRootLogin no" for better security'
        else:
            status = 'pass'
            severity = 'info'
            message = 'SSH root login is disabled'
            recommendation = ''
        
        return SecurityCheckResult(
            check_name='ssh_root_login',
            status=status,
            message=message,
            details=details,
            severity=severity,
            recommendation=recommendation
        )
    
    def check_ssh_password_auth(self) -> SecurityCheckResult:
        """Check if SSH password authentication is enabled"""
        details = {
            'password_authentication': None,
            'keyboard_interactive': None
        }
        
        result = self.executor.run(['test', '-f', '/etc/ssh/sshd_config'])
        if not result.success:
            return SecurityCheckResult(
                check_name='ssh_password_auth',
                status='info',
                message='SSH config not found',
                details=details,
                severity='info',
                recommendation=''
            )
        
        # Get PasswordAuthentication setting
        config = SSHConfigCollector.parse_sshd_config()
        details['password_authentication'] = config.get('passwordauthentication', 'yes')
        details['keyboard_interactive'] = config.get('keyboard-interactive', 'unknown')
        
        if details['password_authentication'] == 'yes':
            status = 'warning'
            severity = 'warning'
            message = 'SSH password authentication is enabled'
            recommendation = 'Disable password auth: "PasswordAuthentication no" in /etc/ssh/sshd_config. Use SSH keys instead.'
        else:
            status = 'pass'
            severity = 'info'
            message = 'SSH password authentication is disabled'
            recommendation = ''
        
        return SecurityCheckResult(
            check_name='ssh_password_auth',
            status=status,
            message=message,
            details=details,
            severity=severity,
            recommendation=recommendation
        )
    
    def check_ssh_port(self) -> SecurityCheckResult:
        """Check SSH port configuration"""
        details = {
            'ssh_port': 22,
            'is_default': True
        }
        
        result = self.executor.run(['test', '-f', '/etc/ssh/sshd_config'])
        if not result.success:
            return SecurityCheckResult(
                check_name='ssh_port',
                status='info',
                message='SSH config not found',
                details=details,
                severity='info',
                recommendation=''
            )
        
        config = SSHConfigCollector.parse_sshd_config()
        port = config.get('port', '22')
        
        try:
            details['ssh_port'] = int(port)
        except ValueError:
            details['ssh_port'] = 22
        
        details['is_default'] = details['ssh_port'] == 22
        
        if details['is_default']:
            status = 'warning'
            severity = 'warning'
            message = 'SSH using default port 22'
            recommendation = 'Consider changing SSH port to non-standard port (security through obscurity)'
        else:
            status = 'pass'
            severity = 'info'
            message = f"SSH using non-standard port {details['ssh_port']}"
            recommendation = ''
        
        return SecurityCheckResult(
            check_name='ssh_port',
            status=status,
            message=message,
            details=details,
            severity=severity,
            recommendation=recommendation
        )
    
    def check_fail2ban(self) -> SecurityCheckResult:
        """Check if fail2ban is installed and active"""
        details = {
            'installed': False,
            'active': False,
            'enabled': False,
            'jails': []
        }
        
        # Check if installed
        details['installed'] = PackageChecker.is_installed('fail2ban')
        
        if not details['installed']:
            return SecurityCheckResult(
                check_name='fail2ban',
                status='warning',
                message='fail2ban is not installed',
                details=details,
                severity='warning',
                recommendation='Install fail2ban for brute-force protection: apt install fail2ban'
            )
        
        # Check if active
        details['active'] = ServiceChecker.is_active('fail2ban')
        details['enabled'] = ServiceChecker.is_enabled('fail2ban')
        
        # Get active jails
        result = self.executor.run(['fail2ban-client', 'status'])
        if result.success:
            for line in result.stdout.split('\n'):
                if 'Jail list:' in line:
                    jails = line.split(':')[1].strip()
                    details['jails'] = [j.strip() for j in jails.split(',') if j.strip()]
        
        if details['active']:
            status = 'pass'
            severity = 'info'
            message = f"fail2ban is active with {len(details['jails'])} jail(s)"
            recommendation = ''
        else:
            status = 'warning'
            severity = 'warning'
            message = 'fail2ban is installed but not running'
            recommendation = 'Start fail2ban: systemctl start fail2ban'
        
        return SecurityCheckResult(
            check_name='fail2ban',
            status=status,
            message=message,
            details=details,
            severity=severity,
            recommendation=recommendation
        )
    
    def check_ufw_status(self) -> SecurityCheckResult:
        """Check UFW firewall status"""
        details = {
            'installed': False,
            'active': False,
            'default_incoming': 'unknown',
            'default_outgoing': 'unknown'
        }
        
        # Check if installed
        details['installed'] = PackageChecker.is_installed('ufw')
        
        if not details['installed']:
            return SecurityCheckResult(
                check_name='ufw_firewall',
                status='info',
                message='UFW is not installed',
                details=details,
                severity='info',
                recommendation='Consider installing UFW for simple firewall management'
            )
        
        # Check status
        result = self.executor.run(['ufw', 'status', 'verbose'])
        if result.success:
            details['active'] = 'Status: active' in result.stdout
            
            for line in result.stdout.split('\n'):
                if 'Default:' in line:
                    if 'deny' in line.lower() or 'reject' in line.lower():
                        details['default_incoming'] = 'deny'
                    elif 'allow' in line.lower():
                        details['default_incoming'] = 'allow'
        
        if details['active']:
            status = 'pass'
            severity = 'info'
            message = 'UFW firewall is active'
            recommendation = ''
        else:
            status = 'warning'
            severity = 'warning'
            message = 'UFW is installed but inactive'
            recommendation = 'Enable UFW: ufw enable (review rules first!)'
        
        return SecurityCheckResult(
            check_name='ufw_firewall',
            status=status,
            message=message,
            details=details,
            severity=severity,
            recommendation=recommendation
        )
    
    def check_unattended_upgrades(self) -> SecurityCheckResult:
        """Check if automatic security updates are enabled"""
        details = {
            'installed': False,
            'enabled': False
        }
        
        # Check if installed (Debian/Ubuntu)
        details['installed'] = PackageChecker.is_installed('unattended-upgrades')
        
        if not details['installed']:
            return SecurityCheckResult(
                check_name='unattended_upgrades',
                status='info',
                message='Unattended upgrades not installed',
                details=details,
                severity='info',
                recommendation='Consider installing unattended-upgrades for automatic security updates'
            )
        
        # Check if enabled
        result = self.executor.run(['cat', '/etc/apt/apt.conf.d/20auto-upgrades'])
        if result.success:
            details['enabled'] = 'Update-Package-Lists "1"' in result.stdout and \
                                 'Unattended-Upgrade "1"' in result.stdout
        
        if details['enabled']:
            status = 'pass'
            severity = 'info'
            message = 'Automatic security updates are enabled'
            recommendation = ''
        else:
            status = 'info'
            severity = 'info'
            message = 'Automatic security updates may not be fully configured'
            recommendation = 'Configure unattended-upgrades for automatic security patches'
        
        return SecurityCheckResult(
            check_name='unattended_upgrades',
            status=status,
            message=message,
            details=details,
            severity=severity,
            recommendation=recommendation
        )
    
    def check_sudo_configuration(self) -> SecurityCheckResult:
        """Check sudo configuration"""
        details = {
            'sudo_installed': False,
            'wheel_group_exists': False,
            'sudo_group_exists': False
        }
        
        details['sudo_installed'] = PackageChecker.is_installed('sudo')
        
        if not details['sudo_installed']:
            return SecurityCheckResult(
                check_name='sudo_config',
                status='info',
                message='sudo is not installed',
                details=details,
                severity='info',
                recommendation='Install sudo for privilege management'
            )
        
        # Check for sudo/wheel groups
        result = self.executor.run(['getent', 'group', 'sudo'])
        details['sudo_group_exists'] = result.success
        
        result = self.executor.run(['getent', 'group', 'wheel'])
        details['wheel_group_exists'] = result.success
        
        return SecurityCheckResult(
            check_name='sudo_config',
            status='pass',
            message='sudo is properly installed',
            details=details,
            severity='info',
            recommendation=''
        )
    
    def check_password_policy(self) -> SecurityCheckResult:
        """Check password policy configuration"""
        details = {
            'pwquality_installed': False,
            'minlen': None,
            'minclass': None,
            'maxrepeat': None
        }
        
        # Check for pwquality (pam_pwquality)
        details['pwquality_installed'] = PackageChecker.is_installed('libpam-pwquality') or \
                                         PackageChecker.is_installed('libpwquality')
        
        # Read pwquality config
        result = self.executor.run(['cat', '/etc/security/pwquality.conf'])
        if result.success:
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line.startswith('minlen'):
                    try:
                        details['minlen'] = int(line.split('=')[1].strip())
                    except (IndexError, ValueError):
                        pass
                elif line.startswith('minclass'):
                    try:
                        details['minclass'] = int(line.split('=')[1].strip())
                    except (IndexError, ValueError):
                        pass
                elif line.startswith('maxrepeat'):
                    try:
                        details['maxrepeat'] = int(line.split('=')[1].strip())
                    except (IndexError, ValueError):
                        pass
        
        issues = []
        if details['minlen'] and details['minlen'] < 12:
            issues.append('Minimum password length < 12')
        if details['minclass'] and details['minclass'] < 3:
            issues.append('Minimum character classes < 3')
        
        if issues:
            status = 'warning'
            severity = 'warning'
            message = f"Password policy issues: {', '.join(issues)}"
            recommendation = 'Strengthen password policy in /etc/security/pwquality.conf'
        elif details['pwquality_installed']:
            status = 'pass'
            severity = 'info'
            message = 'Password quality module is installed'
            recommendation = ''
        else:
            status = 'info'
            severity = 'info'
            message = 'Password quality module not found'
            recommendation = 'Install libpam-pwquality for password policy enforcement'
        
        return SecurityCheckResult(
            check_name='password_policy',
            status=status,
            message=message,
            details=details,
            severity=severity,
            recommendation=recommendation
        )
    
    def check_world_writable_files(self) -> SecurityCheckResult:
        """Check for world-writable files in critical directories"""
        details = {
            'world_writable_count': 0,
            'sample_files': []
        }
        
        # Check /etc for world-writable files
        result = self.executor.run(['find', '/etc', '-type', 'f', '-perm', '-002', '-print'])
        if result.success:
            files = [f for f in result.stdout.split('\n') if f.strip()]
            details['world_writable_count'] = len(files)
            details['sample_files'] = files[:10]  # First 10
        
        if details['world_writable_count'] > 0:
            status = 'warning'
            severity = 'warning'
            message = f"Found {details['world_writable_count']} world-writable files in /etc"
            recommendation = 'Review and fix permissions: chmod o-w <file>'
        else:
            status = 'pass'
            severity = 'info'
            message = 'No world-writable files found in /etc'
            recommendation = ''
        
        return SecurityCheckResult(
            check_name='world_writable_files',
            status=status,
            message=message,
            details=details,
            severity=severity,
            recommendation=recommendation
        )
    
    def run_all_checks(self) -> List[SecurityCheckResult]:
        """Run all security checks"""
        return [
            self.check_ssh_root_login(),
            self.check_ssh_password_auth(),
            self.check_ssh_port(),
            self.check_fail2ban(),
            self.check_ufw_status(),
            self.check_unattended_upgrades(),
            self.check_sudo_configuration(),
            self.check_password_policy(),
            self.check_world_writable_files()
        ]
    
    def get_summary(self) -> Dict[str, Any]:
        """Get security configuration summary"""
        checks = self.run_all_checks()
        
        summary = {
            'total_checks': len(checks),
            'passed': 0,
            'failed': 0,
            'warnings': 0,
            'info': 0,
            'critical_issues': 0
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
        
        return summary
