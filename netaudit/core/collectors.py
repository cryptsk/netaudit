"""
CRYPTSK NetAudit - Collectors Module
Safe system data collection utilities

Copyright (c) 2025 CRYPTSK Pvt Ltd
Website: https://cryptsk.com
Contact: info@cryptsk.com
"""

import subprocess
import shutil
import os
import re
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, field


@dataclass
class CommandResult:
    """Result of a command execution"""
    success: bool
    stdout: str
    stderr: str
    return_code: int
    command: str


class CommandExecutor:
    """
    Safe command executor with no shell=True
    All commands are executed safely without shell interpolation
    """
    
    @staticmethod
    def run(command: List[str], timeout: int = 30) -> CommandResult:
        """
        Execute a command safely without shell=True
        
        Args:
            command: List of command parts (e.g., ['ls', '-la', '/etc'])
            timeout: Timeout in seconds
            
        Returns:
            CommandResult with execution details
        """
        try:
            # Validate command parts
            if not command or not isinstance(command, list):
                return CommandResult(
                    success=False,
                    stdout='',
                    stderr='Invalid command format',
                    return_code=-1,
                    command=' '.join(command) if command else ''
                )
            
            # Sanitize each part (no shell metacharacters injection)
            sanitized = []
            for part in command:
                if isinstance(part, str):
                    sanitized.append(part)
                else:
                    sanitized.append(str(part))
            
            result = subprocess.run(
                sanitized,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False  # NEVER use shell=True for security
            )
            
            return CommandResult(
                success=result.returncode == 0,
                stdout=result.stdout.strip(),
                stderr=result.stderr.strip(),
                return_code=result.returncode,
                command=' '.join(sanitized)
            )
            
        except subprocess.TimeoutExpired:
            return CommandResult(
                success=False,
                stdout='',
                stderr=f'Command timed out after {timeout} seconds',
                return_code=-1,
                command=' '.join(command)
            )
        except FileNotFoundError:
            return CommandResult(
                success=False,
                stdout='',
                stderr=f'Command not found: {command[0] if command else "unknown"}',
                return_code=127,
                command=' '.join(command)
            )
        except PermissionError:
            return CommandResult(
                success=False,
                stdout='',
                stderr='Permission denied',
                return_code=126,
                command=' '.join(command)
            )
        except Exception as e:
            return CommandResult(
                success=False,
                stdout='',
                stderr=f'Unexpected error: {str(e)}',
                return_code=-1,
                command=' '.join(command)
            )
    
    @staticmethod
    def run_readonly_file(filepath: str) -> CommandResult:
        """Safely read a file using cat (for system files)"""
        if not os.path.exists(filepath):
            return CommandResult(
                success=False,
                stdout='',
                stderr=f'File not found: {filepath}',
                return_code=1,
                command=f'cat {filepath}'
            )
        return CommandExecutor.run(['cat', filepath])
    
    @staticmethod
    def check_command_exists(command: str) -> bool:
        """Check if a command exists in PATH"""
        return shutil.which(command) is not None


class SysctlCollector:
    """Collect sysctl kernel parameters"""
    
    @staticmethod
    def get_parameter(param: str) -> Optional[str]:
        """Get a single sysctl parameter value"""
        if not re.match(r'^[a-zA-Z0-9_.]+$', param):
            return None
        
        result = CommandExecutor.run(['sysctl', '-n', param])
        if result.success:
            return result.stdout.strip()
        return None
    
    @staticmethod
    def get_parameters(params: List[str]) -> Dict[str, Optional[str]]:
        """Get multiple sysctl parameters"""
        return {param: SysctlCollector.get_parameter(param) for param in params}
    
    @staticmethod
    def get_all_network_params() -> Dict[str, str]:
        """Get all network-related sysctl parameters"""
        result = CommandExecutor.run(['sysctl', '-a'])
        params = {}
        
        if result.success:
            for line in result.stdout.split('\n'):
                if 'net.' in line and '=' in line:
                    parts = line.split('=', 1)
                    if len(parts) == 2:
                        key = parts[0].strip()
                        value = parts[1].strip()
                        params[key] = value
        
        return params


class ServiceChecker:
    """Check systemd service status"""
    
    @staticmethod
    def is_active(service: str) -> bool:
        """Check if a service is active"""
        if not re.match(r'^[a-zA-Z0-9_.-]+$', service):
            return False
        
        result = CommandExecutor.run(['systemctl', 'is-active', service])
        return result.success and result.stdout == 'active'
    
    @staticmethod
    def is_enabled(service: str) -> bool:
        """Check if a service is enabled"""
        if not re.match(r'^[a-zA-Z0-9_.-]+$', service):
            return False
        
        result = CommandExecutor.run(['systemctl', 'is-enabled', service])
        return result.success and result.stdout == 'enabled'
    
    @staticmethod
    def get_status(service: str) -> Dict[str, Any]:
        """Get detailed service status"""
        return {
            'name': service,
            'active': ServiceChecker.is_active(service),
            'enabled': ServiceChecker.is_enabled(service)
        }


class PackageChecker:
    """Check installed packages"""
    
    @staticmethod
    def is_installed(package: str) -> bool:
        """Check if a package is installed"""
        # Try dpkg first (Debian/Ubuntu)
        if CommandExecutor.check_command_exists('dpkg'):
            result = CommandExecutor.run(['dpkg', '-l', package])
            if result.success and f'ii  {package}' in result.stdout:
                return True
        
        # Try rpm (RHEL/CentOS/Fedora)
        if CommandExecutor.check_command_exists('rpm'):
            result = CommandExecutor.run(['rpm', '-q', package])
            if result.success:
                return True
        
        # Try pacman (Arch Linux)
        if CommandExecutor.check_command_exists('pacman'):
            result = CommandExecutor.run(['pacman', '-Q', package])
            if result.success:
                return True
        
        # Check if binary exists as fallback
        return CommandExecutor.check_command_exists(package)
    
    @staticmethod
    def check_binary_exists(binary: str) -> bool:
        """Check if a binary exists in PATH"""
        return CommandExecutor.check_command_exists(binary)


class NetworkInfoCollector:
    """Collect network interface information"""
    
    @staticmethod
    def get_interfaces() -> List[Dict[str, Any]]:
        """Get network interfaces and their status"""
        interfaces = []
        
        # Use ip command
        result = CommandExecutor.run(['ip', '-o', 'link', 'show'])
        if result.success:
            for line in result.stdout.split('\n'):
                if not line.strip():
                    continue
                
                # Parse: 2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500...
                match = re.match(r'\d+:\s+([^:@]+)[:@]', line)
                if match:
                    iface_name = match.group(1).strip()
                    
                    # Skip loopback
                    if iface_name == 'lo':
                        continue
                    
                    # Get MTU
                    mtu_match = re.search(r'mtu\s+(\d+)', line)
                    mtu = int(mtu_match.group(1)) if mtu_match else 0
                    
                    # Get state
                    state_match = re.search(r'state\s+(\w+)', line)
                    state = state_match.group(1) if state_match else 'unknown'
                    
                    interfaces.append({
                        'name': iface_name,
                        'mtu': mtu,
                        'state': state
                    })
        
        return interfaces
    
    @staticmethod
    def get_ethtool_info(interface: str) -> Dict[str, Any]:
        """Get ethtool offloading info for an interface"""
        info = {
            'interface': interface,
            'offload': {},
            'link_speed': None,
            'duplex': None
        }
        
        if not CommandExecutor.check_command_exists('ethtool'):
            return info
        
        # Get offload settings
        result = CommandExecutor.run(['ethtool', '-k', interface])
        if result.success:
            for line in result.stdout.split('\n'):
                if ':' in line:
                    parts = line.split(':')
                    if len(parts) == 2:
                        key = parts[0].strip()
                        value = parts[1].strip()
                        info['offload'][key] = value
        
        # Get link settings
        result = CommandExecutor.run(['ethtool', interface])
        if result.success:
            speed_match = re.search(r'Speed:\s+(\d+)', result.stdout)
            if speed_match:
                info['link_speed'] = int(speed_match.group(1))
            
            duplex_match = re.search(r'Duplex:\s+(\w+)', result.stdout)
            if duplex_match:
                info['duplex'] = duplex_match.group(1)
        
        return info


class SSHConfigCollector:
    """Collect SSH configuration"""
    
    @staticmethod
    def parse_sshd_config() -> Dict[str, str]:
        """Parse sshd_config file"""
        config = {}
        
        result = CommandExecutor.run(['cat', '/etc/ssh/sshd_config'])
        if result.success:
            for line in result.stdout.split('\n'):
                line = line.strip()
                
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue
                
                # Parse key value
                if ' ' in line:
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        config[parts[0].lower()] = parts[1]
        
        return config
    
    @staticmethod
    def get_permit_root_login() -> Optional[str]:
        """Get PermitRootLogin setting"""
        config = SSHConfigCollector.parse_sshd_config()
        return config.get('permitrootlogin', 'prohibit-password')  # Default in modern OpenSSH
    
    @staticmethod
    def get_password_authentication() -> Optional[str]:
        """Get PasswordAuthentication setting"""
        config = SSHConfigCollector.parse_sshd_config()
        return config.get('passwordauthentication', 'yes')  # Default is yes
