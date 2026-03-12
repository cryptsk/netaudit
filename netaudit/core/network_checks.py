"""
CRYPTSK NetAudit - Network Checks Module
Network configuration security checks

Copyright (c) 2025 CRYPTSK Pvt Ltd
Website: https://cryptsk.com
Contact: info@cryptsk.com
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from .collectors import CommandExecutor, NetworkInfoCollector, ServiceChecker


@dataclass
class NetworkCheckResult:
    """Result of a network check"""
    check_name: str
    status: str  # 'pass', 'fail', 'warning', 'info'
    message: str
    details: Dict[str, Any]
    severity: str  # 'critical', 'warning', 'info'


class NetworkChecker:
    """
    Check network configuration and settings
    """
    
    def __init__(self):
        self.executor = CommandExecutor
        self.net_collector = NetworkInfoCollector()
    
    def check_mtu_consistency(self) -> NetworkCheckResult:
        """Check MTU consistency across interfaces"""
        details = {
            'interfaces': [],
            'mtu_values': [],
            'inconsistent': False,
            'recommended_mtu': 1500
        }
        
        interfaces = self.net_collector.get_interfaces()
        
        for iface in interfaces:
            details['interfaces'].append(iface['name'])
            if iface['mtu'] > 0:
                details['mtu_values'].append({
                    'interface': iface['name'],
                    'mtu': iface['mtu']
                })
        
        # Check if all MTUs are consistent
        mtus = [m['mtu'] for m in details['mtu_values']]
        if mtus:
            unique_mtus = set(mtus)
            details['inconsistent'] = len(unique_mtus) > 1
        
        status = 'warning' if details['inconsistent'] else 'pass'
        message = f"MTU inconsistent across interfaces: {unique_mtus}" if details['inconsistent'] else \
                  f"MTU consistent across {len(details['mtu_values'])} interfaces"
        
        return NetworkCheckResult(
            check_name='mtu_consistency',
            status=status,
            message=message,
            details=details,
            severity='info'
        )
    
    def check_nic_offloading(self) -> NetworkCheckResult:
        """Check NIC offloading status"""
        details = {
            'interfaces': [],
            'offload_issues': []
        }
        
        interfaces = self.net_collector.get_interfaces()
        
        if not self.executor.check_command_exists('ethtool'):
            return NetworkCheckResult(
                check_name='nic_offloading',
                status='info',
                message='ethtool not available for offloading check',
                details=details,
                severity='info'
            )
        
        for iface in interfaces:
            info = self.net_collector.get_ethtool_info(iface['name'])
            
            offload_data = {
                'interface': iface['name'],
                'offload_settings': info.get('offload', {})
            }
            details['interfaces'].append(offload_data)
            
            # Check for potentially problematic offloading
            offload = info.get('offload', {})
            
            # Generic segmentation offload can cause issues
            if offload.get('generic-segmentation-offload') == 'on':
                details['offload_issues'].append({
                    'interface': iface['name'],
                    'setting': 'generic-segmentation-offload',
                    'value': 'on',
                    'note': 'GSO enabled - may cause issues with some network configs'
                })
            
            # Large receive offload
            if offload.get('large-receive-offload') == 'on':
                details['offload_issues'].append({
                    'interface': iface['name'],
                    'setting': 'large-receive-offload',
                    'value': 'on',
                    'note': 'LRO enabled - may cause performance issues'
                })
        
        status = 'warning' if details['offload_issues'] else 'pass'
        message = f"Found {len(details['offload_issues'])} offloading considerations" if details['offload_issues'] else \
                  "NIC offloading settings look reasonable"
        
        return NetworkCheckResult(
            check_name='nic_offloading',
            status=status,
            message=message,
            details=details,
            severity='info'
        )
    
    def check_irq_balance(self) -> NetworkCheckResult:
        """Check if IRQ balance service is active"""
        details = {
            'irqbalance_installed': False,
            'irqbalance_active': False,
            'irqbalance_enabled': False
        }
        
        # Check if irqbalance service exists
        details['irqbalance_installed'] = self.executor.check_command_exists('irqbalance')
        
        # Check service status
        details['irqbalance_active'] = ServiceChecker.is_active('irqbalance')
        details['irqbalance_enabled'] = ServiceChecker.is_enabled('irqbalance')
        
        status = 'warning' if not details['irqbalance_active'] else 'pass'
        message = 'IRQ balance service is active' if details['irqbalance_active'] else \
                  'IRQ balance service is not active - may impact multi-core network performance'
        
        return NetworkCheckResult(
            check_name='irq_balance',
            status=status,
            message=message,
            details=details,
            severity='info'
        )
    
    def check_multiple_nics(self) -> NetworkCheckResult:
        """Check for multiple NIC configuration"""
        details = {
            'interface_count': 0,
            'active_interfaces': [],
            'inactive_interfaces': [],
            'potential_bridge_setup': False
        }
        
        interfaces = self.net_collector.get_interfaces()
        details['interface_count'] = len(interfaces)
        
        for iface in interfaces:
            if iface['state'] == 'UP' or iface['state'] == 'UNKNOWN':
                details['active_interfaces'].append(iface['name'])
            else:
                details['inactive_interfaces'].append(iface['name'])
        
        # Check for bridge interfaces
        result = self.executor.run(['ip', 'link', 'show', 'type', 'bridge'])
        if result.success and result.stdout.strip():
            details['potential_bridge_setup'] = True
        
        # Multiple active interfaces might indicate bonding/teaming
        status = 'info'
        message = f"Found {details['interface_count']} interfaces, {len(details['active_interfaces'])} active"
        
        return NetworkCheckResult(
            check_name='multiple_nics',
            status=status,
            message=message,
            details=details,
            severity='info'
        )
    
    def check_promiscuous_interfaces(self) -> NetworkCheckResult:
        """Check for interfaces in promiscuous mode"""
        details = {
            'promiscuous_interfaces': []
        }
        
        result = self.executor.run(['ip', 'link', 'show'])
        if result.success:
            current_iface = None
            for line in result.stdout.split('\n'):
                # Interface line
                if re_match := __import__('re').search(r'^\d+:\s+([^:@]+)', line):
                    current_iface = re_match.group(1).strip()
                
                # Check for PROMISC flag
                if 'PROMISC' in line and current_iface:
                    details['promiscuous_interfaces'].append(current_iface)
                    current_iface = None
        
        status = 'warning' if details['promiscuous_interfaces'] else 'pass'
        message = f"Found promiscuous interfaces: {details['promiscuous_interfaces']}" if details['promiscuous_interfaces'] else \
                  "No interfaces in promiscuous mode"
        
        return NetworkCheckResult(
            check_name='promiscuous_interfaces',
            status=status,
            message=message,
            details=details,
            severity='warning'
        )
    
    def check_listening_ports(self) -> NetworkCheckResult:
        """Check for listening ports"""
        details = {
            'listening_ports': [],
            'public_bindings': [],
            'total_listening': 0
        }
        
        if self.executor.check_command_exists('ss'):
            result = self.executor.run(['ss', '-tuln'])
        elif self.executor.check_command_exists('netstat'):
            result = self.executor.run(['netstat', '-tuln'])
        else:
            return NetworkCheckResult(
                check_name='listening_ports',
                status='info',
                message='Neither ss nor netstat available',
                details=details,
                severity='info'
            )
        
        if result.success:
            for line in result.stdout.split('\n'):
                if 'LISTEN' in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        # Extract address and port
                        addr_port = parts[-2] if ':' in parts[-2] else parts[-1]
                        
                        # Parse address
                        if ':' in addr_port:
                            addr, port = addr_port.rsplit(':', 1)
                            
                            # Check for public binding
                            is_public = addr in ['0.0.0.0', '::', '*']
                            
                            port_info = {
                                'address': addr,
                                'port': port,
                                'protocol': 'tcp' if 'tcp' in line.lower() else 'udp',
                                'public': is_public
                            }
                            
                            details['listening_ports'].append(port_info)
                            if is_public:
                                details['public_bindings'].append(port_info)
            
            details['total_listening'] = len(details['listening_ports'])
        
        status = 'warning' if len(details['public_bindings']) > 10 else 'pass'
        message = f"{details['total_listening']} ports listening, {len(details['public_bindings'])} on public interfaces"
        
        return NetworkCheckResult(
            check_name='listening_ports',
            status=status,
            message=message,
            details=details,
            severity='info'
        )
    
    def check_dns_config(self) -> NetworkCheckResult:
        """Check DNS configuration"""
        details = {
            'nameservers': [],
            'search_domains': [],
            'using_local_resolver': False
        }
        
        result = self.executor.run(['cat', '/etc/resolv.conf'])
        if result.success:
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line.startswith('nameserver'):
                    parts = line.split()
                    if len(parts) >= 2:
                        ns = parts[1]
                        details['nameservers'].append(ns)
                        if ns in ['127.0.0.1', '::1']:
                            details['using_local_resolver'] = True
                elif line.startswith('search'):
                    parts = line.split()
                    if len(parts) >= 2:
                        details['search_domains'] = parts[1:]
        
        status = 'info'
        message = f"Using {len(details['nameservers'])} nameserver(s)"
        
        return NetworkCheckResult(
            check_name='dns_config',
            status=status,
            message=message,
            details=details,
            severity='info'
        )
    
    def run_all_checks(self) -> List[NetworkCheckResult]:
        """Run all network checks"""
        return [
            self.check_mtu_consistency(),
            self.check_nic_offloading(),
            self.check_irq_balance(),
            self.check_multiple_nics(),
            self.check_promiscuous_interfaces(),
            self.check_listening_ports(),
            self.check_dns_config()
        ]
    
    def get_summary(self) -> Dict[str, Any]:
        """Get network configuration summary"""
        checks = self.run_all_checks()
        
        summary = {
            'total_checks': len(checks),
            'passed': 0,
            'failed': 0,
            'warnings': 0,
            'info': 0,
            'interface_count': 0
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
            
            if check.check_name == 'multiple_nics':
                summary['interface_count'] = check.details.get('interface_count', 0)
        
        return summary
