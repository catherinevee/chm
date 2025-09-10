"""
Structured SSH Command Output Parsers for Network Devices
"""

import re
import json
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

# Import result objects
from backend.common.result_objects import (
    create_success_result, create_failure_result, create_partial_success_result,
    FallbackData, HealthStatus, HealthLevel
)


@dataclass
class ParsedInterface:
    """Parsed interface information"""
    name: str
    status: str
    protocol_status: str
    ip_address: Optional[str] = None
    description: Optional[str] = None
    speed: Optional[str] = None
    mtu: Optional[int] = None
    duplex: Optional[str] = None
    vlan: Optional[str] = None
    counters: Optional[Dict[str, int]] = None


@dataclass
class ParsedSystemInfo:
    """Parsed system information"""
    hostname: str
    model: Optional[str] = None
    serial_number: Optional[str] = None
    software_version: Optional[str] = None
    uptime: Optional[str] = None
    cpu_usage: Optional[float] = None
    memory_usage: Optional[float] = None
    temperature: Optional[float] = None


class CommandParser(ABC):
    """Abstract base class for command parsers"""
    
    @abstractmethod
    def can_parse(self, command: str, output: str) -> bool:
        """Check if this parser can handle the command output"""
        pass
    
    @abstractmethod
    def parse(self, command: str, output: str) -> Dict[str, Any]:
        """Parse command output and return structured data"""
        pass


class CiscoIOSParser(CommandParser):
    """Parser for Cisco IOS commands"""
    
    def can_parse(self, command: str, output: str) -> bool:
        """Check if this is Cisco IOS output"""
        cisco_indicators = [
            'cisco', 'ios', 'catalyst', 'version', 'show'
        ]
        output_lower = output.lower()
        return any(indicator in output_lower for indicator in cisco_indicators)
    
    def parse(self, command: str, output: str) -> Dict[str, Any]:
        """Parse Cisco IOS command output"""
        command_lower = command.lower().strip()
        
        if 'show version' in command_lower:
            return self._parse_show_version(output)
        elif 'show interfaces' in command_lower or 'show ip interface' in command_lower:
            return self._parse_show_interfaces(output)
        elif 'show processes cpu' in command_lower:
            return self._parse_show_processes_cpu(output)
        elif 'show memory' in command_lower:
            return self._parse_show_memory(output)
        elif 'show environment' in command_lower:
            return self._parse_show_environment(output)
        else:
            return {'raw_output': output, 'parsed': False}
    
    def _parse_show_version(self, output: str) -> Dict[str, Any]:
        """Parse 'show version' output"""
        result = {'command': 'show_version', 'parsed': True}
        
        try:
            # Extract system information using regex patterns
            patterns = {
                'software_version': r'Version\s+([^\s,]+)',
                'model': r'cisco\s+(\w+)\s+\(',
                'serial_number': r'System serial number\s*:\s*(\w+)',
                'uptime': r'uptime is\s+(.+?)(?:\n|$)',
                'reload_reason': r'System returned to ROM by\s+(.+?)(?:\n|$)',
                'system_image': r'System image file is\s*"([^"]+)"',
                'configuration_register': r'Configuration register is\s+(0x\w+)'
            }
            
            for key, pattern in patterns.items():
                match = re.search(pattern, output, re.IGNORECASE | re.MULTILINE)
                if match:
                    result[key] = match.group(1).strip()
            
            # Parse memory information
            memory_match = re.search(r'(\d+)K bytes of (\w+) memory', output, re.IGNORECASE)
            if memory_match:
                result['memory_size'] = int(memory_match.group(1)) * 1024
                result['memory_type'] = memory_match.group(2)
            
            # Parse flash memory
            flash_match = re.search(r'(\d+)K bytes of (\w+) flash', output, re.IGNORECASE)
            if flash_match:
                result['flash_size'] = int(flash_match.group(1)) * 1024
                result['flash_type'] = flash_match.group(2)
                
        except Exception as e:
            logger.error(f"Error parsing Cisco show version: {e}")
            result['parse_error'] = str(e)
        
        return result
    
    def _parse_show_interfaces(self, output: str) -> Dict[str, Any]:
        """Parse 'show interfaces' output"""
        result = {'command': 'show_interfaces', 'parsed': True, 'interfaces': []}
        
        try:
            # Split by interface blocks
            interface_blocks = re.split(r'^(\w+[\d/\.]+)\s+is\s+', output, flags=re.MULTILINE)
            
            for i in range(1, len(interface_blocks), 2):
                if i + 1 >= len(interface_blocks):
                    break
                
                interface_name = interface_blocks[i].strip()
                interface_data = interface_blocks[i + 1]
                
                interface = self._parse_interface_block(interface_name, interface_data)
                if interface:
                    result['interfaces'].append(interface)
                    
        except Exception as e:
            logger.error(f"Error parsing Cisco show interfaces: {e}")
            result['parse_error'] = str(e)
        
        return result
    
    def _parse_interface_block(self, name: str, data: str) -> Optional[Dict[str, Any]]:
        """Parse a single interface block"""
        try:
            interface = {'name': name}
            
            # Status and protocol
            status_match = re.search(r'(\w+),.*protocol is (\w+)', data)
            if status_match:
                interface['status'] = status_match.group(1)
                interface['protocol_status'] = status_match.group(2)
            
            # Description
            desc_match = re.search(r'Description:\s*(.+)', data)
            if desc_match:
                interface['description'] = desc_match.group(1).strip()
            
            # Hardware information
            hw_match = re.search(r'Hardware is (.+?),', data)
            if hw_match:
                interface['hardware'] = hw_match.group(1)
            
            # MTU
            mtu_match = re.search(r'MTU (\d+)', data)
            if mtu_match:
                interface['mtu'] = int(mtu_match.group(1))
            
            # Bandwidth
            bw_match = re.search(r'BW (\d+) Kbit', data)
            if bw_match:
                interface['bandwidth_kbps'] = int(bw_match.group(1))
            
            # Duplex and Speed
            duplex_match = re.search(r'(\w+-duplex), (\w+Mb/s)', data)
            if duplex_match:
                interface['duplex'] = duplex_match.group(1)
                interface['speed'] = duplex_match.group(2)
            
            # Counters
            counters = {}
            counter_patterns = {
                'input_packets': r'(\d+) packets input',
                'input_bytes': r'(\d+) bytes',
                'output_packets': r'(\d+) packets output',
                'input_errors': r'(\d+) input error',
                'crc_errors': r'(\d+) CRC',
                'collisions': r'(\d+) collision'
            }
            
            for counter, pattern in counter_patterns.items():
                match = re.search(pattern, data)
                if match:
                    counters[counter] = int(match.group(1))
            
            if counters:
                interface['counters'] = counters
            
            return interface
            
        except Exception as e:
            logger.error(f"Error parsing interface {name}: {e}")
            return create_failure_result(
                error_code="INTERFACE_PARSE_ERROR",
                message=f"Failed to parse interface {name}",
                fallback_data=FallbackData(
                    data={'name': name, 'status': 'unknown', 'parsed': False},
                    health_status=HealthStatus(
                        level=HealthLevel.ERROR,
                        message="Interface parsing failed",
                        details=f"Error parsing interface {name}: {str(e)}"
                    )
                ),
                suggestions=["Check interface output format", "Verify SSH command output", "Review parsing logic"]
            )
    
    def _parse_show_processes_cpu(self, output: str) -> Dict[str, Any]:
        """Parse 'show processes cpu' output"""
        result = {'command': 'show_processes_cpu', 'parsed': True}
        
        try:
            # Parse CPU utilization
            cpu_match = re.search(r'CPU utilization.*?(\d+)%.*?(\d+)%.*?(\d+)%', output)
            if cpu_match:
                result['cpu_5sec'] = int(cpu_match.group(1))
                result['cpu_1min'] = int(cpu_match.group(2))
                result['cpu_5min'] = int(cpu_match.group(3))
            
            # Parse top processes
            processes = []
            process_lines = re.findall(r'^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+[\d\.]+%\s+[\d\.]+%\s+[\d\.]+%\s+\d+\s+(.+)$', output, re.MULTILINE)
            
            for proc_match in process_lines[:10]:  # Top 10 processes
                processes.append({
                    'pid': int(proc_match[0]),
                    'runtime_ms': int(proc_match[1]),
                    'invoked': int(proc_match[2]),
                    'usecs': int(proc_match[3]),
                    'name': proc_match[4].strip()
                })
            
            if processes:
                result['top_processes'] = processes
                
        except Exception as e:
            logger.error(f"Error parsing Cisco show processes cpu: {e}")
            result['parse_error'] = str(e)
        
        return result
    
    def _parse_show_memory(self, output: str) -> Dict[str, Any]:
        """Parse 'show memory' output"""
        result = {'command': 'show_memory', 'parsed': True, 'memory_pools': []}
        
        try:
            # Parse memory summary
            summary_match = re.search(r'Head\s+Total\(b\)\s+Used\(b\)\s+Free\(b\)\s+Lowest\(b\)\s+Largest\(b\)', output)
            if summary_match:
                # Find memory pool entries
                pool_matches = re.findall(r'^(\w+)\s+([0-9A-F]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)', output, re.MULTILINE)
                
                for pool_match in pool_matches:
                    pool = {
                        'name': pool_match[0],
                        'head': pool_match[1],
                        'total_bytes': int(pool_match[2]),
                        'used_bytes': int(pool_match[3]),
                        'free_bytes': int(pool_match[4]),
                        'lowest_bytes': int(pool_match[5]),
                        'largest_bytes': int(pool_match[6])
                    }
                    result['memory_pools'].append(pool)
                    
        except Exception as e:
            logger.error(f"Error parsing Cisco show memory: {e}")
            result['parse_error'] = str(e)
        
        return result
    
    def _parse_show_environment(self, output: str) -> Dict[str, Any]:
        """Parse 'show environment' output"""
        result = {'command': 'show_environment', 'parsed': True, 'sensors': []}
        
        try:
            # Parse temperature sensors
            temp_matches = re.findall(r'(\w+)\s+(\d+)C/(\d+)F\s+(\w+)\s+(\w+)', output)
            
            for temp_match in temp_matches:
                sensor = {
                    'name': temp_match[0],
                    'temperature_c': int(temp_match[1]),
                    'temperature_f': int(temp_match[2]),
                    'status': temp_match[3],
                    'threshold': temp_match[4]
                }
                result['sensors'].append(sensor)
            
            # Parse power supplies
            power_matches = re.findall(r'Power Supply (\d+):\s*(.+)', output)
            power_supplies = []
            
            for power_match in power_matches:
                power_supplies.append({
                    'number': int(power_match[0]),
                    'status': power_match[1].strip()
                })
            
            if power_supplies:
                result['power_supplies'] = power_supplies
                
        except Exception as e:
            logger.error(f"Error parsing Cisco show environment: {e}")
            result['parse_error'] = str(e)
        
        return result


class JuniperParser(CommandParser):
    """Parser for Juniper JunOS commands"""
    
    def can_parse(self, command: str, output: str) -> bool:
        """Check if this is Juniper output"""
        juniper_indicators = [
            'junos', 'juniper', 'show version', 'show chassis'
        ]
        output_lower = output.lower()
        return any(indicator in output_lower for indicator in juniper_indicators)
    
    def parse(self, command: str, output: str) -> Dict[str, Any]:
        """Parse Juniper command output"""
        command_lower = command.lower().strip()
        
        if 'show version' in command_lower:
            return self._parse_show_version(output)
        elif 'show interfaces' in command_lower:
            return self._parse_show_interfaces(output)
        elif 'show chassis hardware' in command_lower:
            return self._parse_show_chassis_hardware(output)
        else:
            return {'raw_output': output, 'parsed': False}
    
    def _parse_show_version(self, output: str) -> Dict[str, Any]:
        """Parse Juniper 'show version' output"""
        result = {'command': 'show_version', 'parsed': True}
        
        try:
            # Try JSON format first
            if output.strip().startswith('{'):
                json_data = json.loads(output)
                if 'software-information' in json_data:
                    sw_info = json_data['software-information'][0]
                    result.update({
                        'hostname': sw_info.get('host-name', [{}])[0].get('data', ''),
                        'model': sw_info.get('product-model', [{}])[0].get('data', ''),
                        'software_version': sw_info.get('junos-version', [{}])[0].get('data', ''),
                    })
            else:
                # Parse text format
                patterns = {
                    'hostname': r'Hostname:\s*(.+)',
                    'model': r'Model:\s*(.+)',
                    'software_version': r'JUNOS\s+(.+)',
                }
                
                for key, pattern in patterns.items():
                    match = re.search(pattern, output, re.IGNORECASE)
                    if match:
                        result[key] = match.group(1).strip()
                        
        except Exception as e:
            logger.error(f"Error parsing Juniper show version: {e}")
            result['parse_error'] = str(e)
        
        return result
    
    def _parse_show_interfaces(self, output: str) -> Dict[str, Any]:
        """Parse Juniper 'show interfaces' output"""
        result = {'command': 'show_interfaces', 'parsed': True, 'interfaces': []}
        
        try:
            # Parse text format interface output
            interface_blocks = re.split(r'^Physical interface:\s*(\S+)', output, flags=re.MULTILINE)
            
            for i in range(1, len(interface_blocks), 2):
                if i + 1 >= len(interface_blocks):
                    break
                
                interface_name = interface_blocks[i].strip()
                interface_data = interface_blocks[i + 1]
                
                interface = {'name': interface_name}
                
                # Parse interface details
                if 'Enabled' in interface_data:
                    interface['status'] = 'up'
                elif 'Disabled' in interface_data:
                    interface['status'] = 'down'
                
                # Speed and duplex
                speed_match = re.search(r'Speed:\s*(\S+)', interface_data)
                if speed_match:
                    interface['speed'] = speed_match.group(1)
                
                result['interfaces'].append(interface)
                
        except Exception as e:
            logger.error(f"Error parsing Juniper show interfaces: {e}")
            result['parse_error'] = str(e)
        
        return result
    
    def _parse_show_chassis_hardware(self, output: str) -> Dict[str, Any]:
        """Parse Juniper 'show chassis hardware' output"""
        result = {'command': 'show_chassis_hardware', 'parsed': True, 'hardware': []}
        
        try:
            # Parse hardware components
            hw_lines = re.findall(r'^(\S+(?:\s+\S+)*?)\s+(\w+)\s+(.+)$', output, re.MULTILINE)
            
            for hw_match in hw_lines:
                component = {
                    'name': hw_match[0].strip(),
                    'type': hw_match[1],
                    'description': hw_match[2].strip()
                }
                result['hardware'].append(component)
                
        except Exception as e:
            logger.error(f"Error parsing Juniper show chassis hardware: {e}")
            result['parse_error'] = str(e)
        
        return result


class LinuxParser(CommandParser):
    """Parser for Linux system commands"""
    
    def can_parse(self, command: str, output: str) -> bool:
        """Check if this is Linux output"""
        linux_indicators = [
            'linux', 'ubuntu', 'centos', 'debian', 'red hat', 'kernel'
        ]
        output_lower = output.lower()
        return any(indicator in output_lower for indicator in linux_indicators)
    
    def parse(self, command: str, output: str) -> Dict[str, Any]:
        """Parse Linux command output"""
        command_lower = command.lower().strip()
        
        if 'uname' in command_lower:
            return self._parse_uname(output)
        elif 'free' in command_lower:
            return self._parse_free(output)
        elif 'top' in command_lower or 'cpu' in output.lower():
            return self._parse_top(output)
        else:
            return {'raw_output': output, 'parsed': False}
    
    def _parse_uname(self, output: str) -> Dict[str, Any]:
        """Parse 'uname -a' output"""
        result = {'command': 'uname', 'parsed': True}
        
        try:
            parts = output.strip().split()
            if len(parts) >= 6:
                result.update({
                    'kernel_name': parts[0],
                    'hostname': parts[1],
                    'kernel_release': parts[2],
                    'kernel_version': parts[3],
                    'machine': parts[4],
                    'processor': parts[5] if len(parts) > 5 else parts[4]
                })
                
        except Exception as e:
            logger.error(f"Error parsing uname output: {e}")
            result['parse_error'] = str(e)
        
        return result
    
    def _parse_free(self, output: str) -> Dict[str, Any]:
        """Parse 'free' command output"""
        result = {'command': 'free', 'parsed': True}
        
        try:
            lines = output.strip().split('\n')
            
            for line in lines:
                if line.startswith('Mem:'):
                    parts = line.split()
                    if len(parts) >= 7:
                        result['memory'] = {
                            'total': int(parts[1]),
                            'used': int(parts[2]),
                            'free': int(parts[3]),
                            'shared': int(parts[4]),
                            'buff_cache': int(parts[5]),
                            'available': int(parts[6])
                        }
                elif line.startswith('Swap:'):
                    parts = line.split()
                    if len(parts) >= 4:
                        result['swap'] = {
                            'total': int(parts[1]),
                            'used': int(parts[2]),
                            'free': int(parts[3])
                        }
                        
        except Exception as e:
            logger.error(f"Error parsing free output: {e}")
            result['parse_error'] = str(e)
        
        return result
    
    def _parse_top(self, output: str) -> Dict[str, Any]:
        """Parse 'top' command output"""
        result = {'command': 'top', 'parsed': True}
        
        try:
            # Parse CPU line
            cpu_match = re.search(r'%Cpu\(s\):\s*([\d\.]+)\s*us,.*?([\d\.]+)\s*sy,.*?([\d\.]+)\s*id', output)
            if cpu_match:
                user_cpu = float(cpu_match.group(1))
                sys_cpu = float(cpu_match.group(2))
                idle_cpu = float(cpu_match.group(3))
                
                result['cpu'] = {
                    'user': user_cpu,
                    'system': sys_cpu,
                    'idle': idle_cpu,
                    'usage': 100.0 - idle_cpu
                }
                
        except Exception as e:
            logger.error(f"Error parsing top output: {e}")
            result['parse_error'] = str(e)
        
        return result


class AristaParser(CommandParser):
    """Parser for Arista EOS commands"""
    
    def can_parse(self, command: str, output: str) -> bool:
        """Check if this is Arista EOS output"""
        arista_indicators = [
            'arista', 'eos', 'anet', 'show version'
        ]
        output_lower = output.lower()
        return any(indicator in output_lower for indicator in arista_indicators)
    
    def parse(self, command: str, output: str) -> Dict[str, Any]:
        """Parse Arista command output"""
        command_lower = command.lower().strip()
        
        if 'show version' in command_lower:
            return self._parse_show_version(output)
        elif 'show interfaces' in command_lower:
            return self._parse_show_interfaces(output)
        else:
            return {'raw_output': output, 'parsed': False}
    
    def _parse_show_version(self, output: str) -> Dict[str, Any]:
        """Parse Arista 'show version' output"""
        result = {'command': 'show_version', 'parsed': True}
        
        try:
            patterns = {
                'software_version': r'Software image version:\s*([^\n]+)',
                'model': r'Hardware version:\s*([^\n]+)',
                'serial_number': r'Serial number:\s*([^\n]+)',
                'system_mac': r'System MAC address:\s*([^\n]+)',
                'uptime': r'Uptime:\s*([^\n]+)'
            }
            
            for key, pattern in patterns.items():
                match = re.search(pattern, output, re.IGNORECASE | re.MULTILINE)
                if match:
                    result[key] = match.group(1).strip()
                    
        except Exception as e:
            logger.error(f"Error parsing Arista show version: {e}")
            result['parse_error'] = str(e)
        
        return result
    
    def _parse_show_interfaces(self, output: str) -> Dict[str, Any]:
        """Parse Arista 'show interfaces' output"""
        result = {'command': 'show_interfaces', 'parsed': True, 'interfaces': []}
        
        try:
            # Arista uses similar format to Cisco but with some differences
            interface_blocks = re.split(r'^(\w+[\d/\.]+)\s+is\s+', output, flags=re.MULTILINE)
            
            for i in range(1, len(interface_blocks), 2):
                if i + 1 >= len(interface_blocks):
                    break
                
                interface_name = interface_blocks[i].strip()
                interface_data = interface_blocks[i + 1]
                
                interface = {'name': interface_name}
                
                # Status parsing
                status_match = re.search(r'(\w+),.*protocol is (\w+)', interface_data)
                if status_match:
                    interface['status'] = status_match.group(1)
                    interface['protocol_status'] = status_match.group(2)
                
                result['interfaces'].append(interface)
                
        except Exception as e:
            logger.error(f"Error parsing Arista show interfaces: {e}")
            result['parse_error'] = str(e)
        
        return result


class HPParser(CommandParser):
    """Parser for HP/HPE Comware commands"""
    
    def can_parse(self, command: str, output: str) -> bool:
        """Check if this is HP/HPE output"""
        hp_indicators = [
            'hp', 'hpe', 'comware', 'procurve'
        ]
        output_lower = output.lower()
        return any(indicator in output_lower for indicator in hp_indicators)
    
    def parse(self, command: str, output: str) -> Dict[str, Any]:
        """Parse HP command output"""
        command_lower = command.lower().strip()
        
        if 'display version' in command_lower:
            return self._parse_display_version(output)
        elif 'display interface' in command_lower:
            return self._parse_display_interface(output)
        else:
            return {'raw_output': output, 'parsed': False}
    
    def _parse_display_version(self, output: str) -> Dict[str, Any]:
        """Parse HP 'display version' output"""
        result = {'command': 'display_version', 'parsed': True}
        
        try:
            patterns = {
                'software_version': r'Software Version\s*([^\n]+)',
                'model': r'HP\s+(\w+[^\n]*)',
                'uptime': r'Uptime is\s*([^\n]+)'
            }
            
            for key, pattern in patterns.items():
                match = re.search(pattern, output, re.IGNORECASE | re.MULTILINE)
                if match:
                    result[key] = match.group(1).strip()
                    
        except Exception as e:
            logger.error(f"Error parsing HP display version: {e}")
            result['parse_error'] = str(e)
        
        return result
    
    def _parse_display_interface(self, output: str) -> Dict[str, Any]:
        """Parse HP 'display interface' output"""
        result = {'command': 'display_interface', 'parsed': True, 'interfaces': []}
        
        try:
            # HP Comware uses different interface format
            interface_blocks = re.split(r'^(\w+[\d/\.]+)\s+current state', output, flags=re.MULTILINE)
            
            for i in range(1, len(interface_blocks), 2):
                if i + 1 >= len(interface_blocks):
                    break
                
                interface_name = interface_blocks[i].strip()
                interface_data = interface_blocks[i + 1]
                
                interface = {'name': interface_name}
                
                # Parse interface status
                if 'UP' in interface_data:
                    interface['status'] = 'up'
                elif 'DOWN' in interface_data:
                    interface['status'] = 'down'
                
                result['interfaces'].append(interface)
                
        except Exception as e:
            logger.error(f"Error parsing HP display interface: {e}")
            result['parse_error'] = str(e)
        
        return result


class SSHCommandParser:
    """Main SSH command parser that delegates to specific parsers"""
    
    def __init__(self):
        self.parsers = [
            CiscoIOSParser(),
            JuniperParser(),
            AristaParser(),
            HPParser(),
            LinuxParser()
        ]
    
    def parse_command_output(self, command: str, output: str, device_type: Optional[str] = None) -> Dict[str, Any]:
        """Parse command output using appropriate parser"""
        if not output or not command:
            return {
                'raw_output': output or '',
                'parsed': False,
                'command': command or '',
                'error': 'Empty command or output'
            }
        
        # Sanitize inputs
        command = command.strip()
        output = output.strip()
        
        parsed_result = None
        
        # Try device type specific parser first
        if device_type:
            device_type_lower = device_type.lower()
            for parser in self.parsers:
                parser_name = parser.__class__.__name__.lower()
                # Check if device type matches parser name
                if any(dt in parser_name for dt in [device_type_lower, device_type_lower.replace('_', ''), device_type_lower.replace('-', '')]):
                    try:
                        if parser.can_parse(command, output):
                            parsed_result = parser.parse(command, output)
                            if parsed_result.get('parsed', False):
                                break
                    except Exception as e:
                        logger.warning(f"Parser {parser.__class__.__name__} failed: {e}")
                        continue
        
        # If no device-specific parser worked, try all parsers
        if not parsed_result or not parsed_result.get('parsed', False):
            for parser in self.parsers:
                try:
                    if parser.can_parse(command, output):
                        test_result = parser.parse(command, output)
                        if test_result.get('parsed', False):
                            parsed_result = test_result
                            break
                except Exception as e:
                    logger.warning(f"Parser {parser.__class__.__name__} failed: {e}")
                    continue
        
        # Return parsed result or unparsed fallback
        if parsed_result and parsed_result.get('parsed', False):
            # Add metadata
            parsed_result['original_command'] = command
            parsed_result['parser_used'] = getattr(parsed_result, '_parser_class', 'unknown')
            return parsed_result
        
        return {
            'raw_output': output,
            'parsed': False,
            'command': command,
            'original_command': command,
            'error': 'No suitable parser found or all parsers failed',
            'attempted_parsers': [p.__class__.__name__ for p in self.parsers]
        }
    
    def extract_system_info(self, parsed_outputs: List[Dict[str, Any]]) -> ParsedSystemInfo:
        """Extract system information from multiple parsed outputs with validation"""
        system_info = ParsedSystemInfo(hostname='unknown')
        
        if not parsed_outputs:
            return system_info
        
        # Sort outputs by priority - show version commands first
        priority_outputs = []
        other_outputs = []
        
        for output in parsed_outputs:
            if not output.get('parsed', False):
                continue
                
            command = output.get('command', '').lower()
            if 'version' in command or 'show_version' in command:
                priority_outputs.append(output)
            else:
                other_outputs.append(output)
        
        # Process priority outputs first, then others
        all_outputs = priority_outputs + other_outputs
        
        for output in all_outputs:
            try:
                # Extract hostname (prefer non-empty values)
                hostname = output.get('hostname', '').strip()
                if hostname and hostname != 'unknown' and not system_info.hostname or system_info.hostname == 'unknown':
                    system_info.hostname = hostname
                
                # Extract model
                model = output.get('model', '').strip()
                if model and not system_info.model:
                    system_info.model = model
                
                # Extract serial number
                serial = output.get('serial_number', '').strip()
                if serial and not system_info.serial_number:
                    system_info.serial_number = serial
                
                # Extract software version
                version = output.get('software_version', '').strip()
                if version and not system_info.software_version:
                    system_info.software_version = version
                
                # Extract uptime
                uptime = output.get('uptime', '').strip()
                if uptime and not system_info.uptime:
                    system_info.uptime = uptime
                
                # Extract CPU usage (prefer more recent/specific values)
                cpu_usage = None
                if 'cpu_5sec' in output and output['cpu_5sec'] is not None:
                    try:
                        cpu_usage = float(output['cpu_5sec'])
                    except (ValueError, TypeError):
                        pass
                elif 'cpu' in output and isinstance(output['cpu'], dict):
                    cpu_data = output['cpu']
                    if 'usage' in cpu_data:
                        try:
                            cpu_usage = float(cpu_data['usage'])
                        except (ValueError, TypeError):
                            pass
                
                if cpu_usage is not None and (system_info.cpu_usage is None or cpu_usage > 0):
                    system_info.cpu_usage = max(0.0, min(100.0, cpu_usage))  # Clamp to 0-100%
                
                # Extract memory usage
                if 'memory_pools' in output and isinstance(output['memory_pools'], list):
                    # Handle Cisco-style memory pools
                    for pool in output['memory_pools']:
                        if isinstance(pool, dict) and pool.get('name', '').lower() == 'processor':
                            total = pool.get('total_bytes', 0)
                            used = pool.get('used_bytes', 0)
                            if total > 0:
                                memory_usage = (used / total) * 100
                                if system_info.memory_usage is None or memory_usage > 0:
                                    system_info.memory_usage = max(0.0, min(100.0, memory_usage))
                elif 'memory' in output and isinstance(output['memory'], dict):
                    # Handle Linux-style memory info
                    memory = output['memory']
                    total = memory.get('total', 0)
                    if total > 0:
                        if 'available' in memory:
                            available = memory['available']
                            used = total - available
                        else:
                            used = memory.get('used', 0)
                        
                        if used >= 0:
                            memory_usage = (used / total) * 100
                            if system_info.memory_usage is None or memory_usage > 0:
                                system_info.memory_usage = max(0.0, min(100.0, memory_usage))
                
                # Extract temperature from environment data
                if 'sensors' in output and isinstance(output['sensors'], list):
                    temps = []
                    for sensor in output['sensors']:
                        if isinstance(sensor, dict) and 'temperature_c' in sensor:
                            try:
                                temp = float(sensor['temperature_c'])
                                if 0 <= temp <= 150:  # Reasonable temperature range
                                    temps.append(temp)
                            except (ValueError, TypeError):
                                pass
                    
                    if temps and system_info.temperature is None:
                        # Use average temperature from all sensors
                        system_info.temperature = sum(temps) / len(temps)
                        
            except Exception as e:
                logger.warning(f"Error extracting system info from output: {e}")
                continue
        
        # Validate extracted information
        if system_info.cpu_usage is not None:
            system_info.cpu_usage = max(0.0, min(100.0, system_info.cpu_usage))
        
        if system_info.memory_usage is not None:
            system_info.memory_usage = max(0.0, min(100.0, system_info.memory_usage))
        
        if system_info.temperature is not None:
            system_info.temperature = max(-50.0, min(150.0, system_info.temperature))
        
        return system_info


# Global parser instance
ssh_parser = SSHCommandParser()