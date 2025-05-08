#!/usr/bin/env python3
"""
NetworkAnalyzer Module
Detects suspicious network connections, unusual open ports, and unexpected outbound traffic.
"""

import os
import logging
import subprocess
import json
import re
import socket
import time
import ssl
import ipaddress
import hashlib
import tempfile
from datetime import datetime, timedelta
from collections import defaultdict, Counter

class NetworkAnalyzer:
    """Analyzes network connections for suspicious activity"""
    
    def __init__(self, config=None):
        """Initialize with configuration"""
        self.logger = logging.getLogger('sharpeye.network')
        self.config = config or {}
        
        # Configure options
        self.baseline_file = self.config.get('baseline_file', '/var/lib/sharpeye/baselines/network.json')
        self.check_listening_ports = self.config.get('check_listening_ports', True)
        self.check_outbound = self.config.get('check_outbound', True)
        self.check_remote_access = self.config.get('check_remote_access', True)
        self.check_arp_spoofing = self.config.get('check_arp_spoofing', True)
        self.check_promiscuous_mode = self.config.get('check_promiscuous_mode', True)
        self.check_ssl_certificates = self.config.get('check_ssl_certificates', True)
        self.check_traffic_patterns = self.config.get('check_traffic_patterns', True)
        self.check_network_services = self.config.get('check_network_services', True)
        
        # Get expected and suspicious ports
        self.expected_ports = set(self.config.get('expected_ports', [
            22,    # SSH
            80,    # HTTP
            443,   # HTTPS
            25,    # SMTP
            465,   # SMTPS
            587,   # SMTP Submission
            110,   # POP3
            995,   # POP3S
            143,   # IMAP
            993,   # IMAPS
            53,    # DNS
            123    # NTP
        ]))
        
        self.suspicious_ports = set(self.config.get('suspicious_ports', [
            31337,  # Back Orifice
            12345,  # NetBus
            6667,   # IRC (often used by botnets)
            4444,   # Metasploit default
            5555,   # Common backdoor
            9000,   # Common backdoor
            1080,   # SOCKS proxy
            8080,   # Alternative HTTP (often proxies)
            3128    # Squid proxy
        ]))
        
        # Define high-risk countries if geo lookup is enabled
        self.enable_geolocation = self.config.get('enable_geolocation', False)
        self.high_risk_countries = self.config.get('high_risk_countries', [
            "KP",  # North Korea
            "RU",  # Russia
            "CN",  # China
            "IR"   # Iran
        ])
        
        # Configure SSL certificate settings
        self.trusted_certificate_authorities = self.config.get('trusted_certificate_authorities', [
            '/etc/ssl/certs/ca-certificates.crt',  # Debian/Ubuntu
            '/etc/pki/tls/certs/ca-bundle.crt',    # RHEL/CentOS
            '/etc/ssl/ca-bundle.pem',              # OpenSUSE
            '/etc/pki/tls/cacert.pem',             # Alternative location
            '/usr/local/share/certs/ca-root-nss.crt'  # FreeBSD
        ])
        
        # Traffic pattern analysis settings
        self.traffic_monitor_duration = self.config.get('traffic_monitor_duration', 30)  # seconds
        self.packet_sample_size = self.config.get('packet_sample_size', 1000)  # number of packets to sample
        self.traffic_pattern_threshold = self.config.get('traffic_pattern_threshold', 0.7)  # similarity threshold
        
        # Network service configuration
        self.service_scan_timeout = self.config.get('service_scan_timeout', 2)  # seconds per port
        self.service_scan_max_ports = self.config.get('service_scan_max_ports', 100)  # max ports to scan
        self.include_local_network = self.config.get('include_local_network', True)  # scan local network
        
        # ARP settings
        self.arp_cache_ttl = self.config.get('arp_cache_ttl', 3600)  # seconds
        self.arp_scan_interval = self.config.get('arp_scan_interval', 300)  # seconds between scans
        
        # Initialize threat intelligence module if enabled
        ti_config = self.config.get('threat_intelligence', {})
        if ti_config.get('enabled', False):
            try:
                from utils.threat_intelligence import ThreatIntelligence
                self.threat_intel = ThreatIntelligence(ti_config)
                self.logger.info(f"Initialized threat intelligence module")
            except ImportError:
                self.logger.warning("Threat intelligence module not found, disabling")
                self.threat_intel = None
        else:
            self.threat_intel = None
            
        # Initialize temporary data storage for traffic pattern analysis
        self.traffic_pattern_data = {}
        self.last_arp_scan_time = 0
        self.arp_cache = {}
    
    def analyze(self):
        """Analyze network connections for anomalies"""
        self.logger.info("Analyzing network connections")
        
        results = {
            'listening_ports': self._check_listening_ports() if self.check_listening_ports else {'skipped': True},
            'established_connections': self._check_established_connections() if self.check_outbound else {'skipped': True},
            'remote_access_services': self._check_remote_access() if self.check_remote_access else {'skipped': True},
            'suspicious_connections': self._check_suspicious_connections(),
            'dns_queries': self._check_recent_dns(),
            'arp_spoofing': self._check_arp_spoofing(),
            'promiscuous_mode': self._check_promiscuous_mode(),
            'ssl_certificates': self._check_ssl_certificates(),
            'traffic_patterns': self._check_traffic_patterns(),
            'network_services': self._check_network_services(),
            'threat_intelligence': self._check_threat_intelligence() if self.threat_intel else {'skipped': True}
        }
        
        # Determine if any anomalies were found
        is_anomalous = (
            results['listening_ports'].get('is_anomalous', False) or
            results['established_connections'].get('is_anomalous', False) or
            results['remote_access_services'].get('is_anomalous', False) or
            results['suspicious_connections'].get('is_anomalous', False) or
            results['dns_queries'].get('is_anomalous', False) or
            results['arp_spoofing'].get('is_anomalous', False) or
            results['promiscuous_mode'].get('is_anomalous', False) or
            results['ssl_certificates'].get('is_anomalous', False) or
            results['traffic_patterns'].get('is_anomalous', False) or
            results['network_services'].get('is_anomalous', False) or
            results['threat_intelligence'].get('is_anomalous', False)
        )
        
        results['is_anomalous'] = is_anomalous
        results['timestamp'] = datetime.now().isoformat()
        
        return results
    
    def _check_listening_ports(self):
        """Check for unusual listening ports"""
        self.logger.debug("Checking for unusual listening ports")
        
        listening_ports = []
        unexpected_ports = []
        suspicious_ports = []
        
        try:
            # Get listening ports using netstat
            cmd = ["netstat", "-tlnp"]
            output = subprocess.check_output(cmd, universal_newlines=True)
            
            # Parse the output
            # Skip header lines
            lines = output.strip().split('\n')[2:]
            
            for line in lines:
                if not line.strip():
                    continue
                
                parts = line.split()
                if len(parts) >= 6:
                    proto = parts[0]
                    local_addr = parts[3]
                    pid_info = parts[6] if len(parts) > 6 else ""
                    
                    # Extract port and address
                    local_addr_parts = local_addr.rsplit(':', 1)
                    if len(local_addr_parts) == 2:
                        addr = local_addr_parts[0]
                        port = int(local_addr_parts[1])
                    else:
                        addr = '0.0.0.0'
                        port = int(local_addr)
                    
                    # Extract PID and program name
                    pid = ""
                    program = ""
                    
                    pid_match = re.search(r'(\d+)/(.*)', pid_info)
                    if pid_match:
                        pid = pid_match.group(1)
                        program = pid_match.group(2)
                    
                    port_info = {
                        'proto': proto,
                        'addr': addr,
                        'port': port,
                        'pid': pid,
                        'program': program
                    }
                    
                    # Check if it's an expected port
                    if port not in self.expected_ports:
                        port_info['unexpected'] = True
                        unexpected_ports.append(port_info)
                        
                        # Check if it's a known suspicious port
                        if port in self.suspicious_ports:
                            port_info['suspicious'] = True
                            suspicious_ports.append(port_info)
                    
                    listening_ports.append(port_info)
            
            # Check for unusual binding addresses (non-localhost for sensitive services)
            sensitive_services = [3306, 5432, 6379, 27017]  # MySQL, PostgreSQL, Redis, MongoDB
            for port_info in listening_ports:
                port = port_info.get('port')
                addr = port_info.get('addr')
                
                if port in sensitive_services and addr not in ['127.0.0.1', '::1', 'localhost']:
                    port_info['unusual_binding'] = True
                    if port_info not in unexpected_ports:
                        unexpected_ports.append(port_info)
            
            # Determine if there are any anomalies
            is_anomalous = len(suspicious_ports) > 0
            
            return {
                'count': len(listening_ports),
                'unexpected_count': len(unexpected_ports),
                'suspicious_count': len(suspicious_ports),
                'listening_ports': listening_ports,
                'unexpected_ports': unexpected_ports,
                'suspicious_ports': suspicious_ports,
                'is_anomalous': is_anomalous
            }
            
        except Exception as e:
            self.logger.error(f"Error checking listening ports: {e}")
            return {
                'error': str(e),
                'is_anomalous': False
            }
    
    def _check_established_connections(self):
        """Check for suspicious established connections"""
        self.logger.debug("Checking established connections")
        
        established_connections = []
        suspicious_connections = []
        
        try:
            # Get established connections using netstat
            cmd = ["netstat", "-tnp"]
            output = subprocess.check_output(cmd, universal_newlines=True)
            
            # Parse the output
            # Skip header lines
            lines = output.strip().split('\n')[2:]
            
            for line in lines:
                if not line.strip():
                    continue
                
                parts = line.split()
                if len(parts) >= 7 and "ESTABLISHED" in line:
                    proto = parts[0]
                    local_addr = parts[3]
                    remote_addr = parts[4]
                    pid_info = parts[6]
                    
                    # Extract local port and address
                    local_addr_parts = local_addr.rsplit(':', 1)
                    if len(local_addr_parts) == 2:
                        local_ip = local_addr_parts[0]
                        local_port = int(local_addr_parts[1])
                    else:
                        local_ip = '0.0.0.0'
                        local_port = int(local_addr)
                    
                    # Extract remote port and address
                    remote_addr_parts = remote_addr.rsplit(':', 1)
                    if len(remote_addr_parts) == 2:
                        remote_ip = remote_addr_parts[0]
                        remote_port = int(remote_addr_parts[1])
                    else:
                        remote_ip = '0.0.0.0'
                        remote_port = int(remote_addr)
                    
                    # Extract PID and program name
                    pid = ""
                    program = ""
                    
                    pid_match = re.search(r'(\d+)/(.*)', pid_info)
                    if pid_match:
                        pid = pid_match.group(1)
                        program = pid_match.group(2)
                    
                    # Check if this is possibly suspicious
                    is_suspicious = False
                    reasons = []
                    
                    # Check for connections to suspicious ports
                    if remote_port in self.suspicious_ports:
                        is_suspicious = True
                        reasons.append(f"Connection to suspicious port {remote_port}")
                    
                    # Check for unusual programs making outbound connections
                    unusual_programs = ['bash', 'sh', 'ksh', 'zsh', 'perl', 'python', 'ruby', 'nc', 'ncat', 'netcat']
                    if any(prog in program.lower() for prog in unusual_programs):
                        is_suspicious = True
                        reasons.append(f"Unusual program making outbound connection: {program}")
                    
                    # Check for non-standard remote ports (not common services)
                    common_remote_ports = [80, 443, 22, 21, 25, 465, 587, 110, 995, 143, 993, 53]
                    if remote_port not in common_remote_ports and remote_port not in self.expected_ports:
                        # Not necessarily suspicious, but unusual
                        if remote_port < 1024:  # Low ports are more suspicious
                            is_suspicious = True
                            reasons.append(f"Connection to unusual low port {remote_port}")
                    
                    # Check for GeoIP information if enabled
                    country_code = None
                    if self.enable_geolocation:
                        try:
                            import geoip2.database
                            
                            # Assuming GeoLite2 database is installed
                            with geoip2.database.Reader('/usr/share/GeoIP/GeoLite2-Country.mmdb') as reader:
                                response = reader.country(remote_ip)
                                country_code = response.country.iso_code
                                
                                if country_code in self.high_risk_countries:
                                    is_suspicious = True
                                    reasons.append(f"Connection to high-risk country: {country_code}")
                        except (ImportError, FileNotFoundError, geoip2.errors.AddressNotFoundError):
                            # GeoIP functionality not available or IP not found
                            pass
                    
                    # Check against threat intelligence if available
                    if self.threat_intel:
                        threat_info = self.threat_intel.check_ip(remote_ip)
                        if threat_info:
                            is_suspicious = True
                            source = threat_info.get('source', 'unknown')
                            feed = threat_info.get('feed', '')
                            description = threat_info.get('description', 'Malicious IP')
                            
                            if feed:
                                reasons.append(f"IP found in threat feed {source}/{feed}: {description}")
                            else:
                                reasons.append(f"IP found in threat feed {source}: {description}")
                    
                    connection_info = {
                        'proto': proto,
                        'local_ip': local_ip,
                        'local_port': local_port,
                        'remote_ip': remote_ip,
                        'remote_port': remote_port,
                        'pid': pid,
                        'program': program,
                        'country_code': country_code
                    }
                    
                    established_connections.append(connection_info)
                    
                    if is_suspicious:
                        connection_info['is_suspicious'] = True
                        connection_info['reasons'] = reasons
                        suspicious_connections.append(connection_info)
            
            # Determine if there are any anomalies
            is_anomalous = len(suspicious_connections) > 0
            
            return {
                'count': len(established_connections),
                'suspicious_count': len(suspicious_connections),
                'established_connections': established_connections,
                'suspicious_connections': suspicious_connections,
                'is_anomalous': is_anomalous
            }
            
        except Exception as e:
            self.logger.error(f"Error checking established connections: {e}")
            return {
                'error': str(e),
                'is_anomalous': False
            }
    
    def _check_remote_access(self):
        """Check for remote access services running"""
        self.logger.debug("Checking remote access services")
        
        remote_access_services = []
        
        try:
            # List of ports commonly used for remote access
            remote_access_ports = [
                22,    # SSH
                23,    # Telnet
                3389,  # RDP
                5900,  # VNC
                5901,  # VNC
                5902,  # VNC
                5800,  # VNC Web
                3350,  # Teamviewer
                4899   # Radmin
            ]
            
            # Get listening ports
            listening_ports_data = self._check_listening_ports()
            listening_ports = listening_ports_data.get('listening_ports', [])
            
            # Check for remote access ports
            for port_info in listening_ports:
                port = port_info.get('port', 0)
                addr = port_info.get('addr', '')
                
                if port in remote_access_ports:
                    # Check if it's bound to all interfaces
                    if addr in ['0.0.0.0', '::', '']:
                        port_info['publicly_accessible'] = True
                        remote_access_services.append(port_info)
                    elif addr not in ['127.0.0.1', '::1', 'localhost']:
                        # Bound to a specific interface, but not localhost
                        port_info['accessible_from_network'] = True
                        remote_access_services.append(port_info)
            
            # Check SSH configuration if available
            ssh_config_issues = []
            if os.path.exists('/etc/ssh/sshd_config'):
                try:
                    with open('/etc/ssh/sshd_config', 'r') as f:
                        ssh_config = f.read()
                        
                        # Check for password authentication
                        if re.search(r'PasswordAuthentication\s+yes', ssh_config, re.IGNORECASE):
                            ssh_config_issues.append("Password authentication is enabled")
                        
                        # Check for root login
                        if re.search(r'PermitRootLogin\s+yes', ssh_config, re.IGNORECASE):
                            ssh_config_issues.append("Root login is permitted")
                        
                        # Check for empty passwords
                        if re.search(r'PermitEmptyPasswords\s+yes', ssh_config, re.IGNORECASE):
                            ssh_config_issues.append("Empty passwords are permitted")
                except (PermissionError, FileNotFoundError):
                    # May not have permission to read the file
                    pass
            
            # Determine if there are any anomalies
            is_anomalous = len(remote_access_services) > 0 and any(
                service.get('publicly_accessible', False) for service in remote_access_services
            )
            
            return {
                'count': len(remote_access_services),
                'remote_access_services': remote_access_services,
                'ssh_config_issues': ssh_config_issues,
                'is_anomalous': is_anomalous or len(ssh_config_issues) > 0
            }
            
        except Exception as e:
            self.logger.error(f"Error checking remote access services: {e}")
            return {
                'error': str(e),
                'is_anomalous': False
            }
    
    def _check_suspicious_connections(self):
        """Check for suspicious network connections based on various criteria"""
        self.logger.debug("Checking suspicious connections")
        
        suspicious_connections = []
        
        try:
            # Get all connections
            cmd = ["netstat", "-antup"]
            output = subprocess.check_output(cmd, universal_newlines=True)
            
            # Parse the output
            # Skip header lines
            lines = output.strip().split('\n')[2:]
            
            for line in lines:
                if not line.strip():
                    continue
                
                parts = line.split()
                if len(parts) >= 6:
                    proto = parts[0]
                    local_addr = parts[3]
                    remote_addr = parts[4]
                    state = parts[5] if len(parts) > 5 else ""
                    pid_info = parts[6] if len(parts) > 6 else ""
                    
                    # Extract local port and address
                    local_addr_parts = local_addr.rsplit(':', 1)
                    if len(local_addr_parts) == 2:
                        local_ip = local_addr_parts[0]
                        local_port = int(local_addr_parts[1])
                    else:
                        local_ip = '0.0.0.0'
                        local_port = int(local_addr)
                    
                    # Extract remote port and address
                    remote_addr_parts = remote_addr.rsplit(':', 1)
                    if len(remote_addr_parts) == 2:
                        remote_ip = remote_addr_parts[0]
                        remote_port = int(remote_addr_parts[1])
                    else:
                        remote_ip = '0.0.0.0'
                        remote_port = int(remote_addr)
                    
                    # Extract PID and program name
                    pid = ""
                    program = ""
                    
                    pid_match = re.search(r'(\d+)/(.*)', pid_info)
                    if pid_match:
                        pid = pid_match.group(1)
                        program = pid_match.group(2)
                    
                    # Check if this is a suspicious connection
                    is_suspicious = False
                    reasons = []
                    
                    # Check for connections to non-standard high ports
                    if state == "ESTABLISHED" and remote_port > 10000:
                        # Look for patterns associated with C&C servers
                        for port in range(remote_port, remote_port + 5):
                            cmd = ["netstat", "-ant", "|", "grep", f":{port}"]
                            try:
                                port_check = subprocess.check_output(cmd, universal_newlines=True, shell=True)
                                if port_check.strip():
                                    # Multiple connections to sequential high ports is suspicious
                                    is_suspicious = True
                                    reasons.append(f"Multiple connections to sequential high ports starting at {remote_port}")
                                    break
                            except subprocess.CalledProcessError:
                                pass
                    
                    # Check for outbound connections from server processes
                    server_processes = ['httpd', 'apache', 'apache2', 'nginx', 'tomcat', 'jetty']
                    if any(server in program.lower() for server in server_processes) and state == "ESTABLISHED":
                        if remote_ip not in ['127.0.0.1', '::1', 'localhost']:
                            is_suspicious = True
                            reasons.append(f"Server process {program} making outbound connection")
                    
                    # Check for multiple connections to the same remote address with different ports
                    # (potential port scan or service discovery)
                    if remote_ip != "0.0.0.0" and remote_ip != "::":
                        cmd = ["netstat", "-ant", "|", "grep", remote_ip, "|", "wc", "-l"]
                        try:
                            count_output = subprocess.check_output(cmd, universal_newlines=True, shell=True)
                            connection_count = int(count_output.strip())
                            if connection_count > 5:  # Arbitrary threshold
                                is_suspicious = True
                                reasons.append(f"Multiple connections ({connection_count}) to the same remote address {remote_ip}")
                        except (subprocess.CalledProcessError, ValueError):
                            pass
                    
                    # Check for connections to known bad ports
                    bad_ports = [6667, 6668, 6669, 4444, 31337]  # IRC, Metasploit, Back Orifice
                    if remote_port in bad_ports:
                        is_suspicious = True
                        reasons.append(f"Connection to known bad port {remote_port}")
                    
                    # Check for non-browser processes connecting to web ports
                    web_ports = [80, 443, 8080, 8443]
                    browser_processes = ['firefox', 'chrome', 'chromium', 'safari', 'opera', 'edge', 'iexplore']
                    if remote_port in web_ports and state == "ESTABLISHED":
                        if program and not any(browser in program.lower() for browser in browser_processes):
                            # Non-browser connecting to web port - not necessarily suspicious for all programs
                            if any(unusual in program.lower() for unusual in ['bash', 'sh', 'python', 'perl', 'ruby', 'nc', 'ncat']):
                                is_suspicious = True
                                reasons.append(f"Non-browser unusual process {program} connecting to web port {remote_port}")
                    
                    # Check against threat intelligence if available
                    if self.threat_intel and remote_ip != "0.0.0.0" and remote_ip != "::":
                        threat_info = self.threat_intel.check_ip(remote_ip)
                        if threat_info:
                            is_suspicious = True
                            source = threat_info.get('source', 'unknown')
                            feed = threat_info.get('feed', '')
                            description = threat_info.get('description', 'Malicious IP')
                            
                            if feed:
                                reasons.append(f"IP found in threat feed {source}/{feed}: {description}")
                            else:
                                reasons.append(f"IP found in threat feed {source}: {description}")
                    
                    if is_suspicious:
                        suspicious_connections.append({
                            'proto': proto,
                            'local_ip': local_ip,
                            'local_port': local_port,
                            'remote_ip': remote_ip,
                            'remote_port': remote_port,
                            'state': state,
                            'pid': pid,
                            'program': program,
                            'reasons': reasons
                        })
            
            # Determine if there are any anomalies
            is_anomalous = len(suspicious_connections) > 0
            
            return {
                'count': len(suspicious_connections),
                'suspicious_connections': suspicious_connections,
                'is_anomalous': is_anomalous
            }
            
        except Exception as e:
            self.logger.error(f"Error checking suspicious connections: {e}")
            return {
                'error': str(e),
                'is_anomalous': False
            }
    
    def _check_recent_dns(self):
        """Check for suspicious DNS queries"""
        self.logger.debug("Checking recent DNS queries")
        
        suspicious_dns = []
        recent_queries = []
        
        try:
            # Check if tcpdump is available
            try:
                subprocess.check_output(["which", "tcpdump"], universal_newlines=True)
                tcpdump_available = True
            except subprocess.CalledProcessError:
                tcpdump_available = False
            
            if tcpdump_available:
                # Capture DNS queries for a short period
                try:
                    cmd = ["timeout", "5", "tcpdump", "-i", "any", "-nn", "udp", "port", "53", "-c", "50"]
                    output = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.PIPE)
                    
                    # Parse tcpdump output for DNS queries
                    dns_query_pattern = r'A\? ([^.]+\.[^.]+\.[^.]+)[\. ]'
                    matches = re.findall(dns_query_pattern, output)
                    
                    domains = set(matches)
                    for domain in domains:
                        recent_queries.append(domain)
                        
                        # Check for suspicious domain patterns
                        if self._is_suspicious_domain(domain):
                            suspicious_dns.append({
                                'domain': domain,
                                'reason': "Suspicious domain pattern"
                            })
                        
                        # Check against threat intelligence if available
                        if self.threat_intel:
                            threat_info = self.threat_intel.check_domain(domain)
                            if threat_info:
                                source = threat_info.get('source', 'unknown')
                                feed = threat_info.get('feed', '')
                                description = threat_info.get('description', 'Malicious domain')
                                
                                if feed:
                                    reason = f"Domain found in threat feed {source}/{feed}: {description}"
                                else:
                                    reason = f"Domain found in threat feed {source}: {description}"
                                
                                suspicious_dns.append({
                                    'domain': domain,
                                    'reason': reason
                                })
                except subprocess.CalledProcessError:
                    # tcpdump might require root privileges
                    pass
            
            # If we can access /var/log/syslog or messages, look for DNS queries
            log_files = ['/var/log/syslog', '/var/log/messages']
            for log_file in log_files:
                if os.path.exists(log_file):
                    try:
                        cmd = ["grep", "named", log_file, "|", "grep", "query", "|", "tail", "-50"]
                        output = subprocess.check_output(cmd, universal_newlines=True, shell=True)
                        
                        # Extract domain names from log entries
                        for line in output.strip().split('\n'):
                            if 'query' in line:
                                domain_match = re.search(r'query: ([^ ]+) ', line)
                                if domain_match:
                                    domain = domain_match.group(1)
                                    if domain not in recent_queries:
                                        recent_queries.append(domain)
                                        
                                        # Check for suspicious domain patterns
                                        if self._is_suspicious_domain(domain):
                                            suspicious_dns.append({
                                                'domain': domain,
                                                'reason': "Suspicious domain pattern",
                                                'source': "log"
                                            })
                                        
                                        # Check against threat intelligence if available
                                        if self.threat_intel:
                                            threat_info = self.threat_intel.check_domain(domain)
                                            if threat_info:
                                                source = threat_info.get('source', 'unknown')
                                                feed = threat_info.get('feed', '')
                                                description = threat_info.get('description', 'Malicious domain')
                                                
                                                if feed:
                                                    reason = f"Domain found in threat feed {source}/{feed}: {description}"
                                                else:
                                                    reason = f"Domain found in threat feed {source}: {description}"
                                                
                                                suspicious_dns.append({
                                                    'domain': domain,
                                                    'reason': reason,
                                                    'source': "log"
                                                })
                    except subprocess.CalledProcessError:
                        # No DNS queries found or permission denied
                        pass
            
            # Determine if there are any anomalies
            is_anomalous = len(suspicious_dns) > 0
            
            return {
                'count': len(recent_queries),
                'suspicious_count': len(suspicious_dns),
                'recent_queries': recent_queries[:20],  # Limit to 20
                'suspicious_dns': suspicious_dns,
                'is_anomalous': is_anomalous
            }
            
        except Exception as e:
            self.logger.error(f"Error checking recent DNS queries: {e}")
            return {
                'error': str(e),
                'is_anomalous': False
            }
    
    def _check_threat_intelligence(self):
        """Check established connections against threat intelligence"""
        self.logger.debug("Checking connections against threat intelligence")
        
        if not self.threat_intel:
            return {
                'error': "Threat intelligence not available",
                'is_anomalous': False
            }
        
        flagged_ips = []
        flagged_domains = []
        
        try:
            # Get statistics from threat intelligence module
            ti_stats = self.threat_intel.get_stats()
            
            # Get established connections
            connections_data = self._check_established_connections()
            connections = connections_data.get('established_connections', [])
            
            # Check each connection's remote IP
            for conn in connections:
                remote_ip = conn.get('remote_ip')
                
                if remote_ip and remote_ip != "0.0.0.0" and remote_ip != "::":
                    threat_info = self.threat_intel.check_ip(remote_ip)
                    
                    if threat_info:
                        flagged_ips.append({
                            'ip': remote_ip,
                            'program': conn.get('program', ''),
                            'port': conn.get('remote_port', 0),
                            'threat_info': threat_info
                        })
            
            # Try to resolve remote IPs to domains and check them
            for conn in connections:
                remote_ip = conn.get('remote_ip')
                
                if remote_ip and remote_ip != "0.0.0.0" and remote_ip != "::":
                    try:
                        domain = socket.gethostbyaddr(remote_ip)[0]
                        
                        # Check the domain against threat intelligence
                        threat_info = self.threat_intel.check_domain(domain)
                        
                        if threat_info:
                            flagged_domains.append({
                                'domain': domain,
                                'ip': remote_ip,
                                'program': conn.get('program', ''),
                                'port': conn.get('remote_port', 0),
                                'threat_info': threat_info
                            })
                    except (socket.herror, socket.gaierror):
                        # Could not resolve IP to domain
                        pass
            
            # Check recent DNS queries as well
            dns_data = self._check_recent_dns()
            queries = dns_data.get('recent_queries', [])
            
            for domain in queries:
                threat_info = self.threat_intel.check_domain(domain)
                
                if threat_info:
                    flagged_domains.append({
                        'domain': domain,
                        'ip': None,
                        'program': None,
                        'port': None,
                        'threat_info': threat_info
                    })
            
            # Determine if there are any anomalies
            is_anomalous = len(flagged_ips) > 0 or len(flagged_domains) > 0
            
            return {
                'ti_enabled': True,
                'ti_stats': ti_stats,
                'flagged_ips_count': len(flagged_ips),
                'flagged_domains_count': len(flagged_domains),
                'flagged_ips': flagged_ips,
                'flagged_domains': flagged_domains,
                'is_anomalous': is_anomalous
            }
            
        except Exception as e:
            self.logger.error(f"Error checking threat intelligence: {e}")
            return {
                'error': str(e),
                'is_anomalous': False
            }
    
    def _check_arp_spoofing(self):
        """Check for potential ARP spoofing attacks on the network"""
        self.logger.debug("Checking for ARP spoofing")
        
        suspicious_entries = []
        duplicate_mac_addresses = []
        duplicate_ip_addresses = []
        
        try:
            # Check if enough time has passed since the last scan
            current_time = time.time()
            if (current_time - self.last_arp_scan_time) < self.arp_scan_interval:
                # Use cached data if available and not expired
                if self.arp_cache and (current_time - self.last_arp_scan_time) < self.arp_cache_ttl:
                    self.logger.debug("Using cached ARP data")
                    return self.arp_cache
            
            # Get the ARP table
            cmd = ["arp", "-an"]
            output = subprocess.check_output(cmd, universal_newlines=True)
            
            # Parse the output
            ip_to_mac = {}
            mac_to_ip = defaultdict(list)
            interface_to_entries = defaultdict(list)
            
            for line in output.strip().split('\n'):
                if not line.strip():
                    continue
                
                # Parse the line to extract IP, MAC, and interface
                # Sample format: ? (192.168.1.1) at 00:11:22:33:44:55 [ether] on eth0
                ip_match = re.search(r'\(([0-9\.]+)\)', line)
                mac_match = re.search(r'at ([0-9a-fA-F:]+)', line)
                interface_match = re.search(r'on (\w+)$', line)
                
                if ip_match and mac_match:
                    ip = ip_match.group(1)
                    mac = mac_match.group(1).lower()
                    interface = interface_match.group(1) if interface_match else "unknown"
                    
                    # Collect data
                    ip_to_mac[ip] = mac
                    mac_to_ip[mac].append(ip)
                    interface_to_entries[interface].append((ip, mac))
            
            # Analyze for duplicate MAC addresses (potentially spoofed)
            for mac, ips in mac_to_ip.items():
                if len(ips) > 1:
                    duplicate_mac_addresses.append({
                        'mac': mac,
                        'ips': ips,
                        'count': len(ips)
                    })
            
            # Check for duplicate IP addresses (address conflict, ARP poisoning)
            for interface, entries in interface_to_entries.items():
                ip_count = Counter(entry[0] for entry in entries)
                for ip, count in ip_count.items():
                    if count > 1:
                        duplicate_ip_addresses.append({
                            'ip': ip,
                            'interface': interface,
                            'count': count
                        })
            
            # Run additional checks for potentially malicious patterns
            
            # Check for known default gateway MAC changing
            # First, identify the default gateway
            try:
                route_cmd = ["ip", "route", "show", "default"]
                route_output = subprocess.check_output(route_cmd, universal_newlines=True)
                
                # Extract default gateway
                dg_match = re.search(r'default via ([0-9\.]+)', route_output)
                if dg_match:
                    default_gateway = dg_match.group(1)
                    
                    # Check if we have a baseline for the default gateway MAC
                    if os.path.exists(self.baseline_file):
                        with open(self.baseline_file, 'r') as f:
                            baseline = json.load(f)
                            
                        baseline_arp = baseline.get('arp_table', {})
                        if default_gateway in baseline_arp and default_gateway in ip_to_mac:
                            if baseline_arp[default_gateway] != ip_to_mac[default_gateway]:
                                suspicious_entries.append({
                                    'ip': default_gateway,
                                    'current_mac': ip_to_mac[default_gateway],
                                    'baseline_mac': baseline_arp[default_gateway],
                                    'reason': "Default gateway MAC address changed"
                                })
            except (subprocess.CalledProcessError, FileNotFoundError):
                # Could not determine default gateway
                pass
            
            # Check for private IP addresses with suspicious MAC address patterns
            for ip, mac in ip_to_mac.items():
                # Check for MACs with all zeros or sequential values
                if re.match(r'00:00:00:00:00:00', mac) or \
                   re.match(r'ff:ff:ff:ff:ff:ff', mac) or \
                   re.match(r'([0-9a-f]{2})\1\1\1\1\1', mac):
                    suspicious_entries.append({
                        'ip': ip,
                        'mac': mac,
                        'reason': "Suspicious MAC address pattern"
                    })
            
            # Update cache
            self.arp_cache = {
                'ip_to_mac': ip_to_mac,
                'duplicate_mac_addresses': duplicate_mac_addresses,
                'duplicate_ip_addresses': duplicate_ip_addresses,
                'suspicious_entries': suspicious_entries,
                'is_anomalous': len(duplicate_mac_addresses) > 0 or len(duplicate_ip_addresses) > 0 or len(suspicious_entries) > 0
            }
            
            self.last_arp_scan_time = current_time
            
            # Prepare results
            return {
                'duplicate_mac_count': len(duplicate_mac_addresses),
                'duplicate_ip_count': len(duplicate_ip_addresses),
                'suspicious_count': len(suspicious_entries),
                'duplicate_mac_addresses': duplicate_mac_addresses,
                'duplicate_ip_addresses': duplicate_ip_addresses,
                'suspicious_entries': suspicious_entries,
                'is_anomalous': len(duplicate_mac_addresses) > 0 or len(duplicate_ip_addresses) > 0 or len(suspicious_entries) > 0
            }
            
        except Exception as e:
            self.logger.error(f"Error checking for ARP spoofing: {e}")
            return {
                'error': str(e),
                'is_anomalous': False
            }
    
    def _check_promiscuous_mode(self):
        """Check for network interfaces in promiscuous mode"""
        self.logger.debug("Checking for promiscuous mode interfaces")
        
        promiscuous_interfaces = []
        
        try:
            # Method 1: Check using ip link
            try:
                cmd = ["ip", "link"]
                output = subprocess.check_output(cmd, universal_newlines=True)
                
                # Parse the output
                current_interface = None
                for line in output.strip().split('\n'):
                    if not line.startswith(' '):  # New interface
                        interface_match = re.search(r'^[0-9]+: (\w+):', line)
                        if interface_match:
                            current_interface = interface_match.group(1)
                    
                    # Check if PROMISC flag is set
                    if current_interface and 'PROMISC' in line:
                        promiscuous_interfaces.append({
                            'interface': current_interface,
                            'detection_method': 'ip_link',
                            'raw_output': line.strip()
                        })
            except (subprocess.CalledProcessError, FileNotFoundError):
                pass
                
            # Method 2: Check using ifconfig
            if not promiscuous_interfaces:
                try:
                    cmd = ["ifconfig", "-a"]
                    output = subprocess.check_output(cmd, universal_newlines=True)
                    
                    # Parse the output
                    current_interface = None
                    for line in output.strip().split('\n'):
                        if not line.startswith(' ') and not line.startswith('\t'):  # New interface
                            interface_match = re.search(r'^(\w+):', line)
                            if interface_match:
                                current_interface = interface_match.group(1)
                        
                        # Check if PROMISC flag is set
                        if current_interface and 'PROMISC' in line:
                            promiscuous_interfaces.append({
                                'interface': current_interface,
                                'detection_method': 'ifconfig',
                                'raw_output': line.strip()
                            })
                except (subprocess.CalledProcessError, FileNotFoundError):
                    pass
            
            # Method 3: Check /sys/class/net/*/flags
            if os.path.exists('/sys/class/net'):
                for interface in os.listdir('/sys/class/net'):
                    flags_file = f'/sys/class/net/{interface}/flags'
                    if os.path.exists(flags_file):
                        try:
                            with open(flags_file, 'r') as f:
                                flags = int(f.read().strip(), 16)
                                # Check if PROMISC flag (0x100) is set
                                if flags & 0x100:
                                    promiscuous_interfaces.append({
                                        'interface': interface,
                                        'detection_method': 'sysfs',
                                        'flags': hex(flags)
                                    })
                        except (PermissionError, ValueError):
                            pass
            
            # Method 4: Check for processes that might have put interfaces in promiscuous mode
            suspicious_processes = []
            packet_capture_tools = ['tcpdump', 'wireshark', 'tshark', 'dumpcap', 'ethereal', 'ettercap', 'dsniff']
            
            try:
                cmd = ["ps", "-aux"]
                output = subprocess.check_output(cmd, universal_newlines=True)
                
                for line in output.strip().split('\n'):
                    if any(tool in line for tool in packet_capture_tools):
                        parts = line.split()
                        if len(parts) >= 11:
                            user = parts[0]
                            pid = parts[1]
                            cpu = parts[2]
                            mem = parts[3]
                            command = ' '.join(parts[10:])
                            
                            suspicious_processes.append({
                                'user': user,
                                'pid': pid,
                                'cpu': cpu,
                                'mem': mem,
                                'command': command
                            })
            except (subprocess.CalledProcessError, FileNotFoundError):
                pass
            
            # Determine if there are any anomalies
            is_anomalous = len(promiscuous_interfaces) > 0
            
            return {
                'promiscuous_interfaces': promiscuous_interfaces,
                'suspicious_processes': suspicious_processes,
                'count': len(promiscuous_interfaces),
                'is_anomalous': is_anomalous or len(suspicious_processes) > 0
            }
            
        except Exception as e:
            self.logger.error(f"Error checking for promiscuous mode interfaces: {e}")
            return {
                'error': str(e),
                'is_anomalous': False
            }
    
    def _check_ssl_certificates(self):
        """Check for invalid or suspicious SSL certificates on the system and active connections"""
        self.logger.debug("Checking SSL certificates")
        
        invalid_certificates = []
        self_signed_certificates = []
        expired_certificates = []
        suspicious_certificates = []
        
        try:
            # Method 1: Check active SSL/TLS connections
            active_ssl_connections = []
            
            # Get established connections to common SSL/TLS ports
            ssl_ports = [443, 465, 636, 989, 990, 993, 995, 5061, 5223, 8443]
            
            # Get established connections data
            established_data = self._check_established_connections()
            established = established_data.get('established_connections', [])
            
            # Filter to only SSL/TLS connections
            ssl_connections = [conn for conn in established if conn.get('remote_port') in ssl_ports or conn.get('local_port') in ssl_ports]
            
            for conn in ssl_connections:
                remote_ip = conn.get('remote_ip')
                remote_port = conn.get('remote_port')
                
                if remote_ip == '0.0.0.0' or remote_ip == '::':
                    continue
                
                # Try to connect and get certificate info
                try:
                    context = ssl.create_default_context()
                    with socket.create_connection((remote_ip, remote_port), timeout=3) as sock:
                        with context.wrap_socket(sock, server_hostname=remote_ip) as ssock:
                            cert = ssock.getpeercert()
                            
                            # Get certificate details
                            not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                            issuer = cert.get('issuer')
                            subject = cert.get('subject')
                            
                            # Check if it's expired
                            now = datetime.now()
                            is_expired = now < not_before or now > not_after
                            
                            # Check if it's self-signed
                            is_self_signed = False
                            if issuer == subject:
                                is_self_signed = True
                            
                            # Add to list
                            cert_info = {
                                'remote_ip': remote_ip,
                                'remote_port': remote_port,
                                'subject': subject,
                                'issuer': issuer,
                                'valid_from': not_before.isoformat(),
                                'valid_to': not_after.isoformat(),
                                'is_expired': is_expired,
                                'is_self_signed': is_self_signed
                            }
                            
                            active_ssl_connections.append(cert_info)
                            
                            # Add to appropriate lists
                            if is_expired:
                                expired_certificates.append(cert_info)
                            
                            if is_self_signed:
                                self_signed_certificates.append(cert_info)
                                
                            # Check for other suspicious properties
                            if not_after - not_before > timedelta(days=825):  # Unusually long validity
                                cert_info['reason'] = "Unusually long validity period"
                                suspicious_certificates.append(cert_info)
                                
                except (socket.timeout, socket.error, ssl.SSLError, ssl.CertificateError):
                    # Could not connect or get certificate
                    pass
            
            # Method 2: Check system certificate stores
            local_certificates = []
            for ca_file in self.trusted_certificate_authorities:
                if os.path.exists(ca_file):
                    try:
                        # Use openssl to list certificates
                        cmd = ["openssl", "crl2pkcs7", "-nocrl", "-certfile", ca_file, "|", "openssl", "pkcs7", "-print_certs", "-text"]
                        output = subprocess.check_output(cmd, universal_newlines=True, shell=True)
                        
                        # Parse the output to get certificate info
                        certs = re.split(r'Certificate:', output)[1:]  # Skip the first empty part
                        
                        for cert_text in certs:
                            # Extract subject and issuer
                            subject_match = re.search(r'Subject: (.*?)$', cert_text, re.MULTILINE)
                            issuer_match = re.search(r'Issuer: (.*?)$', cert_text, re.MULTILINE)
                            
                            # Extract validity period
                            not_before_match = re.search(r'Not Before: (.*?)$', cert_text, re.MULTILINE)
                            not_after_match = re.search(r'Not After : (.*?)$', cert_text, re.MULTILINE)
                            
                            if subject_match and issuer_match and not_before_match and not_after_match:
                                subject = subject_match.group(1)
                                issuer = issuer_match.group(1)
                                not_before_str = not_before_match.group(1)
                                not_after_str = not_after_match.group(1)
                                
                                try:
                                    not_before = datetime.strptime(not_before_str, '%b %d %H:%M:%S %Y %Z')
                                    not_after = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                                    
                                    # Check if it's expired
                                    now = datetime.now()
                                    is_expired = now < not_before or now > not_after
                                    
                                    # Check if it's self-signed
                                    is_self_signed = subject == issuer
                                    
                                    cert_info = {
                                        'subject': subject,
                                        'issuer': issuer,
                                        'valid_from': not_before.isoformat(),
                                        'valid_to': not_after.isoformat(),
                                        'is_expired': is_expired,
                                        'is_self_signed': is_self_signed,
                                        'source': ca_file
                                    }
                                    
                                    local_certificates.append(cert_info)
                                    
                                    # Add to appropriate lists
                                    if is_expired:
                                        expired_certificates.append(cert_info)
                                    
                                    if is_self_signed and not subject.startswith('CN=localhost'):
                                        self_signed_certificates.append(cert_info)
                                        
                                    # Check for other suspicious properties
                                    if not_after - not_before > timedelta(days=825):  # Unusually long validity
                                        cert_info['reason'] = "Unusually long validity period"
                                        suspicious_certificates.append(cert_info)
                                        
                                except ValueError:
                                    # Could not parse date
                                    pass
                    except (subprocess.CalledProcessError, FileNotFoundError):
                        # Could not run openssl command
                        pass
            
            # Determine if there are any anomalies
            is_anomalous = (
                len(invalid_certificates) > 0 or
                len(expired_certificates) > 0 or 
                len(suspicious_certificates) > 0 or
                len(self_signed_certificates) > 2  # Allow a couple of self-signed certs (localhost, etc.)
            )
            
            return {
                'active_ssl_connections': active_ssl_connections,
                'local_certificates': local_certificates[:10],  # Limit to 10
                'invalid_certificates': invalid_certificates,
                'self_signed_certificates': self_signed_certificates,
                'expired_certificates': expired_certificates,
                'suspicious_certificates': suspicious_certificates,
                'active_count': len(active_ssl_connections),
                'invalid_count': len(invalid_certificates),
                'self_signed_count': len(self_signed_certificates),
                'expired_count': len(expired_certificates),
                'suspicious_count': len(suspicious_certificates),
                'is_anomalous': is_anomalous
            }
            
        except Exception as e:
            self.logger.error(f"Error checking SSL certificates: {e}")
            return {
                'error': str(e),
                'is_anomalous': False
            }
    
    def _check_traffic_patterns(self):
        """Analyze network traffic patterns for anomalies"""
        self.logger.debug("Analyzing network traffic patterns")
        
        anomalous_patterns = []
        sample_data = []
        
        try:
            # Check if tcpdump is available
            try:
                subprocess.check_output(["which", "tcpdump"], universal_newlines=True)
                tcpdump_available = True
            except subprocess.CalledProcessError:
                tcpdump_available = False
                
            if not tcpdump_available:
                return {
                    'error': "tcpdump not available",
                    'is_anomalous': False
                }
            
            # Create a temporary file for capturing
            with tempfile.NamedTemporaryFile() as tmp_capture:
                # Capture a small sample of traffic
                cmd = [
                    "timeout", str(self.traffic_monitor_duration), 
                    "tcpdump", "-nn", "-s", "0", "-c", str(self.packet_sample_size),
                    "-w", tmp_capture.name
                ]
                
                try:
                    subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                except subprocess.CalledProcessError:
                    # Capture might timeout if there's not enough traffic
                    pass
                
                # Read the capture file
                cmd = ["tcpdump", "-nn", "-r", tmp_capture.name]
                output = subprocess.check_output(cmd, universal_newlines=True)
                
                # Parse the output
                connections = defaultdict(int)
                protocols = defaultdict(int)
                ports = defaultdict(int)
                packet_sizes = []
                periodic_connections = defaultdict(list)
                
                last_timestamp = None
                prev_packets = {}
                
                for line in output.strip().split('\n'):
                    if not line:
                        continue
                        
                    # Parse packet info
                    parts = line.split()
                    if len(parts) < 5:
                        continue
                    
                    timestamp = parts[0]
                    
                    # Track packet arrival times for periodicity detection
                    if last_timestamp:
                        time_diff = float(timestamp) - float(last_timestamp)
                        for conn_key, timestamps in periodic_connections.items():
                            if len(timestamps) > 0:
                                periodic_connections[conn_key].append(time_diff)
                    
                    last_timestamp = timestamp
                    
                    # Attempt to identify protocol, IPs, and ports
                    protocol = None
                    src_ip = None
                    dst_ip = None
                    src_port = None
                    dst_port = None
                    packet_size = None
                    
                    # Check for IPv4
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+)', line)
                    if ip_match:
                        src_ip = ip_match.group(1)
                        src_port = int(ip_match.group(2))
                        dst_ip = ip_match.group(3)
                        dst_port = int(ip_match.group(4))
                        
                        # Identify protocol
                        protocol = "UDP" if "UDP" in line else "TCP"
                        
                        # Create connection key (normalized so direction doesn't matter)
                        ips = sorted([src_ip, dst_ip])
                        ports = sorted([src_port, dst_port])
                        conn_key = f"{ips[0]}:{ports[0]}<->{ips[1]}:{ports[1]}"
                        
                        connections[conn_key] += 1
                        protocols[protocol] += 1
                        ports[src_port] += 1
                        ports[dst_port] += 1
                        
                        # Extract packet size
                        size_match = re.search(r'length (\d+)', line)
                        if size_match:
                            packet_size = int(size_match.group(1))
                            packet_sizes.append(packet_size)
                        
                        # Store packet info for pattern detection
                        packet_info = {
                            'timestamp': timestamp,
                            'src_ip': src_ip,
                            'src_port': src_port,
                            'dst_ip': dst_ip,
                            'dst_port': dst_port,
                            'protocol': protocol,
                            'size': packet_size
                        }
                        
                        # Check for patterns in consecutive packets
                        if conn_key in prev_packets:
                            prev = prev_packets[conn_key]
                            
                            # Track timestamps for periodicity detection
                            if conn_key not in periodic_connections:
                                periodic_connections[conn_key] = []
                            
                            if 'timestamp' in prev:
                                time_diff = float(timestamp) - float(prev['timestamp'])
                                periodic_connections[conn_key].append(time_diff)
                        
                        prev_packets[conn_key] = packet_info
                        
                        # Keep a limited sample for the results
                        if len(sample_data) < 10:
                            sample_data.append(packet_info)
                
                # Analyze the collected data
                
                # 1. Check for periodic connection patterns (beaconing)
                for conn_key, time_diffs in periodic_connections.items():
                    if len(time_diffs) >= 5:  # Need enough samples
                        # Calculate average and standard deviation
                        avg_time = sum(time_diffs) / len(time_diffs)
                        std_dev = (sum((t - avg_time) ** 2 for t in time_diffs) / len(time_diffs)) ** 0.5
                        
                        # Check if highly periodic (low standard deviation relative to average)
                        if avg_time > 0 and (std_dev / avg_time) < 0.1:  # Less than 10% variation
                            src_dst = conn_key.split('<->')
                            anomalous_patterns.append({
                                'type': 'periodic_beaconing',
                                'connection': conn_key,
                                'avg_interval': avg_time,
                                'std_dev': std_dev,
                                'sample_count': len(time_diffs),
                                'source': src_dst[0],
                                'destination': src_dst[1],
                                'confidence': 'high' if (std_dev / avg_time) < 0.05 else 'medium'
                            })
                
                # 2. Check for unusual packet size distributions
                if packet_sizes:
                    avg_size = sum(packet_sizes) / len(packet_sizes)
                    # Check for unusually uniform packet sizes
                    size_counts = Counter(packet_sizes)
                    most_common_size, most_common_count = size_counts.most_common(1)[0]
                    
                    if most_common_count > len(packet_sizes) * 0.7:  # More than 70% of packets have the same size
                        anomalous_patterns.append({
                            'type': 'uniform_packet_sizes',
                            'most_common_size': most_common_size,
                            'occurrence_percentage': (most_common_count / len(packet_sizes)) * 100,
                            'total_packets': len(packet_sizes),
                            'confidence': 'medium'
                        })
                
                # 3. Check for unusual port activity
                for port, count in ports.items():
                    # Check if it's a high port with substantial traffic
                    if port > 10000 and count > len(packet_sizes) * 0.2:  # More than 20% of traffic
                        # Check if this is a known protocol
                        if port not in self.expected_ports:
                            anomalous_patterns.append({
                                'type': 'unusual_port_activity',
                                'port': port,
                                'packet_count': count,
                                'percentage': (count / len(packet_sizes)) * 100,
                                'confidence': 'medium'
                            })
                
                # Determine if there are any anomalies
                is_anomalous = len(anomalous_patterns) > 0
                
                return {
                    'anomalous_patterns': anomalous_patterns,
                    'sample_data': sample_data,
                    'protocol_distribution': dict(protocols),
                    'anomalous_count': len(anomalous_patterns),
                    'is_anomalous': is_anomalous
                }
                
        except Exception as e:
            self.logger.error(f"Error analyzing traffic patterns: {e}")
            return {
                'error': str(e),
                'is_anomalous': False
            }
    
    def _check_network_services(self):
        """Enumerate and analyze network services for security issues"""
        self.logger.debug("Checking network services")
        
        discovered_services = []
        insecure_services = []
        unusual_services = []
        
        try:
            # Get all listening ports
            listening_data = self._check_listening_ports()
            listening_ports = listening_data.get('listening_ports', [])
            
            # Create a list of local IP addresses to check
            local_ips = ['127.0.0.1']  # Always include localhost
            
            # Get additional local IPs if configured
            if self.include_local_network:
                try:
                    # Get network interfaces
                    cmd = ["ip", "-4", "addr", "show"]
                    output = subprocess.check_output(cmd, universal_newlines=True)
                    
                    # Extract IP addresses
                    ip_matches = re.findall(r'inet\s+(\d+\.\d+\.\d+\.\d+)', output)
                    for ip in ip_matches:
                        if not ip.startswith('127.'):  # Skip loopback
                            local_ips.append(ip)
                except (subprocess.CalledProcessError, FileNotFoundError):
                    pass
            
            # Check each service
            for service in listening_ports:
                port = service.get('port')
                addr = service.get('addr')
                proto = service.get('proto')
                program = service.get('program', '')
                
                # Skip if port or address is not available
                if not port or not addr:
                    continue
                
                # Determine which IP to use for testing
                test_ip = '127.0.0.1'
                if addr != '0.0.0.0' and addr != '::' and addr != '0000:0000:0000:0000:0000:0000:0000:0000':
                    try:
                        ipaddress.ip_address(addr)
                        test_ip = addr
                    except ValueError:
                        pass
                
                # Service info
                service_info = {
                    'ip': test_ip,
                    'port': port,
                    'protocol': proto.lower(),
                    'program': program,
                    'banner': None,
                    'is_secure': None
                }
                
                # Try to connect and get service banner
                try:
                    if 'tcp' in proto.lower():
                        with socket.create_connection((test_ip, port), timeout=self.service_scan_timeout) as sock:
                            # Set non-blocking mode
                            sock.setblocking(0)
                            
                            # Send a probe - either a HTTP request or just a newline
                            if port in [80, 443, 8080, 8443]:
                                probe = b"HEAD / HTTP/1.0\r\n\r\n"
                            else:
                                probe = b"\r\n"
                                
                            try:
                                sock.send(probe)
                            except (socket.error, BlockingIOError):
                                pass
                            
                            # Wait for data
                            banner = b""
                            start_time = time.time()
                            while time.time() - start_time < self.service_scan_timeout:
                                try:
                                    data = sock.recv(1024)
                                    if data:
                                        banner += data
                                    else:
                                        break
                                except (socket.error, BlockingIOError):
                                    time.sleep(0.1)
                                    continue
                            
                            if banner:
                                # Try to decode, but handle binary data
                                try:
                                    service_info['banner'] = banner.decode('utf-8', errors='replace')[:200]  # Limit length
                                except UnicodeDecodeError:
                                    service_info['banner'] = banner.hex()[:200]  # Use hex representation if it's binary
                                
                                # Check for known insecure services
                                if self._is_insecure_service(port, program, service_info['banner']):
                                    service_info['is_secure'] = False
                                    insecure_services.append(service_info)
                                else:
                                    service_info['is_secure'] = True
                                
                                # Check for unusual services
                                if self._is_unusual_service(port, program, service_info['banner']):
                                    service_info['is_unusual'] = True
                                    unusual_services.append(service_info)
                                
                            discovered_services.append(service_info)
                except (socket.timeout, socket.error):
                    # Could not connect
                    service_info['error'] = "Connection failed"
                    discovered_services.append(service_info)
            
            # Determine if there are any anomalies
            is_anomalous = len(insecure_services) > 0 or len(unusual_services) > 0
            
            return {
                'discovered_services': discovered_services,
                'insecure_services': insecure_services,
                'unusual_services': unusual_services,
                'total_count': len(discovered_services),
                'insecure_count': len(insecure_services),
                'unusual_count': len(unusual_services),
                'is_anomalous': is_anomalous
            }
            
        except Exception as e:
            self.logger.error(f"Error checking network services: {e}")
            return {
                'error': str(e),
                'is_anomalous': False
            }
    
    def _is_insecure_service(self, port, program, banner):
        """Check if a service appears to be insecure"""
        if not banner:
            return False
            
        # Check for known insecure services based on port
        insecure_ports = {
            21: "FTP",
            23: "Telnet",
            79: "Finger",
            512: "rexec",
            513: "rlogin",
            514: "rsh"
        }
        
        if port in insecure_ports:
            return True
        
        # Check for clear text authentication in banner
        if "password" in banner.lower() and not ("ssh" in banner.lower() or "ssl" in banner.lower() or "tls" in banner.lower()):
            return True
            
        # Check for outdated/vulnerable software versions
        if "apache" in banner.lower() and "apache/2.2" in banner.lower():
            return True
            
        if "nginx" in banner.lower() and any(v in banner.lower() for v in ["nginx/1.0", "nginx/1.1", "nginx/1.2"]):
            return True
            
        # Check for insecure Redis instances
        if port == 6379 and ("redis" in banner.lower() or "-ERR operation not permitted" in banner):
            return True
            
        # Check for MongoDB without auth
        if port == 27017 and "mongodb" in banner.lower():
            return True
            
        # Check for Memcached
        if port == 11211 and "memcached" in banner.lower():
            return True
            
        # Check for ElasticSearch without auth
        if (port == 9200 or port == 9300) and ("elasticsearch" in banner.lower() or "lucene" in banner.lower()):
            return True
            
        return False
    
    def _is_unusual_service(self, port, program, banner):
        """Check if a service appears unusual"""
        if not banner:
            return False
            
        # Check for services on unexpected ports
        common_http_ports = [80, 443, 8000, 8080, 8443]
        if "HTTP" in banner and port not in common_http_ports:
            return True
            
        # Check for services trying to hide their identity
        if len(banner) < 5 and port not in [22]:  # Exclude SSH which may have short banners
            return True
            
        # Check for unusual characters in banner
        unusual_chars = sum(1 for c in banner if ord(c) < 32 or ord(c) > 126)
        if unusual_chars > len(banner) * 0.3:  # More than 30% unusual characters
            return True
            
        # Check for base64 encoded data in banner
        base64_pattern = r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'
        if re.match(base64_pattern, banner.strip()):
            return True
            
        return False
    
    def _is_suspicious_domain(self, domain):
        """Check if a domain looks suspicious"""
        # Check for common patterns in malicious domains
        
        # Check for long random-looking subdomains
        parts = domain.split('.')
        for part in parts:
            if len(part) > 25:  # Very long subdomain
                return True
            
            # Check for random-looking strings (high entropy)
            if len(part) > 10:
                consonant_count = sum(1 for c in part if c.lower() in 'bcdfghjklmnpqrstvwxz')
                if consonant_count > len(part) * 0.7:  # High consonant ratio
                    return True
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.xyz', '.top', '.work', '.gdn', '.bid', '.stream']
        if any(domain.lower().endswith(tld) for tld in suspicious_tlds):
            return True
        
        # Check for domains with lots of digits
        digit_count = sum(1 for c in domain if c.isdigit())
        if digit_count > len(domain) * 0.3:  # More than 30% digits
            return True
        
        # Check for domains with mixed character types (l1k3th15)
        if len(domain) > 10:
            has_digits = any(c.isdigit() for c in domain)
            has_letters = any(c.isalpha() for c in domain)
            alternating = sum(1 for i in range(1, len(domain)) if domain[i].isdigit() != domain[i-1].isdigit())
            if has_digits and has_letters and alternating > len(domain) * 0.25:
                return True
        
        return False
    
    def establish_baseline(self):
        """Establish baseline for network connections"""
        self.logger.info("Establishing baseline for network connections")
        
        baseline = {
            'timestamp': datetime.now().isoformat(),
            'listening_ports': self._get_listening_ports_baseline(),
            'established_connections': self._get_established_connections_baseline(),
            'processes_with_connections': self._get_processes_with_connections_baseline(),
            'hostname': socket.gethostname()
        }
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.baseline_file), exist_ok=True)
        
        # Write baseline to file
        with open(self.baseline_file, 'w') as f:
            json.dump(baseline, f, indent=2)
        
        self.logger.info(f"Baseline saved to {self.baseline_file}")
        
        return baseline
    
    def _get_listening_ports_baseline(self):
        """Get baseline for listening ports"""
        try:
            # Get listening ports using netstat
            cmd = ["netstat", "-tlnp"]
            output = subprocess.check_output(cmd, universal_newlines=True)
            
            listening_ports = []
            
            # Parse the output
            # Skip header lines
            lines = output.strip().split('\n')[2:]
            
            for line in lines:
                if not line.strip():
                    continue
                
                parts = line.split()
                if len(parts) >= 6:
                    proto = parts[0]
                    local_addr = parts[3]
                    pid_info = parts[6] if len(parts) > 6 else ""
                    
                    # Extract port and address
                    local_addr_parts = local_addr.rsplit(':', 1)
                    if len(local_addr_parts) == 2:
                        addr = local_addr_parts[0]
                        port = int(local_addr_parts[1])
                    else:
                        addr = '0.0.0.0'
                        port = int(local_addr)
                    
                    # Extract PID and program name
                    pid = ""
                    program = ""
                    
                    pid_match = re.search(r'(\d+)/(.*)', pid_info)
                    if pid_match:
                        pid = pid_match.group(1)
                        program = pid_match.group(2)
                    
                    listening_ports.append({
                        'proto': proto,
                        'addr': addr,
                        'port': port,
                        'pid': pid,
                        'program': program
                    })
            
            return listening_ports
            
        except Exception as e:
            self.logger.error(f"Error getting listening ports baseline: {e}")
            return []
    
    def _get_established_connections_baseline(self):
        """Get baseline for established connections"""
        try:
            # Get established connections using netstat
            cmd = ["netstat", "-tnp"]
            output = subprocess.check_output(cmd, universal_newlines=True)
            
            established_connections = []
            
            # Parse the output
            # Skip header lines
            lines = output.strip().split('\n')[2:]
            
            for line in lines:
                if not line.strip():
                    continue
                
                parts = line.split()
                if len(parts) >= 7 and "ESTABLISHED" in line:
                    proto = parts[0]
                    local_addr = parts[3]
                    remote_addr = parts[4]
                    pid_info = parts[6]
                    
                    # Extract local port and address
                    local_addr_parts = local_addr.rsplit(':', 1)
                    if len(local_addr_parts) == 2:
                        local_ip = local_addr_parts[0]
                        local_port = int(local_addr_parts[1])
                    else:
                        local_ip = '0.0.0.0'
                        local_port = int(local_addr)
                    
                    # Extract remote port and address
                    remote_addr_parts = remote_addr.rsplit(':', 1)
                    if len(remote_addr_parts) == 2:
                        remote_ip = remote_addr_parts[0]
                        remote_port = int(remote_addr_parts[1])
                    else:
                        remote_ip = '0.0.0.0'
                        remote_port = int(remote_addr)
                    
                    # Extract PID and program name
                    pid = ""
                    program = ""
                    
                    pid_match = re.search(r'(\d+)/(.*)', pid_info)
                    if pid_match:
                        pid = pid_match.group(1)
                        program = pid_match.group(2)
                    
                    established_connections.append({
                        'proto': proto,
                        'local_ip': local_ip,
                        'local_port': local_port,
                        'remote_ip': remote_ip,
                        'remote_port': remote_port,
                        'pid': pid,
                        'program': program
                    })
            
            return established_connections
            
        except Exception as e:
            self.logger.error(f"Error getting established connections baseline: {e}")
            return []
    
    def _get_processes_with_connections_baseline(self):
        """Get baseline for processes with network connections"""
        try:
            # Get all processes with connections
            cmd = ["lsof", "-i", "-n", "-P"]
            output = subprocess.check_output(cmd, universal_newlines=True)
            
            processes = {}
            
            # Parse the output
            # Skip header line
            lines = output.strip().split('\n')[1:]
            
            for line in lines:
                if not line.strip():
                    continue
                
                parts = line.split()
                if len(parts) >= 9:
                    program = parts[0]
                    pid = parts[1]
                    user = parts[2]
                    
                    # Process already seen
                    if pid in processes:
                        connection_count = processes[pid].get('connection_count', 0)
                        processes[pid]['connection_count'] = connection_count + 1
                    else:
                        # New process
                        processes[pid] = {
                            'program': program,
                            'pid': pid,
                            'user': user,
                            'connection_count': 1
                        }
            
            return list(processes.values())
            
        except Exception as e:
            self.logger.error(f"Error getting processes with connections baseline: {e}")
            return []
    
    def compare_baseline(self):
        """Compare current network connections with baseline"""
        self.logger.info("Comparing network connections with baseline")
        
        # Check if baseline exists
        if not os.path.exists(self.baseline_file):
            self.logger.warning("No baseline found. Run with --establish-baseline first.")
            return {
                'error': "No baseline found",
                'is_anomalous': False
            }
        
        # Load baseline
        with open(self.baseline_file, 'r') as f:
            baseline = json.load(f)
        
        # Get current state
        current_listening = self._get_listening_ports_baseline()
        current_established = self._get_established_connections_baseline()
        current_processes = self._get_processes_with_connections_baseline()
        
        # Compare listening ports
        new_listening_ports = []
        missing_listening_ports = []
        
        baseline_listening = {f"{port['addr']}:{port['port']}": port for port in baseline.get('listening_ports', [])}
        current_listening_dict = {f"{port['addr']}:{port['port']}": port for port in current_listening}
        
        for key, port in current_listening_dict.items():
            if key not in baseline_listening:
                new_listening_ports.append(port)
        
        for key, port in baseline_listening.items():
            if key not in current_listening_dict:
                missing_listening_ports.append(port)
        
        # Check if any new ports are suspicious
        suspicious_new_ports = []
        for port in new_listening_ports:
            port_num = port.get('port', 0)
            if port_num in self.suspicious_ports:
                port['is_suspicious'] = True
                suspicious_new_ports.append(port)
        
        # Compare processes with connections
        new_connection_processes = []
        
        baseline_processes = {proc.get('program', ''): proc for proc in baseline.get('processes_with_connections', [])}
        current_processes_dict = {proc.get('program', ''): proc for proc in current_processes}
        
        for name, proc in current_processes_dict.items():
            if name not in baseline_processes:
                new_connection_processes.append(proc)
            elif proc.get('connection_count', 0) > baseline_processes[name].get('connection_count', 0) * 2:
                # Significant increase in connection count (more than double)
                proc['increased_connections'] = True
                proc['baseline_count'] = baseline_processes[name].get('connection_count', 0)
                new_connection_processes.append(proc)
        
        # Determine if there are any anomalies
        is_anomalous = len(suspicious_new_ports) > 0
        
        return {
            'timestamp': datetime.now().isoformat(),
            'baseline_timestamp': baseline.get('timestamp'),
            'new_listening_ports': new_listening_ports,
            'missing_listening_ports': missing_listening_ports,
            'suspicious_new_ports': suspicious_new_ports,
            'new_connection_processes': new_connection_processes,
            'new_listening_count': len(new_listening_ports),
            'missing_listening_count': len(missing_listening_ports),
            'suspicious_new_count': len(suspicious_new_ports),
            'new_processes_count': len(new_connection_processes),
            'is_anomalous': is_anomalous
        }