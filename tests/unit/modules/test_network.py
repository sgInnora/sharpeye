#!/usr/bin/env python3
"""
Unit tests for the Network Analyzer module.
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock, mock_open
import tempfile
import json
from datetime import datetime, timedelta
import socket
import ssl
import time

# Add src directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../src')))

from modules.network import NetworkAnalyzer

class TestNetworkAnalyzer(unittest.TestCase):
    """Test cases for the Network Analyzer module"""
    
    def setUp(self):
        """Set up test environment"""
        self.config = {
            'check_listening_ports': True,
            'check_outbound': True,
            'check_remote_access': True,
            'check_arp_spoofing': True,
            'check_promiscuous_mode': True,
            'check_ssl_certificates': True,
            'check_traffic_patterns': True,
            'check_network_services': True,
            'enable_geolocation': False,
            'service_scan_timeout': 1,
            'traffic_monitor_duration': 5,
            'packet_sample_size': 50
        }
        
        # Create a temporary directory for baselines
        self.temp_dir = tempfile.TemporaryDirectory()
        self.baseline_file = os.path.join(self.temp_dir.name, 'network.json')
        self.config['baseline_file'] = self.baseline_file
        
        # Initialize analyzer
        self.analyzer = NetworkAnalyzer(self.config)
    
    def tearDown(self):
        """Clean up after tests"""
        self.temp_dir.cleanup()
    
    @patch('subprocess.check_output')
    def test_check_listening_ports(self, mock_subprocess):
        """Test checking for listening ports"""
        # Mock netstat output
        netstat_output = """
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1234/sshd
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      2345/postgres
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      3456/nginx
tcp        0      0 0.0.0.0:4444            0.0.0.0:*               LISTEN      6789/suspicious
tcp6       0      0 :::22                   :::*                    LISTEN      1234/sshd
"""
        mock_subprocess.return_value = netstat_output
        
        # Run test
        result = self.analyzer._check_listening_ports()
        
        # Verify the result
        self.assertTrue(result['is_anomalous'], "Should detect suspicious port")
        self.assertEqual(len(result['listening_ports']), 5, "Should find 5 listening ports")
        self.assertEqual(len(result['suspicious_ports']), 1, "Should find 1 suspicious port")
        
        # Check if Metasploit default port (4444) was identified as suspicious
        found_suspicious = False
        for port in result['suspicious_ports']:
            if port.get('port') == 4444:
                found_suspicious = True
                break
        
        self.assertTrue(found_suspicious, "Should identify port 4444 as suspicious")
    
    @patch('subprocess.check_output')
    def test_check_established_connections(self, mock_subprocess):
        """Test checking for established connections"""
        # Mock netstat output
        netstat_output = """
Active Internet connections (w/o servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 192.168.1.10:46852      192.168.1.1:443         ESTABLISHED 1234/chrome
tcp        0      0 192.168.1.10:42222      203.0.113.1:80          ESTABLISHED 1234/chrome
tcp        0      0 192.168.1.10:12345      198.51.100.1:6667       ESTABLISHED 5678/suspicious
"""
        mock_subprocess.return_value = netstat_output
        
        # Run test
        result = self.analyzer._check_established_connections()
        
        # Verify the result
        self.assertTrue(result['is_anomalous'], "Should detect suspicious connection")
        self.assertEqual(len(result['established_connections']), 3, "Should find 3 established connections")
        self.assertEqual(len(result['suspicious_connections']), 1, "Should find 1 suspicious connection")
        
        # Check if connection to IRC port (6667) was identified as suspicious
        found_suspicious = False
        for conn in result['suspicious_connections']:
            if conn.get('remote_port') == 6667:
                found_suspicious = True
                break
        
        self.assertTrue(found_suspicious, "Should identify connection to IRC port 6667 as suspicious")
    
    @patch('subprocess.check_output')
    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open, read_data="PermitRootLogin yes")
    def test_check_remote_access(self, mock_file, mock_exists, mock_subprocess):
        """Test checking for remote access services"""
        # Setup mocks
        mock_exists.return_value = True
        
        # Mock the _check_listening_ports method to return predictable data
        self.analyzer._check_listening_ports = MagicMock(return_value={
            'listening_ports': [
                {'port': 22, 'addr': '0.0.0.0', 'proto': 'tcp', 'program': 'sshd'},
                {'port': 23, 'addr': '0.0.0.0', 'proto': 'tcp', 'program': 'telnetd'},
                {'port': 3389, 'addr': '0.0.0.0', 'proto': 'tcp', 'program': 'xrdp'}
            ]
        })
        
        # Run test
        result = self.analyzer._check_remote_access()
        
        # Verify the result
        self.assertTrue(result['is_anomalous'], "Should detect remote access services")
        self.assertEqual(len(result['remote_access_services']), 3, "Should find 3 remote access services")
        self.assertGreater(len(result['ssh_config_issues']), 0, "Should detect SSH config issues")
        
        # Check if telnet was detected
        found_telnet = False
        for service in result['remote_access_services']:
            if service.get('port') == 23:
                found_telnet = True
                break
        
        self.assertTrue(found_telnet, "Should identify telnet service")
    
    @patch('subprocess.check_output')
    def test_check_arp_spoofing(self, mock_subprocess):
        """Test checking for ARP spoofing"""
        # Mock arp -an output with duplicate MAC
        arp_output = """
? (192.168.1.1) at 00:11:22:33:44:55 [ether] on eth0
? (192.168.1.2) at 00:11:22:33:44:55 [ether] on eth0
? (192.168.1.3) at aa:bb:cc:dd:ee:ff [ether] on eth0
"""
        # Mock ip route output
        route_output = "default via 192.168.1.1 dev eth0 proto dhcp metric 100"
        
        # Configure mock to return different outputs for different commands
        def side_effect(*args, **kwargs):
            if args[0][0] == 'arp':
                return arp_output
            elif args[0][0] == 'ip':
                return route_output
            return ""
        
        mock_subprocess.side_effect = side_effect
        
        # Create a baseline file with a different MAC for the default gateway
        baseline_data = {
            'arp_table': {
                '192.168.1.1': 'aa:bb:cc:dd:ee:ff'  # Different from current (00:11:22:33:44:55)
            }
        }
        
        with open(self.baseline_file, 'w') as f:
            json.dump(baseline_data, f)
        
        # Run test
        result = self.analyzer._check_arp_spoofing()
        
        # Verify the result
        self.assertTrue(result['is_anomalous'], "Should detect ARP anomalies")
        self.assertEqual(len(result['duplicate_mac_addresses']), 1, "Should find 1 duplicate MAC")
        self.assertGreaterEqual(len(result['suspicious_entries']), 1, "Should find suspicious entries")
        
        # Check if default gateway MAC change was detected
        found_gateway_change = False
        for entry in result['suspicious_entries']:
            if entry.get('ip') == '192.168.1.1' and 'gateway' in entry.get('reason', '').lower():
                found_gateway_change = True
                break
        
        self.assertTrue(found_gateway_change, "Should detect default gateway MAC change")
    
    @patch('subprocess.check_output')
    @patch('os.path.exists')
    @patch('os.listdir')
    @patch('builtins.open', new_callable=mock_open, read_data="0x100")  # 0x100 is PROMISC flag
    def test_check_promiscuous_mode(self, mock_file, mock_listdir, mock_exists, mock_subprocess):
        """Test checking for promiscuous mode interfaces"""
        # Setup mocks
        mock_exists.return_value = True
        mock_listdir.return_value = ['eth0', 'lo']
        
        # Mock ip link output
        ip_link_output = """
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP,PROMISC> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000
    link/ether 00:11:22:33:44:55 brd ff:ff:ff:ff:ff:ff
"""
        # Mock ps output with tcpdump
        ps_output = """
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root      1234  0.0  0.1  12345  6789 ?        S    10:00   0:00 tcpdump -i eth0
"""
        
        # Configure mock to return different outputs for different commands
        def side_effect(*args, **kwargs):
            if args[0][0] == 'ip':
                return ip_link_output
            elif args[0][0] == 'ps':
                return ps_output
            return ""
            
        mock_subprocess.side_effect = side_effect
        
        # Run test
        result = self.analyzer._check_promiscuous_mode()
        
        # Verify the result
        self.assertTrue(result['is_anomalous'], "Should detect promiscuous interfaces")
        self.assertGreaterEqual(len(result['promiscuous_interfaces']), 1, "Should find promiscuous interfaces")
        self.assertGreaterEqual(len(result['suspicious_processes']), 1, "Should find suspicious processes")
        
        # Check if eth0 was detected as promiscuous
        found_eth0 = False
        for interface in result['promiscuous_interfaces']:
            if interface.get('interface') == 'eth0':
                found_eth0 = True
                break
        
        self.assertTrue(found_eth0, "Should detect eth0 in promiscuous mode")
        
        # Check if tcpdump was detected
        found_tcpdump = False
        for process in result['suspicious_processes']:
            if 'tcpdump' in process.get('command', ''):
                found_tcpdump = True
                break
        
        self.assertTrue(found_tcpdump, "Should detect tcpdump process")
    
    @patch('socket.create_connection')
    @patch('ssl.create_default_context')
    @patch('ssl._create_unverified_context')
    @patch('subprocess.check_output')
    def test_check_ssl_certificates(self, mock_subprocess, mock_unverified_context, mock_context, mock_socket):
        """Test checking for SSL certificates"""
        # Create mock objects for SSL connection
        mock_ssl_sock = MagicMock()
        mock_sock = MagicMock()
        
        # Mock SSL certificate data
        now = datetime.now()
        future = now + timedelta(days=365)
        past = now - timedelta(days=365)
        
        # Create a cert for an active connection (valid)
        mock_ssl_sock.getpeercert.return_value = {
            'subject': ((('commonName', 'example.com'),),),
            'issuer': ((('commonName', 'Example CA'),),),
            'notBefore': (now - timedelta(days=10)).strftime('%b %d %H:%M:%S %Y GMT'),
            'notAfter': (now + timedelta(days=355)).strftime('%b %d %H:%M:%S %Y GMT')
        }
        
        # Mock the context's wrap_socket to return our mock SSL socket
        mock_context_instance = MagicMock()
        mock_context_instance.wrap_socket.return_value = mock_ssl_sock
        mock_context.return_value = mock_context_instance
        
        # Mock socket connection
        mock_socket.return_value = mock_sock
        
        # Mock analyzer._check_established_connections to return connections to SSL ports
        self.analyzer._check_established_connections = MagicMock(return_value={
            'established_connections': [
                {'remote_ip': '192.168.1.1', 'remote_port': 443, 'local_port': 12345, 'program': 'curl'}
            ]
        })
        
        # Mock openssl output with some certificates
        openssl_output = f"""
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 12345 (0x3039)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN = Self Signed CA
        Validity
            Not Before: {past.strftime('%b %d %H:%M:%S %Y GMT')}
            Not After : {past.strftime('%b %d %H:%M:%S %Y GMT')}
        Subject: CN = localhost
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 67890 (0x10932)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN = Example CA
        Validity
            Not Before: {now.strftime('%b %d %H:%M:%S %Y GMT')}
            Not After : {future.strftime('%b %d %H:%M:%S %Y GMT')}
        Subject: CN = example.org
"""
        mock_subprocess.return_value = openssl_output
        
        # Run test
        result = self.analyzer._check_ssl_certificates()
        
        # Verify the result
        self.assertTrue(result['is_anomalous'], "Should detect SSL anomalies")
        self.assertGreaterEqual(len(result['active_ssl_connections']), 1, "Should find active SSL connections")
        self.assertGreaterEqual(len(result['local_certificates']), 1, "Should find local certificates")
        
        # Check if we found expired certificates
        self.assertGreaterEqual(len(result['expired_certificates']), 1, "Should find expired certificates")
    
    @patch('subprocess.check_output')
    @patch('subprocess.run')
    @patch('tempfile.NamedTemporaryFile')
    def test_check_traffic_patterns(self, mock_tempfile, mock_run, mock_subprocess):
        """Test checking for suspicious traffic patterns"""
        # Setup mocks
        mock_tempfile.return_value.__enter__.return_value.name = '/tmp/test_capture'
        
        # Mock tcpdump output
        tcpdump_output = """
10:00:00.000000 IP 192.168.1.10.12345 > 198.51.100.1.6667: Flags [P.], seq 1:100, ack 1, win 502, length 99
10:00:01.000000 IP 192.168.1.10.12345 > 198.51.100.1.6667: Flags [P.], seq 100:200, ack 1, win 502, length 100
10:00:02.000000 IP 192.168.1.10.12345 > 198.51.100.1.6667: Flags [P.], seq 200:300, ack 1, win 502, length 100
10:00:03.000000 IP 192.168.1.10.12345 > 198.51.100.1.6667: Flags [P.], seq 300:400, ack 1, win 502, length 100
10:00:04.000000 IP 192.168.1.10.12345 > 198.51.100.1.6667: Flags [P.], seq 400:500, ack 1, win 502, length 100
10:00:05.000000 IP 192.168.1.10.12345 > 198.51.100.1.6667: Flags [P.], seq 500:600, ack 1, win 502, length 100
"""
        
        # Configure mock to handle different command cases
        def side_effect(*args, **kwargs):
            if args[0][0] == 'which':
                return '/usr/bin/tcpdump'
            elif args[0][0] == 'tcpdump' and '-r' in args[0]:
                return tcpdump_output
            return ""
        
        mock_subprocess.side_effect = side_effect
        
        # Run test
        result = self.analyzer._check_traffic_patterns()
        
        # Verify the result
        self.assertTrue(result['is_anomalous'], "Should detect traffic pattern anomalies")
        self.assertGreaterEqual(len(result['anomalous_patterns']), 1, "Should find anomalous patterns")
        
        # Check for periodic beaconing pattern
        found_periodic = False
        for pattern in result['anomalous_patterns']:
            if pattern.get('type') == 'periodic_beaconing':
                found_periodic = True
                break
        
        self.assertTrue(found_periodic, "Should detect periodic beaconing pattern")
    
    @patch('socket.create_connection')
    @patch('subprocess.check_output')
    def test_check_network_services(self, mock_subprocess, mock_socket):
        """Test checking for network services"""
        # Mock the _check_listening_ports method to return predictable data
        self.analyzer._check_listening_ports = MagicMock(return_value={
            'listening_ports': [
                {'port': 22, 'addr': '0.0.0.0', 'proto': 'tcp', 'program': 'sshd'},
                {'port': 80, 'addr': '0.0.0.0', 'proto': 'tcp', 'program': 'httpd'},
                {'port': 21, 'addr': '0.0.0.0', 'proto': 'tcp', 'program': 'vsftpd'}
            ]
        })
        
        # Mock IP addresses
        ip_output = """
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0
"""
        mock_subprocess.return_value = ip_output
        
        # Mock socket for banner grabbing
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [
            b"SSH-2.0-OpenSSH_8.2p1",  # SSH banner
            b"220 (vsFTPd 3.0.3)",  # FTP banner
            b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41"  # HTTP banner
        ]
        mock_socket.return_value.__enter__.return_value = mock_sock
        
        # Run test
        result = self.analyzer._check_network_services()
        
        # Verify the result
        self.assertTrue(result['is_anomalous'], "Should detect insecure services")
        self.assertEqual(len(result['discovered_services']), 3, "Should discover 3 services")
        self.assertGreaterEqual(len(result['insecure_services']), 1, "Should find insecure services")
        
        # Check if FTP was identified as insecure
        found_ftp = False
        for service in result['insecure_services']:
            if service.get('port') == 21:
                found_ftp = True
                break
        
        self.assertTrue(found_ftp, "Should identify FTP as insecure")
    
    def test_is_suspicious_domain(self):
        """Test suspicious domain detection"""
        # Test a normal domain
        normal_domain = "example.com"
        self.assertFalse(self.analyzer._is_suspicious_domain(normal_domain), "Should not flag normal domain")
        
        # Test a suspicious domain with very long subdomain
        long_subdomain = "a" * 30 + ".example.com"
        self.assertTrue(self.analyzer._is_suspicious_domain(long_subdomain), "Should flag domain with long subdomain")
        
        # Test a domain with high consonant ratio
        consonant_domain = "bcdfghjklm.example.com"
        self.assertTrue(self.analyzer._is_suspicious_domain(consonant_domain), "Should flag domain with high consonant ratio")
        
        # Test a domain with suspicious TLD
        suspicious_tld = "example.xyz"
        self.assertTrue(self.analyzer._is_suspicious_domain(suspicious_tld), "Should flag domain with suspicious TLD")
        
        # Test a domain with many digits
        digit_domain = "example123456.com"
        self.assertTrue(self.analyzer._is_suspicious_domain(digit_domain), "Should flag domain with many digits")
        
        # Test a domain with alternating letters and digits
        alternating_domain = "e1x2a3m4p5l6e7.com"
        self.assertTrue(self.analyzer._is_suspicious_domain(alternating_domain), "Should flag domain with alternating characters")
    
    @patch('subprocess.check_output')
    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open)
    def test_establish_baseline(self, mock_file, mock_exists, mock_subprocess):
        """Test establishing a baseline"""
        # Setup mocks
        mock_exists.return_value = True
        
        # Mock various command outputs
        netstat_listen_output = """
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1234/sshd
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      2345/postgres
"""
        
        netstat_established_output = """
Active Internet connections (w/o servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 192.168.1.10:46852      192.168.1.1:443         ESTABLISHED 1234/chrome
"""
        
        lsof_output = """
COMMAND     PID   USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
sshd       1234   root    3u  IPv4  12345      0t0  TCP *:ssh (LISTEN)
postgres   2345 postgres  5u  IPv4  23456      0t0  TCP localhost:postgresql (LISTEN)
chrome     1234   user  125u  IPv4  34567      0t0  TCP 192.168.1.10:46852->192.168.1.1:443 (ESTABLISHED)
"""
        
        # Configure mock to return different outputs for different commands
        def side_effect(*args, **kwargs):
            if args[0][0] == 'netstat' and '-tlnp' in args[0]:
                return netstat_listen_output
            elif args[0][0] == 'netstat' and '-tnp' in args[0]:
                return netstat_established_output
            elif args[0][0] == 'lsof':
                return lsof_output
            return ""
        
        mock_subprocess.side_effect = side_effect
        
        # Run test
        baseline = self.analyzer.establish_baseline()
        
        # Verify the result
        self.assertIsNotNone(baseline, "Should create baseline")
        self.assertIn('listening_ports', baseline, "Baseline should include listening_ports")
        self.assertIn('established_connections', baseline, "Baseline should include established_connections")
        self.assertIn('processes_with_connections', baseline, "Baseline should include processes_with_connections")
        
        # Verify that the baseline was saved to a file
        mock_file.assert_called()
    
    @patch('subprocess.check_output')
    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open, read_data=json.dumps({
        'timestamp': datetime.now().isoformat(),
        'listening_ports': [
            {'proto': 'tcp', 'addr': '0.0.0.0', 'port': 22, 'pid': '1234', 'program': 'sshd'}
        ],
        'established_connections': [],
        'processes_with_connections': [
            {'program': 'sshd', 'pid': '1234', 'user': 'root', 'connection_count': 1}
        ],
        'hostname': 'test-host'
    }))
    def test_compare_baseline(self, mock_file, mock_exists, mock_subprocess):
        """Test comparing against baseline"""
        # Setup mocks
        mock_exists.return_value = True
        
        # Mock _get_listening_ports_baseline to return a different set of ports
        self.analyzer._get_listening_ports_baseline = MagicMock(return_value=[
            {'proto': 'tcp', 'addr': '0.0.0.0', 'port': 22, 'pid': '1234', 'program': 'sshd'},
            {'proto': 'tcp', 'addr': '0.0.0.0', 'port': 80, 'pid': '5678', 'program': 'httpd'}  # New
        ])
        
        # Mock _get_established_connections_baseline to return empty list
        self.analyzer._get_established_connections_baseline = MagicMock(return_value=[])
        
        # Mock _get_processes_with_connections_baseline to return processes
        self.analyzer._get_processes_with_connections_baseline = MagicMock(return_value=[
            {'program': 'sshd', 'pid': '1234', 'user': 'root', 'connection_count': 1},
            {'program': 'httpd', 'pid': '5678', 'user': 'apache', 'connection_count': 1}  # New
        ])
        
        # Run test
        result = self.analyzer.compare_baseline()
        
        # Verify the result
        self.assertTrue(result['is_anomalous'], "Should detect changes from baseline")
        self.assertEqual(len(result['new_listening_ports']), 1, "Should detect 1 new listening port")
        self.assertEqual(len(result['new_connection_processes']), 1, "Should detect 1 new process with connections")
        
        # Check if new HTTP port was detected
        found_http = False
        for port in result['new_listening_ports']:
            if port.get('port') == 80:
                found_http = True
                break
        
        self.assertTrue(found_http, "Should detect new HTTP port")

if __name__ == '__main__':
    unittest.main()