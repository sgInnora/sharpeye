#!/usr/bin/env python3
"""
Unit tests for the SSH Analyzer module.
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock, mock_open
import tempfile
import json
from datetime import datetime, timedelta

# Add src directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../src')))

from modules.ssh_analyzer import SSHAnalyzer

class TestSSHAnalyzer(unittest.TestCase):
    """Test cases for the SSH Analyzer module"""
    
    def setUp(self):
        """Set up test environment"""
        self.config = {
            'check_config': True,
            'check_keys': True,
            'check_auth': True,
            'check_connections': True,
            'check_bruteforce': True,
            'check_tunnels': True,
            'check_key_usage': True,
            'ssh_config_path': '/etc/ssh/sshd_config',
            'auth_log_paths': ['/var/log/auth.log'],
            'ssh_key_paths': ['/etc/ssh', '/root/.ssh'],
            'bf_time_window': 300,
            'bf_attempt_threshold': 5
        }
        
        # Create a temporary directory for baselines
        self.temp_dir = tempfile.TemporaryDirectory()
        self.baseline_file = os.path.join(self.temp_dir.name, 'ssh.json')
        self.config['baseline_file'] = self.baseline_file
        
        # Initialize analyzer
        self.analyzer = SSHAnalyzer(self.config)
    
    def tearDown(self):
        """Clean up after tests"""
        self.temp_dir.cleanup()
    
    @patch('subprocess.check_output')
    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open, read_data="PermitRootLogin yes\nPasswordAuthentication yes\n")
    def test_check_ssh_config(self, mock_file, mock_exists, mock_subprocess):
        """Test SSH config checking for insecure settings"""
        # Setup mocks
        mock_exists.return_value = True
        mock_subprocess.return_value = "2048 SHA256:abcdef user@host (RSA)"
        
        # Run test
        result = self.analyzer._check_ssh_config()
        
        # Verify results
        self.assertTrue(result['is_anomalous'])
        self.assertGreater(result['count'], 0)
        
        # Verify insecure settings were detected
        found_root_login = False
        found_password_auth = False
        
        for issue in result['issues']:
            if issue['setting'] == 'PermitRootLogin' and issue['value'] == 'yes':
                found_root_login = True
            if issue['setting'] == 'PasswordAuthentication' and issue['value'] == 'yes':
                found_password_auth = True
        
        self.assertTrue(found_root_login, "Should detect PermitRootLogin yes as insecure")
        self.assertTrue(found_password_auth, "Should detect PasswordAuthentication yes as insecure")
    
    @patch('subprocess.check_output')
    @patch('os.path.exists')
    @patch('os.stat')
    @patch('os.walk')
    @patch('builtins.open', new_callable=mock_open)
    def test_check_ssh_keys(self, mock_file, mock_walk, mock_stat, mock_exists, mock_subprocess):
        """Test SSH key security checking"""
        # Setup mocks
        mock_exists.return_value = True
        mock_walk.return_value = [
            ('/root/.ssh', [], ['id_rsa', 'id_rsa.pub', 'authorized_keys'])
        ]
        
        # Mock stat to return insecure permissions (0644) for private key
        mock_stat_instance = MagicMock()
        mock_stat_instance.st_mode = 0o644  # World-readable
        mock_stat_instance.st_uid = 0       # root user
        mock_stat.return_value = mock_stat_instance
        
        # Mock subprocess for ssh-keygen output
        mock_subprocess.return_value = "2048 SHA256:abcdef user@host (RSA)"
        
        # Run test
        result = self.analyzer._check_ssh_keys()
        
        # Verify results
        self.assertTrue(result['is_anomalous'])
        self.assertGreater(result['count'], 0)
        
        # Verify insecure permissions were detected
        found_insecure_perms = False
        for issue in result['issues']:
            for key_issue in issue.get('issues', []):
                if 'Insecure private key permissions' in key_issue.get('issue', ''):
                    found_insecure_perms = True
        
        self.assertTrue(found_insecure_perms, "Should detect insecure private key permissions")
    
    @patch('subprocess.check_output')
    @patch('os.path.exists')
    def test_check_ssh_auth(self, mock_exists, mock_subprocess):
        """Test SSH authentication log analysis"""
        # Setup mocks
        mock_exists.return_value = True
        
        # Create sample auth log data with failed login attempts
        auth_log_data = [
            "May 5 10:00:00 host sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 49812 ssh2",
            "May 5 10:00:10 host sshd[12346]: Failed password for invalid user admin from 192.168.1.100 port 49813 ssh2",
            "May 5 10:00:20 host sshd[12347]: Failed password for invalid user admin from 192.168.1.100 port 49814 ssh2",
            "May 5 10:00:30 host sshd[12348]: Failed password for invalid user admin from 192.168.1.100 port 49815 ssh2",
            "May 5 10:00:40 host sshd[12349]: Failed password for invalid user admin from 192.168.1.100 port 49816 ssh2",
            "May 5 10:01:00 host sshd[12350]: Accepted password for user from 192.168.1.100 port 49817 ssh2",
            "May 5 10:02:00 host sshd[12351]: Invalid user test from 192.168.1.101 port 50001 ssh2"
        ]
        
        mock_subprocess.return_value = "\n".join(auth_log_data)
        
        # Run test
        result = self.analyzer._check_ssh_auth()
        
        # Verify results
        self.assertTrue(result['is_anomalous'])
        
        # Verify failed attempts were detected
        failed_attempts_found = False
        for attempt in result.get('recent_failed_attempts', []):
            if attempt.get('username') == 'admin' and attempt.get('count') >= 5:
                failed_attempts_found = True
        
        self.assertTrue(failed_attempts_found, "Should detect multiple failed login attempts")
        
        # Verify suspicious login was detected
        suspicious_login_found = False
        for login in result.get('suspicious_logins', []):
            if login.get('username') == 'user' and '192.168.1.100' in login.get('source_ip', ''):
                suspicious_login_found = True
        
        self.assertTrue(suspicious_login_found, "Should detect successful login after failed attempts")
    
    @patch('subprocess.check_output')
    def test_check_bruteforce(self, mock_subprocess):
        """Test brute force detection"""
        # Setup mocks
        
        # Create sample auth log data with failed login attempts
        auth_log_data = "\n".join([
            "May 5 10:00:00 host sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 49812 ssh2",
            "May 5 10:00:10 host sshd[12346]: Failed password for invalid user admin from 192.168.1.100 port 49813 ssh2",
            "May 5 10:00:20 host sshd[12347]: Failed password for invalid user admin from 192.168.1.100 port 49814 ssh2",
            "May 5 10:00:30 host sshd[12348]: Failed password for invalid user root from 192.168.1.100 port 49815 ssh2",
            "May 5 10:00:40 host sshd[12349]: Failed password for invalid user admin from 192.168.1.100 port 49816 ssh2",
            "May 5 10:00:50 host sshd[12350]: Failed password for invalid user test from 192.168.1.100 port 49817 ssh2"
        ])
        
        mock_subprocess.return_value = auth_log_data
        
        # Run test
        result = self.analyzer._check_bruteforce()
        
        # Verify results
        self.assertTrue(result['is_anomalous'])
        self.assertGreater(result['count'], 0)
        
        # Verify bruteforce attempt was detected
        found_bruteforce = False
        for attempt in result.get('bruteforce_attempts', []):
            if attempt.get('source_ip') == '192.168.1.100' and attempt.get('attempt_count') >= 5:
                found_bruteforce = True
        
        self.assertTrue(found_bruteforce, "Should detect brute force attack from IP")
    
    @patch('subprocess.check_output')
    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open)
    def test_establish_baseline(self, mock_file, mock_exists, mock_subprocess):
        """Test establishing baseline"""
        # Setup mocks
        mock_exists.return_value = True
        mock_subprocess.return_value = "PermitRootLogin no\nPasswordAuthentication no\n"
        
        # Run test
        baseline = self.analyzer.establish_baseline()
        
        # Verify baseline was created
        self.assertIsNotNone(baseline)
        self.assertIn('ssh_config', baseline)
        self.assertIn('ssh_keys', baseline)
        self.assertIn('ssh_users', baseline)
        
        # Verify baseline file was created
        mock_file.assert_called()
    
    @patch('subprocess.check_output')
    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open, read_data=json.dumps({
        'timestamp': datetime.now().isoformat(),
        'ssh_config': {
            'settings': {
                'PermitRootLogin': 'no',
                'PasswordAuthentication': 'no'
            }
        },
        'ssh_keys': [],
        'ssh_users': []
    }))
    def test_compare_baseline(self, mock_file, mock_exists, mock_subprocess):
        """Test comparing against baseline"""
        # Setup mocks
        mock_exists.return_value = True
        
        # Mock that the config has changed
        mock_subprocess.return_value = "PermitRootLogin yes\nPasswordAuthentication no\n"
        
        # Run test
        result = self.analyzer.compare_baseline()
        
        # Verify results
        self.assertTrue(result['is_anomalous'])
        
        # Verify config change was detected
        found_config_change = False
        for change in result.get('config_changes', {}).get('changed_settings', []):
            if change.get('setting') == 'PermitRootLogin' and change.get('new_value') == 'yes':
                found_config_change = True
                self.assertTrue(change.get('security_critical', False), 
                               "PermitRootLogin change should be marked as security critical")
        
        self.assertTrue(found_config_change, "Should detect PermitRootLogin changed from no to yes")
    
    @patch('subprocess.check_output')
    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open, read_data="AllowTcpForwarding yes\nGatewayPorts yes\n")
    def test_check_ssh_tunnels(self, mock_file, mock_exists, mock_subprocess):
        """Test SSH tunneling and port forwarding detection"""
        # Setup mocks
        mock_exists.return_value = True
        
        # Create sample netstat output showing SSH port forwards
        netstat_output = "\n".join([
            "tcp        0      0 0.0.0.0:3306          0.0.0.0:*               LISTEN      1000/ssh",
            "tcp        0      0 0.0.0.0:8080          0.0.0.0:*               LISTEN      1001/ssh",
            "tcp        0      0 192.168.1.10:22       203.0.113.10:40001      ESTABLISHED 1002/sshd",
            "tcp        0      0 192.168.1.10:22       192.168.1.20:55123      ESTABLISHED 1003/sshd"
        ])
        
        # Create sample process output showing SSH tunnels
        ps_output = "\n".join([
            "1000 ssh -L 0.0.0.0:3306:localhost:3306 user@remote-server",
            "1001 ssh -D 8080 -N user@proxy-server",
            "1002 ssh -R 9000:localhost:80 admin@client",
            "1050 grep ssh"
        ])
        
        # Set up mock to return different outputs based on command
        def mock_command_output(cmd, **kwargs):
            cmd_str = " ".join(cmd)
            if "netstat" in cmd_str:
                return netstat_output
            elif "ps" in cmd_str and "pid" not in cmd_str:
                return ps_output
            elif "ps" in cmd_str and "-o user=" in cmd_str:
                return "user"
            return ""
        
        mock_subprocess.side_effect = mock_command_output
        
        # Run test
        result = self.analyzer._check_ssh_tunnels()
        
        # Verify results
        self.assertTrue(result['is_anomalous'])
        self.assertGreater(result['port_forwards_count'], 0)
        self.assertGreater(result['tunnels_count'], 0)
        
        # Verify sensitive port forwards are detected
        found_mysql_forward = False
        for forward in result['port_forwards']:
            if forward.get('local_port') == '3306' and forward.get('exposed_to_all'):
                found_mysql_forward = True
                self.assertEqual(forward.get('severity'), 'high', 
                               "MySQL forwarding should be high severity")
        
        self.assertTrue(found_mysql_forward, "Should detect MySQL port forwarding")
        
        # Verify tunnel types are correctly identified
        found_dynamic_tunnel = False
        found_remote_tunnel = False
        for tunnel in result['findings']:
            if tunnel.get('tunnel_type') == 'dynamic (SOCKS)':
                found_dynamic_tunnel = True
            if tunnel.get('tunnel_type') == 'remote':
                found_remote_tunnel = True
                self.assertEqual(tunnel.get('severity'), 'high',
                               "Remote tunnels should be high severity")
        
        self.assertTrue(found_dynamic_tunnel, "Should detect dynamic (SOCKS) tunnel")
        self.assertTrue(found_remote_tunnel, "Should detect remote tunnel")
        
        # Verify permissive config settings are detected
        found_gateway_ports = False
        for finding in result['findings']:
            if 'config' in finding and finding['config'] == 'GatewayPorts yes':
                found_gateway_ports = True
                self.assertEqual(finding.get('severity'), 'high',
                               "GatewayPorts yes should be high severity")
        
        self.assertTrue(found_gateway_ports, "Should detect permissive GatewayPorts setting")
    
    @patch('subprocess.check_output')
    @patch('os.path.exists')
    def test_check_ssh_key_usage(self, mock_exists, mock_subprocess):
        """Test SSH key usage pattern analysis"""
        # Setup mocks
        mock_exists.return_value = True
        
        # Create sample auth log with key authentication
        key_auth_logs = "\n".join([
            "May 5 10:00:00 host sshd[1234]: Accepted publickey for admin from 192.168.1.100 port 49812 ssh2: RSA SHA256:abc123",
            "May 5 11:00:00 host sshd[1235]: Accepted publickey for admin from 192.168.1.101 port 49813 ssh2: RSA SHA256:abc123",
            "May 5 12:00:00 host sshd[1236]: Accepted publickey for admin from 192.168.1.102 port 49814 ssh2: RSA SHA256:abc123",
            "May 5 13:00:00 host sshd[1237]: Accepted publickey for admin from 192.168.1.103 port 49815 ssh2: RSA SHA256:abc123",
            "May 5 14:00:00 host sshd[1238]: Accepted publickey for admin from 192.168.1.104 port 49816 ssh2: RSA SHA256:abc123",
            "May 5 15:00:00 host sshd[1239]: Accepted publickey for admin from 192.168.1.105 port 49817 ssh2: RSA SHA256:abc123",
            "May 5 00:00:00 host sshd[1240]: Accepted publickey for backup from 192.168.1.200 port 50000 ssh2: RSA SHA256:def456",
            "May 5 01:00:00 host sshd[1241]: Accepted publickey for backup from 192.168.1.200 port 50001 ssh2: RSA SHA256:def456",
            "May 5 02:00:00 host sshd[1242]: Accepted publickey for backup from 192.168.1.200 port 50002 ssh2: RSA SHA256:def456",
            "May 5 03:00:00 host sshd[1243]: Accepted publickey for root from 192.168.1.250 port 51000 ssh2: ssh-dss SHA256:ghi789"
        ])
        
        # Create sample cron file with SSH key
        cron_file_content = "0 0 * * * root ssh -i /root/.ssh/backup_key backup@server"
        
        # Set up mock to return different outputs based on command
        def mock_command_output(cmd, **kwargs):
            cmd_str = " ".join(cmd)
            if "publickey" in cmd_str:
                return key_auth_logs
            elif "cat" in cmd_str or "read" in cmd_str:
                return cron_file_content
            return ""
        
        mock_subprocess.side_effect = mock_command_output
        
        # Set up mock for open to read cron file
        with patch('builtins.open', mock_open(read_data=cron_file_content)):
            # Run test
            result = self.analyzer._check_ssh_key_usage()
        
        # Verify results
        self.assertTrue(result['is_anomalous'])
        self.assertGreater(result['key_auth_count'], 0)
        
        # Verify suspicious patterns are detected
        found_multiple_sources = False
        found_weak_key = False
        
        for pattern in result['suspicious_patterns']:
            if pattern.get('pattern') == 'Multiple source IPs for single user with key authentication':
                found_multiple_sources = True
                self.assertEqual(pattern.get('username'), 'admin',
                               "User with multiple sources should be admin")
                self.assertGreaterEqual(pattern.get('source_count', 0), 6,
                                    "Admin should have at least 6 source IPs")
            
            if pattern.get('pattern') == 'Use of weak key type':
                found_weak_key = True
                self.assertEqual(pattern.get('key_type'), 'ssh-dss',
                               "Should detect ssh-dss as weak key type")
        
        self.assertTrue(found_multiple_sources, "Should detect multiple source IPs for a single user")
        self.assertTrue(found_weak_key, "Should detect use of weak key types")
        
        # Verify statistics are being generated
        self.assertIn('statistics', result)
        self.assertIn('users_count', result['statistics'])
        self.assertIn('top_users', result['statistics'])
        
        # Verify automation detection
        with patch('os.path.exists') as mock_path_exists:
            with patch('os.path.isdir') as mock_is_dir:
                with patch('os.walk') as mock_os_walk:
                    # Setup mocks for cron check
                    mock_path_exists.return_value = True
                    mock_is_dir.return_value = True
                    mock_os_walk.return_value = [('/etc/cron.d', [], ['backup'])]
                    
                    # Test cron key usage detection
                    cron_findings = self.analyzer._check_cron_key_usage()
                    
                    self.assertGreater(len(cron_findings), 0,
                                     "Should detect SSH keys used in cron jobs")
                    self.assertEqual(cron_findings[0]['finding'], 'SSH key used in cron job',
                                   "Should correctly identify SSH key usage in cron")
    
    @patch('time.time')
    def test_performance_metrics(self, mock_time):
        """Test performance metrics in analyze method"""
        # Setup time mock to simulate elapsed time
        mock_time.side_effect = [1000, 1005]  # 5 seconds elapsed
        
        # Mock all the check methods to return simple results
        with patch.object(self.analyzer, '_check_ssh_config', return_value={'is_anomalous': False}):
            with patch.object(self.analyzer, '_check_ssh_keys', return_value={'is_anomalous': False}):
                with patch.object(self.analyzer, '_check_ssh_auth', return_value={'is_anomalous': False}):
                    with patch.object(self.analyzer, '_check_ssh_connections', return_value={'is_anomalous': False}):
                        with patch.object(self.analyzer, '_check_bruteforce', return_value={'is_anomalous': False}):
                            with patch.object(self.analyzer, '_check_ssh_tunnels', return_value={'is_anomalous': False}):
                                with patch.object(self.analyzer, '_check_ssh_key_usage', return_value={'is_anomalous': False}):
                                    # Run the analyze method
                                    result = self.analyzer.analyze()
        
        # Verify performance metrics
        self.assertIn('performance', result)
        self.assertEqual(result['performance']['elapsed_time'], 5)
        self.assertEqual(result['performance']['checks_performed'], 7)
    
    def test_parse_tunnel_spec(self):
        """Test parsing of SSH tunnel specifications"""
        # Test local tunnel parsing
        local_spec = self.analyzer._parse_tunnel_spec("ssh -L 8080:localhost:80 user@host", "local")
        self.assertIsNotNone(local_spec)
        self.assertEqual(local_spec['bind_port'], '8080')
        self.assertEqual(local_spec['target_host'], 'localhost')
        self.assertEqual(local_spec['target_port'], '80')
        
        # Test local tunnel with explicit bind address
        local_bind_spec = self.analyzer._parse_tunnel_spec("ssh -L 0.0.0.0:8080:localhost:80 user@host", "local")
        self.assertIsNotNone(local_bind_spec)
        self.assertEqual(local_bind_spec['bind_address'], '0.0.0.0')
        self.assertEqual(local_bind_spec['bind_port'], '8080')
        
        # Test remote tunnel parsing
        remote_spec = self.analyzer._parse_tunnel_spec("ssh -R 8080:localhost:80 user@host", "remote")
        self.assertIsNotNone(remote_spec)
        self.assertEqual(remote_spec['bind_port'], '8080')
        self.assertEqual(remote_spec['target_port'], '80')
        
        # Test dynamic (SOCKS) tunnel parsing
        dynamic_spec = self.analyzer._parse_tunnel_spec("ssh -D 1080 user@host", "dynamic")
        self.assertIsNotNone(dynamic_spec)
        self.assertEqual(dynamic_spec['bind_port'], '1080')
        self.assertEqual(dynamic_spec['bind_address'], '127.0.0.1')  # Default
        
        # Test with explicit bind address for dynamic
        dynamic_bind_spec = self.analyzer._parse_tunnel_spec("ssh -D 0.0.0.0:1080 user@host", "dynamic")
        self.assertIsNotNone(dynamic_bind_spec)
        self.assertEqual(dynamic_bind_spec['bind_address'], '0.0.0.0')
        self.assertEqual(dynamic_bind_spec['bind_port'], '1080')

if __name__ == '__main__':
    unittest.main()