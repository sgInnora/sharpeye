#!/usr/bin/env python3
"""
Unit tests for the Rootkit Detector module.
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock, mock_open
import tempfile
import json
import sqlite3
from datetime import datetime

# Add src directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../src')))

from modules.rootkit_detector import RootkitDetector


class TestRootkitDetector(unittest.TestCase):
    """Test cases for the Rootkit Detector module"""
    
    def setUp(self):
        """Set up test environment"""
        # Create a temporary database file
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = os.path.join(self.temp_dir.name, 'rootkit_detector_test.db')
        
        # Configure the rootkit detector with test settings
        self.config = {
            'database_path': self.database_path,
            'dkom_detection_enabled': False,  # Disable for tests
            'network_detection_enabled': True,
            'network_scan_timeout': 1,  # Quick timeout for tests
            'thread_count': 2  # Use fewer threads for tests
        }
        
        # Create a test instance
        self.detector = RootkitDetector(self.config)
    
    def tearDown(self):
        """Clean up after tests"""
        self.temp_dir.cleanup()
    
    def test_initialization(self):
        """Test if the module initializes correctly"""
        # Verify that database was created
        self.assertTrue(os.path.exists(self.database_path))
        
        # Check that tables were created
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        # Check rootkit_scans table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='rootkit_scans'")
        self.assertIsNotNone(cursor.fetchone())
        
        # Check detection_results table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='detection_results'")
        self.assertIsNotNone(cursor.fetchone())
        
        # Check baseline_signatures table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='baseline_signatures'")
        self.assertIsNotNone(cursor.fetchone())
        
        conn.close()
    
    @patch('subprocess.run')
    def test_kernel_module_detection(self, mock_run):
        """Test kernel module detection"""
        # Mock subprocess.run to return test data
        mock_process = MagicMock()
        mock_process.stdout = "Module\nrootkitmod  16384  0\n"
        mock_process.returncode = 0
        mock_run.return_value = mock_process
        
        # Mock kernel_analyzer.get_suspicious_modules
        self.detector.kernel_analyzer.get_suspicious_modules = MagicMock(return_value=[
            {
                'name': 'rootkitmod',
                'path': '/lib/modules/rootkitmod.ko',
                'reason': 'Known rootkit',
                'loaded': True
            }
        ])
        
        # Mock kernel_analyzer.get_hidden_modules
        self.detector.kernel_analyzer.get_hidden_modules = MagicMock(return_value=[])
        
        # Run the detection
        result_type, results = self.detector._check_kernel_modules()
        
        # Check results
        self.assertEqual(result_type, 'kernel_module')
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['name'], 'rootkitmod')
        self.assertEqual(results[0]['detection_method'], 'signature_match')
    
    @patch('subprocess.run')
    def test_syscall_hook_detection(self, mock_run):
        """Test syscall hook detection"""
        # Mock kernel_analyzer.get_hooked_syscalls
        self.detector.kernel_analyzer.get_hooked_syscalls = MagicMock(return_value=[
            {
                'name': 'sys_read',
                'address': '0xdeadbeef',
                'module': 'rootkitmod',
                'first_seen': '2023-01-01 12:00:00',
                'last_checked': '2023-01-01 12:30:00'
            }
        ])
        
        # Run the detection
        result_type, results = self.detector._check_syscall_hooks()
        
        # Check results
        self.assertEqual(result_type, 'syscall_hook')
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['name'], 'sys_read')
        self.assertEqual(results[0]['module'], 'rootkitmod')
    
    @patch('os.listdir')
    @patch('subprocess.run')
    def test_hidden_process_detection(self, mock_run, mock_listdir):
        """Test hidden process detection"""
        # Mock os.listdir to return proc directory with PIDs
        mock_listdir.return_value = ['1', '2', '3', '4', '5', 'cpuinfo', 'meminfo']
        
        # Mock subprocess for ps output - missing PID 3
        ps_mock = MagicMock()
        ps_mock.stdout = "PID\n1\n2\n4\n5\n"
        ps_mock.returncode = 0
        
        # Mock subprocess for process name
        comm_mock = mock_open(read_data="hidden_process")
        
        with patch('builtins.open', comm_mock):
            # Configure subprocess mock to return different values based on command
            def subprocess_side_effect(*args, **kwargs):
                if 'ps' in args[0]:
                    return ps_mock
                return MagicMock(returncode=1)  # Default failure for other commands
            
            mock_run.side_effect = subprocess_side_effect
            
            # Run the detection with only ps_proc_comparison method
            self.detector.process_detection_methods = ['ps_proc_comparison']
            result_type, results = self.detector._check_hidden_processes()
            
            # Check results
            self.assertEqual(result_type, 'hidden_process')
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]['pid'], '3')
            self.assertEqual(results[0]['name'], 'hidden_process')
            self.assertEqual(results[0]['detection_method'], 'ps_proc_comparison')
    
    @patch('os.path.exists')
    @patch('subprocess.run')
    def test_hidden_file_detection(self, mock_run, mock_exists):
        """Test hidden file detection"""
        # Mock file existence
        mock_exists.return_value = True
        
        # Mock ls command output
        ls_mock = MagicMock()
        ls_mock.stdout = "total 20\ndrwxr-xr-x 2 root root 4096 Jan 1 12:00 .\ndrwxr-xr-x 20 root root 4096 Jan 1 12:00 ..\n-rwxr-xr-x 1 root root 1234 Jan 1 12:00 file1\n-rwxr-xr-x 1 root root 5678 Jan 1 12:00 file2\n"
        ls_mock.returncode = 0
        
        # Mock find command output - includes an extra file not in ls
        find_mock = MagicMock()
        find_mock.stdout = "/bin/file1\n/bin/file2\n/bin/hidden_file\n"
        find_mock.returncode = 0
        
        # Configure subprocess mock to return different values based on command
        def subprocess_side_effect(*args, **kwargs):
            if 'ls' in args[0]:
                return ls_mock
            elif 'find' in args[0]:
                return find_mock
            return MagicMock(returncode=1)  # Default failure for other commands
        
        mock_run.side_effect = subprocess_side_effect
        
        # Run the detection with only ls_find_comparison method
        self.detector.file_detection_methods = ['ls_find_comparison']
        result_type, results = self.detector._check_hidden_files()
        
        # Check results
        self.assertEqual(result_type, 'hidden_file')
        self.assertTrue(any(r['name'] == 'hidden_file' for r in results))
        self.assertTrue(any(r['detection_method'] == 'ls_find_comparison' for r in results))
    
    @patch('subprocess.run')
    def test_network_backdoor_detection(self, mock_run):
        """Test network backdoor detection"""
        # Mock netstat command output with suspicious port
        netstat_mock = MagicMock()
        netstat_mock.stdout = """
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:31337           0.0.0.0:*               LISTEN      1234/backdoor
tcp        0      0 127.0.0.1:80            0.0.0.0:*               LISTEN      5678/apache2
"""
        netstat_mock.returncode = 0
        
        # Configure subprocess mock to return test data
        mock_run.return_value = netstat_mock
        
        # Add a test backdoor port
        self.detector.backdoor_ports = [31337]
        
        # Run the detection
        result_type, results = self.detector._check_network_backdoors()
        
        # Check results
        self.assertEqual(result_type, 'network_backdoor')
        self.assertTrue(len(results) > 0)
        self.assertTrue(any(r.get('port') == 31337 for r in results))
    
    def test_establish_baseline(self):
        """Test baseline establishment"""
        # Mock analyze method to return test data
        self.detector.analyze = MagicMock(return_value={
            'timestamp': datetime.now().isoformat(),
            'threat_level': 'low',
            'detections': {
                'kernel_module': [],
                'syscall_hook': [],
                'hidden_process': [],
                'hidden_file': [],
                'network_backdoor': [],
                'dkom': []
            },
            'summary': {
                'kernel_module_count': 0,
                'syscall_hook_count': 0,
                'hidden_process_count': 0,
                'hidden_file_count': 0,
                'network_backdoor_count': 0,
                'dkom_count': 0
            }
        })
        
        # Establish baseline
        baseline = self.detector.establish_baseline()
        
        # Check that baseline was created
        self.assertEqual(baseline['threat_level'], 'low')
        self.assertEqual(baseline['summary']['kernel_module_count'], 0)
        
        # Check that it was stored in the database
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM rootkit_scans WHERE summary LIKE '%baseline%'")
        count = cursor.fetchone()[0]
        self.assertEqual(count, 1)
        conn.close()
    
    def test_compare_with_baseline(self):
        """Test baseline comparison"""
        # First, create a test baseline
        baseline_id = self._create_test_baseline()
        
        # Mock _get_latest_baseline to return test data
        self.detector._get_latest_baseline = MagicMock(return_value={
            'id': baseline_id,
            'timestamp': datetime.now().isoformat(),
            'threat_level': 'low',
            'summary': json.dumps({'baseline': True}),
            'details': json.dumps({
                'kernel_module': [],
                'syscall_hook': [],
                'hidden_process': [],
                'hidden_file': [],
                'network_backdoor': [],
                'dkom': []
            })
        })
        
        # Prepare current scan with a new detection
        current_scan = {
            'timestamp': datetime.now().isoformat(),
            'threat_level': 'medium',
            'detections': {
                'kernel_module': [{
                    'name': 'rootkitmod',
                    'path': '/lib/modules/rootkitmod.ko',
                    'detection_method': 'signature_match',
                    'reason': 'Known rootkit',
                    'loaded': True
                }],
                'syscall_hook': [],
                'hidden_process': [],
                'hidden_file': [],
                'network_backdoor': [],
                'dkom': []
            },
            'summary': {
                'kernel_module_count': 1,
                'syscall_hook_count': 0,
                'hidden_process_count': 0,
                'hidden_file_count': 0,
                'network_backdoor_count': 0,
                'dkom_count': 0
            }
        }
        
        # Run comparison
        comparison = self.detector.compare_with_baseline(current_scan)
        
        # Check comparison results
        self.assertTrue(comparison['is_anomalous'])
        self.assertEqual(comparison['new_detections'], 1)
        self.assertEqual(len(comparison['changes']['kernel_module']['new']), 1)
        self.assertEqual(comparison['changes']['kernel_module']['new'][0]['name'], 'rootkitmod')
    
    def test_add_signature(self):
        """Test signature addition"""
        # Add a test signature
        result = self.detector.add_signature(
            'file_signature',
            '/tmp/suspicious_file',
            'Test suspicious file signature',
            'medium',
            'test'
        )
        
        # Check result
        self.assertTrue(result)
        
        # Verify it was added to the database
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM baseline_signatures WHERE signature_value = ?", 
                     ('/tmp/suspicious_file',))
        count = cursor.fetchone()[0]
        self.assertEqual(count, 1)
        conn.close()
        
        # Verify it was loaded into memory
        self.assertIn('/tmp/suspicious_file', self.detector.rootkit_file_signatures)
    
    def test_get_statistics(self):
        """Test statistics retrieval"""
        # Create some test data
        self._create_test_baseline()
        self._create_test_detection()
        
        # Get statistics
        stats = self.detector.get_statistics()
        
        # Check results
        self.assertGreater(stats['total_scans'], 0)
        self.assertGreater(stats['total_detections'], 0)
        self.assertIsNotNone(stats['last_scan'])
    
    def _create_test_baseline(self):
        """Helper to create a test baseline in the database"""
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        INSERT INTO rootkit_scans (timestamp, threat_level, summary, details)
        VALUES (?, ?, ?, ?)
        ''', (
            datetime.now().timestamp(),
            'low',
            json.dumps({'baseline': True, 'summary': {}}),
            json.dumps({})
        ))
        
        baseline_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return baseline_id
    
    def _create_test_detection(self):
        """Helper to create a test detection in the database"""
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        # Create a scan
        cursor.execute('''
        INSERT INTO rootkit_scans (timestamp, threat_level, summary, details)
        VALUES (?, ?, ?, ?)
        ''', (
            datetime.now().timestamp(),
            'medium',
            json.dumps({'summary': {'kernel_module_count': 1}}),
            json.dumps({})
        ))
        
        scan_id = cursor.lastrowid
        
        # Add a detection
        cursor.execute('''
        INSERT INTO detection_results 
        (scan_id, detection_type, threat_level, name, path, details, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            scan_id,
            'kernel_module',
            'critical',
            'rootkitmod',
            '/lib/modules/rootkitmod.ko',
            json.dumps({'reason': 'Test detection'}),
            datetime.now().timestamp()
        ))
        
        conn.commit()
        conn.close()


if __name__ == '__main__':
    unittest.main()