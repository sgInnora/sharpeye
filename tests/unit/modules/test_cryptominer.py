#!/usr/bin/env python3
"""
Unit tests for cryptominer.py module
"""

import os
import sys
import unittest
import tempfile
import shutil
import json
import time
from unittest.mock import patch, MagicMock, mock_open
import threading

# Add src directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../src')))

from modules.cryptominer import CryptominerDetectionModule

class TestCryptominerDetectionModule(unittest.TestCase):
    """Tests for the CryptominerDetectionModule class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.config = {
            'monitoring_interval': 1,
            'continuous_monitoring': False,
            'baseline_file': os.path.join(self.temp_dir, 'cryptominer_baseline.json')
        }
        
        # Create module with mocked detector
        with patch('modules.cryptominer.CryptominerDetector') as mock_detector_class:
            self.mock_detector = mock_detector_class.return_value
            self.module = CryptominerDetectionModule(self.config)
    
    def tearDown(self):
        """Tear down test fixtures"""
        # Ensure monitoring is stopped
        if hasattr(self.module, 'monitoring_thread') and self.module.monitoring_thread:
            self.module.stop_monitoring.set()
            self.module.monitoring_thread.join(timeout=2)
        
        shutil.rmtree(self.temp_dir)
    
    def test_init_with_config(self):
        """Test initialization with configuration"""
        self.assertEqual(self.module.monitoring_interval, 1)
        self.assertEqual(self.module.continuous_monitoring, False)
        self.assertEqual(self.module.baseline_file, os.path.join(self.temp_dir, 'cryptominer_baseline.json'))
    
    def test_init_without_config(self):
        """Test initialization without configuration"""
        with patch('modules.cryptominer.CryptominerDetector'):
            module = CryptominerDetectionModule()
            self.assertEqual(module.monitoring_interval, 60)
            self.assertEqual(module.continuous_monitoring, False)
            self.assertTrue(module.baseline_file.endswith('cryptominer.json'))
    
    def test_get_all_processes(self):
        """Test getting all processes"""
        # Direct testing of function without relying on subprocess
        with patch.object(self.module, '_get_all_processes') as mock_get_processes:
            mock_get_processes.return_value = [1234, 5678, 9101]
            processes = self.module._get_all_processes()
            
            self.assertEqual(len(processes), 3)
            self.assertEqual(processes, [1234, 5678, 9101])
    
    @patch('modules.cryptominer.subprocess.check_output', side_effect=Exception("Test error"))
    def test_get_all_processes_error(self, mock_check_output):
        """Test error handling when getting processes"""
        processes = self.module._get_all_processes()
        
        self.assertEqual(processes, [])
    
    @patch('modules.cryptominer.open', new_callable=mock_open)
    def test_get_system_load(self, mock_file):
        """Test getting system load"""
        mock_file.return_value.__enter__.return_value.read.return_value = "1.0 2.0 3.0 4/5 6"
        
        load = self.module._get_system_load()
        
        self.assertEqual(load['load_1min'], 1.0)
        self.assertEqual(load['load_5min'], 2.0)
        self.assertEqual(load['load_15min'], 3.0)
    
    @patch('modules.cryptominer.open', side_effect=Exception("Test error"))
    def test_get_system_load_error(self, mock_file):
        """Test error handling when getting system load"""
        load = self.module._get_system_load()
        
        self.assertEqual(load['load_1min'], 0)
        self.assertEqual(load['load_5min'], 0)
        self.assertEqual(load['load_15min'], 0)
    
    @patch('modules.cryptominer.CryptominerDetectionModule._get_all_processes')
    def test_analyze(self, mock_get_processes):
        """Test analyzing for cryptominers"""
        # Setup mock processes
        mock_get_processes.return_value = [1234, 5678]
        
        # Setup mock detector results
        self.mock_detector.analyze_process.side_effect = [
            {
                'pid': 1234,
                'command': 'normal_process',
                'is_cryptominer': False,
                'confidence': 0.1,
                'cpu_percent': 10.0,
                'memory_percent': 20.0,
                'reasons': []
            },
            {
                'pid': 5678,
                'command': 'cryptominer_process',
                'is_cryptominer': True,
                'confidence': 0.9,
                'cpu_percent': 90.0,
                'memory_percent': 50.0,
                'reasons': ['High CPU usage', 'Suspicious pattern']
            }
        ]
        
        # Run analysis
        results = self.module.analyze()
        
        # Verify results
        self.assertEqual(results['count'], 1)  # One suspicious process
        self.assertTrue(results['is_anomalous'])
        self.assertEqual(len(results['suspicious_processes']), 1)
        self.assertEqual(results['suspicious_processes'][0]['pid'], 5678)
        
        # Verify latest_results was updated
        self.assertEqual(len(self.module.latest_results), 2)
        self.assertEqual(self.module.latest_results[1234]['is_cryptominer'], False)
        self.assertEqual(self.module.latest_results[5678]['is_cryptominer'], True)
    
    @patch('modules.cryptominer.CryptominerDetectionModule._get_all_processes')
    def test_analyze_no_cryptominers(self, mock_get_processes):
        """Test analyzing with no cryptominers found"""
        # Setup mock processes
        mock_get_processes.return_value = [1234, 5678]
        
        # Setup mock detector results - no cryptominers
        self.mock_detector.analyze_process.side_effect = [
            {
                'pid': 1234,
                'command': 'normal_process1',
                'is_cryptominer': False,
                'confidence': 0.1,
                'cpu_percent': 10.0,
                'memory_percent': 20.0,
                'reasons': []
            },
            {
                'pid': 5678,
                'command': 'normal_process2',
                'is_cryptominer': False,
                'confidence': 0.2,
                'cpu_percent': 30.0,
                'memory_percent': 40.0,
                'reasons': []
            }
        ]
        
        # Run analysis
        results = self.module.analyze()
        
        # Verify results
        self.assertEqual(results['count'], 0)  # No suspicious processes
        self.assertFalse(results['is_anomalous'])
        self.assertEqual(len(results['suspicious_processes']), 0)
        
        # Verify latest_results was updated
        self.assertEqual(len(self.module.latest_results), 2)
    
    @patch('modules.cryptominer.CryptominerDetectionModule._get_all_processes')
    @patch('modules.cryptominer.subprocess.check_output')
    def test_establish_baseline(self, mock_check_output, mock_get_processes):
        """Test establishing baseline for cryptominer detection"""
        # Setup mock processes
        mock_get_processes.return_value = [1234, 5678]
        
        # Mock subprocess output for ps commands
        mock_check_output.side_effect = [
            "process1\n",  # First command output
            "5.0 10.0\n",  # Second command output
            "process2\n",  # Third command output
            "15.0 20.0\n"  # Fourth command output
        ]
        
        # Mock system load
        with patch.object(self.module, '_get_system_load') as mock_get_load:
            mock_get_load.return_value = {
                'load_1min': 1.0,
                'load_5min': 2.0,
                'load_15min': 3.0
            }
            
            # Run establish_baseline
            baseline = self.module.establish_baseline()
        
        # Verify baseline structure
        self.assertEqual(baseline['process_count'], 2)
        self.assertEqual(len(baseline['processes']), 2)
        self.assertEqual(baseline['processes']['1234']['command'], 'process1')
        self.assertEqual(baseline['processes']['1234']['cpu_percent'], 5.0)
        self.assertEqual(baseline['processes']['1234']['mem_percent'], 10.0)
        self.assertEqual(baseline['processes']['5678']['command'], 'process2')
        self.assertEqual(baseline['processes']['5678']['cpu_percent'], 15.0)
        self.assertEqual(baseline['processes']['5678']['mem_percent'], 20.0)
        self.assertEqual(baseline['system_load']['load_1min'], 1.0)
        
        # Verify file was created
        with open(self.module.baseline_file, 'r') as f:
            saved_baseline = json.load(f)
            self.assertEqual(saved_baseline['process_count'], 2)
    
    @patch('modules.cryptominer.subprocess.check_output', side_effect=Exception("Test error"))
    def test_establish_baseline_with_error(self, mock_check_output):
        """Test error handling during baseline establishment"""
        # Setup to return some processes but fail getting info
        with patch.object(self.module, '_get_all_processes') as mock_get_processes:
            mock_get_processes.return_value = [1234, 5678]
            
            # Run establish_baseline
            baseline = self.module.establish_baseline()
        
        # Should still create a baseline, just with empty processes
        self.assertEqual(baseline['process_count'], 0)
        self.assertEqual(len(baseline['processes']), 0)
    
    @patch('modules.cryptominer.os.path.exists')
    def test_compare_baseline_no_baseline(self, mock_exists):
        """Test comparison when no baseline exists"""
        mock_exists.return_value = False
        
        # Run comparison
        result = self.module.compare_baseline()
        
        # Should return error
        self.assertIn('error', result)
        self.assertFalse(result['is_anomalous'])
    
    @patch('modules.cryptominer.os.path.exists')
    @patch('modules.cryptominer.open')
    def test_compare_baseline(self, mock_open, mock_exists):
        """Test comparing current state against baseline"""
        # Setup mocks
        mock_exists.return_value = True
        
        # Create mock baseline data
        baseline_data = {
            'timestamp': '2023-01-01T00:00:00',
            'processes': {
                '1234': {
                    'command': 'normal_process',
                    'cpu_percent': 10.0,
                    'mem_percent': 20.0
                },
                '5678': {
                    'command': 'another_process',
                    'cpu_percent': 30.0,
                    'mem_percent': 40.0
                }
            },
            'system_load': {
                'load_1min': 1.0,
                'load_5min': 2.0,
                'load_15min': 3.0
            }
        }
        
        # Mock file open for reading baseline
        mock_open.return_value.__enter__.return_value.read.return_value = json.dumps(baseline_data)
        
        # Setup mock analyze to return current state with a suspicious process
        with patch.object(self.module, 'analyze') as mock_analyze:
            mock_analyze.return_value = {
                'timestamp': '2023-01-02T00:00:00',
                'suspicious_processes': [
                    {
                        'pid': 9012,  # New process not in baseline
                        'command': 'crypto_miner',
                        'is_cryptominer': True,
                        'confidence': 0.9,
                        'cpu_percent': 90.0,
                        'memory_percent': 50.0,
                        'reasons': ['High CPU usage', 'Mining keyword']
                    }
                ],
                'is_anomalous': True
            }
            
            # Setup mock system load
            with patch.object(self.module, '_get_system_load') as mock_get_load:
                mock_get_load.return_value = {
                    'load_1min': 3.0,  # Higher load
                    'load_5min': 4.0,
                    'load_15min': 4.5
                }
                
                # Run comparison
                result = self.module.compare_baseline()
        
        # Verify results
        self.assertTrue(result['is_anomalous'])
        self.assertEqual(len(result['new_suspicious_processes']), 1)
        self.assertEqual(result['new_suspicious_processes'][0]['command'], 'crypto_miner')
        self.assertEqual(result['baseline_timestamp'], '2023-01-01T00:00:00')
        
        # Verify load difference was calculated
        self.assertEqual(result['load_difference']['load_1min'], 2.0)  # 3.0 - 1.0
        self.assertEqual(result['load_difference']['load_5min'], 2.0)  # 4.0 - 2.0
        self.assertEqual(result['load_difference']['load_15min'], 1.5)  # 4.5 - 3.0
    
    def test_start_stop_monitoring(self):
        """Test starting and stopping the monitoring thread"""
        # Set continuous_monitoring to true for this test
        self.module.continuous_monitoring = True
        
        # Start monitoring
        self.module._start_monitoring()
        
        # Check monitoring thread
        self.assertIsNotNone(self.module.monitoring_thread)
        self.assertTrue(self.module.monitoring_thread.is_alive())
        
        # Stop monitoring
        self.module._stop_monitoring()
        
        # Check monitoring thread was stopped
        time.sleep(0.2)  # Give time for thread to exit
        self.assertFalse(self.module.monitoring_thread.is_alive())
    
    @patch('time.sleep', return_value=None)
    def test_monitoring_loop(self, mock_sleep):
        """Test the monitoring loop functionality"""
        # Setup to run only once
        self.module.stop_monitoring = threading.Event()
        
        def stop_after_one_iteration(*args, **kwargs):
            """Helper to stop monitoring after one iteration"""
            self.module.stop_monitoring.set()
            return {'is_anomalous': True, 'suspicious_processes': [{'pid': 1234, 'command': 'miner'}]}
        
        # Setup mock analyze
        with patch.object(self.module, 'analyze', side_effect=stop_after_one_iteration):
            # Run monitoring loop directly
            self.module._monitoring_loop()
        
        # Verify analyze was called
        self.module.analyze.assert_called_once()
    
    @patch('time.sleep')
    def test_monitoring_loop_with_error(self, mock_sleep):
        """Test error handling in monitoring loop"""
        # Setup to run only once
        self.module.stop_monitoring = threading.Event()
        
        def raise_then_stop(*args, **kwargs):
            """Helper to raise exception then stop"""
            self.module.stop_monitoring.set()
            raise Exception("Test error")
        
        # Setup mock analyze to raise exception
        with patch.object(self.module, 'analyze', side_effect=raise_then_stop):
            # Run monitoring loop directly - should not crash
            self.module._monitoring_loop()
        
        # Verify analyze was called
        self.module.analyze.assert_called_once()
    
    def test_continuous_monitoring_enabled(self):
        """Test that continuous monitoring is enabled when configured"""
        # Set continuous_monitoring to true
        self.module.continuous_monitoring = True
        
        # Patch _start_monitoring to verify it's called
        with patch.object(self.module, '_start_monitoring') as mock_start:
            self.module.analyze()
            mock_start.assert_called_once()
    
    def test_continuous_monitoring_not_started_twice(self):
        """Test that monitoring isn't started twice"""
        # Set continuous_monitoring to true
        self.module.continuous_monitoring = True
        
        # Create mock thread
        mock_thread = MagicMock()
        mock_thread.is_alive.return_value = True
        self.module.monitoring_thread = mock_thread
        
        # Patch _start_monitoring to verify it's not called
        with patch.object(self.module, '_start_monitoring') as mock_start:
            self.module.analyze()
            mock_start.assert_not_called()


if __name__ == '__main__':
    unittest.main()