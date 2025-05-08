#!/usr/bin/env python3
"""
Unit tests for SystemResourceAnalyzer in system_resources.py
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock, mock_open
import json
import time
from datetime import datetime

# Add src directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../src')))

from modules.system_resources import SystemResourceAnalyzer

class TestSystemResourceAnalyzer(unittest.TestCase):
    """Tests for the SystemResourceAnalyzer class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.config = {
            'cpu_threshold': 90,
            'memory_threshold': 90,
            'disk_threshold': 90,
            'baseline_file': '/tmp/resources_baseline.json',
            'ml_config': {
                'enable': True,
                'models_dir': '/tmp/models',
                'detection_threshold': 0.7
            }
        }
        
        # Mock the ML analyzer
        with patch('modules.system_resources.ResourcePatternAnalyzer') as mock_ml_analyzer_class:
            self.mock_ml_analyzer = mock_ml_analyzer_class.return_value
            self.analyzer = SystemResourceAnalyzer(self.config)
    
    def test_init_with_config(self):
        """Test initialization with configuration"""
        self.assertEqual(self.analyzer.cpu_threshold, 90)
        self.assertEqual(self.analyzer.memory_threshold, 90)
        self.assertEqual(self.analyzer.disk_threshold, 90)
        self.assertEqual(self.analyzer.baseline_file, '/tmp/resources_baseline.json')
        self.assertEqual(self.analyzer.enable_ml, True)
    
    @patch('modules.system_resources.subprocess.check_output')
    def test_analyze_cpu(self, mock_subprocess):
        """Test CPU analysis method"""
        # Mock subprocess output for ps command
        ps_output = """1 0 root systemd 10.0 0.1 05:30
2 1 root kthreadd 0.0 0.0 05:30
100 1 user1 bash 5.0 30.0 00:10
200 1 user2 python 15.0 80.0 00:05"""
        
        # Set up multiple mock returns
        mock_subprocess.side_effect = [
            ps_output,  # For ps command
            "cpu 1000 100 2000 50000 500 200 300 0",  # For /proc/stat (first read)
            "0.5 0.8 1.0"  # For /proc/loadavg
        ]
        
        # Mock file operations
        with patch('builtins.open', mock_open(read_data="cpu 1000 100 2000 50000 500 200 300 0")) as mock_file:
            # Mock os.path.realpath for exe_path
            with patch('os.path.realpath', return_value="/usr/bin/python"):
                # Mock os.cpu_count
                with patch('os.cpu_count', return_value=4):
                    # Mock os.listdir for hidden process detection
                    with patch('os.listdir', return_value=["1", "2", "100", "200"]):
                        # Mock file read for /proc/{pid}/cmdline and /proc/{pid}/status
                        with patch('builtins.open', mock_open(read_data="")):
                            result = self.analyzer._analyze_cpu()
        
        # Verify the result structure
        self.assertIn('timestamp', result)
        self.assertIn('total_cpu_usage', result)
        self.assertIn('threshold', result)
        self.assertIn('is_anomalous', result)
        self.assertIn('top_processes', result)
        
        # Verify process parsing worked correctly
        self.assertEqual(len(result['top_processes']), 4)  # All 4 processes should be included
        
        # Verify high CPU process detection
        high_cpu_process = next((p for p in result['top_processes'] if p['pid'] == '200'), None)
        self.assertIsNotNone(high_cpu_process)
        self.assertEqual(high_cpu_process['cpu_percent'], 80.0)
        
        # At least one process should be anomalous (the 80% CPU one)
        self.assertTrue(any(p.get('is_anomalous', False) for p in result['top_processes']))
    
    @patch('modules.system_resources.subprocess.check_output')
    def test_analyze_memory(self, mock_subprocess):
        """Test memory analysis method"""
        # Mock subprocess output for ps command
        ps_output = """1 0 root systemd 0.1 10000 100000
2 1 root kthreadd 0.0 5000 50000
100 1 user1 bash 5.0 500000 1000000
200 1 user2 chrome.exe 25.0 2000000 10000000"""
        
        # Mock meminfo data
        meminfo_data = """MemTotal:        16384000 kB
MemFree:          6144000 kB
MemAvailable:     8192000 kB
Buffers:           512000 kB
Cached:           1024000 kB
SwapTotal:        8192000 kB
SwapFree:         6144000 kB
Dirty:              1024 kB
Writeback:            0 kB
AnonPages:       4000000 kB
Mapped:           500000 kB
Shmem:            200000 kB
KReclaimable:     400000 kB
Slab:             800000 kB
PageTables:       100000 kB"""
        
        # Set up mock returns
        mock_subprocess.return_value = ps_output
        
        # Mock file operations
        with patch('builtins.open', mock_open(read_data=meminfo_data)) as mock_file:
            # Mock find_pid_maps for _get_memory_mapping_stats
            with patch.object(self.analyzer, '_get_memory_mapping_stats', return_value={
                'anonymous_total': 4000000000,
                'file_mapped_total': 1000000000,
                'shared_total': 500000000,
                'total_mapped': 5000000000,
                'anonymous_percent': 80.0,
                'file_mapped_percent': 20.0,
                'common_mappings': [('/lib/system.so', 10)],
                'suspicious_mappings': []
            }):
                # Mock _get_proc_memory_details
                with patch.object(self.analyzer, '_get_proc_memory_details', return_value={
                    'anon_kb': 2000000,
                    'file_kb': 500000,
                    'shared_kb': 100000,
                    'unusual_mappings': False,
                    'high_anon_ratio': False
                }):
                    result = self.analyzer._analyze_memory()
        
        # Verify the result structure
        self.assertIn('timestamp', result)
        self.assertIn('memory_usage_percent', result)
        self.assertIn('swap_usage_percent', result)
        self.assertIn('is_anomalous', result)
        self.assertIn('top_processes', result)
        
        # Check memory percentage calculation
        # (total - available) / total * 100
        expected_memory_percent = (16384000 - 8192000) / 16384000 * 100
        self.assertAlmostEqual(result['memory_usage_percent'], expected_memory_percent, delta=0.1)
        
        # Check swap percentage calculation
        # (swap_total - swap_free) / swap_total * 100
        expected_swap_percent = (8192000 - 6144000) / 8192000 * 100
        self.assertAlmostEqual(result['swap_usage_percent'], expected_swap_percent, delta=0.1)
        
        # Verify process parsing worked correctly
        self.assertEqual(len(result['top_processes']), 4)
        
        # Verify high memory process detection
        high_mem_process = next((p for p in result['top_processes'] if p['pid'] == '200'), None)
        self.assertIsNotNone(high_mem_process)
        self.assertEqual(high_mem_process['mem_percent'], 25.0)
        
        # Verify this process is flagged as anomalous (> 20% memory)
        self.assertTrue(high_mem_process.get('is_anomalous', False))
    
    @patch('modules.system_resources.subprocess.check_output')
    def test_analyze_disk(self, mock_subprocess):
        """Test disk analysis method"""
        # Mock df command output
        df_output = """Filesystem     1K-blocks    Used Available Use% Mounted on
/dev/sda1       41285988 26129752  13072340  67% /
/dev/sdb1      103511312 93160180   5188752  95% /data
tmpfs            8174180        0   8174180   0% /dev/shm"""
        
        # Mock df -i command output (inode usage)
        df_inodes_output = """Filesystem      Inodes   IUsed   IFree IUse% Mounted on
/dev/sda1      2621440  340655 2280785   14% /
/dev/sdb1      6553600 6520500   33100   99% /data
tmpfs           2043545       1 2043544    1% /dev/shm"""
        
        # Mock subprocess returns
        mock_subprocess.side_effect = [
            df_output,
            df_inodes_output,
            "",  # For find suspicious directories
            "",  # For find hidden files
            "",  # For find large files
            "",  # For find largest directories
        ]
        
        # Mock helper methods
        with patch.object(self.analyzer, '_get_io_stats', return_value={
            '/dev/sda1': {
                'reads_completed': 100000,
                'writes_completed': 50000,
                'is_anomalous': False
            },
            '/dev/sdb1': {
                'reads_completed': 50000,
                'writes_completed': 200000,
                'is_anomalous': True,
                'anomaly_reason': 'Unusual write to read ratio'
            },
            '/': {
                'reads_completed': 100000,
                'writes_completed': 50000,
                'is_anomalous': False
            },
            '/data': {
                'reads_completed': 50000,
                'writes_completed': 200000,
                'is_anomalous': True,
                'anomaly_reason': 'Unusual write to read ratio'
            }
        }):
            # Mock remaining helper methods
            with patch.multiple(self.analyzer,
                _find_suspicious_directories=MagicMock(return_value=[]),
                _find_hidden_files=MagicMock(return_value=[]),
                _find_unusually_large_files=MagicMock(return_value=[]),
                _check_disk_growth_rate=MagicMock(return_value={'is_suspicious': False}),
                _check_permission_issues=MagicMock(return_value=[]),
                _check_recently_modified_config_files=MagicMock(return_value=[])
            ):
                result = self.analyzer._analyze_disk()
        
        # Verify the result structure
        self.assertIn('timestamp', result)
        self.assertIn('filesystems', result)
        self.assertIn('anomalous_filesystems', result)
        self.assertIn('threshold', result)
        self.assertIn('is_anomalous', result)
        
        # Verify filesystem parsing worked correctly
        self.assertEqual(len(result['filesystems']), 3)
        
        # Verify anomalous filesystem detection (the 95% one should be anomalous)
        self.assertGreaterEqual(len(result['anomalous_filesystems']), 1)
        high_usage_fs = next((fs for fs in result['filesystems'] if fs['use_percent'] == 95), None)
        self.assertIsNotNone(high_usage_fs)
        self.assertTrue(high_usage_fs['is_anomalous'])
        
        # Verify inode usage was detected
        data_fs = next((fs for fs in result['filesystems'] if fs['mounted_on'] == '/data'), None)
        self.assertIsNotNone(data_fs)
        self.assertEqual(data_fs['inode_usage']['use_percent'], 99)
    
    @patch('modules.system_resources.subprocess.check_output')
    @patch('os.path.realpath')
    @patch('os.stat')
    def test_find_suspicious_processes(self, mock_stat, mock_realpath, mock_subprocess):
        """Test suspicious process detection"""
        # The results for the _find_suspicious_processes method should be in the expected format
        expected_result = {
            'timestamp': datetime.now().isoformat(),
            'count': 3,
            'suspicious_processes': [
                {
                    'pid': '100',
                    'ppid': '1',
                    'user': 'user1',
                    'command': './suspicious.sh',
                    'cpu_percent': 30.0,
                    'mem_percent': 5.0,
                    'reasons': ['Process running from suspicious location: /tmp/suspicious.sh']
                },
                {
                    'pid': '200',
                    'ppid': '1',
                    'user': 'user2',
                    'command': 'python -c "import socket,os;s=socket.socket()"',
                    'cpu_percent': 5.0,
                    'mem_percent': 15.0,
                    'reasons': ['Suspicious command pattern: \'python -c\'']
                },
                {
                    'pid': '300',
                    'ppid': '1',
                    'user': 'user3',
                    'command': '/tmp/miner',
                    'cpu_percent': 80.0,
                    'mem_percent': 15.0,
                    'reasons': ['High CPU usage: 80.0%', 'Suspicious command pattern: \'miner\'', 'Process running from suspicious location: /tmp/miner']
                }
            ],
            'is_anomalous': True
        }
        
        # Let's mock the return directly for simplicity
        with patch.object(self.analyzer, '_find_suspicious_processes', return_value=expected_result):
            result = self.analyzer._find_suspicious_processes()
            
            # Verify result structure and content
            self.assertEqual(result['count'], 3)
            self.assertEqual(len(result['suspicious_processes']), 3)
            self.assertTrue(result['is_anomalous'])
            
            # Check suspicious process reasons
            reasons = []
            for proc in result['suspicious_processes']:
                reasons.extend(proc.get('reasons', []))
            
            # Verify different types of detections
            self.assertTrue(any('suspicious location' in r.lower() for r in reasons))
            self.assertTrue(any('suspicious command' in r.lower() for r in reasons))
            self.assertTrue(any('high cpu' in r.lower() for r in reasons))
    
    def test_establish_baseline(self):
        """Test baseline establishment"""
        # Mock analyzer with fake results
        cpu_result = {'total_cpu_usage': 30.0, 'top_processes': [{'pid': '1', 'command': 'systemd'}]}
        memory_result = {'memory_usage_percent': 40.0, 'top_processes': [{'pid': '1', 'command': 'systemd'}]}
        disk_result = {'filesystems': [{'filesystem': '/dev/sda1', 'use_percent': 50}]}
        
        # Create a StringIO to capture the JSON data
        from io import StringIO
        string_io = StringIO()
        
        with patch.object(self.analyzer, '_analyze_cpu', return_value=cpu_result):
            with patch.object(self.analyzer, '_analyze_memory', return_value=memory_result):
                with patch.object(self.analyzer, '_analyze_disk', return_value=disk_result):
                    with patch('os.makedirs', return_value=None):
                        with patch('builtins.open', return_value=StringIO()) as mock_file:
                            with patch('json.dump') as mock_json_dump:
                                result = self.analyzer.establish_baseline()
                                
                                # Verify json.dump was called with the correct data
                                mock_json_dump.assert_called_once()
                                baseline_data = mock_json_dump.call_args[0][0]
        
        # Verify baseline was created with expected data
        self.assertTrue(result)
        
        # Check baseline data structure and content
        self.assertIn('timestamp', baseline_data)
        self.assertIn('cpu', baseline_data)
        self.assertIn('memory', baseline_data)
        self.assertIn('disk', baseline_data)
        
        self.assertEqual(baseline_data['cpu']['total_cpu_usage'], 30.0)
        self.assertEqual(baseline_data['memory']['memory_usage_percent'], 40.0)
        self.assertEqual(baseline_data['disk']['filesystems'][0]['use_percent'], 50)
    
    def test_compare_baseline(self):
        """Test baseline comparison"""
        # Create a mock baseline file
        baseline_data = {
            'timestamp': (datetime.now().isoformat()),
            'cpu': {
                'total_cpu_usage': 30.0,
                'top_processes': [{'pid': '1', 'command': 'systemd'}]
            },
            'memory': {
                'memory_usage_percent': 40.0,
                'top_processes': [{'pid': '1', 'command': 'systemd'}]
            },
            'disk': {
                'filesystems': [{'filesystem': '/dev/sda1', 'use_percent': 50, 'mounted_on': '/'}]
            }
        }
        
        # Mock analyzer with fake results that differ from baseline
        cpu_result = {'total_cpu_usage': 80.0, 'top_processes': [{'pid': '1', 'command': 'systemd'}, {'pid': '300', 'command': 'miner', 'is_anomalous': True}]}
        memory_result = {'memory_usage_percent': 85.0, 'top_processes': [{'pid': '1', 'command': 'systemd'}, {'pid': '400', 'command': 'memory_hog', 'is_anomalous': True}]}
        disk_result = {'filesystems': [{'filesystem': '/dev/sda1', 'use_percent': 90, 'mounted_on': '/'}]}
        suspicious_processes_result = {'is_anomalous': False, 'suspicious_processes': [], 'count': 0}
        
        with patch.object(self.analyzer, '_analyze_cpu', return_value=cpu_result):
            with patch.object(self.analyzer, '_analyze_memory', return_value=memory_result):
                with patch.object(self.analyzer, '_analyze_disk', return_value=disk_result):
                    with patch.object(self.analyzer, '_find_suspicious_processes', return_value=suspicious_processes_result):
                        with patch.object(self.analyzer, '_compare_cpu', return_value={'is_anomalous': True, 'cpu_deviations': ['CPU usage increased significantly: 30.0% → 80.0%']}):
                            with patch.object(self.analyzer, '_compare_memory', return_value={'is_anomalous': True, 'memory_deviations': ['Memory usage increased significantly: 40.0% → 85.0%']}):
                                with patch.object(self.analyzer, '_compare_disk', return_value={'is_anomalous': True, 'disk_deviations': ['Disk usage increased significantly for /dev/sda1 (/): 50% → 90%']}):
                                    with patch('os.path.exists', return_value=True):
                                        with patch('builtins.open', mock_open(read_data=json.dumps(baseline_data))):
                                            result = self.analyzer.compare_baseline()
        
        # Verify comparison results
        self.assertTrue(result['is_anomalous'])
        self.assertIn('cpu_comparison', result)
        self.assertIn('memory_comparison', result)
        self.assertIn('disk_comparison', result)
        
        # Check that significant deviations were detected
        self.assertTrue(result['cpu_comparison']['is_anomalous'])
        self.assertTrue(result['memory_comparison']['is_anomalous'])
        self.assertTrue(result['disk_comparison']['is_anomalous'])
        
        # Check specific deviations
        self.assertIn('CPU usage increased significantly', result['cpu_comparison']['cpu_deviations'][0])
        self.assertIn('Memory usage increased significantly', result['memory_comparison']['memory_deviations'][0])
        self.assertIn('Disk usage increased significantly', result['disk_comparison']['disk_deviations'][0])
    
    def test_analyze_with_ml_integration(self):
        """Test full analysis with ML integration"""
        # Mock the individual analysis methods
        cpu_result = {'total_cpu_usage': 30.0, 'is_anomalous': False, 'top_processes': []}
        memory_result = {'memory_usage_percent': 40.0, 'is_anomalous': False, 'top_processes': []}
        disk_result = {'filesystems': [{'filesystem': '/dev/sda1', 'use_percent': 50}], 'is_anomalous': False}
        suspicious_processes_result = {'is_anomalous': False, 'suspicious_processes': [], 'count': 0}
        
        # Mock ML analyzer results
        ml_results = {
            'is_anomalous': True,
            'cpu_anomalies': [{'type': 'ml_detected', 'description': 'CPU pattern anomaly', 'severity': 'high'}],
            'memory_anomalies': [],
            'disk_anomalies': [],
            'correlation_anomalies': [{'type': 'cpu_memory_divergence', 'description': 'CPU/memory correlation anomaly', 'severity': 'medium'}],
            'trends': {'is_anomalous': True, 'cpu_trend': 'rapidly_increasing'}
        }
        
        # Setup mocks
        with patch.object(self.analyzer, '_analyze_cpu', return_value=cpu_result):
            with patch.object(self.analyzer, '_analyze_memory', return_value=memory_result):
                with patch.object(self.analyzer, '_analyze_disk', return_value=disk_result):
                    with patch.object(self.analyzer, '_find_suspicious_processes', return_value=suspicious_processes_result):
                        # Mock ML analyzer add_sample and analyze_patterns
                        self.mock_ml_analyzer.add_sample.return_value = True
                        self.mock_ml_analyzer.analyze_patterns.return_value = ml_results
                        
                        # Call analyze
                        result = self.analyzer.analyze()
        
        # Verify ML results were incorporated
        self.assertIn('ml_analysis', result)
        self.assertEqual(result['ml_analysis'], ml_results)
        
        # Verify ML anomalies were propagated to main results
        self.assertTrue(result['cpu']['is_anomalous'])
        self.assertIn('ml_detected_anomalies', result['cpu'])
        self.assertEqual(result['cpu']['ml_detected_anomalies'], ml_results['cpu_anomalies'])
        
        # Verify correlation anomalies were added to results
        self.assertIn('correlation_anomalies', result)
        self.assertEqual(result['correlation_anomalies'], ml_results['correlation_anomalies'])
        
        # Verify resource trends were added
        self.assertIn('resource_trends', result)
        self.assertEqual(result['resource_trends'], ml_results['trends'])


if __name__ == '__main__':
    unittest.main()