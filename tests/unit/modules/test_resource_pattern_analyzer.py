#!/usr/bin/env python3
"""
Unit tests for ResourcePatternAnalyzer in system_resources.py
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock
import numpy as np
import time
from collections import deque

# Add src directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../src')))

from modules.system_resources import ResourcePatternAnalyzer

class TestResourcePatternAnalyzer(unittest.TestCase):
    """Tests for the ResourcePatternAnalyzer class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.config = {
            'history_length': 5,
            'enable_ml': True,
            'models_dir': '/tmp/models',
            'detection_threshold': 0.7
        }
        
        # Mock the ML model manager
        with patch('modules.system_resources.MLModelManager') as mock_ml_manager_class:
            self.mock_ml_manager = mock_ml_manager_class.return_value
            self.mock_ml_manager.load_model.return_value = None  # No models loaded initially
            
            self.analyzer = ResourcePatternAnalyzer(self.config)
    
    def test_init_with_config(self):
        """Test initialization with configuration"""
        self.assertEqual(self.analyzer.history_length, 5)
        self.assertEqual(self.analyzer.enable_ml, True)
        self.assertEqual(self.analyzer.models_dir, '/tmp/models')
        self.assertEqual(self.analyzer.detection_threshold, 0.7)
        
        # Check history deques were initialized
        self.assertEqual(len(self.analyzer.history['cpu']), 0)
        self.assertEqual(len(self.analyzer.history['memory']), 0)
        self.assertEqual(len(self.analyzer.history['disk']), 0)
        self.assertEqual(len(self.analyzer.history['timestamps']), 0)
    
    def test_add_sample(self):
        """Test adding a resource sample to history"""
        # Create sample data
        sample_data = {
            'cpu': {
                'total_cpu_usage': 50.0,
                'top_processes': [{'cpu_percent': 80.0}, {'cpu_percent': 30.0}],
                'anomalous_processes': [],
                'hidden_processes': [],
                'load_averages': [1.0, 1.5, 2.0],
                'cpu_stats': {'percentages': {'iowait': 5.0, 'system': 20.0, 'user': 30.0}}
            },
            'memory': {
                'memory_usage_percent': 60.0,
                'swap_usage_percent': 20.0,
                'top_processes': [{'mem_percent': 30.0}, {'mem_percent': 10.0}],
                'anomalous_processes': [],
                'memory_details': {
                    'cached': 1000,
                    'free': 2000,
                    'anon_pages': 3000,
                    'slab': 500,
                    'fragmentation_index': 2.0
                }
            },
            'disk': {
                'filesystems': [
                    {'use_percent': 70},
                    {'use_percent': 50}
                ],
                'anomalous_filesystems': [],
                'suspicious_directories': [],
                'hidden_files': [],
                'large_files': [],
                'disk_growth': {'is_suspicious': False},
                'permission_issues': [],
                'recently_modified_config': []
            }
        }
        
        # Add the sample
        result = self.analyzer.add_sample(sample_data)
        
        # Verify it was added successfully
        self.assertTrue(result)
        self.assertEqual(len(self.analyzer.history['cpu']), 1)
        self.assertEqual(len(self.analyzer.history['memory']), 1)
        self.assertEqual(len(self.analyzer.history['disk']), 1)
        self.assertEqual(len(self.analyzer.history['timestamps']), 1)
        
        # Verify extracted features
        self.assertEqual(self.analyzer.history['cpu'][0]['total_usage'], 50.0)
        self.assertEqual(self.analyzer.history['cpu'][0]['high_process_count'], 1)  # One process > 70%
        self.assertEqual(self.analyzer.history['memory'][0]['usage_percent'], 60.0)
        self.assertEqual(self.analyzer.history['disk'][0]['avg_usage_percent'], 60.0)  # Average of 70 and 50
    
    def test_analyze_patterns_insufficient_history(self):
        """Test pattern analysis with insufficient history"""
        # No samples added yet
        results = self.analyzer.analyze_patterns()
        
        # Should indicate insufficient history
        self.assertFalse(results['has_sufficient_history'])
        self.assertFalse(results['is_anomalous'])
        self.assertEqual(len(results['cpu_anomalies']), 0)
    
    def test_extract_cpu_features(self):
        """Test CPU feature extraction"""
        cpu_data = {
            'total_cpu_usage': 75.0,
            'top_processes': [
                {'cpu_percent': 80.0},
                {'cpu_percent': 60.0},
                {'cpu_percent': 40.0}
            ],
            'anomalous_processes': [{'pid': '123'}],
            'hidden_processes': [{'pid': '456'}],
            'load_averages': [2.5, 2.0, 1.5],
            'cpu_stats': {
                'percentages': {
                    'iowait': 10.0,
                    'system': 25.0,
                    'user': 40.0
                }
            }
        }
        
        features = self.analyzer._extract_cpu_features(cpu_data)
        
        # Check extracted features
        self.assertEqual(features['total_usage'], 75.0)
        self.assertEqual(features['high_process_count'], 2)  # Two processes > 70%
        self.assertEqual(features['anomalous_process_count'], 1)
        self.assertEqual(features['hidden_process_count'], 1)
        self.assertEqual(features['load_avg'], 2.5)
        self.assertEqual(features['io_wait'], 10.0)
        self.assertEqual(features['system_cpu'], 25.0)
        self.assertEqual(features['user_cpu'], 40.0)
    
    def test_analyze_cpu_patterns_without_model(self):
        """Test CPU pattern analysis without ML model"""
        # Setup history with anomalous pattern (CPU spike)
        self.analyzer.history['cpu'] = deque([
            {
                'total_usage': 30.0,
                'high_process_count': 0,
                'anomalous_process_count': 0,
                'hidden_process_count': 0,
                'load_avg': 1.0,
                'io_wait': 5.0,
                'system_cpu': 10.0,
                'user_cpu': 20.0
            },
            {
                'total_usage': 35.0,
                'high_process_count': 0,
                'anomalous_process_count': 0,
                'hidden_process_count': 0,
                'load_avg': 1.2,
                'io_wait': 6.0,
                'system_cpu': 12.0,
                'user_cpu': 23.0
            },
            {
                'total_usage': 85.0,  # Sudden spike
                'high_process_count': 1,
                'anomalous_process_count': 0,
                'hidden_process_count': 0,
                'load_avg': 3.0,
                'io_wait': 30.0,  # I/O wait spike
                'system_cpu': 50.0,  # High system CPU
                'user_cpu': 20.0
            }
        ], maxlen=5)
        
        # Add timestamps
        now = time.time()
        self.analyzer.history['timestamps'] = deque([
            now - 600,
            now - 300,
            now
        ], maxlen=5)
        
        # Run analysis
        anomalies = self.analyzer._analyze_cpu_patterns()
        
        # Verify anomalies were detected
        self.assertGreaterEqual(len(anomalies), 3)
        
        # Check for specific anomaly types
        anomaly_types = [a['type'] for a in anomalies]
        self.assertIn('cpu_spike', anomaly_types)
        self.assertIn('high_system_cpu', anomaly_types)
        self.assertIn('io_wait_spike', anomaly_types)
    
    @patch('sklearn.ensemble.IsolationForest')
    def test_train_models(self, mock_isolation_forest):
        """Test training ML models"""
        # Mock isolation forest instance
        mock_model = MagicMock()
        mock_isolation_forest.return_value = mock_model
        
        # Add sufficient history data (10 samples)
        for i in range(10):
            sample_data = {
                'cpu': {
                    'total_cpu_usage': 30.0 + i * 5,
                    'top_processes': [{'cpu_percent': 20.0 + i * 2}],
                    'anomalous_processes': [],
                    'hidden_processes': [],
                    'load_averages': [1.0, 1.5, 2.0],
                    'cpu_stats': {'percentages': {'iowait': 5.0, 'system': 10.0, 'user': 15.0}}
                },
                'memory': {
                    'memory_usage_percent': 40.0 + i * 2,
                    'swap_usage_percent': 10.0 + i,
                    'top_processes': [{'mem_percent': 15.0 + i}],
                    'anomalous_processes': [],
                    'memory_details': {
                        'cached': 1000,
                        'free': 2000 - i * 100,
                        'anon_pages': 3000 + i * 100,
                        'slab': 500,
                        'fragmentation_index': 1.0 + i * 0.1
                    }
                },
                'disk': {
                    'filesystems': [
                        {'use_percent': 50 + i},
                        {'use_percent': 40 + i}
                    ],
                    'anomalous_filesystems': [],
                    'suspicious_directories': [],
                    'hidden_files': [],
                    'large_files': [],
                    'disk_growth': {'is_suspicious': False},
                    'permission_issues': [],
                    'recently_modified_config': []
                }
            }
            self.analyzer.add_sample(sample_data)
        
        # Train the models
        result = self.analyzer.train_models()
        
        # Verify success
        self.assertTrue(result)
        
        # Verify models were created and saved
        self.assertEqual(mock_isolation_forest.call_count, 3)  # Three models created
        self.assertEqual(self.analyzer.ml_manager.save_model.call_count, 3)
        
        # Verify model references were updated
        self.assertEqual(self.analyzer.cpu_model, mock_model)
        self.assertEqual(self.analyzer.memory_model, mock_model)
        self.assertEqual(self.analyzer.disk_model, mock_model)
    
    def test_analyze_cross_resource_correlations(self):
        """Test cross-resource correlation analysis"""
        # Setup history with highly correlated patterns
        now = time.time()
        
        # CPU and memory both increasing in perfect correlation
        cpu_values = [30.0, 50.0, 70.0, 80.0, 90.0]
        memory_values = [20.0, 30.0, 40.0, 45.0, 50.0]
        disk_values = [50.0, 55.0, 60.0, 65.0, 70.0]
        
        self.analyzer.history['cpu'] = deque([
            {'total_usage': cpu, 'io_wait': i * 5} for i, cpu in enumerate(cpu_values)
        ], maxlen=5)
        
        self.analyzer.history['memory'] = deque([
            {'usage_percent': mem} for mem in memory_values
        ], maxlen=5)
        
        self.analyzer.history['disk'] = deque([
            {'avg_usage_percent': disk} for disk in disk_values
        ], maxlen=5)
        
        self.analyzer.history['timestamps'] = deque([
            now - 600 * (5-i) for i in range(5)
        ], maxlen=5)
        
        # Run correlation analysis
        anomalies = self.analyzer._analyze_cross_resource_correlations()
        
        # Verify anomalies were detected
        self.assertGreaterEqual(len(anomalies), 1)
        
        # CPU and memory should be highly correlated
        corr_anomaly = next((a for a in anomalies if a['type'] == 'coordinated_resource_usage'), None)
        self.assertIsNotNone(corr_anomaly)
    
    def test_analyze_trends(self):
        """Test resource usage trend analysis"""
        # Setup history with rapidly increasing CPU
        now = time.time()
        
        # CPU rapidly increasing
        cpu_values = [10.0, 30.0, 50.0, 70.0, 90.0]
        memory_values = [20.0, 25.0, 30.0, 35.0, 40.0]
        disk_values = [30.0, 35.0, 40.0, 45.0, 50.0]
        
        self.analyzer.history['cpu'] = deque([
            {'total_usage': cpu} for cpu in cpu_values
        ], maxlen=5)
        
        self.analyzer.history['memory'] = deque([
            {'usage_percent': mem} for mem in memory_values
        ], maxlen=5)
        
        self.analyzer.history['disk'] = deque([
            {'avg_usage_percent': disk} for disk in disk_values
        ], maxlen=5)
        
        self.analyzer.history['timestamps'] = deque([
            now - 600 * (5-i) for i in range(5)
        ], maxlen=5)
        
        # Run trend analysis
        trends = self.analyzer._analyze_trends()
        
        # Verify rapid CPU increase was detected
        self.assertTrue(trends['is_anomalous'])
        self.assertEqual(trends['cpu_trend'], 'rapidly_increasing')
        
        # Verify slopes were calculated
        self.assertGreater(trends['cpu_slope'], 0)
        self.assertGreater(trends['memory_slope'], 0)
        self.assertGreater(trends['disk_slope'], 0)


if __name__ == '__main__':
    unittest.main()