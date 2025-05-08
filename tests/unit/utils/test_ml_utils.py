#!/usr/bin/env python3
"""
Unit tests for ml_utils.py
"""

import os
import sys
import unittest
import tempfile
import shutil
import pickle
import json
import time
from unittest.mock import patch, MagicMock, mock_open
import numpy as np
from collections import deque

# Add src directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../src')))

from utils.ml_utils import MLModelManager, CPUProfiler, CryptominerDetector

class TestMLModelManager(unittest.TestCase):
    """Tests for the MLModelManager class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.config = {'models_dir': self.temp_dir}
        self.model_manager = MLModelManager(self.config)
        
        # Create a simple model for testing
        self.test_model = {'name': 'test_model', 'version': 1.0}
        self.model_path = os.path.join(self.temp_dir, 'test_model.pkl')
        
        with open(self.model_path, 'wb') as f:
            pickle.dump(self.test_model, f)
    
    def tearDown(self):
        """Tear down test fixtures"""
        shutil.rmtree(self.temp_dir)
    
    def test_init_with_config(self):
        """Test initialization with configuration"""
        manager = MLModelManager(self.config)
        self.assertEqual(manager.models_dir, self.temp_dir)
    
    def test_init_without_config(self):
        """Test initialization without configuration"""
        with patch('os.makedirs'):  # Mock os.makedirs to prevent permission issues
            manager = MLModelManager()
            self.assertEqual(manager.models_dir, '/var/lib/sharpeye/models')
    
    def test_load_model_success(self):
        """Test successful model loading"""
        model = self.model_manager.load_model('test_model')
        self.assertEqual(model, self.test_model)
    
    def test_load_model_nonexistent(self):
        """Test loading a non-existent model"""
        model = self.model_manager.load_model('nonexistent_model')
        self.assertIsNone(model)
    
    def test_load_model_error(self):
        """Test error handling during model loading"""
        with patch('builtins.open', side_effect=Exception("Test error")):
            model = self.model_manager.load_model('test_model')
            self.assertIsNone(model)
    
    def test_save_model_success(self):
        """Test successful model saving"""
        new_model = {'name': 'new_model', 'version': 2.0}
        result = self.model_manager.save_model(new_model, 'new_model')
        self.assertTrue(result)
        
        # Verify model was saved
        saved_model = self.model_manager.load_model('new_model')
        self.assertEqual(saved_model, new_model)
    
    def test_save_model_error(self):
        """Test error handling during model saving"""
        with patch('builtins.open', side_effect=Exception("Test error")):
            result = self.model_manager.save_model({'test': 'data'}, 'error_model')
            self.assertFalse(result)
    
    def test_model_exists(self):
        """Test model existence checking"""
        self.assertTrue(self.model_manager.model_exists('test_model'))
        self.assertFalse(self.model_manager.model_exists('nonexistent_model'))


class TestCPUProfiler(unittest.TestCase):
    """Tests for the CPUProfiler class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.config = {
            'sampling_interval': 1,
            'history_length': 5
        }
        self.profiler = CPUProfiler(self.config)
    
    def test_init_with_config(self):
        """Test initialization with configuration"""
        profiler = CPUProfiler(self.config)
        self.assertEqual(profiler.sampling_interval, 1)
        self.assertEqual(profiler.history_length, 5)
    
    def test_init_without_config(self):
        """Test initialization without configuration"""
        profiler = CPUProfiler()
        self.assertEqual(profiler.sampling_interval, 5)
        self.assertEqual(profiler.history_length, 12)
    
    @patch('subprocess.check_output')
    def test_get_process_features_success(self, mock_check_output):
        """Test successful process feature extraction"""
        # Mock subprocess outputs
        mock_outputs = [
            "5.0 10.0 00:01:30",  # ps -p PID -o %cpu,%mem,time
            "test_command",       # ps -p PID -o command
        ]
        mock_check_output.side_effect = mock_outputs
        
        # Mock /proc/PID/stat file
        with patch('builtins.open', mock_open(read_data="1 (test) S 0 0 0 0 0 0 0 0 0 0 100 200 300 400")):
            # Run the method twice to build history
            features1 = self.profiler.get_process_features(1234)
            
            # Sleep to ensure timestamps are different
            time.sleep(0.1)
            
            # Update mock outputs for second call to show changes
            mock_outputs = [
                "10.0 15.0 00:02:00",  # Increased CPU and time
                "test_command",
            ]
            mock_check_output.side_effect = mock_outputs
            
            features2 = self.profiler.get_process_features(1234)
        
        # First result has minimal features
        self.assertEqual(features1['pid'], 1234)
        self.assertEqual(features1['has_enough_history'], False)
        
        # Second result should have more features
        self.assertEqual(features2['pid'], 1234)
        self.assertEqual(features2['has_enough_history'], True)
        self.assertEqual(features2['command'], 'test_command')
        self.assertEqual(features2['current_cpu'], 10.0)
        self.assertEqual(features2['current_mem'], 15.0)
        
        # Check calculated features
        self.assertIn('mean_cpu', features2)
        self.assertIn('std_cpu', features2)
        self.assertIn('cpu_stability', features2)
        
        # Check that growth rates are calculated
        self.assertIn('cpu_growth_rate', features2)
    
    @patch('subprocess.check_output', side_effect=Exception("Test error"))
    def test_get_process_features_error(self, mock_check_output):
        """Test error handling during process feature extraction"""
        features = self.profiler.get_process_features(1234)
        self.assertIsNone(features)
    
    @patch('subprocess.check_output')
    def test_calculate_features_minimal_history(self, mock_check_output):
        """Test feature calculation with minimal history"""
        # Mock subprocess output
        mock_check_output.return_value = "5.0 10.0 00:01:30\n"
        
        # Get features with minimal history
        features = self.profiler.get_process_features(1234)
        
        # Should have minimal features
        self.assertEqual(features['pid'], 1234)
        self.assertEqual(features['has_enough_history'], False)
    
    @patch('subprocess.check_output')
    def test_calculate_features_with_history(self, mock_check_output):
        """Test feature calculation with sufficient history"""
        # Setup process history manually
        pid = 1234
        self.profiler.process_history[pid] = {
            'cpu_percent': deque([10.0, 20.0, 30.0, 40.0], maxlen=5),
            'mem_percent': deque([5.0, 6.0, 7.0, 8.0], maxlen=5),
            'cpu_time': deque([60, 120, 180, 240], maxlen=5),
            'total_time': deque([100, 200, 300, 400], maxlen=5),
            'timestamps': deque([time.time() - 40, time.time() - 30, 
                               time.time() - 20, time.time() - 10], maxlen=5)
        }
        
        # Call _calculate_features directly
        features = self.profiler._calculate_features(pid)
        
        # Check basic features
        self.assertEqual(features['pid'], pid)
        self.assertEqual(features['has_enough_history'], True)
        self.assertEqual(features['current_cpu'], 40.0)
        self.assertEqual(features['current_mem'], 8.0)
        
        # Check statistical features
        self.assertEqual(features['mean_cpu'], 25.0)
        self.assertAlmostEqual(features['std_cpu'], 12.9099, places=4)  # sqrt((10-25)^2 + (20-25)^2 + (30-25)^2 + (40-25)^2 / 4)
        self.assertEqual(features['min_cpu'], 10.0)
        self.assertEqual(features['max_cpu'], 40.0)
        
        # Check calculated ratios
        self.assertIn('cpu_mem_ratio', features)
        self.assertIn('cpu_growth_rate', features)
        self.assertIn('cpu_time_growth_rate', features)
        self.assertIn('cpu_increase_ratio', features)


class TestCryptominerDetector(unittest.TestCase):
    """Tests for the CryptominerDetector class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.config = {
            'ml_config': {'models_dir': '/tmp/models'},
            'profiler_config': {'sampling_interval': 1, 'history_length': 5},
            'thresholds': {
                'cpu_stability': 0.2,
                'cpu_min': 50.0,
                'cpu_mean': 80.0,
                'cpu_time_growth_rate': 0.5,
                'cpu_autocorrelation': 0.7,
                'cpu_spectral_entropy': 1.5
            },
            'mining_keywords': ['miner', 'xmr', 'monero']
        }
        
        # Create detector with mocked dependencies
        with patch('utils.ml_utils.MLModelManager') as mock_ml_manager, \
             patch('utils.ml_utils.CPUProfiler') as mock_profiler:
            self.mock_ml_manager = mock_ml_manager.return_value
            self.mock_profiler = mock_profiler.return_value
            self.detector = CryptominerDetector(self.config)
    
    def test_init_with_config(self):
        """Test initialization with configuration"""
        self.assertEqual(self.detector.thresholds, self.config['thresholds'])
        self.assertEqual(self.detector.mining_keywords, self.config['mining_keywords'])
    
    def test_init_without_config(self):
        """Test initialization without configuration"""
        with patch('utils.ml_utils.MLModelManager'), \
             patch('utils.ml_utils.CPUProfiler'):
            detector = CryptominerDetector()
            self.assertIsNotNone(detector.thresholds)
            self.assertIsNotNone(detector.mining_keywords)
    
    def test_analyze_process_feature_error(self):
        """Test analyze_process with feature extraction error"""
        pid = 1234
        self.mock_profiler.get_process_features.return_value = None
        
        result = self.detector.analyze_process(pid)
        
        self.assertEqual(result['pid'], pid)
        self.assertFalse(result['is_cryptominer'])
        self.assertEqual(result['confidence'], 0.0)
        self.assertIn('error', result)
    
    def test_analyze_process_insufficient_history(self):
        """Test analyze_process with insufficient history"""
        pid = 1234
        self.mock_profiler.get_process_features.return_value = {
            'pid': pid,
            'has_enough_history': False
        }
        
        result = self.detector.analyze_process(pid)
        
        self.assertEqual(result['pid'], pid)
        self.assertFalse(result['is_cryptominer'])
        self.assertEqual(result['confidence'], 0.0)
        self.assertIn('warning', result)
    
    def test_analyze_process_with_ml_model(self):
        """Test analyze_process with ML model available"""
        pid = 1234
        
        # Setup mock model
        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.2, 0.8]])  # 80% confidence
        self.detector.model = mock_model
        
        # Setup mock features
        mock_features = {
            'pid': pid,
            'has_enough_history': True,
            'command': 'test_process',
            'current_cpu': 90.0,
            'current_mem': 50.0,
            'mean_cpu': 85.0,
            'std_cpu': 5.0,
            'min_cpu': 75.0,
            'max_cpu': 95.0,
            'cpu_stability': 0.06,  # Very stable (suspicious)
            'mean_mem': 45.0,
            'std_mem': 5.0,
            'cpu_mem_ratio': 1.9,
            'cpu_growth_rate': 0.1,
            'cpu_time_growth_rate': 0.6,  # Suspicious
            'cpu_increase_ratio': 0.8,
            'cpu_burstiness': 0.1,
            'cpu_autocorrelation': 0.8,  # Suspicious
            'cpu_spectral_entropy': 1.0   # Suspicious
        }
        self.mock_profiler.get_process_features.return_value = mock_features
        
        # Run analysis
        result = self.detector.analyze_process(pid)
        
        # Check results
        self.assertEqual(result['pid'], pid)
        self.assertTrue(result['is_cryptominer'])
        self.assertEqual(result['confidence'], 0.8)
        self.assertEqual(result['command'], 'test_process')
        self.assertEqual(result['cpu_percent'], 90.0)
        self.assertEqual(result['memory_percent'], 50.0)
    
    def test_analyze_process_rule_based_detection(self):
        """Test analyze_process with rule-based detection"""
        pid = 1234
        
        # No ML model available
        self.detector.model = None
        
        # Setup mock features with suspicious mining patterns
        mock_features = {
            'pid': pid,
            'has_enough_history': True,
            'command': 'xmr_miner --cpu-usage=high',  # Contains mining keywords
            'current_cpu': 90.0,
            'current_mem': 50.0,
            'mean_cpu': 85.0,
            'std_cpu': 5.0,
            'min_cpu': 75.0,
            'max_cpu': 95.0,
            'cpu_stability': 0.06,  # Very stable (suspicious)
            'mean_mem': 45.0,
            'std_mem': 5.0,
            'cpu_mem_ratio': 1.9,
            'cpu_growth_rate': 0.1,
            'cpu_time_growth_rate': 0.6,  # Suspicious
            'cpu_increase_ratio': 0.8,
            'cpu_burstiness': 0.1,
            'cpu_autocorrelation': 0.8,  # Suspicious
            'cpu_spectral_entropy': 1.0   # Suspicious
        }
        self.mock_profiler.get_process_features.return_value = mock_features
        
        # Run analysis
        result = self.detector.analyze_process(pid)
        
        # Check results
        self.assertEqual(result['pid'], pid)
        self.assertTrue(result['is_cryptominer'])
        self.assertGreater(len(result['reasons']), 3)  # Should have multiple reasons
    
    def test_analyze_process_not_miner(self):
        """Test analyze_process with non-mining process"""
        pid = 1234
        
        # No ML model available
        self.detector.model = None
        
        # Setup mock features with normal process behavior
        mock_features = {
            'pid': pid,
            'has_enough_history': True,
            'command': 'normal_process',
            'current_cpu': 30.0,  # Lower CPU
            'current_mem': 20.0,
            'mean_cpu': 25.0,     # Lower average
            'std_cpu': 10.0,      # More variable (less suspicious)
            'min_cpu': 10.0,
            'max_cpu': 40.0,
            'cpu_stability': 0.4,  # Less stable (normal)
            'mean_mem': 15.0,
            'std_mem': 5.0,
            'cpu_mem_ratio': 1.7,
            'cpu_growth_rate': 0.05,
            'cpu_time_growth_rate': 0.3,  # Normal
            'cpu_increase_ratio': 0.5,
            'cpu_burstiness': 0.3,
            'cpu_autocorrelation': 0.4,  # Normal
            'cpu_spectral_entropy': 2.0   # Normal
        }
        self.mock_profiler.get_process_features.return_value = mock_features
        
        # Run analysis
        result = self.detector.analyze_process(pid)
        
        # Check results
        self.assertEqual(result['pid'], pid)
        self.assertFalse(result['is_cryptominer'])
        self.assertEqual(len(result['reasons']), 0)  # No suspicious reasons
    
    def test_extract_feature_vector(self):
        """Test extraction of feature vector for ML"""
        features = {
            'mean_cpu': 85.0,
            'std_cpu': 5.0,
            'min_cpu': 75.0,
            'max_cpu': 95.0,
            'cpu_stability': 0.06,
            'mean_mem': 45.0,
            'std_mem': 5.0,
            'cpu_mem_ratio': 1.9,
            'cpu_growth_rate': 0.1,
            'cpu_time_growth_rate': 0.6,
            'cpu_increase_ratio': 0.8,
            'cpu_burstiness': 0.1,
            'cpu_autocorrelation': 0.8,
            'cpu_spectral_entropy': 1.0
        }
        
        vector = self.detector._extract_feature_vector(features)
        
        # Check vector length and contents
        self.assertEqual(len(vector), 14)  # 14 features expected
        self.assertEqual(vector[0], 85.0)  # First feature is mean_cpu
        self.assertEqual(vector[-1], 1.0)  # Last feature is cpu_spectral_entropy
    
    def test_extract_feature_vector_missing_features(self):
        """Test feature vector extraction with missing features"""
        features = {
            'mean_cpu': 85.0,
            'std_cpu': 5.0,
            # Missing several features
        }
        
        vector = self.detector._extract_feature_vector(features)
        
        # Should still produce a complete vector with defaults for missing values
        self.assertEqual(len(vector), 14)
        self.assertEqual(vector[0], 85.0)  # Existing feature preserved
        self.assertEqual(vector[-1], 0.0)  # Missing feature defaulted to 0.0
    
    def test_rule_based_detection_mining_keywords(self):
        """Test rule-based detection for mining keywords"""
        features = {
            'command': 'xmr_miner --cpu-usage=high',
            'mean_cpu': 50.0,
            'std_cpu': 10.0,
            'min_cpu': 30.0,
            'max_cpu': 70.0,
            'cpu_stability': 0.3  # Not suspicious by itself
        }
        
        is_miner, reasons = self.detector._rule_based_detection(features)
        
        # Should detect based on command containing keywords
        self.assertIn("Command contains mining keyword: 'xmr'", reasons)
        self.assertIn("Command contains mining keyword: 'miner'", reasons)
        self.assertTrue(is_miner)  # Two reasons are enough
    
    def test_rule_based_detection_cpu_patterns(self):
        """Test rule-based detection for CPU usage patterns"""
        features = {
            'command': 'normal_process',  # No keywords
            'mean_cpu': 85.0,  # High CPU (suspicious)
            'std_cpu': 5.0,
            'min_cpu': 75.0,  # High minimum (suspicious)
            'max_cpu': 95.0,
            'cpu_stability': 0.05,  # Very stable (suspicious)
            'cpu_autocorrelation': 0.8,  # High correlation (suspicious)
            'cpu_spectral_entropy': 1.0  # Low entropy (suspicious)
        }
        
        is_miner, reasons = self.detector._rule_based_detection(features)
        
        # Should detect based on CPU patterns
        self.assertIn("Unusually stable CPU usage pattern", reasons[0])
        self.assertIn("Consistently high CPU usage", reasons[1])
        self.assertIn("High average CPU usage", reasons[2])
        self.assertIn("Periodic CPU usage pattern", reasons[3])
        self.assertIn("Low randomness in CPU pattern", reasons[4])
        self.assertTrue(is_miner)  # More than two reasons
    
    def test_rule_based_detection_not_miner(self):
        """Test rule-based detection for non-mining process"""
        features = {
            'command': 'normal_process',  # No keywords
            'mean_cpu': 30.0,  # Normal CPU
            'std_cpu': 10.0,
            'min_cpu': 10.0,
            'max_cpu': 50.0,
            'cpu_stability': 0.4,  # Normal stability
            'cpu_autocorrelation': 0.3,  # Normal correlation
            'cpu_spectral_entropy': 2.0  # Normal entropy
        }
        
        is_miner, reasons = self.detector._rule_based_detection(features)
        
        # Should not detect as miner
        self.assertEqual(len(reasons), 0)
        self.assertFalse(is_miner)


if __name__ == '__main__':
    unittest.main()