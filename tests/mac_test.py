#!/usr/bin/env python3
"""
Mac OS X compatible test runner for SharpEye
This script tests the core functionality of ml_utils.py and cryptominer.py 
without relying on Linux-specific paths and commands.
"""

import os
import sys
import unittest
import coverage
from unittest.mock import patch, MagicMock
import importlib.util

# Add parent directory to path to allow imports
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

# Install development requirements if necessary
try:
    import numpy
    import scipy
except ImportError:
    import subprocess
    print("Installing required packages...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "numpy", "scipy", "coverage"])

# Dynamic import of modules
def import_module_from_path(module_name, file_path):
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

# Import the modules we need to test
ml_utils = import_module_from_path("ml_utils", os.path.join(parent_dir, "src", "utils", "ml_utils.py"))
cryptominer = import_module_from_path("cryptominer", os.path.join(parent_dir, "src", "modules", "cryptominer.py"))

# Get the classes we need
MLModelManager = ml_utils.MLModelManager
CPUProfiler = ml_utils.CPUProfiler
CryptominerDetector = ml_utils.CryptominerDetector
CryptominerDetectionModule = cryptominer.CryptominerDetectionModule

class TestMLModelManager(unittest.TestCase):
    """Tests for MLModelManager class with macOS compatibility"""
    
    def setUp(self):
        """Set up test environment"""
        # Use a temp directory for models rather than /var/lib/sharpeye
        self.test_dir = os.path.join(os.path.dirname(__file__), 'test_models')
        os.makedirs(self.test_dir, exist_ok=True)
        self.config = {'models_dir': self.test_dir}
        self.manager = MLModelManager(self.config)
    
    def tearDown(self):
        """Clean up test environment"""
        # Remove test model files
        for file in os.listdir(self.test_dir):
            if file.endswith('.pkl'):
                os.remove(os.path.join(self.test_dir, file))
    
    def test_model_operations(self):
        """Test model saving, loading and checking"""
        # Test model doesn't exist initially
        self.assertFalse(self.manager.model_exists('test_model'))
        
        # Test saving a model
        test_model = {'name': 'test_model', 'data': [1, 2, 3]}
        result = self.manager.save_model(test_model, 'test_model')
        self.assertTrue(result)
        
        # Test model exists after saving
        self.assertTrue(self.manager.model_exists('test_model'))
        
        # Test loading the model
        loaded_model = self.manager.load_model('test_model')
        self.assertEqual(loaded_model, test_model)

class TestCryptominerDetector(unittest.TestCase):
    """Tests for CryptominerDetector with macOS compatibility"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = os.path.join(os.path.dirname(__file__), 'test_models')
        os.makedirs(self.test_dir, exist_ok=True)
        self.config = {
            'ml_config': {'models_dir': self.test_dir},
            'thresholds': {
                'cpu_stability': 0.2,
                'cpu_min': 50.0,
                'cpu_mean': 80.0,
                'cpu_autocorrelation': 0.7,
                'cpu_spectral_entropy': 1.5
            },
            'mining_keywords': ['miner', 'xmr', 'monero']
        }
        
        # Create detector with mocked profiler
        self.cpu_profiler = MagicMock()
        
        # Create detector and manually inject mocked profiler
        self.detector = CryptominerDetector(self.config)
        self.detector.cpu_profiler = self.cpu_profiler
    
    def test_rule_based_detection(self):
        """Test rule-based detection for mining processes"""
        # Test case 1: Command contains mining keywords
        features = {
            'command': 'xmr_miner --cpu-usage=high',
            'mean_cpu': 50.0,
            'std_cpu': 10.0
        }
        
        is_miner, reasons = self.detector._rule_based_detection(features)
        self.assertTrue(is_miner)
        self.assertTrue(any("mining keyword" in reason for reason in reasons))
        
        # Test case 2: High CPU usage pattern
        features = {
            'command': 'normal_process',  # No keywords
            'mean_cpu': 85.0,             # Above threshold
            'min_cpu': 75.0,              # Above threshold
            'cpu_stability': 0.05,        # Very stable (suspicious)
            'cpu_autocorrelation': 0.8    # High correlation (suspicious)
        }
        
        is_miner, reasons = self.detector._rule_based_detection(features)
        self.assertTrue(is_miner)
        self.assertGreater(len(reasons), 1)
        
        # Test case 3: Normal process (not a miner)
        features = {
            'command': 'normal_process',
            'mean_cpu': 30.0,             # Below threshold
            'min_cpu': 10.0,              # Below threshold
            'cpu_stability': 0.5,         # Less stable (normal)
            'cpu_autocorrelation': 0.3    # Lower correlation (normal)
        }
        
        is_miner, reasons = self.detector._rule_based_detection(features)
        self.assertFalse(is_miner)
        self.assertEqual(len(reasons), 0)
    
    def test_analyze_process(self):
        """Test process analysis with various scenarios"""
        # Test case 1: No features available
        self.cpu_profiler.get_process_features.return_value = None
        result = self.detector.analyze_process(1234)
        self.assertFalse(result['is_cryptominer'])
        self.assertIn('error', result)
        
        # Test case 2: Not enough history
        self.cpu_profiler.get_process_features.return_value = {
            'pid': 1234,
            'has_enough_history': False
        }
        result = self.detector.analyze_process(1234)
        self.assertFalse(result['is_cryptominer'])
        self.assertIn('warning', result)
        
        # Test case 3: Detected cryptominer based on rules
        self.cpu_profiler.get_process_features.return_value = {
            'pid': 5678,
            'has_enough_history': True,
            'command': 'xmr_miner --cpu-usage=high',
            'current_cpu': 90.0,
            'current_mem': 50.0,
            'mean_cpu': 85.0,
            'std_cpu': 5.0,
            'min_cpu': 75.0,
            'max_cpu': 95.0,
            'cpu_stability': 0.06,
            'cpu_autocorrelation': 0.8
        }
        
        # No ML model available
        self.detector.model = None
        
        result = self.detector.analyze_process(5678)
        self.assertTrue(result['is_cryptominer'])
        self.assertGreater(len(result['reasons']), 0)

class TestCryptominerModule(unittest.TestCase):
    """Tests for CryptominerDetectionModule with macOS compatibility"""
    
    def setUp(self):
        """Set up test environment"""
        # Create a test baseline directory
        self.test_dir = os.path.join(os.path.dirname(__file__), 'test_baselines')
        os.makedirs(self.test_dir, exist_ok=True)
        
        self.config = {
            'monitoring_interval': 1,
            'continuous_monitoring': False,
            'baseline_file': os.path.join(self.test_dir, 'test_baseline.json')
        }
        
        # Create module and manually inject mocked detector
        self.mock_detector = MagicMock()
        self.module = CryptominerDetectionModule(self.config)
        self.module.detector = self.mock_detector
    
    def tearDown(self):
        """Clean up test environment"""
        # Stop any monitoring thread
        if hasattr(self.module, 'monitoring_thread') and self.module.monitoring_thread:
            self.module.stop_monitoring.set()
            self.module.monitoring_thread.join(timeout=1)
        
        # Remove test baseline file if it exists
        if os.path.exists(self.config['baseline_file']):
            os.remove(self.config['baseline_file'])
    
    def test_analyze(self):
        """Test analyzing for cryptominers"""
        # Mock _get_all_processes to return test PIDs
        with patch.object(self.module, '_get_all_processes', return_value=[1234, 5678]):
            # Mock detector.analyze_process results
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

def run_tests():
    """Run tests and generate coverage report"""
    # Set up coverage
    cov = coverage.Coverage(
        source=[
            os.path.join(parent_dir, "src", "utils", "ml_utils.py"),
            os.path.join(parent_dir, "src", "modules", "cryptominer.py")
        ],
        omit=['*/__pycache__/*', '*/tests/*']
    )
    cov.start()
    
    # Create test suite
    suite = unittest.TestSuite()
    
    # Add test cases
    suite.addTest(unittest.makeSuite(TestMLModelManager))
    suite.addTest(unittest.makeSuite(TestCryptominerDetector))
    suite.addTest(unittest.makeSuite(TestCryptominerModule))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Stop coverage
    cov.stop()
    
    # Print coverage report
    print("\nCoverage Summary:")
    total_coverage = cov.report()
    
    # Generate HTML report
    html_dir = os.path.join(os.path.dirname(__file__), 'coverage_html')
    cov.html_report(directory=html_dir)
    print(f"HTML coverage report saved to {html_dir}")
    
    # Return overall result
    return result.wasSuccessful(), total_coverage

if __name__ == '__main__':
    success, coverage_percent = run_tests()
    
    print(f"\nOverall test result: {'SUCCESS' if success else 'FAILURE'}")
    print(f"Total coverage: {coverage_percent:.2f}%")
    
    # If coverage is below 95%, exit with error
    if coverage_percent < 95.0:
        print(f"ERROR: Coverage is below the required 95% threshold.")
        sys.exit(1)
    else:
        print(f"SUCCESS: Coverage meets or exceeds the required 95% threshold.")
        sys.exit(0)