#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import unittest
import tempfile
import shutil
import time
import sqlite3
import concurrent.futures
from unittest.mock import patch, MagicMock, mock_open, PropertyMock

# Add project root to path so we can import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../')))

# Import the module to test
from src.modules.file_integrity import FileIntegrityMonitor

# Create a patched version of ThreadPoolExecutor that works synchronously
class SynchronousExecutor:
    def __init__(self, max_workers=None):
        self.max_workers = max_workers

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def submit(self, fn, *args, **kwargs):
        class FakeFuture:
            def __init__(self, result):
                self._result = result

            def result(self):
                return self._result

        # Execute the function synchronously
        result = fn(*args, **kwargs)
        return FakeFuture(result)

class TestFileIntegrityMonitor(unittest.TestCase):
    """Test cases for the File Integrity Monitor module"""
    
    def setUp(self):
        """Set up test environment"""
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        self.test_db_path = os.path.join(self.test_dir, 'test_integrity.db')
        
        # Create test configuration
        self.test_config = {
            "directories": [self.test_dir],
            "excluded_paths": [],
            "excluded_extensions": [".tmp"],
            "hash_algorithm": "sha256",
            "thread_count": 1,  # Set to 1 for testing
            "scan_interval": 1,  # Quick scans for testing
            "max_file_size": 1048576,  # 1MB
            "critical_files": []
        }
        
        # Create monitor instance with test configuration
        self.monitor = FileIntegrityMonitor(database_path=self.test_db_path)
        self.monitor.config = self.test_config
        
        # Patch ThreadPoolExecutor to use our synchronous executor for all tests
        self.thread_pool_patcher = patch('concurrent.futures.ThreadPoolExecutor', SynchronousExecutor)
        self.thread_pool_patcher.start()
        
    def tearDown(self):
        """Clean up test environment"""
        # Stop patchers
        self.thread_pool_patcher.stop()
        
        # Remove temporary directory
        shutil.rmtree(self.test_dir)
    
    def test_initialization(self):
        """Test monitor initialization"""
        # Verify instance creation
        self.assertIsInstance(self.monitor, FileIntegrityMonitor)
        
        # Verify database creation
        self.assertTrue(os.path.exists(self.test_db_path))
        
        # Verify database tables
        conn = sqlite3.connect(self.test_db_path)
        cursor = conn.cursor()
        
        # Check for file_baseline table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='file_baseline'")
        self.assertIsNotNone(cursor.fetchone())
        
        # Check for file_changes table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='file_changes'")
        self.assertIsNotNone(cursor.fetchone())
        
        conn.close()
    
    def test_calculate_file_hash(self):
        """Test file hash calculation"""
        # Create a test file
        test_file = os.path.join(self.test_dir, 'test_file.txt')
        with open(test_file, 'w') as f:
            f.write('test content')
        
        # Calculate hash
        file_hash = self.monitor.calculate_file_hash(test_file)
        
        # Verify hash is not None
        self.assertIsNotNone(file_hash)
        
        # Verify hash is a string
        self.assertIsInstance(file_hash, str)
        
        # Verify hash is the correct length for SHA-256
        self.assertEqual(len(file_hash), 64)
    
    def test_should_monitor_file(self):
        """Test file monitoring criteria"""
        # Test included file
        included_file = os.path.join(self.test_dir, 'included.txt')
        self.assertTrue(self.monitor.should_monitor_file(included_file))
        
        # Test excluded extension
        excluded_file = os.path.join(self.test_dir, 'excluded.tmp')
        self.assertFalse(self.monitor.should_monitor_file(excluded_file))
    
    def test_get_file_metadata(self):
        """Test file metadata retrieval"""
        # Create a test file
        test_file = os.path.join(self.test_dir, 'metadata_test.txt')
        with open(test_file, 'w') as f:
            f.write('metadata test content')
        
        # Get metadata
        metadata = self.monitor.get_file_metadata(test_file)
        
        # Verify metadata
        self.assertIsNotNone(metadata)
        self.assertIn('size', metadata)
        self.assertIn('permissions', metadata)
        self.assertIn('owner', metadata)
        self.assertIn('group_owner', metadata)
        self.assertIn('last_modified', metadata)
        
        # Verify size is correct
        self.assertEqual(metadata['size'], len('metadata test content'))
    
    @patch('os.walk')
    @patch('src.modules.file_integrity.FileIntegrityMonitor.calculate_file_hash')
    @patch('src.modules.file_integrity.FileIntegrityMonitor.get_file_metadata')
    @patch('src.modules.file_integrity.FileIntegrityMonitor._process_file_for_baseline')
    def test_create_baseline(self, mock_process_file, mock_get_metadata, mock_calc_hash, mock_walk):
        """Test baseline creation"""
        # Mock os.walk to return test files
        mock_walk.return_value = [
            (self.test_dir, [], ['file1.txt', 'file2.txt', 'file3.tmp'])
        ]
        
        # Mock file metadata
        mock_get_metadata.return_value = {
            'size': 100,
            'permissions': 0o644,
            'owner': 1000,
            'group_owner': 1000,
            'last_modified': time.time()
        }
        
        # Mock file hash
        mock_calc_hash.return_value = 'a' * 64
        
        # Create baseline
        processed, errors = self.monitor.create_baseline()
        
        # Verify processed count (should be 2 files, excluding the .tmp file)
        self.assertEqual(processed, 2)
    
    @patch('os.path.exists')
    @patch('src.modules.file_integrity.FileIntegrityMonitor.calculate_file_hash')
    @patch('src.modules.file_integrity.FileIntegrityMonitor.get_file_metadata')
    @patch('src.modules.file_integrity.FileIntegrityMonitor._check_file_integrity')
    def test_check_integrity(self, mock_check_file, mock_get_metadata, mock_calc_hash, mock_exists):
        """Test integrity checking"""
        # Add a test file to baseline
        conn = sqlite3.connect(self.test_db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        INSERT INTO file_baseline 
        (path, hash, size, permissions, owner, group_owner, last_modified, last_checked, is_critical) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            os.path.join(self.test_dir, 'baseline_file.txt'),
            'a' * 64,
            100,
            0o644,
            1000,
            1000,
            time.time(),
            time.time(),
            0
        ))
        conn.commit()
        conn.close()
        
        # Mock path existence
        mock_exists.return_value = True
        
        # Mock file hash to be different (indicating change)
        mock_calc_hash.return_value = 'b' * 64
        
        # Mock metadata
        mock_get_metadata.return_value = {
            'size': 120,  # Changed size
            'permissions': 0o644,
            'owner': 1000,
            'group_owner': 1000,
            'last_modified': time.time()
        }
        
        # Setup mock for _check_file_integrity
        mock_check_file.return_value = {
            "path": os.path.join(self.test_dir, 'baseline_file.txt'),
            "type": "content",
            "is_critical": 0,
            "timestamp": time.time()
        }
        
        # Check integrity
        changes = self.monitor.check_integrity()
        
        # Verify changes detected
        self.assertGreaterEqual(len(changes), 1)
        # Check if there's a content change in the results
        self.assertTrue(any('content' in str(c.get('type', '')) for c in changes))
    
    def test_detect_ransomware_activity(self):
        """Test ransomware activity detection"""
        # Simulate recent content changes
        conn = sqlite3.connect(self.test_db_path)
        cursor = conn.cursor()
        
        # Insert many content changes to simulate ransomware
        for i in range(200):
            cursor.execute('''
            INSERT INTO file_changes 
            (path, change_type, old_hash, new_hash, timestamp) 
            VALUES (?, ?, ?, ?, ?)
            ''', (
                f'/path/to/file{i}.txt',
                'content',
                'a' * 64,
                'b' * 64,
                time.time()
            ))
            
        # Add some ransomware extensions
        cursor.execute('''
        INSERT INTO file_changes 
        (path, change_type, timestamp) 
        VALUES (?, ?, ?)
        ''', (
            '/path/to/encrypted.ransomware',
            'added',
            time.time()
        ))
        
        conn.commit()
        conn.close()
        
        # Check for ransomware activity
        result = self.monitor.detect_ransomware_activity()
        
        # Verify detection
        self.assertEqual(result['threat_level'], 'critical')
        
    def test_run_scan(self):
        """Test full scan execution"""
        # Patch check_integrity to return no changes
        with patch.object(self.monitor, 'check_integrity', return_value=[]):
            # Patch detect_ransomware_activity
            with patch.object(self.monitor, 'detect_ransomware_activity', 
                             return_value={'threat_level': 'low', 'recent_changes': 0, 
                                          'ransomware_files': [], 'ransom_notes': []}):
                # Patch other detection methods
                with patch.object(self.monitor, 'detect_suspicious_scripts', return_value=[]):
                    with patch.object(self.monitor, 'detect_binary_replacements', return_value=[]):
                        # Run scan
                        result = self.monitor.run_scan()
                        
                        # Verify result
                        self.assertIn('timestamp', result)
                        self.assertIn('scan_time_seconds', result)
                        self.assertIn('total_changes', result)
                        self.assertIn('threat_level', result)
                        
                        # Verify threat level is low when no issues detected
                        self.assertEqual(result['threat_level'], 'low')

if __name__ == '__main__':
    unittest.main()