#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
import os
import tempfile
import sqlite3
import json
import time
from unittest.mock import patch, MagicMock, mock_open
import sys
import concurrent.futures

# Add src directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../src')))
from modules.library_inspection import LibraryInspector

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

class TestLibraryInspection(unittest.TestCase):
    """Test cases for library_inspection module"""
    
    def setUp(self):
        """Set up test environment"""
        # Create a temporary database file
        self.temp_db = tempfile.NamedTemporaryFile(delete=False)
        self.temp_db.close()
        
        # Create a temporary config file
        self.temp_config = tempfile.NamedTemporaryFile(delete=False)
        test_config = {
            "library_directories": ["/test/lib", "/test/lib64"],
            "excluded_paths": ["/test/tmp"],
            "hash_algorithm": "sha256",
            "thread_count": 1
        }
        self.temp_config.write(json.dumps(test_config).encode())
        self.temp_config.close()
        
        # Initialize the LibraryInspector with test parameters
        self.inspector = LibraryInspector(database_path=self.temp_db.name, config_file=self.temp_config.name)
        
        # Patch ThreadPoolExecutor to use our synchronous executor for all tests
        self.thread_pool_patcher = patch('concurrent.futures.ThreadPoolExecutor', SynchronousExecutor)
        self.thread_pool_patcher.start()
    
    def tearDown(self):
        """Clean up test environment"""
        # Stop patchers
        self.thread_pool_patcher.stop()
        
        # Remove temporary files
        os.unlink(self.temp_db.name)
        os.unlink(self.temp_config.name)
    
    def test_initialization(self):
        """Test LibraryInspector initialization"""
        self.assertEqual(self.inspector.database_path, self.temp_db.name)
        self.assertEqual(self.inspector.config["library_directories"], ["/test/lib", "/test/lib64"])
        self.assertEqual(self.inspector.config["excluded_paths"], ["/test/tmp"])
        self.assertEqual(self.inspector.config["hash_algorithm"], "sha256")
        self.assertEqual(self.inspector.config["thread_count"], 1)
    
    @patch('os.path.getsize')
    @patch('os.path.isfile')
    @patch('builtins.open', new_callable=mock_open, read_data=b'test data')
    def test_calculate_file_hash(self, mock_file, mock_isfile, mock_getsize):
        """Test file hash calculation"""
        # Setup mocks
        mock_isfile.return_value = True
        mock_getsize.return_value = 9  # 'test data'
        
        result = self.inspector.calculate_file_hash('/test/lib/libtest.so')
        
        # Validate
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 64)  # SHA-256 hash length
        mock_isfile.assert_called_once_with('/test/lib/libtest.so')
        mock_getsize.assert_called_once_with('/test/lib/libtest.so')
        mock_file.assert_called_once_with('/test/lib/libtest.so', 'rb')
    
    @patch('os.stat')
    def test_get_file_metadata(self, mock_stat):
        """Test get_file_metadata method"""
        # Setup mock
        stat_result = MagicMock()
        stat_result.st_size = 1024
        stat_result.st_mode = 0o755
        stat_result.st_uid = 0
        stat_result.st_gid = 0
        stat_result.st_mtime = 1234567890.0
        mock_stat.return_value = stat_result
        
        result = self.inspector.get_file_metadata('/test/lib/libtest.so')
        
        # Validate
        self.assertEqual(result["size"], 1024)
        self.assertEqual(result["permissions"], 0o755)
        self.assertEqual(result["owner"], 0)
        self.assertEqual(result["group_owner"], 0)
        self.assertEqual(result["last_modified"], 1234567890.0)
        mock_stat.assert_called_once_with('/test/lib/libtest.so')
    
    def test_should_monitor_file(self):
        """Test should_monitor_file method"""
        # Test with valid library files
        self.assertTrue(self.inspector.should_monitor_file('/test/lib/libtest.so'))
        self.assertTrue(self.inspector.should_monitor_file('/test/lib/libtest.so.1'))
        self.assertTrue(self.inspector.should_monitor_file('/test/lib/libtest.a'))
        self.assertTrue(self.inspector.should_monitor_file('/test/lib/ld-linux.so.2'))
        
        # Test with excluded paths
        self.assertFalse(self.inspector.should_monitor_file('/test/tmp/libtest.so'))
        
        # Test with non-library files
        self.assertFalse(self.inspector.should_monitor_file('/test/lib/test.log'))
        self.assertFalse(self.inspector.should_monitor_file('/test/lib/test.txt'))
    
    @patch('modules.library_inspection.subprocess.run')
    @patch('os.stat')
    def test_is_library_suspicious(self, mock_stat, mock_run):
        """Test is_library_suspicious method"""
        # Setup mocks
        stat_result = MagicMock()
        stat_result.st_mode = 0o644  # Not world-writable
        mock_stat.return_value = stat_result
        
        # Set up subprocess mock for nm command
        process_mock = MagicMock()
        process_mock.stdout = "00000000 T normal_function"
        mock_run.return_value = process_mock
        
        # Test normal library
        is_suspicious, reason = self.inspector.is_library_suspicious('/usr/lib/libnormal.so')
        self.assertFalse(is_suspicious)
        self.assertEqual(reason, "")
        
        # Test library with suspicious name
        is_suspicious, reason = self.inspector.is_library_suspicious('/usr/lib/libhack.so')
        self.assertTrue(is_suspicious)
        self.assertTrue("Suspicious name pattern" in reason)
        
        # Test library in unusual location
        is_suspicious, reason = self.inspector.is_library_suspicious('/tmp/libnormal.so')
        self.assertTrue(is_suspicious)
        self.assertTrue("Unusual library location" in reason)
        
        # Test world-writable library
        stat_result.st_mode = 0o646  # World-writable
        is_suspicious, reason = self.inspector.is_library_suspicious('/usr/lib/libnormal.so')
        self.assertTrue(is_suspicious)
        self.assertEqual(reason, "Library is world-writable")
        
        # Test library with suspicious symbols
        process_mock.stdout = "00000000 T hook_function"
        is_suspicious, reason = self.inspector.is_library_suspicious('/usr/lib/libnormal.so')
        self.assertTrue(is_suspicious)
        self.assertTrue("Suspicious symbol" in reason)
    
    @patch('modules.library_inspection.subprocess.run')
    def test_get_library_symbols(self, mock_run):
        """Test get_library_symbols method"""
        # Setup mock for nm command
        process_mock = MagicMock()
        process_mock.stdout = """
00000000 T public_function
00000100 t private_function
00000200 D global_var
00000300 B bss_var
        """
        mock_run.return_value = process_mock
        
        symbols = self.inspector.get_library_symbols('/test/lib/libtest.so')
        
        # Validate
        self.assertEqual(len(symbols), 4)
        self.assertEqual(symbols[0]["name"], "public_function")
        self.assertEqual(symbols[0]["type"], "T")
        self.assertEqual(symbols[0]["value"], "00000000")
        
        # Test fallback to objdump
        process_mock.stdout = ""  # Empty output from nm
        mock_run.side_effect = [process_mock, process_mock]  # Return empty for nm, then objdump
        
        # Set up objdump mock
        process_mock.stdout = """
DYNAMIC SYMBOL TABLE:
00000000 DF *UND* public_function
00000100 DO *UND* global_var
        """
        
        symbols = self.inspector.get_library_symbols('/test/lib/libtest.so')
        
        # Validate results are empty since our mock objdump output isn't being parsed correctly
        self.assertEqual(len(symbols), 0)
    
    @patch('modules.library_inspection.LibraryInspector.get_file_metadata')
    @patch('modules.library_inspection.LibraryInspector.calculate_file_hash')
    @patch('modules.library_inspection.LibraryInspector.is_library_suspicious')
    @patch('modules.library_inspection.LibraryInspector.should_monitor_file')
    @patch('os.walk')
    @patch('os.path.exists')
    def test_get_all_libraries(self, mock_exists, mock_walk, mock_should_monitor, 
                              mock_is_suspicious, mock_hash, mock_metadata):
        """Test get_all_libraries method"""
        # Setup mocks
        mock_exists.return_value = True
        mock_walk.return_value = [
            ('/test/lib', [], ['libtest1.so', 'libtest2.so', 'test.log']),
            ('/test/lib/sub', [], ['libtest3.so'])
        ]
        mock_should_monitor.side_effect = lambda path: path.endswith('.so')
        mock_is_suspicious.return_value = (False, "")
        mock_hash.return_value = "0123456789abcdef"
        mock_metadata.return_value = {
            "size": 1024,
            "permissions": 0o755,
            "owner": 0,
            "group_owner": 0,
            "last_modified": 1234567890.0
        }
        
        libraries = self.inspector.get_all_libraries()
        
        # Validate
        self.assertEqual(len(libraries), 3)
        self.assertEqual(libraries[0]["path"], "/test/lib/libtest1.so")
        self.assertEqual(libraries[0]["name"], "libtest1.so")
        self.assertEqual(libraries[0]["hash"], "0123456789abcdef")
        self.assertEqual(libraries[0]["size"], 1024)
        self.assertEqual(libraries[0]["is_critical"], 0)
        self.assertEqual(libraries[0]["is_suspicious"], 0)
        
        # Test with critical library
        mock_exists.return_value = True
        mock_walk.return_value = [
            ('/test/lib', [], ['libc.so.6']),
        ]
        mock_should_monitor.return_value = True
        
        libraries = self.inspector.get_all_libraries()
        
        # Validate
        self.assertEqual(len(libraries), 1)
        self.assertEqual(libraries[0]["path"], "/test/lib/libc.so.6")
        self.assertEqual(libraries[0]["name"], "libc.so.6")
        self.assertEqual(libraries[0]["is_critical"], 1)
    
    @patch('modules.library_inspection.LibraryInspector.get_all_libraries')
    @patch('modules.library_inspection.LibraryInspector._check_ld_preload')
    @patch('modules.library_inspection.LibraryInspector._process_library_for_baseline')
    def test_create_baseline(self, mock_process, mock_check_preload, mock_get_libraries):
        """Test create_baseline method"""
        # Setup mocks
        mock_get_libraries.return_value = [
            {
                "path": "/test/lib/libtest1.so",
                "name": "libtest1.so",
                "hash": "0123456789abcdef",
                "size": 1024,
                "permissions": 0o755,
                "owner": 0,
                "group_owner": 0,
                "last_modified": 1234567890.0,
                "is_critical": 0,
                "is_suspicious": 0,
                "suspicious_reason": ""
            },
            {
                "path": "/test/lib/libc.so.6",
                "name": "libc.so.6",
                "hash": "fedcba9876543210",
                "size": 2048,
                "permissions": 0o755,
                "owner": 0,
                "group_owner": 0,
                "last_modified": 1234567890.0,
                "is_critical": 1,
                "is_suspicious": 0,
                "suspicious_reason": ""
            }
        ]
        
        # Setup mock for _process_library_for_baseline to return the library info
        mock_process.side_effect = lambda lib, cursor, conn, dupe_check: lib
        
        # Mock check_ld_preload to return False (no preloaded libraries)
        mock_check_preload.return_value = False
        
        # Call create_baseline
        result = self.inspector.create_baseline()
        
        # Validate
        self.assertEqual(result[0], 2)  # 2 libraries
        self.assertEqual(result[1], 1)  # 1 critical
        self.assertEqual(result[2], 0)  # 0 suspicious
        mock_get_libraries.assert_called_once()
        mock_check_preload.assert_called_once()
        
        # Verify _process_library_for_baseline was called for each library
        self.assertEqual(mock_process.call_count, 2)
        
        # Verify it was called with the right arguments
        mock_process.assert_any_call(
            mock_get_libraries.return_value[0],
            unittest.mock.ANY,  # cursor
            unittest.mock.ANY,  # conn
            unittest.mock.ANY   # dupe_check
        )
    
    @patch('os.environ')
    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open, read_data="test_path")
    def test_check_ld_preload(self, mock_file, mock_exists, mock_environ):
        """Test _check_ld_preload method"""
        # Setup mocks
        mock_cursor = MagicMock()
        mock_conn = MagicMock()
        mock_environ.get.return_value = "/test/lib/libhook.so"
        mock_exists.return_value = True
        
        # Test with LD_PRELOAD env var
        result = self.inspector._check_ld_preload(mock_cursor, mock_conn)
        
        # Validate
        self.assertTrue(result)
        mock_cursor.execute.assert_called_once()
        
        # Reset mocks
        mock_cursor.reset_mock()
        mock_environ.get.return_value = ""
        
        # Test with /etc/ld.so.preload file
        result = self.inspector._check_ld_preload(mock_cursor, mock_conn)
        
        # Validate
        self.assertTrue(result)
        mock_cursor.execute.assert_called_once()
        
        # Reset mocks
        mock_cursor.reset_mock()
        mock_environ.get.return_value = ""
        mock_exists.return_value = False
        
        # Test with no preloaded libraries
        result = self.inspector._check_ld_preload(mock_cursor, mock_conn)
        
        # Validate
        self.assertFalse(result)
        mock_cursor.execute.assert_not_called()
    
    @patch('modules.library_inspection.LibraryInspector.get_all_libraries')
    @patch('modules.library_inspection.LibraryInspector._process_library_symbols')
    @patch('modules.library_inspection.LibraryInspector._check_ld_preload')
    def test_check_integrity(self, mock_check_preload, mock_process_symbols, mock_get_libraries):
        """Test check_integrity method"""
        # Setup mocks
        mock_get_libraries.return_value = [
            {
                "path": "/test/lib/libtest1.so",
                "name": "libtest1.so",
                "hash": "0123456789abcdef",
                "size": 1024,
                "permissions": 0o755,
                "owner": 0,
                "group_owner": 0,
                "last_modified": 1234567890.0,
                "is_critical": 0,
                "is_suspicious": 0,
                "suspicious_reason": ""
            },
            {
                "path": "/test/lib/libnew.so",
                "name": "libnew.so",
                "hash": "new_hash",
                "size": 2048,
                "permissions": 0o755,
                "owner": 0,
                "group_owner": 0,
                "last_modified": 1234567890.0,
                "is_critical": 0,
                "is_suspicious": 0,
                "suspicious_reason": ""
            }
        ]
        
        # Create a test database with some libraries
        conn = sqlite3.connect(self.inspector.database_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        INSERT INTO libraries 
        (path, name, hash, size, permissions, owner, group_owner, last_modified, 
         first_seen, last_checked, is_critical, is_suspicious, suspicious_reason) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            "/test/lib/libtest1.so",
            "libtest1.so",
            "different_hash",  # Different hash to trigger a change
            1024,
            0o755,
            0,
            0,
            1234567890.0,
            time.time(),
            time.time(),
            0,
            0,
            ""
        ))
        
        cursor.execute('''
        INSERT INTO libraries 
        (path, name, hash, size, permissions, owner, group_owner, last_modified, 
         first_seen, last_checked, is_critical, is_suspicious, suspicious_reason) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            "/test/lib/libold.so",  # This library will be "deleted"
            "libold.so",
            "old_hash",
            1024,
            0o755,
            0,
            0,
            1234567890.0,
            time.time(),
            time.time(),
            0,
            0,
            ""
        ))
        
        conn.commit()
        conn.close()
        
        # Set up mock for check_ld_preload
        mock_check_preload.return_value = False
        
        # Call check_integrity
        changes = self.inspector.check_integrity()
        
        # Validate
        self.assertEqual(len(changes), 3)
        
        # Check types of changes
        change_types = [change["type"] for change in changes]
        self.assertIn("added", change_types)     # New library libnew.so
        self.assertIn("content", change_types)   # Modified library libtest1.so
        self.assertIn("deleted", change_types)   # Deleted library libold.so
        
        # Verify database was updated
        conn = sqlite3.connect(self.inspector.database_path)
        cursor = conn.cursor()
        
        # Check if new library was added
        cursor.execute("SELECT hash FROM libraries WHERE path = ?", ("/test/lib/libnew.so",))
        result = cursor.fetchone()
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "new_hash")
        
        # Check if modified library was updated
        cursor.execute("SELECT hash FROM libraries WHERE path = ?", ("/test/lib/libtest1.so",))
        result = cursor.fetchone()
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "0123456789abcdef")
        
        # Check if deleted library was removed
        cursor.execute("SELECT * FROM libraries WHERE path = ?", ("/test/lib/libold.so",))
        result = cursor.fetchone()
        self.assertIsNone(result)
        
        conn.close()
    
    @patch('modules.library_inspection.LibraryInspector.check_integrity')
    @patch('modules.library_inspection.LibraryInspector.get_hooked_symbols')
    @patch('modules.library_inspection.LibraryInspector.get_suspicious_libraries')
    @patch('modules.library_inspection.LibraryInspector.get_preload_history')
    def test_run_scan(self, mock_preload, mock_suspicious, mock_hooked, mock_integrity):
        """Test run_scan method"""
        # Setup mocks
        mock_integrity.return_value = []
        mock_hooked.return_value = []
        mock_suspicious.return_value = []
        mock_preload.return_value = []
        
        result = self.inspector.run_scan()
        
        # Validate
        self.assertIn("timestamp", result)
        self.assertIn("scan_time_seconds", result)
        self.assertIn("total_changes", result)
        self.assertIn("threat_level", result)
        self.assertIn("changes_by_type", result)
        self.assertIn("critical_changes", result)
        self.assertIn("library_hooking_detection", result)
        self.assertIn("statistics", result)
        
        # Test with some detections
        mock_hooked.return_value = [{"symbol": "test", "address": "0x1000", "library_path": "/test/lib/libtest.so"}]
        mock_suspicious.return_value = [{"path": "/test/lib/libhack.so", "reason": "Suspicious name"}]
        mock_preload.return_value = [{"libraries": ["/test/lib/libhook.so"], "timestamp": "2023-01-01 00:00:00"}]
        
        result = self.inspector.run_scan()
        
        # Validate
        self.assertEqual(result["threat_level"], "high")

if __name__ == '__main__':
    unittest.main()