#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test configuration for SharpEye

This file contains common test configuration and utility functions
for handling SQLite connections in tests to prevent threading issues.
"""

import os
import sys
import sqlite3
import concurrent.futures
from unittest.mock import patch

# Add project root to sys.path if not already there
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

class SynchronousExecutor:
    """
    A replacement for ThreadPoolExecutor that executes functions synchronously
    
    This is used to avoid SQLite threading issues in tests.
    """
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
    
    def map(self, fn, *iterables, timeout=None, chunksize=1):
        """Synchronous implementation of executor.map"""
        return map(fn, *iterables)

def patch_thread_executor(test_class):
    """
    Patch ThreadPoolExecutor in test setup and teardown methods
    
    Usage:
    @patch_thread_executor
    class TestMyClass(unittest.TestCase):
        ...
    """
    orig_setUp = test_class.setUp
    orig_tearDown = test_class.tearDown
    
    def patched_setUp(self):
        self.thread_pool_patcher = patch('concurrent.futures.ThreadPoolExecutor', SynchronousExecutor)
        self.thread_pool_patcher.start()
        orig_setUp(self)
    
    def patched_tearDown(self):
        orig_tearDown(self)
        self.thread_pool_patcher.stop()
    
    test_class.setUp = patched_setUp
    test_class.tearDown = patched_tearDown
    return test_class

def get_test_db_connection(db_path):
    """
    Create a SQLite connection with proper settings for testing
    
    This ensures connections are thread-safe and enforces proper foreign keys.
    """
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    return conn

def check_setup():
    """
    Check if the test environment is properly set up
    
    Returns a tuple of (success, message)
    """
    import sys
    
    if project_root not in sys.path:
        return False, f"Project root {project_root} not in sys.path"
    
    try:
        # Try importing some core modules
        from src.modules import file_integrity
        from src.modules import system_resources
    except ImportError as e:
        return False, f"Failed to import core modules: {e}"
    
    return True, "Test environment is properly set up"

# Run a quick check if this file is executed directly
if __name__ == "__main__":
    success, message = check_setup()
    print(f"Setup check: {'SUCCESS' if success else 'FAILED'}")
    print(message)
    
    if success:
        print("\nEnvironment information:")
        print(f"Python version: {sys.version}")
        print(f"Project root: {project_root}")
        print(f"sys.path: {sys.path}")
    else:
        sys.exit(1)