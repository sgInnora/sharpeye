#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import unittest
import tempfile
import shutil
import time
import sqlite3
from unittest.mock import patch, MagicMock, mock_open, call

# Add project root to path so we can import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../')))

# Import the module to test
from src.modules.kernel_modules import KernelModuleAnalyzer

class TestKernelModuleAnalyzer(unittest.TestCase):
    """Test cases for the Kernel Module Analyzer module"""
    
    def setUp(self):
        """Set up test environment"""
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        self.test_db_path = os.path.join(self.test_dir, 'test_kernel_modules.db')
        
        # Create test configuration
        self.test_config = {
            "whitelist_modules": ["ext4", "btrfs", "xfs"],
            "known_rootkits": ["diamorphine", "reptile", "suterusu"],
            "thread_count": 1,
            "scan_interval": 1,  # Quick scans for testing
            "suspicious_parameters": ["hidden", "stealth"],
            "suspicious_module_patterns": ["hide[_-].*", ".*[_-]hide"],
            "suspicious_exports": ["hide_process", "hide_file"],
            "critical_syscalls": ["sys_read", "sys_write"],
            "common_module_directories": ["/lib/modules"]
        }
        
        # Create analyzer instance with test configuration
        self.analyzer = KernelModuleAnalyzer(database_path=self.test_db_path)
        self.analyzer.config = self.test_config
        
    def tearDown(self):
        """Clean up test environment"""
        # Remove temporary directory
        shutil.rmtree(self.test_dir)
    
    def test_initialization(self):
        """Test analyzer initialization"""
        # Verify instance creation
        self.assertIsInstance(self.analyzer, KernelModuleAnalyzer)
        
        # Verify database creation
        self.assertTrue(os.path.exists(self.test_db_path))
        
        # Verify database tables
        conn = sqlite3.connect(self.test_db_path)
        cursor = conn.cursor()
        
        # Check for kernel_modules table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='kernel_modules'")
        self.assertIsNotNone(cursor.fetchone())
        
        # Check for module_changes table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='module_changes'")
        self.assertIsNotNone(cursor.fetchone())
        
        # Check for syscall_table table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='syscall_table'")
        self.assertIsNotNone(cursor.fetchone())
        
        conn.close()
    
    @patch('subprocess.run')
    def test_get_loaded_modules(self, mock_subprocess_run):
        """Test retrieval of loaded modules"""
        # Mock subprocess.run to return test data
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.stdout = """Module                  Size  Used by
ext4                  528384  2
xfs                   212992  0
btrfs                 208896  0
"""
        mock_subprocess_run.return_value = mock_process
        
        # Mock _get_module_path
        with patch.object(self.analyzer, '_get_module_path', return_value='/lib/modules/kernel/ext4.ko'):
            # Mock _calculate_file_hash
            with patch.object(self.analyzer, '_calculate_file_hash', return_value='a' * 64):
                # Mock os.path.exists to return True for the module path
                with patch('os.path.exists', return_value=True):
                    # Get loaded modules
                    modules = self.analyzer.get_loaded_modules()
                    
                    # Verify modules
                    self.assertEqual(len(modules), 3)
                    self.assertEqual(modules[0]['name'], 'ext4')
                    self.assertEqual(modules[0]['size'], 528384)
                    self.assertEqual(modules[0]['refcount'], 2)
                    self.assertEqual(modules[0]['path'], '/lib/modules/kernel/ext4.ko')
                    self.assertEqual(modules[0]['hash'], 'a' * 64)
                    self.assertTrue(modules[0]['loaded'])
    
    @patch('subprocess.run')
    def test_get_module_details(self, mock_subprocess_run):
        """Test retrieval of module details"""
        # Mock subprocess.run to return test data
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.stdout = """filename:       /lib/modules/kernel/ext4.ko
description:    Fourth Extended Filesystem
author:         Theodore Ts'o
license:        GPL
parm:           acl:acl options
parm:           xattr:xattr options
depends:        mbcache,jbd2
"""
        mock_subprocess_run.return_value = mock_process
        
        # Get module details
        details = self.analyzer.get_module_details('ext4')
        
        # Verify details
        self.assertEqual(details['name'], 'ext4')
        self.assertEqual(details['path'], '/lib/modules/kernel/ext4.ko')
        self.assertEqual(details['description'], 'Fourth Extended Filesystem')
        self.assertEqual(details['author'], 'Theodore Ts\'o')
        self.assertEqual(details['license'], 'GPL')
        self.assertEqual(len(details['parameters']), 2)
        self.assertEqual(details['dependencies'], ['mbcache', 'jbd2'])
    
    def test_check_module_suspicious(self):
        """Test suspicious module detection"""
        # Test known rootkit
        module_rootkit = {'name': 'diamorphine', 'path': '/tmp/diamorphine.ko'}
        is_suspicious, reason = self.analyzer._check_module_suspicious(module_rootkit)
        self.assertTrue(is_suspicious)
        self.assertIn('Known rootkit', reason)
        
        # Test suspicious name pattern
        module_suspicious_name = {'name': 'hide_process', 'path': '/tmp/hide_process.ko'}
        is_suspicious, reason = self.analyzer._check_module_suspicious(module_suspicious_name)
        self.assertTrue(is_suspicious)
        self.assertIn('Suspicious name pattern', reason)
        
        # Test legitimate module
        module_legit = {'name': 'ext4', 'path': '/lib/modules/kernel/ext4.ko', 'loaded': True}
        
        # Mock get_module_details
        with patch.object(self.analyzer, 'get_module_details', return_value={
            'name': 'ext4',
            'path': '/lib/modules/kernel/ext4.ko',
            'description': 'Fourth Extended Filesystem',
            'author': 'Theodore Ts\'o',
            'license': 'GPL',
            'parameters': [{'name': 'acl', 'description': 'acl options'}],
            'dependencies': ['mbcache', 'jbd2'],
            'signature': 'valid_signature'
        }):
            is_suspicious, reason = self.analyzer._check_module_suspicious(module_legit)
            self.assertFalse(is_suspicious)
            self.assertEqual(reason, '')
    
    @patch('src.modules.kernel_modules.KernelModuleAnalyzer.get_available_modules')
    @patch('src.modules.kernel_modules.KernelModuleAnalyzer._check_module_suspicious')
    @patch('src.modules.kernel_modules.KernelModuleAnalyzer.get_module_details')
    @patch('src.modules.kernel_modules.KernelModuleAnalyzer._check_syscall_table')
    def test_create_baseline(self, mock_check_syscall, mock_get_details, mock_check_suspicious, mock_get_modules):
        """Test baseline creation"""
        # Mock get_available_modules
        mock_get_modules.return_value = [
            {'name': 'ext4', 'path': '/lib/modules/kernel/ext4.ko', 'hash': 'a' * 64, 'loaded': True, 'size': 528384, 'refcount': 2, 'used_by': ''},
            {'name': 'xfs', 'path': '/lib/modules/kernel/xfs.ko', 'hash': 'b' * 64, 'loaded': True, 'size': 212992, 'refcount': 0, 'used_by': ''},
            {'name': 'hide_file', 'path': '/tmp/hide_file.ko', 'hash': 'c' * 64, 'loaded': False, 'size': 10240, 'refcount': 0, 'used_by': ''}
        ]
        
        # Mock check_suspicious
        mock_check_suspicious.side_effect = [
            (False, ''),  # ext4
            (False, ''),  # xfs
            (True, 'Suspicious name pattern')  # hide_file
        ]
        
        # Mock get_module_details
        mock_get_details.return_value = {
            'name': 'ext4',
            'path': '/lib/modules/kernel/ext4.ko',
            'description': 'Fourth Extended Filesystem',
            'author': 'Theodore Ts\'o',
            'license': 'GPL',
            'parameters': [{'name': 'acl', 'description': 'acl options'}],
            'dependencies': ['mbcache', 'jbd2'],
            'signature': 'valid_signature'
        }
        
        # Mock check_syscall_table
        mock_check_syscall.return_value = True
        
        # Create baseline
        processed, suspicious = self.analyzer.create_baseline()
        
        # Verify processed and suspicious counts
        self.assertEqual(processed, 3)
        self.assertEqual(suspicious, 1)
        
        # Verify database contents
        conn = sqlite3.connect(self.test_db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM kernel_modules")
        total_modules = cursor.fetchone()[0]
        self.assertEqual(total_modules, 3)
        
        cursor.execute("SELECT COUNT(*) FROM kernel_modules WHERE is_suspicious = 1")
        suspicious_modules = cursor.fetchone()[0]
        self.assertEqual(suspicious_modules, 1)
        
        conn.close()
    
    @patch('os.path.exists')
    @patch('src.modules.kernel_modules.KernelModuleAnalyzer.get_loaded_modules')
    @patch('src.modules.kernel_modules.KernelModuleAnalyzer._check_module_suspicious')
    def test_check_integrity(self, mock_check_suspicious, mock_get_modules, mock_exists):
        """Test integrity checking"""
        # Add test modules to baseline
        conn = sqlite3.connect(self.test_db_path)
        cursor = conn.cursor()
        
        # Add ext4 module to baseline
        cursor.execute('''
        INSERT INTO kernel_modules 
        (name, size, loaded, refcount, module_hash, file_path, used_by, first_seen, last_seen, is_suspicious, suspicious_reason) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            'ext4',
            528384,
            1,
            2,
            'a' * 64,
            '/lib/modules/kernel/ext4.ko',
            '',
            time.time(),
            time.time(),
            0,
            ''
        ))
        
        # Add xfs module to baseline
        cursor.execute('''
        INSERT INTO kernel_modules 
        (name, size, loaded, refcount, module_hash, file_path, used_by, first_seen, last_seen, is_suspicious, suspicious_reason) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            'xfs',
            212992,
            1,
            0,
            'b' * 64,
            '/lib/modules/kernel/xfs.ko',
            '',
            time.time(),
            time.time(),
            0,
            ''
        ))
        
        conn.commit()
        
        # Mock path existence
        mock_exists.return_value = True
        
        # Mock get_loaded_modules with modified modules
        mock_get_modules.return_value = [
            {'name': 'ext4', 'path': '/lib/modules/kernel/ext4.ko', 'hash': 'a' * 64, 'loaded': True, 'size': 528384, 'refcount': 2, 'used_by': ''},
            # New module not in baseline
            {'name': 'rootkit', 'path': '/tmp/rootkit.ko', 'hash': 'd' * 64, 'loaded': True, 'size': 10240, 'refcount': 0, 'used_by': ''}
            # Missing xfs module (unloaded)
        ]
        
        # Mock check_suspicious
        mock_check_suspicious.side_effect = [
            (False, ''),  # ext4
            (True, 'Known rootkit')  # rootkit
        ]
        
        # Check integrity
        changes = self.analyzer.check_integrity()
        
        # Verify changes detected
        self.assertEqual(len(changes), 2)
        
        # Verify new module detected
        self.assertTrue(any(c['name'] == 'rootkit' and c['type'] == 'added' for c in changes))
        
        # Verify unloaded module detected
        self.assertTrue(any(c['name'] == 'xfs' and c['type'] == 'unloaded' for c in changes))
        
        conn.close()
    
    @patch('src.modules.kernel_modules.KernelModuleAnalyzer.get_hooked_syscalls')
    @patch('src.modules.kernel_modules.KernelModuleAnalyzer.get_hidden_modules')
    @patch('src.modules.kernel_modules.KernelModuleAnalyzer.get_suspicious_modules')
    def test_check_for_rootkit_behavior(self, mock_get_suspicious, mock_get_hidden, mock_get_hooked):
        """Test rootkit behavior detection"""
        # Mock get_hooked_syscalls
        mock_get_hooked.return_value = [
            {'name': 'sys_read', 'address': 'deadbeef', 'module': 'suspicious_module'}
        ]
        
        # Mock get_hidden_modules
        mock_get_hidden.return_value = [
            {'name': 'hidden_module', 'detection_method': 'proc_modules_vs_lsmod'}
        ]
        
        # Mock get_suspicious_modules
        mock_get_suspicious.return_value = [
            {'name': 'suspicious_module', 'reason': 'Suspicious name pattern'}
        ]
        
        # Check for rootkit behavior
        results = self.analyzer.check_for_rootkit_behavior()
        
        # Verify results
        self.assertEqual(results['threat_level'], 'critical')
        self.assertEqual(len(results['syscall_hooks']), 1)
        self.assertEqual(len(results['hidden_modules']), 1)
        self.assertEqual(len(results['suspicious_modules']), 1)
    
    def test_run_scan(self):
        """Test full scan execution"""
        # Patch check_integrity to return test changes
        with patch.object(self.analyzer, 'check_integrity', return_value=[
            {'name': 'ext4', 'type': 'content', 'is_suspicious': False, 'timestamp': time.time()}
        ]):
            # Patch check_for_rootkit_behavior
            with patch.object(self.analyzer, 'check_for_rootkit_behavior', 
                             return_value={'threat_level': 'low', 'syscall_hooks': [], 
                                         'hidden_modules': [], 'suspicious_modules': []}):
                # Patch get_statistics
                with patch.object(self.analyzer, 'get_statistics', 
                                 return_value={'total_modules_monitored': 10, 'suspicious_modules': 0}):
                    # Run scan
                    result = self.analyzer.run_scan()
                    
                    # Verify result
                    self.assertIn('timestamp', result)
                    self.assertIn('scan_time_seconds', result)
                    self.assertIn('total_changes', result)
                    self.assertIn('threat_level', result)
                    self.assertIn('module_changes', result)
                    self.assertIn('rootkit_detection', result)
                    self.assertIn('statistics', result)
                    
                    # Verify threat level is low when no issues detected
                    self.assertEqual(result['threat_level'], 'low')

if __name__ == '__main__':
    unittest.main()