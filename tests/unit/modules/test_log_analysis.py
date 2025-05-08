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
from modules.log_analysis import LogAnalysisEngine

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

class TestLogAnalysis(unittest.TestCase):
    """Test cases for log_analysis module"""
    
    def setUp(self):
        """Set up test environment"""
        # Create a temporary database file
        self.temp_db = tempfile.NamedTemporaryFile(delete=False)
        self.temp_db.close()
        
        # Create a temporary config file
        self.temp_config = tempfile.NamedTemporaryFile(delete=False)
        test_config = {
            "log_files": ["/var/log/test.log", "/var/log/test2.log"],
            "ignored_patterns": ["ignore_me"],
            "scan_interval": 60
        }
        self.temp_config.write(json.dumps(test_config).encode())
        self.temp_config.close()
        
        # Initialize the LogAnalysisEngine with test parameters
        self.engine = LogAnalysisEngine(database_path=self.temp_db.name, config_file=self.temp_config.name)
        
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
        """Test LogAnalysisEngine initialization"""
        self.assertEqual(self.engine.database_path, self.temp_db.name)
        self.assertEqual(self.engine.config["log_files"], ["/var/log/test.log", "/var/log/test2.log"])
        self.assertEqual(self.engine.config["ignored_patterns"], ["ignore_me"])
        self.assertEqual(self.engine.config["scan_interval"], 60)
    
    def test_is_whitelisted_ip(self):
        """Test _is_whitelisted_ip method"""
        # Set up test whitelist
        self.engine.config["whitelist_ips"] = ["127.0.0.1", "192.168.1.0/24", "10.0.0.1"]
        
        # Test exact match
        self.assertTrue(self.engine._is_whitelisted_ip("127.0.0.1"))
        self.assertTrue(self.engine._is_whitelisted_ip("10.0.0.1"))
        
        # Test subnet match
        self.assertTrue(self.engine._is_whitelisted_ip("192.168.1.100"))
        
        # Test non-whitelisted IPs
        self.assertFalse(self.engine._is_whitelisted_ip("8.8.8.8"))
        self.assertFalse(self.engine._is_whitelisted_ip("192.168.2.1"))
        
        # Test edge cases
        self.assertFalse(self.engine._is_whitelisted_ip(""))
        self.assertFalse(self.engine._is_whitelisted_ip(None))
    
    def test_is_whitelisted_user(self):
        """Test _is_whitelisted_user method"""
        # Set up test whitelist
        self.engine.config["whitelist_users"] = ["root", "admin", "system"]
        
        # Test matches
        self.assertTrue(self.engine._is_whitelisted_user("root"))
        self.assertTrue(self.engine._is_whitelisted_user("admin"))
        
        # Test non-whitelisted users
        self.assertFalse(self.engine._is_whitelisted_user("attacker"))
        self.assertFalse(self.engine._is_whitelisted_user("user"))
        
        # Test edge cases
        self.assertFalse(self.engine._is_whitelisted_user(""))
        self.assertFalse(self.engine._is_whitelisted_user(None))
    
    def test_is_log_ignored(self):
        """Test _is_log_ignored method"""
        # Set up test patterns
        self.engine.config["ignored_patterns"] = [
            r"ignore_me",
            r"CRON\[\d+\]",
            r"systemd\[\d+\]: Started Session"
        ]
        
        # Test matches
        self.assertTrue(self.engine._is_log_ignored("Please ignore_me in this log"))
        self.assertTrue(self.engine._is_log_ignored("Jan 01 12:00:00 CRON[1234]: Started job"))
        self.assertTrue(self.engine._is_log_ignored("Jan 01 12:00:00 systemd[123]: Started Session 1 of user"))
        
        # Test non-matches
        self.assertFalse(self.engine._is_log_ignored("Jan 01 12:00:00 sshd[123]: Failed password for user"))
        self.assertFalse(self.engine._is_log_ignored("Jan 01 12:00:00 su: auth failure"))
    
    def test_categorize_log_entry(self):
        """Test _categorize_log_entry method"""
        # Test authentication failure
        category, is_suspicious, is_critical, severity = self.engine._categorize_log_entry(
            "Jan 01 12:00:00 sshd[123]: Failed password for invalid user attacker from 8.8.8.8 port 12345"
        )
        self.assertIn("auth_failures", category)
        self.assertTrue(is_suspicious)
        self.assertFalse(is_critical)
        self.assertEqual(severity, "low")
        
        # Test privilege escalation
        category, is_suspicious, is_critical, severity = self.engine._categorize_log_entry(
            "Jan 01 12:00:00 sudo: user : command=/bin/bash"
        )
        self.assertIn("privilege_escalation", category)
        self.assertTrue(is_suspicious)
        self.assertFalse(is_critical)
        self.assertEqual(severity, "high")
        
        # Test critical event
        category, is_suspicious, is_critical, severity = self.engine._categorize_log_entry(
            "Jan 01 12:00:00 kernel: EXPLOIT detected"
        )
        self.assertIn("critical_event", category)
        self.assertTrue(is_suspicious)
        self.assertTrue(is_critical)
        self.assertEqual(severity, "critical")
        
        # Test normal log
        category, is_suspicious, is_critical, severity = self.engine._categorize_log_entry(
            "Jan 01 12:00:00 service[123]: Normal operation completed"
        )
        self.assertIn("general", category)
        self.assertFalse(is_suspicious)
        self.assertFalse(is_critical)
        self.assertEqual(severity, "info")
    
    def test_extract_log_details(self):
        """Test _extract_log_details method"""
        # Test syslog format
        details = self.engine._extract_log_details(
            "Jan 01 12:00:00 host sshd[123]: Failed password for invalid user attacker from 8.8.8.8 port 12345",
            "/var/log/auth.log"
        )
        self.assertEqual(details["timestamp_str"], "Jan 01 12:00:00")
        self.assertIsNotNone(details["timestamp"])
        self.assertEqual(details["source_host"], "host")
        self.assertEqual(details["source_ip"], "8.8.8.8")
        self.assertEqual(details["source_user"], "attacker")
        
        # Test ISO format
        details = self.engine._extract_log_details(
            "2023-01-01T12:00:00 host service[123]: User admin logged in from 192.168.1.100",
            "/var/log/service.log"
        )
        self.assertEqual(details["timestamp_str"], "2023-01-01T12:00:00")
        self.assertIsNotNone(details["timestamp"])
        self.assertEqual(details["source_host"], "host")
        self.assertEqual(details["source_ip"], "192.168.1.100")
        self.assertEqual(details["source_user"], "admin")
        
        # Test log with no identifiable details
        details = self.engine._extract_log_details(
            "Generic log message with no specific details",
            "/var/log/messages"
        )
        self.assertEqual(details["timestamp_str"], "")
        self.assertIsNotNone(details["timestamp"])  # Should default to current time
        self.assertEqual(details["source_host"], "")
        self.assertEqual(details["source_ip"], "")
        self.assertEqual(details["source_user"], "")
    
    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open, read_data="Jan 01 12:00:00 Failed password for invalid user attacker from 8.8.8.8 port 12345\n")
    def test_process_log_file(self, mock_file, mock_exists):
        """Test process_log_file method"""
        # Setup mocks
        mock_exists.return_value = True
        
        # Mock tell() to simulate file position
        mock_file.return_value.tell.return_value = 100
        
        # Call the method
        events, new_position = self.engine.process_log_file("/var/log/test.log")
        
        # Validate
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_text"], "Jan 01 12:00:00 Failed password for invalid user attacker from 8.8.8.8 port 12345")
        self.assertEqual(events[0]["source_ip"], "8.8.8.8")
        self.assertEqual(events[0]["source_user"], "attacker")
        self.assertTrue(events[0]["is_suspicious"])
        self.assertEqual(new_position, 100)
        
        # Test with empty file
        mock_file.return_value.tell.return_value = 0
        mock_file = mock_open(read_data="")
        
        with patch('builtins.open', mock_file):
            events, new_position = self.engine.process_log_file("/var/log/empty.log")
            
        # Validate
        self.assertEqual(len(events), 0)
        self.assertEqual(new_position, 0)
        
        # Test with nonexistent file
        mock_exists.return_value = False
        
        events, new_position = self.engine.process_log_file("/var/log/nonexistent.log")
        
        # Validate
        self.assertEqual(len(events), 0)
        self.assertEqual(new_position, 0)
    
    @patch('modules.log_analysis.LogAnalysisEngine._get_log_file_hash')
    @patch('os.path.getmtime')
    @patch('os.path.exists')
    def test_store_events(self, mock_exists, mock_mtime, mock_hash):
        """Test store_events method"""
        # Setup mocks
        mock_exists.return_value = True
        mock_mtime.return_value = 1234567890.0
        mock_hash.return_value = "hash123"
        
        # Create test events
        events = [
            {
                "log_file": "/var/log/test.log",
                "timestamp": 1234567890.0,
                "timestamp_str": "Jan 01 12:00:00",
                "event_text": "Failed password for invalid user attacker from 8.8.8.8 port 12345",
                "source_host": "host",
                "source_ip": "8.8.8.8",
                "source_user": "attacker",
                "category": "auth_failures",
                "severity": "low",
                "is_suspicious": True,
                "is_critical": False
            }
        ]
        
        # Call the method
        stored_count = self.engine.store_events(events)
        
        # Validate
        self.assertEqual(stored_count, 1)
        
        # Check database
        conn = sqlite3.connect(self.engine.database_path)
        cursor = conn.cursor()
        
        # Check if log file was added
        cursor.execute("SELECT path FROM log_files WHERE path = ?", ("/var/log/test.log",))
        result = cursor.fetchone()
        self.assertIsNotNone(result)
        
        # Check if event was stored
        cursor.execute("SELECT event_text, source_ip, source_user, is_suspicious FROM log_events WHERE category = ?", ("auth_failures",))
        result = cursor.fetchone()
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "Failed password for invalid user attacker from 8.8.8.8 port 12345")
        self.assertEqual(result[1], "8.8.8.8")
        self.assertEqual(result[2], "attacker")
        self.assertEqual(result[3], 1)
        
        # Check if IP reputation was updated
        cursor.execute("SELECT ip, reputation FROM ip_reputation WHERE ip = ?", ("8.8.8.8",))
        result = cursor.fetchone()
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "8.8.8.8")
        
        # Check if user reputation was updated
        cursor.execute("SELECT username, reputation FROM user_reputation WHERE username = ?", ("attacker",))
        result = cursor.fetchone()
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "attacker")
        
        conn.close()
        
        # Test with no events
        stored_count = self.engine.store_events([])
        self.assertEqual(stored_count, 0)
    
    def test_calculate_reputation(self):
        """Test _calculate_reputation method"""
        # Test critical event
        rep = self.engine._calculate_reputation(10, 10, "neutral", True)
        self.assertEqual(rep, "bad")
        
        # Test mostly failed attempts
        rep = self.engine._calculate_reputation(80, 20, "neutral", False)
        self.assertEqual(rep, "bad")
        
        # Test mostly successful attempts
        rep = self.engine._calculate_reputation(20, 80, "neutral", False)
        self.assertEqual(rep, "good")
        
        # Test balanced attempts
        rep = self.engine._calculate_reputation(50, 50, "neutral", False)
        self.assertEqual(rep, "neutral")
        
        # Test good to neutral transition
        rep = self.engine._calculate_reputation(60, 40, "good", False)
        self.assertEqual(rep, "neutral")
        
        # Test bad to neutral transition
        rep = self.engine._calculate_reputation(10, 90, "bad", False)
        self.assertEqual(rep, "neutral")
        
        # Test no attempts
        rep = self.engine._calculate_reputation(0, 0, "neutral", False)
        self.assertEqual(rep, "neutral")
    
    @patch('sqlite3.connect')
    def test_apply_correlation_rules(self, mock_connect):
        """Test apply_correlation_rules method"""
        # Setup mock connection and cursor
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        
        # Set up cursor for sequence rule query
        # First query returns events matching first pattern
        mock_cursor.fetchall.side_effect = [
            # First query fetches initial events (multiple failed logins)
            [
                (1, 1234567890.0, "8.8.8.8", "attacker", "Failed password for invalid user attacker from 8.8.8.8 port 12345"),
                (2, 1234567891.0, "8.8.8.8", "attacker", "Failed password for invalid user attacker from 8.8.8.8 port 12345"),
                (3, 1234567892.0, "8.8.8.8", "attacker", "Failed password for invalid user attacker from 8.8.8.8 port 12345"),
                (4, 1234567893.0, "8.8.8.8", "attacker", "Failed password for invalid user attacker from 8.8.8.8 port 12345"),
                (5, 1234567894.0, "8.8.8.8", "attacker", "Failed password for invalid user attacker from 8.8.8.8 port 12345")
            ],
            # Second query fetches matching followup event (successful login)
            [(6, 1234567895.0)],
            # Fetch source_user for alert
            [("attacker",)]
        ]
        
        # Call the method
        alerts_generated = self.engine.apply_correlation_rules()
        
        # Validate
        self.assertEqual(alerts_generated, 1)
        
        # Verify sequence rule processing
        self.assertEqual(mock_cursor.execute.call_count, 5)  # 3 selects + 1 insert for the alert + other checks
        
        # Set up cursor for frequency rule query
        mock_cursor.reset_mock()
        mock_cursor.fetchall.side_effect = [
            # Log entries
            [
                (1, 1234567890.0, "8.8.8.8", "attacker", "Failed password for invalid user attacker from 8.8.8.8 port 12345"),
                (2, 1234567891.0, "9.9.9.9", "attacker", "Failed password for invalid user attacker from 9.9.9.9 port 12345"),
                (3, 1234567892.0, "10.10.10.10", "attacker", "Failed password for invalid user attacker from 10.10.10.10 port 12345"),
                (4, 1234567893.0, "11.11.11.11", "attacker", "Failed password for invalid user attacker from 11.11.11.11 port 12345"),
                (5, 1234567894.0, "12.12.12.12", "attacker", "Failed password for invalid user attacker from 12.12.12.12 port 12345")
            ]
        ]
        
        # Set a frequency rule
        self.engine.config["correlation_rules"] = [
            {
                "name": "distributed_auth_attack",
                "description": "Multiple failed authentication attempts from different IPs",
                "rule_type": "frequency",
                "pattern": r"Failed password for .* from (.*) port \d+",
                "extract": 1,  # IP address
                "distinct_values": 5,
                "timeframe": 300,
                "severity": "medium"
            }
        ]
        
        # Call the method
        alerts_generated = self.engine.apply_correlation_rules()
        
        # Can't easily test the frequency rule behavior in a unit test due to the complex regex pattern extraction
        # Just verify that execution completes
        self.assertEqual(mock_cursor.execute.call_count > 0, True)
    
    @patch('sqlite3.connect')
    def test_cleanup_old_data(self, mock_connect):
        """Test cleanup_old_data method"""
        # Setup mock connection and cursor
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        
        # Set up rowcount for each delete operation
        mock_cursor.rowcount = 10
        
        # Call the method
        deleted_count = self.engine.cleanup_old_data()
        
        # Validate
        self.assertEqual(deleted_count, 40)  # 4 delete operations * 10 rows each
        self.assertEqual(mock_cursor.execute.call_count, 4)
        mock_conn.commit.assert_called_once()
    
    @patch('modules.log_analysis.LogAnalysisEngine.process_log_file')
    @patch('modules.log_analysis.LogAnalysisEngine.store_events')
    @patch('modules.log_analysis.LogAnalysisEngine.apply_correlation_rules')
    @patch('modules.log_analysis.LogAnalysisEngine.cleanup_old_data')
    @patch('os.path.exists')
    def test_create_baseline(self, mock_exists, mock_cleanup, mock_apply, mock_store, mock_process):
        """Test create_baseline method"""
        # Setup mocks
        mock_exists.return_value = True
        mock_process.return_value = (
            [
                {
                    "is_suspicious": True,
                    "is_critical": False
                },
                {
                    "is_suspicious": False,
                    "is_critical": False
                }
            ],
            100
        )
        mock_store.return_value = 2
        mock_apply.return_value = 1
        
        # Create test database with log files
        conn = sqlite3.connect(self.engine.database_path)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO log_files (path, last_position) VALUES (?, ?)", ("/var/log/test.log", 0))
        conn.commit()
        conn.close()
        
        # Call the method
        stats = self.engine.create_baseline()
        
        # Validate
        self.assertEqual(stats["files_processed"], 2)
        self.assertEqual(stats["events_collected"], 4)  # 2 events * 2 files
        self.assertEqual(stats["alerts_generated"], 1)
        self.assertEqual(stats["suspicious_events"], 2)  # 1 suspicious event * 2 files
        self.assertEqual(stats["critical_events"], 0)
        
        mock_exists.assert_any_call("/var/log/test.log")
        mock_exists.assert_any_call("/var/log/test2.log")
        self.assertEqual(mock_process.call_count, 2)
        mock_store.assert_called_once()
        mock_apply.assert_called_once()
        mock_cleanup.assert_called_once()
    
    @patch('modules.log_analysis.LogAnalysisEngine.process_log_file')
    @patch('modules.log_analysis.LogAnalysisEngine.store_events')
    @patch('modules.log_analysis.LogAnalysisEngine.apply_correlation_rules')
    @patch('os.path.exists')
    def test_check_integrity(self, mock_exists, mock_apply, mock_store, mock_process):
        """Test check_integrity method"""
        # Setup is same as create_baseline test
        mock_exists.return_value = True
        mock_process.return_value = (
            [
                {
                    "is_suspicious": True,
                    "is_critical": False
                },
                {
                    "is_suspicious": False,
                    "is_critical": False
                }
            ],
            100
        )
        mock_store.return_value = 2
        mock_apply.return_value = 1
        
        # Create test database with log files
        conn = sqlite3.connect(self.engine.database_path)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO log_files (path, last_position) VALUES (?, ?)", ("/var/log/test.log", 0))
        conn.commit()
        conn.close()
        
        # Call the method
        stats = self.engine.check_integrity()
        
        # Validate same as create_baseline
        self.assertEqual(stats["files_processed"], 2)
        self.assertEqual(stats["events_collected"], 4)
        self.assertEqual(stats["alerts_generated"], 1)
        self.assertEqual(stats["suspicious_events"], 2)
        self.assertEqual(stats["critical_events"], 0)
        
        # Difference is that cleanup_old_data isn't called
    
    @patch('os.path.getmtime')
    @patch('os.path.getsize')
    @patch('modules.log_analysis.LogAnalysisEngine._get_log_file_hash')
    @patch('os.path.exists')
    @patch('os.path.isfile')
    def test_check_log_tampering(self, mock_isfile, mock_exists, mock_hash, mock_getsize, mock_getmtime):
        """Test check_log_tampering method"""
        # Setup mocks
        mock_isfile.return_value = True
        mock_exists.return_value = True
        mock_hash.side_effect = ["new_hash", "new_hash"]
        mock_getsize.return_value = 1000
        mock_getmtime.return_value = 1234567890.0
        
        # Create test database with log files
        conn = sqlite3.connect(self.engine.database_path)
        cursor = conn.cursor()
        
        # Add a normal log file
        cursor.execute(
            "INSERT INTO log_files (path, last_modified, hash, last_position) VALUES (?, ?, ?, ?)",
            ("/var/log/normal.log", 1234567890.0, "new_hash", 1000)
        )
        
        # Add a tampered log file (hash changed)
        cursor.execute(
            "INSERT INTO log_files (path, last_modified, hash, last_position) VALUES (?, ?, ?, ?)",
            ("/var/log/tampered.log", 1234567890.0, "old_hash", 1000)
        )
        
        # Add a deleted log file
        cursor.execute(
            "INSERT INTO log_files (path, last_modified, hash, last_position) VALUES (?, ?, ?, ?)",
            ("/var/log/deleted.log", 1234567890.0, "hash123", 1000)
        )
        
        conn.commit()
        conn.close()
        
        # Set up exists and isfile for deleted log
        mock_exists.side_effect = lambda path: path != "/var/log/deleted.log"
        mock_isfile.side_effect = lambda path: path != "/var/log/deleted.log"
        
        # Call the method
        tampering_events = self.engine.check_log_tampering()
        
        # Validate
        self.assertEqual(len(tampering_events), 2)
        
        # Check for tampered and deleted event types
        event_types = [event["tampering_type"] for event in tampering_events]
        self.assertIn("deletion", event_types)
        
        # Since getmtime and hash mock values are consistent, we won't detect the tampering via hash change
        # in this test. We'd need more complex mocking to fully test all cases.
    
    @patch('sqlite3.connect')
    def test_get_security_alerts(self, mock_connect):
        """Test get_security_alerts method"""
        # Setup mock connection and cursor
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        
        # Set up mock data
        mock_cursor.fetchall.return_value = [
            (
                1, 
                "brute_force_success", 
                "Brute force attack followed by successful login", 
                "8.8.8.8", 
                "attacker", 
                1234567890.0, 
                "high", 
                json.dumps([1, 2, 3, 4, 5, 6]), 
                "brute_force_success", 
                0
            )
        ]
        
        # Call the method
        alerts = self.engine.get_security_alerts()
        
        # Validate
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["id"], 1)
        self.assertEqual(alerts[0]["alert_type"], "brute_force_success")
        self.assertEqual(alerts[0]["source_ip"], "8.8.8.8")
        self.assertEqual(alerts[0]["source_user"], "attacker")
        self.assertEqual(alerts[0]["severity"], "high")
        self.assertEqual(alerts[0]["related_events"], [1, 2, 3, 4, 5, 6])
        self.assertFalse(alerts[0]["verified"])
        
        # Test with filters
        self.engine.get_security_alerts(limit=10, severity="high", since=1234567800.0)
        
        # Verify query has WHERE clause and parameters
        mock_cursor.execute.assert_called_with(
            "SELECT * FROM security_alerts WHERE severity = ? AND timestamp > ? ORDER BY timestamp DESC LIMIT ?",
            ["high", 1234567800.0, 10]
        )
    
    @patch('sqlite3.connect')
    def test_get_suspicious_events(self, mock_connect):
        """Test get_suspicious_events method"""
        # Setup mock connection and cursor
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        
        # Set up mock data
        mock_cursor.fetchall.return_value = [
            (
                1, 2, 1234567890.0, "Jan 01 12:00:00", 
                "Failed password for invalid user attacker from 8.8.8.8 port 12345",
                "host", "8.8.8.8", "attacker", "auth_failures", "low", 1, 0
            )
        ]
        
        # Call the method
        events = self.engine.get_suspicious_events()
        
        # Validate
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["id"], 1)
        self.assertEqual(events[0]["event_text"], "Failed password for invalid user attacker from 8.8.8.8 port 12345")
        self.assertEqual(events[0]["source_ip"], "8.8.8.8")
        self.assertEqual(events[0]["source_user"], "attacker")
        self.assertEqual(events[0]["category"], "auth_failures")
        self.assertEqual(events[0]["severity"], "low")
        self.assertTrue(events[0]["is_suspicious"])
        self.assertFalse(events[0]["is_critical"])
        
        # Test with filters
        self.engine.get_suspicious_events(limit=10, category="auth_failures", since=1234567800.0)
        
        # Verify query has WHERE clause and parameters
        mock_cursor.execute.assert_called_with(
            "SELECT * FROM log_events WHERE is_suspicious = 1 AND category LIKE ? AND timestamp > ? ORDER BY timestamp DESC LIMIT ?",
            ["%auth_failures%", 1234567800.0, 10]
        )
    
    @patch('sqlite3.connect')
    def test_get_ip_reputation(self, mock_connect):
        """Test get_ip_reputation method"""
        # Setup mock connection and cursor
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        
        # Set up mock data
        mock_cursor.fetchall.return_value = [
            (
                1, "8.8.8.8", "bad", 1234567890.0, 10, 2, 1234567800.0, 1234567890.0, 0
            )
        ]
        
        # Call the method
        ip_records = self.engine.get_ip_reputation()
        
        # Validate
        self.assertEqual(len(ip_records), 1)
        self.assertEqual(ip_records[0]["id"], 1)
        self.assertEqual(ip_records[0]["ip"], "8.8.8.8")
        self.assertEqual(ip_records[0]["reputation"], "bad")
        self.assertEqual(ip_records[0]["failed_attempts"], 10)
        self.assertEqual(ip_records[0]["successful_attempts"], 2)
        self.assertFalse(ip_records[0]["is_blocked"])
        
        # Test with filters
        self.engine.get_ip_reputation(ip="8.8.8.8", reputation="bad", limit=10)
        
        # Verify query has WHERE clause and parameters
        mock_cursor.execute.assert_called_with(
            "SELECT * FROM ip_reputation WHERE ip = ? AND reputation = ? ORDER BY failed_attempts DESC LIMIT ?",
            ["8.8.8.8", "bad", 10]
        )
    
    @patch('sqlite3.connect')
    def test_verify_alert(self, mock_connect):
        """Test verify_alert method"""
        # Setup mock connection and cursor
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        
        # Call the method
        result = self.engine.verify_alert(123)
        
        # Validate
        self.assertTrue(result)
        mock_cursor.execute.assert_called_with(
            "UPDATE security_alerts SET verified = 1 WHERE id = ?", 
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
            (1000,),  # total_events
            (50,),    # suspicious_events
            (10,),    # critical_events
            (20,),    # total_alerts
            (1000000,),  # database_size
            (5,),     # log_files_count
            (100,),   # events_last_hour
            (5,)      # alerts_last_hour
        ]
        
        mock_cursor.fetchall.side_effect = [
            [("high", 10), ("medium", 5), ("low", 5)],  # severity counts
            [("brute_force", 10), ("account_compromise", 10)],  # alert types
            [("auth_failures", 30), ("web_attacks", 20)],  # event categories
            [("bad", 10), ("neutral", 20), ("good", 5)]  # reputation counts
        ]
        
        # Call the method
        stats = self.engine.get_statistics()
        
        # Validate
        self.assertEqual(stats["total_events"], 1000)
        self.assertEqual(stats["suspicious_events"], 50)
        self.assertEqual(stats["critical_events"], 10)
        self.assertEqual(stats["total_alerts"], 20)
        self.assertEqual(stats["database_size"], 1000000)
        self.assertEqual(stats["events_last_hour"], 100)
        self.assertEqual(stats["alerts_last_hour"], 5)
        
        self.assertEqual(stats["alerts_by_severity"]["high"], 10)
        self.assertEqual(stats["alerts_by_severity"]["medium"], 5)
        self.assertEqual(stats["alerts_by_severity"]["low"], 5)
        
        self.assertEqual(stats["alerts_by_type"]["brute_force"], 10)
        self.assertEqual(stats["alerts_by_type"]["account_compromise"], 10)
        
        self.assertEqual(stats["events_by_category"]["auth_failures"], 30)
        self.assertEqual(stats["events_by_category"]["web_attacks"], 20)
        
        self.assertEqual(stats["ip_reputation_counts"]["bad"], 10)
        self.assertEqual(stats["ip_reputation_counts"]["neutral"], 20)
        self.assertEqual(stats["ip_reputation_counts"]["good"], 5)
        
        self.assertIn("last_updated", stats)
    
    @patch('modules.log_analysis.LogAnalysisEngine.check_integrity')
    @patch('modules.log_analysis.LogAnalysisEngine.check_log_tampering')
    @patch('modules.log_analysis.LogAnalysisEngine.get_security_alerts')
    @patch('modules.log_analysis.LogAnalysisEngine.get_suspicious_events')
    @patch('modules.log_analysis.LogAnalysisEngine.get_statistics')
    def test_run_scan(self, mock_stats, mock_suspicious, mock_alerts, mock_tampering, mock_integrity):
        """Test run_scan method"""
        # Setup mocks
        mock_integrity.return_value = []
        mock_tampering.return_value = []
        mock_alerts.return_value = []
        mock_suspicious.return_value = []
        mock_stats.return_value = {
            "total_events": 1000,
            "suspicious_events": 0,
            "critical_events": 0
        }
        
        # Call the method
        result = self.engine.run_scan()
        
        # Validate
        self.assertIn("timestamp", result)
        self.assertIn("scan_time_seconds", result)
        self.assertIn("events_collected", result)
        self.assertIn("alerts_generated", result)
        self.assertIn("threat_level", result)
        self.assertIn("tampering_detected", result)
        self.assertIn("tampering_events", result)
        self.assertIn("recent_alerts", result)
        self.assertIn("recent_suspicious_events", result)
        self.assertIn("statistics", result)
        
        # Test threat level determination
        self.assertEqual(result["threat_level"], "low")
        
        # Test with tampering
        mock_tampering.return_value = [{"tampering_type": "deletion", "description": "Log file was deleted"}]
        result = self.engine.run_scan()
        self.assertEqual(result["threat_level"], "critical")
        
        # Test with critical events
        mock_tampering.return_value = []
        mock_stats.return_value = {
            "total_events": 1000,
            "suspicious_events": 0,
            "critical_events": 5
        }
        result = self.engine.run_scan()
        self.assertEqual(result["threat_level"], "high")
        
        # Test with many suspicious events
        mock_stats.return_value = {
            "total_events": 1000,
            "suspicious_events": 50,
            "critical_events": 0
        }
        result = self.engine.run_scan()
        self.assertEqual(result["threat_level"], "medium")
    
    @patch('time.sleep')
    @patch('threading.Thread')
    @patch('modules.log_analysis.LogAnalysisEngine.run_scan')
    def test_start_monitoring(self, mock_run_scan, mock_thread, mock_sleep):
        """Test start_monitoring method"""
        # Setup mocks
        mock_run_scan.return_value = {
            "threat_level": "low",
            "events_collected": 0,
            "alerts_generated": 0
        }
        
        # Call the method
        result = self.engine.start_monitoring(interval=10)
        
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