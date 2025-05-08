#!/usr/bin/env python3
"""
ScheduledTasksAnalyzer Module
Detects suspicious or malicious scheduled tasks, cron jobs, systemd timers and other scheduling mechanisms.
"""

import os
import re
import logging
import subprocess
import json
import time
import hashlib
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict
import pwd
import grp

class ScheduledTasksAnalyzer:
    """
    Scheduled Tasks Analysis module for detecting malicious scheduled tasks in Linux systems
    
    Analyzes various scheduling mechanisms including:
    - Cron jobs (system and user crontabs)
    - Systemd timers
    - At jobs
    - Anacron jobs
    - Custom scheduling scripts in init.d, cron.d, etc.
    
    Identifies suspicious tasks based on:
    - Command content (suspicious commands, obfuscation, network activity)
    - Execution time patterns (unusual times, high frequency)
    - User permissions and ownership
    - Hidden or obfuscated tasks
    - Newly added or modified tasks
    """
    
    def __init__(self, config=None):
        """
        Initialize the Scheduled Tasks Analyzer
        
        Args:
            config (dict): Configuration dictionary
        """
        self.logger = logging.getLogger("sharpeye.scheduled_tasks")
        self.config = config or {}
        
        # Initialize database path
        if 'database_path' in self.config:
            self.database_path = self.config['database_path']
        else:
            home_dir = os.path.expanduser("~")
            self.database_path = os.path.join(home_dir, ".sharpeye", "scheduled_tasks.db")
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.database_path), exist_ok=True)
        
        # Set up configuration parameters
        self.setup_configuration()
        
        # Initialize the database
        self._initialize_database()
    
    def setup_configuration(self):
        """Set up configuration parameters with defaults if not provided"""
        # Common cron job locations
        self.crontab_files = self.config.get('crontab_files', [
            '/etc/crontab',
            '/var/spool/cron/crontabs',
            '/etc/cron.d',
            '/etc/cron.hourly',
            '/etc/cron.daily',
            '/etc/cron.weekly',
            '/etc/cron.monthly'
        ])
        
        # Systemd timer locations
        self.systemd_timer_paths = self.config.get('systemd_timer_paths', [
            '/etc/systemd/system',
            '/usr/lib/systemd/system',
            '/lib/systemd/system',
            '/run/systemd/system'
        ])
        
        # At job locations
        self.at_job_paths = self.config.get('at_job_paths', [
            '/var/spool/at',
            '/var/spool/atjobs'
        ])
        
        # Anacron job locations
        self.anacron_paths = self.config.get('anacron_paths', [
            '/etc/anacrontab',
            '/var/spool/anacron'
        ])
        
        # Other scheduled task locations
        self.other_task_paths = self.config.get('other_task_paths', [
            '/etc/init.d',
            '/etc/rc.d'
        ])
        
        # Suspicious commands to look for in tasks
        self.suspicious_commands = self.config.get('suspicious_commands', [
            # Network commands
            'wget', 'curl', 'nc', 'netcat', 'ncat', 'ssh', 'scp', 'ftp', 'telnet',
            # Shell commands for reverse shells
            'bash -i', 'sh -i', 'python -c', 'perl -e', 'ruby -e', 'php -r',
            # Data exfiltration
            'tar ', 'zip ', 'gzip', 'bzip2', '| mail', 'base64',
            # Privilege escalation
            'sudo', 'su', 'chmod +s', 'chmod u+s', 'chmod 4777', 'chmod 2777',
            # Obfuscation techniques
            '`', '$(', '\\x', '\\u', 'eval', 'exec', 'base64 -d', 'base64 --decode',
            # Execution from unusual locations
            '/tmp/', '/dev/shm/', '/var/tmp/', '/var/spool/samba/',
            # Cryptocurrency miners
            'miner', 'xmr', 'monero', 'cryptonight', 'crypto', 'stratum+tcp',
            # Other suspicious patterns
            '> /dev/null', '2>&1', 'mkfifo', '>& /dev/null', '&>/dev/null'
        ])
        
        # Known legitimate scheduled tasks (whitelist)
        self.whitelist_patterns = self.config.get('whitelist_patterns', [
            # Common system tasks
            '/etc/cron.daily/logrotate',
            '/etc/cron.daily/man-db',
            '/etc/cron.daily/mlocate',
            '/etc/cron.daily/updatedb',
            'logrotate',
            'tmpwatch',
            'backup',
            # Add more common legitimate cron jobs here
        ])
        
        # Suspicious time patterns (e.g., middle of the night)
        self.suspicious_time_patterns = self.config.get('suspicious_time_patterns', [
            # Format: (hour_start, hour_end)
            (1, 4)  # 1 AM to 4 AM is considered suspicious
        ])
        
        # High frequency patterns (multiple executions per hour)
        self.high_frequency_threshold = self.config.get('high_frequency_threshold', 6)  # More than once every 10 minutes
        
        # Maximum allowed changes per task between scans
        self.max_allowed_changes = self.config.get('max_allowed_changes', 3)
        
        # Check for new users with scheduled tasks
        self.check_new_users = self.config.get('check_new_users', True)
        
        # Threshold for script line count to be considered suspicious
        self.script_size_threshold = self.config.get('script_size_threshold', 50)
    
    def _initialize_database(self):
        """Initialize the SQLite database"""
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            # Create scheduled_tasks table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS scheduled_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_type TEXT,
                task_name TEXT,
                user TEXT,
                schedule TEXT,
                command TEXT,
                path TEXT,
                hash TEXT,
                first_seen REAL,
                last_seen REAL,
                is_suspicious INTEGER DEFAULT 0,
                suspicious_reason TEXT,
                UNIQUE(task_type, path, command)
            )
            ''')
            
            # Create task_changes table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS task_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER,
                change_type TEXT,
                old_value TEXT,
                new_value TEXT,
                timestamp REAL,
                FOREIGN KEY (task_id) REFERENCES scheduled_tasks(id)
            )
            ''')
            
            # Create scans table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                new_tasks INTEGER,
                modified_tasks INTEGER,
                removed_tasks INTEGER,
                suspicious_tasks INTEGER,
                is_baseline INTEGER DEFAULT 0,
                summary TEXT
            )
            ''')
            
            # Create indices
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_task_type_path ON scheduled_tasks(task_type, path)
            ''')
            
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_task_changes_task_id ON task_changes(task_id)
            ''')
            
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp)
            ''')
            
            conn.commit()
            
        except Exception as e:
            self.logger.error(f"Failed to initialize database: {e}")
        finally:
            if conn:
                conn.close()
    
    def analyze(self):
        """
        Run a comprehensive analysis of all scheduled tasks
        
        Returns:
            dict: Analysis results
        """
        self.logger.info("Starting scheduled tasks analysis")
        start_time = time.time()
        
        # Initialize results structure
        results = {
            'timestamp': datetime.now().isoformat(),
            'is_anomalous': False,
            'suspicious_tasks': [],
            'new_tasks': [],
            'modified_tasks': [],
            'removed_tasks': [],
            'summary': {
                'total_tasks': 0,
                'suspicious_count': 0,
                'new_count': 0,
                'modified_count': 0,
                'removed_count': 0,
                'cron_tasks': 0,
                'systemd_timers': 0,
                'at_jobs': 0,
                'anacron_tasks': 0,
                'other_tasks': 0
            }
        }
        
        # Collect tasks
        all_tasks = []
        
        # Analyze cron jobs
        cron_tasks = self._analyze_cron_jobs()
        all_tasks.extend(cron_tasks)
        results['summary']['cron_tasks'] = len(cron_tasks)
        
        # Analyze systemd timers
        systemd_tasks = self._analyze_systemd_timers()
        all_tasks.extend(systemd_tasks)
        results['summary']['systemd_timers'] = len(systemd_tasks)
        
        # Analyze at jobs
        at_jobs = self._analyze_at_jobs()
        all_tasks.extend(at_jobs)
        results['summary']['at_jobs'] = len(at_jobs)
        
        # Analyze anacron jobs
        anacron_tasks = self._analyze_anacron_jobs()
        all_tasks.extend(anacron_tasks)
        results['summary']['anacron_tasks'] = len(anacron_tasks)
        
        # Analyze other scheduling mechanisms
        other_tasks = self._analyze_other_tasks()
        all_tasks.extend(other_tasks)
        results['summary']['other_tasks'] = len(other_tasks)
        
        # Process all collected tasks
        for task in all_tasks:
            # Check if task is suspicious
            is_suspicious, reason = self._check_task_suspicious(task)
            if is_suspicious:
                task['is_suspicious'] = True
                task['suspicious_reason'] = reason
                results['suspicious_tasks'].append(task)
        
        # Compare with baseline if available
        if self._has_baseline():
            baseline_comparison = self._compare_with_baseline(all_tasks)
            results['new_tasks'] = baseline_comparison.get('new_tasks', [])
            results['modified_tasks'] = baseline_comparison.get('modified_tasks', [])
            results['removed_tasks'] = baseline_comparison.get('removed_tasks', [])
            
            # Update summary counts
            results['summary']['new_count'] = len(results['new_tasks'])
            results['summary']['modified_count'] = len(results['modified_tasks'])
            results['summary']['removed_count'] = len(results['removed_tasks'])
        
        # Update database with current tasks
        self._update_database(all_tasks, results)
        
        # Calculate total and suspicious task counts
        results['summary']['total_tasks'] = len(all_tasks)
        results['summary']['suspicious_count'] = len(results['suspicious_tasks'])
        
        # Determine if anomalies were found
        results['is_anomalous'] = (
            results['summary']['suspicious_count'] > 0 or
            results['summary']['new_count'] > 0 or
            results['summary']['modified_count'] > 0
        )
        
        # Calculate scan time
        scan_time = time.time() - start_time
        results['scan_time'] = scan_time
        
        self.logger.info(f"Scheduled tasks analysis completed in {scan_time:.2f} seconds")
        return results
    
    def _analyze_cron_jobs(self):
        """
        Analyze cron jobs from system and user crontabs
        
        Returns:
            list: Collected cron tasks
        """
        self.logger.debug("Analyzing cron jobs")
        cron_tasks = []
        
        # Check system crontab
        if os.path.exists('/etc/crontab'):
            self._parse_crontab('/etc/crontab', cron_tasks, is_system=True)
        
        # Check system cron directories
        for cron_dir in ['/etc/cron.d', '/etc/cron.hourly', '/etc/cron.daily', 
                        '/etc/cron.weekly', '/etc/cron.monthly']:
            if os.path.exists(cron_dir) and os.path.isdir(cron_dir):
                for filename in os.listdir(cron_dir):
                    filepath = os.path.join(cron_dir, filename)
                    if os.path.isfile(filepath) and not filename.startswith('.'):
                        if cron_dir in ['/etc/cron.hourly', '/etc/cron.daily', 
                                      '/etc/cron.weekly', '/etc/cron.monthly']:
                            # These are scripts executed on a schedule, not crontab files
                            self._parse_scheduled_script(filepath, cron_tasks, cron_dir)
                        else:
                            # These are crontab files
                            self._parse_crontab(filepath, cron_tasks, is_system=True)
        
        # Check user crontabs
        user_crontab_dir = '/var/spool/cron/crontabs'
        if os.path.exists(user_crontab_dir) and os.path.isdir(user_crontab_dir):
            for filename in os.listdir(user_crontab_dir):
                if not filename.startswith('.'):
                    filepath = os.path.join(user_crontab_dir, filename)
                    username = filename  # The filename is the username
                    self._parse_crontab(filepath, cron_tasks, username=username, is_system=False)
        
        return cron_tasks
    
    def _parse_crontab(self, filepath, tasks_list, username=None, is_system=False):
        """
        Parse a crontab file and extract scheduled tasks
        
        Args:
            filepath (str): Path to the crontab file
            tasks_list (list): List to append tasks to
            username (str): Username for user crontabs
            is_system (bool): Whether this is a system crontab
        """
        try:
            with open(filepath, 'r') as f:
                content = f.read()
                
            # Calculate file hash
            file_hash = hashlib.sha256(content.encode()).hexdigest()
            
            # Parse each line
            for line_number, line in enumerate(content.split('\n'), 1):
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Skip environment variables
                if '=' in line and line.split('=')[0].strip().isupper():
                    continue
                
                # Handle @reboot, @daily, etc. format
                if line.startswith('@'):
                    parts = line.split(None, 2)
                    if len(parts) >= 3:
                        schedule_type = parts[0]
                        
                        # For system crontabs, the username is specified in the line
                        if is_system:
                            run_user = parts[1]
                            command = parts[2]
                        else:
                            run_user = username
                            command = parts[1]
                        
                        tasks_list.append({
                            'task_type': 'cron',
                            'task_name': f"{filepath}:{line_number}",
                            'user': run_user,
                            'schedule': schedule_type,
                            'command': command,
                            'path': filepath,
                            'hash': file_hash,
                            'line_number': line_number,
                            'raw': line
                        })
                    continue
                
                # Handle standard crontab format
                parts = line.split()
                if len(parts) >= 6:
                    # Extract schedule components
                    minute, hour, day, month, weekday = parts[:5]
                    
                    # For system crontabs, the username is specified in the line
                    if is_system:
                        run_user = parts[5]
                        command = ' '.join(parts[6:])
                    else:
                        run_user = username
                        command = ' '.join(parts[5:])
                    
                    schedule = f"{minute} {hour} {day} {month} {weekday}"
                    
                    tasks_list.append({
                        'task_type': 'cron',
                        'task_name': f"{filepath}:{line_number}",
                        'user': run_user,
                        'schedule': schedule,
                        'command': command,
                        'path': filepath,
                        'hash': file_hash,
                        'line_number': line_number,
                        'raw': line
                    })
        except Exception as e:
            self.logger.error(f"Error parsing crontab {filepath}: {e}")
    
    def _parse_scheduled_script(self, filepath, tasks_list, directory):
        """
        Parse a scheduled script from cron.hourly, cron.daily, etc.
        
        Args:
            filepath (str): Path to the script file
            tasks_list (list): List to append tasks to
            directory (str): Directory containing the script
        """
        try:
            # Get file owner
            stat_info = os.stat(filepath)
            uid = stat_info.st_uid
            try:
                username = pwd.getpwuid(uid).pw_name
            except KeyError:
                username = str(uid)
            
            # Get file permissions
            permissions = oct(stat_info.st_mode & 0o777)
            
            # Get file content and hash
            with open(filepath, 'rb') as f:
                content = f.read()
                file_hash = hashlib.sha256(content).hexdigest()
            
            # Determine schedule from directory
            schedule = "unknown"
            if 'hourly' in directory:
                schedule = "@hourly"
            elif 'daily' in directory:
                schedule = "@daily"
            elif 'weekly' in directory:
                schedule = "@weekly"
            elif 'monthly' in directory:
                schedule = "@monthly"
            
            # For scripts, the command is the script itself
            command = filepath
            
            tasks_list.append({
                'task_type': 'cron_script',
                'task_name': os.path.basename(filepath),
                'user': username,
                'schedule': schedule,
                'command': command,
                'path': filepath,
                'hash': file_hash,
                'permissions': permissions,
                'content': content.decode('utf-8', errors='replace')
            })
            
        except Exception as e:
            self.logger.error(f"Error parsing scheduled script {filepath}: {e}")
    
    def _analyze_systemd_timers(self):
        """
        Analyze systemd timers
        
        Returns:
            list: Collected systemd timer tasks
        """
        self.logger.debug("Analyzing systemd timers")
        systemd_tasks = []
        
        try:
            # Use systemctl to list timers
            cmd = ["systemctl", "list-timers", "--all"]
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            if proc.returncode != 0:
                self.logger.error(f"Failed to list systemd timers: {proc.stderr}")
                return systemd_tasks
            
            # Parse the output
            lines = proc.stdout.strip().split('\n')
            if len(lines) <= 3:  # Header lines
                return systemd_tasks
                
            # Skip header lines
            in_timer_section = False
            for line in lines:
                if not in_timer_section:
                    if "NEXT" in line and "LEFT" in line and "LAST" in line and "UNIT" in line:
                        in_timer_section = True
                    continue
                
                if not line.strip() or "timers listed" in line:
                    continue
                
                # Extract timer unit name from line
                parts = line.split()
                if len(parts) >= 5:
                    timer_unit = None
                    for i, part in enumerate(parts):
                        if part.endswith('.timer'):
                            timer_unit = part
                            service_unit = parts[i+1] if i+1 < len(parts) else None
                            break
                    
                    if timer_unit:
                        # Use systemctl show to get details about the timer
                        timer_info = self._get_systemd_unit_info(timer_unit)
                        
                        # Get the service unit details if available
                        service_info = {}
                        if service_unit:
                            service_info = self._get_systemd_unit_info(service_unit)
                        
                        # Extract command from service ExecStart
                        command = service_info.get('ExecStart', '').strip()
                        
                        # Extract schedule information from timer
                        schedule = timer_info.get('OnCalendar', timer_info.get('OnBootSec', timer_info.get('OnUnitActiveSec', 'unknown')))
                        
                        # Get unit file paths
                        timer_path = timer_info.get('FragmentPath', '')
                        service_path = service_info.get('FragmentPath', '')
                        
                        # Get file content and hash if path exists
                        timer_hash = ''
                        service_hash = ''
                        timer_content = ''
                        service_content = ''
                        
                        if timer_path and os.path.exists(timer_path):
                            with open(timer_path, 'rb') as f:
                                content = f.read()
                                timer_hash = hashlib.sha256(content).hexdigest()
                                timer_content = content.decode('utf-8', errors='replace')
                        
                        if service_path and os.path.exists(service_path):
                            with open(service_path, 'rb') as f:
                                content = f.read()
                                service_hash = hashlib.sha256(content).hexdigest()
                                service_content = content.decode('utf-8', errors='replace')
                        
                        # Add to tasks list
                        systemd_tasks.append({
                            'task_type': 'systemd_timer',
                            'task_name': timer_unit,
                            'user': service_info.get('User', 'root'),
                            'schedule': schedule,
                            'command': command,
                            'path': timer_path,
                            'hash': timer_hash,
                            'timer_content': timer_content,
                            'service_path': service_path,
                            'service_hash': service_hash,
                            'service_content': service_content,
                            'service_unit': service_unit,
                            'description': timer_info.get('Description', '')
                        })
            
        except Exception as e:
            self.logger.error(f"Error analyzing systemd timers: {e}")
        
        return systemd_tasks
    
    def _get_systemd_unit_info(self, unit_name):
        """
        Get detailed information about a systemd unit
        
        Args:
            unit_name (str): Name of the systemd unit
            
        Returns:
            dict: Unit properties
        """
        unit_info = {}
        
        try:
            cmd = ["systemctl", "show", unit_name]
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            if proc.returncode != 0:
                self.logger.error(f"Failed to get info for unit {unit_name}: {proc.stderr}")
                return unit_info
            
            # Parse the output
            for line in proc.stdout.strip().split('\n'):
                if '=' in line:
                    key, value = line.split('=', 1)
                    unit_info[key] = value
            
            return unit_info
            
        except Exception as e:
            self.logger.error(f"Error getting systemd unit info for {unit_name}: {e}")
            return unit_info
    
    def _analyze_at_jobs(self):
        """
        Analyze at jobs
        
        Returns:
            list: Collected at jobs
        """
        self.logger.debug("Analyzing at jobs")
        at_jobs = []
        
        try:
            # Use 'atq' to list at jobs
            cmd = ["atq"]
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            if proc.returncode != 0:
                # atq might not be installed or no jobs
                self.logger.debug(f"Failed to list at jobs: {proc.stderr}")
                return at_jobs
            
            # Parse the output
            lines = proc.stdout.strip().split('\n')
            for line in lines:
                if not line.strip():
                    continue
                
                parts = line.split()
                if len(parts) >= 5:
                    job_id = parts[0]
                    execution_date = ' '.join(parts[1:5])
                    username = parts[5] if len(parts) > 5 else "unknown"
                    
                    # Try to get job content
                    job_content = self._get_at_job_content(job_id)
                    
                    # Hash the content
                    content_hash = hashlib.sha256(job_content.encode()).hexdigest() if job_content else ""
                    
                    # Add to jobs list
                    at_jobs.append({
                        'task_type': 'at_job',
                        'task_name': f"at_job_{job_id}",
                        'user': username,
                        'schedule': execution_date,
                        'command': job_content.split('\n')[0] if job_content else "unknown",
                        'path': f"/var/spool/at/job_{job_id}",
                        'hash': content_hash,
                        'job_id': job_id,
                        'content': job_content
                    })
            
        except Exception as e:
            self.logger.error(f"Error analyzing at jobs: {e}")
        
        return at_jobs
    
    def _get_at_job_content(self, job_id):
        """
        Get the content of an at job
        
        Args:
            job_id (str): ID of the at job
            
        Returns:
            str: Job content or empty string on error
        """
        try:
            # Use 'at -c' to view job content
            cmd = ["at", "-c", job_id]
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            if proc.returncode != 0:
                self.logger.error(f"Failed to get content for at job {job_id}: {proc.stderr}")
                return ""
            
            return proc.stdout.strip()
            
        except Exception as e:
            self.logger.error(f"Error getting at job content for job {job_id}: {e}")
            return ""
    
    def _analyze_anacron_jobs(self):
        """
        Analyze anacron jobs
        
        Returns:
            list: Collected anacron jobs
        """
        self.logger.debug("Analyzing anacron jobs")
        anacron_jobs = []
        
        # Check anacrontab
        if os.path.exists('/etc/anacrontab'):
            self._parse_anacrontab('/etc/anacrontab', anacron_jobs)
        
        return anacron_jobs
    
    def _parse_anacrontab(self, filepath, tasks_list):
        """
        Parse an anacrontab file
        
        Args:
            filepath (str): Path to the anacrontab file
            tasks_list (list): List to append tasks to
        """
        try:
            with open(filepath, 'r') as f:
                content = f.read()
                
            # Calculate file hash
            file_hash = hashlib.sha256(content.encode()).hexdigest()
            
            # Parse each line
            for line_number, line in enumerate(content.split('\n'), 1):
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Skip environment variables
                if '=' in line and line.split('=')[0].strip().isupper():
                    continue
                
                # Parse anacron job format: period delay job-identifier command
                parts = line.split(None, 3)
                if len(parts) >= 4:
                    period = parts[0]
                    delay = parts[1]
                    job_id = parts[2]
                    command = parts[3]
                    
                    tasks_list.append({
                        'task_type': 'anacron',
                        'task_name': job_id,
                        'user': 'root',  # Anacron jobs typically run as root
                        'schedule': f"Period: {period}, Delay: {delay}",
                        'command': command,
                        'path': filepath,
                        'hash': file_hash,
                        'line_number': line_number,
                        'raw': line
                    })
                
        except Exception as e:
            self.logger.error(f"Error parsing anacrontab {filepath}: {e}")
    
    def _analyze_other_tasks(self):
        """
        Analyze other scheduled tasks mechanisms
        
        Returns:
            list: Collected other scheduled tasks
        """
        self.logger.debug("Analyzing other scheduled task mechanisms")
        other_tasks = []
        
        # Check for custom scripts in init.d and rc.d directories
        init_dirs = ['/etc/init.d', '/etc/rc.d']
        for init_dir in init_dirs:
            if os.path.exists(init_dir) and os.path.isdir(init_dir):
                for filename in os.listdir(init_dir):
                    filepath = os.path.join(init_dir, filename)
                    if os.path.isfile(filepath) and not filename.startswith('.'):
                        self._parse_init_script(filepath, other_tasks)
        
        # Add other scheduling mechanisms here as needed
        
        return other_tasks
    
    def _parse_init_script(self, filepath, tasks_list):
        """
        Parse an init script for scheduled tasks
        
        Args:
            filepath (str): Path to the init script
            tasks_list (list): List to append tasks to
        """
        try:
            # Get file owner
            stat_info = os.stat(filepath)
            uid = stat_info.st_uid
            try:
                username = pwd.getpwuid(uid).pw_name
            except KeyError:
                username = str(uid)
            
            # Get file permissions
            permissions = oct(stat_info.st_mode & 0o777)
            
            # Get file content and hash
            with open(filepath, 'rb') as f:
                content = f.read()
                file_hash = hashlib.sha256(content).hexdigest()
                
            content_str = content.decode('utf-8', errors='replace')
            
            # Look for scheduling patterns in the script
            schedule_patterns = [
                (r'while\s+true', "Infinite loop"),
                (r'sleep\s+\d+', "Sleep interval"),
                (r'watch\s+', "Watch command"),
                (r'at\s+now\s*\+', "At command"),
                (r'(watch|timeout|while|until|for)\s', "Loop construct")
            ]
            
            schedule = "unknown"
            for pattern, desc in schedule_patterns:
                if re.search(pattern, content_str):
                    schedule = desc
                    break
            
            # For init scripts, the command is the script itself
            command = filepath
            
            tasks_list.append({
                'task_type': 'init_script',
                'task_name': os.path.basename(filepath),
                'user': username,
                'schedule': schedule,
                'command': command,
                'path': filepath,
                'hash': file_hash,
                'permissions': permissions,
                'content': content_str
            })
            
        except Exception as e:
            self.logger.error(f"Error parsing init script {filepath}: {e}")
    
    def _check_task_suspicious(self, task):
        """
        Check if a task is suspicious
        
        Args:
            task (dict): Task information
            
        Returns:
            tuple: (is_suspicious, reason)
        """
        # Check if task is whitelisted
        for pattern in self.whitelist_patterns:
            if pattern in task.get('path', '') or pattern in task.get('command', ''):
                return False, ""
        
        # Check for suspicious commands
        command = task.get('command', '').lower()
        for suspicious_cmd in self.suspicious_commands:
            if suspicious_cmd.lower() in command:
                return True, f"Contains suspicious command: {suspicious_cmd}"
        
        # Check for suspicious scheduling
        schedule = task.get('schedule', '').lower()
        
        # Check for high frequency execution
        if task.get('task_type') == 'cron' and not schedule.startswith('@'):
            try:
                # Parse standard cron format
                minute, hour, day, month, weekday = schedule.split()[:5]
                
                # Check for frequent execution (*/X minutes where X is small)
                if minute.startswith('*/'):
                    try:
                        frequency = int(minute[2:])
                        if frequency <= self.high_frequency_threshold:
                            return True, f"High frequency execution: every {frequency} minutes"
                    except ValueError:
                        pass
                
                # Check for execution during suspicious hours
                for start_hour, end_hour in self.suspicious_time_patterns:
                    if hour.isdigit() and start_hour <= int(hour) <= end_hour:
                        return True, f"Suspicious execution time: {hour}:00"
                    elif hour == '*' and minute == '*':
                        return True, f"Runs every minute"
            except Exception:
                pass
        
        # Check for unusual users
        user = task.get('user', '').lower()
        if user in ['root', 'admin'] and any(cmd in command for cmd in ['wget', 'curl', 'nc', 'netcat']):
            return True, f"Privileged user ({user}) running network commands"
        
        # Check for obfuscation techniques
        obfuscation_patterns = [
            (r'`.*`', "Backtick command substitution"),
            (r'\$\(.*\)', "Command substitution"),
            (r'\\x[0-9a-f]{2}', "Hex encoding"),
            (r'base64 -d', "Base64 decoding"),
            (r'eval\s+', "Eval usage"),
            (r'exec\s+', "Exec usage"),
            (r'(\||;|&&)\s*[\'"]?\/tmp\/', "Execution from /tmp"),
            (r'(\||;|&&)\s*[\'"]?\/dev\/shm\/', "Execution from /dev/shm")
        ]
        
        for pattern, reason in obfuscation_patterns:
            if re.search(pattern, command):
                return True, f"Potential obfuscation: {reason}"
        
        # Check for reverse shells
        reverse_shell_patterns = [
            r'bash\s+-i\s+>\&\s+/dev/tcp',
            r'nc\s+.+\s+-e\s+',
            r'netcat\s+.+\s+-e\s+',
            r'python\s+-c\s+[\'"]import socket',
            r'perl\s+-e\s+[\'"]use Socket',
            r'r[\'"]socket\.socket\('
        ]
        
        for pattern in reverse_shell_patterns:
            if re.search(pattern, command):
                return True, "Potential reverse shell"
        
        # For scripts, check content if available
        content = task.get('content', '') + task.get('service_content', '')
        if content:
            # Check script size - large scripts might be suspicious
            line_count = content.count('\n')
            if line_count > self.script_size_threshold:
                # Large scripts need deeper inspection
                if any(cmd in content.lower() for cmd in self.suspicious_commands):
                    return True, f"Large script ({line_count} lines) containing suspicious commands"
            
            # Check for IP addresses or domains
            ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
            domain_pattern = r'https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}'
            
            ip_matches = re.findall(ip_pattern, content)
            domain_matches = re.findall(domain_pattern, content)
            
            if ip_matches or domain_matches:
                # External connections are suspicious for scheduled tasks
                if any(cmd in content.lower() for cmd in ['wget', 'curl', 'nc', 'ssh', 'scp']):
                    targets = ip_matches + domain_matches
                    return True, f"Connects to external targets: {', '.join(targets[:3])}"
        
        # Not suspicious
        return False, ""
    
    def _has_baseline(self):
        """
        Check if a baseline exists
        
        Returns:
            bool: True if baseline exists
        """
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM scans WHERE is_baseline = 1")
            count = cursor.fetchone()[0]
            
            conn.close()
            return count > 0
            
        except Exception as e:
            self.logger.error(f"Error checking for baseline: {e}")
            return False
    
    def _compare_with_baseline(self, current_tasks):
        """
        Compare current tasks with baseline
        
        Args:
            current_tasks (list): Current scheduled tasks
            
        Returns:
            dict: Comparison results
        """
        self.logger.debug("Comparing with baseline")
        results = {
            'new_tasks': [],
            'modified_tasks': [],
            'removed_tasks': []
        }
        
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            # Get baseline tasks
            cursor.execute('''
            SELECT id, task_type, task_name, user, schedule, command, path, hash 
            FROM scheduled_tasks
            ''')
            
            # Build lookup dictionaries
            baseline_tasks = {}
            current_tasks_dict = {}
            
            for row in cursor.fetchall():
                task_id, task_type, task_name, user, schedule, command, path, task_hash = row
                
                # Use path and command as a unique identifier
                task_key = f"{task_type}:{path}:{command}"
                baseline_tasks[task_key] = {
                    'id': task_id,
                    'task_type': task_type,
                    'task_name': task_name,
                    'user': user,
                    'schedule': schedule,
                    'command': command,
                    'path': path,
                    'hash': task_hash
                }
            
            # Build current tasks dictionary
            for task in current_tasks:
                task_type = task.get('task_type', '')
                path = task.get('path', '')
                command = task.get('command', '')
                
                # Use path and command as a unique identifier
                task_key = f"{task_type}:{path}:{command}"
                current_tasks_dict[task_key] = task
            
            # Find new tasks
            for task_key, task in current_tasks_dict.items():
                if task_key not in baseline_tasks:
                    results['new_tasks'].append(task)
            
            # Find removed tasks
            for task_key, task in baseline_tasks.items():
                if task_key not in current_tasks_dict:
                    results['removed_tasks'].append(task)
            
            # Find modified tasks
            for task_key, current_task in current_tasks_dict.items():
                if task_key in baseline_tasks:
                    baseline_task = baseline_tasks[task_key]
                    
                    # Check for changes in hash or schedule
                    if (current_task.get('hash') != baseline_task.get('hash') or
                        current_task.get('schedule') != baseline_task.get('schedule') or
                        current_task.get('user') != baseline_task.get('user')):
                        
                        current_task['baseline_id'] = baseline_task['id']
                        current_task['changes'] = []
                        
                        # Record specific changes
                        if current_task.get('hash') != baseline_task.get('hash'):
                            current_task['changes'].append('content')
                            
                        if current_task.get('schedule') != baseline_task.get('schedule'):
                            current_task['changes'].append('schedule')
                            
                        if current_task.get('user') != baseline_task.get('user'):
                            current_task['changes'].append('user')
                        
                        results['modified_tasks'].append(current_task)
            
            conn.close()
            return results
            
        except Exception as e:
            self.logger.error(f"Error comparing with baseline: {e}")
            return results
    
    def _update_database(self, tasks, scan_results):
        """
        Update the database with current tasks and scan results
        
        Args:
            tasks (list): Current scheduled tasks
            scan_results (dict): Scan results
        """
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            # Begin transaction
            conn.execute("BEGIN TRANSACTION")
            
            # Update existing tasks and add new ones
            timestamp = time.time()
            for task in tasks:
                task_type = task.get('task_type', '')
                task_name = task.get('task_name', '')
                user = task.get('user', '')
                schedule = task.get('schedule', '')
                command = task.get('command', '')
                path = task.get('path', '')
                task_hash = task.get('hash', '')
                is_suspicious = 1 if task.get('is_suspicious', False) else 0
                suspicious_reason = task.get('suspicious_reason', '')
                
                # Check if task exists
                cursor.execute('''
                SELECT id, hash FROM scheduled_tasks 
                WHERE task_type = ? AND path = ? AND command = ?
                ''', (task_type, path, command))
                
                row = cursor.fetchone()
                if row:
                    # Task exists, update it
                    task_id, old_hash = row
                    
                    cursor.execute('''
                    UPDATE scheduled_tasks 
                    SET task_name = ?, user = ?, schedule = ?, hash = ?, 
                        last_seen = ?, is_suspicious = ?, suspicious_reason = ? 
                    WHERE id = ?
                    ''', (
                        task_name, user, schedule, task_hash, 
                        timestamp, is_suspicious, suspicious_reason, task_id
                    ))
                    
                    # Record changes if hash changed
                    if old_hash != task_hash:
                        cursor.execute('''
                        INSERT INTO task_changes 
                        (task_id, change_type, old_value, new_value, timestamp) 
                        VALUES (?, ?, ?, ?, ?)
                        ''', (
                            task_id, 'hash', old_hash, task_hash, timestamp
                        ))
                else:
                    # New task, insert it
                    cursor.execute('''
                    INSERT INTO scheduled_tasks 
                    (task_type, task_name, user, schedule, command, path, hash, 
                     first_seen, last_seen, is_suspicious, suspicious_reason) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        task_type, task_name, user, schedule, command, path, task_hash,
                        timestamp, timestamp, is_suspicious, suspicious_reason
                    ))
            
            # Create scan record
            cursor.execute('''
            INSERT INTO scans 
            (timestamp, new_tasks, modified_tasks, removed_tasks, suspicious_tasks, is_baseline, summary) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                timestamp,
                scan_results['summary'].get('new_count', 0),
                scan_results['summary'].get('modified_count', 0),
                scan_results['summary'].get('removed_count', 0),
                scan_results['summary'].get('suspicious_count', 0),
                0,  # Not a baseline scan
                json.dumps(scan_results['summary'])
            ))
            
            # Commit transaction
            conn.commit()
            
        except Exception as e:
            self.logger.error(f"Error updating database: {e}")
            conn.rollback()
        finally:
            if conn:
                conn.close()
    
    def establish_baseline(self):
        """
        Establish a baseline of scheduled tasks
        
        Returns:
            dict: Baseline scan results
        """
        self.logger.info("Establishing scheduled tasks baseline")
        
        # Run a scan to collect current tasks
        results = self.analyze()
        
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            # Mark this scan as a baseline
            timestamp = time.time()
            
            cursor.execute('''
            INSERT INTO scans 
            (timestamp, new_tasks, modified_tasks, removed_tasks, suspicious_tasks, is_baseline, summary) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                timestamp,
                0,  # No new tasks in a baseline
                0,  # No modified tasks in a baseline
                0,  # No removed tasks in a baseline
                results['summary'].get('suspicious_count', 0),
                1,  # This is a baseline scan
                json.dumps(results['summary'])
            ))
            
            conn.commit()
            
            self.logger.info("Baseline established successfully")
            
        except Exception as e:
            self.logger.error(f"Error establishing baseline: {e}")
        finally:
            if conn:
                conn.close()
        
        return results
    
    def get_scheduled_tasks(self, include_suspicious_only=False):
        """
        Get all scheduled tasks from database
        
        Args:
            include_suspicious_only (bool): Only include suspicious tasks
            
        Returns:
            list: Scheduled tasks
        """
        tasks = []
        
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            query = '''
            SELECT id, task_type, task_name, user, schedule, command, path, hash, 
                   first_seen, last_seen, is_suspicious, suspicious_reason 
            FROM scheduled_tasks
            '''
            
            if include_suspicious_only:
                query += " WHERE is_suspicious = 1"
                
            cursor.execute(query)
            
            for row in cursor.fetchall():
                (task_id, task_type, task_name, user, schedule, command, path, task_hash,
                 first_seen, last_seen, is_suspicious, suspicious_reason) = row
                
                tasks.append({
                    'id': task_id,
                    'task_type': task_type,
                    'task_name': task_name,
                    'user': user,
                    'schedule': schedule,
                    'command': command,
                    'path': path,
                    'hash': task_hash,
                    'first_seen': datetime.fromtimestamp(first_seen).isoformat(),
                    'last_seen': datetime.fromtimestamp(last_seen).isoformat(),
                    'is_suspicious': bool(is_suspicious),
                    'suspicious_reason': suspicious_reason
                })
            
            conn.close()
            return tasks
            
        except Exception as e:
            self.logger.error(f"Error getting scheduled tasks: {e}")
            return tasks
    
    def get_scan_history(self, limit=10):
        """
        Get history of scheduled tasks scans
        
        Args:
            limit (int): Maximum number of scans to return
            
        Returns:
            list: Scan history
        """
        scans = []
        
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT id, timestamp, new_tasks, modified_tasks, removed_tasks, 
                   suspicious_tasks, is_baseline, summary 
            FROM scans 
            ORDER BY timestamp DESC 
            LIMIT ?
            ''', (limit,))
            
            for row in cursor.fetchall():
                (scan_id, timestamp, new_tasks, modified_tasks, removed_tasks,
                 suspicious_tasks, is_baseline, summary) = row
                
                scan_data = {
                    'id': scan_id,
                    'timestamp': datetime.fromtimestamp(timestamp).isoformat(),
                    'new_tasks': new_tasks,
                    'modified_tasks': modified_tasks,
                    'removed_tasks': removed_tasks,
                    'suspicious_tasks': suspicious_tasks,
                    'is_baseline': bool(is_baseline)
                }
                
                # Parse summary if available
                try:
                    summary_data = json.loads(summary)
                    scan_data['summary'] = summary_data
                except (json.JSONDecodeError, TypeError):
                    pass
                
                scans.append(scan_data)
            
            conn.close()
            return scans
            
        except Exception as e:
            self.logger.error(f"Error getting scan history: {e}")
            return scans
    
    def get_task_changes(self, task_id):
        """
        Get history of changes for a specific task
        
        Args:
            task_id (int): ID of the task
            
        Returns:
            list: Change history
        """
        changes = []
        
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT id, change_type, old_value, new_value, timestamp 
            FROM task_changes 
            WHERE task_id = ? 
            ORDER BY timestamp DESC
            ''', (task_id,))
            
            for row in cursor.fetchall():
                (change_id, change_type, old_value, new_value, timestamp) = row
                
                changes.append({
                    'id': change_id,
                    'type': change_type,
                    'old_value': old_value,
                    'new_value': new_value,
                    'timestamp': datetime.fromtimestamp(timestamp).isoformat()
                })
            
            conn.close()
            return changes
            
        except Exception as e:
            self.logger.error(f"Error getting task changes: {e}")
            return changes
    
    def get_statistics(self):
        """
        Get statistics about scheduled tasks
        
        Returns:
            dict: Statistics
        """
        stats = {
            'total_tasks': 0,
            'suspicious_tasks': 0,
            'task_types': {},
            'users': {},
            'recent_changes': 0,
            'last_scan': None
        }
        
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            # Get total tasks
            cursor.execute("SELECT COUNT(*) FROM scheduled_tasks")
            stats['total_tasks'] = cursor.fetchone()[0]
            
            # Get suspicious tasks
            cursor.execute("SELECT COUNT(*) FROM scheduled_tasks WHERE is_suspicious = 1")
            stats['suspicious_tasks'] = cursor.fetchone()[0]
            
            # Get task types breakdown
            cursor.execute("SELECT task_type, COUNT(*) FROM scheduled_tasks GROUP BY task_type")
            for row in cursor.fetchall():
                stats['task_types'][row[0]] = row[1]
            
            # Get users breakdown
            cursor.execute("SELECT user, COUNT(*) FROM scheduled_tasks GROUP BY user")
            for row in cursor.fetchall():
                stats['users'][row[0]] = row[1]
            
            # Get recent changes (last 7 days)
            week_ago = time.time() - (7 * 24 * 60 * 60)
            cursor.execute("SELECT COUNT(*) FROM task_changes WHERE timestamp > ?", (week_ago,))
            stats['recent_changes'] = cursor.fetchone()[0]
            
            # Get last scan time
            cursor.execute("SELECT timestamp FROM scans ORDER BY timestamp DESC LIMIT 1")
            row = cursor.fetchone()
            if row:
                stats['last_scan'] = datetime.fromtimestamp(row[0]).isoformat()
            
            conn.close()
            return stats
            
        except Exception as e:
            self.logger.error(f"Error getting statistics: {e}")
            return stats