#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import subprocess
import json
import logging
import sqlite3
import time
from datetime import datetime
from pathlib import Path
import stat
import pwd
import grp
from concurrent.futures import ThreadPoolExecutor

class PrivilegeEscalationDetector:
    """
    Privilege Escalation Detection Module
    
    Detects potential privilege escalation vectors in Linux systems by analyzing
    SUID/SGID binaries, sudo configurations, capabilities, and other common 
    privilege escalation paths.
    """
    
    def __init__(self, database_path=None, config_file=None):
        """
        Initialize the Privilege Escalation Detector
        
        Args:
            database_path (str): Path to the database file
            config_file (str): Path to configuration file
        """
        self.logger = logging.getLogger("sharpeye.privilege_escalation")
        
        # Set default database path if not provided
        if database_path is None:
            home_dir = os.path.expanduser("~")
            self.database_path = os.path.join(home_dir, ".sharpeye", "privilege_escalation.db")
        else:
            self.database_path = database_path
            
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.database_path), exist_ok=True)
        
        # Load configuration
        self.config = self._load_configuration(config_file)
        
        # Initialize the database
        self._initialize_database()
        
    def _load_configuration(self, config_file):
        """
        Load configuration from file or use defaults
        
        Args:
            config_file (str): Path to configuration file
            
        Returns:
            dict: Configuration settings
        """
        default_config = {
            "scan_directories": [
                "/", 
                "/usr",
                "/opt"
            ],
            "excluded_paths": [
                "/proc",
                "/sys",
                "/dev",
                "/run",
                "/var/log",
                "/var/cache",
                "/tmp"
            ],
            "excluded_suid_binaries": [
                # Common legitimate SUID binaries
                "/bin/su",
                "/bin/sudo",
                "/usr/bin/passwd",
                "/usr/bin/gpasswd",
                "/usr/bin/chsh",
                "/usr/bin/chfn",
                "/usr/bin/newgrp",
                "/bin/mount",
                "/bin/umount",
                "/usr/bin/pkexec",
                "/usr/bin/crontab",
                "/usr/lib/polkit-1/polkit-agent-helper-1",
                "/usr/lib/dbus-1.0/dbus-daemon-launch-helper"
            ],
            "known_dangerous_sudo_config": [
                "NOPASSWD: ALL",
                "NOPASSWD: /bin/sh",
                "NOPASSWD: /bin/bash",
                "NOPASSWD: /usr/bin/python",
                "NOPASSWD: /usr/bin/perl",
                "NOPASSWD: /usr/bin/ruby",
                "NOPASSWD: /usr/bin/vi",
                "NOPASSWD: /usr/bin/vim",
                "NOPASSWD: /usr/bin/nano",
                "NOPASSWD: /usr/bin/find",
                "NOPASSWD: /usr/bin/cp",
                "NOPASSWD: /usr/bin/mv",
                "NOPASSWD: /usr/bin/cat",
                "NOPASSWD: /bin/chmod"
            ],
            "dangerous_capabilities": [
                "cap_sys_admin",
                "cap_sys_ptrace",
                "cap_sys_module",
                "cap_sys_rawio",
                "cap_net_raw",
                "cap_net_admin",
                "cap_sys_chroot",
                "cap_setuid",
                "cap_setgid",
                "cap_dac_override",
                "cap_dac_read_search"
            ],
            "suspicious_cron_patterns": [
                r"curl\s+.*\s*\|\s*bash",
                r"wget\s+.*\s*\|\s*bash",
                r"curl\s+.*\s*\|\s*sh",
                r"wget\s+.*\s*\|\s*sh",
                r"nc\s+.*\s*\|\s*bash",
                r"nc\s+.*\s*\|\s*sh",
                r"ncat\s+.*\s*\|\s*bash",
                r"ncat\s+.*\s*\|\s*sh",
                r"python\s+-c",
                r"perl\s+-e",
                r"ruby\s+-e",
                r"base64\s+-d",
                r"ssh-keygen.*\|\s*bash"
            ],
            "dangerous_nfs_config": [
                "no_root_squash",
                "no_all_squash"
            ],
            "writable_config_files": [
                "/etc/passwd",
                "/etc/shadow",
                "/etc/sudoers",
                "/etc/hosts",
                "/etc/crontab",
                "/etc/cron.d",
                "/etc/cron.daily",
                "/etc/cron.hourly",
                "/etc/cron.monthly",
                "/etc/cron.weekly",
                "/etc/profile",
                "/etc/bash.bashrc",
                "/etc/environment",
                "/etc/ld.so.conf",
                "/etc/ld.so.conf.d"
            ],
            "thread_count": 4,
            "scan_interval": 43200  # 12 hours
        }
        
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                    # Merge user configuration with default
                    for key, value in user_config.items():
                        default_config[key] = value
                self.logger.info(f"Loaded configuration from {config_file}")
            except Exception as e:
                self.logger.error(f"Failed to load configuration file: {e}")
        
        return default_config
    
    def _initialize_database(self):
        """Initialize the SQLite database for storing privilege escalation vectors"""
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            # Create tables if they don't exist
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS suid_binaries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT UNIQUE,
                permissions INTEGER,
                owner TEXT,
                group_owner TEXT,
                size INTEGER,
                last_modified REAL,
                first_seen REAL,
                last_checked REAL,
                is_excluded INTEGER DEFAULT 0,
                is_suspicious INTEGER DEFAULT 0,
                suspicious_reason TEXT
            )
            ''')
            
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS sudo_config (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user TEXT,
                host TEXT,
                privileges TEXT,
                first_seen REAL,
                last_checked REAL,
                is_dangerous INTEGER DEFAULT 0
            )
            ''')
            
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS capabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT UNIQUE,
                capabilities TEXT,
                first_seen REAL,
                last_checked REAL,
                is_dangerous INTEGER DEFAULT 0
            )
            ''')
            
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS cron_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT,
                user TEXT,
                command TEXT,
                schedule TEXT,
                first_seen REAL,
                last_checked REAL,
                is_suspicious INTEGER DEFAULT 0,
                suspicious_reason TEXT
            )
            ''')
            
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS nfs_exports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT,
                options TEXT,
                first_seen REAL,
                last_checked REAL,
                is_dangerous INTEGER DEFAULT 0
            )
            ''')
            
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS writable_configs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT UNIQUE,
                permissions INTEGER,
                owner TEXT,
                group_owner TEXT,
                first_seen REAL,
                last_checked REAL
            )
            ''')
            
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS container_escapes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vector_type TEXT,
                details TEXT,
                first_seen REAL,
                last_checked REAL
            )
            ''')
            
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS escalation_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vector_type TEXT,
                path TEXT,
                change_type TEXT,
                old_value TEXT,
                new_value TEXT,
                timestamp REAL,
                verified INTEGER DEFAULT 0
            )
            ''')
            
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_suid_path ON suid_binaries(path)
            ''')
            
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_sudo_user ON sudo_config(user)
            ''')
            
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_cap_path ON capabilities(path)
            ''')
            
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_cron_user ON cron_jobs(user)
            ''')
            
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_nfs_path ON nfs_exports(path)
            ''')
            
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_change_path ON escalation_changes(path)
            ''')
            
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_change_type ON escalation_changes(vector_type)
            ''')
            
            conn.commit()
            self.logger.info("Database initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize database: {e}")
        finally:
            if conn:
                conn.close()
    
    def find_suid_sgid_binaries(self):
        """
        Find SUID and SGID binaries on the system
        
        Returns:
            list: List of SUID/SGID binaries with their details
        """
        suid_files = []
        
        for directory in self.config["scan_directories"]:
            if not os.path.exists(directory):
                continue
                
            # Skip excluded paths
            if self._is_excluded_path(directory):
                continue
                
            self.logger.info(f"Scanning directory for SUID/SGID files: {directory}")
            
            try:
                # Use find command to locate SUID/SGID files
                find_cmd = [
                    'find', directory, 
                    '(', '-perm', '-4000', '-o', '-perm', '-2000', ')', 
                    '-type', 'f', 
                    '-not', '-path', '*/proc/*', 
                    '-not', '-path', '*/sys/*',
                    '-not', '-path', '*/dev/*',
                    '-not', '-path', '*/run/*'
                ]
                
                for excluded in self.config["excluded_paths"]:
                    if os.path.exists(excluded):
                        find_cmd.extend(['-not', '-path', f'{excluded}/*'])
                
                process = subprocess.run(find_cmd, capture_output=True, text=True)
                
                if process.returncode == 0:
                    files = process.stdout.strip().split('\n')
                    
                    for file_path in files:
                        if not file_path:
                            continue
                            
                        try:
                            file_stat = os.stat(file_path)
                            
                            # Get owner and group names
                            try:
                                owner = pwd.getpwuid(file_stat.st_uid).pw_name
                            except KeyError:
                                owner = str(file_stat.st_uid)
                                
                            try:
                                group = grp.getgrgid(file_stat.st_gid).gr_name
                            except KeyError:
                                group = str(file_stat.st_gid)
                            
                            # Check if this is in the excluded list
                            is_excluded = file_path in self.config["excluded_suid_binaries"]
                            
                            # Check if the binary is suspicious
                            is_suspicious, reason = self._check_suid_suspicious(file_path)
                            
                            suid_files.append({
                                "path": file_path,
                                "permissions": file_stat.st_mode,
                                "owner": owner,
                                "group_owner": group,
                                "size": file_stat.st_size,
                                "last_modified": file_stat.st_mtime,
                                "is_excluded": is_excluded,
                                "is_suspicious": is_suspicious,
                                "suspicious_reason": reason
                            })
                            
                        except Exception as e:
                            self.logger.debug(f"Error processing file {file_path}: {e}")
                            
            except Exception as e:
                self.logger.error(f"Error finding SUID/SGID files in {directory}: {e}")
        
        return suid_files
    
    def _is_excluded_path(self, path):
        """
        Check if a path should be excluded
        
        Args:
            path (str): Path to check
            
        Returns:
            bool: True if path should be excluded, False otherwise
        """
        for excluded in self.config["excluded_paths"]:
            if path.startswith(excluded) or path == excluded:
                return True
        return False
    
    def _check_suid_suspicious(self, file_path):
        """
        Check if a SUID/SGID binary is suspicious
        
        Args:
            file_path (str): Path to the binary
            
        Returns:
            tuple: (bool, str) True if suspicious and reason
        """
        # Check if it's a known legitimate SUID binary
        if file_path in self.config["excluded_suid_binaries"]:
            return False, ""
            
        # Check if it's a script (SUID scripts are generally dangerous)
        try:
            with open(file_path, 'rb') as f:
                header = f.read(4)
                if header.startswith(b'#!'):
                    return True, "SUID script found - extremely dangerous"
        except Exception:
            pass
            
        # Check write permissions for group or others
        try:
            file_stat = os.stat(file_path)
            if file_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                return True, "SUID binary is writable by group or others"
        except Exception:
            pass
            
        # Check for unusual locations
        unusual_locations = [
            "/tmp", "/var/tmp", "/dev/shm", "/var/mail", "/var/spool",
            "/home", "/opt/", "/mnt", "/media"
        ]
        
        for location in unusual_locations:
            if file_path.startswith(location):
                return True, f"SUID binary in unusual location: {location}"
                
        # Check for recently created or modified files
        try:
            file_stat = os.stat(file_path)
            # Check if file was modified in the last 7 days
            if time.time() - file_stat.st_mtime < 7 * 24 * 60 * 60:
                return True, "Recently modified SUID binary"
        except Exception:
            pass
            
        # Check file type using 'file' command
        try:
            output = subprocess.run(['file', file_path], capture_output=True, text=True).stdout
            
            # Check for unusual file types
            if "shell script" in output:
                return True, "SUID shell script"
            elif "Python script" in output or "perl script" in output or "Ruby script" in output:
                return True, "SUID interpreted script"
            elif "statically linked" in output:
                return True, "Statically linked SUID binary (unusual)"
            elif "ASCII text" in output:
                return True, "SUID ASCII text file (unusual)"
        except Exception:
            pass
            
        # Check if the binary has any embedded scripts or suspicious strings
        try:
            strings_output = subprocess.run(['strings', file_path], capture_output=True, text=True).stdout
            
            suspicious_patterns = [
                "bash", "/bin/sh", "/bin/bash", "system(", "exec(", "popen(",
                "subprocess", "os.system", "eval", "sudo", "chmod", "chown"
            ]
            
            for pattern in suspicious_patterns:
                if pattern in strings_output:
                    return True, f"SUID binary contains suspicious string: {pattern}"
        except Exception:
            pass
            
        # All checks passed
        return False, ""
    
    def check_sudo_config(self):
        """
        Check sudo configuration for dangerous settings
        
        Returns:
            list: List of sudo configurations with their details
        """
        sudo_entries = []
        
        try:
            # Use 'sudo -l' to list user's sudo privileges
            # Note: This might not work if the current user doesn't have sudo rights
            sudo_output = subprocess.run(['sudo', '-l'], capture_output=True, text=True)
            
            if sudo_output.returncode == 0:
                output = sudo_output.stdout
                
                # Parse the output
                current_user = None
                for line in output.split('\n'):
                    if line.startswith("User "):
                        match = re.search(r"User\s+(\w+)", line)
                        if match:
                            current_user = match.group(1)
                    elif "may run the following commands" in line:
                        continue
                    elif line.strip() and current_user:
                        # This line contains sudo privileges
                        if "ALL = " in line or "NOPASSWD: " in line:
                            parts = line.strip().split('=')
                            if len(parts) >= 2:
                                hosts = parts[0].strip()
                                privileges = '='.join(parts[1:]).strip()
                                
                                # Check if this config is dangerous
                                is_dangerous = self._check_sudo_config_dangerous(privileges)
                                
                                sudo_entries.append({
                                    "user": current_user,
                                    "host": hosts,
                                    "privileges": privileges,
                                    "is_dangerous": is_dangerous
                                })
            
            # Check /etc/sudoers if readable
            sudoers_path = "/etc/sudoers"
            if os.path.exists(sudoers_path) and os.access(sudoers_path, os.R_OK):
                with open(sudoers_path, 'r') as f:
                    sudoers_content = f.read()
                    
                # Parse sudoers file
                for line in sudoers_content.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if "=" in line:
                            parts = line.split('=')
                            if len(parts) >= 2:
                                user_host = parts[0].strip()
                                privileges = '='.join(parts[1:]).strip()
                                
                                # Extract user and host
                                if ' ' in user_host:
                                    user, host = user_host.split(' ', 1)
                                else:
                                    user = user_host
                                    host = "ALL"
                                
                                # Check if this config is dangerous
                                is_dangerous = self._check_sudo_config_dangerous(privileges)
                                
                                sudo_entries.append({
                                    "user": user,
                                    "host": host,
                                    "privileges": privileges,
                                    "is_dangerous": is_dangerous
                                })
            
            # Check files in /etc/sudoers.d if readable
            sudoers_dir = "/etc/sudoers.d"
            if os.path.exists(sudoers_dir) and os.path.isdir(sudoers_dir):
                for filename in os.listdir(sudoers_dir):
                    filepath = os.path.join(sudoers_dir, filename)
                    if os.path.isfile(filepath) and os.access(filepath, os.R_OK):
                        with open(filepath, 'r') as f:
                            content = f.read()
                            
                        # Parse sudoers file
                        for line in content.split('\n'):
                            line = line.strip()
                            if line and not line.startswith('#'):
                                if "=" in line:
                                    parts = line.split('=')
                                    if len(parts) >= 2:
                                        user_host = parts[0].strip()
                                        privileges = '='.join(parts[1:]).strip()
                                        
                                        # Extract user and host
                                        if ' ' in user_host:
                                            user, host = user_host.split(' ', 1)
                                        else:
                                            user = user_host
                                            host = "ALL"
                                        
                                        # Check if this config is dangerous
                                        is_dangerous = self._check_sudo_config_dangerous(privileges)
                                        
                                        sudo_entries.append({
                                            "user": user,
                                            "host": host,
                                            "privileges": privileges,
                                            "is_dangerous": is_dangerous
                                        })
                
        except Exception as e:
            self.logger.error(f"Error checking sudo configuration: {e}")
            
        return sudo_entries
    
    def _check_sudo_config_dangerous(self, privileges):
        """
        Check if a sudo configuration is dangerous
        
        Args:
            privileges (str): Sudo privileges string
            
        Returns:
            bool: True if dangerous, False otherwise
        """
        # Check against known dangerous configurations
        for dangerous in self.config["known_dangerous_sudo_config"]:
            if dangerous in privileges:
                return True
                
        # Check for ALL privileges
        if "(ALL)" in privileges or "(ALL : ALL)" in privileges:
            return True
            
        # Check for dangerous commands
        dangerous_commands = [
            "vi", "vim", "nano", "emacs", "python", "perl", "ruby", "bash", "sh",
            "find", "cp", "mv", "cat", "dd", "mount", "crontab"
        ]
        
        for cmd in dangerous_commands:
            # Check for command with full path or just the command name
            if f"/bin/{cmd}" in privileges or f"/usr/bin/{cmd}" in privileges or f" {cmd}" in privileges:
                return True
                
        return False
    
    def check_capabilities(self):
        """
        Check for files with capabilities
        
        Returns:
            list: List of files with capabilities
        """
        cap_files = []
        
        try:
            # Try using getcap on common directories
            for directory in self.config["scan_directories"]:
                if not os.path.exists(directory):
                    continue
                    
                # Skip excluded paths
                if self._is_excluded_path(directory):
                    continue
                    
                self.logger.info(f"Scanning directory for capabilities: {directory}")
                
                try:
                    # Using getcap command
                    getcap_cmd = ['getcap', '-r', directory]
                    process = subprocess.run(getcap_cmd, capture_output=True, text=True)
                    
                    if process.returncode == 0:
                        output = process.stdout.strip()
                        
                        for line in output.split('\n'):
                            if line:
                                parts = line.split(' = ')
                                if len(parts) == 2:
                                    path = parts[0]
                                    capabilities = parts[1]
                                    
                                    # Check if these capabilities are dangerous
                                    is_dangerous = self._check_capabilities_dangerous(capabilities)
                                    
                                    cap_files.append({
                                        "path": path,
                                        "capabilities": capabilities,
                                        "is_dangerous": is_dangerous
                                    })
                except Exception as e:
                    self.logger.debug(f"Error checking capabilities in {directory}: {e}")
                    
        except Exception as e:
            self.logger.error(f"Error checking capabilities: {e}")
            
        return cap_files
    
    def _check_capabilities_dangerous(self, capabilities):
        """
        Check if a set of capabilities is dangerous
        
        Args:
            capabilities (str): Capabilities string
            
        Returns:
            bool: True if dangerous, False otherwise
        """
        # Check against known dangerous capabilities
        for dangerous in self.config["dangerous_capabilities"]:
            if dangerous in capabilities:
                return True
                
        # Check for full capability sets
        if "=ep" in capabilities:  # Effective and Permitted
            return True
            
        return False
    
    def check_cron_jobs(self):
        """
        Check for suspicious cron jobs
        
        Returns:
            list: List of cron jobs with their details
        """
        cron_jobs = []
        
        try:
            # Check system-wide cron files
            cron_files = [
                "/etc/crontab",
                "/var/spool/cron/crontabs/root"
            ]
            
            # Add files from /etc/cron.d
            cron_d = "/etc/cron.d"
            if os.path.exists(cron_d) and os.path.isdir(cron_d):
                for filename in os.listdir(cron_d):
                    if filename != "0hourly":  # Skip standard files
                        cron_files.append(os.path.join(cron_d, filename))
            
            # Check each cron file
            for cron_file in cron_files:
                if os.path.exists(cron_file) and os.path.isfile(cron_file) and os.access(cron_file, os.R_OK):
                    with open(cron_file, 'r') as f:
                        content = f.read()
                        
                    # Parse cron file
                    for line in content.split('\n'):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Parse cron line
                            parts = line.split(None, 5)
                            if len(parts) >= 6:
                                schedule = ' '.join(parts[:5])
                                user = parts[5].split(None, 1)[0]
                                command = parts[5].split(None, 1)[1]
                                
                                # Check if the command is suspicious
                                is_suspicious, reason = self._check_cron_suspicious(command)
                                
                                cron_jobs.append({
                                    "path": cron_file,
                                    "user": user,
                                    "command": command,
                                    "schedule": schedule,
                                    "is_suspicious": is_suspicious,
                                    "suspicious_reason": reason
                                })
            
            # Check user crontabs
            for user_info in pwd.getpwall():
                user = user_info.pw_name
                crontab_path = f"/var/spool/cron/crontabs/{user}"
                
                if os.path.exists(crontab_path) and os.path.isfile(crontab_path) and os.access(crontab_path, os.R_OK):
                    with open(crontab_path, 'r') as f:
                        content = f.read()
                        
                    # Parse cron file
                    for line in content.split('\n'):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Parse cron line
                            parts = line.split(None, 5)
                            if len(parts) >= 6:
                                schedule = ' '.join(parts[:5])
                                command = parts[5]
                                
                                # Check if the command is suspicious
                                is_suspicious, reason = self._check_cron_suspicious(command)
                                
                                cron_jobs.append({
                                    "path": crontab_path,
                                    "user": user,
                                    "command": command,
                                    "schedule": schedule,
                                    "is_suspicious": is_suspicious,
                                    "suspicious_reason": reason
                                })
            
        except Exception as e:
            self.logger.error(f"Error checking cron jobs: {e}")
            
        return cron_jobs
    
    def _check_cron_suspicious(self, command):
        """
        Check if a cron command is suspicious
        
        Args:
            command (str): Cron command
            
        Returns:
            tuple: (bool, str) True if suspicious and reason
        """
        # Check against suspicious patterns
        for pattern in self.config["suspicious_cron_patterns"]:
            if re.search(pattern, command):
                return True, f"Matches suspicious pattern: {pattern}"
                
        # Check for curl/wget commands downloading scripts
        if ("curl" in command or "wget" in command) and ("bash" in command or "sh" in command):
            return True, "Downloads and executes scripts from the internet"
            
        # Check for base64 encoded commands
        if "base64" in command and ("-d" in command or "--decode" in command):
            return True, "Uses base64 decoded commands"
            
        # Check for network connections
        if "nc" in command or "netcat" in command or "ncat" in command:
            return True, "Contains network connection commands"
            
        # Check for world-writable scripts
        script_match = re.search(r'(\/\S+\.\w+)', command)
        if script_match:
            script_path = script_match.group(1)
            if os.path.exists(script_path) and os.path.isfile(script_path):
                try:
                    file_stat = os.stat(script_path)
                    if file_stat.st_mode & stat.S_IWOTH:
                        return True, f"Executes world-writable script: {script_path}"
                except Exception:
                    pass
        
        return False, ""
    
    def check_nfs_exports(self):
        """
        Check NFS exports for dangerous configurations
        
        Returns:
            list: List of NFS exports with their details
        """
        nfs_exports = []
        
        try:
            # Check /etc/exports
            exports_path = "/etc/exports"
            if os.path.exists(exports_path) and os.path.isfile(exports_path) and os.access(exports_path, os.R_OK):
                with open(exports_path, 'r') as f:
                    content = f.read()
                    
                # Parse exports file
                for line in content.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split(None, 1)
                        if len(parts) == 2:
                            path = parts[0]
                            options = parts[1]
                            
                            # Check if these options are dangerous
                            is_dangerous = self._check_nfs_dangerous(options)
                            
                            nfs_exports.append({
                                "path": path,
                                "options": options,
                                "is_dangerous": is_dangerous
                            })
                            
            # Alternatively, use 'exportfs -v'
            try:
                export_cmd = ['exportfs', '-v']
                process = subprocess.run(export_cmd, capture_output=True, text=True)
                
                if process.returncode == 0:
                    output = process.stdout.strip()
                    
                    for line in output.split('\n'):
                        if line:
                            parts = line.split(None, 1)
                            if len(parts) == 2:
                                path = parts[0].rstrip(':')
                                options = parts[1]
                                
                                # Check if these options are dangerous
                                is_dangerous = self._check_nfs_dangerous(options)
                                
                                # Only add if not already added from /etc/exports
                                if not any(e['path'] == path for e in nfs_exports):
                                    nfs_exports.append({
                                        "path": path,
                                        "options": options,
                                        "is_dangerous": is_dangerous
                                    })
            except Exception:
                pass
                
        except Exception as e:
            self.logger.error(f"Error checking NFS exports: {e}")
            
        return nfs_exports
    
    def _check_nfs_dangerous(self, options):
        """
        Check if NFS export options are dangerous
        
        Args:
            options (str): NFS export options
            
        Returns:
            bool: True if dangerous, False otherwise
        """
        # Check for dangerous options
        for dangerous in self.config["dangerous_nfs_config"]:
            if dangerous in options:
                return True
                
        return False
    
    def check_writable_configs(self):
        """
        Check for writable system configuration files
        
        Returns:
            list: List of writable configuration files
        """
        writable_configs = []
        
        for config_path in self.config["writable_config_files"]:
            if os.path.exists(config_path):
                try:
                    # Check if it's a file
                    if os.path.isfile(config_path):
                        file_paths = [config_path]
                    elif os.path.isdir(config_path):
                        # If it's a directory, check all files within
                        file_paths = []
                        for root, _, files in os.walk(config_path):
                            for file in files:
                                file_paths.append(os.path.join(root, file))
                    else:
                        continue
                        
                    for path in file_paths:
                        # Check permissions
                        file_stat = os.stat(path)
                        
                        # Check if writable by group or others
                        if file_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                            # Get owner and group names
                            try:
                                owner = pwd.getpwuid(file_stat.st_uid).pw_name
                            except KeyError:
                                owner = str(file_stat.st_uid)
                                
                            try:
                                group = grp.getgrgid(file_stat.st_gid).gr_name
                            except KeyError:
                                group = str(file_stat.st_gid)
                                
                            writable_configs.append({
                                "path": path,
                                "permissions": file_stat.st_mode,
                                "owner": owner,
                                "group_owner": group
                            })
                            
                except Exception as e:
                    self.logger.debug(f"Error checking {config_path}: {e}")
                    
        return writable_configs
    
    def check_container_escapes(self):
        """
        Check for container escape vectors
        
        Returns:
            list: List of potential container escape vectors
        """
        escape_vectors = []
        
        try:
            # Check if we're in a container
            in_container = False
            
            # Method 1: Check for .dockerenv file
            if os.path.exists('/.dockerenv'):
                in_container = True
                escape_vectors.append({
                    "vector_type": "container_detection",
                    "details": "Running inside Docker container (.dockerenv file found)"
                })
                
            # Method 2: Check cgroup
            try:
                with open('/proc/1/cgroup', 'r') as f:
                    cgroup_content = f.read()
                    if 'docker' in cgroup_content or 'lxc' in cgroup_content or 'kubepods' in cgroup_content:
                        in_container = True
                        escape_vectors.append({
                            "vector_type": "container_detection",
                            "details": f"Running inside container (cgroup: {cgroup_content.strip()})"
                        })
            except Exception:
                pass
                
            # Only check for escape vectors if we're in a container
            if in_container:
                # Check for privileged mode
                try:
                    with open('/proc/self/status', 'r') as f:
                        status_content = f.read()
                        if 'CapEff' in status_content:
                            for line in status_content.split('\n'):
                                if line.startswith('CapEff:'):
                                    cap_value = int(line.split(':')[1].strip(), 16)
                                    # Check for high capability value indicating privileged mode
                                    if cap_value > 0xFFFFFFF:
                                        escape_vectors.append({
                                            "vector_type": "privileged_container",
                                            "details": f"Container running in privileged mode (CapEff: {hex(cap_value)})"
                                        })
                except Exception:
                    pass
                    
                # Check for mounted host directories
                proc_mounts = '/proc/mounts'
                if os.path.exists(proc_mounts):
                    with open(proc_mounts, 'r') as f:
                        mounts_content = f.read()
                        
                    dangerous_mounts = [
                        '/dev', '/proc', '/sys', '/var/run/docker.sock'
                    ]
                    
                    for mount in dangerous_mounts:
                        if f' {mount} ' in mounts_content:
                            escape_vectors.append({
                                "vector_type": "dangerous_mount",
                                "details": f"Dangerous host directory mounted: {mount}"
                            })
                            
                # Check for unsafe capabilities
                cap_files = self.check_capabilities()
                for cap in cap_files:
                    if cap["is_dangerous"]:
                        escape_vectors.append({
                            "vector_type": "dangerous_capability",
                            "details": f"Dangerous capability found: {cap['path']} ({cap['capabilities']})"
                        })
                        
                # Check for writable /proc entries
                try:
                    proc_sys = '/proc/sys'
                    if os.path.exists(proc_sys) and os.path.isdir(proc_sys):
                        writable_entries = []
                        for root, _, files in os.walk(proc_sys):
                            for file in files:
                                path = os.path.join(root, file)
                                try:
                                    if os.access(path, os.W_OK):
                                        writable_entries.append(path)
                                except Exception:
                                    pass
                                    
                        if writable_entries:
                            escape_vectors.append({
                                "vector_type": "writable_proc",
                                "details": f"Writable /proc entries found: {writable_entries[:5]}"
                            })
                except Exception:
                    pass
                    
                # Check for unsafe sysctl parameters
                try:
                    # Check if we can unshare the user namespace
                    unshare_cmd = ['unshare', '--user', '--map-root-user', 'id']
                    process = subprocess.run(unshare_cmd, capture_output=True, text=True)
                    
                    if process.returncode == 0 and 'uid=0(root)' in process.stdout:
                        escape_vectors.append({
                            "vector_type": "user_namespace",
                            "details": "User namespace is enabled and can be used for container escapes"
                        })
                except Exception:
                    pass
                    
        except Exception as e:
            self.logger.error(f"Error checking container escapes: {e}")
            
        return escape_vectors
    
    def create_baseline(self):
        """
        Create a baseline of privilege escalation vectors
        
        Returns:
            dict: Statistics about the baseline creation
        """
        self.logger.info("Creating privilege escalation baseline")
        
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        stats = {
            "suid_binaries": 0,
            "sudo_configs": 0,
            "capabilities": 0,
            "cron_jobs": 0,
            "nfs_exports": 0,
            "writable_configs": 0,
            "container_escapes": 0,
            "suspicious_items": 0
        }
        
        current_time = time.time()
        
        # Process SUID/SGID binaries
        suid_binaries = self.find_suid_sgid_binaries()
        for binary in suid_binaries:
            try:
                cursor.execute('''
                INSERT OR REPLACE INTO suid_binaries 
                (path, permissions, owner, group_owner, size, last_modified, 
                 first_seen, last_checked, is_excluded, is_suspicious, suspicious_reason) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    binary["path"],
                    binary["permissions"],
                    binary["owner"],
                    binary["group_owner"],
                    binary["size"],
                    binary["last_modified"],
                    current_time,
                    current_time,
                    1 if binary["is_excluded"] else 0,
                    1 if binary["is_suspicious"] else 0,
                    binary["suspicious_reason"]
                ))
                
                stats["suid_binaries"] += 1
                if binary["is_suspicious"]:
                    stats["suspicious_items"] += 1
            except Exception as e:
                self.logger.error(f"Error storing SUID binary {binary['path']}: {e}")
                
        # Process sudo configurations
        sudo_configs = self.check_sudo_config()
        for config in sudo_configs:
            try:
                cursor.execute('''
                INSERT OR REPLACE INTO sudo_config 
                (user, host, privileges, first_seen, last_checked, is_dangerous) 
                VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    config["user"],
                    config["host"],
                    config["privileges"],
                    current_time,
                    current_time,
                    1 if config["is_dangerous"] else 0
                ))
                
                stats["sudo_configs"] += 1
                if config["is_dangerous"]:
                    stats["suspicious_items"] += 1
            except Exception as e:
                self.logger.error(f"Error storing sudo config for {config['user']}: {e}")
                
        # Process capabilities
        capabilities = self.check_capabilities()
        for cap in capabilities:
            try:
                cursor.execute('''
                INSERT OR REPLACE INTO capabilities 
                (path, capabilities, first_seen, last_checked, is_dangerous) 
                VALUES (?, ?, ?, ?, ?)
                ''', (
                    cap["path"],
                    cap["capabilities"],
                    current_time,
                    current_time,
                    1 if cap["is_dangerous"] else 0
                ))
                
                stats["capabilities"] += 1
                if cap["is_dangerous"]:
                    stats["suspicious_items"] += 1
            except Exception as e:
                self.logger.error(f"Error storing capability for {cap['path']}: {e}")
                
        # Process cron jobs
        cron_jobs = self.check_cron_jobs()
        for job in cron_jobs:
            try:
                cursor.execute('''
                INSERT INTO cron_jobs 
                (path, user, command, schedule, first_seen, last_checked, is_suspicious, suspicious_reason) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    job["path"],
                    job["user"],
                    job["command"],
                    job["schedule"],
                    current_time,
                    current_time,
                    1 if job["is_suspicious"] else 0,
                    job["suspicious_reason"]
                ))
                
                stats["cron_jobs"] += 1
                if job["is_suspicious"]:
                    stats["suspicious_items"] += 1
            except Exception as e:
                self.logger.error(f"Error storing cron job for {job['user']}: {e}")
                
        # Process NFS exports
        nfs_exports = self.check_nfs_exports()
        for export in nfs_exports:
            try:
                cursor.execute('''
                INSERT OR REPLACE INTO nfs_exports 
                (path, options, first_seen, last_checked, is_dangerous) 
                VALUES (?, ?, ?, ?, ?)
                ''', (
                    export["path"],
                    export["options"],
                    current_time,
                    current_time,
                    1 if export["is_dangerous"] else 0
                ))
                
                stats["nfs_exports"] += 1
                if export["is_dangerous"]:
                    stats["suspicious_items"] += 1
            except Exception as e:
                self.logger.error(f"Error storing NFS export for {export['path']}: {e}")
                
        # Process writable configs
        writable_configs = self.check_writable_configs()
        for config in writable_configs:
            try:
                cursor.execute('''
                INSERT OR REPLACE INTO writable_configs 
                (path, permissions, owner, group_owner, first_seen, last_checked) 
                VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    config["path"],
                    config["permissions"],
                    config["owner"],
                    config["group_owner"],
                    current_time,
                    current_time
                ))
                
                stats["writable_configs"] += 1
                stats["suspicious_items"] += 1  # All writable configs are suspicious
            except Exception as e:
                self.logger.error(f"Error storing writable config for {config['path']}: {e}")
                
        # Process container escapes
        container_escapes = self.check_container_escapes()
        for escape in container_escapes:
            try:
                cursor.execute('''
                INSERT INTO container_escapes 
                (vector_type, details, first_seen, last_checked) 
                VALUES (?, ?, ?, ?)
                ''', (
                    escape["vector_type"],
                    escape["details"],
                    current_time,
                    current_time
                ))
                
                stats["container_escapes"] += 1
                if escape["vector_type"] != "container_detection":
                    stats["suspicious_items"] += 1
            except Exception as e:
                self.logger.error(f"Error storing container escape vector: {e}")
                
        conn.commit()
        conn.close()
        
        self.logger.info(f"Baseline creation completed. Found {stats['suspicious_items']} suspicious items.")
        return stats
    
    def check_integrity(self):
        """
        Check for changes in privilege escalation vectors
        
        Returns:
            list: List of detected changes
        """
        self.logger.info("Checking privilege escalation integrity")
        
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        changes = []
        current_time = time.time()
        
        # Check SUID/SGID binaries
        suid_binaries = self.find_suid_sgid_binaries()
        current_suid_paths = {binary["path"]: binary for binary in suid_binaries}
        
        # Get baseline SUID binaries
        cursor.execute(
            "SELECT path, permissions, owner, group_owner, size, last_modified, is_excluded, is_suspicious FROM suid_binaries"
        )
        
        baseline_suid = {}
        for row in cursor.fetchall():
            baseline_suid[row[0]] = {
                "path": row[0],
                "permissions": row[1],
                "owner": row[2],
                "group_owner": row[3],
                "size": row[4],
                "last_modified": row[5],
                "is_excluded": row[6] == 1,
                "is_suspicious": row[7] == 1
            }
            
        # Check for new SUID binaries
        for path, binary in current_suid_paths.items():
            if path not in baseline_suid:
                # New SUID binary detected
                cursor.execute('''
                INSERT INTO escalation_changes 
                (vector_type, path, change_type, new_value, timestamp) 
                VALUES (?, ?, ?, ?, ?)
                ''', (
                    "suid_binary",
                    path,
                    "added",
                    f"Owner: {binary['owner']}, Group: {binary['group_owner']}, Permissions: {oct(binary['permissions'])}",
                    current_time
                ))
                
                # Add to baseline
                cursor.execute('''
                INSERT INTO suid_binaries 
                (path, permissions, owner, group_owner, size, last_modified, 
                 first_seen, last_checked, is_excluded, is_suspicious, suspicious_reason) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    binary["path"],
                    binary["permissions"],
                    binary["owner"],
                    binary["group_owner"],
                    binary["size"],
                    binary["last_modified"],
                    current_time,
                    current_time,
                    1 if binary["is_excluded"] else 0,
                    1 if binary["is_suspicious"] else 0,
                    binary["suspicious_reason"]
                ))
                
                changes.append({
                    "vector_type": "suid_binary",
                    "path": path,
                    "change_type": "added",
                    "is_suspicious": binary["is_suspicious"],
                    "old_value": None,
                    "new_value": f"Owner: {binary['owner']}, Group: {binary['group_owner']}, Permissions: {oct(binary['permissions'])}",
                    "timestamp": current_time
                })
            else:
                # Binary exists, check for changes
                baseline = baseline_suid[path]
                modified = False
                change_details = []
                
                # Check permissions
                if binary["permissions"] != baseline["permissions"]:
                    modified = True
                    change_details.append(f"Permissions changed: {oct(baseline['permissions'])} -> {oct(binary['permissions'])}")
                    
                # Check owner
                if binary["owner"] != baseline["owner"]:
                    modified = True
                    change_details.append(f"Owner changed: {baseline['owner']} -> {binary['owner']}")
                    
                # Check group
                if binary["group_owner"] != baseline["group_owner"]:
                    modified = True
                    change_details.append(f"Group changed: {baseline['group_owner']} -> {binary['group_owner']}")
                    
                # Check size
                if binary["size"] != baseline["size"]:
                    modified = True
                    change_details.append(f"Size changed: {baseline['size']} -> {binary['size']}")
                    
                # Check last modified time
                if binary["last_modified"] != baseline["last_modified"]:
                    modified = True
                    change_details.append(f"Last modified time changed")
                    
                if modified:
                    change_type = "modified"
                    
                    cursor.execute('''
                    INSERT INTO escalation_changes 
                    (vector_type, path, change_type, old_value, new_value, timestamp) 
                    VALUES (?, ?, ?, ?, ?, ?)
                    ''', (
                        "suid_binary",
                        path,
                        change_type,
                        f"Owner: {baseline['owner']}, Group: {baseline['group_owner']}, Permissions: {oct(baseline['permissions'])}",
                        f"Owner: {binary['owner']}, Group: {binary['group_owner']}, Permissions: {oct(binary['permissions'])}",
                        current_time
                    ))
                    
                    # Update baseline
                    cursor.execute('''
                    UPDATE suid_binaries 
                    SET permissions = ?, owner = ?, group_owner = ?, size = ?, 
                    last_modified = ?, last_checked = ?, is_suspicious = ?, suspicious_reason = ? 
                    WHERE path = ?
                    ''', (
                        binary["permissions"],
                        binary["owner"],
                        binary["group_owner"],
                        binary["size"],
                        binary["last_modified"],
                        current_time,
                        1 if binary["is_suspicious"] else 0,
                        binary["suspicious_reason"],
                        path
                    ))
                    
                    changes.append({
                        "vector_type": "suid_binary",
                        "path": path,
                        "change_type": change_type,
                        "is_suspicious": binary["is_suspicious"],
                        "old_value": f"Owner: {baseline['owner']}, Group: {baseline['group_owner']}, Permissions: {oct(baseline['permissions'])}",
                        "new_value": f"Owner: {binary['owner']}, Group: {binary['group_owner']}, Permissions: {oct(binary['permissions'])}",
                        "details": ", ".join(change_details),
                        "timestamp": current_time
                    })
                else:
                    # Just update the last_checked time
                    cursor.execute(
                        "UPDATE suid_binaries SET last_checked = ? WHERE path = ?",
                        (current_time, path)
                    )
        
        # Check for removed SUID binaries
        for path in baseline_suid:
            if path not in current_suid_paths:
                # SUID binary removed
                cursor.execute('''
                INSERT INTO escalation_changes 
                (vector_type, path, change_type, old_value, timestamp) 
                VALUES (?, ?, ?, ?, ?)
                ''', (
                    "suid_binary",
                    path,
                    "removed",
                    f"Owner: {baseline_suid[path]['owner']}, Group: {baseline_suid[path]['group_owner']}, Permissions: {oct(baseline_suid[path]['permissions'])}",
                    current_time
                ))
                
                # Remove from baseline
                cursor.execute("DELETE FROM suid_binaries WHERE path = ?", (path,))
                
                changes.append({
                    "vector_type": "suid_binary",
                    "path": path,
                    "change_type": "removed",
                    "is_suspicious": baseline_suid[path]["is_suspicious"],
                    "old_value": f"Owner: {baseline_suid[path]['owner']}, Group: {baseline_suid[path]['group_owner']}, Permissions: {oct(baseline_suid[path]['permissions'])}",
                    "new_value": None,
                    "timestamp": current_time
                })
        
        # Check sudo configurations
        sudo_configs = self.check_sudo_config()
        
        # Create a unique key for each sudo config
        current_sudo = {}
        for config in sudo_configs:
            key = f"{config['user']}@{config['host']}:{config['privileges']}"
            current_sudo[key] = config
            
        # Get baseline sudo configs
        cursor.execute(
            "SELECT id, user, host, privileges, is_dangerous FROM sudo_config"
        )
        
        baseline_sudo = {}
        for row in cursor.fetchall():
            key = f"{row[1]}@{row[2]}:{row[3]}"
            baseline_sudo[key] = {
                "id": row[0],
                "user": row[1],
                "host": row[2],
                "privileges": row[3],
                "is_dangerous": row[4] == 1
            }
            
        # Check for new sudo configs
        for key, config in current_sudo.items():
            if key not in baseline_sudo:
                # New sudo config detected
                cursor.execute('''
                INSERT INTO escalation_changes 
                (vector_type, path, change_type, new_value, timestamp) 
                VALUES (?, ?, ?, ?, ?)
                ''', (
                    "sudo_config",
                    f"{config['user']}@{config['host']}",
                    "added",
                    config['privileges'],
                    current_time
                ))
                
                # Add to baseline
                cursor.execute('''
                INSERT INTO sudo_config 
                (user, host, privileges, first_seen, last_checked, is_dangerous) 
                VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    config["user"],
                    config["host"],
                    config["privileges"],
                    current_time,
                    current_time,
                    1 if config["is_dangerous"] else 0
                ))
                
                changes.append({
                    "vector_type": "sudo_config",
                    "path": f"{config['user']}@{config['host']}",
                    "change_type": "added",
                    "is_suspicious": config["is_dangerous"],
                    "old_value": None,
                    "new_value": config['privileges'],
                    "timestamp": current_time
                })
            else:
                # Just update the last_checked time
                cursor.execute(
                    "UPDATE sudo_config SET last_checked = ? WHERE id = ?",
                    (current_time, baseline_sudo[key]["id"])
                )
                
        # Check for removed sudo configs
        for key, config in baseline_sudo.items():
            if key not in current_sudo:
                # Sudo config removed
                cursor.execute('''
                INSERT INTO escalation_changes 
                (vector_type, path, change_type, old_value, timestamp) 
                VALUES (?, ?, ?, ?, ?)
                ''', (
                    "sudo_config",
                    f"{config['user']}@{config['host']}",
                    "removed",
                    config['privileges'],
                    current_time
                ))
                
                # Remove from baseline
                cursor.execute("DELETE FROM sudo_config WHERE id = ?", (config["id"],))
                
                changes.append({
                    "vector_type": "sudo_config",
                    "path": f"{config['user']}@{config['host']}",
                    "change_type": "removed",
                    "is_suspicious": config["is_dangerous"],
                    "old_value": config['privileges'],
                    "new_value": None,
                    "timestamp": current_time
                })
        
        # Similar checks for capabilities, cron jobs, NFS exports, writable configs, and container escapes
        # would be implemented here following the same pattern
        
        conn.commit()
        conn.close()
        
        self.logger.info(f"Integrity check completed. Found {len(changes)} changes.")
        return changes
    
    def get_suspicious_vectors(self):
        """
        Get all suspicious privilege escalation vectors
        
        Returns:
            dict: Dictionary of suspicious vectors by type
        """
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        suspicious = {
            "suid_binaries": [],
            "sudo_configs": [],
            "capabilities": [],
            "cron_jobs": [],
            "nfs_exports": [],
            "writable_configs": [],
            "container_escapes": []
        }
        
        # Get suspicious SUID binaries
        cursor.execute(
            "SELECT path, permissions, owner, group_owner, suspicious_reason FROM suid_binaries WHERE is_suspicious = 1"
        )
        
        for row in cursor.fetchall():
            suspicious["suid_binaries"].append({
                "path": row[0],
                "permissions": oct(row[1]),
                "owner": row[2],
                "group_owner": row[3],
                "reason": row[4]
            })
            
        # Get dangerous sudo configs
        cursor.execute(
            "SELECT user, host, privileges FROM sudo_config WHERE is_dangerous = 1"
        )
        
        for row in cursor.fetchall():
            suspicious["sudo_configs"].append({
                "user": row[0],
                "host": row[1],
                "privileges": row[2]
            })
            
        # Get dangerous capabilities
        cursor.execute(
            "SELECT path, capabilities FROM capabilities WHERE is_dangerous = 1"
        )
        
        for row in cursor.fetchall():
            suspicious["capabilities"].append({
                "path": row[0],
                "capabilities": row[1]
            })
            
        # Get suspicious cron jobs
        cursor.execute(
            "SELECT path, user, command, schedule, suspicious_reason FROM cron_jobs WHERE is_suspicious = 1"
        )
        
        for row in cursor.fetchall():
            suspicious["cron_jobs"].append({
                "path": row[0],
                "user": row[1],
                "command": row[2],
                "schedule": row[3],
                "reason": row[4]
            })
            
        # Get dangerous NFS exports
        cursor.execute(
            "SELECT path, options FROM nfs_exports WHERE is_dangerous = 1"
        )
        
        for row in cursor.fetchall():
            suspicious["nfs_exports"].append({
                "path": row[0],
                "options": row[1]
            })
            
        # Get writable config files
        cursor.execute(
            "SELECT path, permissions, owner, group_owner FROM writable_configs"
        )
        
        for row in cursor.fetchall():
            suspicious["writable_configs"].append({
                "path": row[0],
                "permissions": oct(row[1]),
                "owner": row[2],
                "group_owner": row[3]
            })
            
        # Get container escape vectors
        cursor.execute(
            "SELECT vector_type, details FROM container_escapes WHERE vector_type != 'container_detection'"
        )
        
        for row in cursor.fetchall():
            suspicious["container_escapes"].append({
                "vector_type": row[0],
                "details": row[1]
            })
            
        conn.close()
        return suspicious
    
    def get_recent_changes(self, limit=100, since=None, include_verified=False):
        """
        Get recent changes to privilege escalation vectors
        
        Args:
            limit (int): Maximum number of changes to return
            since (float): Only return changes after this timestamp
            include_verified (bool): Whether to include verified changes
            
        Returns:
            list: List of recent changes
        """
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        query = "SELECT * FROM escalation_changes"
        params = []
        
        conditions = []
        
        if since is not None:
            conditions.append("timestamp > ?")
            params.append(since)
            
        if not include_verified:
            conditions.append("verified = 0")
            
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
            
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        
        changes = []
        for row in cursor.fetchall():
            changes.append({
                "id": row[0],
                "vector_type": row[1],
                "path": row[2],
                "change_type": row[3],
                "old_value": row[4],
                "new_value": row[5],
                "timestamp": row[6],
                "verified": bool(row[7])
            })
            
        conn.close()
        return changes
    
    def verify_change(self, change_id):
        """
        Mark a change as verified
        
        Args:
            change_id (int): ID of the change to verify
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            cursor.execute("UPDATE escalation_changes SET verified = 1 WHERE id = ?", (change_id,))
            conn.commit()
            conn.close()
            
            return True
        except Exception as e:
            self.logger.error(f"Failed to verify change {change_id}: {e}")
            return False
    
    def get_statistics(self):
        """
        Get statistics about privilege escalation vectors
        
        Returns:
            dict: Statistics about privilege escalation vectors
        """
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        stats = {}
        
        # SUID binaries stats
        cursor.execute("SELECT COUNT(*) FROM suid_binaries")
        stats["total_suid_binaries"] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM suid_binaries WHERE is_suspicious = 1")
        stats["suspicious_suid_binaries"] = cursor.fetchone()[0]
        
        # Sudo configs stats
        cursor.execute("SELECT COUNT(*) FROM sudo_config")
        stats["total_sudo_configs"] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM sudo_config WHERE is_dangerous = 1")
        stats["dangerous_sudo_configs"] = cursor.fetchone()[0]
        
        # Capabilities stats
        cursor.execute("SELECT COUNT(*) FROM capabilities")
        stats["total_capabilities"] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM capabilities WHERE is_dangerous = 1")
        stats["dangerous_capabilities"] = cursor.fetchone()[0]
        
        # Cron jobs stats
        cursor.execute("SELECT COUNT(*) FROM cron_jobs")
        stats["total_cron_jobs"] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM cron_jobs WHERE is_suspicious = 1")
        stats["suspicious_cron_jobs"] = cursor.fetchone()[0]
        
        # NFS exports stats
        cursor.execute("SELECT COUNT(*) FROM nfs_exports")
        stats["total_nfs_exports"] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM nfs_exports WHERE is_dangerous = 1")
        stats["dangerous_nfs_exports"] = cursor.fetchone()[0]
        
        # Writable configs stats
        cursor.execute("SELECT COUNT(*) FROM writable_configs")
        stats["writable_configs"] = cursor.fetchone()[0]
        
        # Container escapes stats
        cursor.execute("SELECT COUNT(*) FROM container_escapes")
        stats["total_container_vectors"] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM container_escapes WHERE vector_type != 'container_detection'")
        stats["dangerous_container_vectors"] = cursor.fetchone()[0]
        
        # Recent changes stats
        cursor.execute("SELECT COUNT(*) FROM escalation_changes WHERE timestamp > ?", 
                     (time.time() - 86400,))  # Last 24 hours
        stats["recent_changes"] = cursor.fetchone()[0]
        
        # Total suspicious items
        stats["total_suspicious_vectors"] = (
            stats["suspicious_suid_binaries"] +
            stats["dangerous_sudo_configs"] +
            stats["dangerous_capabilities"] +
            stats["suspicious_cron_jobs"] +
            stats["dangerous_nfs_exports"] +
            stats["writable_configs"] +
            stats["dangerous_container_vectors"]
        )
        
        conn.close()
        
        stats["last_updated"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        return stats
    
    def run_scan(self):
        """
        Run a full privilege escalation scan and return the results
        
        Returns:
            dict: Scan results
        """
        start_time = time.time()
        
        # Check integrity
        changes = self.check_integrity()
        
        scan_time = time.time() - start_time
        
        # Get suspicious vectors
        suspicious = self.get_suspicious_vectors()
        
        # Get statistics
        stats = self.get_statistics()
        
        # Determine threat level
        threat_level = "low"
        
        if stats["total_suspicious_vectors"] > 10:
            threat_level = "critical"
        elif stats["total_suspicious_vectors"] > 5:
            threat_level = "high"
        elif stats["total_suspicious_vectors"] > 0:
            threat_level = "medium"
            
        return {
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "scan_time_seconds": scan_time,
            "total_changes": len(changes),
            "threat_level": threat_level,
            "suspicious_vectors": suspicious,
            "statistics": stats,
            "recent_changes": changes[:10] if changes else []
        }
    
    def start_monitoring(self, interval=None):
        """
        Start continuous monitoring in a separate thread
        
        Args:
            interval (int): Monitoring interval in seconds, uses config if None
            
        Returns:
            bool: True if started successfully, False otherwise
        """
        if interval is None:
            interval = self.config["scan_interval"]
            
        self.logger.info(f"Starting continuous monitoring with interval of {interval} seconds")
        
        # Create a thread to run the monitoring
        import threading
        
        def monitoring_thread():
            while True:
                try:
                    self.logger.info("Running scheduled privilege escalation scan")
                    scan_results = self.run_scan()
                    
                    # Log results
                    self.logger.info(f"Scan completed. Threat level: {scan_results['threat_level']}, "
                                   f"Changes detected: {scan_results['total_changes']}")
                    
                    # Alert for high threat level
                    if scan_results["threat_level"] in ["medium", "high", "critical"]:
                        self.logger.warning(f"Elevated threat level detected: {scan_results['threat_level']}")
                        
                        # Log details of suspicious vectors
                        for vector_type, vectors in scan_results["suspicious_vectors"].items():
                            if vectors:
                                self.logger.warning(f"Suspicious {vector_type}: {len(vectors)}")
                                
                                for vector in vectors[:3]:  # Log first 3 of each type
                                    details = vector.get("path", "") or vector.get("user", "") or vector.get("vector_type", "")
                                    reason = vector.get("reason", "") or vector.get("details", "")
                                    self.logger.warning(f"  - {details}: {reason}")
                                    
                        # Log changes
                        if scan_results["recent_changes"]:
                            self.logger.warning(f"Recent changes detected: {len(scan_results['recent_changes'])}")
                            for change in scan_results["recent_changes"][:3]:  # Log first 3 changes
                                self.logger.warning(f"  - {change['vector_type']} {change['change_type']}: {change['path']}")
                    
                except Exception as e:
                    self.logger.error(f"Error in monitoring thread: {e}")
                
                # Sleep until next scan
                time.sleep(interval)
        
        # Start the thread
        monitor_thread = threading.Thread(target=monitoring_thread, daemon=True)
        monitor_thread.start()
        
        return True