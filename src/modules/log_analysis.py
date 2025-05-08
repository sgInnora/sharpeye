#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import json
import logging
import sqlite3
import time
import gzip
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import subprocess

class LogAnalysisEngine:
    """
    Log Analysis Engine Module
    
    Analyzes system and application logs for security events, correlates events
    across multiple logs, detects attack patterns, and identifies suspicious activities.
    """
    
    def __init__(self, database_path=None, config_file=None):
        """
        Initialize the Log Analysis Engine
        
        Args:
            database_path (str): Path to the database file
            config_file (str): Path to configuration file
        """
        self.logger = logging.getLogger("sharpeye.log_analysis")
        
        # Set default database path if not provided
        if database_path is None:
            home_dir = os.path.expanduser("~")
            self.database_path = os.path.join(home_dir, ".sharpeye", "log_analysis.db")
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
            "log_files": [
                "/var/log/auth.log",
                "/var/log/syslog",
                "/var/log/secure",
                "/var/log/messages",
                "/var/log/apache2/access.log",
                "/var/log/apache2/error.log",
                "/var/log/nginx/access.log",
                "/var/log/nginx/error.log",
                "/var/log/mysql/error.log",
                "/var/log/postgresql/postgresql.log",
                "/var/log/fail2ban.log",
                "/var/log/kern.log",
                "/var/log/audit/audit.log"
            ],
            "ignored_patterns": [
                r"systemd\[\d+\]: Started Session \d+ of user",
                r"systemd\[\d+\]: Starting Session \d+ of user",
                r"systemd-logind\[\d+\]: New session \d+ of user",
                r"CRON\[\d+\]"
            ],
            "suspicious_patterns": {
                "auth_failures": [
                    r"Failed password for .* from .* port \d+",
                    r"Failed password for invalid user .* from .* port \d+",
                    r"authentication failure",
                    r"Failed to authenticate",
                    r"authentication failed",
                    r"failed login",
                    r"invalid credentials",
                    r"authentication error"
                ],
                "brute_force": [
                    r"Failed password for .* from .* port \d+",
                    r"authentication failure",
                    r"Failed to authenticate"
                ],
                "privilege_escalation": [
                    r"sudo:.*(COMMAND|command)=",
                    r"\"sudo\".*TTY",
                    r"COMMAND=/bin/bash|COMMAND=/bin/sh",
                    r"pam_unix\(sudo:session\): session opened for user root",
                    r"elevated privileges",
                    r"became root",
                    r"gained access",
                    r"uid=0"
                ],
                "malware_activity": [
                    r"ELF header",
                    r"Executable and Linkable Format",
                    r"process .* killed by SIGSEGV",
                    r"exploit",
                    r"backdoor",
                    r"malware",
                    r"suspicious executable",
                    r"shell script",
                    r"reverse shell",
                    r"remote code execution"
                ],
                "web_attacks": [
                    r"SQL injection",
                    r"XSS",
                    r"cross-site scripting",
                    r"directory traversal",
                    r"LFI",
                    r"RFI",
                    r"command injection",
                    r"webshell",
                    r"file upload",
                    r"../../../",
                    r"\\.\\.\\.\\.\\",
                    r"select.*from",
                    r"UNION SELECT",
                    r"alert\\(",
                    r"eval\\(",
                    r"exec\\(",
                    r"system\\("
                ],
                "unauthorized_access": [
                    r"Access denied",
                    r"permission denied",
                    r"unauthorized access",
                    r"illegal access",
                    r"Access not allowed",
                    r"restricted access",
                    r"access violation"
                ],
                "data_exfiltration": [
                    r"large file transfer",
                    r"unusual outbound traffic",
                    r"data transfer",
                    r"suspicious upload",
                    r"outbound connection to",
                    r"data exfiltration",
                    r"excessive traffic"
                ],
                "suspicious_connections": [
                    r"CONNECT .* HTTP/1.1",
                    r"reverse connection",
                    r"outbound connection to",
                    r"unusual port",
                    r"suspicious IP",
                    r"known malicious IP",
                    r"unusual destination",
                    r"unusual protocol"
                ],
                "kernel_events": [
                    r"kernel: .* Oops",
                    r"kernel: .* segfault",
                    r"kernel: .* protection fault",
                    r"kernel: .* general protection fault",
                    r"kernel: .* memory corruption",
                    r"kernel: .* page fault",
                    r"kernel: .* protection error",
                    r"kernel: .* unauthorized access"
                ],
                "account_changes": [
                    r"password changed",
                    r"user added",
                    r"new user",
                    r"user deleted",
                    r"account locked",
                    r"account unlocked",
                    r"user modified",
                    r"group membership",
                    r"useradd",
                    r"usermod",
                    r"passwd"
                ],
                "file_integrity": [
                    r"file modified",
                    r"file deleted",
                    r"file permission changed",
                    r"file owner changed",
                    r"file integrity",
                    r"unauthorized file access",
                    r"file changed"
                ],
                "service_events": [
                    r"service .* stopped",
                    r"service .* started",
                    r"daemon .* terminated",
                    r"daemon .* started",
                    r"systemd: .* Failed",
                    r"systemd: .* failed to start",
                    r"systemd: .* stopped",
                    r"service disruption"
                ]
            },
            "critical_patterns": [
                r"EXPLOIT",
                r"kernel: .* Oops",
                r"kernel: .* segfault at",
                r"kernel: .* protection fault",
                r"reverse shell",
                r"remote code execution",
                r"backdoor",
                r"rootkit",
                r"exploit attempt",
                r"injection attempt",
                r"data exfiltration",
                r"privilege escalation",
                r"unauthorized root access"
            ],
            "correlation_rules": [
                # Brute force followed by successful login
                {
                    "name": "brute_force_success",
                    "description": "Brute force attack followed by successful login",
                    "rule_type": "sequence",
                    "patterns": [
                        {"category": "brute_force", "min_count": 5, "timeframe": 300},
                        {"pattern": r"Accepted password for .* from .* port \d+", "timeframe": 60}
                    ],
                    "severity": "high"
                },
                # Failed sudo followed by successful sudo
                {
                    "name": "sudo_brute_force",
                    "description": "Multiple failed sudo attempts followed by successful sudo",
                    "rule_type": "sequence",
                    "patterns": [
                        {"pattern": r"sudo: .* authentication failure", "min_count": 3, "timeframe": 300},
                        {"pattern": r"sudo: .* COMMAND=", "timeframe": 60}
                    ],
                    "severity": "high"
                },
                # Web attack followed by suspicious process
                {
                    "name": "web_attack_process",
                    "description": "Web attack followed by suspicious process execution",
                    "rule_type": "sequence",
                    "patterns": [
                        {"category": "web_attacks", "timeframe": 300},
                        {"pattern": r"process .* started", "timeframe": 60}
                    ],
                    "severity": "critical"
                },
                # Multiple failed logins from different IPs
                {
                    "name": "distributed_auth_attack",
                    "description": "Multiple failed authentication attempts from different IPs",
                    "rule_type": "frequency",
                    "pattern": r"Failed password for .* from (.*) port \d+",
                    "extract": 1,  # IP address
                    "distinct_values": 5,
                    "timeframe": 300,
                    "severity": "medium"
                },
                # Account modification after suspicious login
                {
                    "name": "account_compromise",
                    "description": "Account modification after suspicious login",
                    "rule_type": "sequence",
                    "patterns": [
                        {"category": "auth_failures", "timeframe": 600},
                        {"pattern": r"Accepted password for .* from .* port \d+", "timeframe": 300},
                        {"category": "account_changes", "timeframe": 300}
                    ],
                    "severity": "critical"
                }
            ],
            "whitelist_ips": [
                "127.0.0.1",
                "::1"
            ],
            "whitelist_users": [
                "root",
                "www-data",
                "nginx",
                "apache",
                "mysql",
                "postgres"
            ],
            "thread_count": 4,
            "scan_interval": 300,  # 5 minutes
            "retention_days": 30,
            "max_events_per_scan": 100000
        }
        
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                    # Merge user configuration with default
                    for key, value in user_config.items():
                        if key == "suspicious_patterns" and isinstance(value, dict):
                            # Merge suspicious patterns
                            for pattern_key, patterns in value.items():
                                if pattern_key in default_config["suspicious_patterns"]:
                                    default_config["suspicious_patterns"][pattern_key].extend(patterns)
                                else:
                                    default_config["suspicious_patterns"][pattern_key] = patterns
                        elif key == "correlation_rules" and isinstance(value, list):
                            # Append correlation rules
                            default_config["correlation_rules"].extend(value)
                        elif key in ["whitelist_ips", "whitelist_users", "ignored_patterns", "critical_patterns"] and isinstance(value, list):
                            # Extend lists
                            default_config[key].extend(value)
                        else:
                            # Replace other values
                            default_config[key] = value
                self.logger.info(f"Loaded configuration from {config_file}")
            except Exception as e:
                self.logger.error(f"Failed to load configuration file: {e}")
        
        return default_config
    
    def _initialize_database(self):
        """Initialize the SQLite database for storing log events and analysis results"""
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            # Create tables if they don't exist
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS log_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT UNIQUE,
                last_position INTEGER DEFAULT 0,
                last_modified REAL,
                first_seen REAL,
                last_checked REAL,
                hash TEXT
            )
            ''')
            
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS log_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_file_id INTEGER,
                timestamp REAL,
                timestamp_str TEXT,
                event_text TEXT,
                source_host TEXT,
                source_ip TEXT,
                source_user TEXT,
                category TEXT,
                severity TEXT,
                is_suspicious INTEGER DEFAULT 0,
                is_critical INTEGER DEFAULT 0,
                FOREIGN KEY (log_file_id) REFERENCES log_files (id)
            )
            ''')
            
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_type TEXT,
                description TEXT,
                source_ip TEXT,
                source_user TEXT,
                timestamp REAL,
                severity TEXT,
                related_events TEXT,
                correlation_rule TEXT,
                verified INTEGER DEFAULT 0
            )
            ''')
            
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_reputation (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE,
                reputation TEXT,
                last_checked REAL,
                failed_attempts INTEGER DEFAULT 0,
                successful_attempts INTEGER DEFAULT 0,
                first_seen REAL,
                last_seen REAL,
                is_blocked INTEGER DEFAULT 0
            )
            ''')
            
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_reputation (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                reputation TEXT,
                last_checked REAL,
                failed_attempts INTEGER DEFAULT 0,
                successful_attempts INTEGER DEFAULT 0,
                first_seen REAL,
                last_seen REAL,
                is_blocked INTEGER DEFAULT 0
            )
            ''')
            
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_log_events_timestamp ON log_events(timestamp)
            ''')
            
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_log_events_source_ip ON log_events(source_ip)
            ''')
            
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_log_events_source_user ON log_events(source_user)
            ''')
            
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_log_events_category ON log_events(category)
            ''')
            
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_log_events_suspicious ON log_events(is_suspicious)
            ''')
            
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_security_alerts_timestamp ON security_alerts(timestamp)
            ''')
            
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_security_alerts_severity ON security_alerts(severity)
            ''')
            
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_ip_reputation_ip ON ip_reputation(ip)
            ''')
            
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_user_reputation_username ON user_reputation(username)
            ''')
            
            # Set database pragmas for better performance
            cursor.execute('PRAGMA journal_mode = WAL')
            cursor.execute('PRAGMA synchronous = NORMAL')
            cursor.execute('PRAGMA temp_store = MEMORY')
            cursor.execute('PRAGMA mmap_size = 30000000000')
            
            conn.commit()
            self.logger.info("Database initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize database: {e}")
        finally:
            if conn:
                conn.close()
    
    def _is_whitelisted_ip(self, ip):
        """
        Check if an IP is whitelisted
        
        Args:
            ip (str): IP address to check
            
        Returns:
            bool: True if whitelisted, False otherwise
        """
        if not ip:
            return False
            
        # Direct match
        if ip in self.config["whitelist_ips"]:
            return True
            
        # Check subnet matches
        try:
            ip_obj = ipaddress.ip_address(ip)
            for whitelist in self.config["whitelist_ips"]:
                # Check if whitelist entry is a CIDR
                if '/' in whitelist:
                    subnet = ipaddress.ip_network(whitelist, strict=False)
                    if ip_obj in subnet:
                        return True
        except Exception:
            pass
            
        return False
    
    def _is_whitelisted_user(self, user):
        """
        Check if a user is whitelisted
        
        Args:
            user (str): Username to check
            
        Returns:
            bool: True if whitelisted, False otherwise
        """
        if not user:
            return False
            
        return user in self.config["whitelist_users"]
    
    def _is_log_ignored(self, log_entry):
        """
        Check if a log entry should be ignored
        
        Args:
            log_entry (str): Log entry to check
            
        Returns:
            bool: True if should be ignored, False otherwise
        """
        for pattern in self.config["ignored_patterns"]:
            if re.search(pattern, log_entry, re.IGNORECASE):
                return True
                
        return False
    
    def _categorize_log_entry(self, log_entry):
        """
        Categorize a log entry based on patterns
        
        Args:
            log_entry (str): Log entry to categorize
            
        Returns:
            tuple: (category, is_suspicious, is_critical, severity)
        """
        # Check if entry is critical
        is_critical = False
        for pattern in self.config["critical_patterns"]:
            if re.search(pattern, log_entry, re.IGNORECASE):
                is_critical = True
                break
                
        # Check suspicious patterns by category
        is_suspicious = False
        categories = []
        
        for category, patterns in self.config["suspicious_patterns"].items():
            for pattern in patterns:
                if re.search(pattern, log_entry, re.IGNORECASE):
                    is_suspicious = True
                    categories.append(category)
                    break
                    
        # Determine severity
        severity = "info"
        if is_critical:
            severity = "critical"
        elif is_suspicious:
            if any(c in ["privilege_escalation", "malware_activity", "data_exfiltration"] for c in categories):
                severity = "high"
            elif any(c in ["web_attacks", "unauthorized_access", "suspicious_connections"] for c in categories):
                severity = "medium"
            else:
                severity = "low"
                
        # If no specific categories found but entry is critical
        if is_critical and not categories:
            categories.append("critical_event")
            
        # If no categories identified, classify as general
        if not categories:
            categories.append("general")
            
        return (",".join(categories), is_suspicious, is_critical, severity)
    
    def _extract_log_details(self, log_entry, log_file):
        """
        Extract details from a log entry
        
        Args:
            log_entry (str): Log entry to parse
            log_file (str): Source log file
            
        Returns:
            dict: Extracted details
        """
        details = {
            "timestamp_str": "",
            "timestamp": None,
            "source_host": "",
            "source_ip": "",
            "source_user": ""
        }
        
        # Try to extract timestamp
        timestamp_patterns = [
            # Common syslog timestamp: "Jan 23 10:12:34"
            r'^(\w{3}\s+\d{1,2}\s+\d{1,2}:\d{2}:\d{2})',
            # ISO timestamp: "2023-01-23T10:12:34"
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})',
            # Syslog with year: "Jan 23 2023 10:12:34"
            r'^(\w{3}\s+\d{1,2}\s+\d{4}\s+\d{1,2}:\d{2}:\d{2})',
            # ISO format date: "2023-01-23 10:12:34"
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})'
        ]
        
        for pattern in timestamp_patterns:
            match = re.search(pattern, log_entry)
            if match:
                details["timestamp_str"] = match.group(1)
                try:
                    # Try to parse timestamp
                    if 'T' in details["timestamp_str"]:
                        dt = datetime.strptime(details["timestamp_str"], '%Y-%m-%dT%H:%M:%S')
                    elif '-' in details["timestamp_str"] and ' ' in details["timestamp_str"]:
                        dt = datetime.strptime(details["timestamp_str"], '%Y-%m-%d %H:%M:%S')
                    elif ' ' in details["timestamp_str"] and len(details["timestamp_str"].split()) == 3:
                        # Jan 23 10:12:34, need to add year
                        current_year = datetime.now().year
                        dt_str = f"{details['timestamp_str']} {current_year}"
                        dt = datetime.strptime(dt_str, '%b %d %H:%M:%S %Y')
                    elif ' ' in details["timestamp_str"] and len(details["timestamp_str"].split()) == 4:
                        # Jan 23 2023 10:12:34
                        dt = datetime.strptime(details["timestamp_str"], '%b %d %Y %H:%M:%S')
                    else:
                        # Default to current time if parsing fails
                        dt = datetime.now()
                        
                    details["timestamp"] = dt.timestamp()
                except Exception:
                    # If timestamp parsing fails, use file modification time or current time
                    details["timestamp"] = os.path.getmtime(log_file) if os.path.exists(log_file) else time.time()
                    
                break
                
        if not details["timestamp"]:
            # If no timestamp extracted, use file modification time or current time
            details["timestamp"] = os.path.getmtime(log_file) if os.path.exists(log_file) else time.time()
            
        # Try to extract IP address
        ip_patterns = [
            r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            r'IP:\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            r'from\s+([0-9a-fA-F:]+)',  # IPv6
            r'IP:\s+([0-9a-fA-F:]+)',   # IPv6
            r'([0-9a-fA-F:]+)'          # IPv6
        ]
        
        for pattern in ip_patterns:
            match = re.search(pattern, log_entry)
            if match:
                ip = match.group(1)
                # Validate IP address
                try:
                    ipaddress.ip_address(ip)
                    details["source_ip"] = ip
                    break
                except ValueError:
                    continue
                    
        # Try to extract hostname
        host_patterns = [
            r'from\s+(\S+)\s+',
            r'host=(\S+)',
            r'host\s+(\S+)',
            r'hostname=(\S+)',
            r'hostname\s+(\S+)'
        ]
        
        for pattern in host_patterns:
            match = re.search(pattern, log_entry)
            if match:
                host = match.group(1)
                # Remove port if present
                if ':' in host:
                    host = host.split(':')[0]
                details["source_host"] = host
                break
                
        # Try to extract username
        user_patterns = [
            r'user\s+(\S+)',
            r'user=(\S+)',
            r'username=(\S+)',
            r'username\s+(\S+)',
            r'for\s+(\S+)\s+from',
            r'for user (\S+)',
            r'for invalid user (\S+)'
        ]
        
        for pattern in user_patterns:
            match = re.search(pattern, log_entry)
            if match:
                details["source_user"] = match.group(1)
                break
                
        return details
    
    def _open_log_file(self, file_path):
        """
        Open a log file for reading, handling compressed files
        
        Args:
            file_path (str): Path to the log file
            
        Returns:
            file: File object
        """
        if file_path.endswith('.gz'):
            return gzip.open(file_path, 'rt', encoding='utf-8', errors='replace')
        else:
            return open(file_path, 'r', encoding='utf-8', errors='replace')
    
    def _get_log_file_hash(self, file_path):
        """
        Calculate hash for a log file
        
        Args:
            file_path (str): Path to the log file
            
        Returns:
            str: File hash or None if failed
        """
        try:
            if not os.path.isfile(file_path):
                return None
                
            hasher = hashlib.sha256()
            
            with open(file_path, 'rb') as f:
                # Read file in chunks
                for chunk in iter(lambda: f.read(65536), b''):
                    hasher.update(chunk)
                    
            return hasher.hexdigest()
        except Exception as e:
            self.logger.debug(f"Cannot hash file {file_path}: {e}")
            return None
    
    def process_log_file(self, file_path, start_position=0, max_events=None):
        """
        Process a log file and extract events
        
        Args:
            file_path (str): Path to the log file
            start_position (int): Position to start reading from
            max_events (int): Maximum number of events to process
            
        Returns:
            tuple: (events, new_position)
        """
        if not os.path.exists(file_path):
            return [], 0
            
        events = []
        current_position = start_position
        
        try:
            # Check if file has been rotated
            file_size = os.path.getsize(file_path)
            if file_size < start_position:
                # File has been rotated, start from beginning
                start_position = 0
                current_position = 0
                
            with self._open_log_file(file_path) as f:
                # Seek to the start position
                f.seek(start_position)
                
                count = 0
                for line in f:
                    line = line.strip()
                    if line:
                        # Update current position
                        current_position = f.tell()
                        
                        # Skip ignored log entries
                        if self._is_log_ignored(line):
                            continue
                            
                        # Extract details from log entry
                        details = self._extract_log_details(line, file_path)
                        
                        # Categorize log entry
                        category, is_suspicious, is_critical, severity = self._categorize_log_entry(line)
                        
                        # Check if IP or user is whitelisted
                        if (details["source_ip"] and self._is_whitelisted_ip(details["source_ip"])) or \
                           (details["source_user"] and self._is_whitelisted_user(details["source_user"])):
                            # Downgrade severity for whitelisted sources unless it's critical
                            if not is_critical:
                                is_suspicious = False
                                severity = "info"
                                
                        events.append({
                            "log_file": file_path,
                            "timestamp": details["timestamp"],
                            "timestamp_str": details["timestamp_str"],
                            "event_text": line,
                            "source_host": details["source_host"],
                            "source_ip": details["source_ip"],
                            "source_user": details["source_user"],
                            "category": category,
                            "severity": severity,
                            "is_suspicious": is_suspicious,
                            "is_critical": is_critical
                        })
                        
                        count += 1
                        if max_events and count >= max_events:
                            break
                            
        except Exception as e:
            self.logger.error(f"Error processing log file {file_path}: {e}")
            
        return events, current_position
    
    def store_events(self, events):
        """
        Store log events in the database
        
        Args:
            events (list): List of events to store
            
        Returns:
            int: Number of events stored
        """
        if not events:
            return 0
            
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        stored_count = 0
        
        try:
            # Process log files
            for event in events:
                try:
                    # Get or create log file entry
                    cursor.execute(
                        "SELECT id FROM log_files WHERE path = ?",
                        (event["log_file"],)
                    )
                    
                    row = cursor.fetchone()
                    if row:
                        log_file_id = row[0]
                    else:
                        # New log file
                        file_hash = self._get_log_file_hash(event["log_file"])
                        current_time = time.time()
                        last_modified = os.path.getmtime(event["log_file"]) if os.path.exists(event["log_file"]) else current_time
                        
                        cursor.execute('''
                        INSERT INTO log_files 
                        (path, last_position, last_modified, first_seen, last_checked, hash) 
                        VALUES (?, ?, ?, ?, ?, ?)
                        ''', (
                            event["log_file"],
                            0,
                            last_modified,
                            current_time,
                            current_time,
                            file_hash
                        ))
                        
                        log_file_id = cursor.lastrowid
                        
                    # Store the event
                    cursor.execute('''
                    INSERT INTO log_events 
                    (log_file_id, timestamp, timestamp_str, event_text, source_host, source_ip, source_user, 
                     category, severity, is_suspicious, is_critical) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        log_file_id,
                        event["timestamp"],
                        event["timestamp_str"],
                        event["event_text"],
                        event["source_host"],
                        event["source_ip"],
                        event["source_user"],
                        event["category"],
                        event["severity"],
                        1 if event["is_suspicious"] else 0,
                        1 if event["is_critical"] else 0
                    ))
                    
                    stored_count += 1
                    
                    # Update IP reputation
                    if event["source_ip"]:
                        self._update_ip_reputation(cursor, event)
                        
                    # Update user reputation
                    if event["source_user"]:
                        self._update_user_reputation(cursor, event)
                        
                except Exception as e:
                    self.logger.error(f"Error storing event: {e}")
                    
            # Update log file positions
            log_files = {}
            for event in events:
                if event["log_file"] not in log_files:
                    log_files[event["log_file"]] = 0
                    
            for file_path, _ in log_files.items():
                try:
                    # Get the current file size
                    file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
                    
                    cursor.execute(
                        "UPDATE log_files SET last_position = ?, last_checked = ? WHERE path = ?",
                        (file_size, time.time(), file_path)
                    )
                except Exception as e:
                    self.logger.error(f"Error updating log file position for {file_path}: {e}")
                    
            conn.commit()
            
        except Exception as e:
            self.logger.error(f"Error storing events: {e}")
            
        finally:
            conn.close()
            
        return stored_count
    
    def _update_ip_reputation(self, cursor, event):
        """
        Update IP reputation based on event
        
        Args:
            cursor: Database cursor
            event (dict): Event information
        """
        try:
            # Check if IP exists in database
            cursor.execute(
                "SELECT id, failed_attempts, successful_attempts, reputation FROM ip_reputation WHERE ip = ?",
                (event["source_ip"],)
            )
            
            row = cursor.fetchone()
            current_time = time.time()
            
            if row:
                # Update existing IP
                ip_id = row[0]
                failed_attempts = row[1]
                successful_attempts = row[2]
                current_reputation = row[3] or "neutral"
                
                # Update failed/successful attempts
                if "auth_failures" in event["category"] or "brute_force" in event["category"]:
                    failed_attempts += 1
                elif "Accepted" in event["event_text"] and "password" in event["event_text"]:
                    successful_attempts += 1
                    
                # Calculate new reputation
                reputation = self._calculate_reputation(failed_attempts, successful_attempts, current_reputation, event["is_critical"])
                
                cursor.execute('''
                UPDATE ip_reputation 
                SET reputation = ?, last_checked = ?, failed_attempts = ?, 
                successful_attempts = ?, last_seen = ? 
                WHERE id = ?
                ''', (
                    reputation,
                    current_time,
                    failed_attempts,
                    successful_attempts,
                    current_time,
                    ip_id
                ))
                
            else:
                # New IP
                failed_attempts = 1 if "auth_failures" in event["category"] or "brute_force" in event["category"] else 0
                successful_attempts = 1 if "Accepted" in event["event_text"] and "password" in event["event_text"] else 0
                
                # Calculate reputation
                reputation = self._calculate_reputation(failed_attempts, successful_attempts, "neutral", event["is_critical"])
                
                cursor.execute('''
                INSERT INTO ip_reputation 
                (ip, reputation, last_checked, failed_attempts, successful_attempts, 
                 first_seen, last_seen, is_blocked) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    event["source_ip"],
                    reputation,
                    current_time,
                    failed_attempts,
                    successful_attempts,
                    current_time,
                    current_time,
                    0  # Not blocked initially
                ))
                
        except Exception as e:
            self.logger.error(f"Error updating IP reputation for {event['source_ip']}: {e}")
    
    def _update_user_reputation(self, cursor, event):
        """
        Update user reputation based on event
        
        Args:
            cursor: Database cursor
            event (dict): Event information
        """
        try:
            # Check if user exists in database
            cursor.execute(
                "SELECT id, failed_attempts, successful_attempts, reputation FROM user_reputation WHERE username = ?",
                (event["source_user"],)
            )
            
            row = cursor.fetchone()
            current_time = time.time()
            
            if row:
                # Update existing user
                user_id = row[0]
                failed_attempts = row[1]
                successful_attempts = row[2]
                current_reputation = row[3] or "neutral"
                
                # Update failed/successful attempts
                if "auth_failures" in event["category"] or "brute_force" in event["category"]:
                    failed_attempts += 1
                elif "Accepted" in event["event_text"] and "password" in event["event_text"]:
                    successful_attempts += 1
                    
                # Calculate new reputation
                reputation = self._calculate_reputation(failed_attempts, successful_attempts, current_reputation, event["is_critical"])
                
                cursor.execute('''
                UPDATE user_reputation 
                SET reputation = ?, last_checked = ?, failed_attempts = ?, 
                successful_attempts = ?, last_seen = ? 
                WHERE id = ?
                ''', (
                    reputation,
                    current_time,
                    failed_attempts,
                    successful_attempts,
                    current_time,
                    user_id
                ))
                
            else:
                # New user
                failed_attempts = 1 if "auth_failures" in event["category"] or "brute_force" in event["category"] else 0
                successful_attempts = 1 if "Accepted" in event["event_text"] and "password" in event["event_text"] else 0
                
                # Calculate reputation
                reputation = self._calculate_reputation(failed_attempts, successful_attempts, "neutral", event["is_critical"])
                
                cursor.execute('''
                INSERT INTO user_reputation 
                (username, reputation, last_checked, failed_attempts, successful_attempts, 
                 first_seen, last_seen, is_blocked) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    event["source_user"],
                    reputation,
                    current_time,
                    failed_attempts,
                    successful_attempts,
                    current_time,
                    current_time,
                    0  # Not blocked initially
                ))
                
        except Exception as e:
            self.logger.error(f"Error updating user reputation for {event['source_user']}: {e}")
    
    def _calculate_reputation(self, failed_attempts, successful_attempts, current_reputation, is_critical):
        """
        Calculate reputation based on failed and successful attempts
        
        Args:
            failed_attempts (int): Number of failed attempts
            successful_attempts (int): Number of successful attempts
            current_reputation (str): Current reputation
            is_critical (bool): Whether the event is critical
            
        Returns:
            str: New reputation
        """
        # Critical events immediately set bad reputation
        if is_critical:
            return "bad"
            
        # Calculate reputation score
        total_attempts = failed_attempts + successful_attempts
        if total_attempts == 0:
            return "neutral"
            
        failure_ratio = failed_attempts / total_attempts
        
        if current_reputation == "good":
            if failure_ratio > 0.5:
                return "neutral"
            else:
                return "good"
        elif current_reputation == "neutral":
            if failure_ratio > 0.7:
                return "bad"
            elif failure_ratio < 0.3:
                return "good"
            else:
                return "neutral"
        elif current_reputation == "bad":
            if failure_ratio < 0.2:
                return "neutral"
            else:
                return "bad"
        else:
            # Default (new entity)
            if failure_ratio > 0.7:
                return "bad"
            elif failure_ratio < 0.3:
                return "good"
            else:
                return "neutral"
    
    def apply_correlation_rules(self):
        """
        Apply correlation rules to detect security events
        
        Returns:
            int: Number of alerts generated
        """
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        alerts_generated = 0
        
        try:
            for rule in self.config["correlation_rules"]:
                try:
                    if rule["rule_type"] == "sequence":
                        alerts = self._apply_sequence_rule(cursor, rule)
                    elif rule["rule_type"] == "frequency":
                        alerts = self._apply_frequency_rule(cursor, rule)
                    else:
                        self.logger.warning(f"Unknown rule type: {rule['rule_type']}")
                        continue
                        
                    # Store alerts
                    for alert in alerts:
                        cursor.execute('''
                        INSERT INTO security_alerts 
                        (alert_type, description, source_ip, source_user, timestamp, 
                         severity, related_events, correlation_rule, verified) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            alert["alert_type"],
                            alert["description"],
                            alert["source_ip"],
                            alert["source_user"],
                            alert["timestamp"],
                            alert["severity"],
                            alert["related_events"],
                            alert["correlation_rule"],
                            0  # Not verified initially
                        ))
                        
                        alerts_generated += 1
                        
                except Exception as e:
                    self.logger.error(f"Error applying rule {rule['name']}: {e}")
                    
            conn.commit()
            
        except Exception as e:
            self.logger.error(f"Error applying correlation rules: {e}")
            
        finally:
            conn.close()
            
        return alerts_generated
    
    def _apply_sequence_rule(self, cursor, rule):
        """
        Apply a sequence correlation rule
        
        Args:
            cursor: Database cursor
            rule (dict): Rule configuration
            
        Returns:
            list: Generated alerts
        """
        alerts = []
        
        # Get the timeframe for the first pattern
        timeframe = rule["patterns"][0].get("timeframe", 300)  # Default 5 minutes
        min_count = rule["patterns"][0].get("min_count", 1)
        
        # Calculate the time window
        end_time = time.time()
        start_time = end_time - timeframe
        
        # Get matching events for the first pattern
        initial_events = []
        
        if "category" in rule["patterns"][0]:
            # Match by category
            category = rule["patterns"][0]["category"]
            cursor.execute('''
            SELECT id, timestamp, source_ip, source_user, event_text 
            FROM log_events 
            WHERE category LIKE ? AND timestamp BETWEEN ? AND ?
            ORDER BY timestamp DESC
            ''', (f"%{category}%", start_time, end_time))
            
            initial_events = cursor.fetchall()
            
        elif "pattern" in rule["patterns"][0]:
            # Match by pattern
            pattern = rule["patterns"][0]["pattern"]
            cursor.execute('''
            SELECT id, timestamp, source_ip, source_user, event_text 
            FROM log_events 
            WHERE event_text REGEXP ? AND timestamp BETWEEN ? AND ?
            ORDER BY timestamp DESC
            ''', (pattern, start_time, end_time))
            
            # SQLite doesn't support REGEXP natively, so we might need to use LIKE
            if not initial_events:
                cursor.execute('''
                SELECT id, timestamp, source_ip, source_user, event_text 
                FROM log_events 
                WHERE timestamp BETWEEN ? AND ?
                ORDER BY timestamp DESC
                ''', (start_time, end_time))
                
                tmp_events = cursor.fetchall()
                initial_events = []
                
                for event in tmp_events:
                    if re.search(pattern, event[4], re.IGNORECASE):
                        initial_events.append(event)
        
        # Group events by source IP
        grouped_events = {}
        for event in initial_events:
            source_ip = event[2]
            if source_ip:
                if source_ip not in grouped_events:
                    grouped_events[source_ip] = []
                grouped_events[source_ip].append(event)
                
        # Check each group against min_count
        for source_ip, events in grouped_events.items():
            if len(events) >= min_count:
                # This IP has enough events for the first pattern
                # Now check subsequent patterns
                matched = True
                related_events = [e[0] for e in events[:min_count]]  # Take the required number of event IDs
                last_event_time = events[0][1]  # Most recent event timestamp
                
                for i in range(1, len(rule["patterns"])):
                    pattern_def = rule["patterns"][i]
                    pattern_timeframe = pattern_def.get("timeframe", 60)  # Default 1 minute
                    
                    # Calculate the time window for this pattern
                    pattern_start_time = last_event_time
                    pattern_end_time = pattern_start_time + pattern_timeframe
                    
                    # Get matching events for this pattern
                    if "category" in pattern_def:
                        # Match by category
                        category = pattern_def["category"]
                        cursor.execute('''
                        SELECT id, timestamp 
                        FROM log_events 
                        WHERE category LIKE ? AND source_ip = ? AND timestamp BETWEEN ? AND ?
                        ORDER BY timestamp ASC
                        LIMIT 1
                        ''', (f"%{category}%", source_ip, pattern_start_time, pattern_end_time))
                        
                    elif "pattern" in pattern_def:
                        # Match by pattern
                        pattern = pattern_def["pattern"]
                        cursor.execute('''
                        SELECT id, timestamp 
                        FROM log_events 
                        WHERE event_text REGEXP ? AND source_ip = ? AND timestamp BETWEEN ? AND ?
                        ORDER BY timestamp ASC
                        LIMIT 1
                        ''', (pattern, source_ip, pattern_start_time, pattern_end_time))
                        
                        # SQLite doesn't support REGEXP natively, so we might need to use LIKE
                        if not cursor.fetchone():
                            cursor.execute('''
                            SELECT id, timestamp, event_text 
                            FROM log_events 
                            WHERE source_ip = ? AND timestamp BETWEEN ? AND ?
                            ORDER BY timestamp ASC
                            ''', (source_ip, pattern_start_time, pattern_end_time))
                            
                            match_found = False
                            for event_row in cursor.fetchall():
                                if re.search(pattern, event_row[2], re.IGNORECASE):
                                    match_row = (event_row[0], event_row[1])
                                    match_found = True
                                    break
                                    
                            if not match_found:
                                matched = False
                                break
                        else:
                            cursor.execute('''
                            SELECT id, timestamp 
                            FROM log_events 
                            WHERE event_text REGEXP ? AND source_ip = ? AND timestamp BETWEEN ? AND ?
                            ORDER BY timestamp ASC
                            LIMIT 1
                            ''', (pattern, source_ip, pattern_start_time, pattern_end_time))
                    
                    match_row = cursor.fetchone()
                    if not match_row:
                        matched = False
                        break
                        
                    # Add this event to related events
                    related_events.append(match_row[0])
                    last_event_time = match_row[1]
                    
                if matched:
                    # All patterns matched, generate an alert
                    # Get source user from one of the events
                    cursor.execute(
                        "SELECT source_user FROM log_events WHERE id = ?",
                        (related_events[0],)
                    )
                    source_user = cursor.fetchone()[0]
                    
                    alert = {
                        "alert_type": rule["name"],
                        "description": rule["description"],
                        "source_ip": source_ip,
                        "source_user": source_user,
                        "timestamp": time.time(),
                        "severity": rule["severity"],
                        "related_events": json.dumps(related_events),
                        "correlation_rule": rule["name"]
                    }
                    
                    alerts.append(alert)
                    
        return alerts
    
    def _apply_frequency_rule(self, cursor, rule):
        """
        Apply a frequency correlation rule
        
        Args:
            cursor: Database cursor
            rule (dict): Rule configuration
            
        Returns:
            list: Generated alerts
        """
        alerts = []
        
        # Get rule parameters
        pattern = rule["pattern"]
        extract_index = rule.get("extract", 0)  # Default to full match
        distinct_values = rule.get("distinct_values", 1)
        timeframe = rule.get("timeframe", 300)  # Default 5 minutes
        
        # Calculate the time window
        end_time = time.time()
        start_time = end_time - timeframe
        
        # Get matching events
        cursor.execute('''
        SELECT id, timestamp, source_ip, source_user, event_text 
        FROM log_events 
        WHERE timestamp BETWEEN ? AND ?
        ORDER BY timestamp DESC
        ''', (start_time, end_time))
        
        events = cursor.fetchall()
        
        # Extract values using pattern
        extracted_values = {}
        for event in events:
            event_text = event[4]
            match = re.search(pattern, event_text, re.IGNORECASE)
            if match:
                try:
                    # Extract the specified group
                    if extract_index <= len(match.groups()):
                        value = match.group(extract_index) if extract_index > 0 else match.group(0)
                        if value not in extracted_values:
                            extracted_values[value] = []
                        extracted_values[value].append(event)
                except Exception:
                    continue
                    
        # Check if we have enough distinct values
        if len(extracted_values) >= distinct_values:
            # Generate an alert
            # Use the most frequent value for alert details
            most_frequent = max(extracted_values.items(), key=lambda x: len(x[1]))
            value = most_frequent[0]
            value_events = most_frequent[1]
            
            # Get source IP and user
            source_ip = value_events[0][2]
            source_user = value_events[0][3]
            
            # Get all related event IDs
            related_events = []
            for events_list in extracted_values.values():
                related_events.extend([e[0] for e in events_list])
                
            alert = {
                "alert_type": rule["name"],
                "description": f"{rule['description']} (Detected {len(extracted_values)} distinct values)",
                "source_ip": source_ip,
                "source_user": source_user,
                "timestamp": time.time(),
                "severity": rule["severity"],
                "related_events": json.dumps(related_events),
                "correlation_rule": rule["name"]
            }
            
            alerts.append(alert)
            
        return alerts
    
    def cleanup_old_data(self):
        """
        Clean up old data based on retention policy
        
        Returns:
            int: Number of records deleted
        """
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        deleted_count = 0
        
        try:
            # Calculate cutoff time
            retention_days = self.config.get("retention_days", 30)
            cutoff_time = time.time() - (retention_days * 24 * 60 * 60)
            
            # Delete old log events
            cursor.execute(
                "DELETE FROM log_events WHERE timestamp < ?",
                (cutoff_time,)
            )
            
            deleted_count += cursor.rowcount
            
            # Delete old security alerts
            cursor.execute(
                "DELETE FROM security_alerts WHERE timestamp < ?",
                (cutoff_time,)
            )
            
            deleted_count += cursor.rowcount
            
            # Delete IP reputation for IPs not seen in a long time
            cursor.execute(
                "DELETE FROM ip_reputation WHERE last_seen < ?",
                (cutoff_time,)
            )
            
            deleted_count += cursor.rowcount
            
            # Delete user reputation for users not seen in a long time
            cursor.execute(
                "DELETE FROM user_reputation WHERE last_seen < ?",
                (cutoff_time,)
            )
            
            deleted_count += cursor.rowcount
            
            conn.commit()
            
        except Exception as e:
            self.logger.error(f"Error cleaning up old data: {e}")
            
        finally:
            conn.close()
            
        return deleted_count
    
    def create_baseline(self):
        """
        Create a baseline of log events
        
        Returns:
            dict: Statistics about the baseline creation
        """
        self.logger.info("Creating log analysis baseline")
        
        stats = {
            "files_processed": 0,
            "events_collected": 0,
            "alerts_generated": 0,
            "suspicious_events": 0,
            "critical_events": 0
        }
        
        # Process log files
        max_events = self.config.get("max_events_per_scan", 100000)
        
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        # Get existing log files
        cursor.execute("SELECT path, last_position FROM log_files")
        existing_files = {row[0]: row[1] for row in cursor.fetchall()}
        
        conn.close()
        
        # Process each log file
        all_events = []
        
        for file_path in self.config["log_files"]:
            if not os.path.exists(file_path):
                continue
                
            start_position = existing_files.get(file_path, 0)
            events, new_position = self.process_log_file(file_path, start_position, max_events // len(self.config["log_files"]))
            
            if events:
                all_events.extend(events)
                stats["files_processed"] += 1
                stats["events_collected"] += len(events)
                stats["suspicious_events"] += sum(1 for e in events if e["is_suspicious"])
                stats["critical_events"] += sum(1 for e in events if e["is_critical"])
                
        # Store events in database
        if all_events:
            self.store_events(all_events)
            
        # Apply correlation rules
        stats["alerts_generated"] = self.apply_correlation_rules()
        
        # Cleanup old data
        self.cleanup_old_data()
        
        self.logger.info(f"Baseline creation completed. Collected {stats['events_collected']} events, "
                       f"generated {stats['alerts_generated']} alerts.")
        return stats
    
    def check_integrity(self):
        """
        Check log files for new events
        
        Returns:
            dict: Statistics about the check
        """
        self.logger.info("Checking log files for new events")
        
        stats = {
            "files_processed": 0,
            "events_collected": 0,
            "alerts_generated": 0,
            "suspicious_events": 0,
            "critical_events": 0
        }
        
        # Process log files
        max_events = self.config.get("max_events_per_scan", 100000)
        
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        # Get existing log files
        cursor.execute("SELECT path, last_position FROM log_files")
        existing_files = {row[0]: row[1] for row in cursor.fetchall()}
        
        conn.close()
        
        # Process each log file
        all_events = []
        
        for file_path in self.config["log_files"]:
            if not os.path.exists(file_path):
                continue
                
            start_position = existing_files.get(file_path, 0)
            events, new_position = self.process_log_file(file_path, start_position, max_events // len(self.config["log_files"]))
            
            if events:
                all_events.extend(events)
                stats["files_processed"] += 1
                stats["events_collected"] += len(events)
                stats["suspicious_events"] += sum(1 for e in events if e["is_suspicious"])
                stats["critical_events"] += sum(1 for e in events if e["is_critical"])
                
        # Store events in database
        if all_events:
            self.store_events(all_events)
            
        # Apply correlation rules
        stats["alerts_generated"] = self.apply_correlation_rules()
        
        self.logger.info(f"Check completed. Collected {stats['events_collected']} new events, "
                       f"generated {stats['alerts_generated']} alerts.")
        return stats
    
    def check_log_tampering(self):
        """
        Check for log tampering
        
        Returns:
            list: Detected tampering events
        """
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        tampering_events = []
        
        try:
            # Check each log file
            cursor.execute("SELECT id, path, last_modified, hash FROM log_files")
            log_files = cursor.fetchall()
            
            for log_file in log_files:
                file_id, file_path, last_modified, file_hash = log_file
                
                if not os.path.exists(file_path):
                    # Log file was deleted
                    tampering_events.append({
                        "file_path": file_path,
                        "tampering_type": "deletion",
                        "description": "Log file was deleted",
                        "timestamp": time.time()
                    })
                    continue
                    
                # Check if file was modified
                current_modified = os.path.getmtime(file_path)
                current_hash = self._get_log_file_hash(file_path)
                
                if current_hash != file_hash:
                    # File hash changed
                    if current_modified < last_modified:
                        # File is older than last check - suspicious
                        tampering_events.append({
                            "file_path": file_path,
                            "tampering_type": "backdating",
                            "description": "Log file was modified and backdated",
                            "timestamp": time.time()
                        })
                    else:
                        # Get file size
                        file_size = os.path.getsize(file_path)
                        
                        # Get current position
                        cursor.execute("SELECT last_position FROM log_files WHERE id = ?", (file_id,))
                        last_position = cursor.fetchone()[0]
                        
                        if file_size < last_position:
                            # File is smaller than before - suspicious
                            tampering_events.append({
                                "file_path": file_path,
                                "tampering_type": "truncation",
                                "description": "Log file was truncated",
                                "timestamp": time.time()
                            })
                
                # Update file hash and modification time
                cursor.execute(
                    "UPDATE log_files SET hash = ?, last_modified = ? WHERE id = ?",
                    (current_hash, current_modified, file_id)
                )
                
            conn.commit()
            
            # Check for log lines with invalid timestamps
            cursor.execute(
                "SELECT timestamp FROM log_events ORDER BY id DESC LIMIT 1000"
            )
            
            recent_timestamps = [row[0] for row in cursor.fetchall()]
            
            if recent_timestamps:
                # Check for timestamps in the future
                current_time = time.time()
                future_timestamps = [ts for ts in recent_timestamps if ts > current_time + 3600]  # 1 hour buffer
                
                if future_timestamps:
                    tampering_events.append({
                        "file_path": "multiple",
                        "tampering_type": "future_timestamps",
                        "description": f"Found {len(future_timestamps)} log entries with future timestamps",
                        "timestamp": time.time()
                    })
                    
                # Check for large time gaps
                sorted_timestamps = sorted(recent_timestamps)
                for i in range(1, len(sorted_timestamps)):
                    time_gap = sorted_timestamps[i] - sorted_timestamps[i-1]
                    if time_gap > 86400:  # 24 hour gap
                        tampering_events.append({
                            "file_path": "multiple",
                            "tampering_type": "time_gap",
                            "description": f"Found large time gap of {time_gap:.2f} seconds in log events",
                            "timestamp": time.time()
                        })
                        break
            
        except Exception as e:
            self.logger.error(f"Error checking log tampering: {e}")
            
        finally:
            conn.close()
            
        return tampering_events
    
    def get_security_alerts(self, limit=100, severity=None, since=None):
        """
        Get recent security alerts
        
        Args:
            limit (int): Maximum number of alerts to return
            severity (str): Filter by severity
            since (float): Only return alerts after this timestamp
            
        Returns:
            list: List of security alerts
        """
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        query = "SELECT * FROM security_alerts"
        params = []
        
        conditions = []
        
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
            
        if since:
            conditions.append("timestamp > ?")
            params.append(since)
            
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
            
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        
        alerts = []
        for row in cursor.fetchall():
            alerts.append({
                "id": row[0],
                "alert_type": row[1],
                "description": row[2],
                "source_ip": row[3],
                "source_user": row[4],
                "timestamp": row[5],
                "severity": row[6],
                "related_events": json.loads(row[7]) if row[7] else [],
                "correlation_rule": row[8],
                "verified": bool(row[9])
            })
            
        conn.close()
        
        return alerts
    
    def get_suspicious_events(self, limit=100, category=None, since=None):
        """
        Get suspicious log events
        
        Args:
            limit (int): Maximum number of events to return
            category (str): Filter by category
            since (float): Only return events after this timestamp
            
        Returns:
            list: List of suspicious events
        """
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        query = "SELECT * FROM log_events WHERE is_suspicious = 1"
        params = []
        
        if category:
            query += " AND category LIKE ?"
            params.append(f"%{category}%")
            
        if since:
            query += " AND timestamp > ?"
            params.append(since)
            
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        
        events = []
        for row in cursor.fetchall():
            events.append({
                "id": row[0],
                "log_file_id": row[1],
                "timestamp": row[2],
                "timestamp_str": row[3],
                "event_text": row[4],
                "source_host": row[5],
                "source_ip": row[6],
                "source_user": row[7],
                "category": row[8],
                "severity": row[9],
                "is_suspicious": bool(row[10]),
                "is_critical": bool(row[11])
            })
            
        conn.close()
        
        return events
    
    def get_ip_reputation(self, ip=None, reputation=None, limit=100):
        """
        Get IP reputation information
        
        Args:
            ip (str): Filter by IP address
            reputation (str): Filter by reputation
            limit (int): Maximum number of records to return
            
        Returns:
            list: List of IP reputation records
        """
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        query = "SELECT * FROM ip_reputation"
        params = []
        
        conditions = []
        
        if ip:
            conditions.append("ip = ?")
            params.append(ip)
            
        if reputation:
            conditions.append("reputation = ?")
            params.append(reputation)
            
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
            
        query += " ORDER BY failed_attempts DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        
        ip_records = []
        for row in cursor.fetchall():
            ip_records.append({
                "id": row[0],
                "ip": row[1],
                "reputation": row[2],
                "last_checked": row[3],
                "failed_attempts": row[4],
                "successful_attempts": row[5],
                "first_seen": row[6],
                "last_seen": row[7],
                "is_blocked": bool(row[8])
            })
            
        conn.close()
        
        return ip_records
    
    def verify_alert(self, alert_id):
        """
        Mark a security alert as verified
        
        Args:
            alert_id (int): ID of the alert to verify
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            cursor.execute("UPDATE security_alerts SET verified = 1 WHERE id = ?", (alert_id,))
            conn.commit()
            conn.close()
            
            return True
        except Exception as e:
            self.logger.error(f"Failed to verify alert {alert_id}: {e}")
            return False
    
    def get_statistics(self):
        """
        Get statistics about log analysis
        
        Returns:
            dict: Statistics
        """
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        stats = {}
        
        try:
            # Count log events
            cursor.execute("SELECT COUNT(*) FROM log_events")
            stats["total_events"] = cursor.fetchone()[0]
            
            # Count suspicious events
            cursor.execute("SELECT COUNT(*) FROM log_events WHERE is_suspicious = 1")
            stats["suspicious_events"] = cursor.fetchone()[0]
            
            # Count critical events
            cursor.execute("SELECT COUNT(*) FROM log_events WHERE is_critical = 1")
            stats["critical_events"] = cursor.fetchone()[0]
            
            # Count security alerts
            cursor.execute("SELECT COUNT(*) FROM security_alerts")
            stats["total_alerts"] = cursor.fetchone()[0]
            
            # Count alerts by severity
            cursor.execute("SELECT severity, COUNT(*) FROM security_alerts GROUP BY severity")
            severity_counts = cursor.fetchall()
            stats["alerts_by_severity"] = {row[0]: row[1] for row in severity_counts}
            
            # Count alerts by type
            cursor.execute("SELECT alert_type, COUNT(*) FROM security_alerts GROUP BY alert_type")
            type_counts = cursor.fetchall()
            stats["alerts_by_type"] = {row[0]: row[1] for row in type_counts}
            
            # Count events by category
            cursor.execute("SELECT category, COUNT(*) FROM log_events GROUP BY category")
            category_counts = cursor.fetchall()
            stats["events_by_category"] = {row[0]: row[1] for row in category_counts}
            
            # Count IP reputations
            cursor.execute("SELECT reputation, COUNT(*) FROM ip_reputation GROUP BY reputation")
            reputation_counts = cursor.fetchall()
            stats["ip_reputation_counts"] = {row[0]: row[1] for row in reputation_counts}
            
            # Recent activity
            cursor.execute("SELECT COUNT(*) FROM log_events WHERE timestamp > ?", 
                         (time.time() - 3600,))  # Last hour
            stats["events_last_hour"] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM security_alerts WHERE timestamp > ?", 
                         (time.time() - 3600,))  # Last hour
            stats["alerts_last_hour"] = cursor.fetchone()[0]
            
            # Database stats
            cursor.execute("SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()")
            stats["database_size"] = cursor.fetchone()[0]
            
            # Log file stats
            cursor.execute("SELECT COUNT(*) FROM log_files")
            stats["log_files_count"] = cursor.fetchone()[0]
            
        except Exception as e:
            self.logger.error(f"Error getting statistics: {e}")
            
        finally:
            conn.close()
            
        stats["last_updated"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        return stats
    
    def run_scan(self):
        """
        Run a full log analysis scan
        
        Returns:
            dict: Scan results
        """
        start_time = time.time()
        
        # Check log files for new events
        check_stats = self.check_integrity()
        
        # Check for log tampering
        tampering_events = self.check_log_tampering()
        
        # Get recent security alerts
        alerts = self.get_security_alerts(limit=10)
        
        # Get recent suspicious events
        suspicious_events = self.get_suspicious_events(limit=10)
        
        # Get statistics
        stats = self.get_statistics()
        
        scan_time = time.time() - start_time
        
        # Determine threat level
        threat_level = "low"
        
        if tampering_events:
            threat_level = "critical"
        elif check_stats["critical_events"] > 0:
            threat_level = "high"
        elif check_stats["suspicious_events"] > 10 or check_stats["alerts_generated"] > 5:
            threat_level = "medium"
            
        return {
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "scan_time_seconds": scan_time,
            "events_collected": check_stats["events_collected"],
            "alerts_generated": check_stats["alerts_generated"],
            "threat_level": threat_level,
            "tampering_detected": len(tampering_events) > 0,
            "tampering_events": tampering_events,
            "recent_alerts": alerts,
            "recent_suspicious_events": suspicious_events,
            "statistics": stats
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
                    self.logger.info("Running scheduled log analysis scan")
                    scan_results = self.run_scan()
                    
                    # Log results
                    self.logger.info(f"Scan completed. Threat level: {scan_results['threat_level']}, "
                                   f"Events collected: {scan_results['events_collected']}, "
                                   f"Alerts generated: {scan_results['alerts_generated']}")
                    
                    # Alert for high threat level
                    if scan_results["threat_level"] in ["medium", "high", "critical"]:
                        self.logger.warning(f"Elevated threat level detected: {scan_results['threat_level']}")
                        
                        # Log tampering
                        if scan_results["tampering_detected"]:
                            self.logger.warning(f"Log tampering detected! {len(scan_results['tampering_events'])} tampering events found.")
                            for event in scan_results["tampering_events"]:
                                self.logger.warning(f"  - {event['tampering_type']}: {event['description']}")
                                
                        # Log critical events
                        if scan_results["statistics"]["critical_events"] > 0:
                            self.logger.warning(f"Critical security events detected: {scan_results['statistics']['critical_events']}")
                            
                        # Log recent alerts
                        if scan_results["recent_alerts"]:
                            self.logger.warning(f"Recent security alerts: {len(scan_results['recent_alerts'])}")
                            for alert in scan_results["recent_alerts"][:3]:  # Log first 3 alerts
                                self.logger.warning(f"  - {alert['alert_type']} ({alert['severity']}): {alert['description']}")
                    
                except Exception as e:
                    self.logger.error(f"Error in monitoring thread: {e}")
                
                # Sleep until next scan
                time.sleep(interval)
        
        # Start the thread
        monitor_thread = threading.Thread(target=monitoring_thread, daemon=True)
        monitor_thread.start()
        
        return True