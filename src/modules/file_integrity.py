#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import time
import hashlib
import sqlite3
import logging
import stat
import json
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

class FileIntegrityMonitor:
    """
    File System Integrity Monitoring Module
    
    Monitors file system for unauthorized changes, tracks file modifications,
    and detects suspicious file operations.
    """
    
    def __init__(self, database_path=None, config_file=None):
        """
        Initialize the File Integrity Monitor
        
        Args:
            database_path (str): Path to the database file for storing file checksums
            config_file (str): Path to configuration file for monitoring settings
        """
        self.logger = logging.getLogger("sharpeye.file_integrity")
        
        # Set default database path if not provided
        if database_path is None:
            home_dir = os.path.expanduser("~")
            self.database_path = os.path.join(home_dir, ".sharpeye", "file_integrity.db")
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
            "directories": [
                "/etc",
                "/bin",
                "/sbin",
                "/usr/bin",
                "/usr/sbin",
                "/usr/local/bin",
                "/usr/local/sbin",
                "/boot"
            ],
            "excluded_paths": [
                "/var/log",
                "/tmp",
                "/proc",
                "/sys",
                "/dev",
                "/run"
            ],
            "excluded_extensions": [
                ".log",
                ".tmp",
                ".swp",
                ".pid",
                ".cache"
            ],
            "hash_algorithm": "sha256",
            "thread_count": 4,
            "scan_interval": 3600,  # 1 hour
            "max_file_size": 50 * 1024 * 1024,  # 50MB
            "critical_files": [
                "/etc/passwd",
                "/etc/shadow",
                "/etc/group",
                "/etc/sudoers",
                "/etc/ssh/sshd_config",
                "/etc/hosts",
                "/etc/crontab",
                "/etc/profile",
                "/etc/bash.bashrc"
            ]
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
        """Initialize the SQLite database for storing file checksums and metadata"""
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            # Create tables if they don't exist
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_baseline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT UNIQUE,
                hash TEXT,
                size INTEGER,
                permissions INTEGER,
                owner TEXT,
                group_owner TEXT,
                last_modified REAL,
                last_checked REAL,
                is_critical INTEGER DEFAULT 0
            )
            ''')
            
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT,
                change_type TEXT,
                old_hash TEXT,
                new_hash TEXT,
                old_permissions INTEGER,
                new_permissions INTEGER,
                old_owner TEXT,
                new_owner TEXT,
                old_size INTEGER,
                new_size INTEGER,
                timestamp REAL,
                verified INTEGER DEFAULT 0
            )
            ''')
            
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_path ON file_baseline(path)
            ''')
            
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_change_path ON file_changes(path)
            ''')
            
            conn.commit()
            self.logger.info("Database initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize database: {e}")
        finally:
            if conn:
                conn.close()
    
    def calculate_file_hash(self, file_path):
        """
        Calculate hash for a given file
        
        Args:
            file_path (str): Path to the file
            
        Returns:
            str: File hash or None if failed
        """
        try:
            if not os.path.isfile(file_path):
                return None
                
            # Skip if file exceeds max size
            file_size = os.path.getsize(file_path)
            if file_size > self.config["max_file_size"]:
                self.logger.debug(f"Skipping large file: {file_path} ({file_size} bytes)")
                return None
                
            # Choose hash algorithm
            hash_func = getattr(hashlib, self.config["hash_algorithm"])()
            
            with open(file_path, 'rb') as f:
                # Read file in chunks to handle large files efficiently
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_func.update(chunk)
                    
            return hash_func.hexdigest()
        except (IOError, OSError) as e:
            self.logger.debug(f"Cannot hash file {file_path}: {e}")
            return None
    
    def get_file_metadata(self, file_path):
        """
        Get file metadata including permissions, owner, size, and modification time
        
        Args:
            file_path (str): Path to the file
            
        Returns:
            dict: File metadata or None if failed
        """
        try:
            stat_info = os.stat(file_path)
            
            return {
                "size": stat_info.st_size,
                "permissions": stat_info.st_mode,
                "owner": stat_info.st_uid,
                "group_owner": stat_info.st_gid,
                "last_modified": stat_info.st_mtime
            }
        except (IOError, OSError) as e:
            self.logger.debug(f"Cannot get metadata for {file_path}: {e}")
            return None
    
    def should_monitor_file(self, file_path):
        """
        Check if a file should be monitored based on configuration
        
        Args:
            file_path (str): Path to the file
            
        Returns:
            bool: True if file should be monitored, False otherwise
        """
        # Skip excluded paths
        for excluded in self.config["excluded_paths"]:
            if file_path.startswith(excluded):
                return False
                
        # Skip excluded extensions
        _, ext = os.path.splitext(file_path)
        if ext in self.config["excluded_extensions"]:
            return False
            
        # Skip symbolic links
        if os.path.islink(file_path):
            return False
            
        return True
    
    def create_baseline(self, paths=None):
        """
        Create a baseline of file checksums for integrity monitoring
        
        Args:
            paths (list): List of directories to monitor, uses config if None
            
        Returns:
            tuple: (int, int) Count of (processed files, errors)
        """
        if paths is None:
            paths = self.config["directories"]
            
        self.logger.info(f"Creating baseline for paths: {paths}")
        
        file_count = 0
        error_count = 0
        processed_count = 0
        
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        # Mark critical files
        for critical_file in self.config["critical_files"]:
            if os.path.exists(critical_file):
                cursor.execute(
                    "UPDATE file_baseline SET is_critical = 1 WHERE path = ?",
                    (critical_file,)
                )
        
        # Use ThreadPoolExecutor for parallel processing
        with ThreadPoolExecutor(max_workers=self.config["thread_count"]) as executor:
            for directory in paths:
                if not os.path.exists(directory):
                    self.logger.warning(f"Directory does not exist: {directory}")
                    continue
                    
                self.logger.info(f"Scanning directory: {directory}")
                
                # Walk through directory and process each file
                for root, _, files in os.walk(directory):
                    for filename in files:
                        file_path = os.path.join(root, filename)
                        
                        if not self.should_monitor_file(file_path):
                            continue
                            
                        file_count += 1
                        
                        # Submit file processing task to thread pool
                        executor.submit(self._process_file_for_baseline, file_path, cursor, conn)
                        processed_count += 1
                        
                        # Commit periodically to avoid large transactions
                        if processed_count % 1000 == 0:
                            conn.commit()
                            self.logger.info(f"Processed {processed_count} files so far")
        
        # Final commit
        conn.commit()
        
        # Update critical files status
        for critical_file in self.config["critical_files"]:
            cursor.execute(
                "UPDATE file_baseline SET is_critical = 1 WHERE path = ?",
                (critical_file,)
            )
            
        conn.commit()
        conn.close()
        
        self.logger.info(f"Baseline creation completed. Processed {file_count} files with {error_count} errors.")
        return processed_count, error_count
    
    def _process_file_for_baseline(self, file_path, cursor, conn):
        """
        Process a single file for baseline creation
        
        Args:
            file_path (str): Path to the file
            cursor: Database cursor
            conn: Database connection
        """
        try:
            file_hash = self.calculate_file_hash(file_path)
            if file_hash is None:
                return
                
            metadata = self.get_file_metadata(file_path)
            if metadata is None:
                return
                
            # Check if file is in the critical files list
            is_critical = 1 if file_path in self.config["critical_files"] else 0
            
            # Insert or update record in database
            cursor.execute('''
            INSERT OR REPLACE INTO file_baseline 
            (path, hash, size, permissions, owner, group_owner, last_modified, last_checked, is_critical) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                file_path,
                file_hash,
                metadata["size"],
                metadata["permissions"],
                metadata["owner"],
                metadata["group_owner"],
                metadata["last_modified"],
                time.time(),
                is_critical
            ))
            
            # We don't commit here since it will be committed by the calling function
            
        except Exception as e:
            self.logger.error(f"Error processing file {file_path}: {e}")
    
    def check_integrity(self, paths=None):
        """
        Check file integrity against baseline
        
        Args:
            paths (list): List of directories to check, uses config if None
            
        Returns:
            list: List of detected changes
        """
        if paths is None:
            paths = self.config["directories"]
            
        self.logger.info(f"Checking integrity for paths: {paths}")
        
        changes = []
        files_checked = 0
        
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        # Get list of files to check from database
        files_in_db = {}
        for directory in paths:
            cursor.execute("SELECT path, hash, size, permissions, owner, group_owner, last_modified, is_critical FROM file_baseline WHERE path LIKE ?", 
                         (f"{directory}%",))
            for row in cursor.fetchall():
                files_in_db[row[0]] = {
                    "hash": row[1],
                    "size": row[2],
                    "permissions": row[3],
                    "owner": row[4],
                    "group_owner": row[5],
                    "last_modified": row[6],
                    "is_critical": row[7]
                }
        
        # Check each file in the baseline
        with ThreadPoolExecutor(max_workers=self.config["thread_count"]) as executor:
            futures = []
            
            for file_path, baseline in files_in_db.items():
                if not os.path.exists(file_path):
                    # File deleted
                    self._record_change(cursor, conn, file_path, "deleted", 
                                      baseline, None)
                    changes.append({
                        "path": file_path,
                        "type": "deleted",
                        "is_critical": baseline["is_critical"],
                        "timestamp": time.time()
                    })
                    continue
                    
                if not self.should_monitor_file(file_path):
                    continue
                    
                # Submit file check task to thread pool
                futures.append(executor.submit(
                    self._check_file_integrity, 
                    file_path, 
                    baseline,
                    cursor,
                    conn
                ))
                
                files_checked += 1
                
            # Process the results
            for future in futures:
                result = future.result()
                if result:
                    changes.append(result)
        
        # Check for new files
        for directory in paths:
            if os.path.exists(directory):
                for root, _, files in os.walk(directory):
                    for filename in files:
                        file_path = os.path.join(root, filename)
                        
                        if not self.should_monitor_file(file_path):
                            continue
                            
                        if file_path not in files_in_db:
                            # New file detected
                            metadata = self.get_file_metadata(file_path)
                            file_hash = self.calculate_file_hash(file_path)
                            
                            if metadata and file_hash:
                                self._record_change(cursor, conn, file_path, "added", 
                                                  None, {
                                                      "hash": file_hash,
                                                      "size": metadata["size"],
                                                      "permissions": metadata["permissions"],
                                                      "owner": metadata["owner"],
                                                      "group_owner": metadata["group_owner"],
                                                      "last_modified": metadata["last_modified"]
                                                  })
                                                  
                                is_critical = 1 if file_path in self.config["critical_files"] else 0
                                changes.append({
                                    "path": file_path,
                                    "type": "added",
                                    "is_critical": is_critical,
                                    "timestamp": time.time()
                                })
        
        conn.commit()
        conn.close()
        
        self.logger.info(f"Integrity check completed. Checked {files_checked} files, found {len(changes)} changes.")
        return changes
    
    def _check_file_integrity(self, file_path, baseline, cursor, conn):
        """
        Check integrity of a single file against baseline
        
        Args:
            file_path (str): Path to the file
            baseline (dict): Baseline data from database
            cursor: Database cursor
            conn: Database connection
            
        Returns:
            dict: Change details if detected, None otherwise
        """
        try:
            current_hash = self.calculate_file_hash(file_path)
            if current_hash is None:
                return None
                
            current_metadata = self.get_file_metadata(file_path)
            if current_metadata is None:
                return None
                
            change_detected = False
            change_type = []
            
            # Check for content changes
            if current_hash != baseline["hash"]:
                change_detected = True
                change_type.append("content")
                
            # Check for permission changes
            if current_metadata["permissions"] != baseline["permissions"]:
                change_detected = True
                change_type.append("permissions")
                
            # Check for ownership changes
            if (current_metadata["owner"] != baseline["owner"] or 
                current_metadata["group_owner"] != baseline["group_owner"]):
                change_detected = True
                change_type.append("ownership")
            
            # Record the change if detected
            if change_detected:
                change_type_str = ",".join(change_type)
                
                self._record_change(cursor, conn, file_path, change_type_str, 
                                  baseline, current_metadata, current_hash)
                
                return {
                    "path": file_path,
                    "type": change_type_str,
                    "is_critical": baseline["is_critical"],
                    "timestamp": time.time()
                }
                
            # Update last checked time
            cursor.execute(
                "UPDATE file_baseline SET last_checked = ? WHERE path = ?",
                (time.time(), file_path)
            )
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error checking file {file_path}: {e}")
            return None
    
    def _record_change(self, cursor, conn, file_path, change_type, old_data, new_data, new_hash=None):
        """
        Record a detected change in the database
        
        Args:
            cursor: Database cursor
            conn: Database connection
            file_path (str): Path to the file
            change_type (str): Type of change detected
            old_data (dict): Old file metadata
            new_data (dict): New file metadata
            new_hash (str): New file hash if available
        """
        try:
            timestamp = time.time()
            
            if change_type == "deleted":
                cursor.execute('''
                INSERT INTO file_changes 
                (path, change_type, old_hash, old_permissions, old_owner, old_size, timestamp) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    file_path,
                    change_type,
                    old_data["hash"],
                    old_data["permissions"],
                    old_data["owner"],
                    old_data["size"],
                    timestamp
                ))
                
                # Remove from baseline
                cursor.execute("DELETE FROM file_baseline WHERE path = ?", (file_path,))
                
            elif change_type == "added":
                cursor.execute('''
                INSERT INTO file_changes 
                (path, change_type, new_hash, new_permissions, new_owner, new_size, timestamp) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    file_path,
                    change_type,
                    new_data["hash"],
                    new_data["permissions"],
                    new_data["owner"],
                    new_data["size"],
                    timestamp
                ))
                
                # Add to baseline
                is_critical = 1 if file_path in self.config["critical_files"] else 0
                cursor.execute('''
                INSERT INTO file_baseline 
                (path, hash, size, permissions, owner, group_owner, last_modified, last_checked, is_critical) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    file_path,
                    new_data["hash"],
                    new_data["size"],
                    new_data["permissions"],
                    new_data["owner"],
                    new_data["group_owner"],
                    new_data["last_modified"],
                    timestamp,
                    is_critical
                ))
                
            else:
                # Handle modification (content, permissions, ownership)
                cursor.execute('''
                INSERT INTO file_changes 
                (path, change_type, old_hash, new_hash, old_permissions, new_permissions, 
                old_owner, new_owner, old_size, new_size, timestamp) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    file_path,
                    change_type,
                    old_data["hash"],
                    new_hash if new_hash else new_data["hash"],
                    old_data["permissions"],
                    new_data["permissions"],
                    old_data["owner"],
                    new_data["owner"],
                    old_data["size"],
                    new_data["size"],
                    timestamp
                ))
                
                # Update baseline
                cursor.execute('''
                UPDATE file_baseline 
                SET hash = ?, size = ?, permissions = ?, owner = ?, group_owner = ?, 
                last_modified = ?, last_checked = ? 
                WHERE path = ?
                ''', (
                    new_hash if new_hash else new_data["hash"],
                    new_data["size"],
                    new_data["permissions"],
                    new_data["owner"],
                    new_data["group_owner"],
                    new_data["last_modified"],
                    timestamp,
                    file_path
                ))
            
            # Commit changes immediately for critical changes
            if old_data and old_data.get("is_critical") == 1:
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error recording change for {file_path}: {e}")
    
    def get_recent_changes(self, limit=100, since=None, include_verified=False):
        """
        Get recent file changes from the database
        
        Args:
            limit (int): Maximum number of changes to return
            since (float): Only return changes after this timestamp
            include_verified (bool): Whether to include verified changes
            
        Returns:
            list: List of recent changes
        """
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        query = "SELECT * FROM file_changes"
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
                "path": row[1],
                "change_type": row[2],
                "old_hash": row[3],
                "new_hash": row[4],
                "old_permissions": row[5],
                "new_permissions": row[6],
                "old_owner": row[7],
                "new_owner": row[8],
                "old_size": row[9],
                "new_size": row[10],
                "timestamp": row[11],
                "verified": bool(row[12])
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
            
            cursor.execute("UPDATE file_changes SET verified = 1 WHERE id = ?", (change_id,))
            conn.commit()
            conn.close()
            
            return True
        except Exception as e:
            self.logger.error(f"Failed to verify change {change_id}: {e}")
            return False
    
    def get_critical_file_status(self):
        """
        Get the status of critical files
        
        Returns:
            list: List of critical files with their status
        """
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute("""
        SELECT b.path, b.hash, b.last_modified, b.last_checked,
               (SELECT COUNT(*) FROM file_changes c WHERE c.path = b.path AND c.verified = 0) as unverified_changes
        FROM file_baseline b
        WHERE b.is_critical = 1
        """)
        
        critical_files = []
        for row in cursor.fetchall():
            critical_files.append({
                "path": row[0],
                "hash": row[1],
                "last_modified": datetime.fromtimestamp(row[2]).strftime('%Y-%m-%d %H:%M:%S'),
                "last_checked": datetime.fromtimestamp(row[3]).strftime('%Y-%m-%d %H:%M:%S'),
                "unverified_changes": row[4]
            })
            
        conn.close()
        return critical_files
    
    def detect_ransomware_activity(self):
        """
        Detect patterns typical of ransomware activity
        
        Returns:
            dict: Detection results
        """
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        # Look for large number of content changes in a short time
        cursor.execute("""
        SELECT COUNT(*) FROM file_changes 
        WHERE change_type LIKE '%content%' AND timestamp > ?
        """, (time.time() - 300,))  # Last 5 minutes
        
        recent_changes = cursor.fetchone()[0]
        
        # Look for extensions typical of ransomware
        cursor.execute("""
        SELECT path FROM file_changes 
        WHERE path LIKE '%.encrypted' OR path LIKE '%.locked' OR path LIKE '%.crypt' 
        OR path LIKE '%.crypto' OR path LIKE '%.ransomware' OR path LIKE '%.ransom' 
        OR path LIKE '%.pays' OR path LIKE '%.wallet' OR path LIKE '%.wcry' 
        OR path LIKE '%.wncry' OR path LIKE '%.wncryt' OR path LIKE '%.wnry'
        AND timestamp > ?
        """, (time.time() - 3600,))  # Last hour
        
        ransomware_files = [row[0] for row in cursor.fetchall()]
        
        # Look for readme files commonly created by ransomware
        cursor.execute("""
        SELECT path FROM file_changes 
        WHERE (path LIKE '%/READ_ME.txt' OR path LIKE '%/DECRYPT.txt' OR path LIKE '%/HOW_TO_DECRYPT.txt'
        OR path LIKE '%/HELP_DECRYPT.txt' OR path LIKE '%/RECOVERY.txt' OR path LIKE '%/RANSOM.txt'
        OR path LIKE '%/YOUR_FILES.txt') AND change_type = 'added'
        AND timestamp > ?
        """, (time.time() - 3600,))  # Last hour
        
        ransom_notes = [row[0] for row in cursor.fetchall()]
        
        conn.close()
        
        # Determine threat level
        threat_level = "low"
        if len(ransomware_files) > 0 or len(ransom_notes) > 0:
            threat_level = "critical"
        elif recent_changes > 100:  # Arbitrary threshold, tune based on environment
            threat_level = "high"
        elif recent_changes > 50:
            threat_level = "medium"
            
        return {
            "threat_level": threat_level,
            "recent_changes": recent_changes,
            "ransomware_files": ransomware_files,
            "ransom_notes": ransom_notes,
            "timestamp": time.time()
        }
    
    def detect_suspicious_scripts(self):
        """
        Detect recently added or modified scripts in sensitive locations
        
        Returns:
            list: Suspicious script files
        """
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        # Look for script files added or modified in the last 24 hours
        cursor.execute("""
        SELECT c.path, c.change_type, c.timestamp 
        FROM file_changes c
        WHERE (c.path LIKE '%.sh' OR c.path LIKE '%.py' OR c.path LIKE '%.pl' OR c.path LIKE '%.php' 
              OR c.path LIKE '%.rb' OR c.path LIKE '%.cgi')
        AND (c.change_type = 'added' OR c.change_type LIKE '%content%')
        AND c.timestamp > ?
        """, (time.time() - 86400,))  # Last 24 hours
        
        suspicious_scripts = []
        for row in cursor.fetchall():
            path = row[0]
            
            # Check if script is in a sensitive location
            sensitive_location = False
            for directory in ['/etc', '/bin', '/sbin', '/usr/bin', '/usr/sbin', '/usr/local/bin', '/usr/local/sbin']:
                if path.startswith(directory):
                    sensitive_location = True
                    break
            
            if sensitive_location:
                suspicious_scripts.append({
                    "path": path,
                    "change_type": row[1],
                    "timestamp": datetime.fromtimestamp(row[2]).strftime('%Y-%m-%d %H:%M:%S'),
                    "is_sensitive": sensitive_location
                })
                
        conn.close()
        return suspicious_scripts
    
    def detect_binary_replacements(self):
        """
        Detect replaced system binaries
        
        Returns:
            list: Potentially replaced binaries
        """
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        # Check for modified binaries in system directories
        cursor.execute("""
        SELECT c.path, c.change_type, c.timestamp, c.old_hash, c.new_hash
        FROM file_changes c
        JOIN file_baseline b ON c.path = b.path
        WHERE (c.path LIKE '/bin/%' OR c.path LIKE '/sbin/%' OR c.path LIKE '/usr/bin/%' 
              OR c.path LIKE '/usr/sbin/%' OR c.path LIKE '/usr/local/bin/%' OR c.path LIKE '/usr/local/sbin/%')
        AND c.change_type LIKE '%content%'
        AND c.verified = 0
        ORDER BY c.timestamp DESC
        """)
        
        replaced_binaries = []
        for row in cursor.fetchall():
            replaced_binaries.append({
                "path": row[0],
                "change_type": row[1],
                "timestamp": datetime.fromtimestamp(row[2]).strftime('%Y-%m-%d %H:%M:%S'),
                "old_hash": row[3],
                "new_hash": row[4]
            })
                
        conn.close()
        return replaced_binaries
    
    def get_statistics(self):
        """
        Get statistics about the file integrity monitoring system
        
        Returns:
            dict: Statistics
        """
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        # Total files monitored
        cursor.execute("SELECT COUNT(*) FROM file_baseline")
        total_files = cursor.fetchone()[0]
        
        # Critical files monitored
        cursor.execute("SELECT COUNT(*) FROM file_baseline WHERE is_critical = 1")
        critical_files = cursor.fetchone()[0]
        
        # Recent changes (last 24 hours)
        cursor.execute("SELECT COUNT(*) FROM file_changes WHERE timestamp > ?", 
                     (time.time() - 86400,))
        recent_changes = cursor.fetchone()[0]
        
        # Unverified changes
        cursor.execute("SELECT COUNT(*) FROM file_changes WHERE verified = 0")
        unverified_changes = cursor.fetchone()[0]
        
        # Change types breakdown
        cursor.execute("""
        SELECT 
            SUM(CASE WHEN change_type = 'added' THEN 1 ELSE 0 END) as added,
            SUM(CASE WHEN change_type = 'deleted' THEN 1 ELSE 0 END) as deleted,
            SUM(CASE WHEN change_type LIKE '%content%' THEN 1 ELSE 0 END) as content,
            SUM(CASE WHEN change_type LIKE '%permissions%' THEN 1 ELSE 0 END) as permissions,
            SUM(CASE WHEN change_type LIKE '%ownership%' THEN 1 ELSE 0 END) as ownership
        FROM file_changes
        WHERE timestamp > ?
        """, (time.time() - 604800,))  # Last 7 days
        
        row = cursor.fetchone()
        change_types = {
            "added": row[0] or 0,
            "deleted": row[1] or 0,
            "content": row[2] or 0,
            "permissions": row[3] or 0,
            "ownership": row[4] or 0
        }
        
        # Storage usage
        cursor.execute("SELECT page_count * page_size from pragma_page_count(), pragma_page_size()")
        database_size = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "total_files_monitored": total_files,
            "critical_files_monitored": critical_files,
            "recent_changes": recent_changes,
            "unverified_changes": unverified_changes,
            "change_types_last_7_days": change_types,
            "database_size_bytes": database_size,
            "database_path": self.database_path,
            "last_updated": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
    
    def run_scan(self):
        """
        Run a full integrity scan and return the results
        
        Returns:
            dict: Scan results
        """
        start_time = time.time()
        changes = self.check_integrity()
        scan_time = time.time() - start_time
        
        # Categorize changes by type
        change_types = {
            "added": [],
            "deleted": [],
            "content": [],
            "permissions": [],
            "ownership": []
        }
        
        critical_changes = []
        
        for change in changes:
            # Categorize by change type
            if change["type"] == "added":
                change_types["added"].append(change)
            elif change["type"] == "deleted":
                change_types["deleted"].append(change)
            else:
                # Handle multiple change types (comma-separated)
                for change_type in change["type"].split(","):
                    if change_type in change_types:
                        change_types[change_type].append(change)
            
            # Track critical changes
            if change.get("is_critical", 0) == 1:
                critical_changes.append(change)
        
        # Check for ransomware activity
        ransomware_check = self.detect_ransomware_activity()
        
        # Check for suspicious scripts
        suspicious_scripts = self.detect_suspicious_scripts()
        
        # Check for binary replacements
        replaced_binaries = self.detect_binary_replacements()
        
        # Determine overall threat level
        threat_level = "low"
        
        if ransomware_check["threat_level"] == "critical":
            threat_level = "critical"
        elif len(critical_changes) > 0 or len(replaced_binaries) > 0:
            threat_level = "high"
        elif len(suspicious_scripts) > 0 or ransomware_check["threat_level"] == "high":
            threat_level = "medium"
        
        return {
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "scan_time_seconds": scan_time,
            "total_changes": len(changes),
            "threat_level": threat_level,
            "changes_by_type": {
                "added": len(change_types["added"]),
                "deleted": len(change_types["deleted"]),
                "content": len(change_types["content"]),
                "permissions": len(change_types["permissions"]),
                "ownership": len(change_types["ownership"])
            },
            "critical_changes": critical_changes,
            "ransomware_detection": ransomware_check,
            "suspicious_scripts": suspicious_scripts,
            "replaced_binaries": replaced_binaries
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
                    self.logger.info("Running scheduled integrity check")
                    scan_results = self.run_scan()
                    
                    # Log results
                    self.logger.info(f"Scan completed. Threat level: {scan_results['threat_level']}, "
                                   f"Changes detected: {scan_results['total_changes']}")
                    
                    # Alert for high threat level
                    if scan_results["threat_level"] in ["medium", "high", "critical"]:
                        self.logger.warning(f"Elevated threat level detected: {scan_results['threat_level']}")
                        
                        # Log critical details
                        if scan_results["critical_changes"]:
                            self.logger.warning(f"Critical file changes detected: {len(scan_results['critical_changes'])}")
                            for change in scan_results["critical_changes"]:
                                self.logger.warning(f"Critical change: {change['path']} ({change['type']})")
                                
                        if scan_results["ransomware_detection"]["threat_level"] != "low":
                            self.logger.warning("Possible ransomware activity detected!")
                            
                        if scan_results["replaced_binaries"]:
                            self.logger.warning(f"System binary replacements detected: {len(scan_results['replaced_binaries'])}")
                    
                except Exception as e:
                    self.logger.error(f"Error in monitoring thread: {e}")
                
                # Sleep until next scan
                time.sleep(interval)
        
        # Start the thread
        monitor_thread = threading.Thread(target=monitoring_thread, daemon=True)
        monitor_thread.start()
        
        return True