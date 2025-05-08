#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import subprocess
import hashlib
import logging
import json
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

class LibraryInspector:
    """
    Library Inspection Module
    
    Monitors shared libraries for unauthorized changes, detects malicious
    library injections, and identifies library hooking/hijacking.
    """
    
    def __init__(self, database_path=None, config_file=None):
        """
        Initialize the Library Inspector
        
        Args:
            database_path (str): Path to the database file for storing library data
            config_file (str): Path to configuration file
        """
        self.logger = logging.getLogger("sharpeye.library_inspection")
        
        # Set default database path if not provided
        if database_path is None:
            home_dir = os.path.expanduser("~")
            self.database_path = os.path.join(home_dir, ".sharpeye", "library_inspection.db")
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
            "library_directories": [
                "/lib",
                "/lib64",
                "/usr/lib",
                "/usr/local/lib"
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
            "max_file_size": 100 * 1024 * 1024,  # 100MB
            "critical_libraries": [
                "libc.so.6",
                "ld-linux-x86-64.so.2",
                "libcrypto.so",
                "libssl.so",
                "libpam.so",
                "libssh.so",
                "libnss.so",
                "libkrb5.so"
            ],
            "suspicious_library_patterns": [
                # Suspicious library name patterns
                r"lib.*hack.*\.so",
                r"lib.*spy.*\.so",
                r"lib.*steal.*\.so",
                r"lib.*inject.*\.so",
                r"lib.*hook.*\.so",
                r"lib.*root.*\.so",
                r"lib.*exploit.*\.so"
            ],
            "suspicious_function_patterns": [
                # Suspicious function names that might indicate malicious activity
                r"hook_.*",
                r"hijack_.*",
                r"inject_.*",
                r"steal_.*",
                r"spy_.*",
                r"hide_.*",
                r"intercept_.*",
                r"replace_.*"
            ],
            "function_hooking_targets": [
                # Common functions targeted for hooking
                "open", "fopen", "read", "write", "execve", "connect",
                "accept", "socket", "recv", "send", "getaddrinfo", "opendir",
                "readdir", "stat", "getpwent", "getpwnam", "system", "popen",
                "dlopen", "dlsym", "crypt", "encrypt", "SSL_read", "SSL_write"
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
        """Initialize the SQLite database for storing library data"""
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            # Create tables if they don't exist
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS libraries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT UNIQUE,
                name TEXT,
                hash TEXT,
                size INTEGER,
                permissions INTEGER,
                owner INTEGER,
                group_owner INTEGER,
                last_modified REAL,
                first_seen REAL,
                last_checked REAL,
                is_critical INTEGER DEFAULT 0,
                is_suspicious INTEGER DEFAULT 0,
                suspicious_reason TEXT
            )
            ''')
            
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS library_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT,
                change_type TEXT,
                old_hash TEXT,
                new_hash TEXT,
                old_permissions INTEGER,
                new_permissions INTEGER,
                old_owner INTEGER,
                new_owner INTEGER,
                old_size INTEGER,
                new_size INTEGER,
                timestamp REAL,
                verified INTEGER DEFAULT 0
            )
            ''')
            
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS library_symbols (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                library_id INTEGER,
                symbol_name TEXT,
                symbol_type TEXT,
                symbol_value TEXT,
                first_seen REAL,
                last_checked REAL,
                is_hooked INTEGER DEFAULT 0,
                FOREIGN KEY (library_id) REFERENCES libraries (id)
            )
            ''')
            
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS symbol_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                library_id INTEGER,
                symbol_name TEXT,
                change_type TEXT,
                old_value TEXT,
                new_value TEXT,
                timestamp REAL,
                verified INTEGER DEFAULT 0,
                FOREIGN KEY (library_id) REFERENCES libraries (id)
            )
            ''')
            
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS preload_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                libraries TEXT,
                timestamp REAL
            )
            ''')
            
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_library_path ON libraries(path)
            ''')
            
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_library_name ON libraries(name)
            ''')
            
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_change_path ON library_changes(path)
            ''')
            
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_symbol_library ON library_symbols(library_id)
            ''')
            
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_symbol_name ON library_symbols(symbol_name)
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
        # Check if it's a library file
        if not (file_path.endswith('.so') or '.so.' in file_path or 
                file_path.endswith('.a') or '.a.' in file_path or
                'ld-linux' in file_path):
            return False
            
        # Skip excluded paths
        for excluded in self.config["excluded_paths"]:
            if file_path.startswith(excluded):
                return False
                
        # Skip excluded extensions
        _, ext = os.path.splitext(file_path)
        if ext in self.config["excluded_extensions"]:
            return False
            
        return True
    
    def is_library_suspicious(self, file_path, library_name=None):
        """
        Check if a library looks suspicious
        
        Args:
            file_path (str): Path to the library file
            library_name (str): Library name if known, otherwise extracted from path
            
        Returns:
            tuple: (bool, str) True if suspicious and reason
        """
        if library_name is None:
            library_name = os.path.basename(file_path)
            
        # Check against suspicious name patterns
        for pattern in self.config["suspicious_library_patterns"]:
            if re.match(pattern, library_name, re.IGNORECASE):
                return True, f"Suspicious name pattern: {pattern}"
                
        # Check for uncommon/suspicious locations
        common_dirs = [
            "/lib", "/lib64", "/usr/lib", "/usr/local/lib",
            "/usr/lib64", "/usr/local/lib64", "/lib/x86_64-linux-gnu",
            "/usr/lib/x86_64-linux-gnu"
        ]
        
        valid_location = False
        for directory in common_dirs:
            if file_path.startswith(directory):
                valid_location = True
                break
                
        if not valid_location:
            # Library in unusual location, check against exceptions
            exceptions = ["/opt", "/app", "/home"]
            for exc in exceptions:
                if file_path.startswith(exc):
                    valid_location = True
                    break
                    
            if not valid_location:
                return True, f"Unusual library location: {os.path.dirname(file_path)}"
                
        # Check file permissions (writable by others is suspicious)
        try:
            mode = os.stat(file_path).st_mode
            if mode & 0o2:  # World-writable
                return True, "Library is world-writable"
        except Exception:
            pass
            
        # Check the library symbols for suspicious functions
        try:
            # Use nm to get symbols if available
            output = subprocess.run(['nm', '-D', file_path], stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE, text=True).stdout
            
            for line in output.split('\n'):
                if line.strip():
                    parts = line.strip().split()
                    if len(parts) >= 3:  # Symbol has address, type, and name
                        symbol_name = parts[-1]
                        
                        # Check against suspicious function patterns
                        for pattern in self.config["suspicious_function_patterns"]:
                            if re.match(pattern, symbol_name, re.IGNORECASE):
                                return True, f"Suspicious symbol: {symbol_name}"
                                
        except Exception:
            # nm might not be available or file might not be accessible
            pass
            
        # All checks passed
        return False, ""
    
    def get_library_symbols(self, file_path):
        """
        Get exported symbols from a library file
        
        Args:
            file_path (str): Path to the library file
            
        Returns:
            list: List of symbols with their details
        """
        symbols = []
        
        try:
            # Use nm to get symbols if available
            output = subprocess.run(['nm', '-D', file_path], stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE, text=True).stdout
            
            for line in output.split('\n'):
                if line.strip():
                    parts = line.strip().split(' ', 2)
                    if len(parts) >= 2:
                        if len(parts) == 2:
                            # Format with just type and name
                            symbol_value = ""
                            symbol_type = parts[0]
                            symbol_name = parts[1]
                        else:
                            # Format with address, type, and name
                            symbol_value = parts[0]
                            symbol_type = parts[1]
                            symbol_name = parts[2]
                            
                        symbols.append({
                            "name": symbol_name,
                            "type": symbol_type,
                            "value": symbol_value
                        })
            
            # If nm didn't work, try objdump as an alternative
            if not symbols:
                output = subprocess.run(['objdump', '-T', file_path], stdout=subprocess.PIPE, 
                                      stderr=subprocess.PIPE, text=True).stdout
                
                for line in output.split('\n'):
                    if 'DF' in line or 'DO' in line:  # Dynamic Function or Object
                        parts = line.strip().split()
                        if len(parts) >= 7:
                            symbol_value = parts[0]
                            symbol_name = parts[6]
                            symbol_type = 'T' if 'DF' in line else 'D'  # T for code, D for data
                            
                            symbols.append({
                                "name": symbol_name,
                                "type": symbol_type,
                                "value": symbol_value
                            })
                            
        except Exception as e:
            self.logger.debug(f"Failed to get symbols from {file_path}: {e}")
            
        return symbols
    
    def get_all_libraries(self):
        """
        Get all shared library files on the system
        
        Returns:
            list: List of library files with their metadata
        """
        libraries = []
        
        for directory in self.config["library_directories"]:
            if not os.path.exists(directory):
                continue
                
            self.logger.info(f"Scanning directory: {directory}")
            
            # Walk through directory and process each library file
            for root, _, files in os.walk(directory):
                for filename in files:
                    file_path = os.path.join(root, filename)
                    
                    if not self.should_monitor_file(file_path):
                        continue
                        
                    metadata = self.get_file_metadata(file_path)
                    if metadata is None:
                        continue
                        
                    file_hash = self.calculate_file_hash(file_path)
                    if file_hash is None:
                        continue
                        
                    # Check if the library is critical
                    is_critical = 0
                    for critical in self.config["critical_libraries"]:
                        if filename == critical or filename.startswith(critical):
                            is_critical = 1
                            break
                            
                    # Check if the library is suspicious
                    is_suspicious, reason = self.is_library_suspicious(file_path, filename)
                    
                    libraries.append({
                        "path": file_path,
                        "name": filename,
                        "hash": file_hash,
                        "size": metadata["size"],
                        "permissions": metadata["permissions"],
                        "owner": metadata["owner"],
                        "group_owner": metadata["group_owner"],
                        "last_modified": metadata["last_modified"],
                        "is_critical": is_critical,
                        "is_suspicious": 1 if is_suspicious else 0,
                        "suspicious_reason": reason if is_suspicious else ""
                    })
                    
        return libraries
    
    def create_baseline(self):
        """
        Create a baseline of shared libraries for integrity monitoring
        
        Returns:
            tuple: (int, int, int) Count of (processed libraries, critical libraries, suspicious libraries)
        """
        self.logger.info("Creating library baseline")
        
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        # Get all libraries
        libraries = self.get_all_libraries()
        
        processed_count = 0
        critical_count = 0
        suspicious_count = 0
        
        current_time = time.time()
        
        # Use ThreadPoolExecutor for parallel processing
        with ThreadPoolExecutor(max_workers=self.config["thread_count"]) as executor:
            futures = []
            
            for library in libraries:
                # Submit library processing task to thread pool
                futures.append(executor.submit(
                    self._process_library_for_baseline,
                    library,
                    cursor,
                    conn,
                    current_time
                ))
                
            # Process the results
            for future in futures:
                result = future.result()
                if result:
                    processed_count += 1
                    if result.get("is_critical"):
                        critical_count += 1
                    if result.get("is_suspicious"):
                        suspicious_count += 1
        
        # Check for preloaded libraries
        self._check_ld_preload(cursor, conn)
        
        conn.commit()
        conn.close()
        
        self.logger.info(f"Baseline creation completed. Processed {processed_count} libraries, "
                       f"including {critical_count} critical and {suspicious_count} suspicious libraries.")
        return processed_count, critical_count, suspicious_count
    
    def _process_library_for_baseline(self, library, cursor, conn, current_time):
        """
        Process a single library for baseline creation
        
        Args:
            library (dict): Library information
            cursor: Database cursor
            conn: Database connection
            current_time (float): Current time
            
        Returns:
            dict: Library info if successful, None otherwise
        """
        try:
            # Insert or update record in database
            cursor.execute('''
            INSERT OR REPLACE INTO libraries 
            (path, name, hash, size, permissions, owner, group_owner, last_modified, 
             first_seen, last_checked, is_critical, is_suspicious, suspicious_reason) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                library["path"],
                library["name"],
                library["hash"],
                library["size"],
                library["permissions"],
                library["owner"],
                library["group_owner"],
                library["last_modified"],
                current_time,
                current_time,
                library["is_critical"],
                library["is_suspicious"],
                library["suspicious_reason"]
            ))
            
            # Get the library ID
            cursor.execute("SELECT id FROM libraries WHERE path = ?", (library["path"],))
            library_id = cursor.fetchone()[0]
            
            # Process symbols
            self._process_library_symbols(library["path"], library_id, cursor, conn, current_time)
            
            return library
            
        except Exception as e:
            self.logger.error(f"Error processing library {library['path']}: {e}")
            return None
    
    def _process_library_symbols(self, library_path, library_id, cursor, conn, current_time):
        """
        Process and store symbols from a library
        
        Args:
            library_path (str): Path to the library file
            library_id (int): Database ID of the library
            cursor: Database cursor
            conn: Database connection
            current_time (float): Current time
            
        Returns:
            int: Number of symbols processed
        """
        try:
            symbols = self.get_library_symbols(library_path)
            
            for symbol in symbols:
                # Check if symbol exists
                cursor.execute(
                    "SELECT id, symbol_value FROM library_symbols WHERE library_id = ? AND symbol_name = ?",
                    (library_id, symbol["name"])
                )
                
                row = cursor.fetchone()
                
                if row:
                    # Symbol exists, check if value changed
                    symbol_id = row[0]
                    old_value = row[1]
                    
                    if old_value != symbol["value"] and symbol["value"]:
                        # Value changed, might indicate hooking
                        cursor.execute(
                            "UPDATE library_symbols SET symbol_value = ?, last_checked = ?, is_hooked = 1 WHERE id = ?",
                            (symbol["value"], current_time, symbol_id)
                        )
                        
                        # Record the change
                        cursor.execute('''
                        INSERT INTO symbol_changes 
                        (library_id, symbol_name, change_type, old_value, new_value, timestamp) 
                        VALUES (?, ?, ?, ?, ?, ?)
                        ''', (
                            library_id,
                            symbol["name"],
                            "address_changed",
                            old_value,
                            symbol["value"],
                            current_time
                        ))
                    else:
                        # Just update the last_checked time
                        cursor.execute(
                            "UPDATE library_symbols SET last_checked = ? WHERE id = ?",
                            (current_time, symbol_id)
                        )
                else:
                    # New symbol, insert it
                    cursor.execute('''
                    INSERT INTO library_symbols 
                    (library_id, symbol_name, symbol_type, symbol_value, first_seen, last_checked) 
                    VALUES (?, ?, ?, ?, ?, ?)
                    ''', (
                        library_id,
                        symbol["name"],
                        symbol["type"],
                        symbol["value"],
                        current_time,
                        current_time
                    ))
            
            return len(symbols)
            
        except Exception as e:
            self.logger.error(f"Error processing symbols for library {library_path}: {e}")
            return 0
    
    def _check_ld_preload(self, cursor, conn):
        """
        Check for LD_PRELOAD environment variable and preloaded libraries
        
        Args:
            cursor: Database cursor
            conn: Database connection
            
        Returns:
            bool: True if preloaded libraries found, False otherwise
        """
        try:
            preloaded_libraries = []
            
            # Check environment variable
            ld_preload = os.environ.get('LD_PRELOAD', '')
            if ld_preload:
                preloaded_libraries.extend(ld_preload.split(':'))
                
            # Check /etc/ld.so.preload if it exists
            if os.path.exists('/etc/ld.so.preload'):
                with open('/etc/ld.so.preload', 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            preloaded_libraries.append(line)
            
            if preloaded_libraries:
                # Record preloaded libraries
                cursor.execute(
                    "INSERT INTO preload_history (libraries, timestamp) VALUES (?, ?)",
                    (json.dumps(preloaded_libraries), time.time())
                )
                
                self.logger.warning(f"Preloaded libraries detected: {preloaded_libraries}")
                return True
                
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking LD_PRELOAD: {e}")
            return False
    
    def check_integrity(self):
        """
        Check integrity of libraries against baseline
        
        Returns:
            list: List of detected changes
        """
        self.logger.info("Checking library integrity")
        
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        # Get current libraries
        current_libraries = self.get_all_libraries()
        current_paths = {lib["path"]: lib for lib in current_libraries}
        
        # Get baseline libraries
        cursor.execute(
            "SELECT id, path, hash, size, permissions, owner, group_owner, is_critical FROM libraries"
        )
        
        baseline_libraries = {}
        for row in cursor.fetchall():
            baseline_libraries[row[1]] = {
                "id": row[0],
                "path": row[1],
                "hash": row[2],
                "size": row[3],
                "permissions": row[4],
                "owner": row[5],
                "group_owner": row[6],
                "is_critical": row[7]
            }
        
        baseline_paths = set(baseline_libraries.keys())
        current_paths_set = set(current_paths.keys())
        
        changes = []
        current_time = time.time()
        
        # Check for new libraries
        for path in current_paths_set - baseline_paths:
            library = current_paths[path]
            
            # Record the change
            cursor.execute('''
            INSERT INTO library_changes 
            (path, change_type, new_hash, new_permissions, new_owner, new_size, timestamp) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                path,
                "added",
                library["hash"],
                library["permissions"],
                library["owner"],
                library["size"],
                current_time
            ))
            
            # Add new library to baseline
            cursor.execute('''
            INSERT INTO libraries 
            (path, name, hash, size, permissions, owner, group_owner, last_modified, 
             first_seen, last_checked, is_critical, is_suspicious, suspicious_reason) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                library["path"],
                library["name"],
                library["hash"],
                library["size"],
                library["permissions"],
                library["owner"],
                library["group_owner"],
                library["last_modified"],
                current_time,
                current_time,
                library["is_critical"],
                library["is_suspicious"],
                library["suspicious_reason"]
            ))
            
            # Get the library ID
            cursor.execute("SELECT id FROM libraries WHERE path = ?", (path,))
            library_id = cursor.fetchone()[0]
            
            # Process symbols
            self._process_library_symbols(path, library_id, cursor, conn, current_time)
            
            changes.append({
                "path": path,
                "type": "added",
                "is_critical": library["is_critical"],
                "is_suspicious": library["is_suspicious"],
                "reason": library["suspicious_reason"] if library["is_suspicious"] else "",
                "timestamp": current_time
            })
            
        # Check for deleted libraries
        for path in baseline_paths - current_paths_set:
            baseline = baseline_libraries[path]
            
            # Record the change
            cursor.execute('''
            INSERT INTO library_changes 
            (path, change_type, old_hash, old_permissions, old_owner, old_size, timestamp) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                path,
                "deleted",
                baseline["hash"],
                baseline["permissions"],
                baseline["owner"],
                baseline["size"],
                current_time
            ))
            
            # Mark library as deleted in baseline
            cursor.execute(
                "DELETE FROM libraries WHERE path = ?",
                (path,)
            )
            
            changes.append({
                "path": path,
                "type": "deleted",
                "is_critical": baseline["is_critical"],
                "timestamp": current_time
            })
            
        # Check for modified libraries
        for path in baseline_paths.intersection(current_paths_set):
            baseline = baseline_libraries[path]
            current = current_paths[path]
            
            change_detected = False
            change_type = []
            
            # Check hash (content changed)
            if baseline["hash"] != current["hash"]:
                change_detected = True
                change_type.append("content")
                
            # Check permissions
            if baseline["permissions"] != current["permissions"]:
                change_detected = True
                change_type.append("permissions")
                
            # Check ownership
            if baseline["owner"] != current["owner"] or baseline["group_owner"] != current["group_owner"]:
                change_detected = True
                change_type.append("ownership")
                
            # Record the change if detected
            if change_detected:
                change_type_str = ",".join(change_type)
                
                cursor.execute('''
                INSERT INTO library_changes 
                (path, change_type, old_hash, new_hash, old_permissions, new_permissions, 
                 old_owner, new_owner, old_size, new_size, timestamp) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    path,
                    change_type_str,
                    baseline["hash"],
                    current["hash"],
                    baseline["permissions"],
                    current["permissions"],
                    baseline["owner"],
                    current["owner"],
                    baseline["size"],
                    current["size"],
                    current_time
                ))
                
                # Update baseline
                cursor.execute('''
                UPDATE libraries 
                SET hash = ?, size = ?, permissions = ?, owner = ?, group_owner = ?, 
                last_modified = ?, last_checked = ? 
                WHERE path = ?
                ''', (
                    current["hash"],
                    current["size"],
                    current["permissions"],
                    current["owner"],
                    current["group_owner"],
                    current["last_modified"],
                    current_time,
                    path
                ))
                
                # Update symbols
                cursor.execute("SELECT id FROM libraries WHERE path = ?", (path,))
                library_id = cursor.fetchone()[0]
                self._process_library_symbols(path, library_id, cursor, conn, current_time)
                
                changes.append({
                    "path": path,
                    "type": change_type_str,
                    "is_critical": baseline["is_critical"],
                    "is_suspicious": current["is_suspicious"],
                    "reason": current["suspicious_reason"] if current["is_suspicious"] else "",
                    "timestamp": current_time
                })
            else:
                # Just update the last_checked time
                cursor.execute(
                    "UPDATE libraries SET last_checked = ? WHERE path = ?",
                    (current_time, path)
                )
                
                # Check symbols for changes
                cursor.execute("SELECT id FROM libraries WHERE path = ?", (path,))
                library_id = cursor.fetchone()[0]
                self._process_library_symbols(path, library_id, cursor, conn, current_time)
        
        # Check for LD_PRELOAD changes
        if self._check_ld_preload(cursor, conn):
            changes.append({
                "path": "LD_PRELOAD",
                "type": "preload",
                "is_critical": 1,
                "is_suspicious": 1,
                "reason": "LD_PRELOAD environment variable or /etc/ld.so.preload file detected",
                "timestamp": current_time
            })
        
        conn.commit()
        conn.close()
        
        self.logger.info(f"Integrity check completed. Found {len(changes)} changes.")
        return changes
    
    def get_hooked_symbols(self):
        """
        Get list of hooked symbols
        
        Returns:
            list: List of potentially hooked symbols
        """
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        # Get hooked symbols
        cursor.execute('''
        SELECT s.symbol_name, s.symbol_value, s.first_seen, l.path, l.name
        FROM library_symbols s
        JOIN libraries l ON s.library_id = l.id
        WHERE s.is_hooked = 1
        ''')
        
        hooked_symbols = []
        for row in cursor.fetchall():
            hooked_symbols.append({
                "symbol": row[0],
                "address": row[1],
                "first_seen": datetime.fromtimestamp(row[2]).strftime('%Y-%m-%d %H:%M:%S'),
                "library_path": row[3],
                "library_name": row[4]
            })
            
        conn.close()
        return hooked_symbols
    
    def get_suspicious_libraries(self):
        """
        Get list of suspicious libraries
        
        Returns:
            list: List of suspicious libraries
        """
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT path, name, hash, size, suspicious_reason FROM libraries WHERE is_suspicious = 1"
        )
        
        suspicious = []
        for row in cursor.fetchall():
            suspicious.append({
                "path": row[0],
                "name": row[1],
                "hash": row[2],
                "size": row[3],
                "reason": row[4]
            })
            
        conn.close()
        return suspicious
    
    def get_preload_history(self):
        """
        Get history of preloaded libraries
        
        Returns:
            list: History of preloaded libraries
        """
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT libraries, timestamp FROM preload_history ORDER BY timestamp DESC")
        
        history = []
        for row in cursor.fetchall():
            history.append({
                "libraries": json.loads(row[0]),
                "timestamp": datetime.fromtimestamp(row[1]).strftime('%Y-%m-%d %H:%M:%S')
            })
            
        conn.close()
        return history
    
    def get_recent_changes(self, limit=100, since=None, include_verified=False):
        """
        Get recent library changes
        
        Args:
            limit (int): Maximum number of changes to return
            since (float): Only return changes after this timestamp
            include_verified (bool): Whether to include verified changes
            
        Returns:
            list: List of recent changes
        """
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        query = "SELECT * FROM library_changes"
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
                "type": row[2],
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
            
            cursor.execute("UPDATE library_changes SET verified = 1 WHERE id = ?", (change_id,))
            conn.commit()
            conn.close()
            
            return True
        except Exception as e:
            self.logger.error(f"Failed to verify change {change_id}: {e}")
            return False
    
    def check_for_library_hooking(self):
        """
        Perform a detailed check for library hooking
        
        Returns:
            dict: Results of library hooking checks
        """
        results = {
            "hooked_symbols": [],
            "suspicious_libs": [],
            "preload_detected": False,
            "binary_plts": []
        }
        
        # Get hooked symbols
        results["hooked_symbols"] = self.get_hooked_symbols()
        
        # Get suspicious libraries
        results["suspicious_libs"] = self.get_suspicious_libraries()
        
        # Check for preloaded libraries
        preload_history = self.get_preload_history()
        if preload_history:
            results["preload_detected"] = True
            results["preload_history"] = preload_history
        
        # Check PLT hooking in common binaries
        try:
            common_binaries = ['/bin/ls', '/bin/bash', '/usr/bin/ssh', '/bin/login']
            plt_hooks = []
            
            for binary in common_binaries:
                if os.path.exists(binary):
                    # Check if objdump is available
                    try:
                        output = subprocess.run(['objdump', '-R', binary], stdout=subprocess.PIPE, 
                                             stderr=subprocess.PIPE, text=True).stdout
                        
                        for line in output.split('\n'):
                            for func in self.config["function_hooking_targets"]:
                                if f"@plt" in line and func in line:
                                    plt_hooks.append({
                                        "binary": binary,
                                        "function": func,
                                        "line": line.strip()
                                    })
                    except Exception:
                        pass
            
            results["binary_plts"] = plt_hooks
            
        except Exception as e:
            self.logger.error(f"Error checking PLT hooking: {e}")
        
        # Determine overall threat level
        threat_level = "low"
        if results["preload_detected"]:
            threat_level = "critical"
        elif results["hooked_symbols"]:
            threat_level = "high"
        elif results["suspicious_libs"]:
            threat_level = "medium"
            
        results["threat_level"] = threat_level
        results["timestamp"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        return results
    
    def get_statistics(self):
        """
        Get statistics about the library inspection system
        
        Returns:
            dict: Statistics
        """
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        # Total libraries monitored
        cursor.execute("SELECT COUNT(*) FROM libraries")
        total_libraries = cursor.fetchone()[0]
        
        # Critical libraries
        cursor.execute("SELECT COUNT(*) FROM libraries WHERE is_critical = 1")
        critical_libraries = cursor.fetchone()[0]
        
        # Suspicious libraries
        cursor.execute("SELECT COUNT(*) FROM libraries WHERE is_suspicious = 1")
        suspicious_libraries = cursor.fetchone()[0]
        
        # Recent changes (last 24 hours)
        cursor.execute("SELECT COUNT(*) FROM library_changes WHERE timestamp > ?", 
                     (time.time() - 86400,))
        recent_changes = cursor.fetchone()[0]
        
        # Unverified changes
        cursor.execute("SELECT COUNT(*) FROM library_changes WHERE verified = 0")
        unverified_changes = cursor.fetchone()[0]
        
        # Total symbols
        cursor.execute("SELECT COUNT(*) FROM library_symbols")
        total_symbols = cursor.fetchone()[0]
        
        # Hooked symbols
        cursor.execute("SELECT COUNT(*) FROM library_symbols WHERE is_hooked = 1")
        hooked_symbols = cursor.fetchone()[0]
        
        # Change types breakdown
        cursor.execute("""
        SELECT 
            SUM(CASE WHEN change_type = 'added' THEN 1 ELSE 0 END) as added,
            SUM(CASE WHEN change_type = 'deleted' THEN 1 ELSE 0 END) as deleted,
            SUM(CASE WHEN change_type LIKE '%content%' THEN 1 ELSE 0 END) as content,
            SUM(CASE WHEN change_type LIKE '%permissions%' THEN 1 ELSE 0 END) as permissions,
            SUM(CASE WHEN change_type LIKE '%ownership%' THEN 1 ELSE 0 END) as ownership
        FROM library_changes
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
            "total_libraries_monitored": total_libraries,
            "critical_libraries_monitored": critical_libraries,
            "suspicious_libraries": suspicious_libraries,
            "total_symbols_monitored": total_symbols,
            "hooked_symbols": hooked_symbols,
            "recent_changes": recent_changes,
            "unverified_changes": unverified_changes,
            "change_types_last_7_days": change_types,
            "database_size_bytes": database_size,
            "database_path": self.database_path,
            "last_updated": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
    
    def run_scan(self):
        """
        Run a full library integrity scan and return the results
        
        Returns:
            dict: Scan results
        """
        start_time = time.time()
        
        # Check library integrity
        changes = self.check_integrity()
        
        # Check for library hooking
        hooking_check = self.check_for_library_hooking()
        
        scan_time = time.time() - start_time
        
        # Get statistics
        stats = self.get_statistics()
        
        # Categorize changes by type
        change_types = {
            "added": [],
            "deleted": [],
            "content": [],
            "permissions": [],
            "ownership": [],
            "preload": []
        }
        
        critical_changes = []
        
        for change in changes:
            # Categorize by change type
            if change["type"] == "added":
                change_types["added"].append(change)
            elif change["type"] == "deleted":
                change_types["deleted"].append(change)
            elif change["type"] == "preload":
                change_types["preload"].append(change)
            else:
                # Handle multiple change types (comma-separated)
                for change_type in change["type"].split(","):
                    if change_type in change_types:
                        change_types[change_type].append(change)
            
            # Track critical changes
            if change.get("is_critical", 0) == 1:
                critical_changes.append(change)
        
        # Determine overall threat level
        threat_level = hooking_check["threat_level"]
        
        if hooking_check["threat_level"] == "low" and critical_changes:
            threat_level = "high"
            
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
                "ownership": len(change_types["ownership"]),
                "preload": len(change_types["preload"])
            },
            "critical_changes": critical_changes,
            "library_hooking_detection": hooking_check,
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
                    self.logger.info("Running scheduled library integrity scan")
                    scan_results = self.run_scan()
                    
                    # Log results
                    self.logger.info(f"Scan completed. Threat level: {scan_results['threat_level']}, "
                                   f"Changes detected: {scan_results['total_changes']}")
                    
                    # Alert for high threat level
                    if scan_results["threat_level"] in ["medium", "high", "critical"]:
                        self.logger.warning(f"Elevated threat level detected: {scan_results['threat_level']}")
                        
                        # Log critical details
                        if scan_results["critical_changes"]:
                            self.logger.warning(f"Critical library changes detected: {len(scan_results['critical_changes'])}")
                            for change in scan_results["critical_changes"]:
                                self.logger.warning(f"Critical change: {change['path']} ({change['type']})")
                                
                        if scan_results["library_hooking_detection"]["preload_detected"]:
                            self.logger.warning("LD_PRELOAD detected!")
                            
                        if scan_results["library_hooking_detection"]["hooked_symbols"]:
                            self.logger.warning(f"Hooked symbols detected: {len(scan_results['library_hooking_detection']['hooked_symbols'])}")
                            
                        if scan_results["library_hooking_detection"]["suspicious_libs"]:
                            self.logger.warning(f"Suspicious libraries detected: {len(scan_results['library_hooking_detection']['suspicious_libs'])}")
                    
                except Exception as e:
                    self.logger.error(f"Error in monitoring thread: {e}")
                
                # Sleep until next scan
                time.sleep(interval)
        
        # Start the thread
        monitor_thread = threading.Thread(target=monitoring_thread, daemon=True)
        monitor_thread.start()
        
        return True