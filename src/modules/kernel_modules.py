#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import subprocess
import logging
import json
import hashlib
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

class KernelModuleAnalyzer:
    """
    Kernel Module Analysis module for Linux systems
    
    Detects suspicious or malicious kernel modules, monitors module loading/unloading,
    and checks for rootkits and other tampering of kernel functionality.
    """
    
    def __init__(self, database_path=None, config_file=None):
        """
        Initialize the Kernel Module Analyzer
        
        Args:
            database_path (str): Path to the database file for storing module data
            config_file (str): Path to configuration file
        """
        self.logger = logging.getLogger("sharpeye.kernel_modules")
        
        # Set default database path if not provided
        if database_path is None:
            home_dir = os.path.expanduser("~")
            self.database_path = os.path.join(home_dir, ".sharpeye", "kernel_modules.db")
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
            "whitelist_modules": [
                # Common legitimate kernel modules
                "ext4", "btrfs", "xfs", "zfs", "ntfs", "f2fs",  # Filesystems
                "snd", "snd_hda_intel", "snd_usb_audio",  # Sound
                "nvidia", "nouveau", "radeon", "amdgpu",  # Graphics
                "e1000", "r8169", "iwlwifi", "ath9k",  # Network
                "cdrom", "usb_storage", "sd_mod",  # Storage
                "bluetooth", "rfcomm",  # Bluetooth
                "cpufreq", "acpi", "thermal", "battery",  # Power
                "evdev", "hid", "usbhid", "mousedev",  # Input
                "raid1", "dm_crypt", "dm_mod", "md_mod",  # Storage tech
                "vboxdrv", "vboxnetflt", "vboxnetadp"  # VirtualBox
            ],
            "known_rootkits": [
                # Known rootkit modules
                "diamorphine", "reptile", "suterusu", "adore", "modhide", "wnps", 
                "ksim", "khide", "kmod", "tuxkit", "knark", "kis", "sebek", 
                "taskigt", "rootme", "rkit", "enyelkm", "phalanx"
            ],
            "thread_count": 4,
            "scan_interval": 3600,  # 1 hour
            "suspicious_parameters": [
                # Parameters that might be used to hide rootkit functionality
                "hidden", "stealth", "secret", "hide"
            ],
            "suspicious_module_patterns": [
                # Regex patterns for suspicious module names
                r"hide[_-].*",
                r".*[_-]hide",
                r"root[_-]kit",
                r"steal[_-].*",
                r"hack[_-].*",
                r".*[_-]hack",
                r"spy[_-].*",
                r".*[_-]spy"
            ],
            "suspicious_exports": [
                # Suspicious exported symbols that might indicate rootkit activity
                "find_task_by_pid", "unlink_file", "hide_process", "hide_file",
                "hijack_syscall", "modify_syscall", "modify_sys_call_table",
                "hook_syscall", "unregister_security", "proc_root_lookup"
            ],
            "critical_syscalls": [
                # Critical syscalls that are often targeted by rootkits
                "sys_read", "sys_write", "sys_open", "sys_getdents", "sys_getdents64",
                "sys_readdir", "sys_mkdir", "sys_rmdir", "sys_unlink", "sys_link",
                "sys_kill", "sys_chmod", "sys_readlink", "sys_execve", "sys_socket",
                "sys_connect", "sys_accept", "sys_rename", "sys_reboot", "sys_init_module",
                "sys_delete_module", "sys_chown", "sys_stat", "sys_lstat", "sys_fstat"
            ],
            "common_module_directories": [
                "/lib/modules",
                "/usr/lib/modules"
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
        """Initialize the SQLite database for storing kernel module data"""
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            # Create tables if they don't exist
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS kernel_modules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE,
                size INTEGER,
                loaded INTEGER,
                refcount INTEGER,
                module_hash TEXT,
                file_path TEXT,
                used_by TEXT,
                first_seen REAL,
                last_seen REAL,
                is_suspicious INTEGER DEFAULT 0,
                suspicious_reason TEXT
            )
            ''')
            
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS module_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                change_type TEXT,
                old_size INTEGER,
                new_size INTEGER,
                old_hash TEXT,
                new_hash TEXT,
                old_refcount INTEGER,
                new_refcount INTEGER,
                old_used_by TEXT,
                new_used_by TEXT,
                timestamp REAL,
                verified INTEGER DEFAULT 0
            )
            ''')
            
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS syscall_table (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                syscall_name TEXT UNIQUE,
                address TEXT,
                module_name TEXT,
                is_hooked INTEGER DEFAULT 0,
                first_seen REAL,
                last_checked REAL
            )
            ''')
            
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_module_name ON kernel_modules(name)
            ''')
            
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_change_name ON module_changes(name)
            ''')
            
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_syscall_name ON syscall_table(syscall_name)
            ''')
            
            conn.commit()
            self.logger.info("Database initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize database: {e}")
        finally:
            if conn:
                conn.close()
    
    def get_loaded_modules(self):
        """
        Get currently loaded kernel modules
        
        Returns:
            list: List of modules with their details
        """
        modules = []
        
        try:
            # Execute lsmod to get loaded modules
            proc = subprocess.run(['lsmod'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if proc.returncode != 0:
                self.logger.error(f"Failed to run lsmod: {proc.stderr}")
                return modules
                
            lines = proc.stdout.strip().split('\n')
            
            # Skip the header line
            for line in lines[1:]:
                parts = re.split(r'\s+', line.strip())
                if len(parts) >= 3:
                    module_name = parts[0]
                    module_size = int(parts[1])
                    refcount = int(parts[2])
                    used_by = " ".join(parts[3:]) if len(parts) > 3 else ""
                    
                    # Get the module file path
                    module_path = self._get_module_path(module_name)
                    
                    # Calculate hash if module file exists
                    module_hash = None
                    if module_path and os.path.exists(module_path):
                        module_hash = self._calculate_file_hash(module_path)
                    
                    modules.append({
                        "name": module_name,
                        "size": module_size,
                        "refcount": refcount,
                        "used_by": used_by,
                        "path": module_path,
                        "hash": module_hash,
                        "loaded": True
                    })
                
        except Exception as e:
            self.logger.error(f"Error getting loaded modules: {e}")
            
        return modules
    
    def _get_module_path(self, module_name):
        """
        Get the file path for a kernel module
        
        Args:
            module_name (str): Name of the module
            
        Returns:
            str: Path to the module file or None if not found
        """
        try:
            # Get kernel version
            kernel_version = subprocess.run(['uname', '-r'], stdout=subprocess.PIPE, 
                                          stderr=subprocess.PIPE, text=True).stdout.strip()
            
            # Common module locations
            module_paths = []
            
            # Add paths from config
            for directory in self.config["common_module_directories"]:
                if kernel_version:
                    module_paths.append(os.path.join(directory, kernel_version, "kernel", f"{module_name}.ko"))
                    module_paths.append(os.path.join(directory, kernel_version, f"{module_name}.ko"))
                
                # Try searching in subdirectories
                if os.path.exists(directory):
                    for root, dirs, files in os.walk(directory):
                        for file in files:
                            if file == f"{module_name}.ko":
                                module_paths.append(os.path.join(root, file))
            
            # Try to find module using modinfo
            try:
                proc = subprocess.run(['modinfo', '-F', 'filename', module_name], 
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if proc.returncode == 0 and proc.stdout.strip():
                    module_paths.insert(0, proc.stdout.strip())  # Add with highest priority
            except Exception:
                pass
                
            # Check each path
            for path in module_paths:
                if os.path.exists(path):
                    return path
                    
            return None
            
        except Exception as e:
            self.logger.error(f"Error finding module path for {module_name}: {e}")
            return None
    
    def _calculate_file_hash(self, file_path):
        """
        Calculate SHA256 hash for a given file
        
        Args:
            file_path (str): Path to the file
            
        Returns:
            str: File hash or None if failed
        """
        try:
            if not os.path.isfile(file_path):
                return None
                
            hash_func = hashlib.sha256()
            
            with open(file_path, 'rb') as f:
                # Read file in chunks to handle large files efficiently
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_func.update(chunk)
                    
            return hash_func.hexdigest()
        except (IOError, OSError) as e:
            self.logger.debug(f"Cannot hash file {file_path}: {e}")
            return None
    
    def get_module_details(self, module_name):
        """
        Get detailed information about a specific module
        
        Args:
            module_name (str): Name of the kernel module
            
        Returns:
            dict: Module details or None if failed
        """
        try:
            # Run modinfo to get module details
            proc = subprocess.run(['modinfo', module_name], stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE, text=True)
            if proc.returncode != 0:
                self.logger.error(f"Failed to run modinfo for {module_name}: {proc.stderr}")
                return None
                
            lines = proc.stdout.strip().split('\n')
            
            details = {
                "name": module_name,
                "path": None,
                "description": None,
                "author": None,
                "license": None,
                "version": None,
                "parameters": [],
                "dependencies": [],
                "signature": None
            }
            
            current_param = None
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                    
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    if key == "filename":
                        details["path"] = value
                    elif key == "description":
                        details["description"] = value
                    elif key == "author":
                        details["author"] = value
                    elif key == "license":
                        details["license"] = value
                    elif key == "version":
                        details["version"] = value
                    elif key == "depends":
                        details["dependencies"] = [d.strip() for d in value.split(',') if d.strip()]
                    elif key == "sig_key":
                        details["signature"] = value
                    elif key == "parm":
                        current_param = {
                            "name": value.split(':', 1)[0].strip() if ':' in value else value,
                            "description": value.split(':', 1)[1].strip() if ':' in value else None
                        }
                        details["parameters"].append(current_param)
                    elif key == "parmtype" and current_param:
                        current_param["type"] = value
            
            return details
            
        except Exception as e:
            self.logger.error(f"Error getting module details for {module_name}: {e}")
            return None
    
    def get_available_modules(self):
        """
        Get all available kernel modules on the system (including not loaded)
        
        Returns:
            list: List of available modules
        """
        available_modules = []
        
        try:
            # Get kernel version
            kernel_version = subprocess.run(['uname', '-r'], stdout=subprocess.PIPE, 
                                          stderr=subprocess.PIPE, text=True).stdout.strip()
            
            # Search for modules in common directories
            for directory in self.config["common_module_directories"]:
                base_dir = os.path.join(directory, kernel_version) if kernel_version else directory
                
                if not os.path.exists(base_dir):
                    continue
                    
                for root, _, files in os.walk(base_dir):
                    for file in files:
                        if file.endswith('.ko'):
                            module_path = os.path.join(root, file)
                            module_name = file[:-3]  # Remove .ko extension
                            
                            # Calculate hash
                            module_hash = self._calculate_file_hash(module_path)
                            
                            available_modules.append({
                                "name": module_name,
                                "path": module_path,
                                "hash": module_hash,
                                "loaded": False  # Will be updated later
                            })
            
            # Get the list of loaded modules to update the "loaded" flag
            loaded_modules = self.get_loaded_modules()
            loaded_module_names = [m["name"] for m in loaded_modules]
            
            # Update loaded status and add any missing loaded modules
            for module in available_modules:
                if module["name"] in loaded_module_names:
                    module["loaded"] = True
                    
            # Add loaded modules that weren't found in the file system
            for loaded_module in loaded_modules:
                if loaded_module["name"] not in [m["name"] for m in available_modules]:
                    available_modules.append(loaded_module)
                    
            return available_modules
            
        except Exception as e:
            self.logger.error(f"Error getting available modules: {e}")
            return []
    
    def create_baseline(self):
        """
        Create a baseline of kernel modules
        
        Returns:
            tuple: (int, int) Count of (processed modules, suspicious modules)
        """
        self.logger.info("Creating kernel module baseline")
        
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        # Get current modules
        modules = self.get_available_modules()
        
        processed_count = 0
        suspicious_count = 0
        
        for module in modules:
            # Check if module is suspicious
            is_suspicious, reason = self._check_module_suspicious(module)
            
            if is_suspicious:
                suspicious_count += 1
                
            # Get additional details for loaded modules
            details = None
            if module["loaded"]:
                details = self.get_module_details(module["name"])
            
            # Insert or update record in database
            try:
                cursor.execute('''
                INSERT OR REPLACE INTO kernel_modules 
                (name, size, loaded, refcount, module_hash, file_path, used_by, 
                 first_seen, last_seen, is_suspicious, suspicious_reason) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    module["name"],
                    module.get("size", 0),
                    1 if module["loaded"] else 0,
                    module.get("refcount", 0),
                    module.get("hash", ""),
                    module.get("path", ""),
                    module.get("used_by", ""),
                    time.time(),
                    time.time(),
                    1 if is_suspicious else 0,
                    reason if is_suspicious else ""
                ))
                
                processed_count += 1
                
            except Exception as e:
                self.logger.error(f"Error inserting module {module['name']}: {e}")
        
        conn.commit()
        
        # Check for syscall table hooking (if the system supports it)
        try:
            self._check_syscall_table()
        except Exception as e:
            self.logger.error(f"Error checking syscall table: {e}")
        
        conn.close()
        
        self.logger.info(f"Baseline creation completed. Processed {processed_count} modules, "
                       f"found {suspicious_count} suspicious modules.")
        return processed_count, suspicious_count
    
    def _check_module_suspicious(self, module):
        """
        Check if a module is suspicious
        
        Args:
            module (dict): Module information
            
        Returns:
            tuple: (bool, str) True if suspicious and reason
        """
        # Check if it's a known rootkit
        if module["name"] in self.config["known_rootkits"]:
            return True, f"Known rootkit: {module['name']}"
            
        # Check against suspicious name patterns
        for pattern in self.config["suspicious_module_patterns"]:
            if re.match(pattern, module["name"], re.IGNORECASE):
                return True, f"Suspicious name pattern: {pattern}"
                
        # Get module details if loaded
        if module["loaded"]:
            details = self.get_module_details(module["name"])
            if details:
                # Check for suspicious parameters
                for param in details.get("parameters", []):
                    param_name = param.get("name", "")
                    for sus_param in self.config["suspicious_parameters"]:
                        if sus_param.lower() in param_name.lower():
                            return True, f"Suspicious parameter: {param_name}"
                
                # Check if unsigned (if system supports module signing)
                if "signature" in details and details["signature"] is None:
                    # Module signing is supported but this module is unsigned
                    # Not a definite indicator but worth noting
                    return True, "Unsigned module"
                    
                # Check for missing license or author
                if not details.get("license") or not details.get("author"):
                    return True, "Missing license or author information"
        
        # All checks passed
        return False, ""
    
    def _check_syscall_table(self):
        """
        Check for syscall table hooking (if supported by the kernel)
        
        Returns:
            bool: True if successful, False otherwise
        """
        # This is a complex operation that might not work on all kernels
        # and might require special permissions
        
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        try:
            # Check if /proc/kallsyms is available
            if not os.path.exists('/proc/kallsyms'):
                self.logger.warning("Syscall table checking not supported: /proc/kallsyms not available")
                return False
                
            # Try to read syscall table addresses
            syscall_addresses = {}
            
            # Read /proc/kallsyms to find syscall addresses
            with open('/proc/kallsyms', 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        address = parts[0]
                        symbol_type = parts[1]
                        symbol_name = parts[2]
                        
                        # Check if it's a syscall
                        if symbol_name.startswith('sys_') or symbol_name.startswith('__x64_sys_'):
                            module = parts[3] if len(parts) > 3 else ""
                            syscall_addresses[symbol_name] = {
                                "address": address,
                                "module": module
                            }
            
            # Store syscall information
            current_time = time.time()
            
            for syscall_name, info in syscall_addresses.items():
                # Check if syscall is in our critical list or starts with sys_
                is_critical = syscall_name in self.config["critical_syscalls"] or syscall_name.startswith('sys_')
                
                if is_critical:
                    # Check if syscall entry already exists
                    cursor.execute(
                        "SELECT address, module_name, first_seen FROM syscall_table WHERE syscall_name = ?", 
                        (syscall_name,)
                    )
                    
                    row = cursor.fetchone()
                    
                    if row:
                        # Entry exists, check if it changed
                        old_address = row[0]
                        old_module = row[1]
                        first_seen = row[2]
                        
                        is_hooked = 0
                        
                        if old_address != info["address"]:
                            is_hooked = 1
                            self.logger.warning(f"Syscall {syscall_name} address changed: {old_address} -> {info['address']}")
                            
                        if old_module != info["module"] and info["module"]:
                            is_hooked = 1
                            self.logger.warning(f"Syscall {syscall_name} module changed: {old_module} -> {info['module']}")
                            
                        # Update the entry
                        cursor.execute('''
                        UPDATE syscall_table 
                        SET address = ?, module_name = ?, is_hooked = ?, last_checked = ? 
                        WHERE syscall_name = ?
                        ''', (
                            info["address"],
                            info["module"],
                            is_hooked,
                            current_time,
                            syscall_name
                        ))
                        
                    else:
                        # New entry
                        cursor.execute('''
                        INSERT INTO syscall_table 
                        (syscall_name, address, module_name, is_hooked, first_seen, last_checked) 
                        VALUES (?, ?, ?, ?, ?, ?)
                        ''', (
                            syscall_name,
                            info["address"],
                            info["module"],
                            0,  # Not hooked initially
                            current_time,
                            current_time
                        ))
            
            conn.commit()
            return True
            
        except Exception as e:
            self.logger.error(f"Error checking syscall table: {e}")
            return False
            
        finally:
            conn.close()
    
    def check_integrity(self):
        """
        Check integrity of kernel modules against baseline
        
        Returns:
            list: List of detected changes
        """
        self.logger.info("Checking kernel module integrity")
        
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        # Get current modules
        current_modules = self.get_loaded_modules()
        current_module_names = [m["name"] for m in current_modules]
        
        # Get baseline modules
        cursor.execute(
            "SELECT name, size, loaded, refcount, module_hash, file_path, used_by FROM kernel_modules"
        )
        
        baseline_modules = {}
        for row in cursor.fetchall():
            baseline_modules[row[0]] = {
                "name": row[0],
                "size": row[1],
                "loaded": row[2] == 1,
                "refcount": row[3],
                "hash": row[4],
                "path": row[5],
                "used_by": row[6]
            }
        
        baseline_module_names = set(baseline_modules.keys())
        
        changes = []
        
        # Check for new modules
        for module in current_modules:
            if module["name"] not in baseline_module_names:
                # New module detected
                is_suspicious, reason = self._check_module_suspicious(module)
                
                # Record the change
                cursor.execute('''
                INSERT INTO module_changes 
                (name, change_type, new_size, new_hash, new_refcount, new_used_by, timestamp) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    module["name"],
                    "added",
                    module.get("size", 0),
                    module.get("hash", ""),
                    module.get("refcount", 0),
                    module.get("used_by", ""),
                    time.time()
                ))
                
                # Add to baseline
                cursor.execute('''
                INSERT INTO kernel_modules 
                (name, size, loaded, refcount, module_hash, file_path, used_by, 
                 first_seen, last_seen, is_suspicious, suspicious_reason) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    module["name"],
                    module.get("size", 0),
                    1,  # Loaded
                    module.get("refcount", 0),
                    module.get("hash", ""),
                    module.get("path", ""),
                    module.get("used_by", ""),
                    time.time(),
                    time.time(),
                    1 if is_suspicious else 0,
                    reason if is_suspicious else ""
                ))
                
                changes.append({
                    "name": module["name"],
                    "type": "added",
                    "suspicious": is_suspicious,
                    "reason": reason if is_suspicious else "",
                    "timestamp": time.time()
                })
                
        # Check for unloaded modules
        for name, baseline in baseline_modules.items():
            if baseline["loaded"] and name not in current_module_names:
                # Module unloaded
                cursor.execute('''
                INSERT INTO module_changes 
                (name, change_type, old_size, old_hash, old_refcount, old_used_by, timestamp) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    name,
                    "unloaded",
                    baseline.get("size", 0),
                    baseline.get("hash", ""),
                    baseline.get("refcount", 0),
                    baseline.get("used_by", ""),
                    time.time()
                ))
                
                # Update baseline
                cursor.execute('''
                UPDATE kernel_modules 
                SET loaded = 0, last_seen = ? 
                WHERE name = ?
                ''', (
                    time.time(),
                    name
                ))
                
                changes.append({
                    "name": name,
                    "type": "unloaded",
                    "timestamp": time.time()
                })
                
        # Check for modified modules
        for module in current_modules:
            if module["name"] in baseline_module_names:
                baseline = baseline_modules[module["name"]]
                
                # Check if module attributes changed
                change_detected = False
                change_type = []
                
                # Check size
                if module.get("size", 0) != baseline.get("size", 0):
                    change_detected = True
                    change_type.append("size")
                    
                # Check hash
                if module.get("hash") and baseline.get("hash") and module["hash"] != baseline["hash"]:
                    change_detected = True
                    change_type.append("hash")
                    
                # Check refcount (not always reliable but can indicate suspicious activity)
                if module.get("refcount", 0) < baseline.get("refcount", 0):
                    # Refcount decreased unexpectedly
                    change_detected = True
                    change_type.append("refcount")
                    
                # Record the change if detected
                if change_detected:
                    change_type_str = ",".join(change_type)
                    
                    cursor.execute('''
                    INSERT INTO module_changes 
                    (name, change_type, old_size, new_size, old_hash, new_hash, 
                     old_refcount, new_refcount, old_used_by, new_used_by, timestamp) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        module["name"],
                        change_type_str,
                        baseline.get("size", 0),
                        module.get("size", 0),
                        baseline.get("hash", ""),
                        module.get("hash", ""),
                        baseline.get("refcount", 0),
                        module.get("refcount", 0),
                        baseline.get("used_by", ""),
                        module.get("used_by", ""),
                        time.time()
                    ))
                    
                    # Update baseline
                    cursor.execute('''
                    UPDATE kernel_modules 
                    SET size = ?, loaded = 1, refcount = ?, module_hash = ?, 
                    file_path = ?, used_by = ?, last_seen = ? 
                    WHERE name = ?
                    ''', (
                        module.get("size", 0),
                        module.get("refcount", 0),
                        module.get("hash", ""),
                        module.get("path", ""),
                        module.get("used_by", ""),
                        time.time(),
                        module["name"]
                    ))
                    
                    # Check if module became suspicious
                    is_suspicious, reason = self._check_module_suspicious(module)
                    
                    if is_suspicious:
                        cursor.execute('''
                        UPDATE kernel_modules 
                        SET is_suspicious = 1, suspicious_reason = ? 
                        WHERE name = ?
                        ''', (
                            reason,
                            module["name"]
                        ))
                    
                    changes.append({
                        "name": module["name"],
                        "type": change_type_str,
                        "suspicious": is_suspicious,
                        "reason": reason if is_suspicious else "",
                        "timestamp": time.time()
                    })
                else:
                    # Just update the last_seen timestamp
                    cursor.execute(
                        "UPDATE kernel_modules SET last_seen = ? WHERE name = ?",
                        (time.time(), module["name"])
                    )
        
        # Check for syscall table hooking
        try:
            self._check_syscall_table()
            
            # Get hooked syscalls
            cursor.execute(
                "SELECT syscall_name, address, module_name FROM syscall_table WHERE is_hooked = 1"
            )
            
            for row in cursor.fetchall():
                changes.append({
                    "name": row[0],
                    "type": "syscall_hooked",
                    "address": row[1],
                    "module": row[2],
                    "suspicious": True,
                    "reason": "Syscall address or module changed",
                    "timestamp": time.time()
                })
                
        except Exception as e:
            self.logger.error(f"Error checking syscall table: {e}")
        
        conn.commit()
        conn.close()
        
        self.logger.info(f"Integrity check completed. Found {len(changes)} changes.")
        return changes
    
    def get_suspicious_modules(self):
        """
        Get list of suspicious modules
        
        Returns:
            list: List of suspicious modules
        """
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT name, size, loaded, module_hash, file_path, suspicious_reason FROM kernel_modules WHERE is_suspicious = 1"
        )
        
        suspicious = []
        for row in cursor.fetchall():
            suspicious.append({
                "name": row[0],
                "size": row[1],
                "loaded": row[2] == 1,
                "hash": row[3],
                "path": row[4],
                "reason": row[5]
            })
            
        conn.close()
        return suspicious
    
    def get_recent_changes(self, limit=100, since=None, include_verified=False):
        """
        Get recent changes to kernel modules
        
        Args:
            limit (int): Maximum number of changes to return
            since (float): Only return changes after this timestamp
            include_verified (bool): Whether to include verified changes
            
        Returns:
            list: List of recent changes
        """
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        query = "SELECT * FROM module_changes"
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
                "name": row[1],
                "type": row[2],
                "old_size": row[3],
                "new_size": row[4],
                "old_hash": row[5],
                "new_hash": row[6],
                "old_refcount": row[7],
                "new_refcount": row[8],
                "old_used_by": row[9],
                "new_used_by": row[10],
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
            
            cursor.execute("UPDATE module_changes SET verified = 1 WHERE id = ?", (change_id,))
            conn.commit()
            conn.close()
            
            return True
        except Exception as e:
            self.logger.error(f"Failed to verify change {change_id}: {e}")
            return False
    
    def get_hooked_syscalls(self):
        """
        Get list of hooked syscalls
        
        Returns:
            list: List of hooked syscalls
        """
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT syscall_name, address, module_name, first_seen, last_checked FROM syscall_table WHERE is_hooked = 1"
        )
        
        hooked = []
        for row in cursor.fetchall():
            hooked.append({
                "name": row[0],
                "address": row[1],
                "module": row[2],
                "first_seen": datetime.fromtimestamp(row[3]).strftime('%Y-%m-%d %H:%M:%S'),
                "last_checked": datetime.fromtimestamp(row[4]).strftime('%Y-%m-%d %H:%M:%S')
            })
            
        conn.close()
        return hooked
    
    def get_hidden_modules(self):
        """
        Attempt to detect hidden kernel modules
        
        Returns:
            list: List of potentially hidden modules
        """
        hidden_modules = []
        
        try:
            # This method attempts to detect hidden modules by comparing different sources
            # of kernel module information. It's not foolproof and might not work on all
            # systems or with sophisticated rootkits.
            
            # Method 1: Compare /proc/modules with lsmod output
            proc_modules = set()
            lsmod_modules = set()
            
            # Get modules from /proc/modules
            if os.path.exists('/proc/modules'):
                with open('/proc/modules', 'r') as f:
                    for line in f:
                        parts = line.strip().split()
                        if parts:
                            proc_modules.add(parts[0])
            
            # Get modules from lsmod
            lsmod_output = subprocess.run(['lsmod'], stdout=subprocess.PIPE, 
                                         stderr=subprocess.PIPE, text=True).stdout
            for line in lsmod_output.strip().split('\n')[1:]:  # Skip header
                parts = line.strip().split()
                if parts:
                    lsmod_modules.add(parts[0])
            
            # Compare the two sets
            for module in proc_modules - lsmod_modules:
                hidden_modules.append({
                    "name": module,
                    "detection_method": "proc_modules_vs_lsmod",
                    "description": "Module present in /proc/modules but not in lsmod output"
                })
                
            for module in lsmod_modules - proc_modules:
                hidden_modules.append({
                    "name": module,
                    "detection_method": "lsmod_vs_proc_modules",
                    "description": "Module present in lsmod output but not in /proc/modules"
                })
            
            # Method 2: Look for suspicious syscall hooks
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            cursor.execute(
                "SELECT syscall_name, module_name FROM syscall_table WHERE is_hooked = 1"
            )
            
            for row in cursor.fetchall():
                syscall = row[0]
                module = row[1]
                
                if module and module not in lsmod_modules and module not in proc_modules:
                    hidden_modules.append({
                        "name": module,
                        "detection_method": "syscall_hook",
                        "description": f"Module hooked syscall {syscall} but is not visible in module lists"
                    })
            
            conn.close()
            
            # Method 3: Check for common rootkit signatures in memory
            # This is a bit more invasive and might not work on all systems
            try:
                # Use strings on /dev/kmem if available (requires root privileges)
                if os.path.exists('/dev/kmem') and os.access('/dev/kmem', os.R_OK):
                    kmem_output = subprocess.run(['strings', '/dev/kmem'], stdout=subprocess.PIPE, 
                                              stderr=subprocess.PIPE, text=True, timeout=10).stdout
                    
                    # Look for known rootkit strings
                    for line in kmem_output.split('\n'):
                        for rootkit in self.config["known_rootkits"]:
                            if rootkit in line and rootkit not in lsmod_modules and rootkit not in proc_modules:
                                hidden_modules.append({
                                    "name": rootkit,
                                    "detection_method": "memory_strings",
                                    "description": f"Rootkit signature found in kernel memory: {line}"
                                })
            except Exception:
                # This method might fail for many reasons, just skip it
                pass
                
            return hidden_modules
            
        except Exception as e:
            self.logger.error(f"Error detecting hidden modules: {e}")
            return hidden_modules
    
    def check_for_rootkit_behavior(self):
        """
        Check for common rootkit behaviors
        
        Returns:
            dict: Results of rootkit behavior checks
        """
        results = {
            "syscall_hooks": [],
            "hidden_modules": [],
            "hidden_processes": [],
            "suspicious_modules": []
        }
        
        # Check for hooked syscalls
        results["syscall_hooks"] = self.get_hooked_syscalls()
        
        # Check for hidden modules
        results["hidden_modules"] = self.get_hidden_modules()
        
        # Check for suspicious modules
        results["suspicious_modules"] = self.get_suspicious_modules()
        
        # Check for hidden processes (simple check)
        try:
            # Compare process listing from different sources
            ps_output = subprocess.run(['ps', 'aux'], stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE, text=True).stdout
            
            proc_pids = []
            ps_pids = []
            
            # Get PIDs from /proc
            for entry in os.listdir('/proc'):
                if entry.isdigit():
                    proc_pids.append(entry)
            
            # Get PIDs from ps output
            for line in ps_output.strip().split('\n')[1:]:  # Skip header
                parts = line.strip().split()
                if len(parts) > 1 and parts[1].isdigit():
                    ps_pids.append(parts[1])
            
            # Compare the two sets
            proc_pids_set = set(proc_pids)
            ps_pids_set = set(ps_pids)
            
            for pid in proc_pids_set - ps_pids_set:
                # Process in /proc but not in ps output
                process_name = "unknown"
                try:
                    with open(f'/proc/{pid}/comm', 'r') as f:
                        process_name = f.read().strip()
                except:
                    pass
                    
                results["hidden_processes"].append({
                    "pid": pid,
                    "name": process_name,
                    "detection_method": "proc_vs_ps",
                    "description": "Process visible in /proc but not in ps output"
                })
                
        except Exception as e:
            self.logger.error(f"Error checking for hidden processes: {e}")
        
        # Determine overall threat level
        threat_level = "low"
        if results["syscall_hooks"] or results["hidden_modules"]:
            threat_level = "critical"
        elif results["hidden_processes"]:
            threat_level = "high"
        elif results["suspicious_modules"]:
            threat_level = "medium"
            
        results["threat_level"] = threat_level
        results["timestamp"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        return results
    
    def get_statistics(self):
        """
        Get statistics about the kernel module monitoring system
        
        Returns:
            dict: Statistics
        """
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        # Total modules monitored
        cursor.execute("SELECT COUNT(*) FROM kernel_modules")
        total_modules = cursor.fetchone()[0]
        
        # Currently loaded modules
        cursor.execute("SELECT COUNT(*) FROM kernel_modules WHERE loaded = 1")
        loaded_modules = cursor.fetchone()[0]
        
        # Suspicious modules
        cursor.execute("SELECT COUNT(*) FROM kernel_modules WHERE is_suspicious = 1")
        suspicious_modules = cursor.fetchone()[0]
        
        # Recent changes (last 24 hours)
        cursor.execute("SELECT COUNT(*) FROM module_changes WHERE timestamp > ?", 
                     (time.time() - 86400,))
        recent_changes = cursor.fetchone()[0]
        
        # Unverified changes
        cursor.execute("SELECT COUNT(*) FROM module_changes WHERE verified = 0")
        unverified_changes = cursor.fetchone()[0]
        
        # Hooked syscalls
        cursor.execute("SELECT COUNT(*) FROM syscall_table WHERE is_hooked = 1")
        hooked_syscalls = cursor.fetchone()[0]
        
        # Change types breakdown
        cursor.execute("""
        SELECT 
            SUM(CASE WHEN change_type = 'added' THEN 1 ELSE 0 END) as added,
            SUM(CASE WHEN change_type = 'unloaded' THEN 1 ELSE 0 END) as unloaded,
            SUM(CASE WHEN change_type LIKE '%size%' THEN 1 ELSE 0 END) as size,
            SUM(CASE WHEN change_type LIKE '%hash%' THEN 1 ELSE 0 END) as hash,
            SUM(CASE WHEN change_type LIKE '%refcount%' THEN 1 ELSE 0 END) as refcount
        FROM module_changes
        WHERE timestamp > ?
        """, (time.time() - 604800,))  # Last 7 days
        
        row = cursor.fetchone()
        change_types = {
            "added": row[0] or 0,
            "unloaded": row[1] or 0,
            "size": row[2] or 0,
            "hash": row[3] or 0,
            "refcount": row[4] or 0
        }
        
        conn.close()
        
        # Get kernel version
        kernel_version = subprocess.run(['uname', '-r'], stdout=subprocess.PIPE, 
                                      stderr=subprocess.PIPE, text=True).stdout.strip()
        
        return {
            "total_modules_monitored": total_modules,
            "loaded_modules": loaded_modules,
            "suspicious_modules": suspicious_modules,
            "recent_changes": recent_changes,
            "unverified_changes": unverified_changes,
            "hooked_syscalls": hooked_syscalls,
            "change_types_last_7_days": change_types,
            "kernel_version": kernel_version,
            "database_path": self.database_path,
            "last_updated": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
    
    def run_scan(self):
        """
        Run a full kernel module scan and return the results
        
        Returns:
            dict: Scan results
        """
        start_time = time.time()
        
        # Check module integrity
        changes = self.check_integrity()
        
        # Check for rootkit behavior
        rootkit_check = self.check_for_rootkit_behavior()
        
        scan_time = time.time() - start_time
        
        # Get statistics
        stats = self.get_statistics()
        
        # Determine overall threat level
        threat_level = rootkit_check["threat_level"]
        
        return {
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "scan_time_seconds": scan_time,
            "total_changes": len(changes),
            "threat_level": threat_level,
            "module_changes": changes,
            "rootkit_detection": rootkit_check,
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
                    self.logger.info("Running scheduled kernel module scan")
                    scan_results = self.run_scan()
                    
                    # Log results
                    self.logger.info(f"Scan completed. Threat level: {scan_results['threat_level']}, "
                                   f"Changes detected: {scan_results['total_changes']}")
                    
                    # Alert for high threat level
                    if scan_results["threat_level"] in ["medium", "high", "critical"]:
                        self.logger.warning(f"Elevated threat level detected: {scan_results['threat_level']}")
                        
                        # Log critical details
                        if scan_results["rootkit_detection"]["syscall_hooks"]:
                            self.logger.warning(f"Syscall hooks detected: {len(scan_results['rootkit_detection']['syscall_hooks'])}")
                            
                        if scan_results["rootkit_detection"]["hidden_modules"]:
                            self.logger.warning(f"Hidden modules detected: {len(scan_results['rootkit_detection']['hidden_modules'])}")
                            
                        if scan_results["rootkit_detection"]["hidden_processes"]:
                            self.logger.warning(f"Hidden processes detected: {len(scan_results['rootkit_detection']['hidden_processes'])}")
                            
                        if scan_results["rootkit_detection"]["suspicious_modules"]:
                            self.logger.warning(f"Suspicious modules detected: {len(scan_results['rootkit_detection']['suspicious_modules'])}")
                    
                except Exception as e:
                    self.logger.error(f"Error in monitoring thread: {e}")
                
                # Sleep until next scan
                time.sleep(interval)
        
        # Start the thread
        monitor_thread = threading.Thread(target=monitoring_thread, daemon=True)
        monitor_thread.start()
        
        return True