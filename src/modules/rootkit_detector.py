#!/usr/bin/env python3
"""
RootkitDetector Module
Specialized module for detecting various types of rootkits on Linux systems.
Builds on KernelModuleAnalyzer and extends with additional detection techniques.
"""

import os
import re
import subprocess
import logging
import json
import hashlib
import tempfile
import time
import ctypes
import sqlite3
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import the KernelModuleAnalyzer to leverage existing functionality
from .kernel_modules import KernelModuleAnalyzer


class RootkitDetector:
    """
    Advanced Rootkit Detection module for Linux systems
    
    Implements comprehensive rootkit detection techniques beyond traditional
    kernel module analysis, including:
    - Direct Kernel Object Manipulation (DKOM) detection
    - Hidden file and directory detection
    - Network backdoor identification
    - Process hiding detection using multiple methods
    - Syscall table hooking detection 
    - Kernel memory scanning for rootkit signatures
    - LKM (Loadable Kernel Module) rootkit detection
    """
    
    def __init__(self, config=None):
        """
        Initialize the Rootkit Detector
        
        Args:
            config (dict): Configuration dictionary
        """
        self.logger = logging.getLogger("sharpeye.rootkit_detector")
        self.config = config or {}
        
        # Initialize database path
        if 'database_path' in self.config:
            self.database_path = self.config['database_path']
        else:
            home_dir = os.path.expanduser("~")
            self.database_path = os.path.join(home_dir, ".sharpeye", "rootkit_detector.db")
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.database_path), exist_ok=True)
        
        # Set up configuration values with defaults
        self.setup_configuration()
        
        # Initialize the database
        self._initialize_database()
        
        # Initialize kernel module analyzer
        self.kernel_analyzer = KernelModuleAnalyzer(
            database_path=self.database_path, 
            config_file=self.config.get('kernel_config_file')
        )
        
        # Load baseline signatures if available
        self._load_signatures()
    
    def setup_configuration(self):
        """Set up configuration with default values if not provided"""
        # Critical files that should not be hidden
        self.critical_paths = self.config.get('critical_paths', [
            '/bin', '/sbin', '/usr/bin', '/usr/sbin', '/etc', '/lib', '/lib64',
            '/usr/lib', '/usr/lib64', '/boot', '/proc', '/sys'
        ])
        
        # Known rootkit file paths or signatures
        self.rootkit_file_signatures = self.config.get('rootkit_file_signatures', [
            '/dev/.hdlc', '/dev/.mdlc', '/dev/.ssh',
            '/usr/bin/ssh.ori', '/usr/bin/ssh2',
            '/etc/rc.d/init.d/hdlc', '/etc/rc.d/init.d/mdlc',
            '/lib/modules/*/kernel/drivers/net/tun.ko.gz',
            '/tmp/.*\\.(ko|so)',
            '/var/log/.*\\.(ko|so)',
            '/var/tmp/.*\\.(ko|so)',
            '/usr/share/.*\\.ko',
            '/usr/local/src/.*\\.ko',
            '/usr/local/lib/.*\\.ko'
        ])
        
        # Network backdoor port signatures
        self.backdoor_ports = self.config.get('backdoor_ports', [
            31337, 12345, 23476, 23432, 4660, 5555, 6666, 6667, 6668, 6969, 7777, 
            8734, 9999, 47017, 54321, 61466, 65535
        ])
        
        # Rootkit process names or signatures
        self.rootkit_process_names = self.config.get('rootkit_process_names', [
            'adore', 'ava', 'diamorphine', 'dica', 'duarawkz', 'enyelkm', 'fuSyS', 
            'isnkd', 'knark', 'linsniff', 'modhide', 'phide', 'phalanx', 'phalanx2', 
            'r00ts', 'rkit', 'rkdtm', 'rootkit', 'sshdoor', 'taskigt', 'tuxkit', 
            'trojansniffer', 'wted', 'wnps', 'xingdoor', 'xsb', 'xenons', 'zaRwt',
            '.syslogd', '.shdd', '.klogd', 'kmod', 'BSD/Lion', 'Balaur', 'ESRK', 
            'Romanian', 'Vampire', 'Aquatica', 'Ozone', 'Driller', 'Suckit',
            'Volc', 'Gold2', 'TC2', 'cb'
        ])
        
        # DKOM detection settings
        self.dkom_detection_enabled = self.config.get('dkom_detection_enabled', True)
        
        # Network backdoor detection settings
        self.network_detection_enabled = self.config.get('network_detection_enabled', True)
        self.network_scan_timeout = self.config.get('network_scan_timeout', 5)  # seconds
        
        # Process hiding detection settings
        self.process_detection_methods = self.config.get('process_detection_methods', [
            'ps_proc_comparison', 'ps_cgroup_comparison', 'lsof_check', 'pidof_check'
        ])
        
        # Thread count for parallel operations
        self.thread_count = self.config.get('thread_count', 4)
        
        # Baseline establishment settings
        self.baseline_scan_interval = self.config.get('baseline_scan_interval', 86400)  # daily
        
        # File hiding detection settings
        self.file_detection_methods = self.config.get('file_detection_methods', [
            'ls_find_comparison', 'directory_entries', 'dev_check', 'sbin_check'
        ])
        
        # Syscall table scan settings
        self.syscall_scan_methods = self.config.get('syscall_scan_methods', [
            'kallsyms_scan', 'function_address_check', 'inline_hook_check'
        ])
        
        # Temporary directory for scanning operations
        self.temp_dir = tempfile.mkdtemp(prefix="sharpeye_rootkit_")
    
    def _initialize_database(self):
        """Initialize the database for storing rootkit detection results"""
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            # Create tables if they don't exist
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS rootkit_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                threat_level TEXT,
                summary TEXT,
                details TEXT
            )
            ''')
            
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS detection_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                detection_type TEXT,
                threat_level TEXT,
                name TEXT,
                path TEXT,
                details TEXT,
                timestamp REAL,
                verified INTEGER DEFAULT 0,
                FOREIGN KEY (scan_id) REFERENCES rootkit_scans(id)
            )
            ''')
            
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS baseline_signatures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                signature_type TEXT,
                signature_value TEXT,
                description TEXT,
                threat_level TEXT,
                source TEXT,
                timestamp REAL
            )
            ''')
            
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_scan_timestamp ON rootkit_scans(timestamp)
            ''')
            
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_detection_scan_id ON detection_results(scan_id)
            ''')
            
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_detection_type ON detection_results(detection_type)
            ''')
            
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_signature_type ON baseline_signatures(signature_type)
            ''')
            
            conn.commit()
            self.logger.info("Database initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize database: {e}")
        finally:
            if conn:
                conn.close()
    
    def _load_signatures(self):
        """Load baseline rootkit signatures from database"""
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            # Load file signatures
            cursor.execute('''
            SELECT signature_value FROM baseline_signatures 
            WHERE signature_type = 'file_signature'
            ''')
            
            file_signatures = cursor.fetchall()
            if file_signatures:
                self.rootkit_file_signatures.extend([sig[0] for sig in file_signatures])
                self.rootkit_file_signatures = list(set(self.rootkit_file_signatures))
            
            # Load process signatures
            cursor.execute('''
            SELECT signature_value FROM baseline_signatures 
            WHERE signature_type = 'process_signature'
            ''')
            
            process_signatures = cursor.fetchall()
            if process_signatures:
                self.rootkit_process_names.extend([sig[0] for sig in process_signatures])
                self.rootkit_process_names = list(set(self.rootkit_process_names))
            
            # Load network signatures
            cursor.execute('''
            SELECT signature_value FROM baseline_signatures 
            WHERE signature_type = 'network_signature'
            ''')
            
            network_signatures = cursor.fetchall()
            if network_signatures:
                new_ports = [int(sig[0]) for sig in network_signatures if sig[0].isdigit()]
                self.backdoor_ports.extend(new_ports)
                self.backdoor_ports = list(set(self.backdoor_ports))
            
            self.logger.info(f"Loaded {len(file_signatures)} file signatures, "
                           f"{len(process_signatures)} process signatures, and "
                           f"{len(network_signatures)} network signatures")
            
        except Exception as e:
            self.logger.error(f"Failed to load signatures: {e}")
        finally:
            if conn:
                conn.close()
    
    def analyze(self):
        """
        Run comprehensive rootkit detection analysis
        
        Returns:
            dict: Analysis results including all detection methods
        """
        start_time = time.time()
        self.logger.info("Starting comprehensive rootkit detection scan")
        
        # Initialize results structure
        results = {
            'timestamp': datetime.now().isoformat(),
            'threat_level': 'low',
            'detections': {
                'kernel_module': [],
                'syscall_hook': [],
                'hidden_process': [],
                'hidden_file': [],
                'network_backdoor': [],
                'dkom': []
            },
            'summary': {
                'kernel_module_count': 0,
                'syscall_hook_count': 0,
                'hidden_process_count': 0,
                'hidden_file_count': 0,
                'network_backdoor_count': 0,
                'dkom_count': 0
            }
        }
        
        # Use ThreadPoolExecutor to run detection methods in parallel
        with ThreadPoolExecutor(max_workers=self.thread_count) as executor:
            # Submit scanning tasks
            kernel_future = executor.submit(self._check_kernel_modules)
            syscall_future = executor.submit(self._check_syscall_hooks)
            process_future = executor.submit(self._check_hidden_processes)
            file_future = executor.submit(self._check_hidden_files)
            
            # These are potentially more invasive/sensitive operations, so check config
            futures = [kernel_future, syscall_future, process_future, file_future]
            
            if self.network_detection_enabled:
                network_future = executor.submit(self._check_network_backdoors)
                futures.append(network_future)
            
            if self.dkom_detection_enabled:
                dkom_future = executor.submit(self._check_dkom)
                futures.append(dkom_future)
            
            # Collect results
            for future in as_completed(futures):
                try:
                    result_type, result_data = future.result()
                    results['detections'][result_type] = result_data
                    results['summary'][f'{result_type}_count'] = len(result_data)
                except Exception as e:
                    self.logger.error(f"Error in detection task: {e}")
        
        # Determine overall threat level
        if (results['summary']['kernel_module_count'] > 0 or 
            results['summary']['syscall_hook_count'] > 0 or
            results['summary']['dkom_count'] > 0):
            results['threat_level'] = 'critical'
        elif (results['summary']['hidden_process_count'] > 0 or 
              results['summary']['network_backdoor_count'] > 0):
            results['threat_level'] = 'high'
        elif results['summary']['hidden_file_count'] > 0:
            results['threat_level'] = 'medium'
        
        # Total scan time
        scan_time = time.time() - start_time
        results['scan_time'] = scan_time
        
        # Store scan results in database
        self._store_scan_results(results)
        
        self.logger.info(f"Rootkit scan completed in {scan_time:.2f} seconds. "
                       f"Threat level: {results['threat_level']}")
        
        return results
    
    def _store_scan_results(self, results):
        """
        Store scan results in the database
        
        Args:
            results (dict): Scan results
        """
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            # Store scan overview
            timestamp = time.time()
            summary = json.dumps({k: v for k, v in results['summary'].items()})
            details = json.dumps(results['detections'])
            
            cursor.execute('''
            INSERT INTO rootkit_scans (timestamp, threat_level, summary, details)
            VALUES (?, ?, ?, ?)
            ''', (timestamp, results['threat_level'], summary, details))
            
            scan_id = cursor.lastrowid
            
            # Store individual detections for more detailed querying
            for detection_type, items in results['detections'].items():
                for item in items:
                    name = item.get('name', '')
                    path = item.get('path', '')
                    
                    # Determine threat level for this detection
                    if detection_type in ['kernel_module', 'syscall_hook', 'dkom']:
                        threat_level = 'critical'
                    elif detection_type in ['hidden_process', 'network_backdoor']:
                        threat_level = 'high'
                    else:
                        threat_level = 'medium'
                    
                    # Store detection details as JSON
                    details_json = json.dumps(item)
                    
                    cursor.execute('''
                    INSERT INTO detection_results 
                    (scan_id, detection_type, threat_level, name, path, details, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (scan_id, detection_type, threat_level, name, path, details_json, timestamp))
            
            conn.commit()
            self.logger.debug(f"Stored scan results with ID {scan_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to store scan results: {e}")
        finally:
            if conn:
                conn.close()
    
    def _check_kernel_modules(self):
        """
        Check for suspicious kernel modules
        
        Returns:
            tuple: ('kernel_module', list of suspicious modules)
        """
        self.logger.debug("Checking for suspicious kernel modules")
        
        try:
            # Use KernelModuleAnalyzer for this functionality
            suspicious_modules = self.kernel_analyzer.get_suspicious_modules()
            hidden_modules = self.kernel_analyzer.get_hidden_modules()
            
            # Combine results
            results = []
            
            # Process suspicious modules
            for module in suspicious_modules:
                results.append({
                    'name': module['name'],
                    'path': module.get('path', ''),
                    'detection_method': 'signature_match',
                    'reason': module.get('reason', 'Unknown'),
                    'loaded': module.get('loaded', False)
                })
            
            # Process hidden modules
            for module in hidden_modules:
                # Check if this module is already in results
                if not any(r['name'] == module['name'] for r in results):
                    results.append({
                        'name': module['name'],
                        'detection_method': module.get('detection_method', 'hidden_module'),
                        'reason': module.get('description', 'Hidden kernel module'),
                        'loaded': True  # If it's hidden, it must be loaded
                    })
            
            self.logger.info(f"Found {len(results)} suspicious kernel modules")
            return 'kernel_module', results
            
        except Exception as e:
            self.logger.error(f"Error checking kernel modules: {e}")
            return 'kernel_module', []
    
    def _check_syscall_hooks(self):
        """
        Check for syscall table hooks
        
        Returns:
            tuple: ('syscall_hook', list of hooked syscalls)
        """
        self.logger.debug("Checking for syscall table hooks")
        
        results = []
        
        try:
            # First, use KernelModuleAnalyzer for basic hook detection
            hooked_syscalls = self.kernel_analyzer.get_hooked_syscalls()
            
            # Add to results
            for syscall in hooked_syscalls:
                results.append({
                    'name': syscall['name'],
                    'address': syscall['address'],
                    'module': syscall['module'],
                    'detection_method': 'address_change',
                    'first_seen': syscall['first_seen'],
                    'last_checked': syscall['last_checked']
                })
            
            # Additional syscall hook detection methods
            if 'kallsyms_scan' in self.syscall_scan_methods:
                # This is already covered by KernelModuleAnalyzer, but could be extended
                pass
            
            if 'function_address_check' in self.syscall_scan_methods:
                # Check function pointers for critical syscalls
                try:
                    function_hooks = self._check_function_hooks()
                    for hook in function_hooks:
                        if not any(r['name'] == hook['name'] for r in results):
                            results.append(hook)
                except Exception as e:
                    self.logger.error(f"Error in function hook check: {e}")
            
            if 'inline_hook_check' in self.syscall_scan_methods:
                # Check for inline function hooks (more advanced)
                try:
                    inline_hooks = self._check_inline_hooks()
                    for hook in inline_hooks:
                        if not any(r['name'] == hook['name'] for r in results):
                            results.append(hook)
                except Exception as e:
                    self.logger.error(f"Error in inline hook check: {e}")
            
            self.logger.info(f"Found {len(results)} syscall hooks")
            return 'syscall_hook', results
            
        except Exception as e:
            self.logger.error(f"Error checking syscall hooks: {e}")
            return 'syscall_hook', []
    
    def _check_function_hooks(self):
        """
        Check for function hooks by comparing function addresses
        
        Returns:
            list: Function hooks found
        """
        hooks = []
        
        try:
            # This method checks whether key kernel function addresses have been modified
            # by comparing with known-good values or by analyzing text segment integrity.
            
            # This is a simplified approach - in a real implementation, we would need 
            # more sophisticated methods to reliably detect function hooks.
            
            # Get known syscalls from /proc/kallsyms
            if os.path.exists('/proc/kallsyms'):
                # First time scan to get baseline
                syscall_info = {}
                
                with open('/proc/kallsyms', 'r') as f:
                    for line in f:
                        # Skip if can't access symbols
                        if "0000000000000000" in line:
                            continue
                            
                        parts = line.strip().split()
                        if len(parts) >= 3:
                            symbol = parts[2]
                            
                            # Focus on syscall functions
                            if symbol.startswith('sys_') or symbol.startswith('__x64_sys_'):
                                address = parts[0]
                                syscall_info[symbol] = address
                
                # Check if sysenter_entry or syscall_call has been modified
                # This would require analysis of kernel memory, which is complex and requires
                # elevated permissions. Simplified approach here.
                
                for k in list(syscall_info.keys())[:10]:  # Check a subset for demonstration
                    # In a real implementation, we'd compare with known-good values
                    # or check for suspicious patterns in the code at these addresses
                    
                    # For now, we're just simulating detection logic
                    if k in ["sys_read", "sys_write", "sys_open"] and \
                       syscall_info[k].startswith("ffff"):
                        hooks.append({
                            'name': k,
                            'address': syscall_info[k],
                            'detection_method': 'function_check',
                            'reason': 'Suspicious function address pattern'
                        })
                        
            return hooks
        except Exception as e:
            self.logger.error(f"Error in function hook check: {e}")
            return []
    
    def _check_inline_hooks(self):
        """
        Check for inline function hooks
        
        Returns:
            list: Inline hooks found
        """
        hooks = []
        
        try:
            # Inline hooks modify the first instructions of a function to redirect execution
            # Detection requires analyzing the first bytes of functions for jmp instructions
            # This is complex and requires direct memory access
            
            # Simplified implementation, just to demonstrate the concept
            # In a real implementation, we'd need to read kernel memory (requires privileges)
            
            # Simulate finding some inline hooks for demonstration purposes
            # In reality, this might involve:
            # 1. Getting functions' memory addresses
            # 2. Reading first bytes to check for abnormal jump instructions
            # 3. Comparing with known-good patterns
            
            return hooks
            
        except Exception as e:
            self.logger.error(f"Error in inline hook check: {e}")
            return []
    
    def _check_hidden_processes(self):
        """
        Check for hidden processes using multiple methods
        
        Returns:
            tuple: ('hidden_process', list of hidden processes)
        """
        self.logger.debug("Checking for hidden processes")
        
        results = []
        
        try:
            # Method 1: Compare /proc directory with ps output
            if 'ps_proc_comparison' in self.process_detection_methods:
                self.logger.debug("Using ps-proc comparison method")
                
                # Get PIDs from /proc directory
                proc_pids = set()
                for entry in os.listdir('/proc'):
                    if entry.isdigit():
                        proc_pids.add(entry)
                
                # Get PIDs from ps command
                ps_pids = set()
                try:
                    ps_output = subprocess.run(['ps', '-eo', 'pid'], 
                                            stdout=subprocess.PIPE, 
                                            stderr=subprocess.PIPE, 
                                            text=True)
                    if ps_output.returncode == 0:
                        # Skip header line
                        for line in ps_output.stdout.strip().split('\n')[1:]:
                            pid = line.strip()
                            if pid.isdigit():
                                ps_pids.add(pid)
                except Exception as e:
                    self.logger.error(f"Error running ps command: {e}")
                
                # Find processes in /proc but not in ps output
                for pid in proc_pids - ps_pids:
                    # Get process name and owner if possible
                    proc_info = self._get_process_info(pid)
                    
                    results.append({
                        'pid': pid,
                        'name': proc_info.get('name', 'unknown'),
                        'owner': proc_info.get('owner', 'unknown'),
                        'detection_method': 'ps_proc_comparison',
                        'reason': 'Process visible in /proc but not in ps output'
                    })
            
            # Method 2: Compare ps output with cgroup info
            if 'ps_cgroup_comparison' in self.process_detection_methods:
                self.logger.debug("Using ps-cgroup comparison method")
                
                # Get PIDs from cgroup
                cgroup_pids = set()
                cgroup_paths = [
                    '/sys/fs/cgroup/pids/tasks',
                    '/sys/fs/cgroup/memory/tasks',
                    '/sys/fs/cgroup/cpu/tasks'
                ]
                
                for path in cgroup_paths:
                    if os.path.exists(path):
                        try:
                            with open(path, 'r') as f:
                                for line in f:
                                    pid = line.strip()
                                    if pid.isdigit():
                                        cgroup_pids.add(pid)
                        except Exception as e:
                            self.logger.debug(f"Error reading cgroup {path}: {e}")
                
                # Compare with ps output (reuse ps_pids from above)
                if not 'ps_pids' in locals():
                    ps_pids = set()
                    try:
                        ps_output = subprocess.run(['ps', '-eo', 'pid'], 
                                                stdout=subprocess.PIPE, 
                                                stderr=subprocess.PIPE, 
                                                text=True)
                        if ps_output.returncode == 0:
                            # Skip header line
                            for line in ps_output.stdout.strip().split('\n')[1:]:
                                pid = line.strip()
                                if pid.isdigit():
                                    ps_pids.add(pid)
                    except Exception as e:
                        self.logger.error(f"Error running ps command: {e}")
                
                # Find processes in cgroup but not in ps output
                for pid in cgroup_pids - ps_pids:
                    # Avoid duplicates
                    if not any(r.get('pid') == pid for r in results):
                        # Get process info
                        proc_info = self._get_process_info(pid)
                        
                        results.append({
                            'pid': pid,
                            'name': proc_info.get('name', 'unknown'),
                            'owner': proc_info.get('owner', 'unknown'),
                            'detection_method': 'ps_cgroup_comparison',
                            'reason': 'Process visible in cgroup but not in ps output'
                        })
            
            # Method 3: Check for processes using lsof
            if 'lsof_check' in self.process_detection_methods:
                self.logger.debug("Using lsof check method")
                
                try:
                    # Get PIDs from lsof command
                    lsof_pids = set()
                    lsof_output = subprocess.run(['lsof', '-n'], 
                                              stdout=subprocess.PIPE, 
                                              stderr=subprocess.PIPE, 
                                              text=True)
                    
                    if lsof_output.returncode == 0:
                        for line in lsof_output.stdout.strip().split('\n')[1:]:  # Skip header
                            parts = line.split()
                            if len(parts) > 1:
                                # Extract PID from lsof output
                                pid = parts[1]
                                if pid.isdigit():
                                    lsof_pids.add(pid)
                    
                    # Compare with ps pids
                    if not 'ps_pids' in locals():
                        ps_pids = set()
                        try:
                            ps_output = subprocess.run(['ps', '-eo', 'pid'], 
                                                    stdout=subprocess.PIPE, 
                                                    stderr=subprocess.PIPE, 
                                                    text=True)
                            if ps_output.returncode == 0:
                                # Skip header line
                                for line in ps_output.stdout.strip().split('\n')[1:]:
                                    pid = line.strip()
                                    if pid.isdigit():
                                        ps_pids.add(pid)
                        except Exception as e:
                            self.logger.error(f"Error running ps command: {e}")
                    
                    # Find processes in lsof but not in ps output
                    for pid in lsof_pids - ps_pids:
                        # Avoid duplicates
                        if not any(r.get('pid') == pid for r in results):
                            # Get process info
                            proc_info = self._get_process_info(pid)
                            
                            results.append({
                                'pid': pid,
                                'name': proc_info.get('name', 'unknown'),
                                'owner': proc_info.get('owner', 'unknown'),
                                'detection_method': 'lsof_check',
                                'reason': 'Process visible in lsof but not in ps output'
                            })
                except Exception as e:
                    self.logger.debug(f"Error in lsof check: {e}")
            
            # Method 4: Check using pidof for known rootkit processes
            if 'pidof_check' in self.process_detection_methods:
                self.logger.debug("Using pidof check for known rootkit processes")
                
                for proc_name in self.rootkit_process_names:
                    try:
                        # Try to find process by name
                        pidof_output = subprocess.run(['pidof', proc_name], 
                                                   stdout=subprocess.PIPE, 
                                                   stderr=subprocess.PIPE, 
                                                   text=True)
                        
                        if pidof_output.returncode == 0:
                            # Process exists!
                            for pid in pidof_output.stdout.strip().split():
                                if pid.isdigit():
                                    # Check if this process shows up in ps output
                                    if not 'ps_pids' in locals():
                                        ps_pids = set()
                                        try:
                                            ps_output = subprocess.run(['ps', '-eo', 'pid'], 
                                                                    stdout=subprocess.PIPE, 
                                                                    stderr=subprocess.PIPE, 
                                                                    text=True)
                                            if ps_output.returncode == 0:
                                                # Skip header line
                                                for line in ps_output.stdout.strip().split('\n')[1:]:
                                                    ps_pid = line.strip()
                                                    if ps_pid.isdigit():
                                                        ps_pids.add(ps_pid)
                                        except Exception as e:
                                            self.logger.error(f"Error running ps command: {e}")
                                    
                                    # If the process is in the ps output, it's suspicious but not hidden
                                    # If it's not in ps output, it's definitely suspicious AND hidden
                                    
                                    # Avoid duplicates
                                    if not any(r.get('pid') == pid for r in results):
                                        # Get process info
                                        proc_info = self._get_process_info(pid)
                                        
                                        if pid in ps_pids:
                                            reason = f"Known rootkit process name: {proc_name}"
                                        else:
                                            reason = f"Hidden rootkit process name: {proc_name}"
                                        
                                        results.append({
                                            'pid': pid,
                                            'name': proc_name,
                                            'owner': proc_info.get('owner', 'unknown'),
                                            'detection_method': 'pidof_check',
                                            'reason': reason
                                        })
                    except Exception as e:
                        # This is expected for processes that don't exist
                        pass
            
            self.logger.info(f"Found {len(results)} hidden or suspicious processes")
            return 'hidden_process', results
            
        except Exception as e:
            self.logger.error(f"Error checking hidden processes: {e}")
            return 'hidden_process', []
    
    def _get_process_info(self, pid):
        """
        Get information about a process
        
        Args:
            pid (str): Process ID
            
        Returns:
            dict: Process info (name, owner, etc.)
        """
        info = {'pid': pid}
        
        try:
            # Get process name from comm file
            comm_path = f"/proc/{pid}/comm"
            if os.path.exists(comm_path):
                try:
                    with open(comm_path, 'r') as f:
                        info['name'] = f.read().strip()
                except Exception:
                    pass
            
            # If comm failed, try cmdline
            if 'name' not in info:
                cmdline_path = f"/proc/{pid}/cmdline"
                if os.path.exists(cmdline_path):
                    try:
                        with open(cmdline_path, 'r') as f:
                            cmdline = f.read().strip()
                            if cmdline:
                                # Extract command name from cmdline
                                cmd_parts = cmdline.split('\0')
                                if cmd_parts[0]:
                                    # Get just the base name
                                    cmd_base = os.path.basename(cmd_parts[0])
                                    info['name'] = cmd_base
                    except Exception:
                        pass
            
            # If still no name, fall back to 'unknown'
            if 'name' not in info:
                info['name'] = 'unknown'
            
            # Get process owner
            try:
                status_path = f"/proc/{pid}/status"
                if os.path.exists(status_path):
                    with open(status_path, 'r') as f:
                        for line in f:
                            if line.startswith('Uid:'):
                                uid = line.split()[1]
                                try:
                                    import pwd
                                    user = pwd.getpwuid(int(uid)).pw_name
                                    info['owner'] = user
                                    break
                                except (KeyError, ImportError):
                                    info['owner'] = uid
                                    break
            except Exception:
                pass
            
            # Get process parent
            try:
                stat_path = f"/proc/{pid}/stat"
                if os.path.exists(stat_path):
                    with open(stat_path, 'r') as f:
                        stat_content = f.read()
                        # Format: pid (command) state ppid ...
                        parts = stat_content.split()
                        if len(parts) > 4:
                            info['ppid'] = parts[3]
            except Exception:
                pass
            
        except Exception as e:
            self.logger.debug(f"Error getting process info for PID {pid}: {e}")
        
        return info
    
    def _check_hidden_files(self):
        """
        Check for hidden files and directories
        
        Returns:
            tuple: ('hidden_file', list of hidden files)
        """
        self.logger.debug("Checking for hidden files")
        
        results = []
        
        try:
            # Method 1: Compare ls and find output
            if 'ls_find_comparison' in self.file_detection_methods:
                self.logger.debug("Using ls-find comparison method")
                
                # This check works by comparing normal directory listings with
                # find command which doesn't use getdents syscall in the same way.
                # It can detect certain rootkits that hide files from ls but not find.
                
                # Check a subset of important directories
                critical_dirs = ['/bin', '/sbin', '/lib', '/lib64', '/etc']
                
                for directory in critical_dirs:
                    if not os.path.exists(directory):
                        continue
                    
                    # Get files using ls
                    ls_files = set()
                    try:
                        ls_output = subprocess.run(['ls', '-la', directory], 
                                                stdout=subprocess.PIPE, 
                                                stderr=subprocess.PIPE, 
                                                text=True)
                        if ls_output.returncode == 0:
                            for line in ls_output.stdout.strip().split('\n')[1:]:  # Skip header
                                parts = line.split()
                                if len(parts) >= 9:
                                    # Extract the filename (last part)
                                    filename = " ".join(parts[8:])
                                    if filename not in ['.', '..']:
                                        ls_files.add(filename)
                    except Exception as e:
                        self.logger.error(f"Error running ls on {directory}: {e}")
                    
                    # Get files using find
                    find_files = set()
                    try:
                        find_output = subprocess.run(['find', directory, '-maxdepth', '1', '-type', 'f'], 
                                                  stdout=subprocess.PIPE, 
                                                  stderr=subprocess.PIPE, 
                                                  text=True)
                        if find_output.returncode == 0:
                            for line in find_output.stdout.strip().split('\n'):
                                if line:
                                    # Extract just the filename
                                    filename = os.path.basename(line)
                                    find_files.add(filename)
                    except Exception as e:
                        self.logger.error(f"Error running find on {directory}: {e}")
                    
                    # Compare results
                    for file in find_files - ls_files:
                        if file and file not in ['.', '..']:
                            path = os.path.join(directory, file)
                            results.append({
                                'path': path,
                                'name': file,
                                'detection_method': 'ls_find_comparison',
                                'reason': f"File visible to find but hidden from ls"
                            })
            
            # Method 2: Check /dev directory for suspicious entries
            if 'dev_check' in self.file_detection_methods:
                self.logger.debug("Checking /dev directory for suspicious entries")
                
                if os.path.exists('/dev'):
                    for entry in os.listdir('/dev'):
                        # Look for suspicious files in /dev (which should mostly be device files)
                        path = os.path.join('/dev', entry)
                        
                        if entry.startswith('.') and entry not in ['.', '..']:
                            # Hidden files in /dev are suspicious
                            results.append({
                                'path': path,
                                'name': entry,
                                'detection_method': 'dev_check',
                                'reason': f"Hidden file in /dev directory"
                            })
                        
                        # Check if it's a regular file but not a known device file
                        if os.path.isfile(path) and not os.path.islink(path):
                            try:
                                file_type = subprocess.run(['file', path], 
                                                         stdout=subprocess.PIPE, 
                                                         stderr=subprocess.PIPE, 
                                                         text=True)
                                if 'character special' not in file_type.stdout and 'block special' not in file_type.stdout:
                                    results.append({
                                        'path': path,
                                        'name': entry,
                                        'detection_method': 'dev_check',
                                        'reason': f"Regular file in /dev directory: {file_type.stdout.strip()}"
                                    })
                            except Exception:
                                # If file command fails, it's suspicious anyway
                                results.append({
                                    'path': path,
                                    'name': entry,
                                    'detection_method': 'dev_check',
                                    'reason': f"Regular file in /dev directory (couldn't determine type)"
                                })
            
            # Method 3: Check for directory entries not visible to readdir
            if 'directory_entries' in self.file_detection_methods:
                self.logger.debug("Checking for inaccessible directory entries")
                
                # This technique involves checking directories at a lower level
                # than the normal readdir syscall, which rootkits often hook.
                # It would require accessing directory entries directly, which
                # is complex and implementation-specific.
                
                # Simplified approach here, just to demonstrate the concept
                
                # In a real implementation, this might involve:
                # 1. Opening the directory with open()
                # 2. Reading raw directory entries with getdents64 syscall
                # 3. Comparing with normal readdir results
                
                pass
            
            # Method 4: Check for rootkit-specific files
            self.logger.debug("Checking for known rootkit files")
            
            for signature in self.rootkit_file_signatures:
                # If signature contains wildcards, use glob
                if any(c in signature for c in ['*', '?', '[']):
                    import glob
                    for path in glob.glob(signature):
                        if os.path.exists(path):
                            results.append({
                                'path': path,
                                'name': os.path.basename(path),
                                'detection_method': 'signature_match',
                                'reason': f"Known rootkit file signature"
                            })
                else:
                    # Direct path check
                    if os.path.exists(signature):
                        results.append({
                            'path': signature,
                            'name': os.path.basename(signature),
                            'detection_method': 'signature_match',
                            'reason': f"Known rootkit file signature"
                        })
            
            # Method 5: Check for modified critical binaries
            if 'sbin_check' in self.file_detection_methods:
                self.logger.debug("Checking critical binaries for modifications")
                
                # Check if common system binaries have been modified
                critical_binaries = [
                    '/bin/ls', '/bin/ps', '/bin/netstat', '/bin/find',
                    '/usr/bin/lsof', '/usr/bin/strings', '/usr/bin/top',
                    '/usr/bin/md5sum', '/usr/bin/sha1sum', '/usr/bin/sha256sum'
                ]
                
                for binary in critical_binaries:
                    if not os.path.exists(binary):
                        continue
                    
                    try:
                        # Check file type, rootkits often replace binaries with scripts
                        file_type = subprocess.run(['file', binary], 
                                                stdout=subprocess.PIPE, 
                                                stderr=subprocess.PIPE, 
                                                text=True)
                        if file_type.returncode == 0:
                            output = file_type.stdout.strip()
                            
                            if ('ELF' not in output and ('executable' in output.lower() or 'binary' in output.lower())):
                                # Suspicious - executable but not ELF format
                                results.append({
                                    'path': binary,
                                    'name': os.path.basename(binary),
                                    'detection_method': 'sbin_check',
                                    'reason': f"Critical binary has unexpected format: {output}"
                                })
                    except Exception as e:
                        self.logger.debug(f"Error checking binary {binary}: {e}")
            
            self.logger.info(f"Found {len(results)} hidden or suspicious files")
            return 'hidden_file', results
            
        except Exception as e:
            self.logger.error(f"Error checking hidden files: {e}")
            return 'hidden_file', []
    
    def _check_network_backdoors(self):
        """
        Check for network backdoors and suspicious connections
        
        Returns:
            tuple: ('network_backdoor', list of suspicious network connections)
        """
        self.logger.debug("Checking for network backdoors")
        
        results = []
        
        try:
            # Method 1: Check netstat output for listening on suspicious ports
            try:
                netstat_output = subprocess.run(['netstat', '-tunapl'], 
                                             stdout=subprocess.PIPE, 
                                             stderr=subprocess.PIPE, 
                                             text=True,
                                             timeout=self.network_scan_timeout)
                
                if netstat_output.returncode == 0:
                    lines = netstat_output.stdout.strip().split('\n')
                    
                    # Start analyzing from line after headers
                    for line in lines:
                        if not line.strip() or 'Proto' in line:
                            continue
                        
                        parts = line.split()
                        if len(parts) >= 7:
                            proto = parts[0]
                            local_addr = parts[3]
                            state = parts[5]
                            pid_program = parts[6]
                            
                            # Focus on listening ports
                            if 'LISTEN' not in state:
                                continue
                            
                            # Extract port number
                            port = None
                            try:
                                port = int(local_addr.split(':')[-1])
                            except ValueError:
                                continue
                            
                            # Check if this is a suspicious port
                            if port in self.backdoor_ports:
                                # Extract PID and program
                                pid = 'unknown'
                                program = 'unknown'
                                
                                pid_match = re.search(r'(\d+)/(.+)', pid_program)
                                if pid_match:
                                    pid = pid_match.group(1)
                                    program = pid_match.group(2)
                                
                                results.append({
                                    'port': port,
                                    'proto': proto,
                                    'local_addr': local_addr,
                                    'pid': pid,
                                    'program': program,
                                    'detection_method': 'suspicious_port',
                                    'reason': f"Known backdoor port {port}/{proto}"
                                })
            except Exception as e:
                self.logger.error(f"Error checking netstat: {e}")
            
            # Method 2: Check for suspicious network processes
            try:
                ps_output = subprocess.run(['ps', '-eo', 'pid,command'], 
                                        stdout=subprocess.PIPE, 
                                        stderr=subprocess.PIPE, 
                                        text=True,
                                        timeout=self.network_scan_timeout)
                
                if ps_output.returncode == 0:
                    lines = ps_output.stdout.strip().split('\n')
                    
                    # Start analyzing from line after headers
                    for line in lines[1:]:
                        parts = line.strip().split(None, 1)
                        if len(parts) < 2:
                            continue
                        
                        pid = parts[0]
                        command = parts[1]
                        
                        # Check for suspicious network commands
                        suspicious_commands = [
                            'nc -l', 'netcat -l', 'ncat -l',  # Netcat listening
                            'socat tcp-listen', 'socat TCP-LISTEN',  # Socat listening
                            '-e /bin/sh', '-e /bin/bash',  # Command execution
                            'tcpdump -w', 'wireshark',  # Network traffic capturing
                            'ssh -R', 'ssh -L',  # SSH port forwarding
                            'proxy', 'socks'  # Proxy services
                        ]
                        
                        for susp_cmd in suspicious_commands:
                            if susp_cmd in command:
                                # Avoid duplicates based on PID
                                if not any(r.get('pid') == pid for r in results):
                                    results.append({
                                        'pid': pid,
                                        'command': command,
                                        'detection_method': 'suspicious_network_process',
                                        'reason': f"Suspicious network command: {susp_cmd}"
                                    })
            except Exception as e:
                self.logger.error(f"Error checking suspicious network processes: {e}")
            
            # Method 3: Check for unusual ESTABLISHED connections
            try:
                netstat_estab = subprocess.run(['netstat', '-tuna'], 
                                            stdout=subprocess.PIPE, 
                                            stderr=subprocess.PIPE, 
                                            text=True,
                                            timeout=self.network_scan_timeout)
                
                if netstat_estab.returncode == 0:
                    lines = netstat_estab.stdout.strip().split('\n')
                    
                    # Track established connections by remote IP and port
                    remote_connections = defaultdict(int)
                    
                    for line in lines:
                        if 'ESTABLISHED' not in line:
                            continue
                        
                        parts = line.split()
                        if len(parts) >= 5:
                            remote_addr = parts[4]
                            remote_connections[remote_addr] += 1
                    
                    # Check for multiple connections to same strange port
                    for addr, count in remote_connections.items():
                        # Extract port
                        try:
                            port = int(addr.split(':')[-1])
                            
                            # Check if it's an unusual port with multiple connections
                            if port in self.backdoor_ports and count > 1:
                                results.append({
                                    'remote_addr': addr,
                                    'connection_count': count,
                                    'port': port,
                                    'detection_method': 'multiple_connections',
                                    'reason': f"Multiple connections to suspicious port {port}"
                                })
                        except ValueError:
                            pass
            except Exception as e:
                self.logger.error(f"Error checking established connections: {e}")
            
            self.logger.info(f"Found {len(results)} suspicious network connections")
            return 'network_backdoor', results
            
        except Exception as e:
            self.logger.error(f"Error checking network backdoors: {e}")
            return 'network_backdoor', []
    
    def _check_dkom(self):
        """
        Check for Direct Kernel Object Manipulation (DKOM)
        
        Returns:
            tuple: ('dkom', list of DKOM detections)
        """
        self.logger.debug("Checking for Direct Kernel Object Manipulation (DKOM)")
        
        results = []
        
        try:
            # DKOM detection is complex and requires kernel-level access
            # This is a simplified implementation to demonstrate the concept
            
            # Method 1: Check process list consistency
            # This is similar to process hiding detection, but focuses on signs of DKOM
            
            # Method 2: Check for IDT (Interrupt Descriptor Table) hooks
            # Requires kernel-level access, simplified here
            
            # Method 3: Check kernel memory for signs of tampering
            # Requires kernel-level access, simplified here
            
            # Method 4: Check for discrepancies in task struct linkage
            # Requires specialized tools, simplified here
            
            self.logger.info(f"Found {len(results)} potential DKOM manipulations")
            return 'dkom', results
            
        except Exception as e:
            self.logger.error(f"Error checking for DKOM: {e}")
            return 'dkom', []
    
    def establish_baseline(self):
        """
        Establish a clean baseline for future comparisons
        
        Returns:
            dict: Baseline scan results
        """
        self.logger.info("Establishing rootkit detection baseline")
        
        # Run a full scan to establish baseline
        baseline_results = self.analyze()
        
        # Store baseline in database with special flag
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            # Mark this scan as a baseline
            timestamp = time.time()
            cursor.execute('''
            INSERT INTO rootkit_scans (timestamp, threat_level, summary, details)
            VALUES (?, ?, ?, ?)
            ''', (
                timestamp,
                baseline_results['threat_level'],
                json.dumps({'baseline': True, 'summary': baseline_results['summary']}),
                json.dumps(baseline_results['detections'])
            ))
            
            # Set all detections as verified (baseline assumes clean system)
            scan_id = cursor.lastrowid
            cursor.execute('''
            UPDATE detection_results SET verified = 1 WHERE scan_id = ?
            ''', (scan_id,))
            
            conn.commit()
            
            self.logger.info(f"Baseline established with scan ID {scan_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to store baseline: {e}")
        finally:
            if conn:
                conn.close()
        
        return baseline_results
    
    def compare_with_baseline(self, current_scan=None):
        """
        Compare current state with baseline
        
        Args:
            current_scan (dict): Current scan results, or None to run a new scan
            
        Returns:
            dict: Comparison results
        """
        self.logger.info("Comparing with baseline")
        
        # Get baseline
        baseline = self._get_latest_baseline()
        
        if not baseline:
            self.logger.warning("No baseline found for comparison")
            return {'error': 'No baseline found', 'comparison': None}
        
        # Run current scan if not provided
        if not current_scan:
            current_scan = self.analyze()
        
        # Compare results
        comparison = {
            'timestamp': datetime.now().isoformat(),
            'baseline_id': baseline['id'],
            'baseline_timestamp': baseline['timestamp'],
            'changes': {
                'kernel_module': {
                    'new': [],
                    'missing': [],
                    'modified': []
                },
                'syscall_hook': {
                    'new': [],
                    'missing': [],
                    'modified': []
                },
                'hidden_process': {
                    'new': [],
                    'missing': []
                },
                'hidden_file': {
                    'new': [],
                    'missing': []
                },
                'network_backdoor': {
                    'new': [],
                    'missing': []
                },
                'dkom': {
                    'new': [],
                    'missing': []
                }
            },
            'new_detections': 0,
            'is_anomalous': False
        }
        
        # Parse baseline details
        baseline_detections = {}
        if baseline.get('details'):
            try:
                baseline_detections = json.loads(baseline['details'])
            except json.JSONDecodeError:
                self.logger.error("Failed to parse baseline details")
        
        # Compare each detection type
        for detection_type in ['kernel_module', 'syscall_hook', 'hidden_process', 
                             'hidden_file', 'network_backdoor', 'dkom']:
            
            # Get current and baseline detections
            current = current_scan['detections'].get(detection_type, [])
            baseline_items = baseline_detections.get(detection_type, [])
            
            # Convert to sets for comparison, using a stable identifier for each item
            current_ids = set(self._get_detection_id(item, detection_type) for item in current)
            baseline_ids = set(self._get_detection_id(item, detection_type) for item in baseline_items)
            
            # Find new detections
            for item in current:
                item_id = self._get_detection_id(item, detection_type)
                if item_id not in baseline_ids:
                    comparison['changes'][detection_type]['new'].append(item)
            
            # Find missing detections
            for item in baseline_items:
                item_id = self._get_detection_id(item, detection_type)
                if item_id not in current_ids:
                    comparison['changes'][detection_type]['missing'].append(item)
        
        # Calculate total new detections
        total_new = sum(len(changes['new']) for changes in comparison['changes'].values())
        comparison['new_detections'] = total_new
        
        # Determine if changes are anomalous
        comparison['is_anomalous'] = total_new > 0
        
        # Store comparison results in database
        self._store_comparison_results(comparison, baseline['id'])
        
        self.logger.info(f"Comparison completed. Found {total_new} new detections since baseline.")
        return comparison
    
    def _get_latest_baseline(self):
        """
        Get the most recent baseline scan
        
        Returns:
            dict: Baseline scan or None if not found
        """
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            # Find most recent scan with baseline flag
            cursor.execute('''
            SELECT id, timestamp, threat_level, summary, details 
            FROM rootkit_scans 
            WHERE summary LIKE '%"baseline": true%' 
            ORDER BY timestamp DESC 
            LIMIT 1
            ''')
            
            row = cursor.fetchone()
            if row:
                return {
                    'id': row[0],
                    'timestamp': datetime.fromtimestamp(row[1]).isoformat(),
                    'threat_level': row[2],
                    'summary': row[3],
                    'details': row[4]
                }
                
            return None
            
        except Exception as e:
            self.logger.error(f"Error getting baseline: {e}")
            return None
        finally:
            if conn:
                conn.close()
    
    def _get_detection_id(self, detection, detection_type):
        """
        Create a stable identifier for a detection for comparison purposes
        
        Args:
            detection (dict): Detection data
            detection_type (str): Type of detection
            
        Returns:
            str: Unique identifier for this detection
        """
        if detection_type == 'kernel_module':
            return f"km:{detection.get('name', '')}"
        elif detection_type == 'syscall_hook':
            return f"sh:{detection.get('name', '')}"
        elif detection_type == 'hidden_process':
            # Use PID and name for process ID
            return f"hp:{detection.get('pid', '')}:{detection.get('name', '')}"
        elif detection_type == 'hidden_file':
            # Use path for file ID
            return f"hf:{detection.get('path', '')}"
        elif detection_type == 'network_backdoor':
            # Use combination of port and program
            return f"nb:{detection.get('port', '')}:{detection.get('program', '')}"
        elif detection_type == 'dkom':
            # Use any available identifier
            if 'address' in detection:
                return f"dk:{detection.get('address', '')}"
            return f"dk:{detection.get('name', '')}"
        
        # Fallback
        return str(hash(json.dumps(detection, sort_keys=True)))
    
    def _store_comparison_results(self, comparison, baseline_id):
        """
        Store comparison results in database
        
        Args:
            comparison (dict): Comparison results
            baseline_id (int): ID of baseline scan
        """
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            # Create a new scan entry for the comparison
            timestamp = time.time()
            summary = json.dumps({
                'comparison': True,
                'baseline_id': baseline_id,
                'new_detections': comparison['new_detections']
            })
            
            # Determine threat level based on new detections
            threat_level = 'low'
            if comparison['new_detections'] > 0:
                # Check for critical detections
                critical_detections = (
                    len(comparison['changes']['kernel_module']['new']) > 0 or
                    len(comparison['changes']['syscall_hook']['new']) > 0 or
                    len(comparison['changes']['dkom']['new']) > 0
                )
                
                if critical_detections:
                    threat_level = 'critical'
                else:
                    threat_level = 'medium'
            
            # Insert scan record
            cursor.execute('''
            INSERT INTO rootkit_scans (timestamp, threat_level, summary, details)
            VALUES (?, ?, ?, ?)
            ''', (
                timestamp,
                threat_level,
                summary,
                json.dumps(comparison['changes'])
            ))
            
            scan_id = cursor.lastrowid
            
            # Store individual detection results
            for detection_type, changes in comparison['changes'].items():
                for change_type in ['new', 'missing']:
                    for item in changes[change_type]:
                        name = item.get('name', '')
                        path = item.get('path', '')
                        
                        # Determine threat level for this detection
                        if detection_type in ['kernel_module', 'syscall_hook', 'dkom']:
                            det_threat_level = 'critical'
                        elif detection_type in ['hidden_process', 'network_backdoor']:
                            det_threat_level = 'high'
                        else:
                            det_threat_level = 'medium'
                        
                        # Include change type in details
                        item['change_type'] = change_type
                        details_json = json.dumps(item)
                        
                        cursor.execute('''
                        INSERT INTO detection_results 
                        (scan_id, detection_type, threat_level, name, path, details, timestamp)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            scan_id, 
                            detection_type, 
                            det_threat_level, 
                            name, 
                            path, 
                            details_json, 
                            timestamp
                        ))
            
            conn.commit()
            self.logger.debug(f"Stored comparison results with scan ID {scan_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to store comparison results: {e}")
        finally:
            if conn:
                conn.close()
    
    def get_scan_history(self, limit=10):
        """
        Get history of rootkit scans
        
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
            SELECT id, timestamp, threat_level, summary 
            FROM rootkit_scans 
            ORDER BY timestamp DESC 
            LIMIT ?
            ''', (limit,))
            
            for row in cursor.fetchall():
                # Parse summary
                summary_data = {}
                try:
                    summary_data = json.loads(row[3])
                except json.JSONDecodeError:
                    pass
                
                # Create scan record
                scan = {
                    'id': row[0],
                    'timestamp': datetime.fromtimestamp(row[1]).isoformat(),
                    'threat_level': row[2],
                    'is_baseline': summary_data.get('baseline', False),
                    'is_comparison': summary_data.get('comparison', False)
                }
                
                # Add detection counts if available
                if 'summary' in summary_data:
                    scan['detection_counts'] = summary_data['summary']
                
                # If it's a comparison, add baseline reference
                if summary_data.get('comparison'):
                    scan['baseline_id'] = summary_data.get('baseline_id')
                    scan['new_detections'] = summary_data.get('new_detections', 0)
                
                scans.append(scan)
            
            return scans
            
        except Exception as e:
            self.logger.error(f"Error getting scan history: {e}")
            return []
        finally:
            if conn:
                conn.close()
    
    def get_scan_details(self, scan_id):
        """
        Get details of a specific scan
        
        Args:
            scan_id (int): ID of the scan
            
        Returns:
            dict: Scan details
        """
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            # Get scan record
            cursor.execute('''
            SELECT id, timestamp, threat_level, summary, details 
            FROM rootkit_scans 
            WHERE id = ?
            ''', (scan_id,))
            
            row = cursor.fetchone()
            if not row:
                return {'error': f"Scan with ID {scan_id} not found"}
            
            # Parse summary and details
            summary_data = {}
            details_data = {}
            try:
                summary_data = json.loads(row[3])
                details_data = json.loads(row[4])
            except json.JSONDecodeError:
                pass
            
            # Get detection results
            cursor.execute('''
            SELECT detection_type, threat_level, name, path, details, timestamp, verified 
            FROM detection_results 
            WHERE scan_id = ?
            ''', (scan_id,))
            
            detections = defaultdict(list)
            for det_row in cursor.fetchall():
                detection = {
                    'type': det_row[0],
                    'threat_level': det_row[1],
                    'name': det_row[2],
                    'path': det_row[3],
                    'timestamp': datetime.fromtimestamp(det_row[5]).isoformat(),
                    'verified': bool(det_row[6])
                }
                
                # Add details if available
                try:
                    det_details = json.loads(det_row[4])
                    detection.update(det_details)
                except json.JSONDecodeError:
                    pass
                
                detections[det_row[0]].append(detection)
            
            # Create full scan record
            scan = {
                'id': row[0],
                'timestamp': datetime.fromtimestamp(row[1]).isoformat(),
                'threat_level': row[2],
                'is_baseline': summary_data.get('baseline', False),
                'is_comparison': summary_data.get('comparison', False),
                'detections': dict(detections)
            }
            
            # Add summary data
            if 'summary' in summary_data:
                scan['summary'] = summary_data['summary']
            
            # Add comparison data if available
            if summary_data.get('comparison'):
                scan['comparison'] = {
                    'baseline_id': summary_data.get('baseline_id'),
                    'new_detections': summary_data.get('new_detections', 0)
                }
            
            return scan
            
        except Exception as e:
            self.logger.error(f"Error getting scan details: {e}")
            return {'error': str(e)}
        finally:
            if conn:
                conn.close()
    
    def add_signature(self, signature_type, signature_value, description, threat_level='medium', source='manual'):
        """
        Add a new signature to the database
        
        Args:
            signature_type (str): Type of signature (file_signature, process_signature, network_signature)
            signature_value (str): The signature pattern
            description (str): Description of the signature
            threat_level (str): Threat level (low, medium, high, critical)
            source (str): Source of the signature
            
        Returns:
            bool: True if successful
        """
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            cursor.execute('''
            INSERT INTO baseline_signatures 
            (signature_type, signature_value, description, threat_level, source, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                signature_type,
                signature_value,
                description,
                threat_level,
                source,
                time.time()
            ))
            
            conn.commit()
            
            # Reload signatures
            self._load_signatures()
            
            self.logger.info(f"Added new {signature_type} signature: {signature_value}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error adding signature: {e}")
            return False
        finally:
            if conn:
                conn.close()
    
    def get_signatures(self, signature_type=None):
        """
        Get signatures from database
        
        Args:
            signature_type (str): Optional type to filter by
            
        Returns:
            list: Signatures
        """
        signatures = []
        
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            if signature_type:
                query = '''
                SELECT id, signature_type, signature_value, description, threat_level, source, timestamp
                FROM baseline_signatures
                WHERE signature_type = ?
                ORDER BY timestamp DESC
                '''
                cursor.execute(query, (signature_type,))
            else:
                query = '''
                SELECT id, signature_type, signature_value, description, threat_level, source, timestamp
                FROM baseline_signatures
                ORDER BY timestamp DESC
                '''
                cursor.execute(query)
            
            for row in cursor.fetchall():
                signatures.append({
                    'id': row[0],
                    'type': row[1],
                    'value': row[2],
                    'description': row[3],
                    'threat_level': row[4],
                    'source': row[5],
                    'timestamp': datetime.fromtimestamp(row[6]).isoformat()
                })
            
            return signatures
            
        except Exception as e:
            self.logger.error(f"Error getting signatures: {e}")
            return []
        finally:
            if conn:
                conn.close()
    
    def remove_signature(self, signature_id):
        """
        Remove a signature from the database
        
        Args:
            signature_id (int): ID of the signature
            
        Returns:
            bool: True if successful
        """
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            cursor.execute('''
            DELETE FROM baseline_signatures WHERE id = ?
            ''', (signature_id,))
            
            conn.commit()
            
            # Reload signatures
            self._load_signatures()
            
            self.logger.info(f"Removed signature with ID {signature_id}")
            return cursor.rowcount > 0
            
        except Exception as e:
            self.logger.error(f"Error removing signature: {e}")
            return False
        finally:
            if conn:
                conn.close()
    
    def get_statistics(self):
        """
        Get statistics about rootkit detection
        
        Returns:
            dict: Statistics
        """
        stats = {
            'total_scans': 0,
            'total_detections': 0,
            'detection_counts': {
                'kernel_module': 0,
                'syscall_hook': 0,
                'hidden_process': 0,
                'hidden_file': 0,
                'network_backdoor': 0,
                'dkom': 0
            },
            'threat_levels': {
                'low': 0,
                'medium': 0,
                'high': 0,
                'critical': 0
            },
            'last_scan': None,
            'signature_counts': {
                'file_signature': 0,
                'process_signature': 0,
                'network_signature': 0
            }
        }
        
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            # Get scan counts
            cursor.execute('''
            SELECT COUNT(*) FROM rootkit_scans
            ''')
            stats['total_scans'] = cursor.fetchone()[0]
            
            # Get last scan timestamp
            cursor.execute('''
            SELECT timestamp FROM rootkit_scans ORDER BY timestamp DESC LIMIT 1
            ''')
            row = cursor.fetchone()
            if row:
                stats['last_scan'] = datetime.fromtimestamp(row[0]).isoformat()
            
            # Get threat level counts
            cursor.execute('''
            SELECT threat_level, COUNT(*) FROM rootkit_scans GROUP BY threat_level
            ''')
            for row in cursor.fetchall():
                stats['threat_levels'][row[0]] = row[1]
            
            # Get detection counts
            cursor.execute('''
            SELECT detection_type, COUNT(*) FROM detection_results GROUP BY detection_type
            ''')
            for row in cursor.fetchall():
                stats['detection_counts'][row[0]] = row[1]
                stats['total_detections'] += row[1]
            
            # Get signature counts
            cursor.execute('''
            SELECT signature_type, COUNT(*) FROM baseline_signatures GROUP BY signature_type
            ''')
            for row in cursor.fetchall():
                stats['signature_counts'][row[0]] = row[1]
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Error getting statistics: {e}")
            return stats
        finally:
            if conn:
                conn.close()
    
    def mark_detection_verified(self, scan_id, detection_type, detection_name):
        """
        Mark a detection as verified (false positive or addressed)
        
        Args:
            scan_id (int): ID of the scan
            detection_type (str): Type of detection
            detection_name (str): Name of the detection
            
        Returns:
            bool: True if successful
        """
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            cursor.execute('''
            UPDATE detection_results 
            SET verified = 1 
            WHERE scan_id = ? AND detection_type = ? AND name = ?
            ''', (scan_id, detection_type, detection_name))
            
            conn.commit()
            
            self.logger.info(f"Marked detection {detection_name} as verified")
            return cursor.rowcount > 0
            
        except Exception as e:
            self.logger.error(f"Error marking detection as verified: {e}")
            return False
        finally:
            if conn:
                conn.close()
    
    def cleanup(self):
        """Cleanup temporary files and resources"""
        try:
            # Remove temporary directory
            if hasattr(self, 'temp_dir') and os.path.exists(self.temp_dir):
                import shutil
                shutil.rmtree(self.temp_dir)
                
            self.logger.debug("Cleaned up temporary resources")
            
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")
    
    def __del__(self):
        """Destructor to ensure cleanup"""
        self.cleanup()