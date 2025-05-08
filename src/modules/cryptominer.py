#!/usr/bin/env python3
"""
CryptominerDetection Module
Uses machine learning and heuristic detection to identify cryptomining malware.
"""

import os
import logging
import subprocess
import json
from datetime import datetime
import time
import threading

from utils.ml_utils import CryptominerDetector, CPUProfiler, MLModelManager

class CryptominerDetectionModule:
    """Detects cryptomining malware using ML and heuristics"""
    
    def __init__(self, config=None):
        """Initialize with configuration"""
        self.logger = logging.getLogger('sharpeye.cryptominer')
        self.config = config or {}
        
        # Initialize detector
        self.detector = CryptominerDetector(self.config)
        
        # Default monitoring parameters
        self.monitoring_interval = self.config.get('monitoring_interval', 60)  # seconds
        self.continuous_monitoring = self.config.get('continuous_monitoring', False)
        self.baseline_file = self.config.get('baseline_file', '/var/lib/sharpeye/baselines/cryptominer.json')
        
        # Monitoring thread
        self.monitoring_thread = None
        self.stop_monitoring = threading.Event()
        
        # Initialize result storage
        self.latest_results = {}
    
    def analyze(self):
        """
        Analyze system for cryptominers
        """
        self.logger.info("Analyzing system for cryptominer processes")
        
        # Get all running processes
        processes = self._get_all_processes()
        
        # Analyze each process
        suspicious_processes = []
        
        for pid in processes:
            result = self.detector.analyze_process(pid)
            
            # If the process is suspicious, record it
            if result.get('is_cryptominer', False):
                suspicious_processes.append(result)
            
            # Store the result for reference
            self.latest_results[pid] = result
        
        # Compile results
        results = {
            'timestamp': datetime.now().isoformat(),
            'count': len(suspicious_processes),
            'suspicious_processes': suspicious_processes,
            'is_anomalous': len(suspicious_processes) > 0
        }
        
        # Start continuous monitoring if enabled
        if self.continuous_monitoring and not self.monitoring_thread:
            self._start_monitoring()
        
        return results
    
    def establish_baseline(self):
        """
        Establish a baseline of normal processes for future detection
        """
        self.logger.info("Establishing baseline for cryptominer detection")
        
        # Get all running processes
        processes = self._get_all_processes()
        
        # Collect information on normal processes
        baseline_processes = {}
        
        for pid in processes:
            try:
                # Get command info
                cmd = ["ps", "-p", str(pid), "-o", "command", "--no-headers"]
                command = subprocess.check_output(cmd, universal_newlines=True).strip()
                
                # Get CPU and memory info
                cmd = ["ps", "-p", str(pid), "-o", "%cpu,%mem", "--no-headers"]
                resources = subprocess.check_output(cmd, universal_newlines=True).strip()
                
                if resources:
                    parts = resources.split()
                    if len(parts) >= 2:
                        cpu_percent = float(parts[0])
                        mem_percent = float(parts[1])
                        
                        baseline_processes[pid] = {
                            'command': command,
                            'cpu_percent': cpu_percent,
                            'mem_percent': mem_percent
                        }
            except (subprocess.SubprocessError, ValueError):
                continue
        
        # Record features in baseline
        baseline = {
            'timestamp': datetime.now().isoformat(),
            'process_count': len(baseline_processes),
            'processes': baseline_processes,
            'system_load': self._get_system_load()
        }
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.baseline_file), exist_ok=True)
        
        # Write baseline to file
        with open(self.baseline_file, 'w') as f:
            json.dump(baseline, f, indent=2)
        
        self.logger.info(f"Baseline saved to {self.baseline_file}")
        
        return baseline
    
    def compare_baseline(self):
        """
        Compare current state with baseline for anomaly detection
        """
        self.logger.info("Comparing cryptominer detection results with baseline")
        
        # Check if baseline exists
        if not os.path.exists(self.baseline_file):
            self.logger.warning("No baseline found. Run with --establish-baseline first.")
            return {
                'error': "No baseline found",
                'is_anomalous': False
            }
        
        # Load baseline
        with open(self.baseline_file, 'r') as f:
            baseline = json.load(f)
        
        # Get current state
        current_results = self.analyze()
        
        # Compare processes against baseline
        new_suspicious_processes = []
        baseline_processes = baseline.get('processes', {})
        
        for process in current_results.get('suspicious_processes', []):
            pid = process.get('pid')
            command = process.get('command', '')
            
            # Check if this is a known process from baseline
            is_new = True
            for baseline_pid, baseline_process in baseline_processes.items():
                if command == baseline_process.get('command', ''):
                    is_new = False
                    break
            
            if is_new:
                process['is_new'] = True
                new_suspicious_processes.append(process)
        
        # Check system load difference
        baseline_load = baseline.get('system_load', {})
        current_load = self._get_system_load()
        
        load_diff = {
            'load_1min': current_load.get('load_1min', 0) - baseline_load.get('load_1min', 0),
            'load_5min': current_load.get('load_5min', 0) - baseline_load.get('load_5min', 0),
            'load_15min': current_load.get('load_15min', 0) - baseline_load.get('load_15min', 0)
        }
        
        # Finalize comparison results
        comparison = {
            'timestamp': datetime.now().isoformat(),
            'baseline_timestamp': baseline.get('timestamp'),
            'new_suspicious_processes': new_suspicious_processes,
            'load_difference': load_diff,
            'is_anomalous': len(new_suspicious_processes) > 0
        }
        
        return comparison
    
    def _get_all_processes(self):
        """
        Get all running processes
        
        Returns:
            list: List of process IDs
        """
        try:
            cmd = ["ps", "-eo", "pid", "--no-headers"]
            output = subprocess.check_output(cmd, universal_newlines=True)
            
            pids = []
            for line in output.strip().split('\n'):
                if line.strip():
                    try:
                        pid = int(line.strip())
                        pids.append(pid)
                    except ValueError:
                        continue
            
            return pids
        except subprocess.SubprocessError as e:
            self.logger.error(f"Error getting process list: {e}")
            return []
    
    def _get_system_load(self):
        """
        Get system load averages
        
        Returns:
            dict: System load information
        """
        try:
            with open('/proc/loadavg', 'r') as f:
                load = f.read().strip().split()
                
                return {
                    'load_1min': float(load[0]),
                    'load_5min': float(load[1]),
                    'load_15min': float(load[2])
                }
        except (FileNotFoundError, IOError, IndexError, ValueError) as e:
            self.logger.error(f"Error getting system load: {e}")
            return {
                'load_1min': 0,
                'load_5min': 0,
                'load_15min': 0
            }
    
    def _start_monitoring(self):
        """
        Start continuous monitoring for cryptominers in a separate thread
        """
        self.stop_monitoring.clear()
        self.monitoring_thread = threading.Thread(
            target=self._monitoring_loop,
            daemon=True
        )
        self.monitoring_thread.start()
        self.logger.info("Started continuous cryptominer monitoring")
    
    def _stop_monitoring(self):
        """
        Stop the continuous monitoring thread
        """
        if self.monitoring_thread:
            self.stop_monitoring.set()
            self.monitoring_thread.join(timeout=5)
            self.monitoring_thread = None
            self.logger.info("Stopped continuous cryptominer monitoring")
    
    def _monitoring_loop(self):
        """
        Continuous monitoring loop for cryptominers
        """
        self.logger.info(f"Monitoring for cryptominers every {self.monitoring_interval} seconds")
        
        while not self.stop_monitoring.is_set():
            try:
                # Analyze for cryptominers
                results = self.analyze()
                
                # Log any detected cryptominers
                if results.get('is_anomalous', False):
                    self.logger.warning(
                        f"Detected {len(results.get('suspicious_processes', []))} "
                        f"potential cryptominer processes"
                    )
                    
                    for process in results.get('suspicious_processes', []):
                        self.logger.warning(
                            f"Potential cryptominer: PID {process.get('pid')} "
                            f"Command: {process.get('command')} "
                            f"Confidence: {process.get('confidence', 0):.2f}"
                        )
                
                # Sleep until next interval
                self.stop_monitoring.wait(self.monitoring_interval)
                
            except Exception as e:
                self.logger.error(f"Error in cryptominer monitoring loop: {e}")
                # Sleep a bit and continue
                time.sleep(5)
                
        self.logger.info("Cryptominer monitoring thread stopped")