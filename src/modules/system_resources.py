#!/usr/bin/env python3
"""
SystemResourceAnalyzer Module
Detects anomalies in system resource usage including CPU, memory, and disk space.
Includes machine learning capabilities for pattern-based anomaly detection.
"""

import os
import logging
import subprocess
import json
import time
import numpy as np
from datetime import datetime
from collections import deque
import re
import stat

# Import machine learning utilities
from utils.ml_utils import MLModelManager

class ResourcePatternAnalyzer:
    """
    Machine learning-based analyzer for system resource usage patterns
    Uses time series analysis and anomaly detection algorithms to identify
    suspicious resource usage patterns that may indicate compromise
    """
    
    def __init__(self, config=None):
        """Initialize with configuration"""
        self.logger = logging.getLogger('sharpeye.resources.ml')
        self.config = config or {}
        
        # Configuration values
        self.history_length = self.config.get('history_length', 24)  # Number of samples to keep
        self.enable_ml = self.config.get('enable_ml', True)  # Enable ML analysis
        self.models_dir = self.config.get('models_dir', '/var/lib/sharpeye/models')
        self.detection_threshold = self.config.get('detection_threshold', 0.7)  # Anomaly threshold (0-1)
        
        # Initialize ML components
        self.ml_manager = MLModelManager({'models_dir': self.models_dir})
        
        # Load models if they exist
        self.cpu_model = self.ml_manager.load_model('resource_cpu_anomaly')
        self.memory_model = self.ml_manager.load_model('resource_memory_anomaly')
        self.disk_model = self.ml_manager.load_model('resource_disk_anomaly')
        
        # Initialize history storage
        self.history = {
            'cpu': deque(maxlen=self.history_length),
            'memory': deque(maxlen=self.history_length),
            'disk': deque(maxlen=self.history_length),
            'timestamps': deque(maxlen=self.history_length)
        }
        
        # Isolation Forest parameters (for training new models)
        self.isolation_forest_params = {
            'n_estimators': 100,
            'max_samples': 'auto',
            'contamination': 'auto',
            'random_state': 42
        }
        
    def add_sample(self, resource_data):
        """
        Add a new resource usage sample to the history
        
        Args:
            resource_data: Dictionary with CPU, memory, and disk metrics
        """
        try:
            # Extract key metrics
            cpu_metrics = self._extract_cpu_features(resource_data.get('cpu', {}))
            memory_metrics = self._extract_memory_features(resource_data.get('memory', {}))
            disk_metrics = self._extract_disk_features(resource_data.get('disk', {}))
            
            # Add to history
            self.history['cpu'].append(cpu_metrics)
            self.history['memory'].append(memory_metrics)
            self.history['disk'].append(disk_metrics)
            self.history['timestamps'].append(time.time())
            
            return True
        
        except Exception as e:
            self.logger.error(f"Error adding resource sample: {e}")
            return False
    
    def analyze_patterns(self):
        """
        Analyze resource usage patterns using ML techniques
        
        Returns:
            dict: Analysis results with detected anomalies
        """
        results = {
            'timestamp': datetime.now().isoformat(),
            'has_sufficient_history': len(self.history['timestamps']) >= 3,
            'cpu_anomalies': [],
            'memory_anomalies': [],
            'disk_anomalies': [],
            'is_anomalous': False
        }
        
        # Skip analysis if we don't have enough history
        if not results['has_sufficient_history']:
            self.logger.debug("Insufficient history for ML analysis (need at least 3 samples)")
            return results
        
        # Run ML-based detection if enabled
        if self.enable_ml:
            # CPU pattern analysis
            cpu_anomalies = self._analyze_cpu_patterns()
            if cpu_anomalies:
                results['cpu_anomalies'] = cpu_anomalies
                results['is_anomalous'] = True
            
            # Memory pattern analysis
            memory_anomalies = self._analyze_memory_patterns()
            if memory_anomalies:
                results['memory_anomalies'] = memory_anomalies
                results['is_anomalous'] = True
            
            # Disk pattern analysis
            disk_anomalies = self._analyze_disk_patterns()
            if disk_anomalies:
                results['disk_anomalies'] = disk_anomalies
                results['is_anomalous'] = True
            
            # Add correlation analysis
            correlation_anomalies = self._analyze_cross_resource_correlations()
            if correlation_anomalies:
                results['correlation_anomalies'] = correlation_anomalies
                results['is_anomalous'] = True
        
        # Add trend analysis
        trend_results = self._analyze_trends()
        results['trends'] = trend_results
        if trend_results.get('is_anomalous', False):
            results['is_anomalous'] = True
        
        return results
    
    def _extract_cpu_features(self, cpu_data):
        """Extract key features from CPU data for time series analysis"""
        features = {
            'total_usage': cpu_data.get('total_cpu_usage', 0),
            'high_process_count': len([p for p in cpu_data.get('top_processes', []) 
                                if p.get('cpu_percent', 0) > 70]),
            'anomalous_process_count': len(cpu_data.get('anomalous_processes', [])),
            'hidden_process_count': len(cpu_data.get('hidden_processes', [])),
            'load_avg': cpu_data.get('load_averages', [0, 0, 0])[0],  # 1-minute load average
            'io_wait': cpu_data.get('cpu_stats', {}).get('percentages', {}).get('iowait', 0),
            'system_cpu': cpu_data.get('cpu_stats', {}).get('percentages', {}).get('system', 0),
            'user_cpu': cpu_data.get('cpu_stats', {}).get('percentages', {}).get('user', 0)
        }
        return features
    
    def _extract_memory_features(self, memory_data):
        """Extract key features from memory data for time series analysis"""
        features = {
            'usage_percent': memory_data.get('memory_usage_percent', 0),
            'swap_percent': memory_data.get('swap_usage_percent', 0),
            'high_process_count': len([p for p in memory_data.get('top_processes', []) 
                                 if p.get('mem_percent', 0) > 20]),
            'anomalous_process_count': len(memory_data.get('anomalous_processes', [])),
            'cached_ratio': memory_data.get('memory_details', {}).get('cached', 0) / 
                           (memory_data.get('memory_details', {}).get('free', 1) + 0.1),
            'anon_pages': memory_data.get('memory_details', {}).get('anon_pages', 0),
            'slab_memory': memory_data.get('memory_details', {}).get('slab', 0),
            'fragmentation': memory_data.get('memory_details', {}).get('fragmentation_index', 1)
        }
        return features
    
    def _extract_disk_features(self, disk_data):
        """Extract key features from disk data for time series analysis"""
        # Calculate average filesystem usage
        filesystems = disk_data.get('filesystems', [])
        avg_usage = 0
        if filesystems:
            avg_usage = sum(fs.get('use_percent', 0) for fs in filesystems) / len(filesystems)
        
        features = {
            'avg_usage_percent': avg_usage,
            'anomalous_fs_count': len(disk_data.get('anomalous_filesystems', [])),
            'suspicious_dir_count': len(disk_data.get('suspicious_directories', [])),
            'hidden_file_count': len(disk_data.get('hidden_files', [])),
            'large_file_count': len(disk_data.get('large_files', [])),
            'suspicious_growth': 1 if disk_data.get('disk_growth', {}).get('is_suspicious', False) else 0,
            'permission_issue_count': len(disk_data.get('permission_issues', [])),
            'modified_config_count': len(disk_data.get('recently_modified_config', []))
        }
        return features
    
    def _analyze_cpu_patterns(self):
        """
        Analyze CPU usage patterns for anomalies using ML and statistical methods
        
        Returns:
            list: Detected anomalies with descriptions
        """
        anomalies = []
        
        try:
            # Convert history to numpy array for analysis
            cpu_history = np.array([[
                sample['total_usage'],
                sample['high_process_count'],
                sample['anomalous_process_count'],
                sample['hidden_process_count'],
                sample['load_avg'],
                sample['io_wait'],
                sample['system_cpu'],
                sample['user_cpu']
            ] for sample in self.history['cpu']])
            
            # Check if we have a model
            if self.cpu_model:
                # Use ML model for anomaly detection
                # Reshape for scikit-learn API
                predictions = self.cpu_model.predict(cpu_history)
                anomaly_scores = self.cpu_model.decision_function(cpu_history)
                
                # Check most recent sample (last in the array)
                if predictions[-1] == -1:  # Anomaly in isolation forest
                    anomalies.append({
                        'type': 'ml_detected',
                        'description': 'Machine learning model detected CPU usage anomaly',
                        'score': float(anomaly_scores[-1]),
                        'severity': 'high'
                    })
            
            # Always perform statistical analysis regardless of ML model
            if len(cpu_history) >= 3:
                # 1. Check for sudden spikes in CPU usage
                total_usage = cpu_history[:, 0]  # First column is total_usage
                if total_usage[-1] > 80 and total_usage[-1] > total_usage[-2] * 1.5:
                    anomalies.append({
                        'type': 'cpu_spike',
                        'description': f'Sudden spike in CPU usage: {total_usage[-2]:.1f}% -> {total_usage[-1]:.1f}%',
                        'severity': 'medium'
                    })
                
                # 2. Check for hidden processes appearing
                hidden_count = cpu_history[:, 3]  # Fourth column is hidden_process_count
                if hidden_count[-1] > 0 and hidden_count[-2] == 0:
                    anomalies.append({
                        'type': 'hidden_processes',
                        'description': f'Hidden processes detected: {int(hidden_count[-1])} process(es)',
                        'severity': 'high'
                    })
                
                # 3. Check for unusual system to user CPU ratio
                system_cpu = cpu_history[:, 6]  # Seventh column is system_cpu
                user_cpu = cpu_history[:, 7]    # Eighth column is user_cpu
                
                if system_cpu[-1] > 40 and system_cpu[-1] > user_cpu[-1] * 2:
                    anomalies.append({
                        'type': 'high_system_cpu',
                        'description': f'Unusually high system CPU time: {system_cpu[-1]:.1f}% (user: {user_cpu[-1]:.1f}%)',
                        'severity': 'medium' 
                    })
                
                # 4. Detect sustained high load averages
                load_avg = cpu_history[:, 4]  # Fifth column is load_avg
                # Get physical CPU count 
                cpu_count = os.cpu_count() or 1
                if all(load > cpu_count * 1.5 for load in load_avg[-3:]):
                    anomalies.append({
                        'type': 'sustained_high_load',
                        'description': f'Sustained high load average: {load_avg[-1]:.2f} on {cpu_count} CPUs',
                        'severity': 'medium'
                    })
                
                # 5. Detect I/O wait spikes that might indicate disk encryption/crypto
                io_wait = cpu_history[:, 5]  # Sixth column is io_wait
                if io_wait[-1] > 25 and io_wait[-1] > np.mean(io_wait[:-1]) * 2:
                    anomalies.append({
                        'type': 'io_wait_spike',
                        'description': f'Unusual I/O wait time spike: {io_wait[-1]:.1f}% (avg: {np.mean(io_wait[:-1]):.1f}%)',
                        'severity': 'high'
                    })
        
        except Exception as e:
            self.logger.error(f"Error analyzing CPU patterns: {e}")
            
        return anomalies
    
    def _analyze_memory_patterns(self):
        """
        Analyze memory usage patterns for anomalies using ML and statistical methods
        
        Returns:
            list: Detected anomalies with descriptions
        """
        anomalies = []
        
        try:
            # Convert history to numpy array for analysis
            memory_history = np.array([[
                sample['usage_percent'],
                sample['swap_percent'],
                sample['high_process_count'],
                sample['anomalous_process_count'],
                sample['cached_ratio'],
                sample['anon_pages'],
                sample['slab_memory'],
                sample['fragmentation']
            ] for sample in self.history['memory']])
            
            # Check if we have a model
            if self.memory_model:
                # Use ML model for anomaly detection
                predictions = self.memory_model.predict(memory_history)
                anomaly_scores = self.memory_model.decision_function(memory_history)
                
                # Check most recent sample (last in the array)
                if predictions[-1] == -1:  # Anomaly in isolation forest
                    anomalies.append({
                        'type': 'ml_detected',
                        'description': 'Machine learning model detected memory usage anomaly',
                        'score': float(anomaly_scores[-1]),
                        'severity': 'high'
                    })
            
            # Statistical analysis
            if len(memory_history) >= 3:
                # 1. Detect rapid memory consumption
                mem_usage = memory_history[:, 0]  # First column is usage_percent
                if mem_usage[-1] > 85 and mem_usage[-1] > mem_usage[-2] * 1.3:
                    anomalies.append({
                        'type': 'memory_spike',
                        'description': f'Rapid memory consumption: {mem_usage[-2]:.1f}% -> {mem_usage[-1]:.1f}%',
                        'severity': 'high'
                    })
                
                # 2. Detect swap exhaustion (potential for system instability)
                swap_usage = memory_history[:, 1]  # Second column is swap_percent
                if swap_usage[-1] > 90 and swap_usage[-1] > swap_usage[0] + 40:
                    anomalies.append({
                        'type': 'swap_exhaustion',
                        'description': f'Swap space nearly exhausted: {swap_usage[-1]:.1f}% used',
                        'severity': 'critical'
                    })
                
                # 3. Detect unusual increase in anonymous memory (often malicious processes)
                anon_pages = memory_history[:, 5]  # Sixth column is anon_pages
                if anon_pages[-1] > anon_pages[-2] * 1.5:
                    anomalies.append({
                        'type': 'anon_memory_spike',
                        'description': 'Unusual increase in anonymous memory pages',
                        'severity': 'medium'
                    })
                
                # 4. Detect fragmentation issues that could indicate memory leaks
                fragmentation = memory_history[:, 7]  # Eighth column is fragmentation
                if fragmentation[-1] > 8 and fragmentation[-1] > np.mean(fragmentation[:-1]) * 1.5:
                    anomalies.append({
                        'type': 'memory_fragmentation',
                        'description': f'Increasing memory fragmentation: index {fragmentation[-1]:.2f}',
                        'severity': 'medium'
                    })
                
                # 5. Detect unusual kernel memory usage (slab)
                slab_memory = memory_history[:, 6]  # Seventh column is slab_memory
                if slab_memory[-1] > slab_memory[0] * 2:
                    anomalies.append({
                        'type': 'kernel_memory_growth',
                        'description': 'Unusual kernel memory (slab) growth',
                        'severity': 'high'
                    })
        
        except Exception as e:
            self.logger.error(f"Error analyzing memory patterns: {e}")
            
        return anomalies
    
    def _analyze_disk_patterns(self):
        """
        Analyze disk usage patterns for anomalies using ML and statistical methods
        
        Returns:
            list: Detected anomalies with descriptions
        """
        anomalies = []
        
        try:
            # Convert history to numpy array for analysis
            disk_history = np.array([[
                sample['avg_usage_percent'],
                sample['anomalous_fs_count'],
                sample['suspicious_dir_count'],
                sample['hidden_file_count'],
                sample['large_file_count'],
                sample['suspicious_growth'],
                sample['permission_issue_count'],
                sample['modified_config_count']
            ] for sample in self.history['disk']])
            
            # Check if we have a model
            if self.disk_model:
                # Use ML model for anomaly detection
                predictions = self.disk_model.predict(disk_history)
                anomaly_scores = self.disk_model.decision_function(disk_history)
                
                # Check most recent sample (last in the array)
                if predictions[-1] == -1:  # Anomaly in isolation forest
                    anomalies.append({
                        'type': 'ml_detected',
                        'description': 'Machine learning model detected disk usage anomaly',
                        'score': float(anomaly_scores[-1]),
                        'severity': 'high'
                    })
            
            # Statistical analysis
            if len(disk_history) >= 3:
                # 1. Detect rapid disk space consumption
                disk_usage = disk_history[:, 0]  # First column is avg_usage_percent
                if disk_usage[-1] > 85 and disk_usage[-1] > disk_usage[-2] * 1.2:
                    anomalies.append({
                        'type': 'disk_space_spike',
                        'description': f'Rapid disk space consumption: {disk_usage[-2]:.1f}% -> {disk_usage[-1]:.1f}%',
                        'severity': 'high'
                    })
                
                # 2. Detect appearance of new hidden files
                hidden_files = disk_history[:, 3]  # Fourth column is hidden_file_count
                if hidden_files[-1] > hidden_files[-2]:
                    anomalies.append({
                        'type': 'new_hidden_files',
                        'description': f'New hidden files detected: {int(hidden_files[-1] - hidden_files[-2])} file(s)',
                        'severity': 'high'
                    })
                
                # 3. Detect suspicious directory changes
                suspicious_dirs = disk_history[:, 2]  # Third column is suspicious_dir_count
                if suspicious_dirs[-1] > suspicious_dirs[-2]:
                    anomalies.append({
                        'type': 'new_suspicious_directories',
                        'description': f'New suspicious directories: {int(suspicious_dirs[-1] - suspicious_dirs[-2])} directory(s)',
                        'severity': 'high'
                    })
                
                # 4. Detect permission issues that might indicate compromise
                permission_issues = disk_history[:, 6]  # Seventh column is permission_issue_count
                if permission_issues[-1] > permission_issues[-2]:
                    anomalies.append({
                        'type': 'new_permission_issues',
                        'description': f'New permission security issues: {int(permission_issues[-1] - permission_issues[-2])} issue(s)',
                        'severity': 'critical'
                    })
                
                # 5. Detect configuration file modifications
                config_mods = disk_history[:, 7]  # Eighth column is modified_config_count
                if config_mods[-1] > config_mods[-2]:
                    anomalies.append({
                        'type': 'config_modifications',
                        'description': f'Configuration files modified: {int(config_mods[-1] - config_mods[-2])} file(s)',
                        'severity': 'high'
                    })
        
        except Exception as e:
            self.logger.error(f"Error analyzing disk patterns: {e}")
            
        return anomalies
    
    def _analyze_cross_resource_correlations(self):
        """
        Analyze correlations between different resource types
        
        Returns:
            list: Detected correlation anomalies
        """
        anomalies = []
        
        try:
            if len(self.history['timestamps']) >= 5:
                # Get the most recent values for each resource
                cpu_data = np.array([sample['total_usage'] for sample in self.history['cpu']])
                memory_data = np.array([sample['usage_percent'] for sample in self.history['memory']])
                disk_data = np.array([sample['avg_usage_percent'] for sample in self.history['disk']])
                
                # Calculate correlations
                cpu_mem_corr = np.corrcoef(cpu_data, memory_data)[0, 1]
                cpu_disk_corr = np.corrcoef(cpu_data, disk_data)[0, 1]
                mem_disk_corr = np.corrcoef(memory_data, disk_data)[0, 1]
                
                # Anomaly patterns:
                
                # 1. High CPU with decreasing memory (memory leak or resource exhaustion)
                if cpu_data[-1] > 80 and np.mean(cpu_data[-3:]) > np.mean(cpu_data[:-3]) and \
                   np.mean(memory_data[-3:]) < np.mean(memory_data[:-3]):
                    anomalies.append({
                        'type': 'cpu_memory_divergence',
                        'description': 'High CPU with decreasing available memory (possible resource exhaustion)',
                        'severity': 'high'
                    })
                
                # 2. High disk I/O without corresponding CPU (covert data exfiltration)
                io_wait = np.array([sample.get('io_wait', 0) for sample in self.history['cpu']])
                if np.mean(io_wait[-3:]) > 20 and np.mean(cpu_data[-3:]) < 50:
                    anomalies.append({
                        'type': 'disk_io_anomaly',
                        'description': 'High disk I/O without corresponding CPU usage (possible data exfiltration)',
                        'severity': 'critical'
                    })
                
                # 3. Strong inverse correlation between CPU and memory (unusual)
                if -0.8 < cpu_mem_corr < -0.5:
                    anomalies.append({
                        'type': 'inverse_correlation',
                        'description': f'Unusual inverse correlation between CPU and memory usage (r={cpu_mem_corr:.2f})',
                        'severity': 'medium'
                    })
                
                # 4. Extremely high correlation between all three (potential coordinated attack)
                if cpu_mem_corr > 0.95 and cpu_disk_corr > 0.95 and mem_disk_corr > 0.95:
                    anomalies.append({
                        'type': 'coordinated_resource_usage',
                        'description': 'Unusually perfect correlation between all resource types (potential coordinated attack)',
                        'severity': 'high'
                    })
        
        except Exception as e:
            self.logger.error(f"Error analyzing resource correlations: {e}")
            
        return anomalies
    
    def _analyze_trends(self):
        """
        Analyze long-term trends in resource usage
        
        Returns:
            dict: Trend analysis results
        """
        result = {
            'cpu_trend': 'stable',
            'memory_trend': 'stable',
            'disk_trend': 'stable',
            'is_anomalous': False
        }
        
        try:
            # Need at least 5 data points for trend analysis
            if len(self.history['timestamps']) >= 5:
                # Calculate trends using linear regression
                cpu_data = np.array([sample['total_usage'] for sample in self.history['cpu']])
                memory_data = np.array([sample['usage_percent'] for sample in self.history['memory']])
                disk_data = np.array([sample['avg_usage_percent'] for sample in self.history['disk']])
                time_data = np.array(self.history['timestamps'])
                
                # Normalize time to avoid numerical issues
                time_norm = (time_data - time_data[0]) / (time_data[-1] - time_data[0] + 0.001)
                
                # Calculate slopes
                cpu_slope = np.polyfit(time_norm, cpu_data, 1)[0]
                memory_slope = np.polyfit(time_norm, memory_data, 1)[0]
                disk_slope = np.polyfit(time_norm, disk_data, 1)[0]
                
                # Add slopes to result
                result['cpu_slope'] = float(cpu_slope)
                result['memory_slope'] = float(memory_slope)
                result['disk_slope'] = float(disk_slope)
                
                # Interpret CPU trend
                if cpu_slope > 20:
                    result['cpu_trend'] = 'rapidly_increasing'
                    result['is_anomalous'] = True
                elif cpu_slope > 10:
                    result['cpu_trend'] = 'increasing'
                elif cpu_slope < -10:
                    result['cpu_trend'] = 'decreasing'
                
                # Interpret memory trend
                if memory_slope > 15:
                    result['memory_trend'] = 'rapidly_increasing'
                    result['is_anomalous'] = True
                elif memory_slope > 5:
                    result['memory_trend'] = 'increasing'
                elif memory_slope < -5:
                    result['memory_trend'] = 'decreasing'
                
                # Interpret disk trend
                if disk_slope > 10:
                    result['disk_trend'] = 'rapidly_increasing'
                    result['is_anomalous'] = True
                elif disk_slope > 3:
                    result['disk_trend'] = 'increasing'
                elif disk_slope < -1:
                    result['disk_trend'] = 'decreasing'
                
                # Check for convergence (multiple resources increasing simultaneously)
                if (cpu_slope > 10 and memory_slope > 5 and disk_slope > 3):
                    result['convergence'] = 'all_resources_increasing'
                    result['is_anomalous'] = True
        
        except Exception as e:
            self.logger.error(f"Error analyzing resource trends: {e}")
            result['error'] = str(e)
            
        return result
    
    def train_models(self, data_file=None):
        """
        Train machine learning models for anomaly detection
        
        Args:
            data_file: Optional JSON file with labeled training data
            
        Returns:
            bool: True if training was successful
        """
        try:
            self.logger.info("Training ML models for resource anomaly detection")
            
            # If we have enough samples, we can train from our own history
            if len(self.history['cpu']) >= 10:
                # Import here to avoid unnecessary dependencies if ML is disabled
                from sklearn.ensemble import IsolationForest
                
                # Create models
                cpu_model = IsolationForest(**self.isolation_forest_params)
                memory_model = IsolationForest(**self.isolation_forest_params)
                disk_model = IsolationForest(**self.isolation_forest_params)
                
                # Prepare data
                cpu_data = np.array([list(sample.values()) for sample in self.history['cpu']])
                memory_data = np.array([list(sample.values()) for sample in self.history['memory']])
                disk_data = np.array([list(sample.values()) for sample in self.history['disk']])
                
                # Train models
                cpu_model.fit(cpu_data)
                memory_model.fit(memory_data)
                disk_model.fit(disk_data)
                
                # Save models
                self.ml_manager.save_model(cpu_model, 'resource_cpu_anomaly')
                self.ml_manager.save_model(memory_model, 'resource_memory_anomaly')
                self.ml_manager.save_model(disk_model, 'resource_disk_anomaly')
                
                # Update model references
                self.cpu_model = cpu_model
                self.memory_model = memory_model
                self.disk_model = disk_model
                
                self.logger.info("Successfully trained resource anomaly detection models")
                return True
            
            else:
                self.logger.warning("Insufficient data for training (need at least 10 samples)")
                return False
                
        except Exception as e:
            self.logger.error(f"Error training ML models: {e}")
            return False


class SystemResourceAnalyzer:
    """Analyzes system resources for anomalies"""
    
    def __init__(self, config=None):
        """Initialize with configuration"""
        self.logger = logging.getLogger('sharpeye.resources')
        self.config = config or {}
        
        # Default thresholds
        self.cpu_threshold = self.config.get('cpu_threshold', 90)  # 90% CPU usage
        self.memory_threshold = self.config.get('memory_threshold', 90)  # 90% memory usage
        self.disk_threshold = self.config.get('disk_threshold', 90)  # 90% disk usage
        self.baseline_file = self.config.get('baseline_file', '/var/lib/sharpeye/baselines/resources.json')
        
        # Process monitoring settings from config
        self.process_config = self.config.get('processes', {})
        self.high_cpu_threshold = self.process_config.get('high_cpu_threshold', 80)  # CPU % to consider high
        self.high_memory_threshold = self.process_config.get('high_memory_threshold', 50)  # Memory % to consider high
        self.suspicious_paths = self.process_config.get('suspicious_paths', [
            "/tmp", "/dev/shm", "/var/tmp", "/run/user"
        ])
        self.suspicious_commands = self.process_config.get('suspicious_commands', [
            "miner", "xmr", "crypto", "kworker", "./", "/tmp/", "curl", "wget",
            "nc ", "netcat", "ncat", "bash -i", "perl -e", "python -c", "ruby -e"
        ])
        
        # Initialize machine learning analyzer if enabled
        ml_config = self.config.get('ml_config', {})
        self.enable_ml = ml_config.get('enable', True)
        self.ml_analyzer = ResourcePatternAnalyzer(ml_config) if self.enable_ml else None
    
    def analyze(self):
        """Analyze system resources for anomalies"""
        self.logger.info("Analyzing system resources")
        
        # Perform traditional threshold-based analysis
        results = {
            'cpu': self._analyze_cpu(),
            'memory': self._analyze_memory(),
            'disk': self._analyze_disk(),
            'suspicious_processes': self._find_suspicious_processes()
        }
        
        # Add machine learning-based pattern analysis if enabled
        if self.enable_ml and self.ml_analyzer:
            # Add the current sample to the pattern analyzer's history
            self.ml_analyzer.add_sample(results)
            
            # Perform pattern analysis
            ml_results = self.ml_analyzer.analyze_patterns()
            
            # Add ML results to the output
            results['ml_analysis'] = ml_results
            
            # If ML found anomalies not caught by traditional methods,
            # update the overall anomaly status
            if ml_results.get('is_anomalous', False):
                if not results['cpu'].get('is_anomalous', False) and ml_results.get('cpu_anomalies'):
                    results['cpu']['is_anomalous'] = True
                    results['cpu']['ml_detected_anomalies'] = ml_results.get('cpu_anomalies', [])
                
                if not results['memory'].get('is_anomalous', False) and ml_results.get('memory_anomalies'):
                    results['memory']['is_anomalous'] = True
                    results['memory']['ml_detected_anomalies'] = ml_results.get('memory_anomalies', [])
                
                if not results['disk'].get('is_anomalous', False) and ml_results.get('disk_anomalies'):
                    results['disk']['is_anomalous'] = True 
                    results['disk']['ml_detected_anomalies'] = ml_results.get('disk_anomalies', [])
                
                # Add cross-resource correlations (not covered by individual resource analyzers)
                if ml_results.get('correlation_anomalies'):
                    results['correlation_anomalies'] = ml_results.get('correlation_anomalies', [])
                
                # Add resource usage trends
                if ml_results.get('trends', {}).get('is_anomalous', False):
                    results['resource_trends'] = ml_results.get('trends', {})
            
            # If we have enough history, try to train ML models (if not already trained)
            if not self.ml_analyzer.cpu_model and len(self.ml_analyzer.history['cpu']) >= 10:
                self.ml_analyzer.train_models()
        
        # Calculate overall result status
        results['is_anomalous'] = (
            results['cpu'].get('is_anomalous', False) or
            results['memory'].get('is_anomalous', False) or
            results['disk'].get('is_anomalous', False) or
            len(results['suspicious_processes']) > 0 or
            results.get('ml_analysis', {}).get('is_anomalous', False)
        )
        
        return results
    
    def _analyze_cpu(self):
        """Analyze CPU usage with advanced anomaly detection"""
        self.logger.debug("Analyzing CPU usage")
        
        # Get top CPU-consuming processes
        try:
            # Get overall CPU stats
            cpu_stats = self._get_cpu_stats()
            
            # Get detailed process information
            cmd = ["ps", "-eo", "pid,ppid,user,cmd,%mem,%cpu,etime", "--sort=-%cpu", "--no-headers"]
            output = subprocess.check_output(cmd, universal_newlines=True)
            
            # Parse the output
            processes = []
            total_cpu = 0
            anomalous_processes = []
            hidden_process_check = []
            
            for line in output.strip().split('\n'):
                if not line.strip():
                    continue
                    
                parts = line.split()
                if len(parts) >= 7:
                    # Extract data
                    pid = parts[0]
                    ppid = parts[1]
                    user = parts[2]
                    cpu_percent = float(parts[-2])
                    mem_percent = float(parts[-3])
                    
                    # Extract cmd and etime (ensuring we handle spaces in command)
                    cmd_end_index = len(parts) - 3
                    etime_index = len(parts) - 1
                    
                    etime = parts[etime_index] 
                    cmd = ' '.join(parts[3:cmd_end_index])
                    
                    # Add to total CPU
                    total_cpu += cpu_percent
                    
                    # Runtime analysis
                    runtime_anomaly = False
                    runtime_reason = ""
                    if self._is_runtime_anomalous(etime, cmd, cpu_percent):
                        runtime_anomaly = True
                        runtime_reason = f"Unusual runtime pattern: {etime}"
                    
                    # CPU/Memory ratio analysis
                    ratio_anomaly = False
                    ratio_reason = ""
                    if cpu_percent > 5 and mem_percent < 0.1:
                        ratio_anomaly = True
                        ratio_reason = f"Unusual CPU/Memory ratio: high CPU ({cpu_percent}%) with low memory ({mem_percent}%)"
                    
                    # Name disguise detection
                    name_anomaly = False
                    name_reason = ""
                    if self._check_process_name_disguise(cmd):
                        name_anomaly = True
                        name_reason = "Possible process name disguise detected"
                    
                    # Check if process is running from unusual location
                    location_anomaly = False
                    location_reason = ""
                    try:
                        exe_path = os.path.realpath(f"/proc/{pid}/exe")
                        if self._is_unusual_process_location(exe_path, cmd):
                            location_anomaly = True
                            location_reason = f"Process running from unusual location: {exe_path}"
                    except (FileNotFoundError, PermissionError):
                        pass
                    
                    # Collect process info
                    process_info = {
                        'pid': pid,
                        'ppid': ppid,
                        'user': user,
                        'command': cmd,
                        'cpu_percent': cpu_percent,
                        'mem_percent': mem_percent,
                        'runtime': etime,
                        'is_anomalous': False,
                        'anomaly_reasons': []
                    }
                    
                    # Check if this specific process is anomalous
                    if (cpu_percent > 50) or runtime_anomaly or ratio_anomaly or name_anomaly or location_anomaly:
                        process_info['is_anomalous'] = True
                        
                        if cpu_percent > 50:
                            process_info['anomaly_reasons'].append(f"High CPU usage: {cpu_percent}%")
                        
                        if runtime_anomaly:
                            process_info['anomaly_reasons'].append(runtime_reason)
                            
                        if ratio_anomaly:
                            process_info['anomaly_reasons'].append(ratio_reason)
                            
                        if name_anomaly:
                            process_info['anomaly_reasons'].append(name_reason)
                            
                        if location_anomaly:
                            process_info['anomaly_reasons'].append(location_reason)
                            
                        anomalous_processes.append(process_info)
                    
                    processes.append(process_info)
                    
                    # Add PID to list for hidden process detection
                    hidden_process_check.append(int(pid))
                    
                    # We still collect all processes but only return top ones in the result
            
            # Get all processes from /proc for hidden process detection
            hidden_processes = self._detect_hidden_processes(hidden_process_check)
            
            # Calculate load averages
            load_avg_anomaly = False
            load_avg_message = ""
            load_averages = self._get_load_averages()
            
            # Check if load average is anomalous compared to CPU count
            try:
                cpu_count = os.cpu_count() or 1
                if load_averages[0] > cpu_count * 2:  # 1-minute load more than 2x CPU count
                    load_avg_anomaly = True
                    load_avg_message = f"High load average: {load_averages[0]} on {cpu_count} CPUs"
            except Exception as e:
                self.logger.error(f"Error checking load average: {e}")
            
            # Determine if overall CPU usage is anomalous
            # Use multiple criteria
            is_anomalous = (
                total_cpu > self.cpu_threshold or 
                len(anomalous_processes) > 0 or
                len(hidden_processes) > 0 or
                load_avg_anomaly
            )
            
            # Sort processes by CPU usage and keep only top 15
            top_processes = sorted(processes, key=lambda p: p['cpu_percent'], reverse=True)[:15]
            
            return {
                'timestamp': datetime.now().isoformat(),
                'total_cpu_usage': total_cpu,
                'threshold': self.cpu_threshold,
                'is_anomalous': is_anomalous,
                'top_processes': top_processes,
                'anomalous_processes': anomalous_processes,
                'hidden_processes': hidden_processes,
                'cpu_stats': cpu_stats,
                'load_averages': load_averages,
                'load_avg_anomaly': load_avg_anomaly,
                'load_avg_message': load_avg_message if load_avg_anomaly else ""
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing CPU: {e}")
            return {
                'error': str(e),
                'is_anomalous': False
            }
    
    def _get_cpu_stats(self):
        """Get detailed CPU statistics from /proc/stat"""
        try:
            with open('/proc/stat', 'r') as f:
                cpu_line = f.readline().strip()
            
            # Parse CPU stats
            # Format: cpu user nice system idle iowait irq softirq steal guest guest_nice
            stats = cpu_line.split()
            if len(stats) >= 8:
                cpu_time = {
                    'user': int(stats[1]),
                    'nice': int(stats[2]),
                    'system': int(stats[3]),
                    'idle': int(stats[4]),
                    'iowait': int(stats[5]),
                    'irq': int(stats[6]),
                    'softirq': int(stats[7])
                }
                
                # Calculate percentages
                total = sum(cpu_time.values())
                if total > 0:
                    cpu_percent = {k: (v / total) * 100 for k, v in cpu_time.items()}
                    
                    # Check for unusual ratios that could indicate cryptominers or rootkits
                    is_unusual = (
                        (cpu_percent['system'] > 40) or  # Unusually high system time
                        (cpu_percent['iowait'] > 30) or  # High I/O wait could indicate disk encryption/decryption
                        (cpu_percent['irq'] + cpu_percent['softirq'] > 20)  # High interrupt time
                    )
                    
                    return {
                        'percentages': cpu_percent,
                        'is_unusual': is_unusual,
                        'raw_values': cpu_time
                    }
            
            return {'error': 'Unable to parse CPU statistics'}
            
        except Exception as e:
            self.logger.error(f"Error getting CPU stats: {e}")
            return {'error': str(e)}
    
    def _get_load_averages(self):
        """Get system load averages (1, 5, 15 minutes)"""
        try:
            with open('/proc/loadavg', 'r') as f:
                line = f.readline().strip()
            
            parts = line.split()
            if len(parts) >= 3:
                return [float(parts[0]), float(parts[1]), float(parts[2])]
            
            return [0, 0, 0]
            
        except Exception as e:
            self.logger.error(f"Error getting load averages: {e}")
            return [0, 0, 0]
    
    def _is_runtime_anomalous(self, etime, cmd, cpu_percent):
        """Detect anomalous runtime patterns"""
        # Skip well-known system processes
        if any(x in cmd.lower() for x in ['systemd', 'init', 'kthread', 'bash', 'zsh', 'fish', 'sshd']):
            return False
            
        # Check for very short-running high CPU processes
        if cpu_percent > 70 and '-' not in etime and etime.count(':') == 0:
            # Process running for less than 1 hour with high CPU is suspicious
            try:
                seconds = int(etime)
                if seconds < 60:  # Less than a minute
                    return True
            except ValueError:
                pass
        
        # Check for unusual runtime for known processes
        if 'chrome' in cmd.lower() and '-' in etime:
            # Browsers running for multiple days is unusual
            return True
            
        return False
    
    def _check_process_name_disguise(self, cmd):
        """Check if process name appears to be disguised as system process"""
        cmd_lower = cmd.lower()
        
        # Check for slight misspellings of common system processes
        system_processes = {
            'systemd': ['systemdd', 'systemld', 'systend', 'systmd'],
            'sshd': ['sshhd', 'sshdd', 'sssd'],
            'httpd': ['htttpd', 'htttpd', 'hhttpd'],
            'nginx': ['ngnix', 'ngninx', 'nqinx'],
            'cron': ['cr0n', 'crond', 'coron'],
            'init': ['initt', 'inlt']
        }
        
        for legit, disguises in system_processes.items():
            # Skip if it's the legitimate process
            if cmd_lower.startswith(legit):
                continue
                
            # Check for disguised names
            for disguise in disguises:
                if cmd_lower.startswith(disguise):
                    self.logger.warning(f"Possible disguised process detected: {cmd}")
                    return True
                    
        # Check for whitespace obfuscation
        if cmd.startswith(' ') or '  ' in cmd.strip():
            return True
            
        # Check for unicode lookalikes
        unicode_disguises = ['\u0430', '\u0435', '\u0440', '\u0445', '\u0456']  # Cyrillic lookalikes
        if any(c in cmd for c in unicode_disguises):
            return True
            
        return False
    
    def _is_unusual_process_location(self, exe_path, cmd):
        """Check if process is running from an unusual location"""
        # Extract process name from cmd
        cmd_parts = cmd.split()
        proc_name = os.path.basename(cmd_parts[0]) if cmd_parts else ""
        
        # Common system binaries should be in standard locations
        system_locations = ['/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/', '/usr/local/bin/']
        
        common_system_processes = ['systemd', 'init', 'bash', 'sh', 'sshd', 'cron', 'nginx', 'httpd', 'php', 'python']
        
        if any(proc in proc_name for proc in common_system_processes):
            if not any(exe_path.startswith(loc) for loc in system_locations):
                return True
                
        # Check for temporary or unusual locations
        suspicious_locations = ['/tmp/', '/dev/shm/', '/var/tmp/', '/run/user/', '/home/']
        return any(exe_path.startswith(loc) for loc in suspicious_locations)
    
    def _detect_hidden_processes(self, visible_pids):
        """Detect potential hidden processes by comparing ps output with /proc listing"""
        hidden_processes = []
        
        try:
            # Get all PIDs from /proc
            proc_pids = []
            for pid_dir in os.listdir('/proc'):
                if pid_dir.isdigit():
                    proc_pids.append(int(pid_dir))
            
            # Find PIDs that are in /proc but not in ps output
            for pid in proc_pids:
                if pid not in visible_pids:
                    # Verify it's not a kernel thread or newly created process
                    try:
                        # Check cmdline
                        with open(f'/proc/{pid}/cmdline', 'r') as f:
                            cmdline = f.read().strip()
                            
                        # Empty cmdline might indicate kernel thread, so check status
                        if not cmdline:
                            with open(f'/proc/{pid}/status', 'r') as f:
                                status_content = f.read()
                                # Skip if it's a kernel thread
                                if 'VmSize:' not in status_content:
                                    continue
                        
                        # Get more information about this potentially hidden process
                        process_info = {'pid': pid, 'cmdline': cmdline}
                        
                        # Try to get exe path
                        try:
                            exe_path = os.path.realpath(f'/proc/{pid}/exe')
                            process_info['exe_path'] = exe_path
                        except (FileNotFoundError, PermissionError):
                            process_info['exe_path'] = 'Unknown (permission denied)'
                        
                        # Get parent PID
                        try:
                            with open(f'/proc/{pid}/status', 'r') as f:
                                for line in f:
                                    if line.startswith('PPid:'):
                                        ppid = int(line.split()[1])
                                        process_info['ppid'] = ppid
                                        break
                        except Exception:
                            process_info['ppid'] = 'Unknown'
                        
                        # Add to hidden processes list
                        hidden_processes.append(process_info)
                        
                    except (FileNotFoundError, PermissionError):
                        # Process might have terminated during our check
                        continue
            
            return hidden_processes
            
        except Exception as e:
            self.logger.error(f"Error detecting hidden processes: {e}")
            return [{'error': str(e)}]
    
    def _analyze_memory(self):
        """Analyze memory usage with advanced anomaly detection"""
        self.logger.debug("Analyzing memory usage")
        
        try:
            # Get detailed memory information
            memory_info = self._get_detailed_memory_info()
            
            if 'error' in memory_info:
                self.logger.error(f"Failed to get memory information: {memory_info['error']}")
                return {
                    'error': memory_info['error'],
                    'is_anomalous': False
                }
                
            # Get memory usage by mapping types
            mapping_info = self._get_memory_mapping_stats()
            
            # Get detailed process memory information
            cmd = ["ps", "-eo", "pid,ppid,user,cmd,%mem,rss,vsz", "--sort=-%mem", "--no-headers"]
            output = subprocess.check_output(cmd, universal_newlines=True)
            
            # Parse the output
            processes = []
            anomalous_processes = []
            
            for line in output.strip().split('\n'):
                if not line.strip():
                    continue
                    
                parts = line.split()
                if len(parts) >= 7:
                    # Extract data
                    pid = parts[0]
                    ppid = parts[1]
                    user = parts[2]
                    mem_percent = float(parts[-3])
                    rss = int(parts[-2])  # Resident Set Size in KB
                    vsz = int(parts[-1])  # Virtual Memory Size in KB
                    
                    cmd_parts = parts[3:-3]
                    cmd = ' '.join(cmd_parts)
                    
                    # Calculate VSZ/RSS ratio
                    vsz_rss_ratio = vsz / rss if rss > 0 else 0
                    
                    # Check for process-specific memory anomalies
                    is_anomalous = False
                    anomaly_reasons = []
                    
                    # Check for high memory usage
                    if mem_percent > 20:  # Single process using >20% memory
                        is_anomalous = True
                        anomaly_reasons.append(f"High memory usage: {mem_percent}%")
                    
                    # Check for abnormal VSZ to RSS ratio (could indicate memory leaks)
                    if 10 < vsz_rss_ratio < 50 and rss > 1000000:  # >1GB RSS
                        is_anomalous = True
                        anomaly_reasons.append(f"Potential memory leak: VSZ/RSS ratio {vsz_rss_ratio:.1f}")
                    
                    # Check for known memory-hogging processes running with suspiciously high memory
                    if any(proc in cmd.lower() for proc in ['java', 'chrome', 'firefox']) and mem_percent > 30:
                        is_anomalous = True
                        anomaly_reasons.append(f"High memory usage for {cmd.split()[0]}: {mem_percent}%")
                    
                    # Get detailed process memory info from /proc if possible
                    detailed_proc_mem = {}
                    try:
                        detailed_proc_mem = self._get_proc_memory_details(pid)
                        
                        # Check for unusual memory mapping patterns
                        if detailed_proc_mem.get('unusual_mappings', False):
                            is_anomalous = True
                            anomaly_reasons.append("Unusual memory mappings detected")
                            
                        if detailed_proc_mem.get('high_anon_ratio', False):
                            is_anomalous = True
                            anomaly_reasons.append("Unusually high anonymous memory usage")
                    except Exception as e:
                        self.logger.debug(f"Error getting detailed memory for PID {pid}: {e}")
                    
                    # Create process info object
                    process_info = {
                        'pid': pid,
                        'ppid': ppid,
                        'user': user,
                        'command': cmd,
                        'mem_percent': mem_percent,
                        'rss': rss,
                        'vsz': vsz,
                        'vsz_rss_ratio': vsz_rss_ratio,
                        'is_anomalous': is_anomalous,
                        'anomaly_reasons': anomaly_reasons,
                        'detailed_memory': detailed_proc_mem
                    }
                    
                    processes.append(process_info)
                    
                    if is_anomalous:
                        anomalous_processes.append(process_info)
                    
                    # We still collect all processes but return only the top ones in the result
            
            # Calculate adjusted dynamic thresholds based on system profile
            dynamic_threshold = self._calculate_dynamic_memory_threshold(memory_info)
            
            # Determine if overall memory usage is anomalous (using multiple criteria)
            memory_percent = memory_info['memory_usage_percent']
            
            memory_anomalies = []
            
            # 1. Check against dynamic threshold
            if memory_percent > dynamic_threshold:
                memory_anomalies.append(f"Memory usage ({memory_percent:.1f}%) exceeds dynamic threshold ({dynamic_threshold:.1f}%)")
            
            # 2. Check swap usage
            swap_percent = memory_info.get('swap_percent', 0)
            if swap_percent > 80 and memory_info.get('swap_total', 0) > 0:
                memory_anomalies.append(f"High swap usage: {swap_percent:.1f}%")
            
            # 3. Check for abnormal cached to free ratio
            cached = memory_info.get('cached', 0)
            total = memory_info.get('total', 1)
            free = memory_info.get('free', 0)
            
            if cached > 0 and free > 0:
                cached_free_ratio = cached / free
                if cached_free_ratio > 10:  # Unusually high cached to free ratio
                    memory_anomalies.append(f"Abnormal cached/free memory ratio: {cached_free_ratio:.1f}")
            
            # 4. Check for unusual slab memory usage
            slab = memory_info.get('slab', 0)
            if slab / total > 0.20:  # Slab using more than 20% of memory
                memory_anomalies.append(f"High kernel slab memory usage: {(slab/total*100):.1f}%")
            
            # 5. Check for unusual page table usage
            page_tables = memory_info.get('page_tables', 0)
            if page_tables / total > 0.05:  # Page tables using more than 5% of memory
                memory_anomalies.append(f"High page table memory usage: {(page_tables/total*100):.1f}%")
            
            # 6. Check if memory fragmentation is high
            if memory_info.get('fragmentation_index', 0) > 5:
                memory_anomalies.append(f"High memory fragmentation index: {memory_info['fragmentation_index']}")
            
            # Check if we found any anomalies or anomalous processes
            is_anomalous = len(memory_anomalies) > 0 or len(anomalous_processes) > 0
            
            # Sort processes by memory usage and keep only top 15
            top_processes = sorted(processes, key=lambda p: p['mem_percent'], reverse=True)[:15]
            
            return {
                'timestamp': datetime.now().isoformat(),
                'total_memory': memory_info['total'],
                'available_memory': memory_info['available'],
                'free_memory': memory_info['free'],
                'memory_usage_percent': memory_percent,
                'swap_usage_percent': swap_percent,
                'standard_threshold': self.memory_threshold,
                'dynamic_threshold': dynamic_threshold,
                'is_anomalous': is_anomalous,
                'memory_anomalies': memory_anomalies,
                'top_processes': top_processes,
                'anomalous_processes': anomalous_processes,
                'memory_details': memory_info,
                'mapping_info': mapping_info
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing memory: {e}")
            return {
                'error': str(e),
                'is_anomalous': False
            }
            
    def _get_detailed_memory_info(self):
        """Get detailed memory information from /proc/meminfo"""
        try:
            # Get memory information from /proc/meminfo
            with open('/proc/meminfo', 'r') as f:
                meminfo = f.readlines()
            
            # Initialize variables
            memory_data = {
                'total': 0,
                'free': 0,
                'available': 0,
                'cached': 0,
                'swap_total': 0,
                'swap_free': 0,
                'slab': 0,
                'page_tables': 0,
                'dirty': 0,
                'writeback': 0,
                'anon_pages': 0,
                'mapped': 0,
                'shmem': 0,
                'kreclaimable': 0,
                'kernel_stack': 0,
                'hugepages_total': 0,
                'hugepages_free': 0,
                'memory_usage_percent': 0,
                'swap_percent': 0,
                'fragmentation_index': 0
            }
            
            # Parse memory info
            for line in meminfo:
                # Extract key-value pairs
                parts = line.split(':')
                if len(parts) >= 2:
                    key = parts[0].strip()
                    value_parts = parts[1].strip().split()
                    value = int(value_parts[0])  # Value in kB
                    
                    # Map common keys to our structure
                    if key == 'MemTotal':
                        memory_data['total'] = value
                    elif key == 'MemFree':
                        memory_data['free'] = value
                    elif key == 'MemAvailable':
                        memory_data['available'] = value
                    elif key == 'Cached':
                        memory_data['cached'] = value
                    elif key == 'SwapTotal':
                        memory_data['swap_total'] = value
                    elif key == 'SwapFree':
                        memory_data['swap_free'] = value
                    elif key == 'Slab':
                        memory_data['slab'] = value
                    elif key == 'PageTables':
                        memory_data['page_tables'] = value
                    elif key == 'Dirty':
                        memory_data['dirty'] = value
                    elif key == 'Writeback':
                        memory_data['writeback'] = value
                    elif key == 'AnonPages':
                        memory_data['anon_pages'] = value
                    elif key == 'Mapped':
                        memory_data['mapped'] = value
                    elif key == 'Shmem':
                        memory_data['shmem'] = value
                    elif key == 'KReclaimable':
                        memory_data['kreclaimable'] = value
                    elif key == 'KernelStack':
                        memory_data['kernel_stack'] = value
                    elif key == 'HugePages_Total':
                        memory_data['hugepages_total'] = value
                    elif key == 'HugePages_Free':
                        memory_data['hugepages_free'] = value
            
            # Calculate derived metrics
            total = memory_data['total']
            if total > 0:
                # Memory usage percentage
                used_memory = total - memory_data['available']
                memory_data['memory_usage_percent'] = (used_memory / total) * 100
                
                # Swap usage percentage
                if memory_data['swap_total'] > 0:
                    swap_used = memory_data['swap_total'] - memory_data['swap_free']
                    memory_data['swap_percent'] = (swap_used / memory_data['swap_total']) * 100
                
                # Memory fragmentation index - ratio between MemFree and MemAvailable
                # Higher values indicate more fragmentation
                if memory_data['free'] > 0:
                    memory_data['fragmentation_index'] = memory_data['available'] / memory_data['free']
            
            return memory_data
            
        except Exception as e:
            self.logger.error(f"Error getting detailed memory info: {e}")
            return {'error': str(e)}
            
    def _get_memory_mapping_stats(self):
        """Analyze memory mappings across processes"""
        try:
            anonymous_total = 0
            file_mapped_total = 0
            shared_total = 0
            mapping_counts = {}
            suspicious_mappings = []
            
            # Get list of all processes
            process_dirs = [d for d in os.listdir('/proc') if d.isdigit()]
            
            for pid in process_dirs:
                try:
                    # Check maps file
                    maps_file = f'/proc/{pid}/maps'
                    if os.path.exists(maps_file):
                        with open(maps_file, 'r') as f:
                            maps_data = f.readlines()
                        
                        # Process specific mappings
                        proc_anonymous = 0
                        proc_file_mapped = 0
                        proc_shared = 0
                        
                        for line in maps_data:
                            parts = line.split()
                            if len(parts) >= 6:
                                # Example: 7fc4c3d92000-7fc4c3f92000 rw-p 00000000 00:00 0
                                addr_range = parts[0]
                                perms = parts[1]
                                offset = parts[2]
                                dev = parts[3]
                                inode = parts[4]
                                pathname = ' '.join(parts[5:]) if len(parts) > 5 else ""
                                
                                # Calculate size of mapping
                                addr_start, addr_end = addr_range.split('-')
                                size = int(addr_end, 16) - int(addr_start, 16)
                                
                                # Track mapping types
                                if dev == "00:00" and inode == "0":
                                    # Anonymous mapping
                                    proc_anonymous += size
                                    anonymous_total += size
                                elif inode != "0":
                                    # File mapping
                                    proc_file_mapped += size
                                    file_mapped_total += size
                                
                                # Track shared memory
                                if 's' in perms:
                                    proc_shared += size
                                    shared_total += size
                                
                                # Track unusual mappings
                                if 'x' in perms and 'w' in perms and pathname and not pathname.startswith('/'):
                                    # Executable and writable mapping that's not from a standard path
                                    suspicious_mappings.append({
                                        'pid': pid,
                                        'mapping': line.strip(),
                                        'size': size,
                                        'reason': "Executable+writable non-standard mapping"
                                    })
                                
                                # Track mapping paths
                                if pathname:
                                    if pathname in mapping_counts:
                                        mapping_counts[pathname] += 1
                                    else:
                                        mapping_counts[pathname] = 1
                
                except (IOError, PermissionError):
                    # Skip processes we can't access
                    continue
            
            # Create summary data
            total_mapped = anonymous_total + file_mapped_total
            
            return {
                'anonymous_total': anonymous_total,
                'file_mapped_total': file_mapped_total,
                'shared_total': shared_total,
                'total_mapped': total_mapped,
                'anonymous_percent': (anonymous_total / total_mapped * 100) if total_mapped > 0 else 0,
                'file_mapped_percent': (file_mapped_total / total_mapped * 100) if total_mapped > 0 else 0,
                'common_mappings': sorted(mapping_counts.items(), key=lambda x: x[1], reverse=True)[:20],
                'suspicious_mappings': suspicious_mappings
            }
                
        except Exception as e:
            self.logger.error(f"Error analyzing memory mappings: {e}")
            return {'error': str(e)}
            
    def _get_proc_memory_details(self, pid):
        """Get detailed memory information for a specific process"""
        result = {
            'anon_kb': 0,
            'file_kb': 0,
            'shared_kb': 0,
            'unusual_mappings': False,
            'high_anon_ratio': False
        }
        
        try:
            # Read status file
            with open(f'/proc/{pid}/status', 'r') as f:
                status_data = f.readlines()
                
            # Extract relevant information
            for line in status_data:
                if line.startswith('VmRSS:'):
                    result['rss_kb'] = int(line.split()[1])
                elif line.startswith('RssAnon:'):
                    result['anon_kb'] = int(line.split()[1])
                elif line.startswith('RssFile:'):
                    result['file_kb'] = int(line.split()[1])
                elif line.startswith('RssShmem:'):
                    result['shared_kb'] = int(line.split()[1])
            
            # Check maps file for unusual mappings
            with open(f'/proc/{pid}/maps', 'r') as f:
                maps_data = f.readlines()
                
            # Count mappings and check for suspicious patterns
            exec_count = 0
            write_exec_count = 0
            suspicious_path_count = 0
            
            for line in maps_data:
                parts = line.split()
                if len(parts) >= 2:
                    perms = parts[1]
                    
                    # Track executable mappings
                    if 'x' in perms:
                        exec_count += 1
                        
                        # Writable and executable is unusual
                        if 'w' in perms:
                            write_exec_count += 1
                    
                    # Check for mappings outside standard paths
                    if len(parts) >= 6:
                        path = parts[5]
                        if path and not path.startswith('/'):
                            suspicious_path_count += 1
            
            # Check for unusual patterns
            if write_exec_count > 3:
                result['unusual_mappings'] = True
                result['write_exec_count'] = write_exec_count
                
            if suspicious_path_count > 2:
                result['unusual_mappings'] = True
                result['suspicious_path_count'] = suspicious_path_count
            
            # Calculate anonymous memory ratio
            total_rss = result.get('rss_kb', 0)
            if total_rss > 0:
                anon_ratio = result['anon_kb'] / total_rss
                result['anon_ratio'] = anon_ratio
                
                # Processes with high anonymous memory (>85%) can be suspicious
                # (excluding known anon-heavy apps like browsers)
                if anon_ratio > 0.85 and total_rss > 500000:  # >500MB and >85% anonymous
                    result['high_anon_ratio'] = True
            
            return result
            
        except (IOError, PermissionError):
            return result  # Return default values if we can't access the process
        except Exception as e:
            self.logger.debug(f"Error getting process memory details for PID {pid}: {e}")
            return result
            
    def _calculate_dynamic_memory_threshold(self, memory_info):
        """Calculate a dynamic memory threshold based on system characteristics"""
        # Start with configured threshold
        base_threshold = self.memory_threshold
        
        # Get total memory in GB
        total_gb = memory_info['total'] / (1024 * 1024)  # Convert KB to GB
        
        # Adjust threshold based on total memory:
        # - Large memory systems (>16GB) can tolerate higher usage
        # - Small memory systems (<4GB) need lower thresholds
        if total_gb > 16:
            threshold_adjustment = 5  # Allow 5% more on large memory systems
        elif total_gb < 4:
            threshold_adjustment = -5  # Require 5% less on small memory systems
        else:
            threshold_adjustment = 0
            
        # Adjust for swap availability
        swap_total = memory_info.get('swap_total', 0)
        swap_free = memory_info.get('swap_free', 0)
        
        if swap_total > 0:
            swap_used_percent = ((swap_total - swap_free) / swap_total) * 100
            # If swap is heavily used, lower threshold
            if swap_used_percent > 50:
                threshold_adjustment -= 5
                
        # Adjust for memory fragmentation
        fragmentation_index = memory_info.get('fragmentation_index', 1)
        if fragmentation_index > 3:
            threshold_adjustment -= 2  # Lower threshold if memory is fragmented
            
        # Calculate final dynamic threshold with limits
        dynamic_threshold = max(50, min(95, base_threshold + threshold_adjustment))
        
        return dynamic_threshold
    
    def _analyze_disk(self):
        """Analyze disk usage with advanced anomaly detection"""
        self.logger.debug("Analyzing disk usage")
        
        try:
            # Get disk usage using df command
            cmd = ["df", "-h"]
            output = subprocess.check_output(cmd, universal_newlines=True)
            
            # Get inodes usage (to detect inode exhaustion)
            cmd_inodes = ["df", "-i"]
            output_inodes = subprocess.check_output(cmd_inodes, universal_newlines=True)
            
            # Get IO statistics
            io_stats = self._get_io_stats()
            
            # Parse df output
            filesystems = []
            anomalous_filesystems = []
            
            # Skip the header
            lines = output.strip().split('\n')[1:]
            
            for line in lines:
                parts = line.split()
                if len(parts) >= 5:
                    # Extract data
                    filesystem = parts[0]
                    size = parts[1]
                    used = parts[2]
                    available = parts[3]
                    use_percent = int(parts[4].rstrip('%'))
                    mounted_on = parts[5] if len(parts) > 5 else ""
                    
                    # Get corresponding inode information
                    inode_usage = self._get_inode_usage(output_inodes, filesystem)
                    
                    # Check if this filesystem has anomalous IO activity
                    io_anomaly = False
                    io_anomaly_reason = ""
                    
                    if filesystem in io_stats:
                        fs_io = io_stats[filesystem]
                        if fs_io.get('is_anomalous', False):
                            io_anomaly = True
                            io_anomaly_reason = fs_io.get('anomaly_reason', "Unusual IO activity")
                    
                    # Determine if filesystem is anomalous based on multiple criteria
                    # 1. Space usage above threshold
                    space_anomaly = use_percent > self.disk_threshold
                    
                    # 2. Inode usage anomaly
                    inode_anomaly = False
                    if inode_usage and inode_usage.get('use_percent', 0) > 90:
                        inode_anomaly = True
                    
                    is_anomalous = space_anomaly or inode_anomaly or io_anomaly
                    
                    # Create filesystem info object
                    fs_info = {
                        'filesystem': filesystem,
                        'size': size,
                        'used': used,
                        'available': available,
                        'use_percent': use_percent,
                        'mounted_on': mounted_on,
                        'inode_usage': inode_usage,
                        'io_stats': io_stats.get(filesystem, {}),
                        'is_anomalous': is_anomalous,
                        'anomaly_reasons': []
                    }
                    
                    # Add anomaly reasons
                    if space_anomaly:
                        fs_info['anomaly_reasons'].append(f"High space usage: {use_percent}%")
                    
                    if inode_anomaly:
                        fs_info['anomaly_reasons'].append(f"High inode usage: {inode_usage.get('use_percent')}%")
                    
                    if io_anomaly:
                        fs_info['anomaly_reasons'].append(io_anomaly_reason)
                    
                    filesystems.append(fs_info)
                    
                    if is_anomalous:
                        anomalous_filesystems.append(fs_info)
            
            # Advanced anomaly detection
            suspicious_dirs = self._find_suspicious_directories(anomalous_filesystems)
            hidden_files = self._find_hidden_files()
            large_files = self._find_unusually_large_files(anomalous_filesystems)
            suspicious_growth = self._check_disk_growth_rate(filesystems)
            permission_issues = self._check_permission_issues()
            recently_modified_config = self._check_recently_modified_config_files()
            
            # Find largest directories if we have any anomalous filesystems
            large_directories = []
            
            if anomalous_filesystems:
                for fs in anomalous_filesystems:
                    mount_point = fs['mounted_on']
                    
                    # Skip some mount points
                    if mount_point in ['/proc', '/sys', '/dev']:
                        continue
                    
                    try:
                        # Find large directories
                        cmd = ["du", "-h", "--max-depth=3", mount_point]
                        du_output = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.PIPE)
                        
                        # Get the top 5 largest directories
                        dirs = []
                        for line in du_output.strip().split('\n'):
                            if not line.strip():
                                continue
                                
                            parts = line.split()
                            if len(parts) >= 2:
                                size = parts[0]
                                directory = ' '.join(parts[1:])
                                
                                dirs.append({
                                    'size': size,
                                    'size_bytes': self._human_to_bytes(size),
                                    'directory': directory
                                })
                        
                        # Sort by size
                        dirs.sort(key=lambda x: x['size_bytes'], reverse=True)
                        
                        # Add directories to the list
                        large_directories.append({
                            'mount_point': mount_point,
                            'largest_dirs': dirs[:10]  # Keep top 10 instead of 5
                        })
                        
                    except Exception as e:
                        self.logger.warning(f"Error finding large directories on {mount_point}: {e}")
            
            # Determine if overall disk state is anomalous
            is_anomalous = (
                len(anomalous_filesystems) > 0 or
                len(suspicious_dirs) > 0 or
                len(hidden_files) > 0 or
                suspicious_growth['is_suspicious'] or
                len(permission_issues) > 0 or
                len(recently_modified_config) > 0
            )
            
            return {
                'timestamp': datetime.now().isoformat(),
                'filesystems': filesystems,
                'anomalous_filesystems': anomalous_filesystems,
                'threshold': self.disk_threshold,
                'is_anomalous': is_anomalous,
                'large_directories': large_directories,
                'suspicious_directories': suspicious_dirs,
                'hidden_files': hidden_files,
                'large_files': large_files,
                'disk_growth': suspicious_growth,
                'permission_issues': permission_issues,
                'recently_modified_config': recently_modified_config
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing disk: {e}")
            return {
                'error': str(e),
                'is_anomalous': False
            }
            
    def _get_inode_usage(self, df_inodes_output, filesystem):
        """Extract inode usage from df -i output for a specific filesystem"""
        for line in df_inodes_output.strip().split('\n')[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 5 and parts[0] == filesystem:
                # Extract inode information
                inodes_total = int(parts[1])
                inodes_used = int(parts[2])
                inodes_free = int(parts[3])
                inodes_use_percent = int(parts[4].rstrip('%'))
                
                return {
                    'total': inodes_total,
                    'used': inodes_used,
                    'free': inodes_free,
                    'use_percent': inodes_use_percent
                }
        
        return None
    
    def _get_io_stats(self):
        """Get IO statistics from /proc/diskstats"""
        io_stats = {}
        
        try:
            # Read disk stats
            with open('/proc/diskstats', 'r') as f:
                diskstats = f.readlines()
            
            # Get device to mount point mapping
            mount_info = {}
            try:
                with open('/proc/mounts', 'r') as f:
                    mounts = f.readlines()
                
                for line in mounts:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0].startswith('/dev/'):
                        device = parts[0].split('/')[-1]
                        mount_point = parts[1]
                        mount_info[device] = mount_point
            except Exception as e:
                self.logger.error(f"Error reading mount information: {e}")
            
            # Process disk stats (format varies by kernel version)
            for line in diskstats:
                parts = line.split()
                if len(parts) >= 14:  # Kernel 2.6+
                    device_name = parts[2]
                    
                    # Skip non-physical devices
                    if device_name.startswith('loop') or device_name.startswith('ram'):
                        continue
                    
                    # Extract metrics
                    reads_completed = int(parts[3])
                    reads_merged = int(parts[4])
                    sectors_read = int(parts[5])
                    read_time_ms = int(parts[6])
                    writes_completed = int(parts[7])
                    writes_merged = int(parts[8])
                    sectors_written = int(parts[9])
                    write_time_ms = int(parts[10])
                    
                    # Newer kernel versions have additional fields
                    io_in_progress = int(parts[11]) if len(parts) >= 12 else 0
                    io_time_ms = int(parts[12]) if len(parts) >= 13 else 0
                    
                    # Calculate derived metrics
                    total_io = reads_completed + writes_completed
                    total_time_ms = read_time_ms + write_time_ms
                    
                    # Check for anomalies (these thresholds should be calibrated)
                    is_anomalous = False
                    anomaly_reason = ""
                    
                    # High time per IO can indicate a slow or failing device
                    if total_io > 1000 and total_time_ms / total_io > 100:  # >100ms per IO
                        is_anomalous = True
                        anomaly_reason = f"High IO time ({total_time_ms/total_io:.1f}ms per IO)"
                    
                    # High write to read ratio can indicate ransomware or data exfiltration
                    if reads_completed > 0 and writes_completed / reads_completed > 10:
                        is_anomalous = True
                        anomaly_reason = f"Unusual write to read ratio ({writes_completed/reads_completed:.1f})"
                    
                    # High IO in progress can indicate IO bottleneck
                    if io_in_progress > 100:
                        is_anomalous = True
                        anomaly_reason = f"High pending IO operations ({io_in_progress})"
                    
                    # Create device stats
                    device_stats = {
                        'reads_completed': reads_completed,
                        'writes_completed': writes_completed,
                        'sectors_read': sectors_read,
                        'sectors_written': sectors_written,
                        'read_time_ms': read_time_ms,
                        'write_time_ms': write_time_ms,
                        'io_in_progress': io_in_progress,
                        'io_time_ms': io_time_ms,
                        'is_anomalous': is_anomalous,
                        'anomaly_reason': anomaly_reason
                    }
                    
                    # Find the mount point for this device
                    mount_point = mount_info.get(device_name, None)
                    device_path = f"/dev/{device_name}"
                    
                    # Store under both device path and mount point if available
                    io_stats[device_path] = device_stats
                    if mount_point:
                        io_stats[mount_point] = device_stats
            
            return io_stats
            
        except Exception as e:
            self.logger.error(f"Error getting IO stats: {e}")
            return {}
    
    def _find_suspicious_processes(self):
        """Find suspicious processes based on various heuristics"""
        self.logger.debug("Looking for suspicious processes")
        suspicious = []

        try:
            # Get process list with command details
            cmd = ["ps", "-eo", "pid,ppid,user,cmd,%cpu,%mem", "--no-headers"]
            output = subprocess.check_output(cmd, universal_newlines=True)
            
            for line in output.strip().split('\n'):
                if not line.strip():
                    continue
                    
                # Extract process information
                parts = line.split(None, 5)  # Split up to 6 parts on whitespace
                if len(parts) >= 6:
                    pid = parts[0]
                    ppid = parts[1]
                    user = parts[2]
                    command = ' '.join(parts[3:-2])  # Command is everything except the last two fields
                    
                    try:
                        cpu_percent = float(parts[-2])
                        mem_percent = float(parts[-1])
                    except ValueError:
                        cpu_percent = 0.0
                        mem_percent = 0.0
                    
                    # Check for suspicious location
                    location_suspicious = False
                    location_reason = ""
                    try:
                        exe_path = os.path.realpath(f"/proc/{pid}/exe")
                        if self._is_unusual_process_location(exe_path, command):
                            location_suspicious = True
                            location_reason = f"Process running from suspicious location: {exe_path}"
                    except (FileNotFoundError, PermissionError):
                        pass
                    
                    # Check for suspicious command
                    cmd_suspicious = False
                    cmd_reason = ""
                    if any(pattern in command.lower() for pattern in self.suspicious_commands):
                        cmd_suspicious = True
                        matching_patterns = [p for p in self.suspicious_commands if p in command.lower()]
                        cmd_reason = f"Suspicious command pattern: {', '.join(matching_patterns)}"
                    
                    # Check for disguised names
                    disguise_suspicious = False
                    disguise_reason = ""
                    if self._check_process_name_disguise(command):
                        disguise_suspicious = True
                        disguise_reason = "Possible disguised process name"
                    
                    # Check for high resource usage
                    resource_suspicious = False
                    resource_reason = ""
                    if cpu_percent > self.high_cpu_threshold:
                        resource_suspicious = True
                        resource_reason = f"High CPU usage: {cpu_percent}%"
                    elif mem_percent > self.high_memory_threshold:
                        resource_suspicious = True
                        resource_reason = f"High memory usage: {mem_percent}%"
                    
                    # If any check flagged this process as suspicious, add it to the list
                    if location_suspicious or cmd_suspicious or disguise_suspicious or resource_suspicious:
                        process_info = {
                            'pid': pid,
                            'ppid': ppid,
                            'user': user,
                            'command': command,
                            'cpu_percent': cpu_percent,
                            'mem_percent': mem_percent,
                            'reasons': []
                        }
                        
                        if location_suspicious:
                            process_info['reasons'].append(location_reason)
                        
                        if cmd_suspicious:
                            process_info['reasons'].append(cmd_reason)
                        
                        if disguise_suspicious:
                            process_info['reasons'].append(disguise_reason)
                        
                        if resource_suspicious:
                            process_info['reasons'].append(resource_reason)
                        
                        suspicious.append(process_info)
        
        except Exception as e:
            self.logger.error(f"Error finding suspicious processes: {e}")
        
        return suspicious
        
    def establish_baseline(self):
        """Create a baseline of normal system resource usage"""
        self.logger.info("Establishing system resource baseline")
        
        try:
            # Gather current resource information
            cpu_info = self._analyze_cpu()
            memory_info = self._analyze_memory()
            disk_info = self._analyze_disk()
            
            # Create baseline data
            baseline = {
                'timestamp': datetime.now().isoformat(),
                'cpu': cpu_info,
                'memory': memory_info,
                'disk': disk_info
            }
            
            # Ensure directory exists
            baseline_dir = os.path.dirname(self.baseline_file)
            if baseline_dir and not os.path.exists(baseline_dir):
                os.makedirs(baseline_dir, exist_ok=True)
            
            # Write baseline to file
            with open(self.baseline_file, 'w') as f:
                json.dump(baseline, f, indent=2)
            
            self.logger.info(f"Baseline saved to {self.baseline_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error establishing baseline: {e}")
            return False
    
    def compare_baseline(self):
        """Compare current system state with the baseline"""
        self.logger.info("Comparing system state with baseline")
        
        result = {
            'timestamp': datetime.now().isoformat(),
            'has_deviations': False,
            'cpu_deviations': [],
            'memory_deviations': [],
            'disk_deviations': [],
            'new_processes': []
        }
        
        try:
            # Check if baseline file exists
            if not os.path.exists(self.baseline_file):
                self.logger.warning(f"Baseline file not found: {self.baseline_file}")
                result['error'] = "Baseline file not found"
                return result
            
            # Load baseline data
            with open(self.baseline_file, 'r') as f:
                baseline = json.load(f)
            
            # Get current system state
            current_cpu = self._analyze_cpu()
            current_memory = self._analyze_memory()
            current_disk = self._analyze_disk()
            
            # Compare CPU metrics
            baseline_cpu = baseline.get('cpu', {})
            baseline_cpu_usage = baseline_cpu.get('total_cpu_usage', 0)
            current_cpu_usage = current_cpu.get('total_cpu_usage', 0)
            
            if current_cpu_usage > baseline_cpu_usage * 1.5:
                result['cpu_deviations'].append(f"CPU usage increased significantly: {baseline_cpu_usage:.1f}% → {current_cpu_usage:.1f}%")
                result['has_deviations'] = True
            
            # Compare memory metrics
            baseline_memory = baseline.get('memory', {})
            baseline_memory_usage = baseline_memory.get('memory_usage_percent', 0)
            current_memory_usage = current_memory.get('memory_usage_percent', 0)
            
            if current_memory_usage > baseline_memory_usage * 1.3:
                result['memory_deviations'].append(f"Memory usage increased significantly: {baseline_memory_usage:.1f}% → {current_memory_usage:.1f}%")
                result['has_deviations'] = True
            
            # Compare swap usage
            baseline_swap = baseline_memory.get('swap_usage_percent', 0)
            current_swap = current_memory.get('swap_usage_percent', 0)
            
            if current_swap > baseline_swap + 30:  # 30% increase in swap usage
                result['memory_deviations'].append(f"Swap usage increased significantly: {baseline_swap:.1f}% → {current_swap:.1f}%")
                result['has_deviations'] = True
            
            # Compare disk metrics
            baseline_filesystems = baseline.get('disk', {}).get('filesystems', [])
            current_filesystems = current_disk.get('filesystems', [])
            
            # Create filesystem mapping for easy comparison
            baseline_fs_map = {fs.get('filesystem'): fs for fs in baseline_filesystems}
            
            for fs in current_filesystems:
                fs_name = fs.get('filesystem')
                if fs_name in baseline_fs_map:
                    baseline_fs = baseline_fs_map[fs_name]
                    baseline_usage = baseline_fs.get('use_percent', 0)
                    current_usage = fs.get('use_percent', 0)
                    
                    if current_usage > baseline_usage + 20:  # 20% absolute increase
                        result['disk_deviations'].append(
                            f"Disk usage increased significantly for {fs_name} ({fs.get('mounted_on', '')}): "
                            f"{baseline_usage}% → {current_usage}%"
                        )
                        result['has_deviations'] = True
            
            # Compare process lists (looking for new processes)
            baseline_processes = set()
            for proc_list in [baseline_cpu.get('top_processes', []), baseline_memory.get('top_processes', [])][:5]:
                for proc in proc_list:
                    cmd = proc.get('command', '')
                    if cmd:
                        baseline_processes.add(cmd)
            
            current_processes = set()
            new_processes = []
            
            for proc_list in [current_cpu.get('top_processes', []), current_memory.get('top_processes', [])][:5]:
                for proc in proc_list:
                    cmd = proc.get('command', '')
                    if cmd:
                        current_processes.add(cmd)
                        if cmd not in baseline_processes and proc.get('is_anomalous', False):
                            new_processes.append(proc)
            
            # Add new anomalous processes to the results
            if new_processes:
                result['new_processes'] = new_processes
                result['cpu_deviations'].append(f"Detected {len(new_processes)} new anomalous processes")
                result['has_deviations'] = True
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error comparing with baseline: {e}")
            result['error'] = str(e)
            return result
    
    def _find_suspicious_directories(self, anomalous_filesystems):
        """Find suspicious directories with unusual permissions or contents"""
        suspicious = []
        
        try:
            # Only check filesystems that are above threshold
            scan_dirs = []
            for fs in anomalous_filesystems:
                mount_point = fs.get('mounted_on')
                if mount_point and mount_point not in ['/proc', '/sys', '/dev']:
                    scan_dirs.append(mount_point)
            
            # Add specific sensitive directories
            sensitive_dirs = ['/tmp', '/var/tmp', '/dev/shm', '/var/www']
            for directory in sensitive_dirs:
                if os.path.exists(directory) and directory not in scan_dirs:
                    scan_dirs.append(directory)
            
            # Define suspicious patterns
            suspicious_names = [
                'crypto', 'miner', 'xmr', 'monero', '.hidden', '.secret', 
                '.private', '.ssh2', '.exploit', 'rootkit', 'backdoor'
            ]
            
            # Scan each directory for suspicious patterns
            for scan_dir in scan_dirs:
                try:
                    # Get executable files in temp directories
                    if scan_dir in ['/tmp', '/var/tmp', '/dev/shm']:
                        cmd = ["find", scan_dir, "-type", "f", "-executable"]
                        try:
                            output = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.PIPE)
                            executable_files = output.strip().split('\n')
                            
                            for file_path in executable_files:
                                if file_path and os.path.exists(file_path):
                                    # Get file info
                                    try:
                                        file_stat = os.stat(file_path)
                                        file_size = file_stat.st_size
                                        file_perms = file_stat.st_mode
                                        file_owner = file_stat.st_uid
                                        
                                        suspicious.append({
                                            'path': file_path,
                                            'type': 'executable',
                                            'size': file_size,
                                            'reason': f"Executable file in temporary directory"
                                        })
                                    except (OSError, PermissionError):
                                        pass
                        except subprocess.CalledProcessError:
                            # Skip if find fails
                            pass
                    
                    # Check for world-writable directories
                    cmd = ["find", scan_dir, "-type", "d", "-perm", "-0002", "-not", "-path", "*/proc/*", "-not", "-path", "*/sys/*"]
                    try:
                        output = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.PIPE)
                        writable_dirs = output.strip().split('\n')
                        
                        for dir_path in writable_dirs:
                            if dir_path and os.path.exists(dir_path):
                                # Filter out expected writable dirs
                                if not any(dir_path.startswith(d) for d in ['/tmp', '/var/tmp']):
                                    suspicious.append({
                                        'path': dir_path,
                                        'type': 'directory',
                                        'reason': f"World-writable directory"
                                    })
                    except subprocess.CalledProcessError:
                        # Skip if find fails
                        pass
                    
                    # Check for suspicious directory names
                    for name in suspicious_names:
                        cmd = ["find", scan_dir, "-type", "d", "-name", f"*{name}*", "-not", "-path", "*/proc/*", "-not", "-path", "*/sys/*"]
                        try:
                            output = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.PIPE)
                            matching_dirs = output.strip().split('\n')
                            
                            for dir_path in matching_dirs:
                                if dir_path and os.path.exists(dir_path):
                                    suspicious.append({
                                        'path': dir_path,
                                        'type': 'directory',
                                        'reason': f"Suspicious directory name containing '{name}'"
                                    })
                        except subprocess.CalledProcessError:
                            # Skip if find fails
                            pass
                
                except Exception as e:
                    self.logger.warning(f"Error scanning {scan_dir} for suspicious directories: {e}")
            
            # Deduplicate results
            unique_paths = set()
            result = []
            
            for item in suspicious:
                if item['path'] and item['path'] not in unique_paths and item['path'] != '':
                    unique_paths.add(item['path'])
                    result.append(item)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error finding suspicious directories: {e}")
            return []
    
    def _find_hidden_files(self):
        """Find potentially malicious hidden files in sensitive locations"""
        hidden_files = []
        
        try:
            # Sensitive locations to check for hidden files
            locations = [
                '/etc', '/bin', '/sbin', '/usr/bin', '/usr/sbin', 
                '/usr/local/bin', '/usr/local/sbin', '/var/www', 
                '/tmp', '/var/tmp', '/dev/shm'
            ]
            
            for location in locations:
                if not os.path.exists(location) or not os.path.isdir(location):
                    continue
                
                # Find hidden files but skip normal hidden config files
                cmd = ["find", location, "-name", ".*", "-type", "f", "-not", "-path", "*/\\.git/*", "-not", "-path", "*/\\.config/*"]
                try:
                    output = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.PIPE)
                    
                    for file_path in output.strip().split('\n'):
                        if not file_path or file_path == '':
                            continue
                        
                        # Skip common legitimate hidden files
                        if any(file_path.endswith(ext) for ext in ['.gitignore', '.bashrc', '.profile', '.vimrc', '.nanorc']):
                            continue
                        
                        # Check if file is executable or in temporary directory
                        is_suspicious = False
                        reason = ""
                        
                        try:
                            file_stat = os.stat(file_path)
                            
                            # Check if executable
                            if file_stat.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                                is_suspicious = True
                                reason = "Hidden executable file"
                            
                            # Check if in temporary directory
                            if any(file_path.startswith(tmp) for tmp in ['/tmp', '/var/tmp', '/dev/shm']):
                                is_suspicious = True
                                reason = "Hidden file in temporary directory"
                            
                            # Check size (small hidden files in system dirs are more suspicious)
                            if file_stat.st_size < 1000 and any(file_path.startswith(sys_dir) for sys_dir in ['/bin', '/sbin', '/usr/bin', '/usr/sbin']):
                                is_suspicious = True
                                reason = "Small hidden file in system directory"
                            
                            if is_suspicious:
                                hidden_files.append({
                                    'path': file_path,
                                    'size': file_stat.st_size,
                                    'reason': reason
                                })
                                
                        except (FileNotFoundError, PermissionError):
                            continue
                
                except subprocess.CalledProcessError:
                    # Skip if find fails
                    pass
            
            return hidden_files
            
        except Exception as e:
            self.logger.error(f"Error finding hidden files: {e}")
            return []
    
    def _find_unusually_large_files(self, anomalous_filesystems):
        """Find unusually large files in anomalous filesystems"""
        large_files = []
        
        try:
            # Only check filesystems that are above threshold
            for fs in anomalous_filesystems:
                mount_point = fs.get('mounted_on')
                if not mount_point or mount_point in ['/proc', '/sys', '/dev']:
                    continue
                
                # Use find to locate large files (>100MB)
                cmd = ["find", mount_point, "-type", "f", "-size", "+100M", "-ls"]
                try:
                    output = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.PIPE)
                    for line in output.strip().split('\n'):
                        if not line.strip():
                            continue
                        
                        parts = line.split()
                        if len(parts) >= 11:
                            size = int(parts[6])  # Size in bytes
                            file_path = ' '.join(parts[10:])  # File path
                            
                            # Skip common large files like database files, logs, etc.
                            if any(ext in file_path.lower() for ext in ['.log', '.db', '.sqlite', '.iso', '.img', '.vmdk']):
                                continue
                            
                            # Skip files in standard locations
                            if any(dir_path in file_path for dir_path in ['/usr/lib', '/usr/share', '/var/lib', '/var/cache', '/boot']):
                                continue
                            
                            # Convert size to human-readable format
                            size_human = self._bytes_to_human(size)
                            
                            large_files.append({
                                'path': file_path,
                                'size': size_human,
                                'size_bytes': size,
                                'filesystem': mount_point
                            })
                except subprocess.CalledProcessError:
                    # Skip if find fails
                    pass
            
            # Sort by size descending
            large_files.sort(key=lambda f: f['size_bytes'], reverse=True)
            
            # Keep top 20 files
            return large_files[:20]
            
        except Exception as e:
            self.logger.error(f"Error finding large files: {e}")
            return []
    
    def _check_disk_growth_rate(self, filesystems):
        """Check for suspicious disk space growth rate"""
        result = {
            'is_suspicious': False,
            'details': []
        }
        
        # Check disk usage using historic data if available
        # For now, we just check the current state for signs of rapid growth
        
        for fs in filesystems:
            if fs.get('use_percent', 0) > 90 and fs.get('available', '').endswith('M'):  # Very low space left
                result['is_suspicious'] = True
                result['details'].append({
                    'filesystem': fs.get('filesystem'),
                    'mounted_on': fs.get('mounted_on'),
                    'reason': f"Critical disk space: {fs.get('use_percent')}% used, only {fs.get('available')} available"
                })
        
        return result
    
    def _check_permission_issues(self):
        """Check for permission security issues"""
        issues = []
        
        try:
            # Check for world-writable directories in sensitive locations
            sensitive_dirs = ["/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/boot"]
            
            for directory in sensitive_dirs:
                if not os.path.exists(directory) or not os.path.isdir(directory):
                    continue
                
                cmd = ["find", directory, "-type", "d", "-perm", "-0002", "-ls"]
                try:
                    output = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.PIPE)
                    for line in output.strip().split('\n'):
                        if not line.strip():
                            continue
                        
                        parts = line.split()
                        if len(parts) >= 11:
                            dir_path = ' '.join(parts[10:])  # Directory path
                            issues.append({
                                'path': dir_path,
                                'type': 'world_writable_directory',
                                'severity': 'critical',
                                'description': f"World-writable directory in sensitive location: {dir_path}"
                            })
                except subprocess.CalledProcessError:
                    # Skip if find fails
                    pass
                    
            # Check for setuid/setgid files that shouldn't have those permissions
            cmd = ["find", "/", "-path", "/proc", "-prune", "-o", "-path", "/sys", "-prune", "-o", "-path", "/dev", "-prune", "-o", "-perm", "-4000", "-o", "-perm", "-2000", "-ls"]
            try:
                output = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.PIPE)
                
                # Common legitimate setuid/setgid binaries to exclude
                legitimate_setuid = [
                    "/bin/su", "/bin/sudo", "/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/gpasswd",
                    "/usr/bin/chsh", "/usr/bin/chfn", "/bin/mount", "/bin/umount", "/usr/bin/pkexec",
                    "/usr/bin/crontab", "/usr/bin/at"
                ]
                
                for line in output.strip().split('\n'):
                    if not line.strip():
                        continue
                    
                    parts = line.split()
                    if len(parts) >= 11:
                        file_path = ' '.join(parts[10:])  # File path
                        
                        # Skip legitimate setuid binaries
                        if any(file_path.startswith(legit) for legit in legitimate_setuid):
                            continue
                        
                        # Check permissions to determine if setuid, setgid, or both
                        perms = parts[2]
                        is_setuid = perms[3] == 's' or perms[3] == 'S'
                        is_setgid = perms[6] == 's' or perms[6] == 'S'
                        
                        if is_setuid:
                            perm_type = "setuid"
                        elif is_setgid:
                            perm_type = "setgid"
                        else:
                            perm_type = "setuid/setgid"
                        
                        issues.append({
                            'path': file_path,
                            'type': f'unexpected_{perm_type}',
                            'severity': 'high',
                            'description': f"Unexpected {perm_type} file: {file_path}"
                        })
            except subprocess.CalledProcessError:
                # Skip if find fails
                pass
            
            return issues
            
        except Exception as e:
            self.logger.error(f"Error checking permission issues: {e}")
            return []
    
    def _check_recently_modified_config_files(self):
        """Check for recently modified configuration files"""
        modified_files = []
        
        try:
            # Check for recently modified files in /etc (last 24 hours)
            if not os.path.exists("/etc") or not os.path.isdir("/etc"):
                return modified_files
            
            cmd = ["find", "/etc", "-type", "f", "-mtime", "-1", "-ls"]
            try:
                output = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.PIPE)
                
                # Skip certain files that change frequently
                skip_patterns = [
                    "motd", "mtab", "resolv.conf", "adjtime", "ld.so.cache",
                    "passwd-", "group-", "shadow-", "gshadow-"
                ]
                
                for line in output.strip().split('\n'):
                    if not line.strip():
                        continue
                    
                    parts = line.split()
                    if len(parts) >= 11:
                        file_path = ' '.join(parts[10:])  # File path
                        
                        # Skip common files that change frequently
                        if any(pattern in file_path for pattern in skip_patterns):
                            continue
                        
                        # Get file info
                        try:
                            stat_info = os.stat(file_path)
                            mtime = datetime.fromtimestamp(stat_info.st_mtime).isoformat()
                            
                            modified_files.append({
                                'path': file_path,
                                'modified_time': mtime,
                                'size': stat_info.st_size
                            })
                        except (FileNotFoundError, PermissionError):
                            continue
            except subprocess.CalledProcessError:
                # Skip if find fails
                pass
            
            return modified_files
            
        except Exception as e:
            self.logger.error(f"Error checking modified config files: {e}")
            return []
    
    def _bytes_to_human(self, bytes_value):
        """Convert bytes to human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.1f}{unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.1f}PB"
        
        try:
            # Directories to scan (from anomalous filesystems)
            scan_dirs = []
            for fs in anomalous_filesystems:
                mount_point = fs.get('mounted_on')
                if mount_point and mount_point not in ['/proc', '/sys', '/dev']:
                    scan_dirs.append(mount_point)
            
            # Add specific sensitive directories
            sensitive_dirs = ['/tmp', '/var/tmp', '/dev/shm', '/var/www']
            for directory in sensitive_dirs:
                if os.path.exists(directory) and directory not in scan_dirs:
                    scan_dirs.append(directory)
            
            # Define suspicious patterns
            suspicious_names = [
                'crypto', 'miner', 'xmr', 'monero', '.hidden', '.secret', 
                '.private', '.ssh2', '.exploit', 'rootkit', 'backdoor'
            ]
            
            # Scan each directory for suspicious patterns
            for scan_dir in scan_dirs:
                try:
                    # Get executable files in temp directories
                    if scan_dir in ['/tmp', '/var/tmp', '/dev/shm']:
                        cmd = ["find", scan_dir, "-type", "f", "-executable"]
                        try:
                            output = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.PIPE)
                            executable_files = output.strip().split('\n')
                            
                            for file_path in executable_files:
                                if file_path and os.path.exists(file_path):
                                    # Get file info
                                    try:
                                        file_stat = os.stat(file_path)
                                        file_size = file_stat.st_size
                                        file_perms = file_stat.st_mode
                                        file_owner = file_stat.st_uid
                                        
                                        suspicious.append({
                                            'path': file_path,
                                            'type': 'executable',
                                            'size': file_size,
                                            'reason': f"Executable file in temporary directory"
                                        })
                                    except (OSError, PermissionError):
                                        pass
                        except subprocess.CalledProcessError:
                            # Skip if find fails
                            pass
                    
                    # Check for world-writable directories
                    cmd = ["find", scan_dir, "-type", "d", "-perm", "-0002", "-not", "-path", "*/proc/*", "-not", "-path", "*/sys/*"]
                    try:
                        output = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.PIPE)
                        writable_dirs = output.strip().split('\n')
                        
                        for dir_path in writable_dirs:
                            if dir_path and os.path.exists(dir_path):
                                # Filter out expected writable dirs
                                if not any(dir_path.startswith(d) for d in ['/tmp', '/var/tmp']):
                                    suspicious.append({
                                        'path': dir_path,
                                        'type': 'directory',
                                        'reason': f"World-writable directory"
                                    })
                    except subprocess.CalledProcessError:
                        # Skip if find fails
                        pass
                    
                    # Check for suspicious directory names
                    for name in suspicious_names:
                        cmd = ["find", scan_dir, "-type", "d", "-name", f"*{name}*", "-not", "-path", "*/proc/*", "-not", "-path", "*/sys/*"]
                        try:
                            output = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.PIPE)
                            matching_dirs = output.strip().split('\n')
                            
                            for dir_path in matching_dirs:
                                if dir_path and os.path.exists(dir_path):
                                    suspicious.append({
                                        'path': dir_path,
                                        'type': 'directory',
                                        'reason': f"Suspicious directory name containing '{name}'"
                                    })
                        except subprocess.CalledProcessError:
                            # Skip if find fails
                            pass
                
                except Exception as e:
                    self.logger.warning(f"Error scanning {scan_dir} for suspicious directories: {e}")
            
            # Deduplicate results
            unique_paths = set()
            result = []
            
            for item in suspicious:
                if item['path'] and item['path'] not in unique_paths and item['path'] != '':
                    unique_paths.add(item['path'])
                    result.append(item)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error finding suspicious directories: {e}")
            return []
    
    def _find_hidden_files(self):
        """Find potentially malicious hidden files in sensitive locations"""
        hidden_files = []
        
        try:
            # Sensitive locations to check for hidden files
            locations = [
                '/etc', '/bin', '/sbin', '/usr/bin', '/usr/sbin', 
                '/usr/local/bin', '/usr/local/sbin', '/var/www', 
                '/root', '/home'
            ]
            
            # Find hidden files but exclude normal hidden configuration files
            for location in locations:
                if not os.path.exists(location) or not os.path.isdir(location):
                    continue
                
                cmd = [
                    "find", location, "-name", ".*", "-type", "f", 
                    # Exclude common hidden files
                    "!", "-name", ".bashrc", "!", "-name", ".bash_history",
                    "!", "-name", ".bash_profile", "!", "-name", ".viminfo",
                    "!", "-name", ".gitignore", "!", "-name", ".profile",
                    "!", "-path", "*/node_modules/*", "!", "-path", "*/.git/*",
                    "!", "-path", "*/.svn/*", "!", "-path", "*/.ssh/*"
                ]
                
                try:
                    output = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.PIPE)
                    files = output.strip().split('\n')
                    
                    for file_path in files:
                        if file_path and file_path != '':
                            try:
                                # Check if file is executable or has suspicious content
                                file_stat = os.stat(file_path)
                                
                                # Check if executable
                                is_executable = bool(file_stat.st_mode & stat.S_IXUSR)
                                
                                # Check file size - extremely large or small hidden files can be suspicious
                                size = file_stat.st_size
                                
                                file_info = {
                                    'path': file_path,
                                    'size': size,
                                    'is_executable': is_executable,
                                    'reason': "Hidden file in sensitive location"
                                }
                                
                                # Add more suspicion reasons
                                if is_executable:
                                    file_info['reason'] += ", executable"
                                
                                # Check content for scripts (only for small files)
                                if size < 1024 * 10:  # Less than 10KB
                                    try:
                                        with open(file_path, 'r') as f:
                                            content = f.read()
                                            
                                            # Check for suspicious patterns
                                            patterns = [
                                                "eval(", "base64_decode", "exec(", "system(",
                                                "Process.Start", "sh -c", "bash -c",
                                                "wget", "curl", "nc ", "/bin/sh"
                                            ]
                                            
                                            for pattern in patterns:
                                                if pattern in content:
                                                    file_info['reason'] += f", contains '{pattern}'"
                                                    break
                                    except Exception:
                                        pass
                                
                                hidden_files.append(file_info)
                                
                            except (PermissionError, FileNotFoundError):
                                pass
                
                except subprocess.CalledProcessError:
                    # Skip if find command fails
                    continue
            
            return hidden_files
            
        except Exception as e:
            self.logger.error(f"Error finding hidden files: {e}")
            return []
            
    def _find_unusually_large_files(self, anomalous_filesystems):
        """Find unusually large files that might be consuming disk space"""
        large_files = []
        
        try:
            # Directories to scan (from anomalous filesystems)
            scan_dirs = []
            for fs in anomalous_filesystems:
                mount_point = fs.get('mounted_on')
                if mount_point and mount_point not in ['/proc', '/sys', '/dev']:
                    scan_dirs.append(mount_point)
            
            if not scan_dirs:
                # If no anomalous filesystems, check some default locations
                scan_dirs = ['/var', '/tmp', '/home']
            
            # Find large files
            threshold_mb = 500  # Files larger than 500MB are considered large
            
            for scan_dir in scan_dirs:
                cmd = [
                    "find", scan_dir, "-type", "f", 
                    "-size", f"+{threshold_mb}M", 
                    "-not", "-path", "*/proc/*", 
                    "-not", "-path", "*/sys/*"
                ]
                
                try:
                    output = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.PIPE)
                    files = output.strip().split('\n')
                    
                    for file_path in files:
                        if file_path and os.path.exists(file_path):
                            try:
                                # Get file info
                                file_stat = os.stat(file_path)
                                size_bytes = file_stat.st_size
                                size_mb = size_bytes / (1024 * 1024)
                                
                                # Get file extension
                                _, ext = os.path.splitext(file_path)
                                
                                # Check if file size is unusual for its type
                                is_unusual = False
                                reason = f"Large file ({size_mb:.1f} MB)"
                                
                                # Certain formats shouldn't be extremely large
                                if ext.lower() in ['.log', '.txt', '.json', '.xml', '.csv'] and size_mb > 1000:
                                    is_unusual = True
                                    reason += f", unusually large for {ext} format"
                                
                                # Check for common large formats that might be normal
                                if ext.lower() in ['.iso', '.vmdk', '.vdi', '.qcow2', '.raw', '.img']:
                                    is_unusual = False  # These formats are expected to be large
                                
                                # Executable files shouldn't be too large
                                if (ext.lower() in ['.so', '.dll', '.exe', '.bin', '.dylib', ''] and 
                                    os.access(file_path, os.X_OK) and size_mb > 200):
                                    is_unusual = True
                                    reason += ", unusually large for executable"
                                
                                # Add to results if unusual or very large
                                if is_unusual or size_mb > 5000:  # Always add files >5GB
                                    large_files.append({
                                        'path': file_path,
                                        'size_bytes': size_bytes,
                                        'size_mb': size_mb,
                                        'type': ext[1:] if ext else "unknown",
                                        'is_unusual': is_unusual,
                                        'reason': reason
                                    })
                            
                            except (PermissionError, FileNotFoundError):
                                pass
                
                except subprocess.CalledProcessError:
                    # Skip if find command fails
                    continue
            
            # Sort by size (largest first)
            large_files.sort(key=lambda x: x['size_bytes'], reverse=True)
            
            # Limit to top 20 largest files
            return large_files[:20]
            
        except Exception as e:
            self.logger.error(f"Error finding large files: {e}")
            return []
            
    def _check_disk_growth_rate(self, filesystems):
        """Check for suspicious disk usage growth rates"""
        result = {
            'is_suspicious': False,
            'suspicious_filesystems': []
        }
        
        try:
            # Read stored usage history if available
            disk_history_file = os.path.join(os.path.dirname(self.baseline_file), 'disk_history.json')
            
            history = {}
            try:
                if os.path.exists(disk_history_file):
                    with open(disk_history_file, 'r') as f:
                        history = json.load(f)
            except Exception as e:
                self.logger.warning(f"Error reading disk history: {e}")
            
            # Current time
            now = time.time()
            
            # Check growth rate for each filesystem
            for fs in filesystems:
                filesystem = fs.get('filesystem')
                mounted_on = fs.get('mounted_on')
                use_percent = fs.get('use_percent', 0)
                
                # Skip pseudo filesystems
                if mounted_on in ['/proc', '/sys', '/dev', '/run', '/boot']:
                    continue
                
                fs_key = f"{filesystem}:{mounted_on}"
                
                if fs_key in history:
                    prev_record = history[fs_key]
                    prev_time = prev_record.get('time', 0)
                    prev_percent = prev_record.get('use_percent', 0)
                    
                    # Calculate time delta in hours
                    time_delta_hours = (now - prev_time) / 3600
                    
                    # Only consider measurements that are at least 1 hour apart
                    if time_delta_hours >= 1:
                        # Calculate growth rate (percentage points per hour)
                        growth_rate = (use_percent - prev_percent) / time_delta_hours
                        
                        # Check if growth rate is suspicious
                        # Thresholds need to be calibrated based on environment
                        is_suspicious = False
                        if growth_rate > 5:  # More than 5 percentage points per hour is very rapid
                            is_suspicious = True
                        elif growth_rate > 2 and use_percent > 85:  # Moderate growth but high usage
                            is_suspicious = True
                        
                        if is_suspicious:
                            result['is_suspicious'] = True
                            result['suspicious_filesystems'].append({
                                'filesystem': filesystem,
                                'mounted_on': mounted_on,
                                'current_percent': use_percent,
                                'previous_percent': prev_percent,
                                'growth_rate': growth_rate,
                                'time_delta_hours': time_delta_hours
                            })
                
                # Update history
                history[fs_key] = {
                    'time': now,
                    'use_percent': use_percent
                }
            
            # Write updated history
            try:
                os.makedirs(os.path.dirname(disk_history_file), exist_ok=True)
                with open(disk_history_file, 'w') as f:
                    json.dump(history, f)
            except Exception as e:
                self.logger.warning(f"Error writing disk history: {e}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error checking disk growth rate: {e}")
            return {'is_suspicious': False, 'error': str(e)}
            
    def _check_permission_issues(self):
        """Check for suspicious permission issues in important directories"""
        issues = []
        
        try:
            # Critical directories to check
            critical_dirs = [
                '/etc', '/etc/ssh', '/etc/ssl', '/etc/pam.d', 
                '/var/log', '/var/spool/cron', '/root'
            ]
            
            for directory in critical_dirs:
                if not os.path.exists(directory) or not os.path.isdir(directory):
                    continue
                
                # Check directory permissions
                try:
                    dir_stat = os.stat(directory)
                    dir_mode = dir_stat.st_mode
                    
                    # Directory should not be world-writable
                    if dir_mode & stat.S_IWOTH:
                        issues.append({
                            'path': directory,
                            'type': 'directory',
                            'issue': 'World-writable critical directory',
                            'mode': oct(dir_mode & 0o777)
                        })
                except (PermissionError, FileNotFoundError):
                    pass
                
                # Check permissions of files in directory
                cmd = ["find", directory, "-type", "f", "-perm", "-0002"]
                try:
                    output = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.PIPE)
                    writable_files = output.strip().split('\n')
                    
                    for file_path in writable_files:
                        if file_path and file_path != '':
                            issues.append({
                                'path': file_path,
                                'type': 'file',
                                'issue': 'World-writable file in critical directory',
                                'mode': oct(os.stat(file_path).st_mode & 0o777)
                            })
                except subprocess.CalledProcessError:
                    # Skip if find command fails
                    pass
                
                # Check specific permissions for SSH
                if directory == '/etc/ssh' and os.path.exists('/etc/ssh/sshd_config'):
                    try:
                        ssh_stat = os.stat('/etc/ssh/sshd_config')
                        ssh_mode = ssh_stat.st_mode
                        
                        # SSH config should be 644 or more restrictive
                        if ssh_mode & (stat.S_IWGRP | stat.S_IWOTH):
                            issues.append({
                                'path': '/etc/ssh/sshd_config',
                                'type': 'file',
                                'issue': 'SSH config with insecure permissions',
                                'mode': oct(ssh_mode & 0o777)
                            })
                    except (PermissionError, FileNotFoundError):
                        pass
            
            return issues
            
        except Exception as e:
            self.logger.error(f"Error checking permission issues: {e}")
            return []
            
    def _check_recently_modified_config_files(self):
        """Find recently modified configuration files that could indicate compromise"""
        modified_files = []
        
        try:
            # Critical config directories
            config_dirs = [
                '/etc', '/etc/ssh', '/etc/pam.d', '/etc/sudoers.d', 
                '/etc/security', '/etc/cron.d'
            ]
            
            # Check for recently modified files (last 48 hours)
            time_threshold = time.time() - (48 * 3600)
            
            for directory in config_dirs:
                if not os.path.exists(directory) or not os.path.isdir(directory):
                    continue
                
                cmd = ["find", directory, "-type", "f", "-mtime", "-2"]
                try:
                    output = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.PIPE)
                    recent_files = output.strip().split('\n')
                    
                    for file_path in recent_files:
                        if file_path and file_path != '':
                            try:
                                file_stat = os.stat(file_path)
                                
                                # Skip very small files
                                if file_stat.st_size < 10:
                                    continue
                                    
                                # Get modification time
                                mtime = file_stat.st_mtime
                                
                                # Add to results
                                modified_files.append({
                                    'path': file_path,
                                    'modified_time': datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S'),
                                    'owner': file_stat.st_uid,
                                    'group': file_stat.st_gid,
                                    'size': file_stat.st_size
                                })
                            except (PermissionError, FileNotFoundError):
                                pass
                except subprocess.CalledProcessError:
                    # Skip if find command fails
                    pass
            
            # Sort by modification time (newest first)
            modified_files.sort(key=lambda x: x.get('modified_time', ''), reverse=True)
            
            return modified_files
            
        except Exception as e:
            self.logger.error(f"Error checking recently modified config files: {e}")
            return []
    
    def _find_suspicious_processes(self):
        """Find suspicious processes based on resource usage patterns"""
        self.logger.debug("Finding suspicious processes")
        
        suspicious_processes = []
        
        try:
            # Get all processes
            cmd = ["ps", "-eo", "pid,ppid,user,cmd,%mem,%cpu", "--no-headers"]
            output = subprocess.check_output(cmd, universal_newlines=True)
            
            for line in output.strip().split('\n'):
                if not line.strip():
                    continue
                    
                parts = line.split()
                if len(parts) >= 6:
                    # Extract data
                    pid = parts[0]
                    ppid = parts[1]
                    user = parts[2]
                    cpu_percent = float(parts[-1])
                    mem_percent = float(parts[-2])
                    cmd = ' '.join(parts[3:-2])
                    
                    # Check for suspicious resource usage patterns
                    is_suspicious = False
                    reason = []
                    
                    # Criteria for suspicious processes
                    
                    # 1. High CPU usage for non-system processes
                    if cpu_percent > 80 and user != 'root' and 'sbin' not in cmd:
                        is_suspicious = True
                        reason.append(f"High CPU usage ({cpu_percent}%)")
                    
                    # 2. High memory usage
                    if mem_percent > 50:
                        is_suspicious = True
                        reason.append(f"High memory usage ({mem_percent}%)")
                    
                    # 3. Suspicious command names or paths
                    suspicious_names = [
                        'miner', 'xmr', 'crypto', 'kworker', './', '/tmp/', 
                        'curl', 'wget', 'nc ', 'netcat', 'ncat',
                        'bash -i', 'perl -e', 'python -c', 'ruby -e'
                    ]
                    
                    for name in suspicious_names:
                        if name in cmd.lower():
                            is_suspicious = True
                            reason.append(f"Suspicious command pattern: '{name}'")
                    
                    # 4. Processes running from temporary directories
                    suspicious_paths = ['/tmp', '/dev/shm', '/var/tmp', '/run/user']
                    
                    # Get process executable path
                    try:
                        exe_path = os.path.realpath(f"/proc/{pid}/exe")
                        for path in suspicious_paths:
                            if exe_path.startswith(path):
                                is_suspicious = True
                                reason.append(f"Running from suspicious location: {exe_path}")
                    except (FileNotFoundError, PermissionError):
                        # Process might have terminated or we don't have permission
                        pass
                    
                    if is_suspicious:
                        suspicious_processes.append({
                            'pid': pid,
                            'ppid': ppid,
                            'user': user,
                            'command': cmd,
                            'cpu_percent': cpu_percent,
                            'mem_percent': mem_percent,
                            'reasons': reason
                        })
            
            return {
                'timestamp': datetime.now().isoformat(),
                'count': len(suspicious_processes),
                'suspicious_processes': suspicious_processes,
                'is_anomalous': len(suspicious_processes) > 0
            }
            
        except Exception as e:
            self.logger.error(f"Error finding suspicious processes: {e}")
            return {
                'error': str(e),
                'is_anomalous': False
            }
    
    def _human_to_bytes(self, size_str):
        """Convert human-readable size string to bytes"""
        units = {"B": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
        
        try:
            size = size_str.upper()
            if not size[-1].isdigit():
                number = float(size[:-1])
                unit = size[-1]
                if unit == 'B':
                    return int(number)
                return int(number * units.get(unit, 1))
            else:
                return int(size)
        except (ValueError, AttributeError, KeyError):
            return 0
    
    def establish_baseline(self):
        """Establish baseline for system resources"""
        self.logger.info("Establishing baseline for system resources")
        
        baseline = {
            'timestamp': datetime.now().isoformat(),
            'cpu': self._analyze_cpu(),
            'memory': self._analyze_memory(),
            'disk': self._analyze_disk()
        }
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.baseline_file), exist_ok=True)
        
        # Write baseline to file
        with open(self.baseline_file, 'w') as f:
            json.dump(baseline, f, indent=2)
        
        self.logger.info(f"Baseline saved to {self.baseline_file}")
        
        return baseline
    
    def compare_baseline(self):
        """Compare current state with baseline"""
        self.logger.info("Comparing system resources with baseline")
        
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
        current = {
            'cpu': self._analyze_cpu(),
            'memory': self._analyze_memory(),
            'disk': self._analyze_disk()
        }
        
        # Compare
        comparison = {
            'timestamp': datetime.now().isoformat(),
            'baseline_timestamp': baseline.get('timestamp'),
            'cpu_comparison': self._compare_cpu(baseline.get('cpu', {}), current['cpu']),
            'memory_comparison': self._compare_memory(baseline.get('memory', {}), current['memory']),
            'disk_comparison': self._compare_disk(baseline.get('disk', {}), current['disk']),
            'suspicious_processes': self._find_suspicious_processes()
        }
        
        # Overall anomaly status
        is_anomalous = (
            comparison['cpu_comparison'].get('is_anomalous', False) or
            comparison['memory_comparison'].get('is_anomalous', False) or
            comparison['disk_comparison'].get('is_anomalous', False) or
            comparison['suspicious_processes'].get('is_anomalous', False)
        )
        
        comparison['is_anomalous'] = is_anomalous
        
        return comparison
    
    def _compare_cpu(self, baseline, current):
        """Compare CPU baseline with current state"""
        # Calculate difference
        baseline_usage = baseline.get('total_cpu_usage', 0)
        current_usage = current.get('total_cpu_usage', 0)
        
        diff = current_usage - baseline_usage
        percent_diff = (diff / baseline_usage) * 100 if baseline_usage > 0 else 0
        
        # Determine if anomalous
        is_anomalous = abs(percent_diff) > 50  # 50% difference threshold
        
        # Compare processes
        baseline_processes = {p.get('command'): p.get('cpu_percent', 0) for p in baseline.get('top_processes', [])}
        current_processes = {p.get('command'): p.get('cpu_percent', 0) for p in current.get('top_processes', [])}
        
        new_processes = [cmd for cmd in current_processes if cmd not in baseline_processes]
        missing_processes = [cmd for cmd in baseline_processes if cmd not in current_processes]
        
        return {
            'baseline_usage': baseline_usage,
            'current_usage': current_usage,
            'difference': diff,
            'percent_difference': percent_diff,
            'is_anomalous': is_anomalous,
            'new_processes': new_processes,
            'missing_processes': missing_processes
        }
    
    def _compare_memory(self, baseline, current):
        """Compare memory baseline with current state"""
        # Calculate difference
        baseline_percent = baseline.get('memory_usage_percent', 0)
        current_percent = current.get('memory_usage_percent', 0)
        
        diff = current_percent - baseline_percent
        
        # Determine if anomalous
        is_anomalous = abs(diff) > 20  # 20% difference threshold
        
        # Compare processes
        baseline_processes = {p.get('command'): p.get('mem_percent', 0) for p in baseline.get('top_processes', [])}
        current_processes = {p.get('command'): p.get('mem_percent', 0) for p in current.get('top_processes', [])}
        
        new_processes = [cmd for cmd in current_processes if cmd not in baseline_processes]
        missing_processes = [cmd for cmd in baseline_processes if cmd not in current_processes]
        
        return {
            'baseline_percent': baseline_percent,
            'current_percent': current_percent,
            'difference': diff,
            'is_anomalous': is_anomalous,
            'new_processes': new_processes,
            'missing_processes': missing_processes
        }
    
    def _compare_disk(self, baseline, current):
        """Compare disk baseline with current state"""
        # Compare filesystems
        baseline_filesystems = {fs.get('mounted_on'): fs.get('use_percent', 0) for fs in baseline.get('filesystems', [])}
        current_filesystems = {fs.get('mounted_on'): fs.get('use_percent', 0) for fs in current.get('filesystems', [])}
        
        # Check for significant changes
        significant_changes = []
        
        for mount_point, current_percent in current_filesystems.items():
            if mount_point in baseline_filesystems:
                baseline_percent = baseline_filesystems[mount_point]
                diff = current_percent - baseline_percent
                
                if abs(diff) > 20:  # 20% difference threshold
                    significant_changes.append({
                        'mount_point': mount_point,
                        'baseline_percent': baseline_percent,
                        'current_percent': current_percent,
                        'difference': diff
                    })
        
        # Check for new and missing filesystems
        new_filesystems = [mount for mount in current_filesystems if mount not in baseline_filesystems]
        missing_filesystems = [mount for mount in baseline_filesystems if mount not in current_filesystems]
        
        is_anomalous = (
            len(significant_changes) > 0 or
            len(new_filesystems) > 0 or
            len(missing_filesystems) > 0
        )
        
        return {
            'significant_changes': significant_changes,
            'new_filesystems': new_filesystems,
            'missing_filesystems': missing_filesystems,
            'is_anomalous': is_anomalous
        }