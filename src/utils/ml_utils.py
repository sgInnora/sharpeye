#!/usr/bin/env python3
"""
Machine Learning Utilities for SharpEye
Provides utilities for model loading, prediction, and training.
"""

import os
import logging
import json
import pickle
import numpy as np
from datetime import datetime
import subprocess
from collections import deque

class MLModelManager:
    """
    Manages machine learning models for detection tasks
    """
    
    def __init__(self, config=None):
        """Initialize with configuration"""
        self.logger = logging.getLogger('sharpeye.ml_utils')
        self.config = config or {}
        
        # Set default paths
        self.models_dir = self.config.get('models_dir', '/var/lib/sharpeye/models')
        os.makedirs(self.models_dir, exist_ok=True)
    
    def load_model(self, model_name):
        """
        Load a model from disk
        """
        model_path = os.path.join(self.models_dir, f"{model_name}.pkl")
        
        if not os.path.exists(model_path):
            self.logger.warning(f"Model {model_name} does not exist at {model_path}")
            return None
        
        try:
            with open(model_path, 'rb') as f:
                model = pickle.load(f)
            self.logger.info(f"Loaded model {model_name} from {model_path}")
            return model
        except Exception as e:
            self.logger.error(f"Error loading model {model_name}: {e}")
            return None
    
    def save_model(self, model, model_name):
        """
        Save a model to disk
        """
        model_path = os.path.join(self.models_dir, f"{model_name}.pkl")
        
        try:
            with open(model_path, 'wb') as f:
                pickle.dump(model, f)
            self.logger.info(f"Saved model {model_name} to {model_path}")
            return True
        except Exception as e:
            self.logger.error(f"Error saving model {model_name}: {e}")
            return False
    
    def model_exists(self, model_name):
        """
        Check if a model exists
        """
        model_path = os.path.join(self.models_dir, f"{model_name}.pkl")
        return os.path.exists(model_path)


class CPUProfiler:
    """
    Profiles CPU usage patterns for processes
    """
    
    def __init__(self, config=None):
        """Initialize with configuration"""
        self.logger = logging.getLogger('sharpeye.cpu_profiler')
        self.config = config or {}
        
        # Configuration defaults
        self.sampling_interval = self.config.get('sampling_interval', 5)  # seconds
        self.history_length = self.config.get('history_length', 12)  # samples
        
        # Process history store
        self.process_history = {}
    
    def get_process_features(self, pid):
        """
        Get CPU usage features for a specific process
        
        Returns:
            dict: Features dictionary or None if process not found/accessible
        """
        try:
            # Get process information
            cmd = ["ps", "-p", str(pid), "-o", "%cpu,%mem,time", "--no-headers"]
            output = subprocess.check_output(cmd, universal_newlines=True).strip()
            
            if not output:
                return None
                
            parts = output.split()
            if len(parts) < 3:
                return None
                
            cpu_percent = float(parts[0])
            mem_percent = float(parts[1])
            
            # Get CPU time in seconds
            time_str = parts[2]
            time_parts = time_str.split(':')
            
            # Handle HH:MM:SS format
            if len(time_parts) == 3:
                cpu_time = int(time_parts[0]) * 3600 + int(time_parts[1]) * 60 + int(time_parts[2])
            # Handle MM:SS format
            elif len(time_parts) == 2:
                cpu_time = int(time_parts[0]) * 60 + int(time_parts[1])
            else:
                cpu_time = int(time_parts[0])
            
            # Get process command
            cmd = ["ps", "-p", str(pid), "-o", "command", "--no-headers"]
            command = subprocess.check_output(cmd, universal_newlines=True).strip()
            
            # Get /proc stats for more detailed CPU info
            try:
                with open(f"/proc/{pid}/stat", 'r') as f:
                    stat = f.read().split()
                    utime = int(stat[13])
                    stime = int(stat[14])
                    cutime = int(stat[15])
                    cstime = int(stat[16])
                    total_time = utime + stime + cutime + cstime
            except (FileNotFoundError, IOError, IndexError):
                total_time = 0
            
            # Update history
            if pid not in self.process_history:
                self.process_history[pid] = {
                    'cpu_percent': deque(maxlen=self.history_length),
                    'mem_percent': deque(maxlen=self.history_length),
                    'cpu_time': deque(maxlen=self.history_length),
                    'total_time': deque(maxlen=self.history_length),
                    'timestamps': deque(maxlen=self.history_length),
                }
            
            self.process_history[pid]['cpu_percent'].append(cpu_percent)
            self.process_history[pid]['mem_percent'].append(mem_percent)
            self.process_history[pid]['cpu_time'].append(cpu_time)
            self.process_history[pid]['total_time'].append(total_time)
            self.process_history[pid]['timestamps'].append(datetime.now().timestamp())
            
            # Calculate features
            features = self._calculate_features(pid)
            features['command'] = command
            
            return features
            
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            self.logger.debug(f"Could not get information for PID {pid}: {e}")
            return None
    
    def _calculate_features(self, pid):
        """
        Calculate features from process history
        """
        history = self.process_history[pid]
        
        # Basic statistics
        features = {
            'pid': pid
        }
        
        # Only calculate features if we have enough history
        if len(history['cpu_percent']) < 2:
            features['has_enough_history'] = False
            return features
        
        features['has_enough_history'] = True
        
        # Current values
        features['current_cpu'] = history['cpu_percent'][-1]
        features['current_mem'] = history['mem_percent'][-1]
        
        # CPU statistics
        features['mean_cpu'] = np.mean(history['cpu_percent'])
        features['std_cpu'] = np.std(history['cpu_percent'])
        features['min_cpu'] = np.min(history['cpu_percent'])
        features['max_cpu'] = np.max(history['cpu_percent'])
        
        # CPU stability (is it consistently using similar CPU?)
        features['cpu_stability'] = features['std_cpu'] / (features['mean_cpu'] + 0.1)  # Add 0.1 to avoid division by zero
        
        # Memory statistics
        features['mean_mem'] = np.mean(history['mem_percent'])
        features['std_mem'] = np.std(history['mem_percent'])
        features['min_mem'] = np.min(history['mem_percent'])
        features['max_mem'] = np.max(history['mem_percent'])
        
        # CPU/Memory ratio
        features['cpu_mem_ratio'] = features['mean_cpu'] / (features['mean_mem'] + 0.1)  # Add 0.1 to avoid division by zero
        
        # CPU usage pattern features
        if len(history['timestamps']) >= 2:
            # Time elapsed since first measurement
            time_elapsed = history['timestamps'][-1] - history['timestamps'][0]
            
            if time_elapsed > 0:
                # CPU growth rate
                cpu_growth = (history['cpu_percent'][-1] - history['cpu_percent'][0]) / time_elapsed
                features['cpu_growth_rate'] = cpu_growth
                
                # CPU time growth rate
                if len(history['cpu_time']) >= 2:
                    cpu_time_growth = (history['cpu_time'][-1] - history['cpu_time'][0]) / time_elapsed
                    features['cpu_time_growth_rate'] = cpu_time_growth
                    
                    # Is CPU consistently increasing?
                    cpu_increases = sum(1 for i in range(1, len(history['cpu_percent'])) 
                                     if history['cpu_percent'][i] > history['cpu_percent'][i-1])
                    features['cpu_increase_ratio'] = cpu_increases / (len(history['cpu_percent']) - 1)
                    
                    # CPU burstiness
                    if time_elapsed > 0 and len(history['timestamps']) > 3:
                        time_diff = np.diff(history['timestamps'])
                        cpu_diff = np.diff(history['cpu_percent'])
                        
                        # Rate of change per second
                        cpu_rate_of_change = np.abs(cpu_diff / (time_diff + 0.001))
                        features['cpu_burstiness'] = np.std(cpu_rate_of_change) / (np.mean(cpu_rate_of_change) + 0.001)
                
        # Statistical features of CPU/Memory patterns
        if len(history['cpu_percent']) >= 4:
            # Autocorrelation (periodicity detection)
            cpu_series = np.array(history['cpu_percent'])
            n = len(cpu_series)
            if n > 3:  # Need at least 4 samples for lag-1 autocorrelation
                # Calculate lag-1 autocorrelation
                lag_1_autocorr = np.corrcoef(cpu_series[:-1], cpu_series[1:])[0, 1]
                features['cpu_autocorrelation'] = lag_1_autocorr
                
                # Calculate spectral entropy (measure of randomness)
                from scipy import signal
                from scipy.stats import entropy
                
                # Make sure we have enough data for meaningful spectral analysis
                if n >= 8:
                    freqs, psd = signal.welch(cpu_series, nperseg=min(128, n//2))
                    if np.sum(psd) > 0:
                        psd_norm = psd / np.sum(psd)
                        spectral_entropy = entropy(psd_norm)
                        features['cpu_spectral_entropy'] = spectral_entropy
        
        return features


class CryptominerDetector:
    """
    Detects cryptominer processes using ML and heuristics
    """
    
    def __init__(self, config=None):
        """Initialize with configuration"""
        self.logger = logging.getLogger('sharpeye.cryptominer_detector')
        self.config = config or {}
        
        # Initialize ML utilities
        self.ml_manager = MLModelManager(self.config.get('ml_config', {}))
        self.cpu_profiler = CPUProfiler(self.config.get('profiler_config', {}))
        
        # Load detection model if it exists
        self.model = self.ml_manager.load_model('cryptominer_detector')
        
        # Known mining-related keywords
        self.mining_keywords = self.config.get('mining_keywords', [
            'miner', 'xmr', 'monero', 'eth', 'ethereum', 'btc', 'bitcoin',
            'stratum', 'mining', 'hashrate', 'cryptonight', 'ethash', 'zcash',
            'equihash', 'randomx', 'coin', 'nicehash', 'pool'
        ])
        
        # Default feature thresholds
        self.thresholds = self.config.get('thresholds', {
            'cpu_stability': 0.2,  # Low variation in CPU usage
            'cpu_min': 50.0,       # Consistently high CPU
            'cpu_mean': 80.0,      # High average CPU usage
            'cpu_time_growth_rate': 0.5,  # Steady CPU time growth
            'cpu_autocorrelation': 0.7,   # Strong autocorrelation (periodic pattern)
            'cpu_spectral_entropy': 1.5    # Low entropy (predictable pattern)
        })
    
    def analyze_process(self, pid):
        """
        Analyze a single process for cryptomining behavior
        
        Args:
            pid: Process ID to analyze
            
        Returns:
            dict: Analysis results with detection verdict
        """
        # Get process features
        features = self.cpu_profiler.get_process_features(pid)
        
        if not features:
            return {
                'pid': pid,
                'error': 'Failed to get process features',
                'is_cryptominer': False,
                'confidence': 0.0,
                'reasons': []
            }
        
        if not features.get('has_enough_history', False):
            return {
                'pid': pid,
                'warning': 'Not enough history to analyze',
                'is_cryptominer': False,
                'confidence': 0.0,
                'reasons': []
            }
        
        # ML-based detection (if model is available)
        ml_verdict = {
            'is_cryptominer': False,
            'confidence': 0.0
        }
        
        if self.model:
            try:
                # Extract features for ML model
                feature_vector = self._extract_feature_vector(features)
                
                # Make prediction
                confidence = self.model.predict_proba([feature_vector])[0, 1]
                ml_verdict = {
                    'is_cryptominer': confidence > 0.7,  # Threshold for positive detection
                    'confidence': confidence
                }
            except Exception as e:
                self.logger.warning(f"ML prediction failed for PID {pid}: {e}")
        
        # Rule-based detection (as fallback or complement to ML)
        rule_verdict, reasons = self._rule_based_detection(features)
        
        # Combine ML and rule-based detection
        final_verdict = ml_verdict['is_cryptominer'] or rule_verdict
        
        # If ML detection available, use its confidence, otherwise use rule-based
        confidence = ml_verdict['confidence'] if self.model else (0.8 if rule_verdict else 0.0)
        
        return {
            'pid': pid,
            'command': features.get('command', 'unknown'),
            'is_cryptominer': final_verdict,
            'confidence': confidence,
            'cpu_percent': features['current_cpu'],
            'memory_percent': features['current_mem'],
            'reasons': reasons,
            'features': features
        }
    
    def _extract_feature_vector(self, features):
        """
        Extract ML feature vector from process features
        """
        # Define feature order for ML model input
        feature_names = [
            'mean_cpu', 'std_cpu', 'min_cpu', 'max_cpu', 
            'cpu_stability', 'mean_mem', 'std_mem',
            'cpu_mem_ratio', 'cpu_growth_rate', 'cpu_time_growth_rate',
            'cpu_increase_ratio', 'cpu_burstiness', 'cpu_autocorrelation',
            'cpu_spectral_entropy'
        ]
        
        # Extract features in the correct order
        vector = []
        for name in feature_names:
            if name in features:
                vector.append(features[name])
            else:
                # Use sensible defaults for missing features
                vector.append(0.0)
        
        return vector
    
    def _rule_based_detection(self, features):
        """
        Apply rule-based detection for cryptominers
        
        Returns:
            tuple: (is_cryptominer, reasons)
        """
        reasons = []
        command = features.get('command', '').lower()
        
        # Check for known mining keywords in command
        for keyword in self.mining_keywords:
            if keyword.lower() in command:
                reasons.append(f"Command contains mining keyword: '{keyword}'")
        
        # Check CPU pattern features
        if 'cpu_stability' in features and features['cpu_stability'] < self.thresholds['cpu_stability']:
            reasons.append(f"Unusually stable CPU usage pattern (stability: {features['cpu_stability']:.3f})")
        
        if 'min_cpu' in features and features['min_cpu'] > self.thresholds['cpu_min']:
            reasons.append(f"Consistently high CPU usage (min: {features['min_cpu']:.1f}%)")
        
        if 'mean_cpu' in features and features['mean_cpu'] > self.thresholds['cpu_mean']:
            reasons.append(f"High average CPU usage ({features['mean_cpu']:.1f}%)")
        
        if 'cpu_time_growth_rate' in features and features['cpu_time_growth_rate'] > self.thresholds['cpu_time_growth_rate']:
            reasons.append(f"Steady CPU time growth (rate: {features['cpu_time_growth_rate']:.3f}/s)")
        
        if 'cpu_autocorrelation' in features and features['cpu_autocorrelation'] > self.thresholds['cpu_autocorrelation']:
            reasons.append(f"Periodic CPU usage pattern (autocorr: {features['cpu_autocorrelation']:.3f})")
        
        if 'cpu_spectral_entropy' in features and features['cpu_spectral_entropy'] < self.thresholds['cpu_spectral_entropy']:
            reasons.append(f"Low randomness in CPU pattern (entropy: {features['cpu_spectral_entropy']:.3f})")
        
        # Final rule-based verdict
        is_cryptominer = len(reasons) >= 2  # Need at least 2 indicators
        
        return is_cryptominer, reasons