#!/usr/bin/env python3
"""
SSHAnalyzer Module
Detects SSH-related security issues including:
- Insecure SSH configurations
- SSH key vulnerabilities
- Suspicious SSH authentication attempts
- SSH connection anomalies
- SSH brute force attempts
"""

import os
import logging
import subprocess
import json
import re
import socket
import time
import stat
import pwd
import hashlib
import ipaddress
from datetime import datetime, timedelta
from collections import defaultdict

class SSHAnalyzer:
    """Analyzes SSH configurations, keys, and logs for security issues"""
    
    def __init__(self, config=None):
        """Initialize with configuration"""
        self.logger = logging.getLogger('sharpeye.ssh')
        self.config = config or {}
        
        # Configure options
        self.baseline_file = self.config.get('baseline_file', '/var/lib/sharpeye/baselines/ssh.json')
        self.check_config = self.config.get('check_config', True)
        self.check_keys = self.config.get('check_keys', True)
        self.check_auth = self.config.get('check_auth', True)
        self.check_connections = self.config.get('check_connections', True)
        self.check_bruteforce = self.config.get('check_bruteforce', True)
        
        # Configuration settings
        self.ssh_config_path = self.config.get('ssh_config_path', '/etc/ssh/sshd_config')
        self.auth_log_paths = self.config.get('auth_log_paths', [
            '/var/log/auth.log',
            '/var/log/secure',
            '/var/log/audit/audit.log'
        ])
        self.ssh_key_paths = self.config.get('ssh_key_paths', [
            '/etc/ssh',
            '/root/.ssh',
            '/home'
        ])
        
        # Bruteforce detection settings
        self.bf_time_window = self.config.get('bf_time_window', 300)  # 5 minutes
        self.bf_attempt_threshold = self.config.get('bf_attempt_threshold', 5)  # 5 attempts
        
        # SSH configuration security settings
        self.secure_ciphers = self.config.get('secure_ciphers', [
            'chacha20-poly1305@openssh.com',
            'aes256-gcm@openssh.com',
            'aes128-gcm@openssh.com',
            'aes256-ctr',
            'aes192-ctr',
            'aes128-ctr'
        ])
        
        self.secure_macs = self.config.get('secure_macs', [
            'hmac-sha2-512-etm@openssh.com',
            'hmac-sha2-256-etm@openssh.com',
            'umac-128-etm@openssh.com',
            'hmac-sha2-512',
            'hmac-sha2-256',
            'umac-128@openssh.com'
        ])
        
        self.secure_kex = self.config.get('secure_kex', [
            'curve25519-sha256@libssh.org',
            'curve25519-sha256',
            'diffie-hellman-group16-sha512',
            'diffie-hellman-group18-sha512',
            'diffie-hellman-group-exchange-sha256'
        ])
        
        # Insecure settings to check for
        self.insecure_settings = self.config.get('insecure_settings', {
            'PermitRootLogin': ['yes', 'without-password'],
            'PasswordAuthentication': ['yes'],
            'PermitEmptyPasswords': ['yes'],
            'X11Forwarding': ['yes'],
            'AllowTcpForwarding': ['yes'],
            'UsePAM': ['no'],
            'Protocol': ['1', '1,2', '2,1'],
            'IgnoreRhosts': ['no'],
            'HostbasedAuthentication': ['yes'],
            'PermitUserEnvironment': ['yes']
        })
        
        # Recommended security settings
        self.recommended_settings = self.config.get('recommended_settings', {
            'LogLevel': ['VERBOSE'],
            'MaxAuthTries': ['3', '4'],
            'MaxSessions': ['2', '3', '4'],
            'ClientAliveInterval': ['300', '600'],
            'ClientAliveCountMax': ['0', '1', '2'],
            'LoginGraceTime': ['30', '60', '120']
        })
        
        # Initialize threat intelligence module if enabled
        ti_config = self.config.get('threat_intelligence', {})
        if ti_config.get('enabled', False):
            try:
                from utils.threat_intelligence import ThreatIntelligence
                self.threat_intel = ThreatIntelligence(ti_config)
                self.logger.info(f"Initialized threat intelligence module")
            except ImportError:
                self.logger.warning("Threat intelligence module not found, disabling")
                self.threat_intel = None
        else:
            self.threat_intel = None
    
    def analyze(self):
        """Analyze SSH security"""
        self.logger.info("Analyzing SSH security")
        
        # Get start time for performance tracking
        start_time = time.time()
        
        # Enhanced check options
        check_tunnels = self.config.get('check_tunnels', True)
        check_key_usage = self.config.get('check_key_usage', True)
        
        results = {
            'config_issues': self._check_ssh_config() if self.check_config else {'skipped': True},
            'key_issues': self._check_ssh_keys() if self.check_keys else {'skipped': True},
            'auth_issues': self._check_ssh_auth() if self.check_auth else {'skipped': True},
            'connection_anomalies': self._check_ssh_connections() if self.check_connections else {'skipped': True},
            'bruteforce_attempts': self._check_bruteforce() if self.check_bruteforce else {'skipped': True},
            'tunneling_analysis': self._check_ssh_tunnels() if check_tunnels else {'skipped': True},
            'key_usage_patterns': self._check_ssh_key_usage() if check_key_usage else {'skipped': True}
        }
        
        # Determine if any anomalies were found
        is_anomalous = (
            results['config_issues'].get('is_anomalous', False) or
            results['key_issues'].get('is_anomalous', False) or
            results['auth_issues'].get('is_anomalous', False) or
            results['connection_anomalies'].get('is_anomalous', False) or
            results['bruteforce_attempts'].get('is_anomalous', False) or
            results['tunneling_analysis'].get('is_anomalous', False) or
            results['key_usage_patterns'].get('is_anomalous', False)
        )
        
        results['is_anomalous'] = is_anomalous
        results['timestamp'] = datetime.now().isoformat()
        
        # Add performance metrics
        elapsed_time = time.time() - start_time
        results['performance'] = {
            'elapsed_time': elapsed_time,
            'checks_performed': sum(1 for k, v in results.items() if k != 'performance' and k != 'is_anomalous' and k != 'timestamp' and not v.get('skipped', False))
        }
        
        return results
    
    def _check_ssh_config(self):
        """Check SSH server configuration for security issues"""
        self.logger.debug("Checking SSH configuration")
        
        config_issues = []
        security_score = 100  # Start with perfect score
        
        try:
            # Check if SSH config file exists
            if not os.path.exists(self.ssh_config_path):
                return {
                    'error': f"SSH config file not found: {self.ssh_config_path}",
                    'is_anomalous': True
                }
            
            # Parse SSH config file
            config_settings = {}
            includes = []
            
            with open(self.ssh_config_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        continue
                    
                    # Handle include directives
                    if line.lower().startswith('include '):
                        includes.append(line.split(' ', 1)[1])
                        continue
                    
                    # Parse key-value settings
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        key, value = parts
                        config_settings[key] = value
            
            # Process include files if any
            for include_path in includes:
                # Handle wildcards
                if '*' in include_path:
                    import glob
                    include_files = glob.glob(include_path)
                else:
                    include_files = [include_path]
                
                for incl_file in include_files:
                    if os.path.exists(incl_file):
                        try:
                            with open(incl_file, 'r') as f:
                                for line in f:
                                    line = line.strip()
                                    # Skip comments and empty lines
                                    if not line or line.startswith('#'):
                                        continue
                                    
                                    # Parse key-value settings
                                    parts = line.split(None, 1)
                                    if len(parts) == 2:
                                        key, value = parts
                                        config_settings[key] = value
                        except Exception as e:
                            self.logger.error(f"Error parsing include file {incl_file}: {e}")
            
            # Check for insecure settings
            for key, insecure_values in self.insecure_settings.items():
                if key in config_settings and config_settings[key] in insecure_values:
                    config_issues.append({
                        'setting': key,
                        'value': config_settings[key],
                        'recommendation': f"Change {key} from '{config_settings[key]}' to a more secure value",
                        'severity': 'high' if key in ['PermitRootLogin', 'PasswordAuthentication', 'PermitEmptyPasswords'] else 'medium'
                    })
                    # Reduce security score
                    if key in ['PermitRootLogin', 'PasswordAuthentication', 'PermitEmptyPasswords']:
                        security_score -= 15  # Major issues
                    else:
                        security_score -= 5   # Minor issues
            
            # Check for missing recommended settings
            for key, recommended_values in self.recommended_settings.items():
                if key not in config_settings:
                    config_issues.append({
                        'setting': key,
                        'issue': 'Missing',
                        'recommendation': f"Add {key} with value {recommended_values[0]}",
                        'severity': 'medium'
                    })
                    security_score -= 3  # Minor issues
                elif config_settings[key] not in recommended_values:
                    config_issues.append({
                        'setting': key,
                        'value': config_settings[key],
                        'recommendation': f"Consider changing {key} to one of: {', '.join(recommended_values)}",
                        'severity': 'low'
                    })
                    security_score -= 1  # Very minor issues
            
            # Check for cipher configuration
            if 'Ciphers' in config_settings:
                configured_ciphers = [c.strip() for c in config_settings['Ciphers'].split(',')]
                insecure_ciphers = [c for c in configured_ciphers if c not in self.secure_ciphers]
                if insecure_ciphers:
                    config_issues.append({
                        'setting': 'Ciphers',
                        'insecure_values': insecure_ciphers,
                        'recommendation': f"Remove insecure ciphers: {', '.join(insecure_ciphers)}",
                        'severity': 'high'
                    })
                    security_score -= 10
            
            # Check for MAC configuration
            if 'MACs' in config_settings:
                configured_macs = [m.strip() for m in config_settings['MACs'].split(',')]
                insecure_macs = [m for m in configured_macs if m not in self.secure_macs]
                if insecure_macs:
                    config_issues.append({
                        'setting': 'MACs',
                        'insecure_values': insecure_macs,
                        'recommendation': f"Remove insecure MACs: {', '.join(insecure_macs)}",
                        'severity': 'high'
                    })
                    security_score -= 10
            
            # Check for key exchange configuration
            if 'KexAlgorithms' in config_settings:
                configured_kex = [k.strip() for k in config_settings['KexAlgorithms'].split(',')]
                insecure_kex = [k for k in configured_kex if k not in self.secure_kex]
                if insecure_kex:
                    config_issues.append({
                        'setting': 'KexAlgorithms',
                        'insecure_values': insecure_kex,
                        'recommendation': f"Remove insecure key exchange algorithms: {', '.join(insecure_kex)}",
                        'severity': 'high'
                    })
                    security_score -= 10
            
            # Check host keys
            host_keys = [
                '/etc/ssh/ssh_host_dsa_key',
                '/etc/ssh/ssh_host_ecdsa_key',
                '/etc/ssh/ssh_host_ed25519_key',
                '/etc/ssh/ssh_host_rsa_key'
            ]
            
            weak_keys = []
            for key_path in host_keys:
                if os.path.exists(key_path):
                    key_type = key_path.split('_')[-1]
                    if key_type == 'dsa':
                        weak_keys.append(key_path)
                    elif key_type == 'rsa':
                        # Check RSA key size
                        try:
                            pub_key_path = f"{key_path}.pub"
                            if os.path.exists(pub_key_path):
                                with open(pub_key_path, 'r') as f:
                                    key_data = f.read().strip().split()
                                    if len(key_data) >= 2:
                                        import base64
                                        import struct
                                        key_bytes = base64.b64decode(key_data[1])
                                        # Skip the first parts to get to the key size
                                        # (this is a simplification, proper parsing would be more complex)
                                        try:
                                            int_len = struct.unpack('>I', key_bytes[0:4])[0]
                                            # Skip to exponent
                                            offset = 4 + int_len
                                            exp_len = struct.unpack('>I', key_bytes[offset:offset+4])[0]
                                            # Skip to modulus
                                            offset = offset + 4 + exp_len
                                            mod_len = struct.unpack('>I', key_bytes[offset:offset+4])[0]
                                            
                                            # Calculate bit length
                                            bit_length = mod_len * 8
                                            if bit_length < 2048:
                                                weak_keys.append(f"{key_path} (RSA {bit_length}-bit)")
                                        except:
                                            # Fallback for parsing errors
                                            self.logger.warning(f"Could not parse RSA key size from {pub_key_path}")
                        except Exception as e:
                            self.logger.error(f"Error checking RSA key size: {e}")
            
            if weak_keys:
                config_issues.append({
                    'issue': 'Weak host keys',
                    'keys': weak_keys,
                    'recommendation': "Replace DSA keys and RSA keys smaller than 2048 bits",
                    'severity': 'high'
                })
                security_score -= 15
            
            # Check permissions on config file
            try:
                config_stat = os.stat(self.ssh_config_path)
                config_mode = config_stat.st_mode
                
                if (config_mode & (stat.S_IRWXG | stat.S_IRWXO)) != 0:
                    # Group or others have some permissions
                    config_issues.append({
                        'issue': 'Insecure sshd_config permissions',
                        'current': oct(config_mode & 0o777),
                        'recommendation': "Change permissions to 0600",
                        'severity': 'high'
                    })
                    security_score -= 10
            except Exception as e:
                self.logger.error(f"Error checking sshd_config permissions: {e}")
            
            # Ensure security score is within range
            security_score = max(0, min(100, security_score))
            
            return {
                'count': len(config_issues),
                'security_score': security_score,
                'issues': config_issues,
                'settings': config_settings,
                'is_anomalous': len(config_issues) > 0
            }
            
        except Exception as e:
            self.logger.error(f"Error checking SSH configuration: {e}")
            return {
                'error': str(e),
                'is_anomalous': False
            }
    
    def _check_ssh_keys(self):
        """Check SSH keys for security issues"""
        self.logger.debug("Checking SSH keys")
        
        key_issues = []
        
        try:
            all_keys = []
            
            # Find SSH keys
            for path in self.ssh_key_paths:
                if os.path.exists(path):
                    if path == '/home':
                        # Special handling for /home directory
                        try:
                            # Get all user home directories
                            for user_dir in os.listdir(path):
                                user_ssh_dir = os.path.join(path, user_dir, '.ssh')
                                if os.path.isdir(user_ssh_dir):
                                    # Search for key files
                                    for root, _, files in os.walk(user_ssh_dir):
                                        for file in files:
                                            # Check for common key file names
                                            if file in ['id_dsa', 'id_rsa', 'identity'] or file.endswith('.key'):
                                                key_path = os.path.join(root, file)
                                                all_keys.append(key_path)
                        except Exception as e:
                            self.logger.error(f"Error scanning user home directories: {e}")
                    else:
                        # Regular directory scan
                        for root, _, files in os.walk(path):
                            for file in files:
                                if (file.startswith('id_') or file.startswith('ssh_host_') or 
                                    file == 'authorized_keys' or file == 'identity' or 
                                    file.endswith('.key') or file.endswith('_key')):
                                    key_path = os.path.join(root, file)
                                    all_keys.append(key_path)
            
            # Analyze found keys
            for key_path in all_keys:
                key_issues_found = []
                
                try:
                    # Check if this is a private key
                    is_private = (not key_path.endswith('.pub') and 
                                 not os.path.basename(key_path) in ['authorized_keys', 'known_hosts'])
                    
                    # Check permissions
                    key_stat = os.stat(key_path)
                    key_mode = key_stat.st_mode
                    
                    # Get owner info
                    try:
                        owner_name = pwd.getpwuid(key_stat.st_uid).pw_name
                    except KeyError:
                        owner_name = str(key_stat.st_uid)
                    
                    if is_private:
                        # Private keys should be 0600 or more restrictive
                        if (key_mode & (stat.S_IRWXG | stat.S_IRWXO)) != 0:
                            # Group or others have some permissions
                            key_issues_found.append({
                                'issue': 'Insecure private key permissions',
                                'current': oct(key_mode & 0o777),
                                'recommendation': "Change permissions to 0600",
                                'severity': 'high'
                            })
                    else:
                        # Public keys should be 0644 or more restrictive
                        if (key_mode & stat.S_IWGRP) or (key_mode & stat.S_IWOTH):
                            # Group or others have write permissions
                            key_issues_found.append({
                                'issue': 'Insecure public key permissions',
                                'current': oct(key_mode & 0o777),
                                'recommendation': "Change permissions to 0644 or more restrictive",
                                'severity': 'medium'
                            })
                    
                    # Check key type for private keys
                    if is_private:
                        # Check file content to determine key type
                        with open(key_path, 'r') as f:
                            try:
                                first_line = f.readline().strip()
                                
                                # Check for DSA keys
                                if 'DSA PRIVATE KEY' in first_line:
                                    key_issues_found.append({
                                        'issue': 'Weak key algorithm (DSA)',
                                        'recommendation': "Replace with ED25519 or RSA (4096-bit)",
                                        'severity': 'high'
                                    })
                                
                                # Check for RSA keys
                                elif 'RSA PRIVATE KEY' in first_line:
                                    # Determine key strength - simplistic, could be improved
                                    key_strength = None
                                    key_contents = f.read()
                                    if len(key_contents) < 1000:  # Rough estimate
                                        key_strength = 'weak'
                                    
                                    if key_strength == 'weak':
                                        key_issues_found.append({
                                            'issue': 'Potentially weak RSA key',
                                            'recommendation': "Replace with 4096-bit RSA or ED25519",
                                            'severity': 'medium'
                                        })
                                
                                # Look for passphrase protection
                                f.seek(0)
                                key_contents = f.read()
                                if 'ENCRYPTED' not in key_contents and is_private:
                                    key_issues_found.append({
                                        'issue': 'Private key not protected by passphrase',
                                        'recommendation': "Add passphrase protection to key",
                                        'severity': 'high'
                                    })
                            except UnicodeDecodeError:
                                # Not a text file or different encoding
                                pass
                    
                    # If it's authorized_keys, check for dangerous entries
                    if os.path.basename(key_path) == 'authorized_keys':
                        with open(key_path, 'r') as f:
                            for line_num, line in enumerate(f, 1):
                                line = line.strip()
                                
                                # Skip comments and empty lines
                                if not line or line.startswith('#'):
                                    continue
                                
                                # Check for command restrictions
                                if 'command=' not in line and 'no-port-forwarding' not in line:
                                    key_issues_found.append({
                                        'issue': 'Unrestricted authorized key',
                                        'line': line_num,
                                        'recommendation': "Add command= and no-port-forwarding restrictions",
                                        'severity': 'medium'
                                    })
                                
                                # Check for from= restriction
                                if 'from=' not in line:
                                    key_issues_found.append({
                                        'issue': 'Missing source IP restriction',
                                        'line': line_num,
                                        'recommendation': "Add from= restriction to limit source IPs",
                                        'severity': 'low'
                                    })
                    
                    # Add to overall issues if any found
                    if key_issues_found:
                        key_issues.append({
                            'path': key_path,
                            'owner': owner_name,
                            'type': 'private' if is_private else 'public',
                            'issues': key_issues_found
                        })
                
                except Exception as e:
                    self.logger.error(f"Error analyzing key {key_path}: {e}")
            
            return {
                'count': len(key_issues),
                'key_count': len(all_keys),
                'issues': key_issues,
                'is_anomalous': len(key_issues) > 0
            }
            
        except Exception as e:
            self.logger.error(f"Error checking SSH keys: {e}")
            return {
                'error': str(e),
                'is_anomalous': False
            }
    
    def _check_ssh_auth(self):
        """Check SSH authentication logs for issues"""
        self.logger.debug("Checking SSH authentication logs")
        
        auth_issues = []
        recent_failed_attempts = []
        suspicious_successful_logins = []
        
        try:
            # Find the first available auth log
            auth_log_path = None
            for log_path in self.auth_log_paths:
                if os.path.exists(log_path):
                    auth_log_path = log_path
                    break
            
            if not auth_log_path:
                return {
                    'error': f"No SSH authentication logs found",
                    'searched_paths': self.auth_log_paths,
                    'is_anomalous': False
                }
            
            # Parse auth log
            failed_attempts = defaultdict(list)
            successful_logins = []
            invalid_users = set()
            
            # Get timestamp for filtering recent entries (last 24 hours)
            recent_time = datetime.now() - timedelta(days=1)
            
            # Patterns for log parsing
            failed_login_patterns = [
                r'Failed password for (?:invalid user )?(\S+) from (\S+) port',
                r'Failed publickey for (?:invalid user )?(\S+) from (\S+) port',
                r'Failed none for (?:invalid user )?(\S+) from (\S+) port',
                r'authentication failure;.*user=(\S+)',
                r'Invalid user (\S+) from (\S+) port'
            ]
            
            successful_login_pattern = r'Accepted (\S+) for (\S+) from (\S+) port'
            invalid_user_pattern = r'Invalid user (\S+) from'
            
            # Try both direct reading and using grep
            try:
                # First try direct file reading
                with open(auth_log_path, 'r') as f:
                    for line in f:
                        if 'sshd' not in line:
                            continue
                            
                        # Parse timestamp
                        try:
                            # Match various timestamp formats
                            # Format: Jan 1 01:01:01
                            log_time_match = re.search(r'(\w{3}\s+\d+\s+\d+:\d+:\d+)', line)
                            if log_time_match:
                                log_time_str = log_time_match.group(1)
                                current_year = datetime.now().year
                                log_time = datetime.strptime(f"{log_time_str} {current_year}", "%b %d %H:%M:%S %Y")
                                
                                # Adjust year if date appears to be from last year
                                if log_time > datetime.now():
                                    log_time = log_time.replace(year=current_year - 1)
                            else:
                                # Just use recent time as fallback
                                log_time = recent_time
                        except Exception as e:
                            # Default to recent time on parsing errors
                            log_time = recent_time
                            
                        # Process the line
                        self._process_auth_log_line(line, log_time, recent_time, failed_login_patterns, 
                                                 successful_login_pattern, invalid_user_pattern,
                                                 failed_attempts, successful_logins, invalid_users)
            except UnicodeDecodeError:
                # Fallback to grep if file has encoding issues
                try:
                    # Use grep to find relevant lines
                    cmd = ["grep", "sshd", auth_log_path]
                    output = subprocess.check_output(cmd, universal_newlines=True)
                    
                    for line in output.strip().split('\n'):
                        if not line:
                            continue
                        
                        # Parse timestamp (same as above)
                        try:
                            log_time_match = re.search(r'(\w{3}\s+\d+\s+\d+:\d+:\d+)', line)
                            if log_time_match:
                                log_time_str = log_time_match.group(1)
                                current_year = datetime.now().year
                                log_time = datetime.strptime(f"{log_time_str} {current_year}", "%b %d %H:%M:%S %Y")
                                
                                if log_time > datetime.now():
                                    log_time = log_time.replace(year=current_year - 1)
                            else:
                                log_time = recent_time
                        except Exception:
                            log_time = recent_time
                            
                        # Process the line
                        self._process_auth_log_line(line, log_time, recent_time, failed_login_patterns, 
                                                 successful_login_pattern, invalid_user_pattern,
                                                 failed_attempts, successful_logins, invalid_users)
                except subprocess.CalledProcessError as e:
                    self.logger.error(f"Error using grep on auth log: {e}")
            
            # Create summary of failed attempts
            for username, attempts in failed_attempts.items():
                if attempts:
                    recent_failed_attempts.append({
                        'username': username,
                        'count': len(attempts),
                        'sources': list(set(ip for ip, _ in attempts)),
                        'timestamps': sorted([ts.isoformat() for _, ts in attempts])
                    })
            
            # Sort by count
            recent_failed_attempts.sort(key=lambda x: x['count'], reverse=True)
            
            # Check for suspicious successful logins
            for auth_type, username, ip, timestamp in successful_logins:
                is_suspicious = False
                reasons = []
                
                # Check if login was preceded by multiple failures
                if username in failed_attempts:
                    if any(failed_ip == ip for failed_ip, _ in failed_attempts[username]):
                        is_suspicious = True
                        reasons.append("Login succeeded after failed attempts from same IP")
                
                # Check for logins with unusual authentication types
                if auth_type not in ['publickey', 'password']:
                    is_suspicious = True
                    reasons.append(f"Unusual authentication type: {auth_type}")
                
                # Check against threat intelligence if available
                if self.threat_intel:
                    threat_info = self.threat_intel.check_ip(ip)
                    if threat_info:
                        is_suspicious = True
                        source = threat_info.get('source', 'unknown')
                        threat_type = threat_info.get('type', 'suspicious')
                        reasons.append(f"Source IP found in threat feed {source} as {threat_type}")
                
                # Check if IP is from an unusual country/location
                # (would require GeoIP library, simplified here)
                
                # Check if the user logged in is unusual
                # (would require baseline of normal users)
                
                if is_suspicious:
                    suspicious_successful_logins.append({
                        'timestamp': timestamp.isoformat(),
                        'username': username,
                        'source_ip': ip,
                        'auth_type': auth_type,
                        'reasons': reasons
                    })
            
            # Check for suspicious patterns
            
            # 1. Check for login attempts with invalid users
            if invalid_users:
                auth_issues.append({
                    'issue': 'Login attempts with invalid users',
                    'count': len(invalid_users),
                    'users': list(invalid_users)[:10],  # Limit to 10 for brevity
                    'recommendation': "Investigate source of these attempts",
                    'severity': 'medium'
                })
            
            # 2. Check for successful logins after failures
            if suspicious_successful_logins:
                auth_issues.append({
                    'issue': 'Suspicious successful logins',
                    'count': len(suspicious_successful_logins),
                    'logins': suspicious_successful_logins,
                    'recommendation': "Investigate these logins for potential compromise",
                    'severity': 'high'
                })
            
            # 3. Check for high numbers of failed attempts
            high_failure_sources = {}
            for username, attempts in failed_attempts.items():
                for ip, _ in attempts:
                    high_failure_sources[ip] = high_failure_sources.get(ip, 0) + 1
            
            suspicious_sources = {ip: count for ip, count in high_failure_sources.items() if count >= 5}
            if suspicious_sources:
                auth_issues.append({
                    'issue': 'High numbers of failed login attempts from specific sources',
                    'sources': [{'ip': ip, 'count': count} for ip, count in suspicious_sources.items()],
                    'recommendation': "Consider blocking these IPs with firewall rules",
                    'severity': 'medium'
                })
            
            return {
                'count': len(auth_issues),
                'failed_attempts_count': sum(len(attempts) for attempts in failed_attempts.values()),
                'successful_logins_count': len(successful_logins),
                'issues': auth_issues,
                'recent_failed_attempts': recent_failed_attempts[:10],  # Limit to top 10
                'suspicious_logins': suspicious_successful_logins,
                'is_anomalous': len(suspicious_successful_logins) > 0 or len(auth_issues) > 0
            }
            
        except Exception as e:
            self.logger.error(f"Error checking SSH authentication logs: {e}")
            return {
                'error': str(e),
                'is_anomalous': False
            }
    
    def _process_auth_log_line(self, line, log_time, recent_time, failed_patterns, 
                              success_pattern, invalid_pattern, failed_attempts, 
                              successful_logins, invalid_users):
        """Process a single auth log line to extract relevant information"""
        # Skip if line is not recent enough
        if log_time < recent_time:
            return
            
        # Check for failed login attempts
        for pattern in failed_patterns:
            match = re.search(pattern, line)
            if match:
                # Extract username and IP if available (patterns may have different group counts)
                username = match.group(1) if match.lastindex >= 1 else "unknown"
                source_ip = match.group(2) if match.lastindex >= 2 else "unknown"
                
                failed_attempts[username].append((source_ip, log_time))
                break  # Stop after first match
        
        # Check for successful logins
        success_match = re.search(success_pattern, line)
        if success_match:
            auth_type = success_match.group(1)
            username = success_match.group(2)
            source_ip = success_match.group(3)
            
            successful_logins.append((auth_type, username, source_ip, log_time))
        
        # Check for invalid users
        invalid_match = re.search(invalid_pattern, line)
        if invalid_match:
            invalid_users.add(invalid_match.group(1))
    
    def _check_ssh_connections(self):
        """Check current SSH connections for anomalies"""
        self.logger.debug("Checking SSH connections")
        
        active_connections = []
        suspicious_connections = []
        
        try:
            # Get SSH connections using netstat
            cmd = ["netstat", "-tnp", "|", "grep", "sshd"]
            try:
                output = subprocess.check_output(cmd, universal_newlines=True, shell=True)
                
                # Parse the output
                for line in output.strip().split('\n'):
                    if not line.strip():
                        continue
                    
                    parts = line.split()
                    if len(parts) >= 7 and ("ESTABLISHED" in line or "CONNECTED" in line):
                        proto = parts[0]
                        local_addr = parts[3]
                        remote_addr = parts[4]
                        state = parts[5] if len(parts) > 5 else ""
                        pid_info = parts[6] if len(parts) > 6 else ""
                        
                        # Extract remote IP and port
                        remote_addr_parts = remote_addr.rsplit(':', 1)
                        if len(remote_addr_parts) == 2:
                            remote_ip = remote_addr_parts[0]
                            remote_port = int(remote_addr_parts[1])
                        else:
                            remote_ip = remote_addr
                            remote_port = 0
                        
                        # Extract PID and program
                        pid = ""
                        program = ""
                        
                        pid_match = re.search(r'(\d+)/(.*)', pid_info)
                        if pid_match:
                            pid = pid_match.group(1)
                            program = pid_match.group(2)
                        
                        connection = {
                            'remote_ip': remote_ip,
                            'remote_port': remote_port,
                            'state': state,
                            'pid': pid,
                            'program': program
                        }
                        
                        active_connections.append(connection)
                        
                        # Check if connection is suspicious
                        is_suspicious = False
                        reasons = []
                        
                        # Check against threat intelligence if available
                        if self.threat_intel:
                            threat_info = self.threat_intel.check_ip(remote_ip)
                            if threat_info:
                                is_suspicious = True
                                source = threat_info.get('source', 'unknown')
                                threat_type = threat_info.get('type', 'suspicious')
                                reasons.append(f"Source IP found in threat feed {source} as {threat_type}")
                        
                        # Try to get user information for the connection
                        try:
                            if pid:
                                # Use lsof to get user information
                                cmd = ["lsof", "-p", pid]
                                lsof_output = subprocess.check_output(cmd, universal_newlines=True)
                                
                                # Extract username
                                username = None
                                for lsof_line in lsof_output.split('\n'):
                                    if lsof_line.startswith(program):
                                        lsof_parts = lsof_line.split()
                                        if len(lsof_parts) > 2:
                                            username = lsof_parts[2]
                                            break
                                
                                if username:
                                    connection['username'] = username
                                    
                                    # Check if root login
                                    if username == 'root':
                                        is_suspicious = True
                                        reasons.append("Root login detected")
                                        
                                    # Check active session duration
                                    try:
                                        cmd = ["ps", "-o", "etimes=", "-p", pid]
                                        ps_output = subprocess.check_output(cmd, universal_newlines=True).strip()
                                        
                                        if ps_output and ps_output.isdigit():
                                            session_time = int(ps_output)
                                            connection['session_time'] = session_time
                                            
                                            # Flag very long sessions (> 24 hours)
                                            if session_time > 86400:
                                                reasons.append(f"Very long session ({session_time//3600} hours)")
                                    except:
                                        pass
                        except:
                            # Could not get user information
                            pass
                        
                        # Check for unusual ports
                        common_ssh_client_ports = [22, 2222]
                        if remote_port not in common_ssh_client_ports:
                            # Not necessarily suspicious, but unusual
                            connection['unusual_port'] = True
                        
                        # Check for internal IP connecting from outside
                        try:
                            ip_obj = ipaddress.ip_address(remote_ip)
                            if not ip_obj.is_private and not ip_obj.is_loopback:
                                # External IP - not suspicious by itself
                                connection['external_ip'] = True
                        except ValueError:
                            # Not a valid IP address
                            pass
                        
                        if is_suspicious:
                            connection['is_suspicious'] = True
                            connection['reasons'] = reasons
                            suspicious_connections.append(connection)
            except subprocess.CalledProcessError:
                # No SSH connections found
                pass
            
            # Get alternative view using 'who' command
            active_users = []
            try:
                cmd = ["who"]
                who_output = subprocess.check_output(cmd, universal_newlines=True)
                
                for line in who_output.strip().split('\n'):
                    if not line.strip():
                        continue
                    
                    parts = line.split()
                    if len(parts) >= 5:
                        username = parts[0]
                        tty = parts[1]
                        login_time = ' '.join(parts[2:4])
                        
                        # Look for remote connections
                        source_ip = None
                        if '(' in line and ')' in line:
                            source_match = re.search(r'\((.*?)\)', line)
                            if source_match:
                                source_ip = source_match.group(1)
                        
                        if source_ip:
                            user_session = {
                                'username': username,
                                'tty': tty,
                                'login_time': login_time,
                                'source_ip': source_ip
                            }
                            
                            active_users.append(user_session)
                            
                            # Cross-reference with connections
                            for conn in active_connections:
                                if conn.get('remote_ip') == source_ip:
                                    conn['username'] = username
                                    conn['login_time'] = login_time
                                    
                                    # Check if root login
                                    if username == 'root':
                                        if 'is_suspicious' not in conn:
                                            conn['is_suspicious'] = True
                                            conn['reasons'] = ["Root login detected"]
                                            suspicious_connections.append(conn)
                                        elif "Root login detected" not in conn.get('reasons', []):
                                            conn['reasons'].append("Root login detected")
            except subprocess.CalledProcessError:
                # Could not run 'who' command
                pass
            
            # Check for unusual patterns across connections
            
            # Multiple connections from same source
            source_counts = defaultdict(int)
            for conn in active_connections:
                source_ip = conn.get('remote_ip')
                if source_ip:
                    source_counts[source_ip] += 1
            
            multiple_connection_sources = {ip: count for ip, count in source_counts.items() if count > 2}
            
            # Determine if there are any anomalies
            is_anomalous = len(suspicious_connections) > 0 or multiple_connection_sources
            
            return {
                'active_count': len(active_connections),
                'suspicious_count': len(suspicious_connections),
                'active_connections': active_connections,
                'suspicious_connections': suspicious_connections,
                'active_users': active_users,
                'multiple_connection_sources': [{'ip': ip, 'count': count} for ip, count in multiple_connection_sources.items()],
                'is_anomalous': is_anomalous
            }
            
        except Exception as e:
            self.logger.error(f"Error checking SSH connections: {e}")
            return {
                'error': str(e),
                'is_anomalous': False
            }
    
    def _check_bruteforce(self):
        """Check for SSH brute force attempts"""
        self.logger.debug("Checking for SSH brute force attempts")
        
        bruteforce_attempts = []
        
        try:
            # Find the first available auth log
            auth_log_path = None
            for log_path in self.auth_log_paths:
                if os.path.exists(log_path):
                    auth_log_path = log_path
                    break
            
            if not auth_log_path:
                return {
                    'error': f"No SSH authentication logs found",
                    'searched_paths': self.auth_log_paths,
                    'is_anomalous': False
                }
            
            # Look for brute force attacks in the last hour
            cutoff_time = time.time() - 3600
            
            # Use fail2ban-like logic to detect brute force attempts
            failed_attempts = defaultdict(list)
            
            # Try both direct reading and using grep
            try:
                # Get recent failed login attempts
                cmd = ["grep", "Failed password for", auth_log_path, "|", "tail", "-1000"]
                try:
                    output = subprocess.check_output(cmd, universal_newlines=True, shell=True)
                    
                    # Parse the failed attempts
                    for line in output.strip().split('\n'):
                        if not line:
                            continue
                        
                        # Extract timestamp
                        timestamp_match = re.search(r'(\w{3}\s+\d+\s+\d+:\d+:\d+)', line)
                        if timestamp_match:
                            timestamp_str = timestamp_match.group(1)
                            try:
                                # Add current year since logs don't include year
                                current_year = datetime.now().year
                                log_time = datetime.strptime(f"{timestamp_str} {current_year}", "%b %d %H:%M:%S %Y")
                                
                                # Handle year rollover
                                if log_time > datetime.now():
                                    log_time = log_time.replace(year=current_year - 1)
                                
                                # Skip entries older than our cutoff
                                if log_time.timestamp() < cutoff_time:
                                    continue
                            except:
                                # On parsing error, just process the line anyway
                                pass
                        
                        # Extract username and source IP
                        user_ip_match = re.search(r'Failed password for (?:invalid user )?(\S+) from (\S+)', line)
                        if user_ip_match:
                            username = user_ip_match.group(1)
                            source_ip = user_ip_match.group(2)
                            
                            # Record this attempt
                            if username != 'invalid':  # Skip generic 'invalid' entries
                                failed_attempts[source_ip].append((username, line))
                except subprocess.CalledProcessError:
                    # Could not run grep command
                    self.logger.warning("Could not run grep command for brute force detection")
            except Exception as e:
                self.logger.error(f"Error parsing auth log for brute force: {e}")
            
            # Analyze for brute force patterns
            for source_ip, attempts in failed_attempts.items():
                if len(attempts) >= self.bf_attempt_threshold:
                    # Check for attempts within time window
                    # (simplified - a more thorough implementation would parse actual timestamps)
                    
                    # Get unique usernames tried
                    usernames = list(set(username for username, _ in attempts))
                    
                    bruteforce_attempts.append({
                        'source_ip': source_ip,
                        'attempt_count': len(attempts),
                        'usernames_tried': usernames[:10],  # Limit to 10 for brevity
                        'username_count': len(usernames)
                    })
            
            # Check against threat intelligence
            if self.threat_intel and bruteforce_attempts:
                for attempt in bruteforce_attempts:
                    source_ip = attempt.get('source_ip')
                    if source_ip:
                        threat_info = self.threat_intel.check_ip(source_ip)
                        if threat_info:
                            attempt['threat_info'] = threat_info
            
            # Sort by attempt count
            bruteforce_attempts.sort(key=lambda x: x.get('attempt_count', 0), reverse=True)
            
            # Determine if there are any anomalies
            is_anomalous = len(bruteforce_attempts) > 0
            
            return {
                'count': len(bruteforce_attempts),
                'time_window': self.bf_time_window,
                'attempt_threshold': self.bf_attempt_threshold,
                'bruteforce_attempts': bruteforce_attempts,
                'is_anomalous': is_anomalous
            }
            
        except Exception as e:
            self.logger.error(f"Error checking for SSH brute force attempts: {e}")
            return {
                'error': str(e),
                'is_anomalous': False
            }
    
    def establish_baseline(self):
        """Establish baseline for SSH security"""
        self.logger.info("Establishing baseline for SSH security")
        
        # Build baseline data
        ssh_config = self._get_ssh_config_baseline()
        ssh_keys = self._get_ssh_keys_baseline()
        ssh_users = self._get_ssh_users_baseline()
        
        baseline = {
            'timestamp': datetime.now().isoformat(),
            'hostname': socket.gethostname(),
            'ssh_config': ssh_config,
            'ssh_keys': ssh_keys,
            'ssh_users': ssh_users
        }
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.baseline_file), exist_ok=True)
        
        # Write baseline to file
        with open(self.baseline_file, 'w') as f:
            json.dump(baseline, f, indent=2)
        
        self.logger.info(f"Baseline saved to {self.baseline_file}")
        
        return baseline
    
    def _get_ssh_config_baseline(self):
        """Get baseline for SSH server configuration"""
        try:
            config_settings = {}
            
            # Check if SSH config file exists
            if not os.path.exists(self.ssh_config_path):
                return {'error': 'SSH config file not found'}
            
            # Parse SSH config file
            with open(self.ssh_config_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        continue
                    
                    # Parse key-value settings
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        key, value = parts
                        config_settings[key] = value
            
            # Get config file hash
            try:
                with open(self.ssh_config_path, 'rb') as f:
                    config_hash = hashlib.sha256(f.read()).hexdigest()
                    config_settings['_file_hash'] = config_hash
            except:
                pass
            
            # Get host keys information
            host_keys = []
            for key_type in ['rsa', 'dsa', 'ecdsa', 'ed25519']:
                key_path = f'/etc/ssh/ssh_host_{key_type}_key'
                if os.path.exists(key_path):
                    key_info = {'type': key_type, 'path': key_path}
                    
                    # Get public key fingerprint
                    try:
                        pub_key_path = f"{key_path}.pub"
                        if os.path.exists(pub_key_path):
                            cmd = ["ssh-keygen", "-lf", pub_key_path]
                            output = subprocess.check_output(cmd, universal_newlines=True)
                            key_info['fingerprint'] = output.strip()
                    except:
                        pass
                    
                    host_keys.append(key_info)
            
            return {
                'settings': config_settings,
                'host_keys': host_keys
            }
            
        except Exception as e:
            self.logger.error(f"Error getting SSH config baseline: {e}")
            return {'error': str(e)}
    
    def _get_ssh_keys_baseline(self):
        """Get baseline for SSH keys"""
        try:
            key_info = []
            
            # Find SSH keys
            for path in self.ssh_key_paths:
                if os.path.exists(path):
                    if path == '/home':
                        # Special handling for /home directory
                        try:
                            # Get all user home directories
                            for user_dir in os.listdir(path):
                                user_ssh_dir = os.path.join(path, user_dir, '.ssh')
                                if os.path.isdir(user_ssh_dir):
                                    # Create fingerprints of key files
                                    self._process_key_dir(user_ssh_dir, key_info)
                        except Exception as e:
                            self.logger.error(f"Error scanning user home directories: {e}")
                    else:
                        # Regular directory scan
                        self._process_key_dir(path, key_info)
            
            return key_info
            
        except Exception as e:
            self.logger.error(f"Error getting SSH keys baseline: {e}")
            return []
    
    def _process_key_dir(self, directory, key_info):
        """Process an SSH key directory and update key_info list"""
        for root, _, files in os.walk(directory):
            for file in files:
                # Focus on public keys for baseline (safer)
                if file.endswith('.pub') or file == 'authorized_keys':
                    key_path = os.path.join(root, file)
                    
                    try:
                        # Get key fingerprint
                        cmd = ["ssh-keygen", "-lf", key_path]
                        try:
                            output = subprocess.check_output(cmd, universal_newlines=True)
                            fingerprint = output.strip()
                        except subprocess.CalledProcessError:
                            fingerprint = "Error getting fingerprint"
                        
                        # Get file stats
                        key_stat = os.stat(key_path)
                        
                        # Get owner info
                        try:
                            owner_name = pwd.getpwuid(key_stat.st_uid).pw_name
                        except KeyError:
                            owner_name = str(key_stat.st_uid)
                        
                        key_info.append({
                            'path': key_path,
                            'owner': owner_name,
                            'fingerprint': fingerprint,
                            'permissions': oct(key_stat.st_mode & 0o777),
                            'last_modified': datetime.fromtimestamp(key_stat.st_mtime).isoformat()
                        })
                    except Exception as e:
                        self.logger.error(f"Error processing key {key_path}: {e}")
    
    def _get_ssh_users_baseline(self):
        """Get baseline for SSH users"""
        try:
            # Get users who can SSH in
            ssh_users = []
            
            # Look for users in AllowUsers directive in sshd_config
            if os.path.exists(self.ssh_config_path):
                with open(self.ssh_config_path, 'r') as f:
                    for line in f:
                        if line.strip().startswith('AllowUsers'):
                            allowed = line.strip().split()[1:]
                            for user in allowed:
                                ssh_users.append({'username': user, 'source': 'AllowUsers'})
            
            # Look for users in AllowGroups directive in sshd_config
            allowed_groups = []
            if os.path.exists(self.ssh_config_path):
                with open(self.ssh_config_path, 'r') as f:
                    for line in f:
                        if line.strip().startswith('AllowGroups'):
                            allowed_groups = line.strip().split()[1:]
            
            # Get users from allowed groups
            if allowed_groups:
                try:
                    import grp
                    for group_name in allowed_groups:
                        try:
                            group = grp.getgrnam(group_name)
                            for member in group.gr_mem:
                                ssh_users.append({'username': member, 'source': f'AllowGroups ({group_name})'})
                        except KeyError:
                            # Group not found
                            pass
                except ImportError:
                    # Group module not available
                    pass
            
            # If no explicit allows, get all users with SSH keys
            if not ssh_users:
                # Look at authorized_keys files
                for user_info in pwd.getpwall():
                    username = user_info.pw_name
                    home_dir = user_info.pw_dir
                    
                    if home_dir and os.path.isdir(home_dir):
                        auth_keys_path = os.path.join(home_dir, '.ssh', 'authorized_keys')
                        if os.path.exists(auth_keys_path):
                            ssh_users.append({'username': username, 'source': 'authorized_keys'})
            
            # Get historical SSH users from auth log
            historical_users = set()
            for log_path in self.auth_log_paths:
                if os.path.exists(log_path):
                    try:
                        cmd = ["grep", "Accepted", log_path, "|", "grep", "sshd"]
                        output = subprocess.check_output(cmd, universal_newlines=True, shell=True)
                        
                        # Parse out usernames from successful logins
                        for line in output.strip().split('\n'):
                            match = re.search(r'Accepted \S+ for (\S+) from', line)
                            if match:
                                username = match.group(1)
                                historical_users.add(username)
                    except subprocess.CalledProcessError:
                        # No matches found
                        pass
            
            # Add historical users to the list
            for username in historical_users:
                if not any(user['username'] == username for user in ssh_users):
                    ssh_users.append({'username': username, 'source': 'auth_logs'})
            
            return ssh_users
            
        except Exception as e:
            self.logger.error(f"Error getting SSH users baseline: {e}")
            return []
    
    def compare_baseline(self):
        """Compare current SSH security with baseline"""
        self.logger.info("Comparing SSH security with baseline")
        
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
        current_config = self._get_ssh_config_baseline()
        current_keys = self._get_ssh_keys_baseline()
        current_users = self._get_ssh_users_baseline()
        
        # Compare SSH config
        config_changes = self._compare_ssh_config(baseline.get('ssh_config', {}), current_config)
        
        # Compare SSH keys
        key_changes = self._compare_ssh_keys(baseline.get('ssh_keys', []), current_keys)
        
        # Compare SSH users
        user_changes = self._compare_ssh_users(baseline.get('ssh_users', []), current_users)
        
        # Determine if there are any anomalies
        is_anomalous = (
            config_changes.get('is_anomalous', False) or
            key_changes.get('is_anomalous', False) or
            user_changes.get('is_anomalous', False)
        )
        
        return {
            'timestamp': datetime.now().isoformat(),
            'baseline_timestamp': baseline.get('timestamp'),
            'config_changes': config_changes,
            'key_changes': key_changes,
            'user_changes': user_changes,
            'is_anomalous': is_anomalous
        }
    
    def _compare_ssh_config(self, baseline_config, current_config):
        """Compare SSH configurations"""
        changes = {
            'changed_settings': [],
            'new_settings': [],
            'removed_settings': [],
            'host_key_changes': [],
            'is_anomalous': False
        }
        
        try:
            # Compare basic config file integrity
            baseline_hash = baseline_config.get('settings', {}).get('_file_hash')
            current_hash = current_config.get('settings', {}).get('_file_hash')
            
            if baseline_hash and current_hash and baseline_hash != current_hash:
                changes['file_changed'] = True
            
            # Compare settings
            baseline_settings = baseline_config.get('settings', {})
            current_settings = current_config.get('settings', {})
            
            # Find changed settings
            for key, base_value in baseline_settings.items():
                if key == '_file_hash':
                    continue
                    
                if key in current_settings:
                    if current_settings[key] != base_value:
                        changes['changed_settings'].append({
                            'setting': key,
                            'old_value': base_value,
                            'new_value': current_settings[key]
                        })
                else:
                    changes['removed_settings'].append({
                        'setting': key,
                        'old_value': base_value
                    })
            
            # Find new settings
            for key, curr_value in current_settings.items():
                if key == '_file_hash':
                    continue
                    
                if key not in baseline_settings:
                    changes['new_settings'].append({
                        'setting': key,
                        'value': curr_value
                    })
            
            # Check for security-critical changes
            security_critical_settings = [
                'PermitRootLogin', 'PasswordAuthentication', 'PermitEmptyPasswords',
                'Protocol', 'UsePAM', 'HostbasedAuthentication', 'PubkeyAuthentication',
                'Ciphers', 'MACs', 'KexAlgorithms'
            ]
            
            for change in changes['changed_settings']:
                if change['setting'] in security_critical_settings:
                    change['security_critical'] = True
                    changes['is_anomalous'] = True
            
            # Compare host keys
            baseline_host_keys = {key['type']: key for key in baseline_config.get('host_keys', [])}
            current_host_keys = {key['type']: key for key in current_config.get('host_keys', [])}
            
            # Check for changed host keys
            for key_type, base_key in baseline_host_keys.items():
                if key_type in current_host_keys:
                    current_key = current_host_keys[key_type]
                    base_fingerprint = base_key.get('fingerprint', '')
                    current_fingerprint = current_key.get('fingerprint', '')
                    
                    if base_fingerprint and current_fingerprint and base_fingerprint != current_fingerprint:
                        changes['host_key_changes'].append({
                            'type': key_type,
                            'old_fingerprint': base_fingerprint,
                            'new_fingerprint': current_fingerprint,
                            'security_critical': True
                        })
                        changes['is_anomalous'] = True
                else:
                    changes['host_key_changes'].append({
                        'type': key_type,
                        'old_fingerprint': base_key.get('fingerprint', ''),
                        'status': 'removed',
                        'security_critical': True
                    })
                    changes['is_anomalous'] = True
            
            # Check for new host keys
            for key_type, curr_key in current_host_keys.items():
                if key_type not in baseline_host_keys:
                    changes['host_key_changes'].append({
                        'type': key_type,
                        'new_fingerprint': curr_key.get('fingerprint', ''),
                        'status': 'added',
                        'security_critical': True
                    })
                    changes['is_anomalous'] = True
            
            return changes
            
        except Exception as e:
            self.logger.error(f"Error comparing SSH configurations: {e}")
            return {
                'error': str(e),
                'is_anomalous': False
            }
    
    def _compare_ssh_keys(self, baseline_keys, current_keys):
        """Compare SSH keys"""
        changes = {
            'new_keys': [],
            'removed_keys': [],
            'modified_keys': [],
            'is_anomalous': False
        }
        
        try:
            # Create dictionaries keyed by path
            baseline_dict = {key['path']: key for key in baseline_keys}
            current_dict = {key['path']: key for key in current_keys}
            
            # Find new keys
            for path, key in current_dict.items():
                if path not in baseline_dict:
                    changes['new_keys'].append(key)
            
            # Find removed keys
            for path, key in baseline_dict.items():
                if path not in current_dict:
                    changes['removed_keys'].append(key)
            
            # Find modified keys
            for path, curr_key in current_dict.items():
                if path in baseline_dict:
                    base_key = baseline_dict[path]
                    
                    # Check fingerprint changes
                    base_fingerprint = base_key.get('fingerprint', '')
                    curr_fingerprint = curr_key.get('fingerprint', '')
                    
                    if base_fingerprint and curr_fingerprint and base_fingerprint != curr_fingerprint:
                        modified_key = curr_key.copy()
                        modified_key['old_fingerprint'] = base_fingerprint
                        modified_key['change_type'] = 'fingerprint'
                        changes['modified_keys'].append(modified_key)
                    
                    # Check permission changes
                    base_perms = base_key.get('permissions', '')
                    curr_perms = curr_key.get('permissions', '')
                    
                    if base_perms and curr_perms and base_perms != curr_perms:
                        # Only add if not already added for fingerprint change
                        if not any(k['path'] == path and k.get('change_type') == 'fingerprint' 
                                 for k in changes['modified_keys']):
                            modified_key = curr_key.copy()
                            modified_key['old_permissions'] = base_perms
                            modified_key['change_type'] = 'permissions'
                            changes['modified_keys'].append(modified_key)
            
            # Determine if changes are security critical
            security_critical_paths = ['authorized_keys', '/etc/ssh/ssh_host_']
            
            # Flag security critical changes
            for key_list in [changes['new_keys'], changes['removed_keys'], changes['modified_keys']]:
                for key in key_list:
                    if any(critical in key['path'] for critical in security_critical_paths):
                        key['security_critical'] = True
                        changes['is_anomalous'] = True
            
            return changes
            
        except Exception as e:
            self.logger.error(f"Error comparing SSH keys: {e}")
            return {
                'error': str(e),
                'is_anomalous': False
            }
    
    def _compare_ssh_users(self, baseline_users, current_users):
        """Compare SSH users"""
        changes = {
            'new_users': [],
            'removed_users': [],
            'is_anomalous': False
        }
        
        try:
            # Create dictionaries keyed by username
            baseline_dict = {user['username']: user for user in baseline_users}
            current_dict = {user['username']: user for user in current_users}
            
            # Find new users
            for username, user in current_dict.items():
                if username not in baseline_dict:
                    changes['new_users'].append(user)
                    
                    # New users are security critical
                    user['security_critical'] = True
                    changes['is_anomalous'] = True
            
            # Find removed users
            for username, user in baseline_dict.items():
                if username not in current_dict:
                    changes['removed_users'].append(user)
            
            return changes
            
        except Exception as e:
            self.logger.error(f"Error comparing SSH users: {e}")
            return {
                'error': str(e),
                'is_anomalous': False
            }
    
    def _check_ssh_tunnels(self):
        """Check for SSH tunneling and port forwarding activities"""
        self.logger.debug("Checking for SSH tunneling and port forwarding")
        
        tunnel_findings = []
        port_forwards = []
        suspicious_tunnels = []
        
        try:
            # Check active SSH sessions for port forwarding
            cmd = ["netstat", "-tunp", "|", "grep", "ssh"]
            try:
                output = subprocess.check_output(cmd, universal_newlines=True, shell=True)
                
                # Parse connections for tunneling patterns
                # LISTEN state on non-standard ports often indicates port forwarding
                for line in output.strip().split('\n'):
                    if not line.strip():
                        continue
                    
                    # Check for LISTEN state which often indicates forwarding
                    if "LISTEN" in line and "ssh" in line:
                        parts = line.split()
                        
                        if len(parts) >= 4:
                            local_addr = parts[3]
                            local_parts = local_addr.rsplit(':', 1)
                            
                            if len(local_parts) == 2:
                                listen_addr = local_parts[0]
                                listen_port = local_parts[1]
                                
                                # Extract process info
                                pid_info = ""
                                for part in parts:
                                    if "/" in part:
                                        pid_info = part
                                        break
                                
                                # Prepare information about this forwarding
                                port_forward = {
                                    'local_addr': listen_addr,
                                    'local_port': listen_port,
                                    'pid_info': pid_info
                                }
                                
                                # Check if this is a commonly forwarded port
                                common_forwarded_ports = ['3306', '5432', '27017', '6379', '8080', '8443', '9000']
                                port_forward['common_service'] = listen_port in common_forwarded_ports
                                
                                # Flag unusual bind addresses
                                if listen_addr == '0.0.0.0':
                                    port_forward['exposed_to_all'] = True
                                    port_forward['security_risk'] = "Port forward exposed to all interfaces"
                                    
                                    # This is particularly risky for sensitive services
                                    sensitive_ports = {
                                        '3306': 'MySQL',
                                        '5432': 'PostgreSQL',
                                        '27017': 'MongoDB',
                                        '6379': 'Redis',
                                        '1433': 'MSSQL',
                                        '9200': 'Elasticsearch'
                                    }
                                    
                                    if listen_port in sensitive_ports:
                                        port_forward['sensitive_service'] = sensitive_ports[listen_port]
                                        port_forward['severity'] = 'high'
                                    else:
                                        port_forward['severity'] = 'medium'
                                    
                                    suspicious_tunnels.append(port_forward)
                                
                                port_forwards.append(port_forward)
                        
                    # Check for ESTABLISHED connections that may be part of tunnel chains
                    elif "ESTABLISHED" in line and "ssh" in line:
                        parts = line.split()
                        
                        if len(parts) >= 4:
                            local_addr = parts[3]
                            remote_addr = parts[4]
                            
                            # Extract PIDs
                            pid_info = ""
                            for part in parts:
                                if "/" in part:
                                    pid_info = part
                                    break
                            
                            # Check for unusual remote ports
                            remote_parts = remote_addr.rsplit(':', 1)
                            if len(remote_parts) == 2:
                                remote_ip = remote_parts[0]
                                remote_port = remote_parts[1]
                                
                                if remote_port != '22' and remote_port != '2222':
                                    # SSH connection to non-standard port could be a tunnel chain
                                    tunnel_finding = {
                                        'local_addr': local_addr,
                                        'remote_addr': remote_addr,
                                        'remote_ip': remote_ip,
                                        'remote_port': remote_port,
                                        'pid_info': pid_info,
                                        'finding': 'SSH connection to non-standard port',
                                        'severity': 'low'
                                    }
                                    
                                    tunnel_findings.append(tunnel_finding)
            except subprocess.CalledProcessError:
                # No SSH connections found
                pass
            
            # Check processes for command-line signs of tunneling
            try:
                # Find all SSH processes
                ssh_procs = subprocess.check_output(["ps", "-eo", "pid,command", "|", "grep", "ssh"], 
                                                   universal_newlines=True, shell=True)
                
                for line in ssh_procs.strip().split('\n'):
                    if "grep ssh" in line:  # Skip the grep process itself
                        continue
                        
                    # Check for tunneling options in command line
                    tunnel_flags = ['-L', '-R', '-D', '-N', '-f']
                    tunnel_type = None
                    
                    for flag in tunnel_flags:
                        if f" {flag} " in line or line.endswith(f" {flag}"):
                            if flag == '-L':
                                tunnel_type = 'local'
                            elif flag == '-R':
                                tunnel_type = 'remote'
                            elif flag == '-D':
                                tunnel_type = 'dynamic (SOCKS)'
                            
                            # Extract PID
                            parts = line.strip().split()
                            if parts:
                                pid = parts[0]
                                command = ' '.join(parts[1:])
                                
                                # Parse tunnel specification if possible
                                tunnel_spec = self._parse_tunnel_spec(command, tunnel_type)
                                
                                # Get username if possible
                                username = self._get_process_owner(pid)
                                
                                finding = {
                                    'pid': pid,
                                    'command': command,
                                    'tunnel_type': tunnel_type,
                                    'username': username
                                }
                                
                                if tunnel_spec:
                                    finding.update(tunnel_spec)
                                
                                # Check if this is a background tunnel (-f flag)
                                if ' -f ' in line or line.endswith(' -f'):
                                    finding['background'] = True
                                
                                # Check if this is possibly a persistent tunnel
                                if ' -N ' in line or line.endswith(' -N'):
                                    finding['no_shell'] = True
                                    
                                # Determine severity
                                if tunnel_type == 'remote':
                                    # Remote tunnels allow external access to internal resources
                                    finding['severity'] = 'high'
                                    finding['security_risk'] = "Remote tunnel may expose internal services"
                                    suspicious_tunnels.append(finding)
                                elif tunnel_type == 'dynamic':
                                    # SOCKS proxies can be used to bypass security controls
                                    finding['severity'] = 'medium'
                                    finding['security_risk'] = "Dynamic proxy may allow security bypass"
                                    suspicious_tunnels.append(finding)
                                elif tunnel_type == 'local' and tunnel_spec and tunnel_spec.get('bind_address') == '0.0.0.0':
                                    # Local tunnels bound to all interfaces can be a risk
                                    finding['severity'] = 'medium'
                                    finding['security_risk'] = "Local tunnel exposed to all interfaces"
                                    suspicious_tunnels.append(finding)
                                else:
                                    finding['severity'] = 'low'
                                
                                tunnel_findings.append(finding)
            except subprocess.CalledProcessError:
                # Error or no SSH processes found
                pass
            
            # Check for related configurations in SSH config
            if os.path.exists(self.ssh_config_path):
                with open(self.ssh_config_path, 'r') as f:
                    config_content = f.read()
                    
                    # Look for permissive forwarding settings
                    if re.search(r'^\s*AllowTcpForwarding\s+yes', config_content, re.MULTILINE):
                        tunnel_findings.append({
                            'finding': 'SSH server allows TCP forwarding',
                            'config': 'AllowTcpForwarding yes',
                            'recommendation': 'Set AllowTcpForwarding to no if not required',
                            'severity': 'medium'
                        })
                    
                    if re.search(r'^\s*GatewayPorts\s+yes', config_content, re.MULTILINE):
                        tunnel_findings.append({
                            'finding': 'SSH server allows remote hosts to connect to forwarded ports',
                            'config': 'GatewayPorts yes',
                            'recommendation': 'Set GatewayPorts to no unless explicitly required',
                            'severity': 'high',
                            'security_risk': "Remote tunnels can be accessed from any host"
                        })
                        suspicious_tunnels.append({
                            'config': 'GatewayPorts yes',
                            'severity': 'high',
                            'security_risk': "Remote tunnels can be accessed from any host"
                        })
                    
                    if re.search(r'^\s*PermitTunnel\s+yes', config_content, re.MULTILINE):
                        tunnel_findings.append({
                            'finding': 'SSH server allows tun device forwarding',
                            'config': 'PermitTunnel yes',
                            'recommendation': 'Set PermitTunnel to no unless VPN functionality is required',
                            'severity': 'medium'
                        })
            
            # Determine if there are any anomalies
            is_anomalous = len(suspicious_tunnels) > 0
            
            # Check against threat intelligence if available
            if self.threat_intel and tunnel_findings:
                for finding in tunnel_findings:
                    # Check remote hosts in tunnels
                    if 'remote_ip' in finding:
                        remote_ip = finding['remote_ip']
                        threat_info = self.threat_intel.check_ip(remote_ip)
                        if threat_info:
                            finding['threat_info'] = threat_info
                            finding['severity'] = 'high'
                            finding['security_risk'] = f"Tunnel to known malicious host: {threat_info.get('type', 'suspicious')}"
                            is_anomalous = True
                            if finding not in suspicious_tunnels:
                                suspicious_tunnels.append(finding)
            
            return {
                'tunnels_count': len(tunnel_findings),
                'port_forwards_count': len(port_forwards),
                'suspicious_count': len(suspicious_tunnels),
                'findings': tunnel_findings,
                'port_forwards': port_forwards,
                'suspicious_tunnels': suspicious_tunnels,
                'is_anomalous': is_anomalous
            }
            
        except Exception as e:
            self.logger.error(f"Error checking SSH tunnels: {e}")
            return {
                'error': str(e),
                'is_anomalous': False
            }
    
    def _get_process_owner(self, pid):
        """Get owner of a process"""
        try:
            output = subprocess.check_output(["ps", "-o", "user=", "-p", pid], universal_newlines=True)
            return output.strip()
        except:
            return None
    
    def _parse_tunnel_spec(self, command, tunnel_type):
        """Parse tunnel specification from SSH command line"""
        try:
            if not tunnel_type:
                return None
                
            # Look for tunnel specifications
            spec_matches = []
            
            if tunnel_type == 'local':
                # Format: -L [bind_address:]port:host:hostport
                spec_matches = re.findall(r'-L\s+(\S+)', command)
            elif tunnel_type == 'remote':
                # Format: -R [bind_address:]port:host:hostport
                spec_matches = re.findall(r'-R\s+(\S+)', command)
            elif tunnel_type == 'dynamic':
                # Format: -D [bind_address:]port
                spec_matches = re.findall(r'-D\s+(\S+)', command)
            
            if not spec_matches:
                return None
                
            spec = spec_matches[0]
            
            if tunnel_type in ['local', 'remote']:
                parts = spec.split(':')
                
                if len(parts) == 3:
                    # port:host:hostport
                    return {
                        'bind_address': '127.0.0.1',  # Default
                        'bind_port': parts[0],
                        'target_host': parts[1],
                        'target_port': parts[2]
                    }
                elif len(parts) == 4:
                    # bind_address:port:host:hostport
                    return {
                        'bind_address': parts[0],
                        'bind_port': parts[1],
                        'target_host': parts[2],
                        'target_port': parts[3]
                    }
            elif tunnel_type == 'dynamic':
                parts = spec.split(':')
                
                if len(parts) == 1:
                    # port
                    return {
                        'bind_address': '127.0.0.1',  # Default
                        'bind_port': parts[0]
                    }
                elif len(parts) == 2:
                    # bind_address:port
                    return {
                        'bind_address': parts[0],
                        'bind_port': parts[1]
                    }
            
            return None
        except:
            return None
    
    def _check_ssh_key_usage(self):
        """Analyze SSH key usage patterns"""
        self.logger.debug("Analyzing SSH key usage patterns")
        
        key_usage = []
        suspicious_patterns = []
        key_statistics = {}
        
        try:
            # Find valid auth log
            auth_log_path = None
            for log_path in self.auth_log_paths:
                if os.path.exists(log_path):
                    auth_log_path = log_path
                    break
            
            if not auth_log_path:
                return {
                    'error': "No SSH authentication logs found",
                    'is_anomalous': False
                }
            
            # Parse logs for key usage
            key_auth_logs = []
            
            try:
                # Use grep to find publickey authentications
                cmd = ["grep", "publickey", auth_log_path, "|", "grep", "Accepted"]
                key_log_output = subprocess.check_output(cmd, universal_newlines=True, shell=True)
                
                # Process the log entries
                for line in key_log_output.strip().split('\n'):
                    if not line:
                        continue
                    
                    # Extract timestamp, user, and source IP
                    timestamp_match = re.search(r'(\w{3}\s+\d+\s+\d+:\d+:\d+)', line)
                    user_match = re.search(r'Accepted publickey for (\S+) from (\S+)', line)
                    key_match = re.search(r'publickey for \S+ from \S+.*: (\S+)', line)
                    
                    if timestamp_match and user_match:
                        timestamp_str = timestamp_match.group(1)
                        username = user_match.group(1)
                        source_ip = user_match.group(2)
                        key_type = key_match.group(1) if key_match else "unknown"
                        
                        # Parse timestamp
                        try:
                            current_year = datetime.now().year
                            log_time = datetime.strptime(f"{timestamp_str} {current_year}", "%b %d %H:%M:%S %Y")
                            
                            # Handle year rollover
                            if log_time > datetime.now():
                                log_time = log_time.replace(year=current_year - 1)
                                
                            timestamp = log_time.isoformat()
                        except:
                            timestamp = timestamp_str
                        
                        entry = {
                            'timestamp': timestamp,
                            'username': username,
                            'source_ip': source_ip,
                            'key_type': key_type
                        }
                        
                        key_auth_logs.append(entry)
            except subprocess.CalledProcessError:
                # No key authentication logs found
                pass
            
            # Analyze key usage patterns
            if key_auth_logs:
                # Group by user, source, and key type
                usage_by_user = defaultdict(list)
                usage_by_source = defaultdict(list)
                usage_by_key_type = defaultdict(list)
                
                for entry in key_auth_logs:
                    username = entry['username']
                    source_ip = entry['source_ip']
                    key_type = entry['key_type']
                    
                    usage_by_user[username].append(entry)
                    usage_by_source[source_ip].append(entry)
                    usage_by_key_type[key_type].append(entry)
                
                # Create statistics
                key_statistics = {
                    'users_count': len(usage_by_user),
                    'sources_count': len(usage_by_source),
                    'key_types_count': len(usage_by_key_type),
                    'total_auth_count': len(key_auth_logs),
                    'top_users': [{'username': k, 'count': len(v)} for k, v in 
                                sorted(usage_by_user.items(), key=lambda x: len(x[1]), reverse=True)[:5]],
                    'top_sources': [{'source_ip': k, 'count': len(v)} for k, v in 
                                  sorted(usage_by_source.items(), key=lambda x: len(x[1]), reverse=True)[:5]],
                    'key_types': [{'type': k, 'count': len(v)} for k, v in 
                                sorted(usage_by_key_type.items(), key=lambda x: len(x[1]), reverse=True)]
                }
                
                # Check for suspicious patterns
                
                # 1. Multiple source IPs using the same username with keys
                for username, entries in usage_by_user.items():
                    sources = set(entry['source_ip'] for entry in entries)
                    if len(sources) > 5:  # High number of source IPs
                        suspicious_patterns.append({
                            'pattern': 'Multiple source IPs for single user with key authentication',
                            'username': username,
                            'source_count': len(sources),
                            'sources': list(sources)[:10],  # Limit to top 10
                            'severity': 'medium',
                            'recommendation': f"Verify all sources are legitimate for user {username}"
                        })
                
                # 2. Unusual login times for key-based authentication
                for username, entries in usage_by_user.items():
                    # Try to identify unusual login hours
                    try:
                        login_hours = []
                        for entry in entries:
                            if isinstance(entry['timestamp'], str) and 'T' in entry['timestamp']:
                                time_part = entry['timestamp'].split('T')[1]
                                hour = int(time_part.split(':')[0])
                                login_hours.append(hour)
                        
                        # Check for logins during unusual hours (11 PM - 5 AM)
                        unusual_hours = [h for h in login_hours if h >= 23 or h < 5]
                        if unusual_hours and len(unusual_hours) / len(login_hours) > 0.3:  # More than 30% during unusual hours
                            suspicious_patterns.append({
                                'pattern': 'Unusual login hours with key authentication',
                                'username': username,
                                'unusual_hours_count': len(unusual_hours),
                                'total_logins': len(login_hours),
                                'severity': 'low',
                                'recommendation': f"Verify if user {username} typically logs in during these hours"
                            })
                    except:
                        # Skip time analysis on error
                        pass
                
                # 3. Use of weak key types
                weak_key_types = ['ssh-rsa', 'ssh-dss', 'ecdsa-sha2-nistp256']
                for key_type, entries in usage_by_key_type.items():
                    if key_type in weak_key_types:
                        users = set(entry['username'] for entry in entries)
                        suspicious_patterns.append({
                            'pattern': 'Use of weak key type',
                            'key_type': key_type,
                            'usage_count': len(entries),
                            'users': list(users),
                            'severity': 'medium',
                            'recommendation': f"Upgrade {key_type} keys to more secure types (Ed25519 recommended)"
                        })
                
                # 4. Check against threat intelligence if available
                if self.threat_intel:
                    for source_ip, entries in usage_by_source.items():
                        threat_info = self.threat_intel.check_ip(source_ip)
                        if threat_info:
                            users = set(entry['username'] for entry in entries)
                            suspicious_patterns.append({
                                'pattern': 'Key authentication from suspicious IP',
                                'source_ip': source_ip,
                                'threat_info': threat_info,
                                'users': list(users),
                                'auth_count': len(entries),
                                'severity': 'high',
                                'recommendation': f"Investigate key-based logins from suspicious IP {source_ip}"
                            })
                
                # Add all authentication logs to the key usage array
                key_usage = key_auth_logs
            
            # Look for key-based automation patterns
            # Check crontab, systemd timers, etc., for SSH key usage
            cron_key_usage = self._check_cron_key_usage()
            if cron_key_usage:
                key_usage.extend(cron_key_usage)
            
            # Add systemd timer checks
            systemd_key_usage = self._check_systemd_key_usage()
            if systemd_key_usage:
                key_usage.extend(systemd_key_usage)
            
            # Determine if there are any anomalies
            is_anomalous = len(suspicious_patterns) > 0
            
            return {
                'key_auth_count': len(key_auth_logs),
                'suspicious_patterns_count': len(suspicious_patterns),
                'key_usage': key_usage[:50],  # Limit to first 50 entries
                'statistics': key_statistics,
                'suspicious_patterns': suspicious_patterns,
                'is_anomalous': is_anomalous
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing SSH key usage: {e}")
            return {
                'error': str(e),
                'is_anomalous': False
            }
    
    def _check_cron_key_usage(self):
        """Check cron jobs for SSH key usage"""
        cron_findings = []
        
        try:
            # Check system-wide cron directories
            cron_dirs = ['/etc/cron.d', '/etc/cron.hourly', '/etc/cron.daily', 
                         '/etc/cron.weekly', '/etc/cron.monthly']
            
            for cron_dir in cron_dirs:
                if os.path.isdir(cron_dir):
                    for root, _, files in os.walk(cron_dir):
                        for file in files:
                            file_path = os.path.join(root, file)
                            
                            try:
                                with open(file_path, 'r') as f:
                                    content = f.read()
                                    
                                    # Look for SSH commands with identity files
                                    ssh_key_matches = re.findall(r'ssh\s+.*-i\s+(\S+)', content)
                                    
                                    if ssh_key_matches:
                                        for key_path in ssh_key_matches:
                                            cron_findings.append({
                                                'type': 'cron',
                                                'source': file_path,
                                                'key_path': key_path,
                                                'finding': 'SSH key used in cron job'
                                            })
                            except:
                                # Skip files that can't be read
                                pass
            
            # Check system-wide crontab
            if os.path.exists('/etc/crontab'):
                try:
                    with open('/etc/crontab', 'r') as f:
                        content = f.read()
                        
                        # Look for SSH commands with identity files
                        ssh_key_matches = re.findall(r'ssh\s+.*-i\s+(\S+)', content)
                        
                        if ssh_key_matches:
                            for key_path in ssh_key_matches:
                                cron_findings.append({
                                    'type': 'crontab',
                                    'source': '/etc/crontab',
                                    'key_path': key_path,
                                    'finding': 'SSH key used in system crontab'
                                })
                except:
                    # Skip if can't read
                    pass
            
            return cron_findings
        except Exception as e:
            self.logger.error(f"Error checking cron for SSH keys: {e}")
            return []
    
    def _check_systemd_key_usage(self):
        """Check systemd services and timers for SSH key usage"""
        systemd_findings = []
        
        try:
            # Find all service files
            service_dirs = ['/etc/systemd/system', '/usr/lib/systemd/system']
            
            for service_dir in service_dirs:
                if os.path.isdir(service_dir):
                    for root, _, files in os.walk(service_dir):
                        for file in files:
                            if file.endswith('.service'):
                                file_path = os.path.join(root, file)
                                
                                try:
                                    with open(file_path, 'r') as f:
                                        content = f.read()
                                        
                                        # Look for SSH commands with identity files
                                        ssh_key_matches = re.findall(r'ssh\s+.*-i\s+(\S+)', content)
                                        
                                        if ssh_key_matches:
                                            for key_path in ssh_key_matches:
                                                systemd_findings.append({
                                                    'type': 'systemd',
                                                    'source': file_path,
                                                    'key_path': key_path,
                                                    'finding': 'SSH key used in systemd service'
                                                })
                                except:
                                    # Skip files that can't be read
                                    pass
            
            return systemd_findings
        except Exception as e:
            self.logger.error(f"Error checking systemd for SSH keys: {e}")
            return []