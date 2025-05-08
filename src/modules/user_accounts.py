#!/usr/bin/env python3
"""
UserAccountAnalyzer Module
Detects suspicious user accounts, unauthorized privilege escalation, and more.
"""

import os
import logging
import subprocess
import json
import re
from datetime import datetime

class UserAccountAnalyzer:
    """Analyzes user accounts for security issues"""
    
    def __init__(self, config=None):
        """Initialize with configuration"""
        self.logger = logging.getLogger('sharpeye.accounts')
        self.config = config or {}
        
        # Configure options
        self.baseline_file = self.config.get('baseline_file', '/var/lib/sharpeye/baselines/accounts.json')
        self.check_sudo = self.config.get('check_sudo', True)
        self.check_shell = self.config.get('check_shell', True)
        self.check_auth_logs = self.config.get('check_auth_logs', True)
        
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
        """Analyze user accounts for anomalies"""
        self.logger.info("Analyzing user accounts")
        
        # Record start time for performance metrics
        start_time = datetime.now()
        
        # Get the configured checks from config
        check_home_security = self.config.get('check_home_security', True)
        check_password_policy = self.config.get('check_password_policy', True)
        check_group_membership = self.config.get('check_group_membership', True)
        check_privilege_escalation = self.config.get('check_privilege_escalation', True)
        check_mfa_status = self.config.get('check_mfa_status', True)
        check_login_patterns = self.config.get('check_login_patterns', True)
        
        # Run the main checks
        results = {
            'root_accounts': self._check_root_accounts(),
            'users_with_shell': self._check_users_with_shell(),
            'sudo_users': self._check_sudo_users(),
            'suspicious_accounts': self._check_suspicious_accounts(),
            'recent_account_changes': self._check_recent_changes(),
            'recent_logins': self._check_recent_logins()
        }
        
        # Run the new enhanced checks
        if check_home_security:
            results['home_directory_security'] = self._check_home_directory_security()
        else:
            results['home_directory_security'] = {'skipped': True, 'is_anomalous': False}
            
        if check_password_policy:
            results['password_policy'] = self._check_password_policy()
        else:
            results['password_policy'] = {'skipped': True, 'is_anomalous': False}
            
        if check_group_membership:
            results['group_membership'] = self._check_group_membership()
        else:
            results['group_membership'] = {'skipped': True, 'is_anomalous': False}
            
        if check_privilege_escalation:
            results['privilege_escalation'] = self._check_privilege_escalation()
        else:
            results['privilege_escalation'] = {'skipped': True, 'is_anomalous': False}
            
        if check_mfa_status:
            results['mfa_status'] = self._check_mfa_status()
        else:
            results['mfa_status'] = {'skipped': True, 'is_anomalous': False}
            
        if check_login_patterns:
            results['login_patterns'] = self._check_login_patterns()
        else:
            results['login_patterns'] = {'skipped': True, 'is_anomalous': False}
        
        # Check for threat intelligence integration
        if hasattr(self, 'threat_intel') and self.threat_intel:
            results['threat_intelligence'] = self._check_threat_intelligence()
        
        # Determine if any anomalies were found
        is_anomalous = any(
            results[key].get('is_anomalous', False) 
            for key in results 
            if not results[key].get('skipped', False)
        )
        
        results['is_anomalous'] = is_anomalous
        results['timestamp'] = datetime.now().isoformat()
        
        # Add performance metrics
        end_time = datetime.now()
        execution_time = (end_time - start_time).total_seconds()
        results['performance'] = {
            'execution_time_seconds': execution_time,
            'checks_performed': len([k for k, v in results.items() if k not in ['is_anomalous', 'timestamp', 'performance'] and not v.get('skipped', False)]),
            'timestamp': end_time.isoformat()
        }
        
        return results
    
    def _check_root_accounts(self):
        """Check for accounts with UID 0 (root privileges)"""
        self.logger.debug("Checking for root accounts")
        
        try:
            # Only root should have UID 0
            cmd = ["awk", "-F:", "($3 == 0) {print $1}", "/etc/passwd"]
            output = subprocess.check_output(cmd, universal_newlines=True)
            
            accounts = output.strip().split('\n')
            accounts = [account for account in accounts if account]  # Remove empty strings
            
            # It's suspicious if there's more than one root account
            is_anomalous = len(accounts) > 1
            
            return {
                'accounts': accounts,
                'count': len(accounts),
                'is_anomalous': is_anomalous,
                'expected_count': 1
            }
            
        except Exception as e:
            self.logger.error(f"Error checking root accounts: {e}")
            return {
                'error': str(e),
                'is_anomalous': False
            }
    
    def _check_users_with_shell(self):
        """Check for users with valid login shells"""
        self.logger.debug("Checking for users with shells")
        
        try:
            # Get users with valid shells
            cmd = ["grep", "-vE", "'/sbin/nologin|/bin/false'", "/etc/passwd"]
            output = subprocess.check_output(cmd, universal_newlines=True)
            
            users = []
            valid_shells = ['/bin/bash', '/bin/sh', '/bin/zsh', '/bin/ksh', '/bin/csh', '/bin/dash']
            system_accounts = ['root', 'sync', 'shutdown', 'halt']
            
            for line in output.strip().split('\n'):
                if not line.strip():
                    continue
                
                parts = line.split(':')
                if len(parts) >= 7:
                    username = parts[0]
                    uid = int(parts[2])
                    shell = parts[6]
                    
                    # Check if this is a valid shell
                    if shell in valid_shells:
                        # Exclude system accounts from suspicion
                        is_suspicious = uid < 1000 and username not in system_accounts
                        
                        users.append({
                            'username': username,
                            'uid': uid,
                            'shell': shell,
                            'is_suspicious': is_suspicious
                        })
            
            # Count suspicious users
            suspicious_users = [user for user in users if user.get('is_suspicious', False)]
            is_anomalous = len(suspicious_users) > 0
            
            return {
                'users': users,
                'suspicious_users': suspicious_users,
                'count': len(users),
                'suspicious_count': len(suspicious_users),
                'is_anomalous': is_anomalous
            }
            
        except Exception as e:
            self.logger.error(f"Error checking users with shells: {e}")
            return {
                'error': str(e),
                'is_anomalous': False
            }
    
    def _check_sudo_users(self):
        """Check for users with sudo privileges"""
        self.logger.debug("Checking for sudo users")
        
        if not self.check_sudo:
            return {
                'skipped': True,
                'is_anomalous': False
            }
        
        try:
            sudo_users = []
            sudo_groups = []
            
            # Check /etc/sudoers
            cmd = ["grep", "-vE", "^#|^Defaults", "/etc/sudoers"]
            try:
                output = subprocess.check_output(cmd, universal_newlines=True)
                
                for line in output.strip().split('\n'):
                    if not line.strip():
                        continue
                    
                    # Check for user entries
                    if not line.startswith('%'):
                        username = line.split()[0]
                        if username and username != 'root':
                            sudo_users.append({
                                'username': username,
                                'source': '/etc/sudoers'
                            })
                    else:
                        # Check for group entries
                        group = line.split()[0][1:]  # Remove '%' prefix
                        if group:
                            sudo_groups.append({
                                'group': group,
                                'source': '/etc/sudoers'
                            })
            except subprocess.CalledProcessError:
                # File might not exist or be readable
                pass
            
            # Check /etc/sudoers.d/ directory
            if os.path.isdir('/etc/sudoers.d'):
                for filename in os.listdir('/etc/sudoers.d'):
                    if filename.startswith('.'):
                        continue
                    
                    filepath = os.path.join('/etc/sudoers.d', filename)
                    if os.path.isfile(filepath):
                        cmd = ["grep", "-vE", "^#|^Defaults", filepath]
                        try:
                            output = subprocess.check_output(cmd, universal_newlines=True)
                            
                            for line in output.strip().split('\n'):
                                if not line.strip():
                                    continue
                                
                                # Check for user entries
                                if not line.startswith('%'):
                                    username = line.split()[0]
                                    if username and username != 'root':
                                        sudo_users.append({
                                            'username': username,
                                            'source': filepath
                                        })
                                else:
                                    # Check for group entries
                                    group = line.split()[0][1:]  # Remove '%' prefix
                                    if group:
                                        sudo_groups.append({
                                            'group': group,
                                            'source': filepath
                                        })
                        except subprocess.CalledProcessError:
                            # File might not be readable
                            pass
            
            # Check if there are unexpected sudo users or groups
            expected_sudo_groups = self.config.get('expected_sudo_groups', ['sudo', 'wheel', 'admin'])
            unexpected_groups = [group for group in sudo_groups if group['group'] not in expected_sudo_groups]
            
            is_anomalous = len(unexpected_groups) > 0
            
            # For sudo users, we generally just report them since it's hard to know what's expected
            
            return {
                'sudo_users': sudo_users,
                'sudo_groups': sudo_groups,
                'unexpected_groups': unexpected_groups,
                'is_anomalous': is_anomalous
            }
            
        except Exception as e:
            self.logger.error(f"Error checking sudo users: {e}")
            return {
                'error': str(e),
                'is_anomalous': False
            }
    
    def _check_suspicious_accounts(self):
        """Check for suspicious accounts (hidden, no password, etc.)"""
        self.logger.debug("Checking for suspicious accounts")
        
        suspicious_accounts = []
        
        try:
            # Check for accounts with no password
            cmd = ["awk", "-F:", "($2 == \"\") {print $1}", "/etc/shadow"]
            try:
                output = subprocess.check_output(cmd, universal_newlines=True)
                
                for username in output.strip().split('\n'):
                    if username and username != 'root':
                        suspicious_accounts.append({
                            'username': username,
                            'reason': 'No password',
                            'severity': 'high'
                        })
            except (subprocess.CalledProcessError, PermissionError):
                # May not have permission to read /etc/shadow
                self.logger.warning("Could not check /etc/shadow for accounts with no password")
            
            # Check for hidden accounts (UID < 1000 but not system accounts)
            cmd = ["awk", "-F:", "($3 < 1000 && $3 > 0) {print $1,$3,$7}", "/etc/passwd"]
            output = subprocess.check_output(cmd, universal_newlines=True)
            
            system_accounts = ['bin', 'daemon', 'adm', 'lp', 'sync', 'shutdown', 'halt', 
                             'mail', 'news', 'uucp', 'operator', 'games', 'gopher', 
                             'ftp', 'nobody', 'dbus', 'systemd-network', 'systemd-resolve',
                             'systemd-timesync', 'polkitd', 'rpc', 'rpcuser', 'nfsnobody',
                             'sshd', 'chrony', 'ntp', 'postfix', 'tcpdump']
            
            for line in output.strip().split('\n'):
                if not line.strip():
                    continue
                
                parts = line.split()
                if len(parts) >= 2:
                    username = parts[0]
                    uid = int(parts[1])
                    shell = parts[2] if len(parts) > 2 else ""
                    
                    if username not in system_accounts:
                        suspicious_accounts.append({
                            'username': username,
                            'uid': uid,
                            'shell': shell,
                            'reason': 'Hidden user (UID < 1000)',
                            'severity': 'medium'
                        })
            
            # Check for accounts with UID/GID inconsistency
            cmd = ["awk", "-F:", "($3 != $4) {print $1,$3,$4}", "/etc/passwd"]
            output = subprocess.check_output(cmd, universal_newlines=True)
            
            for line in output.strip().split('\n'):
                if not line.strip():
                    continue
                
                parts = line.split()
                if len(parts) >= 3:
                    username = parts[0]
                    uid = int(parts[1])
                    gid = int(parts[2])
                    
                    # Exclude system accounts
                    if uid >= 1000 and username not in system_accounts:
                        suspicious_accounts.append({
                            'username': username,
                            'uid': uid,
                            'gid': gid,
                            'reason': 'UID/GID inconsistency',
                            'severity': 'low'
                        })
            
            # Determine if there are any high-severity suspicious accounts
            high_severity_accounts = [acct for acct in suspicious_accounts if acct.get('severity') == 'high']
            medium_severity_accounts = [acct for acct in suspicious_accounts if acct.get('severity') == 'medium']
            
            is_anomalous = len(high_severity_accounts) > 0 or len(medium_severity_accounts) > 0
            
            return {
                'suspicious_accounts': suspicious_accounts,
                'high_severity_count': len(high_severity_accounts),
                'medium_severity_count': len(medium_severity_accounts),
                'total_count': len(suspicious_accounts),
                'is_anomalous': is_anomalous
            }
            
        except Exception as e:
            self.logger.error(f"Error checking suspicious accounts: {e}")
            return {
                'error': str(e),
                'is_anomalous': False
            }
    
    def _check_recent_changes(self):
        """Check for recently changed password or account information"""
        self.logger.debug("Checking for recent account changes")
        
        recent_changes = []
        
        try:
            # Check /etc/passwd and /etc/shadow for recent changes
            cmd = ["stat", "-c", "%Y %n", "/etc/passwd", "/etc/shadow", "/etc/group"]
            output = subprocess.check_output(cmd, universal_newlines=True)
            
            for line in output.strip().split('\n'):
                if not line.strip():
                    continue
                
                parts = line.split()
                if len(parts) >= 2:
                    timestamp = int(parts[0])
                    filename = ' '.join(parts[1:])
                    
                    # Convert timestamp to datetime
                    change_time = datetime.fromtimestamp(timestamp)
                    
                    # Check if change is recent (within the last 24 hours)
                    time_diff = datetime.now() - change_time
                    if time_diff.days < 1:
                        recent_changes.append({
                            'file': filename,
                            'timestamp': change_time.isoformat(),
                            'hours_ago': time_diff.seconds / 3600
                        })
            
            # Check for specific user password changes
            cmd = ["awk", "-F:", "{print $1, $3}", "/etc/shadow"]
            try:
                output = subprocess.check_output(cmd, universal_newlines=True)
                
                for line in output.strip().split('\n'):
                    if not line.strip():
                        continue
                    
                    parts = line.split()
                    if len(parts) >= 2:
                        username = parts[0]
                        password_hash = parts[1]
                        
                        # Check if password was changed recently
                        cmd = ["chage", "-l", username]
                        try:
                            chage_output = subprocess.check_output(cmd, universal_newlines=True)
                            
                            # Parse the output to find the last password change date
                            last_change_match = re.search(r'Last password change\s*:\s*(.+)', chage_output)
                            if last_change_match:
                                last_change_str = last_change_match.group(1).strip()
                                
                                # Check if it's "never" or a date
                                if last_change_str.lower() == 'never':
                                    if username != 'root':  # Don't flag root if password never changed
                                        recent_changes.append({
                                            'username': username,
                                            'change_type': 'password',
                                            'timestamp': 'never'
                                        })
                                else:
                                    # Try to parse the date
                                    try:
                                        # Format might vary by system locale
                                        date_formats = [
                                            '%b %d, %Y',
                                            '%Y-%m-%d',
                                            '%d %b %Y',
                                            '%d/%m/%Y',
                                            '%m/%d/%Y'
                                        ]
                                        
                                        last_change_date = None
                                        for date_format in date_formats:
                                            try:
                                                last_change_date = datetime.strptime(last_change_str, date_format)
                                                break
                                            except ValueError:
                                                continue
                                        
                                        if last_change_date:
                                            time_diff = datetime.now() - last_change_date
                                            if time_diff.days < 1:
                                                recent_changes.append({
                                                    'username': username,
                                                    'change_type': 'password',
                                                    'timestamp': last_change_date.isoformat(),
                                                    'hours_ago': time_diff.seconds / 3600
                                                })
                                    except ValueError:
                                        # Could not parse date
                                        pass
                        except subprocess.CalledProcessError:
                            # Command failed, may not have permission
                            pass
            except (subprocess.CalledProcessError, PermissionError):
                # May not have permission to read /etc/shadow
                self.logger.warning("Could not check recent password changes")
            
            # Determine if there are any suspicious recent changes
            is_anomalous = len(recent_changes) > 0
            
            return {
                'recent_changes': recent_changes,
                'count': len(recent_changes),
                'is_anomalous': is_anomalous
            }
            
        except Exception as e:
            self.logger.error(f"Error checking recent account changes: {e}")
            return {
                'error': str(e),
                'is_anomalous': False
            }
    
    def _check_recent_logins(self):
        """Check for recent login attempts and successes"""
        self.logger.debug("Checking for recent logins")
        
        if not self.check_auth_logs:
            return {
                'skipped': True,
                'is_anomalous': False
            }
        
        recent_logins = []
        failed_logins = []
        
        try:
            # Check recent logins using 'last' command
            cmd = ["last", "-n", "20"]
            output = subprocess.check_output(cmd, universal_newlines=True)
            
            for line in output.strip().split('\n'):
                if not line.strip() or 'wtmp begins' in line:
                    continue
                
                parts = line.split()
                if len(parts) >= 5:
                    username = parts[0]
                    source = parts[2]
                    date_str = ' '.join(parts[3:8])
                    
                    # Skip reboots
                    if username in ['reboot', 'shutdown']:
                        continue
                    
                    recent_logins.append({
                        'username': username,
                        'source': source,
                        'date': date_str
                    })
            
            # Check for failed logins in auth log
            auth_log_files = [
                '/var/log/auth.log',
                '/var/log/secure'
            ]
            
            for log_file in auth_log_files:
                if os.path.exists(log_file):
                    cmd = ["grep", "Failed password", log_file]
                    try:
                        output = subprocess.check_output(cmd, universal_newlines=True)
                        
                        for line in output.strip().split('\n'):
                            if not line.strip():
                                continue
                            
                            # Parse failed login attempts
                            username_match = re.search(r'for (\w+)', line)
                            source_match = re.search(r'from (\S+)', line)
                            date_match = re.search(r'^(\w+\s+\d+\s+\d+:\d+:\d+)', line)
                            
                            if username_match and source_match and date_match:
                                username = username_match.group(1)
                                source = source_match.group(1)
                                date_str = date_match.group(1)
                                
                                failed_logins.append({
                                    'username': username,
                                    'source': source,
                                    'date': date_str
                                })
                    except subprocess.CalledProcessError:
                        # No failed logins found
                        pass
            
            # Check for successful logins in auth log
            for log_file in auth_log_files:
                if os.path.exists(log_file):
                    cmd = ["grep", "Accepted password", log_file]
                    try:
                        output = subprocess.check_output(cmd, universal_newlines=True)
                        
                        for line in output.strip().split('\n'):
                            if not line.strip():
                                continue
                            
                            # Parse successful login attempts
                            username_match = re.search(r'for (\w+)', line)
                            source_match = re.search(r'from (\S+)', line)
                            date_match = re.search(r'^(\w+\s+\d+\s+\d+:\d+:\d+)', line)
                            
                            if username_match and source_match and date_match:
                                username = username_match.group(1)
                                source = source_match.group(1)
                                date_str = date_match.group(1)
                                
                                # Check if this is a suspicious login (e.g., from unusual source)
                                is_suspicious = False
                                reason = []
                                
                                # Check if source is a known suspicious IP
                                suspicious_ips = self.config.get('suspicious_ips', [])
                                if source in suspicious_ips:
                                    is_suspicious = True
                                    reason.append(f"Login from suspicious IP: {source}")
                                
                                # Check if username is root (direct root login is generally bad practice)
                                if username == 'root':
                                    is_suspicious = True
                                    reason.append("Direct root login")
                                
                                recent_logins.append({
                                    'username': username,
                                    'source': source,
                                    'date': date_str,
                                    'is_suspicious': is_suspicious,
                                    'reason': reason if is_suspicious else None
                                })
                    except subprocess.CalledProcessError:
                        # No successful logins found
                        pass
            
            # Count suspicious logins
            suspicious_logins = [login for login in recent_logins if login.get('is_suspicious', False)]
            
            # Count failed login attempts by source IP
            failed_sources = {}
            for login in failed_logins:
                source = login.get('source', '')
                if source in failed_sources:
                    failed_sources[source] += 1
                else:
                    failed_sources[source] = 1
            
            # Check for brute force attempts (many failed logins from same source)
            brute_force_threshold = self.config.get('brute_force_threshold', 5)
            brute_force_attempts = {source: count for source, count in failed_sources.items()
                                  if count >= brute_force_threshold}
            
            is_anomalous = (
                len(suspicious_logins) > 0 or
                len(brute_force_attempts) > 0
            )
            
            return {
                'recent_logins': recent_logins,
                'failed_logins': failed_logins,
                'suspicious_logins': suspicious_logins,
                'brute_force_attempts': brute_force_attempts,
                'suspicious_count': len(suspicious_logins),
                'failed_count': len(failed_logins),
                'brute_force_count': len(brute_force_attempts),
                'is_anomalous': is_anomalous
            }
            
        except Exception as e:
            self.logger.error(f"Error checking recent logins: {e}")
            return {
                'error': str(e),
                'is_anomalous': False
            }
    
    def establish_baseline(self):
        """Establish baseline for user accounts"""
        self.logger.info("Establishing baseline for user accounts")
        
        baseline = {
            'timestamp': datetime.now().isoformat(),
            'users': self._get_all_users(),
            'sudo_users': self._check_sudo_users().get('sudo_users', []),
            'sudo_groups': self._check_sudo_users().get('sudo_groups', [])
        }
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.baseline_file), exist_ok=True)
        
        # Write baseline to file
        with open(self.baseline_file, 'w') as f:
            json.dump(baseline, f, indent=2)
        
        self.logger.info(f"Baseline saved to {self.baseline_file}")
        
        return baseline
    
    def _get_all_users(self):
        """Get all users from /etc/passwd"""
        users = []
        
        try:
            with open('/etc/passwd', 'r') as f:
                for line in f:
                    if not line.strip():
                        continue
                    
                    parts = line.strip().split(':')
                    if len(parts) >= 7:
                        username = parts[0]
                        uid = int(parts[2])
                        gid = int(parts[3])
                        gecos = parts[4]
                        home_dir = parts[5]
                        shell = parts[6]
                        
                        users.append({
                            'username': username,
                            'uid': uid,
                            'gid': gid,
                            'gecos': gecos,
                            'home_dir': home_dir,
                            'shell': shell
                        })
        except Exception as e:
            self.logger.error(f"Error getting all users: {e}")
        
        return users
    
    def compare_baseline(self):
        """Compare current state with baseline"""
        self.logger.info("Comparing user accounts with baseline")
        
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
        current_users = self._get_all_users()
        current_sudo_users = self._check_sudo_users().get('sudo_users', [])
        current_sudo_groups = self._check_sudo_users().get('sudo_groups', [])
        
        # Compare users
        baseline_users = {user.get('username'): user for user in baseline.get('users', [])}
        current_users_dict = {user.get('username'): user for user in current_users}
        
        new_users = [user for username, user in current_users_dict.items() if username not in baseline_users]
        removed_users = [user for username, user in baseline_users.items() if username not in current_users_dict]
        
        # Check for modified users
        modified_users = []
        for username, current_user in current_users_dict.items():
            if username in baseline_users:
                baseline_user = baseline_users[username]
                
                # Check for changes
                if (current_user.get('uid') != baseline_user.get('uid') or
                    current_user.get('gid') != baseline_user.get('gid') or
                    current_user.get('shell') != baseline_user.get('shell')):
                    
                    modified_users.append({
                        'username': username,
                        'current': current_user,
                        'baseline': baseline_user,
                        'changes': {
                            'uid': current_user.get('uid') != baseline_user.get('uid'),
                            'gid': current_user.get('gid') != baseline_user.get('gid'),
                            'shell': current_user.get('shell') != baseline_user.get('shell')
                        }
                    })
        
        # Compare sudo privileges
        baseline_sudo_users = {user.get('username'): user for user in baseline.get('sudo_users', [])}
        current_sudo_users_dict = {user.get('username'): user for user in current_sudo_users}
        
        new_sudo_users = [user for username, user in current_sudo_users_dict.items() if username not in baseline_sudo_users]
        removed_sudo_users = [user for username, user in baseline_sudo_users.items() if username not in current_sudo_users_dict]
        
        # Compare sudo groups
        baseline_sudo_groups = {group.get('group'): group for group in baseline.get('sudo_groups', [])}
        current_sudo_groups_dict = {group.get('group'): group for group in current_sudo_groups}
        
        new_sudo_groups = [group for groupname, group in current_sudo_groups_dict.items() if groupname not in baseline_sudo_groups]
        removed_sudo_groups = [group for groupname, group in baseline_sudo_groups.items() if groupname not in current_sudo_groups_dict]
        
        # Determine if there are any anomalies
        is_anomalous = (
            len(new_users) > 0 or
            len(removed_users) > 0 or
            len(modified_users) > 0 or
            len(new_sudo_users) > 0 or
            len(new_sudo_groups) > 0
        )
        
        return {
            'timestamp': datetime.now().isoformat(),
            'baseline_timestamp': baseline.get('timestamp'),
            'new_users': new_users,
            'removed_users': removed_users,
            'modified_users': modified_users,
            'new_sudo_users': new_sudo_users,
            'removed_sudo_users': removed_sudo_users,
            'new_sudo_groups': new_sudo_groups,
            'removed_sudo_groups': removed_sudo_groups,
            'is_anomalous': is_anomalous
        }
    
    def _check_home_directory_security(self):
        """Check home directory permissions and security issues"""
        self.logger.debug("Checking home directory security")
        
        home_issues = []
        
        try:
            # Get all user home directories
            user_homes = {}
            with open('/etc/passwd', 'r') as f:
                for line in f:
                    if not line.strip():
                        continue
                    
                    parts = line.strip().split(':')
                    if len(parts) >= 7:
                        username = parts[0]
                        uid = int(parts[2])
                        home_dir = parts[5]
                        
                        # Skip system accounts (UID < 1000) except root
                        if uid >= 1000 or username == 'root':
                            user_homes[username] = {
                                'home_dir': home_dir,
                                'uid': uid
                            }
            
            # Check each home directory
            for username, info in user_homes.items():
                home_dir = info['home_dir']
                uid = info['uid']
                
                if not os.path.exists(home_dir):
                    continue  # Skip if home directory doesn't exist
                
                # Check home directory permissions
                try:
                    home_stat = os.stat(home_dir)
                    home_mode = home_stat.st_mode
                    home_owner = home_stat.st_uid
                    
                    # Check if home directory is owned by the user
                    if home_owner != uid:
                        home_issues.append({
                            'username': username,
                            'home_dir': home_dir,
                            'issue': 'Home directory not owned by user',
                            'owner': home_owner,
                            'expected_owner': uid,
                            'severity': 'high'
                        })
                    
                    # Check if home directory is world-readable
                    if home_mode & stat.S_IROTH:
                        home_issues.append({
                            'username': username,
                            'home_dir': home_dir,
                            'issue': 'Home directory is world-readable',
                            'mode': oct(home_mode & 0o777),
                            'recommendation': 'chmod o-r ' + home_dir,
                            'severity': 'medium'
                        })
                    
                    # Check if home directory is world-writable
                    if home_mode & stat.S_IWOTH:
                        home_issues.append({
                            'username': username,
                            'home_dir': home_dir,
                            'issue': 'Home directory is world-writable',
                            'mode': oct(home_mode & 0o777),
                            'recommendation': 'chmod o-w ' + home_dir,
                            'severity': 'high'
                        })
                    
                    # Check if home directory is world-executable
                    if home_mode & stat.S_IXOTH:
                        home_issues.append({
                            'username': username,
                            'home_dir': home_dir,
                            'issue': 'Home directory is world-executable',
                            'mode': oct(home_mode & 0o777),
                            'recommendation': 'chmod o-x ' + home_dir,
                            'severity': 'medium'
                        })
                    
                    # Check for .ssh directory issues
                    ssh_dir = os.path.join(home_dir, '.ssh')
                    if os.path.exists(ssh_dir):
                        ssh_stat = os.stat(ssh_dir)
                        ssh_mode = ssh_stat.st_mode
                        ssh_owner = ssh_stat.st_uid
                        
                        # Check if .ssh directory is owned by the user
                        if ssh_owner != uid:
                            home_issues.append({
                                'username': username,
                                'path': ssh_dir,
                                'issue': '.ssh directory not owned by user',
                                'owner': ssh_owner,
                                'expected_owner': uid,
                                'severity': 'high'
                            })
                        
                        # Check if .ssh directory has secure permissions (700)
                        if ssh_mode & (stat.S_IRWXG | stat.S_IRWXO):
                            home_issues.append({
                                'username': username,
                                'path': ssh_dir,
                                'issue': '.ssh directory has insecure permissions',
                                'mode': oct(ssh_mode & 0o777),
                                'recommendation': 'chmod 700 ' + ssh_dir,
                                'severity': 'high'
                            })
                        
                        # Check SSH keys in the directory
                        for file in os.listdir(ssh_dir):
                            if file.startswith('id_') and not file.endswith('.pub'):
                                # This is a private key
                                key_path = os.path.join(ssh_dir, file)
                                key_stat = os.stat(key_path)
                                key_mode = key_stat.st_mode
                                key_owner = key_stat.st_uid
                                
                                # Check if key is owned by the user
                                if key_owner != uid:
                                    home_issues.append({
                                        'username': username,
                                        'path': key_path,
                                        'issue': 'SSH private key not owned by user',
                                        'owner': key_owner,
                                        'expected_owner': uid,
                                        'severity': 'high'
                                    })
                                
                                # Check if key has secure permissions (600)
                                if key_mode & (stat.S_IRWXG | stat.S_IRWXO):
                                    home_issues.append({
                                        'username': username,
                                        'path': key_path,
                                        'issue': 'SSH private key has insecure permissions',
                                        'mode': oct(key_mode & 0o777),
                                        'recommendation': 'chmod 600 ' + key_path,
                                        'severity': 'high'
                                    })
                    
                    # Check for .bashrc/.bash_profile issues
                    for rc_file in ['.bashrc', '.bash_profile', '.profile']:
                        rc_path = os.path.join(home_dir, rc_file)
                        if os.path.exists(rc_path):
                            rc_stat = os.stat(rc_path)
                            rc_mode = rc_stat.st_mode
                            rc_owner = rc_stat.st_uid
                            
                            # Check if RC file is owned by the user
                            if rc_owner != uid:
                                home_issues.append({
                                    'username': username,
                                    'path': rc_path,
                                    'issue': f'{rc_file} not owned by user',
                                    'owner': rc_owner,
                                    'expected_owner': uid,
                                    'severity': 'high'
                                })
                            
                            # Check if RC file is world-writable
                            if rc_mode & stat.S_IWOTH:
                                home_issues.append({
                                    'username': username,
                                    'path': rc_path,
                                    'issue': f'{rc_file} is world-writable',
                                    'mode': oct(rc_mode & 0o777),
                                    'recommendation': 'chmod o-w ' + rc_path,
                                    'severity': 'high'
                                })
                            
                            # Check for suspicious content in RC files
                            try:
                                with open(rc_path, 'r') as f:
                                    content = f.read()
                                    
                                    # Look for suspicious commands
                                    suspicious_patterns = [
                                        'curl.*sh', 'wget.*sh', '>/dev/null', 
                                        'nc ', 'netcat', 'chmod 777', 'chmod.*a+x',
                                        '0.0.0.0', 'eval.*base64', 'base64.*-d'
                                    ]
                                    
                                    for pattern in suspicious_patterns:
                                        if re.search(pattern, content):
                                            home_issues.append({
                                                'username': username,
                                                'path': rc_path,
                                                'issue': f'Suspicious pattern ({pattern}) found in {rc_file}',
                                                'severity': 'high'
                                            })
                            except:
                                # Couldn't read file, skip
                                pass
                    
                except (FileNotFoundError, PermissionError):
                    # Couldn't access directory, skip
                    pass
            
            # Determine if there are any high-severity issues
            high_severity_issues = [issue for issue in home_issues if issue.get('severity') == 'high']
            medium_severity_issues = [issue for issue in home_issues if issue.get('severity') == 'medium']
            
            is_anomalous = len(high_severity_issues) > 0 or len(medium_severity_issues) > 0
            
            return {
                'issues': home_issues,
                'high_severity_count': len(high_severity_issues),
                'medium_severity_count': len(medium_severity_issues),
                'total_count': len(home_issues),
                'is_anomalous': is_anomalous
            }
            
        except Exception as e:
            self.logger.error(f"Error checking home directory security: {e}")
            return {
                'error': str(e),
                'is_anomalous': False
            }
    
    def _check_password_policy(self):
        """Check password policy and aging settings"""
        self.logger.debug("Checking password policy")
        
        policy_issues = []
        
        try:
            # Get all users with passwords
            passwd_users = []
            try:
                with open('/etc/passwd', 'r') as f:
                    for line in f:
                        if not line.strip():
                            continue
                        
                        parts = line.strip().split(':')
                        if len(parts) >= 7:
                            username = parts[0]
                            passwd = parts[1]
                            uid = int(parts[2])
                            
                            # Skip system accounts except root
                            if uid >= 1000 or username == 'root':
                                passwd_users.append(username)
            except:
                self.logger.error("Could not read /etc/passwd")
                passwd_users = []
            
            # Check shadow password aging info
            try:
                for username in passwd_users:
                    cmd = ["chage", "-l", username]
                    try:
                        output = subprocess.check_output(cmd, universal_newlines=True)
                        
                        # Parse the output
                        last_change_match = re.search(r'Last password change\s*:\s*(.+)', output)
                        password_expires_match = re.search(r'Password expires\s*:\s*(.+)', output)
                        password_inactive_match = re.search(r'Password inactive\s*:\s*(.+)', output)
                        account_expires_match = re.search(r'Account expires\s*:\s*(.+)', output)
                        min_days_match = re.search(r'Minimum number of days between password change\s*:\s*(.+)', output)
                        max_days_match = re.search(r'Maximum number of days between password change\s*:\s*(.+)', output)
                        warning_days_match = re.search(r'Number of days of warning before password expires\s*:\s*(.+)', output)
                        
                        # Check for policy issues
                        
                        # Check if password expiry is disabled (max_days = 99999)
                        if max_days_match:
                            max_days = max_days_match.group(1).strip()
                            if max_days == 'never' or max_days == '99999':
                                policy_issues.append({
                                    'username': username,
                                    'issue': 'Password expiry disabled',
                                    'value': max_days,
                                    'recommendation': f'chage -M 90 {username}',
                                    'severity': 'medium'
                                })
                        
                        # Check if minimum days is 0 (can change password immediately after change)
                        if min_days_match:
                            min_days = min_days_match.group(1).strip()
                            if min_days == '0':
                                policy_issues.append({
                                    'username': username,
                                    'issue': 'Minimum password age is 0 days',
                                    'value': min_days,
                                    'recommendation': f'chage -m 1 {username}',
                                    'severity': 'low'
                                })
                        
                        # Check if password expiry warning is too short
                        if warning_days_match:
                            warning_days = warning_days_match.group(1).strip()
                            if warning_days == '0' or warning_days == '1' or warning_days == '2':
                                policy_issues.append({
                                    'username': username,
                                    'issue': 'Password expiry warning period too short',
                                    'value': warning_days,
                                    'recommendation': f'chage -W 7 {username}',
                                    'severity': 'low'
                                })
                        
                        # Check if account never expires
                        if account_expires_match:
                            account_expires = account_expires_match.group(1).strip()
                            if account_expires == 'never':
                                # This is not necessarily a security issue, but worth noting
                                policy_issues.append({
                                    'username': username,
                                    'issue': 'Account never expires',
                                    'value': account_expires,
                                    'severity': 'info'
                                })
                        
                        # Check if password is very old (more than 1 year)
                        if last_change_match:
                            last_change_str = last_change_match.group(1).strip()
                            if last_change_str != 'never':
                                # Try to parse the date
                                try:
                                    # Format might vary by system locale
                                    date_formats = [
                                        '%b %d, %Y',
                                        '%Y-%m-%d',
                                        '%d %b %Y',
                                        '%d/%m/%Y',
                                        '%m/%d/%Y'
                                    ]
                                    
                                    last_change_date = None
                                    for date_format in date_formats:
                                        try:
                                            last_change_date = datetime.strptime(last_change_str, date_format)
                                            break
                                        except ValueError:
                                            continue
                                    
                                    if last_change_date:
                                        time_diff = datetime.now() - last_change_date
                                        if time_diff.days > 365:
                                            policy_issues.append({
                                                'username': username,
                                                'issue': 'Password not changed in over a year',
                                                'last_change': last_change_str,
                                                'days_since_change': time_diff.days,
                                                'recommendation': f'passwd {username}',
                                                'severity': 'medium'
                                            })
                                except:
                                    # Couldn't parse date, skip
                                    pass
                    except subprocess.CalledProcessError:
                        # Command failed, skip this user
                        pass
            except:
                self.logger.error("Could not check password aging information")
            
            # Check PAM password policy
            pam_config_files = [
                '/etc/pam.d/common-password',
                '/etc/pam.d/system-auth',
                '/etc/pam.d/password-auth'
            ]
            
            for pam_file in pam_config_files:
                if not os.path.exists(pam_file):
                    continue
                
                try:
                    with open(pam_file, 'r') as f:
                        content = f.read()
                        
                        # Check if pwquality or cracklib is being used
                        if 'pam_pwquality.so' not in content and 'pam_cracklib.so' not in content:
                            policy_issues.append({
                                'issue': 'No strong password policy module configured',
                                'file': pam_file,
                                'recommendation': 'Install libpam-pwquality or libpam-cracklib',
                                'severity': 'high'
                            })
                        else:
                            # Check for specific policy settings
                            pw_line = None
                            if 'pam_pwquality.so' in content:
                                # Find the pwquality line
                                for line in content.splitlines():
                                    if 'pam_pwquality.so' in line:
                                        pw_line = line
                                        break
                            elif 'pam_cracklib.so' in content:
                                # Find the cracklib line
                                for line in content.splitlines():
                                    if 'pam_cracklib.so' in line:
                                        pw_line = line
                                        break
                            
                            if pw_line:
                                # Check for minlen setting
                                minlen_match = re.search(r'minlen=(\d+)', pw_line)
                                if not minlen_match:
                                    policy_issues.append({
                                        'issue': 'Minimum password length not set',
                                        'file': pam_file,
                                        'line': pw_line,
                                        'recommendation': 'Add minlen=14 to the pam_pwquality.so line',
                                        'severity': 'medium'
                                    })
                                elif minlen_match and int(minlen_match.group(1)) < 10:
                                    policy_issues.append({
                                        'issue': 'Minimum password length too short',
                                        'file': pam_file,
                                        'line': pw_line,
                                        'value': minlen_match.group(1),
                                        'recommendation': 'Increase minlen to at least 14',
                                        'severity': 'medium'
                                    })
                                
                                # Check for missing complexity requirements
                                for param in ['dcredit', 'ucredit', 'lcredit', 'ocredit']:
                                    if param not in pw_line:
                                        policy_issues.append({
                                            'issue': f'Password complexity parameter {param} not set',
                                            'file': pam_file,
                                            'line': pw_line,
                                            'recommendation': f'Add {param}=-1 to require at least one character of this class',
                                            'severity': 'low'
                                        })
                except:
                    # Couldn't read file, skip
                    pass
            
            # Check login.defs password policy
            login_defs_path = '/etc/login.defs'
            if os.path.exists(login_defs_path):
                try:
                    with open(login_defs_path, 'r') as f:
                        login_defs = f.read()
                        
                        # Check PASS_MAX_DAYS
                        max_days_match = re.search(r'^PASS_MAX_DAYS\s+(\d+)', login_defs, re.MULTILINE)
                        if not max_days_match:
                            policy_issues.append({
                                'issue': 'PASS_MAX_DAYS not set in login.defs',
                                'file': login_defs_path,
                                'recommendation': 'Add PASS_MAX_DAYS 90',
                                'severity': 'medium'
                            })
                        elif max_days_match and int(max_days_match.group(1)) > 90:
                            policy_issues.append({
                                'issue': 'PASS_MAX_DAYS too high',
                                'file': login_defs_path,
                                'value': max_days_match.group(1),
                                'recommendation': 'Set PASS_MAX_DAYS to 90 or less',
                                'severity': 'medium'
                            })
                        
                        # Check PASS_MIN_DAYS
                        min_days_match = re.search(r'^PASS_MIN_DAYS\s+(\d+)', login_defs, re.MULTILINE)
                        if not min_days_match:
                            policy_issues.append({
                                'issue': 'PASS_MIN_DAYS not set in login.defs',
                                'file': login_defs_path,
                                'recommendation': 'Add PASS_MIN_DAYS 1',
                                'severity': 'low'
                            })
                        elif min_days_match and int(min_days_match.group(1)) < 1:
                            policy_issues.append({
                                'issue': 'PASS_MIN_DAYS set to 0',
                                'file': login_defs_path,
                                'value': min_days_match.group(1),
                                'recommendation': 'Set PASS_MIN_DAYS to at least 1',
                                'severity': 'low'
                            })
                        
                        # Check PASS_WARN_AGE
                        warn_age_match = re.search(r'^PASS_WARN_AGE\s+(\d+)', login_defs, re.MULTILINE)
                        if not warn_age_match:
                            policy_issues.append({
                                'issue': 'PASS_WARN_AGE not set in login.defs',
                                'file': login_defs_path,
                                'recommendation': 'Add PASS_WARN_AGE 7',
                                'severity': 'low'
                            })
                        elif warn_age_match and int(warn_age_match.group(1)) < 7:
                            policy_issues.append({
                                'issue': 'PASS_WARN_AGE too low',
                                'file': login_defs_path,
                                'value': warn_age_match.group(1),
                                'recommendation': 'Set PASS_WARN_AGE to at least 7',
                                'severity': 'low'
                            })
                except:
                    # Couldn't read file, skip
                    pass
            
            # Determine if there are any high-severity issues
            high_severity_issues = [issue for issue in policy_issues if issue.get('severity') == 'high']
            medium_severity_issues = [issue for issue in policy_issues if issue.get('severity') == 'medium']
            
            is_anomalous = len(high_severity_issues) > 0 or len(medium_severity_issues) > 0
            
            return {
                'issues': policy_issues,
                'high_severity_count': len(high_severity_issues),
                'medium_severity_count': len(medium_severity_issues),
                'total_count': len(policy_issues),
                'is_anomalous': is_anomalous
            }
            
        except Exception as e:
            self.logger.error(f"Error checking password policy: {e}")
            return {
                'error': str(e),
                'is_anomalous': False
            }
    
    def _check_group_membership(self):
        """Check suspicious or dangerous group memberships"""
        self.logger.debug("Checking group membership")
        
        group_issues = []
        
        try:
            # Define sensitive groups
            sensitive_groups = {
                'root': 'Provides full system access',
                'wheel': 'Can use su to become root',
                'sudo': 'Can use sudo to execute commands as root',
                'admin': 'Administrative access',
                'shadow': 'Can read shadow passwords',
                'disk': 'Raw access to disk devices',
                'adm': 'Access to logs',
                'video': 'Access to video devices',
                'docker': 'Equivalent to root access',
                'lxd': 'Can escalate to root within containers',
                'libvirt': 'Can manage virtual machines',
                'wireshark': 'Can capture network traffic'
            }
            
            # Get group members for all groups
            group_members = {}
            try:
                # Read /etc/group file
                with open('/etc/group', 'r') as f:
                    for line in f:
                        if not line.strip():
                            continue
                        
                        parts = line.strip().split(':')
                        if len(parts) >= 4:
                            group_name = parts[0]
                            members = parts[3].split(',') if parts[3] else []
                            
                            group_members[group_name] = members
                
                # Now get primary group for each user
                with open('/etc/passwd', 'r') as f:
                    for line in f:
                        if not line.strip():
                            continue
                        
                        parts = line.strip().split(':')
                        if len(parts) >= 7:
                            username = parts[0]
                            gid = parts[3]
                            
                            # Find the group name for this GID
                            for group_name, group_data in group_members.items():
                                # Need to get the GID for this group
                                try:
                                    import grp
                                    group_info = grp.getgrnam(group_name)
                                    if str(group_info.gr_gid) == gid:
                                        # This is the primary group for this user
                                        if username not in group_members.get(group_name, []):
                                            # Add user to their primary group if not already there
                                            if group_name in group_members:
                                                group_members[group_name].append(username)
                                            else:
                                                group_members[group_name] = [username]
                                except:
                                    # Couldn't get group info, skip
                                    pass
            except:
                self.logger.error("Could not read group memberships")
            
            # Check for users in sensitive groups
            for group_name, description in sensitive_groups.items():
                if group_name in group_members:
                    members = group_members[group_name]
                    
                    # Check each member
                    for username in members:
                        # Skip root for root group (that's normal)
                        if group_name == 'root' and username == 'root':
                            continue
                        
                        # Get user info
                        uid = None
                        try:
                            import pwd
                            user_info = pwd.getpwnam(username)
                            uid = user_info.pw_uid
                        except:
                            # Couldn't get user info, skip
                            continue
                        
                        # Skip system accounts (UID < 1000)
                        if uid and uid < 1000:
                            continue
                        
                        # This is a normal user in a sensitive group
                        group_issues.append({
                            'username': username,
                            'uid': uid,
                            'group': group_name,
                            'issue': f'User in sensitive group: {group_name}',
                            'description': description,
                            'severity': 'medium' if group_name in ['root', 'wheel', 'sudo', 'admin', 'docker', 'lxd'] else 'low'
                        })
            
            # Check for suspicious group names (hidden or unusual)
            for group_name, members in group_members.items():
                # Skip empty groups
                if not members:
                    continue
                
                # Check for suspicious group names
                if (group_name.startswith('.') or  # Hidden group
                    re.search(r'[^\w.-]', group_name) or  # Contains unusual characters
                    group_name.endswith('adm') and group_name != 'adm' or  # Looks like admin
                    group_name.endswith('admin') and group_name != 'admin' or
                    'sudo' in group_name and group_name != 'sudo'):  # Looks like sudo group
                    group_issues.append({
                        'group': group_name,
                        'members': members,
                        'issue': 'Suspicious group name',
                        'severity': 'medium'
                    })
            
            # Determine if there are any high-severity issues
            high_severity_issues = [issue for issue in group_issues if issue.get('severity') == 'high']
            medium_severity_issues = [issue for issue in group_issues if issue.get('severity') == 'medium']
            
            is_anomalous = len(high_severity_issues) > 0 or len(medium_severity_issues) > 0
            
            return {
                'issues': group_issues,
                'high_severity_count': len(high_severity_issues),
                'medium_severity_count': len(medium_severity_issues),
                'total_count': len(group_issues),
                'is_anomalous': is_anomalous
            }
            
        except Exception as e:
            self.logger.error(f"Error checking group membership: {e}")
            return {
                'error': str(e),
                'is_anomalous': False
            }
    
    def _check_privilege_escalation(self):
        """Check for privilege escalation vectors"""
        self.logger.debug("Checking privilege escalation vectors")
        
        privilege_issues = []
        
        try:
            # Check for SUID/SGID binaries in user home directories
            user_homes = {}
            with open('/etc/passwd', 'r') as f:
                for line in f:
                    if not line.strip():
                        continue
                    
                    parts = line.strip().split(':')
                    if len(parts) >= 7:
                        username = parts[0]
                        uid = int(parts[2])
                        home_dir = parts[5]
                        
                        # Skip system accounts (UID < 1000) except root
                        if uid >= 1000 or username == 'root':
                            user_homes[username] = home_dir
            
            # Search for SUID/SGID binaries in home directories
            for username, home_dir in user_homes.items():
                if not os.path.exists(home_dir):
                    continue
                
                try:
                    # Use find command to locate SUID/SGID binaries
                    cmd = ["find", home_dir, "-type", "f", "-perm", "/u+s,g+s", "-exec", "ls", "-la", "{}", ";"]
                    try:
                        output = subprocess.check_output(cmd, universal_newlines=True)
                        
                        # Parse the output
                        if output.strip():
                            for line in output.strip().split('\n'):
                                if not line.strip():
                                    continue
                                
                                # Get the file path from the line
                                parts = line.split()
                                if len(parts) >= 9:
                                    permissions = parts[0]
                                    owner = parts[2]
                                    group = parts[3]
                                    file_path = ' '.join(parts[8:])
                                    
                                    # Determine if SUID, SGID, or both
                                    is_suid = 's' in permissions[3]
                                    is_sgid = 's' in permissions[6]
                                    
                                    privilege_type = []
                                    if is_suid:
                                        privilege_type.append("SUID")
                                    if is_sgid:
                                        privilege_type.append("SGID")
                                    
                                    privilege_issues.append({
                                        'file': file_path,
                                        'owner': owner,
                                        'group': group,
                                        'permissions': permissions,
                                        'username': username,
                                        'privilege_type': ','.join(privilege_type),
                                        'issue': f"{'/'.join(privilege_type)} binary in user home directory",
                                        'severity': 'high'
                                    })
                    except subprocess.CalledProcessError:
                        # Command failed, skip
                        pass
                except:
                    # Error during search, skip
                    pass
            
            # Check for custom sudo rules
            sudo_issues = self._check_sudo_users()
            if not sudo_issues.get('skipped', False):
                sudo_users = sudo_issues.get('sudo_users', [])
                
                for sudo_user in sudo_users:
                    # Get user info
                    username = sudo_user.get('username')
                    uid = None
                    try:
                        import pwd
                        user_info = pwd.getpwnam(username)
                        uid = user_info.pw_uid
                    except:
                        # Couldn't get user info, skip
                        continue
                    
                    # Skip system accounts (UID < 1000)
                    if uid and uid < 1000:
                        continue
                    
                    # This is a normal user with sudo privileges
                    privilege_issues.append({
                        'username': username,
                        'uid': uid,
                        'issue': 'User has sudo privileges',
                        'source': sudo_user.get('source', 'unknown'),
                        'severity': 'medium'
                    })
            
            # Check for writable files owned by root but writable by others
            try:
                # Use find command to locate world-writable files owned by root
                cmd = ["find", "/", "-type", "f", "-user", "root", "-perm", "-o+w", "-exec", "ls", "-la", "{}", ";", "2>/dev/null"]
                try:
                    output = subprocess.check_output(cmd, universal_newlines=True)
                    
                    # Parse the output
                    if output.strip():
                        for line in output.strip().split('\n'):
                            if not line.strip():
                                continue
                            
                            # Get the file path from the line
                            parts = line.split()
                            if len(parts) >= 9:
                                permissions = parts[0]
                                owner = parts[2]
                                group = parts[3]
                                file_path = ' '.join(parts[8:])
                                
                                # Skip certain directories that are expected to have world-writable files
                                if any(d in file_path for d in ['/proc/', '/sys/', '/dev/', '/tmp/', '/var/tmp/', '/run/']) or \
                                   file_path.startswith('/var/spool/') or file_path.startswith('/var/mail/'):
                                    continue
                                
                                privilege_issues.append({
                                    'file': file_path,
                                    'owner': owner,
                                    'group': group,
                                    'permissions': permissions,
                                    'issue': 'World-writable file owned by root',
                                    'recommendation': f"chmod o-w {file_path}",
                                    'severity': 'high'
                                })
                except subprocess.CalledProcessError:
                    # Command failed, skip
                    pass
            except:
                # Error during search, skip
                pass
            
            # Check for writable directories owned by root
            try:
                # Use find command to locate world-writable directories owned by root
                cmd = ["find", "/", "-type", "d", "-user", "root", "-perm", "-o+w", "-exec", "ls", "-ld", "{}", ";", "2>/dev/null"]
                try:
                    output = subprocess.check_output(cmd, universal_newlines=True)
                    
                    # Parse the output
                    if output.strip():
                        for line in output.strip().split('\n'):
                            if not line.strip():
                                continue
                            
                            # Get the directory path from the line
                            parts = line.split()
                            if len(parts) >= 9:
                                permissions = parts[0]
                                owner = parts[2]
                                group = parts[3]
                                dir_path = ' '.join(parts[8:])
                                
                                # Skip certain directories that are expected to be world-writable
                                if dir_path in ['/tmp', '/var/tmp', '/dev/shm', '/run/lock'] or \
                                   any(d in dir_path for d in ['/proc/', '/sys/', '/dev/', '/run/']):
                                    continue
                                
                                # Check if the sticky bit is set (which mitigates some of the risk)
                                is_sticky = 't' in permissions[9]
                                
                                privilege_issues.append({
                                    'directory': dir_path,
                                    'owner': owner,
                                    'group': group,
                                    'permissions': permissions,
                                    'issue': 'World-writable directory owned by root' + (' (sticky bit set)' if is_sticky else ''),
                                    'recommendation': f"chmod {'o-w' if not is_sticky else '+t'} {dir_path}",
                                    'severity': 'high' if not is_sticky else 'medium'
                                })
                except subprocess.CalledProcessError:
                    # Command failed, skip
                    pass
            except:
                # Error during search, skip
                pass
            
            # Check for binaries with capabilities
            try:
                # Check if getcap command is available
                cmd = ["which", "getcap"]
                try:
                    subprocess.check_output(cmd, universal_newlines=True)
                    
                    # Use getcap to find files with capabilities
                    cmd = ["getcap", "-r", "/", "2>/dev/null"]
                    try:
                        output = subprocess.check_output(cmd, universal_newlines=True, shell=True)
                        
                        # Parse the output
                        if output.strip():
                            for line in output.strip().split('\n'):
                                if not line.strip():
                                    continue
                                
                                # Get the file path and capabilities
                                parts = line.split(' = ')
                                if len(parts) >= 2:
                                    file_path = parts[0]
                                    capabilities = parts[1]
                                    
                                    # Check for dangerous capabilities
                                    dangerous_caps = [
                                        'cap_dac_override', 'cap_dac_read_search', 
                                        'cap_sys_admin', 'cap_sys_ptrace', 
                                        'cap_sys_module', 'cap_net_admin',
                                        'cap_net_raw', 'cap_setuid', 'cap_setgid',
                                        'cap_chown', 'cap_fowner'
                                    ]
                                    
                                    has_dangerous = any(cap in capabilities for cap in dangerous_caps)
                                    
                                    privilege_issues.append({
                                        'file': file_path,
                                        'capabilities': capabilities,
                                        'issue': 'Binary with capabilities' + (' (dangerous)' if has_dangerous else ''),
                                        'severity': 'high' if has_dangerous else 'medium'
                                    })
                    except subprocess.CalledProcessError:
                        # Command failed, skip
                        pass
                except subprocess.CalledProcessError:
                    # getcap not available, skip
                    pass
            except:
                # Error during search, skip
                pass
            
            # Determine if there are any high-severity issues
            high_severity_issues = [issue for issue in privilege_issues if issue.get('severity') == 'high']
            medium_severity_issues = [issue for issue in privilege_issues if issue.get('severity') == 'medium']
            
            is_anomalous = len(high_severity_issues) > 0 or len(medium_severity_issues) > 0
            
            return {
                'issues': privilege_issues,
                'high_severity_count': len(high_severity_issues),
                'medium_severity_count': len(medium_severity_issues),
                'total_count': len(privilege_issues),
                'is_anomalous': is_anomalous
            }
            
        except Exception as e:
            self.logger.error(f"Error checking privilege escalation vectors: {e}")
            return {
                'error': str(e),
                'is_anomalous': False
            }
    
    def _check_mfa_status(self):
        """Check for MFA configuration"""
        self.logger.debug("Checking MFA status")
        
        mfa_issues = []
        mfa_status = {
            'pam_google_authenticator': False,
            'pam_duo': False,
            'pam_u2f': False,
            'pam_oath': False,
            'pam_yubico': False,
            'configured_users': []
        }
        
        try:
            # Check if any MFA PAM modules are installed
            pam_modules = [
                ('/usr/lib/*/security/pam_google_authenticator.so', 'pam_google_authenticator'),
                ('/usr/lib/*/security/pam_duo.so', 'pam_duo'),
                ('/usr/lib/*/security/pam_u2f.so', 'pam_u2f'),
                ('/usr/lib/*/security/pam_oath.so', 'pam_oath'),
                ('/usr/lib/*/security/pam_yubico.so', 'pam_yubico')
            ]
            
            for module_path, module_name in pam_modules:
                # Use glob to find the module
                import glob
                module_files = glob.glob(module_path)
                
                if module_files:
                    mfa_status[module_name] = True
            
            # Check PAM configurations for MFA usage
            pam_config_files = [
                '/etc/pam.d/sshd',
                '/etc/pam.d/login',
                '/etc/pam.d/system-auth',
                '/etc/pam.d/common-auth'
            ]
            
            mfa_configured = False
            
            for pam_file in pam_config_files:
                if not os.path.exists(pam_file):
                    continue
                
                try:
                    with open(pam_file, 'r') as f:
                        content = f.read()
                        
                        # Check for MFA configuration
                        for module_name in ['pam_google_authenticator.so', 'pam_duo.so', 'pam_u2f.so', 'pam_oath.so', 'pam_yubico.so']:
                            if module_name in content:
                                mfa_configured = True
                                mfa_status['mfa_configured'] = True
                                mfa_status['mfa_file'] = pam_file
                                mfa_status['mfa_module'] = module_name
                except:
                    # Couldn't read file, skip
                    pass
            
            # Check for user-specific MFA configuration
            user_mfa_files = [
                '.google_authenticator',
                '.yubico',
                '.u2f_keys'
            ]
            
            # Check home directories for MFA configuration files
            user_homes = {}
            with open('/etc/passwd', 'r') as f:
                for line in f:
                    if not line.strip():
                        continue
                    
                    parts = line.strip().split(':')
                    if len(parts) >= 7:
                        username = parts[0]
                        uid = int(parts[2])
                        home_dir = parts[5]
                        
                        # Skip system accounts (UID < 1000) except root
                        if uid >= 1000 or username == 'root':
                            user_homes[username] = home_dir
            
            for username, home_dir in user_homes.items():
                if not os.path.exists(home_dir):
                    continue
                
                has_mfa = False
                
                for mfa_file in user_mfa_files:
                    mfa_path = os.path.join(home_dir, mfa_file)
                    if os.path.exists(mfa_path):
                        has_mfa = True
                        mfa_status['configured_users'].append({
                            'username': username,
                            'mfa_file': mfa_file
                        })
            
            # Determine if there are any MFA issues
            
            # Check if MFA is completely missing
            if not any(mfa_status.get(module, False) for module in ['pam_google_authenticator', 'pam_duo', 'pam_u2f', 'pam_oath', 'pam_yubico']):
                mfa_issues.append({
                    'issue': 'No MFA modules installed',
                    'recommendation': 'Install at least one MFA PAM module (google-authenticator, duo, u2f, oath, yubico)',
                    'severity': 'medium'
                })
            elif not mfa_status.get('mfa_configured', False):
                mfa_issues.append({
                    'issue': 'MFA module installed but not configured in PAM',
                    'recommendation': 'Configure PAM to use the installed MFA module',
                    'severity': 'medium'
                })
            
            # Check if only some users have MFA configured
            if mfa_status.get('mfa_configured', False) and mfa_status.get('configured_users', []):
                configured_users = set(user['username'] for user in mfa_status['configured_users'])
                all_users = set(user_homes.keys())
                
                # Check root specifically
                if 'root' in all_users and 'root' not in configured_users:
                    mfa_issues.append({
                        'issue': 'Root user does not have MFA configured',
                        'recommendation': 'Configure MFA for the root user',
                        'severity': 'high'
                    })
                
                # Check sudo users
                sudo_issues = self._check_sudo_users()
                if not sudo_issues.get('skipped', False):
                    sudo_users = [user['username'] for user in sudo_issues.get('sudo_users', [])]
                    
                    for sudo_user in sudo_users:
                        if sudo_user not in configured_users and sudo_user in all_users:
                            mfa_issues.append({
                                'issue': f'Sudo user {sudo_user} does not have MFA configured',
                                'recommendation': f'Configure MFA for the sudo user {sudo_user}',
                                'severity': 'high'
                            })
            
            # Determine if there are any high-severity issues
            high_severity_issues = [issue for issue in mfa_issues if issue.get('severity') == 'high']
            medium_severity_issues = [issue for issue in mfa_issues if issue.get('severity') == 'medium']
            
            is_anomalous = len(high_severity_issues) > 0 or len(medium_severity_issues) > 0
            
            return {
                'issues': mfa_issues,
                'high_severity_count': len(high_severity_issues),
                'medium_severity_count': len(medium_severity_issues),
                'total_count': len(mfa_issues),
                'mfa_status': mfa_status,
                'is_anomalous': is_anomalous
            }
            
        except Exception as e:
            self.logger.error(f"Error checking MFA status: {e}")
            return {
                'error': str(e),
                'is_anomalous': False
            }
    
    def _check_login_patterns(self):
        """Analyze login patterns for anomalies"""
        self.logger.debug("Analyzing login patterns")
        
        pattern_issues = []
        
        try:
            # Get recent login data
            recent_logins = []
            
            # Using last command
            cmd = ["last", "-n", "100"]
            try:
                output = subprocess.check_output(cmd, universal_newlines=True)
                
                for line in output.strip().split('\n'):
                    if not line.strip() or 'wtmp begins' in line:
                        continue
                    
                    parts = line.split()
                    if len(parts) >= 5:
                        username = parts[0]
                        tty = parts[1]
                        source = parts[2]
                        date_str = ' '.join(parts[3:8])
                        
                        # Skip reboots
                        if username in ['reboot', 'shutdown']:
                            continue
                        
                        # Try to parse the date
                        login_time = None
                        try:
                            # This is complex because 'last' output format varies by OS
                            # Let's try to identify a timestamp in the date string
                            time_match = re.search(r'(\d{2}):(\d{2})', date_str)
                            if time_match:
                                hour = int(time_match.group(1))
                                minute = int(time_match.group(2))
                                
                                # Record just the hour for hour-based analysis
                                login_time = hour
                        except:
                            # Couldn't parse time, skip
                            pass
                        
                        recent_logins.append({
                            'username': username,
                            'tty': tty,
                            'source': source,
                            'date': date_str,
                            'hour': login_time
                        })
            except subprocess.CalledProcessError:
                # Command failed, skip
                pass
            
            # Check for unusual login hours
            unusual_hours = [22, 23, 0, 1, 2, 3, 4, 5]  # 10 PM to 5 AM
            
            # Group logins by user
            user_logins = {}
            for login in recent_logins:
                username = login['username']
                if username not in user_logins:
                    user_logins[username] = []
                user_logins[username].append(login)
            
            # Check each user's login patterns
            for username, logins in user_logins.items():
                # Skip if no login time information
                valid_logins = [login for login in logins if login.get('hour') is not None]
                if not valid_logins:
                    continue
                
                # Check for unusual hours
                unusual_hour_logins = [login for login in valid_logins if login.get('hour') in unusual_hours]
                if unusual_hour_logins:
                    if len(unusual_hour_logins) > 0.5 * len(valid_logins):
                        # More than 50% of logins during unusual hours
                        pattern_issues.append({
                            'username': username,
                            'issue': 'Majority of logins during unusual hours (10 PM - 5 AM)',
                            'unusual_logins': len(unusual_hour_logins),
                            'total_logins': len(valid_logins),
                            'examples': unusual_hour_logins[:3],
                            'severity': 'medium'
                        })
                    elif len(unusual_hour_logins) > 0:
                        # Some logins during unusual hours
                        pattern_issues.append({
                            'username': username,
                            'issue': 'Some logins during unusual hours (10 PM - 5 AM)',
                            'unusual_logins': len(unusual_hour_logins),
                            'total_logins': len(valid_logins),
                            'examples': unusual_hour_logins[:3],
                            'severity': 'low'
                        })
            
            # Check for logins from multiple source IPs
            for username, logins in user_logins.items():
                # Get unique source IPs
                sources = set()
                for login in logins:
                    source = login.get('source')
                    if source and source != ':0' and source != ':1' and source != 'tty1':
                        sources.add(source)
                
                # Skip if fewer than 3 sources
                if len(sources) < 3:
                    continue
                
                pattern_issues.append({
                    'username': username,
                    'issue': 'Logins from multiple source IPs',
                    'source_count': len(sources),
                    'sources': list(sources)[:5],  # Limit to top 5
                    'severity': 'low'
                })
            
            # Check for simultaneous logins (multiple active sessions)
            active_sessions = {}
            
            cmd = ["who"]
            try:
                output = subprocess.check_output(cmd, universal_newlines=True)
                
                for line in output.strip().split('\n'):
                    if not line.strip():
                        continue
                    
                    parts = line.split()
                    if len(parts) >= 5:
                        username = parts[0]
                        
                        if username not in active_sessions:
                            active_sessions[username] = []
                        
                        active_sessions[username].append({
                            'tty': parts[1],
                            'date': ' '.join(parts[2:4]),
                            'source': parts[4] if '(' in parts[4] else 'local'
                        })
            except subprocess.CalledProcessError:
                # Command failed, skip
                pass
            
            # Check for users with multiple active sessions
            for username, sessions in active_sessions.items():
                if len(sessions) > 2:
                    # Multiple active sessions
                    pattern_issues.append({
                        'username': username,
                        'issue': 'Multiple simultaneous active sessions',
                        'session_count': len(sessions),
                        'sessions': sessions,
                        'severity': 'low'
                    })
            
            # Check for frequent logins (potential scripted access)
            for username, logins in user_logins.items():
                if len(logins) > 20:
                    # Many logins, potential scripted access
                    pattern_issues.append({
                        'username': username,
                        'issue': 'High number of logins (potential scripted access)',
                        'login_count': len(logins),
                        'severity': 'low'
                    })
            
            # Determine if there are any high-severity issues
            high_severity_issues = [issue for issue in pattern_issues if issue.get('severity') == 'high']
            medium_severity_issues = [issue for issue in pattern_issues if issue.get('severity') == 'medium']
            
            is_anomalous = len(high_severity_issues) > 0 or len(medium_severity_issues) > 0
            
            return {
                'issues': pattern_issues,
                'high_severity_count': len(high_severity_issues),
                'medium_severity_count': len(medium_severity_issues),
                'total_count': len(pattern_issues),
                'logins_analyzed': len(recent_logins),
                'is_anomalous': is_anomalous
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing login patterns: {e}")
            return {
                'error': str(e),
                'is_anomalous': False
            }
    
    def _check_threat_intelligence(self):
        """Check login sources against threat intelligence"""
        self.logger.debug("Checking login sources against threat intelligence")
        
        threats = []
        
        try:
            if not hasattr(self, 'threat_intel') or not self.threat_intel:
                return {
                    'error': "Threat intelligence module not initialized",
                    'is_anomalous': False
                }
            
            # Get recent login data from auth logs
            auth_log_files = [
                '/var/log/auth.log',
                '/var/log/secure'
            ]
            
            login_sources = []
            
            for log_file in auth_log_files:
                if not os.path.exists(log_file):
                    continue
                
                cmd = ["grep", "Accepted", log_file]
                try:
                    output = subprocess.check_output(cmd, universal_newlines=True)
                    
                    for line in output.strip().split('\n'):
                        if not line.strip():
                            continue
                        
                        # Parse successful login attempts
                        source_match = re.search(r'from (\S+)', line)
                        if source_match:
                            source_ip = source_match.group(1)
                            
                            if source_ip not in ['127.0.0.1', 'localhost', '::1']:
                                login_sources.append(source_ip)
                except subprocess.CalledProcessError:
                    # No matches found
                    pass
            
            # Get login sources from last command
            cmd = ["last", "-n", "50"]
            try:
                output = subprocess.check_output(cmd, universal_newlines=True)
                
                for line in output.strip().split('\n'):
                    if not line.strip() or 'wtmp begins' in line:
                        continue
                    
                    parts = line.split()
                    if len(parts) >= 3:
                        source = parts[2]
                        
                        # Check if it looks like an IP address or hostname
                        if source and source not in ['tty1', ':0', ':1'] and '(' not in source:
                            login_sources.append(source)
            except subprocess.CalledProcessError:
                # Command failed, skip
                pass
            
            # Check sources against threat intelligence
            unique_sources = set(login_sources)
            
            for source in unique_sources:
                # Try to extract IP from hostname if needed
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', source)
                if ip_match:
                    source_ip = ip_match.group(1)
                else:
                    source_ip = source
                
                # Check against threat intelligence
                threat_info = self.threat_intel.check_ip(source_ip)
                if threat_info:
                    threats.append({
                        'source_ip': source_ip,
                        'threat_info': threat_info,
                        'severity': 'high'
                    })
            
            is_anomalous = len(threats) > 0
            
            return {
                'threats': threats,
                'count': len(threats),
                'sources_checked': len(unique_sources),
                'is_anomalous': is_anomalous
            }
            
        except Exception as e:
            self.logger.error(f"Error checking threat intelligence: {e}")
            return {
                'error': str(e),
                'is_anomalous': False
            }