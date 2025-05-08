# User Account Analyzer Module Documentation

## Overview

The User Account Analyzer module provides comprehensive security analysis for user accounts on Linux systems. It detects suspicious user accounts, unauthorized privilege escalation, weak password policies, insecure home directory configurations, missing MFA, and anomalous login patterns that could indicate potential security breaches.

## Key Features

### 1. Root Account Analysis
- Detection of multiple accounts with UID 0 (root privileges)
- Verification of proper root account configuration
- Root account security monitoring

### 2. User Shell Analysis
- Detection of system accounts with login shells
- Verification of valid login shells
- Identification of suspicious shell configurations

### 3. Sudo User Analysis
- Detection of users with sudo privileges
- Monitoring of sudo group membership
- Analysis of sudo configuration files
- Identification of unexpected sudo groups

### 4. Suspicious Account Detection
- Detection of accounts with no passwords
- Identification of hidden user accounts (UID < 1000)
- Detection of UID/GID inconsistencies
- Analysis of suspicious account attributes

### 5. Account Change Monitoring
- Detection of recently modified account information
- Monitoring of password age and changes
- Analysis of account additions and modifications
- Verification of account expiration settings

### 6. Login Activity Analysis
- Monitoring of recent login activity
- Detection of failed login attempts
- Identification of suspicious login sources
- Brute force attempt detection

### 7. Home Directory Security Analysis
- Verification of proper home directory permissions
- Detection of insecure SSH key storage
- Analysis of shell configuration files for security issues
- Identification of suspicious content in startup files

### 8. Password Policy Analysis
- Verification of password complexity requirements
- Checking of password aging settings
- Analysis of PAM configuration for password security
- Identification of expired or stale passwords

### 9. Group Membership Analysis
- Detection of users in sensitive groups (root, sudo, wheel, docker, etc.)
- Identification of suspicious group names
- Analysis of group membership patterns
- Privilege assessment based on group membership

### 10. Privilege Escalation Detection
- Detection of SUID/SGID binaries in unusual locations
- Identification of world-writable files owned by root
- Analysis of binaries with dangerous capabilities
- Detection of potential privilege escalation vectors

### 11. MFA Status Checking
- Verification of MFA module installation and configuration
- Identification of privileged users without MFA
- Checking for MFA usage on critical accounts
- Analysis of PAM configuration for MFA settings

### 12. Login Pattern Analysis
- Detection of logins during unusual hours
- Identification of logins from multiple source IPs
- Analysis of simultaneous active sessions
- Detection of suspicious login frequency patterns

### 13. Threat Intelligence Integration
- Checking login sources against known threat databases
- Correlation of suspicious activity with threat feeds
- Enrichment of security findings with threat context
- Risk assessment based on threat intelligence

### 14. Baseline Creation and Comparison
- Creation of user account security baselines
- Detection of changes from baseline
- Identification of new or removed accounts
- Monitoring of privilege changes

## Configuration Options

The User Account Analyzer supports a comprehensive set of configuration options, which can be found in the default `config.yaml` file:

```yaml
user_accounts:
  # Enable/disable specific checks
  check_sudo: true
  check_shell: true
  check_auth_logs: true
  check_home_security: true
  check_password_policy: true
  check_group_membership: true
  check_privilege_escalation: true
  check_mfa_status: true
  check_login_patterns: true
  
  # Path to store baseline data
  baseline_file: "/var/lib/sharpeye/baselines/accounts.json"
  
  # Expected sudo groups that are considered normal
  expected_sudo_groups:
    - "sudo"
    - "wheel"
    - "admin"
  
  # List of suspicious IPs to monitor
  suspicious_ips:
    - "192.168.1.100"
  
  # Threshold for brute force detection
  brute_force_threshold: 5
  
  # Threat intelligence integration settings
  threat_intelligence:
    enabled: false
    api_key: ""
    check_login_sources: true
    check_usernames: true
```

## Usage Examples

### Basic Analysis

```python
from modules.user_accounts import UserAccountAnalyzer

# Initialize with default configuration
analyzer = UserAccountAnalyzer()

# Run full analysis
results = analyzer.analyze()

# Check if any anomalies were found
if results['is_anomalous']:
    print("Security issues detected in user accounts!")
    
    # Check for root account issues
    if results['root_accounts'].get('is_anomalous', False):
        print(f"Found {results['root_accounts']['count']} root accounts (expected: 1)")
    
    # Check for suspicious accounts
    if results['suspicious_accounts'].get('is_anomalous', False):
        print(f"Found {results['suspicious_accounts']['total_count']} suspicious accounts")
        print(f"High severity: {results['suspicious_accounts']['high_severity_count']}")
        print(f"Medium severity: {results['suspicious_accounts']['medium_severity_count']}")
```

### Checking for Home Directory Security Issues

```python
from modules.user_accounts import UserAccountAnalyzer

# Initialize analyzer
analyzer = UserAccountAnalyzer()

# Only check home directory security
results = analyzer._check_home_directory_security()

# Check for issues
if results['is_anomalous']:
    print(f"Found {results['total_count']} home directory security issues:")
    for issue in results['issues']:
        username = issue.get('username', 'unknown')
        issue_desc = issue.get('issue', 'unknown issue')
        severity = issue.get('severity', 'unknown')
        print(f" - User {username}: {issue_desc} (Severity: {severity})")
```

### Establishing and Comparing Baselines

```python
from modules.user_accounts import UserAccountAnalyzer

# Initialize analyzer
analyzer = UserAccountAnalyzer()

# Create baseline
analyzer.establish_baseline()
print("User account baseline created successfully.")

# Later on, compare against baseline
comparison = analyzer.compare_baseline()

# Check for changes
if comparison['is_anomalous']:
    print("User account configuration has changed since baseline!")
    
    # Check for new users
    if comparison.get('new_users', []):
        print("New users detected:")
        for user in comparison['new_users']:
            print(f" - {user['username']} (UID: {user.get('uid', 'unknown')})")
    
    # Check for modified users
    if comparison.get('modified_users', []):
        print("Modified users detected:")
        for user in comparison['modified_users']:
            print(f" - {user['username']} had changes in: {', '.join(k for k, v in user.get('changes', {}).items() if v)}")
    
    # Check for new sudo users
    if comparison.get('new_sudo_users', []):
        print("New sudo users detected:")
        for user in comparison['new_sudo_users']:
            print(f" - {user['username']} (Source: {user.get('source', 'unknown')})")
```

## Security Recommendations

Based on analysis from the User Account Analyzer module, we recommend the following account security best practices:

1. **User Account Management**
   - Maintain only one account with UID 0 (root)
   - Disable direct root login
   - Implement proper account lifecycle management
   - Regularly audit user accounts and privileges

2. **Password Security**
   - Enforce strong password policies (length, complexity, history)
   - Configure proper password aging (90 days maximum)
   - Implement account lockout after failed attempts
   - Disable empty passwords and weak configurations

3. **Home Directory Security**
   - Set appropriate permissions (0750 or more restrictive)
   - Secure SSH directories and keys (0700 for .ssh, 0600 for private keys)
   - Monitor shell initialization files for suspicious content
   - Prevent world-readable home directories

4. **Privilege Management**
   - Implement the principle of least privilege
   - Limit sudo access to required users only
   - Use sudo with command restrictions when possible
   - Monitor users in privileged groups (wheel, docker, etc.)

5. **SUID/SGID Security**
   - Regularly audit SUID/SGID binaries
   - Remove unnecessary SUID/SGID bits
   - Be cautious of SUID binaries in user home directories
   - Monitor capability settings for privileged access

6. **Multi-Factor Authentication**
   - Implement MFA for all privileged accounts
   - Enforce MFA for remote access
   - Verify MFA module configuration
   - Regularly audit MFA compliance

7. **Login Security**
   - Monitor login times and patterns
   - Configure account lockout policies
   - Restrict access from suspicious locations
   - Implement IP-based access controls for sensitive accounts

8. **Group Management**
   - Regularly audit group memberships
   - Limit membership in privileged groups
   - Implement proper group-based access controls
   - Monitor for suspicious group names or configurations

## Integration with Threat Intelligence

The User Account Analyzer can integrate with threat intelligence services to enhance its detection capabilities. When threat intelligence integration is enabled, the analyzer can:

1. Check login source IPs against known threat feeds
2. Identify login attempts from high-risk regions
3. Correlate usernames with known attack patterns
4. Provide additional context for suspicious login activity

To enable threat intelligence integration, configure the `threat_intelligence` section in the main SharpEye configuration file.

## Performance Considerations

The User Account Analyzer is designed for efficiency but can be resource-intensive when analyzing systems with many users or extensive login history. Consider the following performance tips:

1. Disable checks that are not relevant to your environment
2. Configure appropriate baseline file locations
3. Limit the scope of privilege escalation checks to critical areas
4. Use the performance metrics in the analysis results to tune your configuration
5. Schedule baseline comparisons during off-peak hours

---

## Release History

- **v1.0 (May 8, 2025)**: Initial release with basic user account security analysis
  - Root account, shell, sudo, and suspicious account detection
  - Account change monitoring and login activity analysis
  - Baseline creation and comparison functionality

- **v1.1 (May 8, 2025)**: Enhanced functionality
  - Added home directory security analysis
  - Added password policy analysis
  - Added group membership analysis
  - Added privilege escalation detection
  - Added MFA status checking
  - Added login pattern analysis
  - Added threat intelligence integration
  - Improved performance metrics