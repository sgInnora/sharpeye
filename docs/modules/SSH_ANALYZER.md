# SSH Analyzer Module Documentation

## Overview

The SSH Analyzer module provides comprehensive security analysis for SSH services, configurations, keys, authentication logs, connections, tunneling, and key usage patterns. It detects a wide range of SSH-related security issues and anomalies that could indicate potential security breaches or misconfigurations.

## Key Features

### 1. SSH Configuration Analysis
- Detection of insecure SSH server configurations
- Verification of secure ciphers, MACs, and key exchange algorithms
- Host key validation and integrity checking
- Config file permission verification
- Baseline comparison for configuration changes

### 2. SSH Key Security Analysis
- Detection of weak key types (DSA, short RSA keys)
- Verification of proper key permissions
- Detection of unprotected private keys
- Analysis of authorized_keys file for proper restrictions

### 3. SSH Authentication Log Analysis
- Detection of brute force attempts
- Analysis of successful logins with suspicious patterns
- Detection of invalid user login attempts
- Historical login analysis and anomaly detection

### 4. SSH Connection Monitoring
- Detection of active SSH connections
- Identification of suspicious connections
- Analysis of connection durations and patterns
- Root login detection
- Unusual source detection

### 5. SSH Brute Force Detection
- Historical brute force attempt identification
- IP-based source correlation
- Username-based correlation
- Threat intelligence integration

### 6. SSH Tunnel and Port Forwarding Detection
- Analysis of local, remote, and dynamic (SOCKS) tunnels
- Detection of exposed sensitive services
- Identification of suspicious forwarding configurations
- Command-line tunnel detection
- Configuration review for forwarding settings

### 7. SSH Key Usage Pattern Analysis
- Tracking of key-based authentication over time
- Detection of unusual key usage patterns
- Monitoring keys used from multiple sources
- Analysis of logins during unusual hours
- Weak key type usage analysis

### 8. SSH Key Automation Analysis
- Detection of SSH keys used in cron jobs
- Analysis of SSH keys in systemd timers
- Monitoring for keys in automation scripts

### 9. Baseline Creation and Comparison
- Creation of SSH security baselines
- Detection of changes from baseline
- Highlighting of security-critical changes
- Host key rotation monitoring

## Configuration Options

The SSH analyzer supports a comprehensive set of configuration options, which can be found in the default `config.yaml` file:

```yaml
ssh:
  # Check authorized keys
  check_authorized_keys: true
  
  # Check SSH config files
  check_config: true
  
  # Check for weak algorithms
  check_algorithms: true
  
  # Check for SSH tunnels
  check_tunnels: true
  
  # Check for SSH key usage patterns
  check_key_usage: true
  
  # Check for SSH brute force attempts
  check_bruteforce: true
  
  # Check for SSH connections
  check_connections: true
  
  # Check for SSH authentication issues
  check_auth: true
  
  # Configure SSH analyzer settings
  auth_log_paths:
    - "/var/log/auth.log"
    - "/var/log/secure"
    - "/var/log/audit/audit.log"
  
  ssh_config_path: "/etc/ssh/sshd_config"
  
  ssh_key_paths:
    - "/etc/ssh"
    - "/root/.ssh"
    - "/home"
  
  # Bruteforce detection settings
  bf_time_window: 300  # 5 minutes
  bf_attempt_threshold: 5  # 5 attempts
  
  # Secure ciphers
  secure_ciphers:
    - "chacha20-poly1305@openssh.com"
    - "aes256-gcm@openssh.com"
    - "aes128-gcm@openssh.com"
    - "aes256-ctr"
    - "aes192-ctr"
    - "aes128-ctr"
  
  # Secure MACs
  secure_macs:
    - "hmac-sha2-512-etm@openssh.com"
    - "hmac-sha2-256-etm@openssh.com"
    - "umac-128-etm@openssh.com"
    - "hmac-sha2-512"
    - "hmac-sha2-256"
    - "umac-128@openssh.com"
  
  # Secure key exchange algorithms
  secure_kex:
    - "curve25519-sha256@libssh.org"
    - "curve25519-sha256"
    - "diffie-hellman-group16-sha512"
    - "diffie-hellman-group18-sha512"
    - "diffie-hellman-group-exchange-sha256"
  
  # Configuration recommendations
  recommended_settings:
    PermitRootLogin: "no"
    PasswordAuthentication: "no"
    X11Forwarding: "no"
    MaxAuthTries: 3
    AllowAgentForwarding: "no"
    AllowTcpForwarding: "no"
    PermitEmptyPasswords: "no"
    GatewayPorts: "no"
    PermitTunnel: "no"
    LogLevel: "VERBOSE"
    ClientAliveInterval: 300
    ClientAliveCountMax: 2
    LoginGraceTime: 60
```

## Usage Examples

### Basic Analysis

```python
from modules.ssh_analyzer import SSHAnalyzer

# Initialize with default configuration
analyzer = SSHAnalyzer()

# Run full analysis
results = analyzer.analyze()

# Check if any anomalies were found
if results['is_anomalous']:
    print("Security issues detected in SSH configuration or usage!")
    
    # Print config issues if any
    if results['config_issues'].get('is_anomalous', False):
        print(f"Found {results['config_issues']['count']} SSH configuration issues")
        for issue in results['config_issues']['issues']:
            print(f" - {issue.get('setting', 'Unknown setting')}: {issue.get('recommendation', '')}")
    
    # Print key issues if any
    if results['key_issues'].get('is_anomalous', False):
        print(f"Found {results['key_issues']['count']} SSH key security issues")
```

### Checking for SSH Tunnels

```python
from modules.ssh_analyzer import SSHAnalyzer

# Initialize analyzer
analyzer = SSHAnalyzer()

# Only check for SSH tunnels
results = analyzer._check_ssh_tunnels()

# Check for suspicious tunnels
if results['is_anomalous']:
    print(f"Found {results['suspicious_count']} suspicious SSH tunnels:")
    for tunnel in results['suspicious_tunnels']:
        print(f" - Tunnel: {tunnel.get('tunnel_type', 'unknown')} from {tunnel.get('username', 'unknown user')}")
        print(f"   Risk: {tunnel.get('security_risk', 'unknown risk')}")
        print(f"   Severity: {tunnel.get('severity', 'unknown')}")
```

### Establishing and Comparing Baselines

```python
from modules.ssh_analyzer import SSHAnalyzer

# Initialize analyzer
analyzer = SSHAnalyzer()

# Create baseline
analyzer.establish_baseline()
print("Baseline created successfully.")

# Later on, compare against baseline
comparison = analyzer.compare_baseline()

# Check for changes
if comparison['is_anomalous']:
    print("SSH configuration has changed since baseline!")
    
    # Check for config changes
    if comparison['config_changes'].get('is_anomalous', False):
        for change in comparison['config_changes'].get('changed_settings', []):
            print(f" - Setting {change['setting']} changed from '{change['old_value']}' to '{change['new_value']}'")
            if change.get('security_critical', False):
                print("   (This is a security-critical change)")
    
    # Check for host key changes
    for key_change in comparison['config_changes'].get('host_key_changes', []):
        print(f" - Host key ({key_change['type']}) has changed!")
        print(f"   Old: {key_change.get('old_fingerprint', 'Unknown')}")
        print(f"   New: {key_change.get('new_fingerprint', 'Unknown')}")
```

## Security Recommendations

Based on analysis from the SSH Analyzer module, we recommend the following SSH security best practices:

1. **Configuration Security**
   - Disable root login (`PermitRootLogin no`)
   - Disable password authentication (`PasswordAuthentication no`)
   - Use only strong encryption algorithms
   - Set proper permissions on SSH config files (0600)
   - Use ED25519 keys instead of RSA/DSA
   - Set appropriate login grace time and max auth tries

2. **Key Security**
   - Use ED25519 keys where possible
   - Always protect private keys with strong passphrases
   - Set proper permissions on keys (0600 for private, 0644 for public)
   - Restrict keys using `from=` and `command=` options in authorized_keys
   - Regularly rotate host keys

3. **Authentication Security**
   - Implement fail2ban or similar tools for brute force protection
   - Monitor logs for suspicious login patterns
   - Restrict SSH access to specific IP ranges where possible
   - Consider using port knocking or single-packet authorization

4. **Tunneling Security**
   - Disable TCP forwarding unless specifically needed (`AllowTcpForwarding no`)
   - Disable gateway ports (`GatewayPorts no`)
   - Disable tunnel device forwarding (`PermitTunnel no`)
   - Monitor for unauthorized tunnels

5. **General Security**
   - Keep SSH software updated
   - Use verbose logging
   - Consider changing the default port (though not a strong security measure)
   - Implement proper network segmentation
   - Use keys with hardware security modules for critical systems

## Integration with Threat Intelligence

The SSH analyzer can integrate with threat intelligence services to enhance its detection capabilities. When threat intelligence integration is enabled, the analyzer can:

1. Check source IPs against known threat feeds
2. Identify login attempts from high-risk regions
3. Correlate brute force attempts with known attack patterns
4. Provide additional context for suspicious SSH tunnels and connections

To enable threat intelligence integration, configure the `threat_intelligence` section in the main SharpEye configuration file.

## Performance Considerations

The SSH analyzer is designed for efficiency but can be resource-intensive when analyzing large log files or systems with many SSH keys. Consider the following performance tips:

1. Configure appropriate log file paths to avoid unnecessary searches
2. Set reasonable thresholds for brute force detection
3. Limit the scope of key paths when not scanning the entire system
4. Schedule baseline comparisons during off-peak hours
5. Use the performance metrics in the analysis results to tune your configuration

---

## Release History

- **v1.0 (May 8, 2025)**: Initial release with comprehensive SSH security analysis
  - Full SSH configuration, key, authentication, and connection analysis
  - Baseline creation and comparison functionality
  - Integration with threat intelligence

- **v1.1 (May 8, 2025)**: Enhanced functionality
  - Added SSH tunneling and port forwarding detection
  - Added SSH key usage pattern analysis
  - Added performance optimization metrics
  - Improved threat intelligence integration