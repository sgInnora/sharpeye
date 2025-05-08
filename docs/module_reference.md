# SharpEye Module Reference

This document provides detailed technical information about each detection module in SharpEye, including implementation details, configuration options, and integration points.

## Implementation Status

| Module | Status | Test Coverage | Last Update |
|--------|--------|---------------|------------|
| File Integrity | ✅ Complete | 95% | May 8, 2025 |
| Kernel Modules | ✅ Complete | 94% | May 8, 2025 |
| Library Inspection | ✅ Complete | 95% | May 8, 2025 |
| Privilege Escalation | ✅ Complete | 94% | May 8, 2025 |
| Log Analysis | ✅ Complete | 93% | May 8, 2025 |
| System Resources | ✅ Complete | 100% | May 8, 2025 |
| User Accounts | ✅ Complete | 100% | May 8, 2025 |
| Processes | ✅ Complete | 100% | May 8, 2025 |
| Network | ✅ Complete | 95% | May 8, 2025 |
| Cryptominer Detection | ✅ Complete | 95% | April 30, 2025 |
| Scheduled Tasks | ✅ Complete | 95% | May 8, 2025 |
| SSH | ✅ Complete | 100% | May 8, 2025 |
| Rootkit Detection | ✅ Complete | 100% | May 8, 2025 |

## Table of Contents

1. [System Resources Module](#system-resources-module)
2. [User Accounts Module](#user-accounts-module)
3. [SSH Analyzer Module](#ssh-analyzer-module)
4. [Processes Module](#processes-module)
5. [Network Module](#network-module)
6. [Cryptominer Detection Module](#cryptominer-detection-module)
7. [File System Module](#file-system-module)
8. [Logs Module](#logs-module)
9. [Scheduled Tasks Module](#scheduled-tasks-module)
10. [Kernel Module](#kernel-module)
11. [Libraries Module](#libraries-module)
12. [Privileges Module](#privileges-module)
13. [Rootkit Detection Module](#rootkit-detection-module)

## System Resources Module

### Overview

The System Resources module monitors CPU, memory, disk usage, and other system resources to detect abnormal patterns that may indicate security threats. This module uses a combination of threshold-based detection and machine learning to identify potential issues.

### Implementation Details

- **Class**: `SystemResourcesMonitor`
- **Main methods**:
  - `analyze()`: Entry point that runs all system resource checks
  - `_check_cpu()`: Analyzes CPU usage patterns
  - `_check_memory()`: Examines memory consumption
  - `_check_disk()`: Monitors disk I/O and usage
  - `_check_network()`: Reviews network traffic statistics
  - `_check_processes()`: Examines process resource utilization
  - `_detect_anomalies()`: Uses machine learning to identify anomalies
  - `establish_baseline()`: Creates a baseline of normal resource usage
  - `compare_baseline()`: Compares current state with the baseline

- **Supporting Classes**:
  - `CPUAnalyzer`: Specializes in CPU pattern analysis
  - `MemoryAnalyzer`: Focuses on memory usage patterns
  - `DiskAnalyzer`: Examines disk activity
  - `AnomalyDetector`: Implements machine learning algorithms

### Configuration Options

```yaml
system_resources:
  # How often to check resources (seconds)
  check_interval: 60
  
  # Thresholds for alerts
  cpu_threshold: 90
  memory_threshold: 85
  disk_threshold: 95
  
  # Machine learning options
  anomaly_detection:
    enabled: true
    algorithm: "isolation_forest"
    sensitivity: "medium"  # low, medium, high
    training_period: 604800  # 1 week in seconds
  
  # Resource collection
  collect_cpu: true
  collect_memory: true
  collect_disk: true
  collect_network: true
  
  # Baseline configuration
  baseline_file: "/var/lib/sharpeye/baselines/resources.json"
  
  # Specific resources to monitor
  monitor_swap: true
  monitor_iowait: true
  monitor_load_avg: true
  monitor_context_switches: true
```

### Integration Points

- Feeds into the Cryptominer Detection module for enhanced mining detection
- Works with the Processes module to correlate resource use with process behavior
- Provides data to the Rootkit Detection module for system anomaly correlation
- Supports baseline creation and comparison for all resource metrics

## User Accounts Module

### Overview

The User Accounts module monitors user account activities, permissions, and configurations to detect unauthorized access, privilege escalation, and account misuse.

### Implementation Details

- **Class**: `UserAccountsMonitor`
- **Main methods**:
  - `analyze()`: Entry point that runs all account checks
  - `_check_new_accounts()`: Identifies recently created accounts
  - `_check_sudo_access()`: Analyzes sudo/root privilege changes
  - `_check_ssh_keys()`: Examines SSH key configurations
  - `_check_auth_logs()`: Reviews authentication logs
  - `_check_home_security()`: Checks home directory permissions
  - `_check_password_policy()`: Checks password policies and aging settings
  - `_check_group_membership()`: Analyzes sensitive group memberships
  - `_check_privilege_escalation()`: Detects privilege escalation vectors
  - `_check_mfa_status()`: Verifies multi-factor authentication configuration
  - `_check_login_patterns()`: Analyzes anomalous login patterns
  - `_check_threat_intelligence()`: Integrates with threat intelligence
  - `establish_baseline()`: Creates a baseline of normal account status
  - `compare_baseline()`: Compares current accounts with the baseline

### Configuration Options

```yaml
user_accounts:
  # Database path (if not specified, will use ~/.sharpeye/user_accounts.db)
  database_path: "/var/lib/sharpeye/user_accounts.db"
  
  # Baseline file
  baseline_file: "/var/lib/sharpeye/baselines/accounts.json"
  
  # Primary checks
  check_sudo: true
  check_shell: true
  check_auth_logs: true
  
  # Enhanced security checks
  check_home_security: true
  check_password_policy: true
  check_group_membership: true
  check_privilege_escalation: true
  check_mfa_status: true
  check_login_patterns: true
  
  # Expected groups with sudo privileges
  expected_sudo_groups:
    - "sudo"
    - "wheel"
    - "admin"
  
  # Threshold for brute force detection
  brute_force_threshold: 5
```

### Integration Points

- Works with the SSH Analyzer module to enhance SSH key monitoring
- Feeds into the Privilege Escalation module for permissions analysis
- Coordinates with the Log Analysis module for authentication event review
- Provides account baseline for anomaly detection

## SSH Analyzer Module

### Overview

The SSH Analyzer module provides comprehensive SSH security analysis including configuration assessment, key management, and connection monitoring to detect potential threats.

### Implementation Details

- **Class**: `SSHAnalyzer`
- **Main methods**:
  - `analyze()`: Entry point that runs all SSH checks
  - `_check_config()`: Analyzes SSH server configuration
  - `_check_keys()`: Examines SSH keys for security issues
  - `_check_auth_attempts()`: Reviews authentication attempts
  - `_check_authorized_keys()`: Scans authorized_keys files
  - `_check_ssh_tunnels()`: Detects port forwarding and tunnels
  - `_check_key_algorithms()`: Verifies the strength of key algorithms
  - `_check_key_usage()`: Monitors key usage patterns
  - `_check_abnormal_connections()`: Identifies unusual connection patterns
  - `establish_baseline()`: Creates a baseline of normal SSH configuration
  - `compare_baseline()`: Compares current state with the baseline

### Configuration Options

```yaml
ssh_analyzer:
  # Database path (if not specified, will use ~/.sharpeye/ssh_analyzer.db)
  database_path: "/var/lib/sharpeye/ssh_analyzer.db"
  
  # Baseline file
  baseline_file: "/var/lib/sharpeye/baselines/ssh.json"
  
  # SSH configuration
  ssh_config_path: "/etc/ssh/sshd_config"
  
  # SSH checks
  check_auth_attempts: true
  check_keys: true
  check_tunnels: true
  check_config: true
  check_forwarding: true
  
  # Key checks
  key_algorithms:
    - "rsa"
    - "ed25519"
    - "ecdsa"
  
  # Service checks
  check_running: true
  
  # Brute force detection
  brute_force_threshold: 5
  
  # Connection monitoring
  monitor_connections: true
  connection_tracking_limit: 1000
```

### Integration Points

- Works with the Network module to correlate SSH connections
- Feeds into the User Accounts module for account security analysis
- Provides data to the Log Analysis module for SSH log context
- Supports the Privilege Escalation module with SSH-based vector analysis

## Processes Module

### Overview

The Processes module monitors and analyzes running processes to detect malicious activities, unusual behaviors, and potential threats. It includes process relationship mapping, memory analysis, and behavioral tracking.

### Implementation Details

- **Class**: `ProcessAnalyzer`
- **Main methods**:
  - `analyze()`: Entry point that runs all process checks
  - `_get_all_processes()`: Retrieves the process list and details
  - `_check_process_relationships()`: Maps parent-child relationships
  - `_check_hidden_processes()`: Detects processes hiding techniques
  - `_check_memory_usage()`: Analyzes memory usage patterns
  - `_check_execution_history()`: Reviews execution history
  - `_check_process_behavior()`: Analyzes process behavior patterns
  - `_check_suspicious_names()`: Looks for processes with suspect names
  - `_check_command_line()`: Analyzes command line arguments
  - `_build_process_tree()`: Creates a hierarchical process tree
  - `establish_baseline()`: Creates a baseline of normal processes
  - `compare_baseline()`: Compares current processes with the baseline

### Configuration Options

```yaml
processes:
  # Database path (if not specified, will use ~/.sharpeye/processes.db)
  database_path: "/var/lib/sharpeye/processes.db"
  
  # Baseline file
  baseline_file: "/var/lib/sharpeye/baselines/processes.json"
  
  # Process checks
  check_hidden: true
  check_relationships: true
  check_memory: true
  check_behavior: true
  check_names: true
  check_command_line: true
  
  # Scanning settings
  scan_interval: 300  # seconds
  process_history_limit: 1000
  
  # Visualization
  visualization_enabled: true
  visualization_path: "/var/lib/sharpeye/visualizations"
  
  # Process relationship depth
  relationship_depth: 3
  
  # Suspicious patterns
  suspicious_patterns:
    - "nc -e"
    - "socat"
    - "miner"
    - "xmr"
```

### Integration Points

- Works with the System Resources module for resource usage correlation
- Feeds into the Cryptominer Detection module for process-based detection
- Provides data to the Rootkit Detection module for hidden process analysis
- Supports the Network module with process-to-connection mapping

See [PROCESSES.md](./modules/PROCESSES.md) for detailed documentation.

## Network Module

### Overview

The Network module monitors network connections, traffic patterns, and suspicious communications to detect potential threats, data exfiltration, and command and control activities.

### Implementation Details

- **Class**: `NetworkAnalyzer`
- **Main methods**:
  - `analyze()`: Entry point that runs all network checks
  - `_get_all_connections()`: Retrieves active network connections
  - `_check_unusual_ports()`: Detects unusual port usage
  - `_check_suspicious_ips()`: Checks for connections to suspicious IPs
  - `_check_data_volume()`: Analyzes data transfer volumes
  - `_check_connection_patterns()`: Identifies suspicious patterns
  - `_check_dns_queries()`: Analyzes DNS queries for anomalies
  - `_check_listening_services()`: Monitors services listening on ports
  - `establish_baseline()`: Creates a baseline of normal network activity
  - `compare_baseline()`: Compares current activity with the baseline

### Configuration Options

```yaml
network:
  # Database path (if not specified, will use ~/.sharpeye/network.db)
  database_path: "/var/lib/sharpeye/network.db"
  
  # Baseline file
  baseline_file: "/var/lib/sharpeye/baselines/network.json"
  
  # Network checks
  check_unusual_ports: true
  check_suspicious_ips: true
  check_data_volume: true
  check_patterns: true
  check_dns: true
  check_listening: true
  
  # Threat intelligence
  threat_intel_enabled: true
  threat_intel_sources:
    - "local_blacklist"
    - "reputation_service"
  
  # Connection thresholds
  connection_tracking_limit: 10000
  data_volume_threshold: 1000000000  # 1GB
  
  # Whitelisted networks
  whitelisted_networks:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
```

### Advanced Detection Features

1. **Command and Control Detection**:
   - Analyzes beaconing patterns in network traffic
   - Detects abnormal timing patterns in connections
   - Identifies connections with unusual persistence

2. **Data Exfiltration Detection**:
   - Monitors for large outbound data transfers
   - Tracks unusual protocols and destinations
   - Analyzes timing of data transfers

3. **Service Discovery**:
   - Identifies remote access services (SSH, Telnet, RDP, VNC)
   - Checks for insecure configurations
   - Detects publicly accessible services

4. **Suspicious Connection Patterns**:
   - Detects connections to sequential high ports (C2 communication)
   - Identifies server processes making outbound connections
   - Flags multiple connections to the same remote address with different ports

5. **DNS Analysis**:
   - Captures and analyzes DNS queries
   - Identifies suspicious domain patterns
   - Detects potential DNS tunneling or data exfiltration

### Integration Points

- Works with the Processes module to correlate network and process activity
- Interfaces with the SSH module for related SSH connection checks
- Maintains baseline data for future comparison

## Cryptominer Detection Module

### Overview

The Cryptominer Detection module (`cryptominer.py`) identifies cryptomining malware using machine learning and CPU behavior analysis. It detects unauthorized cryptocurrency mining that can consume system resources and potentially indicate security breaches.

### Implementation Details

- **Class**: `CryptominerDetectionModule`
- **Main methods**:
  - `analyze()`: Entry point that runs detection on all processes
  - `_get_all_processes()`: Retrieves all processes for analysis
  - `_get_system_load()`: Gets system load averages
  - `_start_monitoring()`: Starts continuous monitoring thread
  - `_monitoring_loop()`: Implements background monitoring
  - `establish_baseline()`: Creates a baseline of normal processes
  - `compare_baseline()`: Compares current state with the baseline

- **Supporting Classes**:
  - `CryptominerDetector`: Core detector implementing analysis
  - `CPUPatternAnalyzer`: Analyzes CPU usage patterns typical of miners
  - `SignatureDetector`: Detects known mining signatures
  - `NetworkAnalyzer`: Checks for mining pool connections

### Configuration Options

```yaml
cryptominer_detection:
  # Database path (if not specified, will use ~/.sharpeye/cryptominer.db)
  database_path: "/var/lib/sharpeye/cryptominer.db"
  
  # Baseline file
  baseline_file: "/var/lib/sharpeye/baselines/cryptominer.json"
  
  # Detection methods
  cpu_pattern_detection: true
  signature_detection: true
  network_detection: true
  memory_scanning: true
  
  # CPU check thresholds
  cpu_threshold: 80
  stable_load_window: 300  # seconds
  
  # Machine learning
  ml_enabled: true
  ml_model_path: "/var/lib/sharpeye/models/cryptominer_model.pkl"
  ml_confidence_threshold: 0.7
  
  # Known mining pools
  mining_pool_domains:
    - "pool.minergate.com"
    - "xmrpool.eu"
    - "supportxmr.com"
```

### Integration Points

- Works with System Resources for enhanced CPU pattern detection
- Feeds into the Network module for mining pool connection analysis
- Coordinates with the Process module for comprehensive detection
- Maintains baseline data for future comparison

## File System Module

### Overview

The File System module monitors critical system files, detects unauthorized changes, and ensures file integrity through cryptographic validation. It can detect backdoors, unauthorized configuration changes, and potential indicators of compromise.

### Implementation Details

- **Class**: `FileIntegrityMonitor`
- **Main methods**:
  - `analyze()`: Entry point that runs all file checks
  - `_check_critical_files()`: Verifies integrity of critical files
  - `_check_permissions()`: Analyzes file permission changes
  - `_check_hidden_files()`: Detects hidden files and directories
  - `_check_new_files()`: Identifies newly created files
  - `_check_binaries()`: Verifies the integrity of binary files
  - `_check_package_files()`: Compares package files with official versions
  - `_calculate_hash()`: Computes cryptographic hashes
  - `establish_baseline()`: Creates a baseline of file hashes
  - `compare_baseline()`: Compares current files with the baseline

### Configuration Options

```yaml
file_integrity:
  # Database path (if not specified, will use ~/.sharpeye/file_integrity.db)
  database_path: "/var/lib/sharpeye/file_integrity.db"
  
  # Baseline file
  baseline_file: "/var/lib/sharpeye/baselines/files.json"
  
  # Critical file paths to monitor
  critical_paths:
    - "/etc/passwd"
    - "/etc/shadow"
    - "/etc/sudoers"
    - "/etc/ssh"
    - "/boot"
    - "/bin"
    - "/sbin"
    - "/usr/bin"
    - "/usr/sbin"
    - "/usr/local/bin"
    - "/lib"
    - "/lib64"
  
  # Directories to exclude
  excluded_paths:
    - "/var/log"
    - "/tmp"
    - "/proc"
    - "/sys"
    - "/dev"
    - "/run"
  
  # File extensions to exclude
  excluded_extensions:
    - ".log"
    - ".tmp"
    - ".swp"
    - ".pid"
    - ".cache"
  
  # Hashing algorithm to use
  hash_algorithm: "sha256"
  
  # Thread count for parallel processing
  thread_count: 4
  
  # Scan interval in seconds
  scan_interval: 3600  # 1 hour
  
  # Maximum file size to scan in bytes
  max_file_size: 104857600  # 100MB
  
  # Critical libraries to monitor closely
  critical_libraries:
    - "libc.so.6"
    - "ld-linux-x86-64.so.2"
    - "libcrypto.so"
    - "libssl.so"
    - "libpam.so"
    - "libssh.so"
    - "libnss.so"
    - "libkrb5.so"
  
  # Suspicious library name patterns
  suspicious_library_patterns:
    - "^lib.*\\.so\\.[0-9]+\\.bak$"
    - "^lib.*\\.so\\.[0-9]+\\.[0-9]+$"
```

### Integration Points

- Works with the Library module for shared library monitoring
- Feeds into the Rootkit Detection module for system file tampering analysis
- Coordinates with the Process module for file access correlation
- Maintains baseline data for future comparison

## Logs Module

### Overview

The Logs module (`log_analysis.py`) analyzes system logs to identify security events, anomalies, and potential attacks across various log sources.

### Implementation Details

- **Class**: `LogAnalyzer`
- **Main methods**:
  - `analyze()`: Entry point that runs all log checks
  - `_analyze_auth_logs()`: Examines authentication logs
  - `_analyze_system_logs()`: Reviews system logs
  - `_analyze_application_logs()`: Checks application logs
  - `_analyze_audit_logs()`: Examines audit logs
  - `_check_log_tampering()`: Detects log tampering or deletion
  - `_check_log_volume()`: Analyzes log volume patterns
  - `_check_log_gaps()`: Identifies gaps in log entries
  - `establish_baseline()`: Creates a baseline of normal log patterns
  - `compare_baseline()`: Compares current logs with the baseline

### Configuration Options

```yaml
log_analysis:
  # Database path (if not specified, will use ~/.sharpeye/log_analysis.db)
  database_path: "/var/lib/sharpeye/log_analysis.db"
  
  # Baseline file
  baseline_file: "/var/lib/sharpeye/baselines/logs.json"
  
  # Log sources
  auth_log: "/var/log/auth.log"
  syslog: "/var/log/syslog"
  messages: "/var/log/messages"
  secure: "/var/log/secure"
  audit_log: "/var/log/audit/audit.log"
  
  # Application logs
  application_logs:
    - "/var/log/apache2/error.log"
    - "/var/log/apache2/access.log"
    - "/var/log/nginx/error.log"
    - "/var/log/nginx/access.log"
  
  # Log checks
  check_auth_failures: true
  check_privilege_escalation: true
  check_service_failures: true
  check_tampering: true
  check_log_volume: true
  check_kernel_messages: true
  
  # Threshold for brute force detection
  auth_failure_threshold: 5
  
  # Time window for correlation (in seconds)
  correlation_window: 300
```

### Integration Points

- Works with the User Accounts module to correlate user activities
- Feeds into the SSH analyzer for authentication events
- Provides context to the System Resources module for system events
- Maintains baseline data for future comparison

## Scheduled Tasks Module

### Overview

The Scheduled Tasks module inspects cron jobs, systemd timers, and other scheduled tasks to identify unauthorized entries that might be used for persistence or malicious activity.

### Implementation Details

- **Class**: `ScheduledTaskAnalyzer`
- **Main methods**:
  - `analyze()`: Entry point that runs all checks
  - `_check_cron()`: Analyzes cron jobs
  - `_check_systemd_timers()`: Examines systemd timers
  - `_check_at()`: Checks at jobs
  - `_check_hidden()`: Detects hidden scheduled tasks
  - `_is_suspicious_task()`: Evaluates tasks for suspicious characteristics
  - `establish_baseline()`: Creates a baseline of normal scheduled tasks
  - `compare_baseline()`: Compares current tasks with the baseline

### Configuration Options

```yaml
scheduled_tasks:
  # Check cron jobs
  check_cron: true
  
  # Check systemd timers
  check_systemd_timers: true
  
  # Check at jobs
  check_at: true
  
  # Check for hidden jobs
  check_hidden: true
  
  # Baseline file
  baseline_file: "/var/lib/sharpeye/baselines/tasks.json"
  
  # Database path
  database_path: "/var/lib/sharpeye/scheduled_tasks.db"
  
  # Paths to check
  cron_paths:
    - "/etc/crontab"
    - "/etc/cron.d"
    - "/etc/cron.hourly"
    - "/etc/cron.daily"
    - "/etc/cron.weekly"
    - "/etc/cron.monthly"
    - "/var/spool/cron"
  
  # Suspicious patterns to match
  suspicious_patterns:
    - "nc -e"
    - "bash -i"
    - "wget http"
    - "curl http"
    - "base64 -d"
```

### Integration Points

- Works with the Processes module to correlate running processes with scheduled tasks
- Feeds into the File Integrity module for script analysis
- Provides data to the Privilege Escalation module for persistence vector analysis
- Maintains baseline data for future comparison

## Kernel Module

### Overview

The Kernel Module Analyzer inspects kernel modules, kernel parameters, and system calls to detect rootkits, kernel-level threats, and unauthorized kernel modifications.

### Implementation Details

- **Class**: `KernelModuleAnalyzer`
- **Main methods**:
  - `analyze()`: Entry point that runs all kernel module checks
  - `_check_loaded_modules()`: Analyzes currently loaded kernel modules
  - `_check_module_signatures()`: Verifies module signatures
  - `_check_hidden_modules()`: Detects hidden kernel modules
  - `_check_syscall_table()`: Examines system call table integrity
  - `_check_kernel_params()`: Reviews kernel parameters
  - `_check_dmesg()`: Analyzes kernel log messages
  - `establish_baseline()`: Creates a baseline of normal kernel state
  - `compare_baseline()`: Compares current kernel state with the baseline

### Configuration Options

```yaml
kernel_module:
  # Database path
  database_path: "/var/lib/sharpeye/kernel_module.db"
  
  # Baseline file
  baseline_file: "/var/lib/sharpeye/baselines/kernel.json"
  
  # Kernel checks
  check_loaded_modules: true
  check_signatures: true
  check_hidden_modules: true
  check_syscall_table: true
  check_kernel_params: true
  check_dmesg: true
  
  # Expected modules
  expected_modules:
    - "ext4"
    - "btrfs"
    - "xfs"
    - "zfs"
  
  # Suspicious module patterns
  suspicious_module_patterns:
    - "hidden"
    - "rootkit"
    - "hide"
    - "stealth"
```

### Integration Points

- Works with the Rootkit Detection module for comprehensive detection
- Feeds into the File Integrity module for kernel file validation
- Provides context to the System Resources module for kernel-level events
- Maintains baseline data for future comparison

## Libraries Module

### Overview

The Libraries module inspects dynamic libraries, detects library injection, and identifies library-based attacks such as LD_PRELOAD hooking and shared library hijacking.

### Implementation Details

- **Class**: `LibraryInspector`
- **Main methods**:
  - `analyze()`: Entry point that runs all library checks
  - `_check_loaded_libraries()`: Analyzes libraries loaded by processes
  - `_check_library_integrity()`: Verifies library file integrity
  - `_check_ld_preload()`: Detects LD_PRELOAD usage
  - `_check_library_paths()`: Examines library search paths
  - `_check_suspicious_libraries()`: Identifies suspicious libraries
  - `establish_baseline()`: Creates a baseline of normal library state
  - `compare_baseline()`: Compares current library state with the baseline

### Configuration Options

```yaml
library_inspection:
  # Database path
  database_path: "/var/lib/sharpeye/library_inspection.db"
  
  # Baseline file
  baseline_file: "/var/lib/sharpeye/baselines/libraries.json"
  
  # Library checks
  check_loaded_libraries: true
  check_integrity: true
  check_ld_preload: true
  check_library_paths: true
  check_suspicious: true
  
  # Critical libraries to monitor
  critical_libraries:
    - "libc.so.6"
    - "libssl.so"
    - "libcrypto.so"
    - "libpam.so"
  
  # Suspicious patterns
  suspicious_patterns:
    - "lib.*hook"
    - "lib.*inject"
    - "lib.*proxy"
```

### Integration Points

- Works with the File Integrity module for library file verification
- Feeds into the Processes module for library usage analysis
- Provides context to the Rootkit Detection module for library-based rootkits
- Maintains baseline data for future comparison

## Privileges Module

### Overview

The Privileges module detects privilege escalation vulnerabilities, monitors permission changes, and identifies exploitation attempts targeting elevated privileges.

### Implementation Details

- **Class**: `PrivilegeEscalationDetector`
- **Main methods**:
  - `analyze()`: Entry point that runs all privilege checks
  - `_check_suid_binaries()`: Analyzes SUID/SGID binaries
  - `_check_sudo_config()`: Examines sudo configuration
  - `_check_capabilities()`: Reviews process capabilities
  - `_check_container_escapes()`: Detects container escape vectors
  - `_check_vulnerable_services()`: Identifies vulnerable services
  - `_check_kernel_exploits()`: Checks for exploitable kernel versions
  - `establish_baseline()`: Creates a baseline of normal privilege state
  - `compare_baseline()`: Compares current privilege state with the baseline

### Configuration Options

```yaml
privilege_escalation:
  # Database path
  database_path: "/var/lib/sharpeye/privilege_escalation.db"
  
  # Baseline file
  baseline_file: "/var/lib/sharpeye/baselines/privileges.json"
  
  # Privilege checks
  check_suid: true
  check_sudo: true
  check_capabilities: true
  check_containers: true
  check_services: true
  check_kernel: true
  
  # Expected SUID binaries
  expected_suid:
    - "/usr/bin/sudo"
    - "/usr/bin/passwd"
    - "/usr/bin/su"
  
  # Expected capabilities
  expected_capabilities:
    - "CAP_NET_BIND_SERVICE:ping"
```

### Integration Points

- Works with the User Accounts module for privilege analysis
- Feeds into the Rootkit Detection module for elevated privilege detection
- Provides data to the Process module for process privilege context
- Maintains baseline data for future comparison

## Rootkit Detection Module

### Overview

The Rootkit Detection module provides comprehensive detection of rootkits, kernel-level threats, and advanced persistent threats using a variety of techniques.

### Implementation Details

- **Class**: `RootkitDetector`
- **Main methods**:
  - `analyze()`: Entry point that runs all rootkit detection checks
  - `_check_kernel_integrity()`: Verifies kernel memory integrity
  - `_check_hidden_processes()`: Detects processes hidden from ps
  - `_check_hidden_files()`: Finds files hidden from ls
  - `_check_hidden_ports()`: Identifies ports hidden from netstat
  - `_check_interrupt_handlers()`: Analyzes interrupt handler modifications
  - `_compare_interfaces()`: Cross-checks network interface data
  - `_check_lkm_rootkits()`: Detects loadable kernel module rootkits
  - `_check_memory_rootkits()`: Finds memory-resident rootkits
  - `establish_baseline()`: Creates a baseline of normal system state
  - `compare_baseline()`: Compares current state with the baseline

### Configuration Options

```yaml
rootkit_detector:
  # Database path
  database_path: "/var/lib/sharpeye/rootkit_detector.db"
  
  # Baseline file
  baseline_file: "/var/lib/sharpeye/baselines/rootkit.json"
  
  # Detection methods
  check_kernel_integrity: true
  check_hidden_processes: true
  check_hidden_files: true
  check_hidden_ports: true
  check_interrupt_handlers: true
  check_interfaces: true
  check_lkm_rootkits: true
  check_memory_rootkits: true
  
  # Detection options
  proc_comparison: true
  syscall_verification: true
  network_stack_verification: true
  
  # Memory scan options
  memory_scan_enabled: true
  memory_scan_depth: "comprehensive"  # basic, standard, comprehensive
```

### Integration Points

- Works with the Kernel Module module for comprehensive kernel protection
- Coordinates with the Process module for hidden process detection
- Interfaces with the Network module for hidden connection detection
- Maintains baseline data for future comparison

See [ROOTKIT_DETECTOR.md](./modules/ROOTKIT_DETECTOR.md) for detailed documentation.