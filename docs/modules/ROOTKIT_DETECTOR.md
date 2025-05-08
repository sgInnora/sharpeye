# Rootkit Detector Module Documentation

## Overview

The Rootkit Detector module provides comprehensive detection capabilities for identifying advanced rootkits and kernel-level malware in Linux systems. Utilizing multiple detection techniques, it offers defense-in-depth against sophisticated threats that attempt to hide their presence from standard detection tools.

## Key Features

### 1. Kernel Module Analysis

- Detects unauthorized kernel modules
- Verifies module signatures and integrity
- Monitors kernel symbol table modifications
- Identifies suspicious kernel hooks
- Analyzes module load/unload behavior
- Detects hidden kernel modules

### 2. System Call Table Integrity

- Monitors system call table modifications
- Detects function pointer hijacking
- Verifies system call integrity
- Identifies inline hooks in system calls
- Detects VDSO/VSYSCALL tampering
- Monitors trampoline code injection

### 3. Memory Analysis

- Scans kernel memory for suspicious patterns
- Detects hidden kernel objects
- Identifies runtime code modifications
- Analyzes memory-mapped regions
- Detects return-oriented programming (ROP) patterns
- Identifies code injection in process memory

### 4. File System Integrity

- Detects discrepancies between file system layers
- Identifies hidden files and directories
- Monitors critical system file modifications
- Detects library preloading attempts
- Verifies file system handler integrity
- Identifies namespace isolation tricks

## Implementation Details

### Classes and Methods

- **Class**: `RootkitDetector`
- **Main methods**:
  - `analyze()`: Performs full rootkit analysis
  - `check_kernel_modules()`: Analyzes kernel modules
  - `verify_syscall_table()`: Checks system call table integrity
  - `scan_memory()`: Performs kernel memory analysis
  - `check_fs_integrity()`: Verifies file system integrity
  - `detect_hidden_resources()`: Finds hidden processes, files, etc.
  - `check_preload_hooks()`: Analyzes library preload hooks
  - `verify_proc_entries()`: Examines /proc entries for tampering
  - `report_findings()`: Generates detailed analysis report

### Technical Implementation

```python
def analyze(self):
    """Perform comprehensive rootkit detection analysis."""
    self.logger.info("Starting rootkit detection analysis...")
    
    # Run all detection engines
    kernel_findings = self._check_kernel_modules()
    syscall_findings = self._verify_syscall_table()
    memory_findings = self._scan_memory()
    fs_findings = self._check_fs_integrity()
    hidden_resources = self._detect_hidden_resources()
    preload_findings = self._check_preload_hooks()
    proc_findings = self._verify_proc_entries()
    
    # Analyze results and determine threat level
    threat_level = self._assess_threat_level(
        kernel_findings, syscall_findings, memory_findings,
        fs_findings, hidden_resources, preload_findings,
        proc_findings
    )
    
    # Compile comprehensive report
    report = {
        'threat_level': threat_level,
        'kernel_findings': kernel_findings,
        'syscall_findings': syscall_findings,
        'memory_findings': memory_findings,
        'fs_findings': fs_findings,
        'hidden_resources': hidden_resources,
        'preload_findings': preload_findings,
        'proc_findings': proc_findings,
        'timestamp': datetime.now().isoformat(),
        'detection_stats': self._get_detection_stats()
    }
    
    self.logger.info(f"Rootkit detection completed with threat level: {threat_level}")
    return report
```

## Configuration Options

```yaml
rootkit_detector:
  # Core detection engines
  check_kernel_modules: true
  check_syscall_table: true
  scan_kernel_memory: true
  check_fs_integrity: true
  detect_hidden_resources: true
  check_preload_hooks: true
  verify_proc: true
  
  # Advanced options
  use_kernel_debugger: false  # Requires additional permissions
  use_hardware_assistance: false  # If available
  memory_scan_level: 1  # 1-3, higher is more thorough but slower
  
  # Performance settings
  thorough_scan: false  # Enable for more comprehensive but slower scan
  scan_interval: 86400  # Daily, in seconds
  
  # Response options
  alert_level: high  # low, medium, high (threshold for alerts)
  auto_quarantine: false  # Automatically quarantine detected threats
  
  # Exclusions
  excluded_paths: ["/var/lib/docker"]
  trusted_modules: ["nvidia", "vbox"]
```

## Detection Capabilities

### 1. Kernel-Mode Rootkits

- **Direct Kernel Object Manipulation (DKOM)**
  - Detects manipulation of kernel data structures
  - Identifies process hiding via task struct unlinking
  - Detects network connection hiding in netstat structures

- **Kernel Hook Detection**
  - System call table hook identification
  - Virtual file system (VFS) hook detection
  - Interrupt descriptor table (IDT) modification checking
  - Netfilter hook analysis

- **Loadable Kernel Module (LKM) Rootkits**
  - Detection of unauthorized kernel modules
  - Module verification using signature checking
  - Hidden module detection through memory analysis
  - Identification of rootkit-specific module patterns

### 2. User-Mode Rootkits

- **Library Injection Techniques**
  - LD_PRELOAD abuse detection
  - Shared library hooking identification
  - Executable patching detection
  - Runtime code injection analysis

- **Process Manipulation**
  - Process hiding detection
  - PTRACE abuse identification
  - Process credential manipulation detection
  - Backdoored binary detection

### 3. Advanced Persistent Threats

- **Bootkit Detection**
  - Boot process integrity verification
  - Firmware implant detection capabilities
  - UEFI/BIOS modification checking
  - Boot sequence anomaly detection

- **Persistence Mechanisms**
  - Identifying hidden autostart mechanisms
  - Detection of modified init scripts
  - Systemd unit file tampering detection
  - Cron job analysis for suspicious entries

## Integration Points

- Integrates with Processes module for cross-validation of hidden processes
- Works with File System module to correlate file system findings
- Connects with Network module to verify connection hiding
- Provides data to the Logs module for event correlation
- Shares findings with SSH module for integrity checking
- Feeds into the centralized threat assessment engine

## Usage Examples

### Example 1: Basic Rootkit Scan

```python
from sharpeye.modules.rootkit_detector import RootkitDetector

# Initialize the detector
detector = RootkitDetector()

# Run a complete analysis
results = detector.analyze()

# Process findings
if results['threat_level'] > 0:
    print(f"Potential rootkit activity detected! Threat level: {results['threat_level']}")
    
    # Display specific findings
    if results['kernel_findings']:
        print("\nKernel issues:")
        for finding in results['kernel_findings']:
            print(f" - {finding['type']}: {finding['description']}")
            
    if results['hidden_resources']:
        print("\nHidden resources:")
        for resource in results['hidden_resources']:
            print(f" - {resource['type']}: {resource['name']} ({resource['details']})")
```

### Example 2: Scheduled Scanning

```python
from sharpeye.modules.rootkit_detector import RootkitDetector
import schedule
import time

def run_rootkit_scan():
    detector = RootkitDetector(config={'thorough_scan': True})
    results = detector.analyze()
    
    # Save results to file for later analysis
    with open('/var/log/sharpeye/rootkit_scan.json', 'w') as f:
        json.dump(results, f)
    
    # Alert on high threat level
    if results['threat_level'] >= 2:
        send_security_alert(results)

# Schedule daily scans
schedule.every().day.at("03:00").do(run_rootkit_scan)

while True:
    schedule.run_pending()
    time.sleep(60)
```

### Example 3: Custom Detection Focus

```python
from sharpeye.modules.rootkit_detector import RootkitDetector

# Configure a specialized detector focused on kernel memory analysis
config = {
    'check_kernel_modules': True,
    'check_syscall_table': True,
    'scan_kernel_memory': True,
    'check_fs_integrity': False,  # Disable for performance
    'detect_hidden_resources': False,  # Disable for performance
    'memory_scan_level': 3,  # Maximum thoroughness
    'use_kernel_debugger': True  # Enable advanced detection
}

# Initialize the specialized detector
detector = RootkitDetector(config=config)

# Run the focused analysis
kernel_results = detector.analyze()
print(f"Kernel analysis complete. Threat level: {kernel_results['threat_level']}")
```

## Troubleshooting

### Common Issues

1. **High CPU Usage**
   - Reduce the memory scan level
   - Disable the thorough scan option
   - Increase the scan interval
   - Limit scan to specific detection engines

2. **False Positives**
   - Add legitimate modules to the trusted_modules list
   - Add expected paths to the excluded_paths list
   - Adjust the alert_level threshold
   - Update the detection signatures

3. **Permission Issues**
   - Ensure the tool is running with root privileges
   - Check kernel module permissions
   - Verify access to /dev/kmem (if used)
   - Confirm debugfs is mounted correctly

## Best Practices

1. **Regular Scans**
   - Schedule thorough scans during off-hours
   - Conduct quick scans after system changes
   - Maintain baseline scan results for comparison
   - Verify after kernel updates

2. **Incident Response**
   - Isolate affected systems immediately
   - Preserve memory and disk images for forensics
   - Use multiple tools to confirm findings
   - Document all observed behaviors

3. **Prevention Measures**
   - Use secure boot mechanisms
   - Maintain regular security patches
   - Implement kernel module signing
   - Monitor file integrity with separate tools
   - Use host-based IDS/IPS systems

4. **Advanced Detection Setup**
   - Configure hardware-assisted virtualization for safer analysis
   - Use kernel parameters to enhance security (e.g., lockdown mode)
   - Implement out-of-band monitoring
   - Consider network-level detection for covert channels

For more detailed information and advanced usage, refer to the complete [Rootkit Detector API Documentation](../api/rootkit_detector_api.md).