# System Resources Analyzer Module

## Overview

The System Resources Analyzer module monitors CPU, memory, and disk resources to detect anomalies that may indicate security threats. It combines traditional threshold-based monitoring with machine learning to detect patterns of resource abuse that might indicate cryptominers, data exfiltration, denial-of-service attacks, or other malicious activities.

## Key Features

1. **Comprehensive Resource Monitoring**
   - CPU usage and load analysis
   - Memory and swap usage tracking
   - Disk space and I/O monitoring
   - Process resource usage analysis

2. **Machine Learning-based Pattern Detection**
   - Identifies unusual resource usage patterns
   - Detects sustained resource abuse
   - Recognizes cryptomining and other resource-intensive malware
   - Cross-resource correlation for sophisticated attack detection

3. **Process Analysis**
   - Identifies suspicious processes based on resource usage
   - Detects processes running from unusual locations
   - Identifies disguised process names
   - Monitors for processes with suspicious command patterns

4. **Disk Security Analysis**
   - Finds suspicious directories and files
   - Identifies unusual permission settings
   - Detects hidden files in sensitive locations
   - Monitors for unusually large files

5. **Baseline Comparison**
   - Establishes normal resource usage patterns
   - Detects deviations from established baselines
   - Identifies new anomalous processes
   - Monitors for significant changes in resource utilization

## Technical Details

### System Resource Analyzer

The core analyzer utilizes multiple detection methods:

1. **Threshold-based Analysis**: Monitors for resource usage exceeding configurable thresholds
2. **Machine Learning Detection**: Uses Isolation Forest algorithm for anomaly detection
3. **Behavioral Analysis**: Examines resource usage patterns and correlations
4. **Suspicious Process Detection**: Applies heuristics to identify suspicious processes

### Resource Pattern Analyzer

The ML component analyzes patterns in:

1. **CPU Patterns**: Stability, spikes, usage distribution, hidden processes
2. **Memory Patterns**: Usage growth, swap behavior, memory leaks, fragmentation
3. **Disk Patterns**: Space usage, growth rate, file creation, permission changes
4. **Cross-resource Correlations**: Relationships between different resource types

## Usage Examples

### Monitoring for Resource Anomalies

```python
# Initialize the analyzer
from modules.system_resources import SystemResourceAnalyzer

analyzer = SystemResourceAnalyzer({
    'cpu_threshold': 90,
    'memory_threshold': 85,
    'disk_threshold': 90
})

# Run the analysis
results = analyzer.analyze()

# Check for anomalies
if results['is_anomalous']:
    print("Resource anomalies detected!")
    
    if results['cpu'].get('is_anomalous'):
        print(f"CPU anomaly: {results['cpu'].get('total_cpu_usage')}% usage")
        
    if results['memory'].get('is_anomalous'):
        print(f"Memory anomaly: {results['memory'].get('memory_usage_percent')}% usage")
        
    if results['disk'].get('is_anomalous'):
        print("Disk anomalies detected in filesystems:")
        for fs in results['disk'].get('anomalous_filesystems', []):
            print(f"  - {fs['filesystem']} ({fs['use_percent']}%)")
```

### Establishing and Comparing with a Baseline

```python
# Establish a baseline during normal operation
analyzer.establish_baseline()

# Later, check for deviations from the baseline
deviations = analyzer.compare_baseline()

if deviations['has_deviations']:
    print("System state has deviated from the baseline:")
    
    for cpu_dev in deviations['cpu_deviations']:
        print(f"CPU: {cpu_dev}")
        
    for mem_dev in deviations['memory_deviations']:
        print(f"Memory: {mem_dev}")
        
    for disk_dev in deviations['disk_deviations']:
        print(f"Disk: {disk_dev}")
        
    if deviations['new_processes']:
        print("New anomalous processes detected:")
        for proc in deviations['new_processes']:
            print(f"  - {proc['command']} (PID: {proc['pid']})")
```

## Configuration Options

The module can be configured with the following options:

```yaml
system_resources:
  # CPU usage threshold in percent
  cpu_threshold: 90
  
  # Memory usage threshold in percent
  memory_threshold: 90
  
  # Disk usage threshold in percent
  disk_threshold: 90
  
  # Process monitoring settings
  processes:
    # Check processes running from unusual locations
    check_unusual_locations: true
    
    # Check processes with high resource usage
    check_high_resource_usage: true
    
    # Threshold for high CPU usage in percent
    high_cpu_threshold: 80
    
    # Threshold for high memory usage in percent
    high_memory_threshold: 50
    
    # List of paths considered suspicious when processes run from them
    suspicious_paths:
      - "/tmp"
      - "/dev/shm"
      - "/var/tmp"
      - "/run/user"
    
    # Suspicious command patterns to look for
    suspicious_commands:
      - "miner"
      - "xmr"
      - "crypto"
      - "kworker"
      - "./"
      - "/tmp/"
      - "curl"
      - "wget"
      - "nc "
      - "netcat"
      - "ncat"
      - "bash -i"
      - "perl -e"
      - "python -c"
      - "ruby -e"
  
  # Machine learning configuration
  ml_config:
    # Enable ML-based analysis
    enable: true
    
    # Directory to store ML models
    models_dir: "/var/lib/sharpeye/models"
    
    # Number of samples to keep in history
    history_length: 24
    
    # Anomaly detection threshold
    detection_threshold: 0.7
```

## Integration With Other Modules

The System Resources Analyzer integrates with several other SharpEye modules:

1. **Cryptominer Detection**: Provides resource usage data for mining detection
2. **Processes Analyzer**: Shares suspicious process information
3. **Network Analyzer**: Correlates with network activity for improved detection
4. **File Integrity**: Identifies suspicious files and file system changes

## Security Recommendations

1. **Baseline Creation**: Establish resource baselines during normal operation
2. **Regular Monitoring**: Schedule periodic system resource scans
3. **Alert Configuration**: Set up alerts for significant resource anomalies
4. **Custom Thresholds**: Adjust thresholds based on your system's normal operation
5. **Machine Learning Training**: Allow sufficient time for the ML models to learn normal patterns

## Common Issues and Solutions

1. **False Positives**: Adjust thresholds if legitimate high resource usage is causing alerts
2. **Memory Limitations**: Reduce the `history_length` if memory usage is a concern
3. **CPU Intensive**: Schedule ML-based analysis during off-peak hours if detection uses too many resources
4. **Missing Baseline**: Ensure a baseline is established before comparing against it

## Changelog

- **v1.0.0** (May 8, 2025): Initial release with basic threshold-based detection
- **v1.1.0** (May 8, 2025): Added machine learning-based pattern detection
- **v1.2.0** (May 8, 2025): Implemented process analysis and suspicious process detection
- **v1.3.0** (May 8, 2025): Added baseline creation and comparison functionality
- **v1.4.0** (May 8, 2025): Enhanced disk security monitoring capabilities
- **v2.0.0** (May 8, 2025): Complete rewrite with cross-resource correlation and advanced ML detection