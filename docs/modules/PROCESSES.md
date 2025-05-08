# Processes Module Documentation

## Overview

The Processes Module analyzes running processes to detect malicious activities, hidden processes, and unusual behavior that might indicate a security breach. It employs advanced process relationship mapping to identify lateral movement and malicious process chains, providing deep visibility into system activity.

## Key Features

### 1. Process Analysis and Monitoring
- Comprehensive analysis of running processes
- Detection of hidden processes not visible through standard tools
- Resource usage monitoring for anomalous patterns
- Command-line argument analysis for suspicious patterns
- Process attribute verification for tampering signs

### 2. Process Relationship Mapping
- Parent-child relationship mapping
- Process chain analysis
- Lateral movement detection
- Visual process tree generation
- Time-based analysis of process spawning patterns

### 3. File and Network Correlation
- Correlation of process activity with file operations
- Network connection analysis linked to processes
- Detection of processes accessing sensitive files
- Identification of unusual socket operations
- Analysis of shared resources between processes

### 4. Advanced Detection Techniques
- Syscall hooking detection
- Memory-resident malware detection
- Known malicious signature detection
- Statistical anomaly detection
- Behavioral analysis of process activities

### 5. Baseline Comparison
- Establishment of process baseline for normal system operation
- Comparison against baseline for newly detected anomalies
- Tracking of process lifecycle changes
- Detection of deviation from expected process behaviors
- Historical analysis of process evolution

## Technical Details

### Process Analyzer

The core analyzer utilizes multiple detection methods:

1. **Standard Process Analysis**: Collects and analyzes information about running processes using multiple sources
2. **Hidden Process Detection**: Compares process listings from multiple sources to identify hidden processes
3. **Relationship Analysis**: Maps parent-child relationships to identify unusual process chains
4. **Behavioral Analysis**: Monitors process behavior over time to detect anomalies
5. **File and Network Integration**: Correlates process activity with file and network operations

### Process Relationship Mapper

The relationship mapper component:

1. **Builds a Process Graph**: Creates a directed graph of process relationships
2. **Identifies Critical Paths**: Analyzes process chains for suspicious patterns
3. **Detects Lateral Movement**: Identifies processes that may indicate lateral movement
4. **Generates Visualizations**: Creates visual representations of process relationships
5. **Performs Time-series Analysis**: Examines process spawning patterns over time

## Configuration Options

```yaml
processes:
  # Basic detection options
  enable_hidden_process_detection: true
  enable_relationship_mapping: true
  enable_behavior_monitoring: true
  
  # Process monitoring settings
  max_processes_to_analyze: 500
  scan_interval_seconds: 60
  
  # Hidden process detection options
  detection_methods:
    pid_directory: true
    proc_maps: true
    proc_net: true
    syscall: true
    
  # Process relationship options
  relationship:
    max_depth: 10
    generate_graph: true
    detect_cycles: true
    
  # Behavioral monitoring options
  behavior:
    resource_threshold: 80
    fd_threshold: 100
    track_history: true
    
  # Exclusion patterns
  exclude_processes:
    - "^systemd$"
    - "^kthreadd$"
    - "^\\[.*\\]$"
    
  # Suspicious patterns
  suspicious_patterns:
    - "\\.\\./\\.\\."
    - "/tmp/.*/\\w{16}"
    - "sh -c .* > /dev/null"
```

## Usage Examples

### Basic Process Analysis

```python
from modules.processes import ProcessAnalyzer

# Initialize the analyzer
analyzer = ProcessAnalyzer()

# Perform basic analysis
results = analyzer.analyze()

# Check for suspicious processes
if results['suspicious_processes']:
    print(f"Found {len(results['suspicious_processes'])} suspicious processes:")
    for proc in results['suspicious_processes']:
        print(f"  - PID {proc['pid']}: {proc['command']}")
        print(f"    Reason: {proc['reason']}")
```

### Process Relationship Mapping

```python
from modules.processes import ProcessRelationshipMapper

# Initialize the mapper
mapper = ProcessRelationshipMapper()

# Generate process relationship map
relationship_map = mapper.generate_map()

# Identify suspicious relationships
suspicious = mapper.identify_suspicious_relationships(relationship_map)

# Generate visualization
graph_data = mapper.generate_visualization(relationship_map, highlight_suspicious=True)

# Save the graph image
with open('process_map.png', 'wb') as f:
    f.write(graph_data)
```

### Setting Up a Baseline

```python
from modules.processes import ProcessAnalyzer

analyzer = ProcessAnalyzer()

# Establish a baseline during normal operation
analyzer.establish_baseline()

# Later, compare current state against baseline
deviations = analyzer.compare_baseline()

if deviations['new_processes']:
    print("New processes detected since baseline:")
    for proc in deviations['new_processes']:
        print(f"  - {proc['command']} (PID: {proc['pid']})")
```

## Integration With Other Modules

The Processes Module integrates with several other SharpEye modules:

1. **File Integrity**: Processes that access monitored files are correlated with file integrity changes
2. **Network Analysis**: Process network activity is linked with network monitoring
3. **System Resources**: Resource usage by processes is correlated with system resource analysis
4. **Rootkit Detection**: Findings contribute to rootkit detection capabilities

## Security Recommendations

1. **Process Monitoring**: Regularly monitor running processes and establish baselines
2. **Suspicious Patterns**: Watch for processes with unusual names, paths, or arguments
3. **Process Relationships**: Be aware of unexpected parent-child relationships
4. **Resource Usage**: Monitor processes consuming excessive resources
5. **Command Line Analysis**: Regularly review process command lines for suspicious patterns

## Common Issues and Solutions

1. **High CPU Usage**: Adjust `max_processes_to_analyze` and `scan_interval_seconds` to reduce resource impact
2. **False Positives**: Add legitimate processes to `exclude_processes` list
3. **Incomplete Relationship Maps**: Increase `relationship.max_depth` for more complete analysis
4. **Missing Processes**: Enable additional `detection_methods` for comprehensive process discovery

## Changelog

- **v1.0.0 (May 8, 2025)**: Initial release with basic process analysis
- **v1.1.0 (May 8, 2025)**: Added relationship mapping
- **v1.2.0 (May 8, 2025)**: Integrated with file and network correlation
- **v1.3.0 (May 8, 2025)**: Added baseline comparison functionality
- **v2.0.0 (May 8, 2025)**: Complete implementation with process visualization and advanced detection