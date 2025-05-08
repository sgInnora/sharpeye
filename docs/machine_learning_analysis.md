# Machine Learning Analysis in SharpEye

SharpEye now incorporates machine learning techniques to enhance its anomaly detection capabilities. This document provides an overview of the ML-based analysis features, focusing on system resource monitoring.

## System Resource Pattern Analysis

The system resource module (`SystemResourceAnalyzer`) has been enhanced with machine learning capabilities for detecting anomalous resource usage patterns that might indicate compromise or security threats.

### Overview

Traditional threshold-based anomaly detection is useful but has limitations:
- Fixed thresholds may miss subtle anomalies
- Cannot detect correlations between different resources
- Unable to recognize patterns that develop over time
- Cannot learn from system's normal behavior

The machine learning enhancement addresses these limitations by:
- Analyzing resource usage patterns over time
- Detecting anomalies based on deviations from expected behavior
- Identifying correlations between different resource types
- Recognizing suspicious trends and patterns that evolve gradually

### Implemented Techniques

The `ResourcePatternAnalyzer` class implements several machine learning and statistical analysis approaches:

1. **Unsupervised Anomaly Detection** - Using Isolation Forest algorithm to identify anomalous resource usage patterns
2. **Time Series Analysis** - Tracking resource metrics over time to detect unusual changes
3. **Correlation Analysis** - Detecting suspicious correlations between different resource types
4. **Trend Analysis** - Identifying concerning trends using linear regression

### Key Features

#### 1. Historical Data Analysis

The analyzer maintains a history of resource metrics, allowing it to establish a baseline of normal behavior:
- Configurable history length (default: 24 data points)
- Automatic feature extraction from CPU, memory, and disk data
- Rolling window analysis for continuous monitoring

#### 2. Machine Learning Models

Three separate ML models are used to detect anomalies in different resource types:
- CPU usage pattern anomaly detection
- Memory usage pattern anomaly detection
- Disk usage pattern anomaly detection

The models are implemented using scikit-learn's Isolation Forest algorithm, which:
- Does not require labeled training data
- Works well with high-dimensional data
- Is efficient for real-time anomaly detection
- Can detect outliers in the feature space

#### 3. Cross-Resource Correlation Analysis

Beyond individual resource anomalies, the analyzer detects suspicious correlations between resources:
- CPU and memory usage patterns
- Disk I/O and CPU patterns
- System and user CPU time ratios
- Unusual resource convergence patterns

Common attack patterns detected include:
- High disk I/O without corresponding CPU usage (potential data exfiltration)
- Perfectly correlated resource usage (potential coordinated attack)
- High CPU with decreasing available memory (resource exhaustion attack)

#### 4. Statistical Pattern Detection

Even without trained models, the analyzer uses statistical methods to identify suspicious patterns:
- Sudden resource usage spikes
- Sustained high load
- Unusual system-to-user CPU ratio
- Memory fragmentation increases
- Suspicious process behavior

#### 5. Self-Training Capability

The analyzer can train its own models based on observed system behavior:
- Automatically trains models after collecting sufficient history
- Adapts to the specific system's baseline behavior
- No need for pre-labeled training data

### Implementation Details

#### Feature Extraction

For effective ML analysis, raw resource data is transformed into feature vectors:

**CPU Features:**
- Total CPU usage percentage
- Count of high-CPU processes
- Count of anomalous processes
- Count of hidden processes
- System load average
- I/O wait percentage
- System CPU percentage
- User CPU percentage

**Memory Features:**
- Memory usage percentage
- Swap usage percentage
- Count of high-memory processes
- Count of anomalous processes
- Cached-to-free memory ratio
- Anonymous pages count
- Slab memory usage
- Memory fragmentation index

**Disk Features:**
- Average filesystem usage percentage
- Count of anomalous filesystems
- Count of suspicious directories
- Count of hidden files
- Count of large files
- Suspicious growth indicator
- Count of permission issues
- Count of modified configuration files

#### Analysis Workflow

The machine learning analysis follows this workflow:

1. During system initialization, ML models are loaded if available
2. With each resource analysis, metrics are extracted and added to history
3. If sufficient history exists (≥3 samples), pattern analysis is performed
4. Anomalies are detected using both ML and statistical methods
5. After collecting sufficient samples (≥10), models are trained if not already available

#### Integration with Traditional Analysis

ML-based analysis complements, rather than replaces, traditional threshold-based detection:
- Traditional analysis catches immediate, obvious anomalies
- ML analysis catches subtle, evolving, or correlated anomalies
- Results from both approaches are combined in the final report

### Configuration

The ML-based analysis can be configured in the SharpEye configuration file:

```yaml
system_resources:
  # Traditional thresholds
  cpu_threshold: 90
  memory_threshold: 90
  disk_threshold: 90
  
  # ML configuration
  ml_config:
    enable: true               # Enable/disable ML analysis
    history_length: 24         # Number of samples to keep in history
    detection_threshold: 0.7   # Anomaly detection threshold (0-1)
    models_dir: /var/lib/sharpeye/models  # Directory for saving/loading models
```

### Sample Output

When ML-based anomalies are detected, they are included in the analysis results:

```json
{
  "cpu": {
    "is_anomalous": true,
    "ml_detected_anomalies": [
      {
        "type": "ml_detected",
        "description": "Machine learning model detected CPU usage anomaly",
        "score": -0.42,
        "severity": "high"
      },
      {
        "type": "io_wait_spike",
        "description": "Unusual I/O wait time spike: 35.2% (avg: 5.8%)",
        "severity": "high"
      }
    ]
  },
  "correlation_anomalies": [
    {
      "type": "disk_io_anomaly",
      "description": "High disk I/O without corresponding CPU usage (possible data exfiltration)",
      "severity": "critical"
    }
  ],
  "resource_trends": {
    "cpu_trend": "rapidly_increasing",
    "memory_trend": "stable",
    "disk_trend": "increasing",
    "cpu_slope": 25.3,
    "memory_slope": 3.2,
    "disk_slope": 8.7,
    "is_anomalous": true
  }
}
```

### Future Enhancements

Planned future enhancements to the ML-based analysis include:

1. **Supervised Learning Models** - Adding the ability to train models based on known attack patterns
2. **Deep Learning Integration** - Incorporating LSTM networks for sequence-based anomaly detection
3. **Multi-system Analysis** - Correlating patterns across multiple systems
4. **Automated Response** - Suggesting mitigation actions based on detected patterns
5. **User Feedback Loop** - Incorporating user feedback on false positives/negatives

## Using ML Analysis in Other Modules

The machine learning approach implemented in the system resources module provides a framework that can be extended to other SharpEye modules:

- **User Account Module** - Detect anomalous login patterns and user behavior
- **Network Module** - Identify unusual network traffic patterns
- **Process Module** - Detect anomalous process behavior and relationships
- **SSH Module** - Recognize suspicious SSH access patterns
- **Rootkit Detection** - Enhance detection of sophisticated rootkits

Implementing ML analysis in these modules will follow a similar pattern:
1. Collect relevant metrics over time
2. Extract features that capture important characteristics
3. Apply unsupervised learning for anomaly detection
4. Correlate findings across different data sources

## Requirements

The machine learning capabilities require the following Python packages:
- numpy
- scikit-learn

These dependencies are included in the SharpEye requirements.txt file.