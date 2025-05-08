# Cryptominer Detection Module Documentation

This document provides detailed technical information about the Cryptominer Detection module in SharpEye, including implementation details, configuration options, and integration points.

## Table of Contents

1. [Overview](#overview)
2. [Implementation Details](#implementation-details)
3. [Configuration Options](#configuration-options)
4. [Detection Capabilities](#detection-capabilities)
5. [Integration Points](#integration-points)
6. [Machine Learning Aspects](#machine-learning-aspects)

## Overview

The Cryptominer Detection module (`cryptominer.py`) is designed to identify malicious cryptocurrency mining software running on Linux systems. It uses a combination of machine learning, CPU usage pattern analysis, and heuristic detection to identify processes that may be mining cryptocurrency without authorization.

Cryptominers exhibit distinctive resource utilization patterns - they typically use high CPU, maintain consistent usage patterns, and may contain specific keywords in their command names. This module implements sophisticated detection techniques for these behaviors.

## Implementation Details

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
  - `CPUProfiler`: Collects CPU usage patterns for processes
  - `MLModelManager`: Manages machine learning models for detection

## Configuration Options

```yaml
cryptominer:
  # Enable continuous background monitoring
  continuous_monitoring: false
  
  # Monitoring interval in seconds
  monitoring_interval: 60
  
  # Feature thresholds for heuristic detection
  thresholds:
    cpu_stability: 0.2      # Lower values indicate more stable (suspicious) CPU usage
    cpu_min: 50.0           # Minimum CPU usage to consider suspicious
    cpu_mean: 80.0          # Mean CPU usage to consider suspicious
    cpu_time_growth_rate: 0.5  # CPU time growth rate to consider suspicious
    cpu_autocorrelation: 0.7   # CPU usage autocorrelation to consider suspicious
    cpu_spectral_entropy: 1.5   # CPU usage spectral entropy to consider suspicious
  
  # Keywords associated with cryptomining software
  mining_keywords:
    - "miner"
    - "xmr"
    - "monero"
    - "eth"
    - "ethereum"
    - "btc"
    - "bitcoin"
    - "stratum"
    - "mining"
    - "hashrate"
    - "cryptonight"
    - "ethash"
    - "zcash"
    - "equihash"
    - "randomx"
    - "coin"
    - "nicehash"
    - "pool"
  
  # CPU profiler configuration
  profiler_config:
    # Sampling interval in seconds
    sampling_interval: 5
    
    # Number of samples to keep in history
    history_length: 12
  
  # Machine learning configuration
  ml_config:
    # Directory to store ML models
    models_dir: "/var/lib/sharpeye/models"
    
    # Whether to use ML detection if available
    use_ml: true
```

## Detection Capabilities

1. **CPU Usage Pattern Analysis**:
   - Analyzes CPU usage stability and consistency
   - Detects the sustained high CPU usage typical of miners
   - Identifies periodic patterns unique to mining algorithms
   - Measures CPU usage autocorrelation and spectral entropy

2. **Machine Learning-Based Detection**:
   - Uses ML models to identify cryptomining behavior
   - Features include CPU usage patterns, memory usage, and system load
   - Can detect previously unknown cryptominers based on behavior patterns
   - Operates even without a trained model using heuristic fallback

3. **Command and Process Analysis**:
   - Identifies mining-related keywords in process commands
   - Detects processes running from suspicious locations
   - Cross-references with known miner binary patterns

4. **Time-Series Behavior Monitoring**:
   - Tracks process resource usage over time
   - Identifies consistent growth patterns in CPU/memory usage
   - Detects periodic behavior characteristic of mining algorithms

5. **Anomaly Detection**:
   - Compares current processes against baseline
   - Flags new processes with cryptomining characteristics
   - Identifies changes in system load related to mining activity

## Integration Points

- Interfaces with the System Resources module for additional context
- Works with the Processes module to correlate with other suspicious behaviors
- Can operate in continuous background monitoring mode
- Maintains baseline data for future comparison

## Machine Learning Aspects

The module includes a machine learning framework for identifying cryptominers:

1. **Feature Engineering**:
   - CPU usage statistics (mean, standard deviation, min/max)
   - CPU stability metrics (variation over time)
   - CPU/memory relationship features
   - CPU growth rate and pattern features
   - Frequency-domain features (spectral entropy, autocorrelation)

2. **Model Management**:
   - Models can be trained offline with labeled data
   - Pre-trained models are loaded from the models directory
   - Graceful fallback to heuristic detection if no model is available
   - Models can be updated or replaced as detection techniques evolve

3. **Feature Extraction**:
   - Time-series processing of CPU usage patterns
   - Statistical feature computation from process behavior
   - Advanced features including spectral analysis and autocorrelation
   - Optimization for low overhead during runtime analysis

The machine learning component is designed to improve detection accuracy over time, especially for sophisticated miners that might evade simpler detection methods.