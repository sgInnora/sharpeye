# SharpEye: Advanced Linux Intrusion Detection System

<div align="center">
<p>
    <img width="140" src="assets/logo.png" alt="SharpEye logo">
</p>
<p>
    <b>Advanced Linux Intrusion Detection and Threat Hunting System</b>
</p>
<p>
    <b>高级Linux入侵检测与威胁狩猎系统</b>
</p>
</div>

---

**English** | [中文](./README_CN.md)

## Overview

**SharpEye** is a comprehensive Linux intrusion detection and system security monitoring framework designed by innora.ai. It employs advanced analytics, machine learning, and behavior-based detection to identify and alert on suspicious activities, potential compromises, and security threats in real-time.

### Key Features

- **Advanced ML-Based Resource Analysis**: Detect anomalies in CPU, memory, and disk usage patterns using machine learning and time series analysis
- **User Account Security**: Identify unauthorized accounts, privilege escalations, and suspicious login patterns
- **Process Analysis**: Detect malicious and suspicious processes with behavioral analysis
- **Network Connection Monitoring**: Identify unusual network connections and data transfers
- **Threat Intelligence Integration**: Verify network connections against known malicious IP databases
- **ML-Based Cryptominer Detection**: Identify unauthorized cryptocurrency mining with machine learning
- **File System Integrity**: Verify system file integrity and detect unauthorized changes with robust checksum validation
- **Log Analysis Engine**: Correlate events across multiple log sources to detect sophisticated attack patterns
- **Scheduled Task Inspection**: Identify malicious cron jobs and scheduled tasks
- **SSH Security**: Monitor SSH configuration and detect unauthorized access attempts
- **Kernel Module Analysis**: Detect malicious kernel modules, rootkits, and syscall table hooking
- **Library Inspection**: Identify dynamic library hijacking attempts and detect malicious preloaded libraries
- **Privilege Escalation Detection**: Find and alert on potential privilege escalation vectors including SUID binaries, capabilities, and dangerous sudo configurations

## Installation

```bash
git clone https://github.com/sgInnora/sharpeye.git
cd sharpeye
sudo ./install.sh
```

## Basic Usage

```bash
# Run a full system scan
sudo sharpeye --full-scan

# Run a specific module
sudo sharpeye --module network

# Establish baseline for future comparison
sudo sharpeye --establish-baseline

# Compare against baseline
sudo sharpeye --compare-baseline
```

## Configuration

Configuration files are stored in `/etc/sharpeye/` after installation. Edit `config.yaml` to customize scan parameters and detection thresholds.

## Requirements

- Linux-based operating system (Debian, Ubuntu, CentOS, RHEL, etc.)
- Python 3.6+
- Root privileges for comprehensive scanning

## Current Status

As of May 2025, here is the current implementation status of SharpEye's core modules:

| Module | Status | Test Coverage |
|--------|--------|---------------|
| File System Integrity | ✅ Complete | 95% |
| Kernel Module Analysis | ✅ Complete | 94% |
| Library Inspection | ✅ Complete | 95% |
| Privilege Escalation Detection | ✅ Complete | 94% |
| Log Analysis Engine | ✅ Complete | 93% |
| Cryptominer Detection | ✅ Complete | 95% |
| System Resources | ✅ Complete | 100% |
| User Accounts | ✅ Complete | 100% |
| Processes | ✅ Complete | 100% |
| Network | ✅ Complete | 95% |
| Scheduled Tasks | ✅ Complete | 95% |
| SSH | ✅ Complete | 100% |
| Rootkit Detection | ✅ Complete | 100% |

The project is now fully implemented with all 13 modules completed and comprehensively tested. A fully functional CI/CD pipeline with GitHub Actions ensures code quality and test coverage for all modules. For detailed project status information, see [Project Status](docs/PROJECT_STATUS.md).

## Documentation

For more detailed information, see:
- [User Guide](docs/user_guide.md) | [用户指南](docs/user_guide_zh.md)
- [Module Reference](docs/module_reference.md) | [模块参考](docs/module_reference_zh.md)
- [Machine Learning Analysis](docs/machine_learning_analysis.md) | [机器学习分析](docs/machine_learning_analysis_zh.md)
- [Testing Guide](docs/testing.md) | [测试指南](docs/testing_zh.md)
- [Project Status](docs/PROJECT_STATUS.md) | [项目状态](docs/PROJECT_STATUS_ZH.md)
- [SQLite Threading Guide](docs/SQLITE_THREADING.md) | [SQLite线程指南](docs/SQLITE_THREADING_ZH.md)
- [CI/CD Status](docs/CI_CD_STATUS.md) | [CI/CD状态](docs/CI_CD_STATUS_ZH.md)
- [CI/CD Fix Guide](docs/CI_CD_FIX.md) | [CI/CD修复指南](docs/CI_CD_FIX_ZH.md)
- [Enhancement Summary](docs/ENHANCEMENT_SUMMARY.md) | [增强总结](docs/ENHANCEMENT_SUMMARY_ZH.md)

## Contributing

Contributions are welcome! Please see our [Contributing Guide](CONTRIBUTING.md) for more details.

## About innora.ai

innora.ai specializes in developing advanced security solutions for modern computing environments. Our team combines expertise in malware analysis, threat intelligence, and machine learning to create cutting-edge security tools that help organizations protect their critical infrastructure.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- The innora.ai research team
- All contributors and security researchers who have helped improve this project
- Open source security tools that have inspired this project