# SharpEye User Guide | SharpEye用户指南

[English](#table-of-contents) | [中文](#目录)

## Table of Contents

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Basic Usage](#basic-usage)
4. [Detection Modules](#detection-modules)
5. [Baseline Management](#baseline-management)
6. [Configuration](#configuration)
7. [Report Formats](#report-formats)
8. [Troubleshooting](#troubleshooting)
9. [Command Reference](#command-reference)

## Introduction

SharpEye is a comprehensive Linux intrusion detection system designed to help system administrators identify security breaches, anomalies, and potential threats. It performs automated scans of various system components and provides detailed reports about potential security issues.

SharpEye operates on the principle of detecting anomalies in system behavior, comparing against established baselines, and identifying known suspicious patterns. By regularly running SharpEye scans, you can detect intrusions early and respond appropriately.

## Installation

### Prerequisites

- Linux-based operating system (Debian, Ubuntu, CentOS, RHEL, etc.)
- Python 3.6+
- Root privileges for comprehensive scanning

### Installation Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/SharpEye.git
   cd SharpEye
   ```

2. Run the installation script:
   ```bash
   sudo ./install.sh
   ```

The installation script will:
- Install required dependencies
- Create configuration directories
- Set up default configuration
- Install SharpEye as a system command
- Set up a systemd service or cron job for regular scans (optional)

## Basic Usage

After installation, you can run SharpEye with the following commands:

### Run a Full System Scan

```bash
sudo sharpeye --full-scan
```

This will run all detection modules and generate a comprehensive report.

### Run a Specific Module

```bash
sudo sharpeye --module <module_name>
```

Replace `<module_name>` with one of the following: `system`, `users`, `processes`, `network`, `filesystem`, `logs`, `scheduled`, `ssh`, `kernel`, `libraries`, `privileges`, `rootkit`.

### Establish Baseline

Before regular scans, it's recommended to establish a baseline of normal system behavior:

```bash
sudo sharpeye --establish-baseline
```

This captures the current state of your system as a baseline for future comparisons.

### Compare Against Baseline

```bash
sudo sharpeye --compare-baseline
```

This compares the current system state against the previously established baseline and reports differences.

### Specify Output Format

```bash
sudo sharpeye --format <format>
```

Replace `<format>` with one of: `text`, `json`, `html`, `pdf`.

## Detection Modules

SharpEye includes several detection modules, each focusing on a specific aspect of the system:

### System Resources

The System Resources module monitors CPU, memory, and disk usage to detect anomalies that may indicate malicious activity.

**What it checks for:**
- Unusually high CPU or memory usage
- Processes consuming excessive resources
- Suspicious processes
- Unexpected disk space usage
- Large files in unusual locations

**Common anomalies detected:**
- Cryptominers (high CPU)
- Memory leaks or resource exhaustion attacks
- Malware or backdoors running as processes
- Data exfiltration (large unexpected files)

**Command:**
```bash
sudo sharpeye --module system
```

### User Accounts

The User Accounts module checks for suspicious user accounts, unauthorized privilege escalation, and more.

**What it checks for:**
- Unauthorized root accounts (UID 0)
- Users with unexpected shells
- Users with sudo privileges
- Suspicious account modifications
- Unusual login patterns

**Common anomalies detected:**
- Backdoor accounts
- Privilege escalation
- Unauthorized sudo access
- Recently modified accounts
- Brute force login attempts

**Command:**
```bash
sudo sharpeye --module users
```

### Processes

The Processes module analyzes running processes to detect malicious activities.

**What it checks for:**
- Hidden processes
- Processes running from suspicious locations
- Unusual parent-child process relationships
- Suspicious file handles
- Unusual network connections

**Common anomalies detected:**
- Rootkits hiding processes
- Malware running from /tmp or other unusual locations
- Webshells (web server spawning shells)
- Backdoors maintaining persistence
- Data exfiltration processes

**Command:**
```bash
sudo sharpeye --module processes
```

### Network Connections

The Network Connections module examines network activity to identify unauthorized connections and potential data exfiltration.

**What it checks for:**
- Unusual listening ports
- Suspicious outbound connections
- Remote access services
- Suspicious DNS queries
- Connections to high-risk countries

**Common anomalies detected:**
- Backdoor listeners
- Command & Control (C2) connections
- Data exfiltration
- DNS tunneling
- Reverse shells

**Command:**
```bash
sudo sharpeye --module network
```

### Other Modules

SharpEye includes several other modules for comprehensive system scanning. See the [Module Reference](module_reference.md) for detailed information about all available modules.

## Baseline Management

Establishing and maintaining baselines is crucial for effective anomaly detection.

### When to Establish a Baseline

Establish a baseline:
- After a clean install
- After applying significant system updates
- After intentionally making major configuration changes
- When deploying to a new environment

### Updating Baselines

You should update your baseline when you make legitimate changes to your system that would otherwise be flagged as anomalies.

```bash
sudo sharpeye --establish-baseline
```

### Baseline Expiration

By default, baselines expire after 30 days. You can modify this in the configuration file.

## Configuration

SharpEye can be configured by editing the files in `/etc/sharpeye/`:

- `config.yaml`: Main configuration file
- `local_config.yaml`: Local overrides for specific settings

### Important Configuration Options

#### General Settings

```yaml
general:
  output_dir: "/var/lib/sharpeye/reports"
  log_level: "info"
  report_format: "text"
  email:
    enabled: false
    # ... email settings ...
```

#### Threshold Settings

You can adjust thresholds for various detections:

```yaml
system_resources:
  cpu_threshold: 90
  memory_threshold: 90
  disk_threshold: 90
```

#### Exclusions

You can configure exclusions to reduce false positives:

```yaml
filesystem:
  exclude_paths:
    - "/proc"
    - "/sys"
    - "/dev"
    - "/run"
```

## Report Formats

SharpEye supports multiple report formats:

### Text Format

Plain text reports are easy to read and parse with standard Unix tools.

```bash
sudo sharpeye --format text
```

### JSON Format

JSON reports are ideal for programmatic processing and integration with other tools.

```bash
sudo sharpeye --format json
```

### HTML Format

HTML reports provide rich visual presentation with color-coded alerts.

```bash
sudo sharpeye --format html
```

### PDF Format

PDF reports are suitable for documentation and sharing with non-technical stakeholders.

```bash
sudo sharpeye --format pdf
```

## Troubleshooting

### Common Issues

#### Permission Denied Errors

SharpEye requires root privileges for most of its functionality:

```bash
sudo sharpeye --full-scan
```

#### Missing Dependencies

If you encounter errors about missing dependencies:

```bash
sudo ./install.sh --reinstall-deps
```

#### High False Positive Rate

If you're seeing too many false positives:
1. Establish a new baseline
2. Adjust thresholds in the configuration
3. Add exclusions for specific paths or processes

#### Performance Issues

If SharpEye is running too slowly:
1. Run specific modules instead of full scans
2. Increase scan intervals
3. Adjust filesystem scan paths to exclude large directories

## Command Reference

```
Usage: sharpeye [options]

Options:
  --config PATH            Path to configuration file
  --log-level LEVEL        Set logging level (debug, info, warning, error, critical)
  --output-dir DIR         Directory to store reports
  --full-scan              Run all detection modules
  --module NAME            Run a specific detection module
  --establish-baseline     Establish baseline for future comparison
  --compare-baseline       Compare against previously established baseline
  --format FORMAT          Report output format (text, json, html, pdf)
  --email ADDRESS          Email address to send reports to
  --help                   Show this help message and exit
```

For detailed information about a specific module:

```bash
sudo sharpeye --help-module <module_name>
```

---

# 目录

1. [简介](#简介)
2. [安装](#安装)
3. [基本用法](#基本用法)
4. [检测模块](#检测模块)
5. [基线管理](#基线管理)
6. [配置](#配置)
7. [报告格式](#报告格式)
8. [故障排除](#故障排除)
9. [命令参考](#命令参考)

## 简介

SharpEye是一个全面的Linux入侵检测系统，旨在帮助系统管理员识别安全漏洞、异常情况和潜在威胁。它对各种系统组件进行自动扫描，并提供有关潜在安全问题的详细报告。

SharpEye基于检测系统行为异常、与已建立的基线进行比较以及识别已知可疑模式的原则运行。通过定期运行SharpEye扫描，您可以及早发现入侵并做出适当的响应。

## 安装

### 前提条件

- 基于Linux的操作系统（Debian、Ubuntu、CentOS、RHEL等）
- Python 3.6+
- 需要root权限进行全面扫描

### 安装步骤

1. 克隆仓库：
   ```bash
   git clone https://github.com/yourusername/SharpEye.git
   cd SharpEye
   ```

2. 运行安装脚本：
   ```bash
   sudo ./install.sh
   ```

安装脚本将：
- 安装所需的依赖
- 创建配置目录
- 设置默认配置
- 将SharpEye安装为系统命令
- 设置systemd服务或cron作业以进行定期扫描（可选）

## 基本用法

安装后，您可以使用以下命令运行SharpEye：

### 运行完整系统扫描

```bash
sudo sharpeye --full-scan
```

这将运行所有检测模块并生成全面的报告。

### 运行特定模块

```bash
sudo sharpeye --module <module_name>
```

将`<module_name>`替换为以下之一：`system`、`users`、`processes`、`network`、`filesystem`、`logs`、`scheduled`、`ssh`、`kernel`、`libraries`、`privileges`、`rootkit`。

### 建立基线

在定期扫描之前，建议建立正常系统行为的基线：

```bash
sudo sharpeye --establish-baseline
```

这会捕获系统的当前状态作为未来比较的基线。

### 与基线进行比较

```bash
sudo sharpeye --compare-baseline
```

这将当前系统状态与先前建立的基线进行比较并报告差异。

### 指定输出格式

```bash
sudo sharpeye --format <format>
```

将`<format>`替换为以下之一：`text`、`json`、`html`、`pdf`。

## 检测模块

SharpEye包含多个检测模块，每个模块都关注系统的特定方面：

### 系统资源

系统资源模块监控CPU、内存和磁盘使用情况，以检测可能表明恶意活动的异常。

**检查内容：**
- 异常高的CPU或内存使用率
- 消耗过多资源的进程
- 可疑进程
- 意外的磁盘空间使用
- 不寻常位置的大文件

**常见检测到的异常：**
- 加密货币挖矿程序（高CPU使用）
- 内存泄漏或资源耗尽攻击
- 作为进程运行的恶意软件或后门
- 数据外泄（大型意外文件）

**命令：**
```bash
sudo sharpeye --module system
```

### 用户账户

用户账户模块检查可疑用户账户、未授权权限提升等。

**检查内容：**
- 未授权的root账户（UID 0）
- 具有意外shell的用户
- 具有sudo权限的用户
- 可疑的账户修改
- 异常的登录模式

**常见检测到的异常：**
- 后门账户
- 权限提升
- 未授权的sudo访问
- 最近修改的账户
- 暴力登录尝试

**命令：**
```bash
sudo sharpeye --module users
```

### 进程

进程模块分析运行中的进程以检测恶意活动。

**检查内容：**
- 隐藏进程
- 从可疑位置运行的进程
- 异常的父子进程关系
- 可疑的文件句柄
- 异常的网络连接

**常见检测到的异常：**
- 隐藏进程的rootkit
- 从/tmp或其他不寻常位置运行的恶意软件
- Webshell（Web服务器派生shell）
- 维持持久性的后门
- 数据外泄进程

**命令：**
```bash
sudo sharpeye --module processes
```

### 网络连接

网络连接模块检查网络活动，以识别未授权的连接和潜在的数据外泄。

**检查内容：**
- 异常的监听端口
- 可疑的出站连接
- 远程访问服务
- 可疑的DNS查询
- 与高风险国家的连接

**常见检测到的异常：**
- 后门监听器
- 命令与控制（C2）连接
- 数据外泄
- DNS隧道
- 反向shell

**命令：**
```bash
sudo sharpeye --module network
```

### 其他模块

SharpEye包含几个其他模块，用于全面的系统扫描。有关所有可用模块的详细信息，请参阅[模块参考](module_reference.md)。

## 基线管理

建立和维护基线对于有效的异常检测至关重要。

### 何时建立基线

在以下情况下建立基线：
- 在干净安装后
- 应用重要系统更新后
- 有意进行重大配置更改后
- 部署到新环境时

### 更新基线

当您对系统进行合法更改时，应更新您的基线，否则这些更改可能会被标记为异常。

```bash
sudo sharpeye --establish-baseline
```

### 基线过期

默认情况下，基线30天后过期。您可以在配置文件中修改此设置。

## 配置

可以通过编辑`/etc/sharpeye/`中的文件来配置SharpEye：

- `config.yaml`：主配置文件
- `local_config.yaml`：特定设置的本地覆盖

### 重要配置选项

#### 常规设置

```yaml
general:
  output_dir: "/var/lib/sharpeye/reports"
  log_level: "info"
  report_format: "text"
  email:
    enabled: false
    # ... 邮件设置 ...
```

#### 阈值设置

您可以调整各种检测的阈值：

```yaml
system_resources:
  cpu_threshold: 90
  memory_threshold: 90
  disk_threshold: 90
```

#### 排除项

您可以配置排除项以减少误报：

```yaml
filesystem:
  exclude_paths:
    - "/proc"
    - "/sys"
    - "/dev"
    - "/run"
```

## 报告格式

SharpEye支持多种报告格式：

### 文本格式

纯文本报告易于阅读，并可用标准Unix工具解析。

```bash
sudo sharpeye --format text
```

### JSON格式

JSON报告非常适合程序化处理和与其他工具集成。

```bash
sudo sharpeye --format json
```

### HTML格式

HTML报告提供丰富的视觉表现，带有颜色编码的警报。

```bash
sudo sharpeye --format html
```

### PDF格式

PDF报告适合文档记录和与非技术利益相关者共享。

```bash
sudo sharpeye --format pdf
```

## 故障排除

### 常见问题

#### 权限拒绝错误

SharpEye的大多数功能需要root权限：

```bash
sudo sharpeye --full-scan
```

#### 缺少依赖

如果您遇到有关缺少依赖的错误：

```bash
sudo ./install.sh --reinstall-deps
```

#### 高误报率

如果您看到太多误报：
1. 建立新的基线
2. 调整配置中的阈值
3. 为特定路径或进程添加排除项

#### 性能问题

如果SharpEye运行太慢：
1. 运行特定模块而不是完整扫描
2. 增加扫描间隔
3. 调整文件系统扫描路径以排除大型目录

## 命令参考

```
用法: sharpeye [选项]

选项:
  --config PATH            配置文件路径
  --log-level LEVEL        设置日志级别(debug, info, warning, error, critical)
  --output-dir DIR         存储报告的目录
  --full-scan              运行所有检测模块
  --module NAME            运行特定检测模块
  --establish-baseline     建立用于将来比较的基线
  --compare-baseline       与先前建立的基线进行比较
  --format FORMAT          报告输出格式(text, json, html, pdf)
  --email ADDRESS          发送报告的电子邮件地址
  --help                   显示此帮助消息并退出
```

有关特定模块的详细信息：

```bash
sudo sharpeye --help-module <module_name>
```