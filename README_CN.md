# SharpEye: 高级Linux入侵检测系统

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

[English](./README.md) | **中文**

## 项目概述

**SharpEye** 是由innora.ai设计的全面Linux入侵检测和系统安全监控框架。它采用先进的分析技术、机器学习和基于行为的检测方法，实时识别和警报可疑活动、潜在入侵和安全威胁。

### 功能特点

- **系统资源监控**：检测CPU、内存和磁盘使用模式中的异常
- **用户账户安全**：识别未授权账户、权限提升和可疑登录模式
- **进程分析**：通过行为分析检测恶意和可疑进程
- **网络连接监控**：识别异常网络连接和数据传输
- **威胁情报集成**：验证网络连接是否存在于已知恶意IP数据库中
- **基于机器学习的加密货币挖矿检测**：使用机器学习识别未授权的加密货币挖矿活动
- **文件系统完整性**：验证系统文件完整性并检测未授权更改
- **日志分析引擎**：监控和分析系统日志中的可疑活动
- **计划任务检查**：识别恶意的cron任务和计划任务
- **SSH安全性**：监控SSH配置并检测未授权访问尝试
- **内核模块分析**：检测恶意内核模块和rootkit
- **库检查**：识别动态库劫持尝试
- **权限提升检测**：发现并警报潜在的权限提升向量

## 安装

```bash
git clone https://github.com/sgInnora/sharpeye.git
cd sharpeye
sudo ./install.sh
```

## 基本用法

```bash
# 运行完整系统扫描
sudo sharpeye --full-scan

# 运行特定模块
sudo sharpeye --module network

# 建立基线以供将来比较
sudo sharpeye --establish-baseline

# 与基线进行比较
sudo sharpeye --compare-baseline
```

## 配置

安装后，配置文件存储在`/etc/sharpeye/`目录中。编辑`config.yaml`来自定义扫描参数和检测阈值。

## 系统要求

- 基于Linux的操作系统（Debian、Ubuntu、CentOS、RHEL等）
- Python 3.6+
- 需要root权限进行全面扫描

## 当前状态

截至2025年5月，SharpEye核心模块的当前实现状态如下：

| 模块 | 状态 | 测试覆盖率 |
|--------|--------|---------------|
| 文件系统完整性 | ✅ 已完成 | 95% |
| 内核模块分析 | ✅ 已完成 | 94% |
| 库检查 | ✅ 已完成 | 95% |
| 权限提升检测 | ✅ 已完成 | 94% |
| 日志分析引擎 | ✅ 已完成 | 93% |
| 加密货币挖矿检测 | ✅ 已完成 | 95% |
| 系统资源 | ✅ 已完成 | 100% |
| 用户账户 | ✅ 已完成 | 100% |
| 进程 | ✅ 已完成 | 100% |
| 网络 | ✅ 已完成 | 95% |
| 计划任务 | ✅ 已完成 | 95% |
| SSH | ✅ 已完成 | 100% |
| Rootkit检测 | ✅ 已完成 | 100% |

该项目现已全部实现完成，所有13个模块已全部完成并经过全面测试。项目拥有功能完善的CI/CD流水线，使用GitHub Actions确保所有模块的代码质量和测试覆盖率。有关详细的项目状态信息，请参阅[项目状态](docs/PROJECT_STATUS_ZH.md)。

## 文档

有关更详细的信息，请参阅：
- [用户指南](docs/user_guide_zh.md)
- [模块参考](docs/module_reference_zh.md)
- [机器学习分析](docs/machine_learning_analysis_zh.md)
- [测试指南](docs/testing_zh.md)
- [项目状态](docs/PROJECT_STATUS_ZH.md)
- [SQLite线程指南](docs/SQLITE_THREADING_ZH.md)
- [CI/CD状态](docs/CI_CD_STATUS_ZH.md)
- [CI/CD修复指南](docs/CI_CD_FIX_ZH.md)
- [增强总结](docs/ENHANCEMENT_SUMMARY_ZH.md)

## 参与贡献

欢迎贡献！请查看我们的[贡献指南](CONTRIBUTING.md)了解更多详情。

## 关于innora.ai

innora.ai专注于为现代计算环境开发高级安全解决方案。我们的团队结合了恶意软件分析、威胁情报和机器学习方面的专业知识，创建尖端安全工具，帮助组织保护其关键基础设施。

## 许可证

本项目基于MIT许可证 - 详情请参阅[LICENSE](LICENSE)文件。

## 致谢

- innora.ai研究团队
- 所有帮助改进此项目的贡献者和安全研究人员
- 启发本项目的开源安全工具