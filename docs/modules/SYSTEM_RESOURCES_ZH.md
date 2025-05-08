# 系统资源分析器模块

## 概述

系统资源分析器模块监控CPU、内存和磁盘资源，以检测可能表明安全威胁的异常情况。它结合了传统的基于阈值的监控和机器学习，以检测可能指示加密货币挖矿、数据泄露、拒绝服务攻击或其他恶意活动的资源滥用模式。

## 主要功能

1. **全面的资源监控**
   - CPU使用率和负载分析
   - 内存和交换分区使用率跟踪
   - 磁盘空间和I/O监控
   - 进程资源使用分析

2. **基于机器学习的模式检测**
   - 识别异常的资源使用模式
   - 检测持续的资源滥用
   - 识别加密货币挖矿和其他资源密集型恶意软件
   - 跨资源相关性分析，用于检测复杂攻击

3. **进程分析**
   - 基于资源使用情况识别可疑进程
   - 检测从异常位置运行的进程
   - 识别伪装的进程名称
   - 监控具有可疑命令模式的进程

4. **磁盘安全分析**
   - 查找可疑目录和文件
   - 识别异常的权限设置
   - 检测敏感位置中的隐藏文件
   - 监控异常大的文件

5. **基准比较**
   - 建立正常资源使用模式
   - 检测与已建立基准的偏差
   - 识别新的异常进程
   - 监控资源使用的显著变化

## 技术细节

### 系统资源分析器

核心分析器使用多种检测方法：

1. **基于阈值的分析**：监控超过可配置阈值的资源使用情况
2. **机器学习检测**：使用隔离森林算法进行异常检测
3. **行为分析**：检查资源使用模式和相关性
4. **可疑进程检测**：应用启发式方法识别可疑进程

### 资源模式分析器

机器学习组件分析以下模式：

1. **CPU模式**：稳定性、峰值、使用分布、隐藏进程
2. **内存模式**：使用增长、交换行为、内存泄漏、内存碎片
3. **磁盘模式**：空间使用、增长率、文件创建、权限变更
4. **跨资源相关性**：不同资源类型之间的关系

## 使用示例

### 监控资源异常

```python
# 初始化分析器
from modules.system_resources import SystemResourceAnalyzer

analyzer = SystemResourceAnalyzer({
    'cpu_threshold': 90,
    'memory_threshold': 85,
    'disk_threshold': 90
})

# 运行分析
results = analyzer.analyze()

# 检查异常
if results['is_anomalous']:
    print("检测到资源异常！")
    
    if results['cpu'].get('is_anomalous'):
        print(f"CPU异常：使用率 {results['cpu'].get('total_cpu_usage')}%")
        
    if results['memory'].get('is_anomalous'):
        print(f"内存异常：使用率 {results['memory'].get('memory_usage_percent')}%")
        
    if results['disk'].get('is_anomalous'):
        print("在以下文件系统中检测到磁盘异常：")
        for fs in results['disk'].get('anomalous_filesystems', []):
            print(f"  - {fs['filesystem']} ({fs['use_percent']}%)")
```

### 建立和比较基准

```python
# 在正常操作期间建立基准
analyzer.establish_baseline()

# 稍后，检查与基准的偏差
deviations = analyzer.compare_baseline()

if deviations['has_deviations']:
    print("系统状态已偏离基准：")
    
    for cpu_dev in deviations['cpu_deviations']:
        print(f"CPU：{cpu_dev}")
        
    for mem_dev in deviations['memory_deviations']:
        print(f"内存：{mem_dev}")
        
    for disk_dev in deviations['disk_deviations']:
        print(f"磁盘：{disk_dev}")
        
    if deviations['new_processes']:
        print("检测到新的异常进程：")
        for proc in deviations['new_processes']:
            print(f"  - {proc['command']} (PID: {proc['pid']})")
```

## 配置选项

该模块可以使用以下选项进行配置：

```yaml
system_resources:
  # CPU使用阈值百分比
  cpu_threshold: 90
  
  # 内存使用阈值百分比
  memory_threshold: 90
  
  # 磁盘使用阈值百分比
  disk_threshold: 90
  
  # 进程监控设置
  processes:
    # 检查从不寻常位置运行的进程
    check_unusual_locations: true
    
    # 检查资源使用率高的进程
    check_high_resource_usage: true
    
    # 高CPU使用率阈值百分比
    high_cpu_threshold: 80
    
    # 高内存使用率阈值百分比
    high_memory_threshold: 50
    
    # 进程从中运行时被视为可疑的路径列表
    suspicious_paths:
      - "/tmp"
      - "/dev/shm"
      - "/var/tmp"
      - "/run/user"
    
    # 需要查找的可疑命令模式
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
  
  # 机器学习配置
  ml_config:
    # 启用基于ML的分析
    enable: true
    
    # 存储ML模型的目录
    models_dir: "/var/lib/sharpeye/models"
    
    # 历史记录中保留的样本数
    history_length: 24
    
    # 异常检测阈值
    detection_threshold: 0.7
```

## 与其他模块的集成

系统资源分析器与其他几个SharpEye模块集成：

1. **加密货币挖矿检测**：为挖矿检测提供资源使用数据
2. **进程分析器**：共享可疑进程信息
3. **网络分析器**：与网络活动相关联，以改进检测
4. **文件完整性**：识别可疑文件和文件系统更改

## 安全建议

1. **基准创建**：在正常操作期间建立资源基准
2. **定期监控**：安排定期系统资源扫描
3. **警报配置**：为重大资源异常设置警报
4. **自定义阈值**：根据系统的正常运行调整阈值
5. **机器学习训练**：为ML模型提供足够的时间来学习正常模式

## 常见问题和解决方案

1. **误报**：如果合法的高资源使用导致警报，请调整阈值
2. **内存限制**：如果内存使用是一个问题，请减少`history_length`
3. **CPU密集型**：如果检测使用太多资源，请在非高峰时段安排基于ML的分析
4. **缺少基准**：确保在与基准比较之前已建立基准

## 更新日志

- **v1.0.0**（2025年5月8日）：初始发布，具有基本的基于阈值的检测
- **v1.1.0**（2025年5月8日）：添加基于机器学习的模式检测
- **v1.2.0**（2025年5月8日）：实现进程分析和可疑进程检测
- **v1.3.0**（2025年5月8日）：添加基准创建和比较功能
- **v1.4.0**（2025年5月8日）：增强磁盘安全监控功能
- **v2.0.0**（2025年5月8日）：完全重写，具有跨资源相关性和高级ML检测

## 常见用例

### 用例1：检测隐藏的加密货币挖矿

系统资源分析器特别擅长检测隐藏的加密货币挖矿操作，其特征包括：

- 持续高CPU使用率，通常在夜间或系统空闲时运行
- 进程使用伪装名称或从临时目录运行
- 具有高系统CPU时间与用户CPU时间比率
- 内存与CPU使用不成比例
- 长期运行的高CPU负载模式

### 用例2：识别数据泄露活动

该模块可以通过以下模式帮助识别潜在的数据泄露：

- 非典型的磁盘I/O与CPU活动模式
- 临时目录中出现异常大的文件
- 系统中出现的新隐藏文件
- 文件系统使用量的突然激增
- 带有可疑命令参数的进程（例如加密或打包工具）

### 用例3：检测资源耗尽攻击

系统资源分析器可以通过以下迹象识别潜在的拒绝服务尝试：

- 资源使用的异常激增
- 多个相似进程消耗系统资源
- 内存泄漏模式和内存资源耗尽
- 持续高负载但没有明显的合法进程原因
- 系统文件的权限更改