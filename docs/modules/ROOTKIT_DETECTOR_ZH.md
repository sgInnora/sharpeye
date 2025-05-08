# Rootkit检测模块文档

## 概述

Rootkit检测模块提供全面的检测功能，用于识别Linux系统中的高级rootkit和内核级恶意软件。它利用多种检测技术，对试图隐藏自身存在的复杂威胁提供深度防御。

## 主要功能

### 1. 内核模块分析

- 检测未授权的内核模块
- 验证模块签名和完整性
- 监控内核符号表修改
- 识别可疑的内核钩子
- 分析模块加载/卸载行为
- 检测隐藏的内核模块

### 2. 系统调用表完整性

- 监控系统调用表修改
- 检测函数指针劫持
- 验证系统调用完整性
- 识别系统调用中的内联钩子
- 检测VDSO/VSYSCALL篡改
- 监控跳转代码注入

### 3. 内存分析

- 扫描内核内存查找可疑模式
- 检测隐藏的内核对象
- 识别运行时代码修改
- 分析内存映射区域
- 检测面向返回的编程(ROP)模式
- 识别进程内存中的代码注入

### 4. 文件系统完整性

- 检测文件系统层之间的差异
- 识别隐藏的文件和目录
- 监控关键系统文件修改
- 检测库预加载尝试
- 验证文件系统处理程序完整性
- 识别命名空间隔离技巧

## 实现细节

### 类和方法

- **类**: `RootkitDetector`
- **主要方法**:
  - `analyze()`: 执行完整的rootkit分析
  - `check_kernel_modules()`: 分析内核模块
  - `verify_syscall_table()`: 检查系统调用表完整性
  - `scan_memory()`: 执行内核内存分析
  - `check_fs_integrity()`: 验证文件系统完整性
  - `detect_hidden_resources()`: 查找隐藏的进程、文件等
  - `check_preload_hooks()`: 分析库预加载钩子
  - `verify_proc_entries()`: 检查/proc条目是否被篡改
  - `report_findings()`: 生成详细分析报告

### 技术实现

```python
def analyze(self):
    """执行全面的rootkit检测分析。"""
    self.logger.info("开始rootkit检测分析...")
    
    # 运行所有检测引擎
    kernel_findings = self._check_kernel_modules()
    syscall_findings = self._verify_syscall_table()
    memory_findings = self._scan_memory()
    fs_findings = self._check_fs_integrity()
    hidden_resources = self._detect_hidden_resources()
    preload_findings = self._check_preload_hooks()
    proc_findings = self._verify_proc_entries()
    
    # 分析结果并确定威胁级别
    threat_level = self._assess_threat_level(
        kernel_findings, syscall_findings, memory_findings,
        fs_findings, hidden_resources, preload_findings,
        proc_findings
    )
    
    # 编译综合报告
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
    
    self.logger.info(f"Rootkit检测完成，威胁级别: {threat_level}")
    return report
```

## 配置选项

```yaml
rootkit_detector:
  # 核心检测引擎
  check_kernel_modules: true
  check_syscall_table: true
  scan_kernel_memory: true
  check_fs_integrity: true
  detect_hidden_resources: true
  check_preload_hooks: true
  verify_proc: true
  
  # 高级选项
  use_kernel_debugger: false  # 需要额外权限
  use_hardware_assistance: false  # 如果可用
  memory_scan_level: 1  # 1-3，更高级别更彻底但更慢
  
  # 性能设置
  thorough_scan: false  # 启用可获得更全面但更慢的扫描
  scan_interval: 86400  # 每日一次，以秒为单位
  
  # 响应选项
  alert_level: high  # low, medium, high (警报阈值)
  auto_quarantine: false  # 自动隔离检测到的威胁
  
  # 排除项
  excluded_paths: ["/var/lib/docker"]
  trusted_modules: ["nvidia", "vbox"]
```

## 检测能力

### 1. 内核模式Rootkit

- **直接内核对象操作(DKOM)**
  - 检测内核数据结构的操作
  - 通过任务结构解链识别进程隐藏
  - 检测netstat结构中的网络连接隐藏

- **内核钩子检测**
  - 系统调用表钩子识别
  - 虚拟文件系统(VFS)钩子检测
  - 中断描述符表(IDT)修改检查
  - Netfilter钩子分析

- **可加载内核模块(LKM) Rootkit**
  - 检测未授权的内核模块
  - 使用签名检查进行模块验证
  - 通过内存分析检测隐藏模块
  - 识别rootkit特定的模块模式

### 2. 用户模式Rootkit

- **库注入技术**
  - LD_PRELOAD滥用检测
  - 共享库挂钩识别
  - 可执行文件修补检测
  - 运行时代码注入分析

- **进程操作**
  - 进程隐藏检测
  - PTRACE滥用识别
  - 进程凭证操作检测
  - 后门二进制文件检测

### 3. 高级持续性威胁

- **Bootkit检测**
  - 引导过程完整性验证
  - 固件植入检测能力
  - UEFI/BIOS修改检查
  - 引导序列异常检测

- **持久性机制**
  - 识别隐藏的自启动机制
  - 检测修改过的init脚本
  - Systemd单元文件篡改检测
  - Cron作业分析查找可疑条目

## 集成点

- 与进程模块集成，交叉验证隐藏进程
- 与文件系统模块协作，关联文件系统发现
- 连接网络模块验证连接隐藏
- 向日志模块提供事件关联数据
- 与SSH模块共享发现，进行完整性检查
- 为中央威胁评估引擎提供数据

## 使用示例

### 示例1: 基本Rootkit扫描

```python
from sharpeye.modules.rootkit_detector import RootkitDetector

# 初始化检测器
detector = RootkitDetector()

# 运行完整分析
results = detector.analyze()

# 处理发现
if results['threat_level'] > 0:
    print(f"检测到潜在的rootkit活动！威胁级别: {results['threat_level']}")
    
    # 显示具体发现
    if results['kernel_findings']:
        print("\n内核问题:")
        for finding in results['kernel_findings']:
            print(f" - {finding['type']}: {finding['description']}")
            
    if results['hidden_resources']:
        print("\n隐藏资源:")
        for resource in results['hidden_resources']:
            print(f" - {resource['type']}: {resource['name']} ({resource['details']})")
```

### 示例2: 定时扫描

```python
from sharpeye.modules.rootkit_detector import RootkitDetector
import schedule
import time

def run_rootkit_scan():
    detector = RootkitDetector(config={'thorough_scan': True})
    results = detector.analyze()
    
    # 将结果保存到文件以供日后分析
    with open('/var/log/sharpeye/rootkit_scan.json', 'w') as f:
        json.dump(results, f)
    
    # 高威胁级别时发出警报
    if results['threat_level'] >= 2:
        send_security_alert(results)

# 安排每日扫描
schedule.every().day.at("03:00").do(run_rootkit_scan)

while True:
    schedule.run_pending()
    time.sleep(60)
```

### 示例3: 自定义检测重点

```python
from sharpeye.modules.rootkit_detector import RootkitDetector

# 配置专注于内核内存分析的专用检测器
config = {
    'check_kernel_modules': True,
    'check_syscall_table': True,
    'scan_kernel_memory': True,
    'check_fs_integrity': False,  # 出于性能考虑禁用
    'detect_hidden_resources': False,  # 出于性能考虑禁用
    'memory_scan_level': 3,  # 最高彻底性
    'use_kernel_debugger': True  # 启用高级检测
}

# 初始化专用检测器
detector = RootkitDetector(config=config)

# 运行针对性分析
kernel_results = detector.analyze()
print(f"内核分析完成。威胁级别: {kernel_results['threat_level']}")
```

## 故障排除

### 常见问题

1. **高CPU使用率**
   - 降低内存扫描级别
   - 禁用彻底扫描选项
   - 增加扫描间隔
   - 将扫描限制在特定检测引擎

2. **误报**
   - 将合法模块添加到trusted_modules列表
   - 将预期路径添加到excluded_paths列表
   - 调整alert_level阈值
   - 更新检测签名

3. **权限问题**
   - 确保工具以root权限运行
   - 检查内核模块权限
   - 验证对/dev/kmem的访问(如果使用)
   - 确认debugfs正确挂载

## 最佳实践

1. **定期扫描**
   - 在非工作时间安排彻底扫描
   - 系统更改后进行快速扫描
   - 维护基准扫描结果以供比较
   - 内核更新后验证

2. **事件响应**
   - 立即隔离受影响的系统
   - 保留内存和磁盘映像以供取证
   - 使用多种工具确认发现
   - 记录所有观察到的行为

3. **预防措施**
   - 使用安全启动机制
   - 维持定期安全补丁
   - 实施内核模块签名
   - 使用单独的工具监控文件完整性
   - 使用基于主机的IDS/IPS系统

4. **高级检测设置**
   - 配置硬件辅助虚拟化以进行更安全的分析
   - 使用内核参数增强安全性(例如锁定模式)
   - 实施带外监控
   - 考虑网络级别检测隐蔽通道

有关更详细的信息和高级用法，请参阅完整的[Rootkit检测器API文档](../api/rootkit_detector_api_zh.md)。