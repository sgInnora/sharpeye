# 进程模块文档

## 概述

进程模块分析运行中的进程，检测恶意活动、隐藏进程和可能表明安全漏洞的异常行为。它采用先进的进程关系映射技术来识别横向移动和恶意进程链，提供对系统活动的深入可见性。

## 主要功能

### 1. 进程分析与监控

- 对运行中进程的全面分析
- 实时进程创建和终止监控
- 命令行参数和环境变量审核
- 进程权限和所有权分析
- 进程资源使用监控
- 隐藏进程检测

### 2. 进程关系映射

- 构建完整的进程层次结构图
- 识别父子进程关系
- 跟踪进程间通信（IPC）
- 检测进程注入和代码执行
- 识别异常的进程关系链
- 分析并可视化进程创建树

### 3. 行为分析

- 识别已知的恶意进程签名
- 检测异常的进程行为模式
- 监控可疑的系统调用
- 分析进程网络连接
- 监视文件系统交互
- 评估进程稳定性和寿命

### 4. 高级异常检测

- 基线比较和偏差检测
- 时间序列分析查找异常活动
- 使用统计模型识别异常值
- 与历史进程行为对比
- 检测新出现的进程
- 识别特权提升和权限变更

## 实现细节

### 类和方法

- **类**: `ProcessAnalyzer`
- **主要方法**:
  - `analyze()`: 分析所有进程并生成报告
  - `monitor_new_processes()`: 持续监控新进程创建
  - `build_process_tree()`: 构建进程关系树
  - `check_process_signatures()`: 检查已知的恶意签名
  - `detect_hidden_processes()`: 识别隐藏的进程
  - `analyze_process_behavior()`: 分析进程行为模式
  - `check_privileges()`: 检查进程权限变更
  - `establish_baseline()`: 创建进程基线
  - `compare_with_baseline()`: 与基线比较当前状态

### 技术实现

```python
def analyze(self):
    """分析系统上的所有进程并生成报告。"""
    self.logger.info("开始进程分析...")
    
    process_list = self._get_process_list()
    process_tree = self._build_process_tree(process_list)
    hidden_processes = self._detect_hidden_processes(process_list)
    suspicious_processes = self._check_process_signatures(process_list)
    anomalies = self._analyze_process_behavior(process_list, process_tree)
    privilege_issues = self._check_privileges(process_list)
    
    # 与基线比较（如果存在）
    baseline_deviations = None
    if os.path.exists(self.baseline_file):
        baseline_deviations = self._compare_with_baseline(process_list)
    
    # 组合所有发现并返回结果
    findings = {
        'hidden_processes': hidden_processes,
        'suspicious_processes': suspicious_processes,
        'anomalous_behavior': anomalies,
        'privilege_issues': privilege_issues,
        'baseline_deviations': baseline_deviations,
        'process_tree': self._serialize_process_tree(process_tree)
    }
    
    self.logger.info(f"进程分析完成，发现 {len(suspicious_processes)} 个可疑进程")
    return findings
```

## 配置选项

```yaml
processes:
  # 启用/禁用特定检查
  check_hidden: true
  check_signatures: true
  check_behavior: true
  check_privileges: true
  check_relationships: true
  
  # 进程监控设置
  monitor_interval: 60  # 秒
  process_history: 7    # 天
  
  # 基线设置
  use_baseline: true
  baseline_update_interval: 604800  # 7天，以秒为单位
  
  # 阈值设置
  cpu_threshold: 90     # CPU使用百分比
  memory_threshold: 85  # 内存使用百分比
  
  # 其他设置
  ignore_system_processes: false
  include_kernel_threads: false
  track_short_lived: true
```

## 检测能力

### 1. 恶意进程检测

- **加密货币挖矿进程**
  - 检测常见的挖矿软件
  - 识别具有挖矿特征的未知进程
  - 分析CPU和GPU使用模式

- **木马和后门**
  - 检测已知木马的进程特征
  - 识别可疑的长时间运行进程
  - 检查反向shell和命令执行

- **勒索软件活动**
  - 检测文件系统大量访问活动
  - 识别可疑的加密操作
  - 监控进程创建链和活动顺序

### 2. 隐藏进程检测

- **进程隐藏技术**
  - 对比不同进程列表来源
  - 检测DKOM（直接内核对象操作）
  - 分析/proc文件系统和ps输出差异

- **先进检测方法**
  - 内存扫描识别隠匿进程
  - 进程ID序列分析发现缺失PID
  - 系统调用跟踪检测进程操作

### 3. 权限和特权管理

- **权限提升检测**
  - 监控UID/GID变化
  - 检测SUID/SGID滥用
  - 识别capability滥用

- **特权进程监控**
  - 跟踪root运行的进程
  - 监控特权组访问
  - 检测不必要的特权执行

## 集成点

- 与文件系统模块集成以关联文件访问
- 向网络模块提供进程-连接关联数据
- 使用系统资源数据验证资源使用模式
- 与用户账户模块关联用户活动
- 向日志模块提供进程日志分析数据
- 与Rootkit检测模块共享隐藏进程信息

## 使用示例

### 示例1: 基本进程状态检查

```python
from sharpeye.modules.processes import ProcessAnalyzer

# 初始化进程分析器
analyzer = ProcessAnalyzer()

# 运行分析
results = analyzer.analyze()

# 处理结果
if results['suspicious_processes']:
    print("发现可疑进程:")
    for process in results['suspicious_processes']:
        print(f" - PID: {process['pid']}, 命令: {process['cmd']}, 原因: {process['reason']}")
```

### 示例2: 实时进程监控

```python
from sharpeye.modules.processes import ProcessAnalyzer

# 初始化进程分析器
analyzer = ProcessAnalyzer(config={'monitor_interval': 30})

# 设置回调函数
def process_alert(event_type, process_info):
    print(f"进程事件: {event_type}")
    print(f"进程: {process_info['pid']} - {process_info['cmd']}")

# 启动监控（带回调）
analyzer.monitor_new_processes(callback=process_alert)
```

### 示例3: 创建和使用进程基线

```python
from sharpeye.modules.processes import ProcessAnalyzer

# 初始化进程分析器
analyzer = ProcessAnalyzer()

# 创建基线
analyzer.establish_baseline()
print("进程基线已创建")

# 在之后的某个时间点，运行与基线的比较
deviations = analyzer.compare_with_baseline()
if deviations:
    print("发现基线偏差:")
    for dev in deviations:
        print(f" - {dev['type']}: {dev['details']}")
```

## 故障排除

### 常见问题

1. **误报率高**
   - 调整配置中的阈值
   - 为特定进程添加白名单
   - 重新创建更准确的基线

2. **性能影响**
   - 增加扫描间隔
   - 减少跟踪的进程历史记录
   - 禁用最消耗资源的检查

3. **隐藏进程检测不全面**
   - 确保以root权限运行
   - 启用更多的检测引擎
   - 结合rootkit检测模块使用

## 最佳实践

1. **创建准确的初始基线**
   - 在干净的系统上建立基线
   - 确保记录所有合法的系统进程
   - 定期更新基线以适应系统变化

2. **调整监控粒度**
   - 为关键系统增加检查频率
   - 为非关键系统减少检查频率
   - 根据系统负载调整阈值

3. **有效处理警报**
   - 建立明确的警报响应流程
   - 为不同类型的异常设置优先级
   - 将警报与其他来源的数据关联

4. **维护进程知识库**
   - 收集已知的恶意进程签名
   - 文档记录系统正常进程
   - 持续更新检测规则

有关更多详细信息和高级用法，请参阅完整的[进程分析器API文档](../api/process_analyzer_api.md)。