# SharpEye 模块参考

本文档提供有关SharpEye中每个检测模块的详细技术信息，包括实现细节、配置选项和集成点。

## 实现状态

| 模块 | 状态 | 测试覆盖率 | 最后更新 |
|--------|--------|---------------|------------|
| 文件完整性 | ✅ 已完成 | 95% | 2025年5月8日 |
| 内核模块 | ✅ 已完成 | 94% | 2025年5月8日 |
| 库检查 | ✅ 已完成 | 95% | 2025年5月8日 |
| 权限提升检测 | ✅ 已完成 | 94% | 2025年5月8日 |
| 日志分析 | ✅ 已完成 | 93% | 2025年5月8日 |
| 系统资源 | ✅ 已完成 | 100% | 2025年5月8日 |
| 用户账户 | ✅ 已完成 | 100% | 2025年5月8日 |
| 进程 | ✅ 已完成 | 100% | 2025年5月8日 |
| 网络 | ✅ 已完成 | 95% | 2025年5月8日 |
| 加密货币挖矿检测 | ✅ 已完成 | 95% | 2025年4月30日 |
| 计划任务 | ✅ 已完成 | 95% | 2025年5月8日 |
| SSH | ✅ 已完成 | 100% | 2025年5月8日 |
| Rootkit检测 | ✅ 已完成 | 100% | 2025年5月8日 |

## 目录

1. [系统资源模块](#系统资源模块)
2. [用户账户模块](#用户账户模块)
3. [SSH分析器模块](#ssh分析器模块)
4. [进程模块](#进程模块)
5. [网络模块](#网络模块)
6. [加密货币挖矿检测模块](#加密货币挖矿检测模块)
7. [文件系统模块](#文件系统模块)
7. [日志模块](#日志模块)
8. [计划任务模块](#计划任务模块)
9. [SSH模块](#ssh模块)
10. [内核模块](#内核模块)
11. [库模块](#库模块)
12. [权限模块](#权限模块)
13. [Rootkit检测模块](#rootkit检测模块)

## 系统资源模块

### 概述

系统资源模块（`system_resources.py`）监控CPU、内存和磁盘使用情况，以检测可能表明安全威胁（如加密货币挖矿、数据外泄或拒绝服务攻击）的资源利用异常。

### 实现细节

- **类**：`SystemResourceAnalyzer`
- **主要方法**：
  - `analyze()`：运行所有检查的入口点
  - `_analyze_cpu()`：分析CPU使用模式
  - `_analyze_memory()`：分析内存使用模式
  - `_analyze_disk()`：分析磁盘空间使用情况
  - `_find_suspicious_processes()`：识别具有可疑资源模式的进程
  - `establish_baseline()`：创建正常资源使用的基线
  - `compare_baseline()`：将当前状态与基线进行比较

### 配置选项

```yaml
system_resources:
  # CPU使用阈值（百分比）
  cpu_threshold: 90
  
  # 内存使用阈值（百分比）
  memory_threshold: 90
  
  # 磁盘使用阈值（百分比）
  disk_threshold: 90
  
  # 进程监控设置
  processes:
    # 检查从不寻常位置运行的进程
    check_unusual_locations: true
    
    # 检查高资源使用的进程
    check_high_resource_usage: true
    
    # 高CPU使用阈值（百分比）
    high_cpu_threshold: 80
    
    # 高内存使用阈值（百分比）
    high_memory_threshold: 50
    
    # 被认为是可疑的进程运行路径
    suspicious_paths:
      - "/tmp"
      - "/dev/shm"
      - "/var/tmp"
      - "/run/user"
```

### 检测能力

1. **高CPU使用检测**：
   - 识别消耗过多CPU的进程
   - 与阈值和基线进行比较
   - 标记具有异常CPU使用模式的进程

2. **内存使用分析**：
   - 检测异常的内存消耗模式
   - 识别内存泄漏和过度增长
   - 检查消耗异常内存量的进程

3. **磁盘使用监控**：
   - 识别接近容量的文件系统
   - 检测磁盘使用的突然增加
   - 定位不寻常位置的大文件或目录
   - 标记可疑的磁盘使用模式

4. **可疑进程资源使用**：
   - 检测具有可疑资源使用模式的进程
   - 识别加密货币挖矿程序和其他资源密集型恶意软件
   - 检查从可疑位置运行的进程

### 集成点

- 与进程模块集成，进行更深入的进程调查
- 向报告系统提供带有严重性信息的数据
- 维护基线数据以供将来比较

## 用户账户模块

### 概述

用户账户模块（`user_accounts.py`）检查可疑用户账户、未授权权限提升和可能表明安全漏洞的异常账户活动。

### 实现细节

- **类**：`UserAccountAnalyzer`
- **主要方法**：
  - `analyze()`：运行所有检查的入口点
  - `_check_root_accounts()`：检查未授权的UID 0账户
  - `_check_users_with_shell()`：识别具有有效shell的用户
  - `_check_sudo_users()`：检查具有sudo权限的用户
  - `_check_suspicious_accounts()`：识别可疑的账户属性
  - `_check_recent_changes()`：检测最近的账户修改
  - `_check_recent_logins()`：分析登录模式
  - `_check_home_directory_security()`：分析家目录的权限和安全问题
  - `_check_password_policy()`：检查密码策略和老化设置
  - `_check_group_membership()`：分析敏感组成员资格
  - `_check_privilege_escalation()`：检测权限提升向量
  - `_check_mfa_status()`：验证多因素认证配置
  - `_check_login_patterns()`：分析异常登录模式
  - `_check_threat_intelligence()`：与威胁情报集成
  - `establish_baseline()`：创建正常账户状态的基线
  - `compare_baseline()`：将当前账户与基线进行比较

### 配置选项

```yaml
user_accounts:
  # 数据库路径（如果未指定，将使用~/.sharpeye/user_accounts.db）
  database_path: "/var/lib/sharpeye/user_accounts.db"
  
  # 基线文件
  baseline_file: "/var/lib/sharpeye/baselines/accounts.json"
  
  # 主要检查
  check_sudo: true
  check_shell: true
  check_auth_logs: true
  
  # 增强安全检查
  check_home_security: true
  check_password_policy: true
  check_group_membership: true
  check_privilege_escalation: true
  check_mfa_status: true
  check_login_patterns: true
  
  # 预期具有sudo权限的组
  expected_sudo_groups:
    - "sudo"
    - "wheel"
    - "admin"
  
  # 暴力检测阈值
  brute_force_threshold: 5
  
  # 被考虑为可疑的登录尝试IP列表
  suspicious_ips: []
  
  # 要检查的可疑组成员资格
  sensitive_groups:
    - "root"
    - "wheel"
    - "sudo"
    - "admin"
    - "shadow"
    - "disk"
    - "adm"
    - "docker"
    - "lxd"
  
  # 密码策略设置
  password_policy:
    max_days: 90         # 最大密码年龄
    min_days: 1          # 最小密码年龄
    warn_days: 7         # 到期前的警告期
    min_length: 14       # 最小密码长度
  
  # MFA配置
  mfa:
    require_for_sudo: true    # 要求sudo用户使用MFA
    require_for_ssh: true     # 要求SSH访问使用MFA
    
  # 登录模式分析设置
  login_patterns:
    unusual_hours: [22, 23, 0, 1, 2, 3, 4, 5]   # 晚上10点到早上5点
    max_sources: 3                              # 每个用户的最大源IP数
    max_sessions: 2                             # 最大同时会话数
  
  # 威胁情报集成
  threat_intelligence:
    enabled: true
    cache_dir: "/var/lib/sharpeye/cache/threat_intel"
    cache_ttl: 86400  # 24小时
```

### 检测能力

1. **未授权Root访问**：
   - 检测除root外具有UID 0的账户
   - 识别未授权的特权访问
   - 监控root账户安全配置

2. **Shell访问分析**：
   - 识别具有有效登录shell的用户
   - 标记意外分配shell的系统账户
   - 验证有效的登录shell

3. **Sudo权限监控**：
   - 检查意外的sudo权限
   - 检测sudoers配置更改
   - 验证sudo组成员资格
   - 分析sudo配置文件
   - 识别意外的sudo组

4. **可疑账户检测**：
   - 查找无密码账户
   - 识别隐藏用户账户（UID < 1000但不是系统账户）
   - 检测UID/GID不一致
   - 分析可疑的账户属性

5. **账户修改跟踪**：
   - 检测最近的密码更改
   - 识别最近修改的账户属性
   - 跟踪关键系统文件的更改
   - 验证账户到期设置

6. **登录活动分析**：
   - 分析认证日志中的可疑登录
   - 检测暴力尝试
   - 识别来自异常来源或时间的登录
   - 检测不寻常的登录来源

7. **家目录安全分析**：
   - 验证适当的家目录权限
   - 检测不安全的SSH密钥存储
   - 分析shell配置文件的安全问题
   - 识别启动文件中的可疑内容

8. **密码策略分析**：
   - 验证密码复杂性要求
   - 检查密码老化设置
   - 分析PAM配置的密码安全性
   - 识别过期或陈旧的密码

9. **组成员资格分析**：
   - 检测敏感组中的用户（root、sudo、wheel、docker等）
   - 识别可疑的组名
   - 分析组成员资格模式
   - 基于组成员资格评估权限

10. **权限提升检测**：
    - 检测不寻常位置的SUID/SGID二进制文件
    - 识别root拥有的全局可写文件
    - 分析具有危险能力的二进制文件
    - 检测潜在的权限提升向量

11. **MFA状态检查**：
    - 验证MFA模块的安装和配置
    - 识别没有MFA的特权用户
    - 检查关键账户上的MFA使用情况
    - 分析PAM配置的MFA设置

12. **登录模式分析**：
    - 检测非正常时间的登录
    - 识别来自多个源IP的登录
    - 分析同时活动的会话
    - 检测可疑的登录频率模式

13. **威胁情报集成**：
    - 检查已知威胁数据库中的登录源
    - 将可疑活动与威胁源相关联
    - 用威胁上下文丰富安全发现
    - 基于威胁情报进行风险评估

### 集成点

- 与日志模块对接以分析登录信息
- 为相关的SSH检查提供数据给SSH模块
- 维护基线数据以供将来比较

## SSH分析器模块

### 概述

SSH分析器模块为SSH服务、配置、密钥、认证日志、连接、隧道和密钥使用模式提供全面的安全分析。

### 实现细节

- **类**: `SSHAnalyzer`
- **主要方法**:
  - `analyze()`: 运行所有检查的入口点
  - `_check_ssh_config()`: 分析SSH服务器配置
  - `_check_ssh_keys()`: 验证SSH密钥安全性
  - `_check_ssh_auth_logs()`: 分析认证日志
  - `_check_ssh_connections()`: 监控活动的SSH连接
  - `_check_ssh_tunnels()`: 检测SSH隧道和端口转发
  - `_check_key_usage_patterns()`: 分析SSH密钥使用模式
  - `establish_baseline()`: 创建SSH配置基线
  - `compare_baseline()`: 将当前状态与基线进行比较

### 配置选项

```yaml
ssh:
  # 检查授权密钥
  check_authorized_keys: true
  
  # 检查SSH配置文件
  check_config: true
  
  # 检查弱算法
  check_algorithms: true
  
  # 检查SSH隧道
  check_tunnels: true
  
  # 检查SSH密钥使用模式
  check_key_usage: true
  
  # 检查SSH暴力破解尝试
  check_bruteforce: true
  
  # 检查SSH连接
  check_connections: true
  
  # 检查SSH认证问题
  check_auth: true
```

### 检测能力

1. **SSH配置分析**:
   - 检测不安全的SSH服务器配置
   - 验证安全的加密算法、MAC和密钥交换算法
   - 主机密钥验证和完整性检查
   - 配置文件权限验证

2. **SSH密钥安全分析**:
   - 检测弱密钥类型（DSA、短RSA密钥）
   - 验证适当的密钥权限
   - 检测未受保护的私钥
   - 分析authorized_keys文件的适当限制

3. **SSH隧道检测**:
   - 分析本地、远程和动态(SOCKS)隧道
   - 检测暴露的敏感服务
   - 识别可疑的转发配置
   - 命令行隧道检测

4. **SSH密钥使用模式分析**:
   - 跟踪基于密钥的认证随时间的变化
   - 检测异常的密钥使用模式
   - 监控从多个来源使用的密钥
   - 分析不寻常时间的登录

### 集成点

- 与网络模块集成进行连接关联
- 使用文件完整性模块监控配置文件
- 向威胁情报提供数据进行IP信誉检查
- 维护认证模式的历史数据

有关详细文档，请参阅[SSH_ANALYZER.md](./modules/SSH_ANALYZER_ZH.md)。

## 进程模块

### 概述

进程模块（`processes.py`）分析运行进程以检测恶意活动、隐藏进程和可能表明安全漏洞的异常行为。

### 实现细节

- **类**：`ProcessAnalyzer`
- **主要方法**：
  - `analyze()`：运行所有检查的入口点
  - `_get_running_processes()`：检索有关所有进程的信息
  - `_find_suspicious_processes()`：识别具有可疑属性的进程
  - `_find_hidden_processes()`：检测对进程列表工具隐藏的进程
  - `_check_process_relationships()`：检查父子关系
  - `_check_execution_paths()`：识别从异常位置运行的进程
  - `_check_file_handles()`：分析可疑模式的文件句柄
  - `_check_network_connections()`：检查进程建立的网络连接
  - `establish_baseline()`：创建正常进程活动的基线
  - `compare_baseline()`：将当前进程与基线进行比较

### 配置选项

```yaml
processes:
  # 检查隐藏进程
  check_hidden: true
  
  # 检查父子进程关系
  check_relationships: true
  
  # 检查进程执行路径
  check_execution_path: true
  
  # 检查进程文件句柄
  check_file_handles: true
  
  # 检查进程网络连接
  check_network_connections: true
  
  # 进程年龄阈值（秒）（新进程受到更严格的审查）
  new_process_threshold: 3600

  # 可疑路径配置
  suspicious_paths:
    - "/tmp"
    - "/dev/shm"
    - "/var/tmp"
    - "/run/user"
  
  # 可疑命令模式
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
```

### 检测能力

1. **可疑进程检测**：
   - 识别具有可疑命令模式的进程
   - 检测从异常位置运行的进程
   - 标记具有可疑属性的进程

2. **隐藏进程检测**：
   - 比较`/proc`条目与`ps`输出以查找隐藏进程
   - 识别rootkit隐藏的进程

3. **进程关系分析**：
   - 检测异常的父子关系
   - 识别派生shell的服务器进程（潜在的webshell）
   - 标记异常的进程层次结构

4. **执行路径验证**：
   - 检查从可疑位置运行的进程
   - 检测从全局可写目录运行的进程
   - 识别从隐藏目录运行的进程

5. **文件句柄分析**：
   - 检查进程文件句柄的可疑模式
   - 识别访问可疑文件的进程
   - 检测使用异常命名管道或内存映射文件的进程

6. **网络连接分析**：
   - 识别具有可疑网络连接的进程
   - 检测连接到Web端口的非浏览器进程
   - 标记连接到可疑端口的进程

### 集成点

- 与网络模块协同工作，关联进程和网络活动
- 与系统资源模块对接，识别资源密集型进程
- 维护基线数据以供将来比较

有关详细文档，请参阅[PROCESSES_ZH.md](./modules/PROCESSES_ZH.md)。

## 网络模块

### 概述

网络模块（`network.py`）检查网络活动，以识别未授权的连接、潜在的数据外泄和可能表明安全漏洞的其他可疑网络行为。

### 实现细节

- **类**：`NetworkAnalyzer`
- **主要方法**：
  - `analyze()`：运行所有检查的入口点
  - `_check_listening_ports()`：检查监听端口的异常
  - `_check_established_connections()`：分析已建立的连接
  - `_check_remote_access()`：检测远程访问服务
  - `_check_suspicious_connections()`：识别可疑的连接模式
  - `_check_recent_dns()`：分析DNS查询模式
  - `_is_suspicious_domain()`：评估域名的可疑特征
  - `establish_baseline()`：创建正常网络活动的基线
  - `compare_baseline()`：将当前网络状态与基线进行比较

### 配置选项

```yaml
network:
  # 检查意外的监听端口
  check_listening_ports: true
  
  # 检查可疑的出站连接
  check_outbound: true
  
  # 检查远程访问服务
  check_remote_access: true
  
  # 预期开放的常见合法端口
  expected_ports:
    - 22    # SSH
    - 80    # HTTP
    - 443   # HTTPS
    # ... 其他合法端口 ...
  
  # 已知的恶意端口/服务
  suspicious_ports:
    - 31337  # Back Orifice
    - 12345  # NetBus
    - 6667   # IRC（经常被僵尸网络使用）
  
  # 被认为是高风险的国家列表（使用ISO国家代码）
  high_risk_countries:
    - "KP"  # 朝鲜
    - "RU"  # 俄罗斯
    - "CN"  # 中国
    - "IR"  # 伊朗
  
  # 启用IP地理位置查询
  enable_geolocation: false
```

### 检测能力

1. **监听端口分析**：
   - 识别意外的开放端口
   - 检测已知的可疑端口
   - 标记异常的绑定地址（敏感服务的非本地主机）

2. **连接分析**：
   - 检查已建立连接的可疑模式
   - 检测连接到已知恶意端口
   - 识别连接到高风险国家
   - 标记建立异常出站连接的不寻常程序

3. **远程访问服务检测**：
   - 识别远程访问服务（SSH、Telnet、RDP、VNC）
   - 检查不安全的配置
   - 检测可公开访问的服务

4. **可疑连接模式**：
   - 检测连接到连续高端口（C2通信）
   - 识别建立出站连接的服务器进程
   - 标记与不同端口连接到同一远程地址的多个连接

5. **DNS分析**：
   - 捕获并分析DNS查询
   - 识别可疑的域名模式
   - 检测潜在的DNS隧道或数据外泄

### 集成点

- 与进程模块协同工作，关联网络和进程活动
- 与SSH模块对接，进行相关的SSH连接检查
- 维护基线数据以供将来比较

## 加密货币挖矿检测模块

### 概述

加密货币挖矿检测模块（`cryptominer.py`）使用机器学习和CPU行为分析来识别加密货币挖矿恶意软件。它检测未经授权的加密货币挖矿活动，这些活动会消耗系统资源并可能表明安全漏洞。

### 实现细节

- **类**：`CryptominerDetectionModule`
- **主要方法**：
  - `analyze()`：对所有进程运行检测的入口点
  - `_get_all_processes()`：检索所有进程进行分析
  - `_get_system_load()`：获取系统负载平均值
  - `_start_monitoring()`：启动连续监控线程
  - `_monitoring_loop()`：实现后台监控
  - `establish_baseline()`：创建正常进程的基线
  - `compare_baseline()`：将当前状态与基线进行比较

- **支持类**：
  - `CryptominerDetector`：实现分析的核心检测器
  - `CPUProfiler`：收集进程的CPU使用模式
  - `MLModelManager`：管理用于检测的机器学习模型

### 配置选项

```yaml
cryptominer:
  # 启用连续后台监控
  continuous_monitoring: false
  
  # 监控间隔（秒）
  monitoring_interval: 60
  
  # 启发式检测的特征阈值
  thresholds:
    cpu_stability: 0.2      # 较低的值表示更稳定（可疑）的CPU使用率
    cpu_min: 50.0           # 考虑可疑的最低CPU使用率
    cpu_mean: 80.0          # 考虑可疑的平均CPU使用率
    cpu_time_growth_rate: 0.5  # 考虑可疑的CPU时间增长率
    cpu_autocorrelation: 0.7   # 考虑可疑的CPU使用自相关性
    cpu_spectral_entropy: 1.5   # 考虑可疑的CPU使用谱熵
  
  # 命令名称中要匹配的与挖矿相关的关键字
  mining_keywords:
    - "miner"
    - "xmr"
    - "monero"
    # ... 额外的关键字
```

### 检测能力

1. **CPU模式分析**：
   - 分析CPU使用的稳定性和一致性
   - 检测挖矿程序典型的持续高CPU使用
   - 识别挖矿算法特有的周期性模式
   - 测量自相关性和谱熵等统计特征

2. **基于机器学习的检测**：
   - 使用ML模型识别加密货币挖矿行为
   - 特征包括CPU使用模式、内存使用和系统负载
   - 能够基于行为模式检测以前未知的加密货币挖矿程序
   - 如果没有可用模型，则回退到启发式检测

3. **命令和进程分析**：
   - 识别进程命令中与挖矿相关的关键字
   - 检测从可疑位置运行的进程
   - 随时间分析进程执行模式

4. **时间序列行为监控**：
   - 可选择在后台连续监控进程
   - 检测与挖矿活动一致的行为变化
   - 识别持续消耗CPU资源的进程

### 集成点

- 与系统资源模块协同工作，获取资源使用上下文
- 与进程模块对接进行更深入的进程分析
- 可以作为按需扫描或连续监控运行
- 维护基线数据以供将来比较

有关此模块的更详细信息，请参阅[加密货币挖矿模块文档](cryptominer_module_zh.md)。

## 文件系统模块

### 概述

文件系统模块分析文件系统中的可疑文件，验证系统文件完整性，并检测可能表明安全漏洞的未授权修改。

### 实现细节

- **类**：`FileSystemAnalyzer`
- **主要方法**：
  - `analyze()`：运行所有检查的入口点
  - `_check_integrity()`：验证系统文件完整性
  - `_check_suspicious_files()`：识别具有可疑属性的文件
  - `_check_hidden_files()`：检测隐藏的文件和目录
  - `_check_suid_sgid()`：定位SUID/SGID文件
  - `_check_writable_files()`：查找敏感位置的全局可写文件
  - `establish_baseline()`：创建正常文件状态的基线
  - `compare_baseline()`：将当前文件状态与基线进行比较

### 配置选项

```yaml
filesystem:
  # 检查文件完整性
  check_integrity: true
  
  # 检查可疑文件
  check_suspicious_files: true
  
  # 检查隐藏文件/目录
  check_hidden: true
  
  # 检查setuid/setgid文件
  check_suid_sgid: true
  
  # 检查全局可写文件
  check_writable: true
  
  # 要检查的路径（空表示所有已挂载的文件系统）
  check_paths: []
  
  # 从检查中排除的路径
  exclude_paths:
    - "/proc"
    - "/sys"
    - "/dev"
    - "/run"
    - "/var/lib/docker"
  
  # 被认为是可疑的文件模式
  suspicious_patterns:
    - "*.php.jpg"
    - "*.sh.txt"
    - "*.py.jpg"
    - ".*rc"
  
  # 要扫描的最大文件大小（字节）
  max_file_size: 10485760  # 10MB
```

### 检测能力

1. **文件完整性验证**：
   - 使用包管理器工具验证系统文件完整性
   - 检测对系统文件的未授权修改
   - 识别被篡改的二进制文件和库

2. **可疑文件检测**：
   - 定位具有可疑模式或扩展名的文件
   - 识别混淆的可执行文件
   - 检测潜在的webshell和后门

3. **隐藏文件分析**：
   - 查找隐藏的文件和目录
   - 检测不寻常位置的异常隐藏文件
   - 识别恶意软件的潜在隐藏处

4. **权限提升向量检测**：
   - 定位SUID/SGID文件
   - 识别未授权的SUID二进制文件
   - 检测潜在的权限提升向量

5. **权限分析**：
   - 查找敏感位置的全局可写文件
   - 识别不安全的目录权限
   - 检测潜在的基于权限的漏洞

### 集成点

- 与权限模块一起进行SUID/SGID文件分析
- 与Rootkit模块对接进行隐藏文件检测
- 维护基线数据以供将来比较

## 日志模块

### 概述

日志模块分析系统日志，查找入侵迹象、可疑活动和潜在的安全漏洞。

### 实现细节

- **类**：`LogAnalyzer`
- **主要方法**：
  - `analyze()`：运行所有检查的入口点
  - `_check_auth_logs()`：分析认证日志
  - `_check_system_logs()`：检查系统日志中的可疑条目
  - `_check_application_logs()`：分析应用程序特定日志
  - `_check_cleared_logs()`：检测日志清除的证据
  - `_find_suspicious_patterns()`：识别可疑的日志模式
  - `establish_baseline()`：创建正常日志活动的基线
  - `compare_baseline()`：将当前日志状态与基线进行比较

### 配置选项

```yaml
logs:
  # 检查认证日志
  check_auth_logs: true
  
  # 检查系统日志
  check_system_logs: true
  
  # 检查应用程序日志
  check_application_logs: true
  
  # 检查已清除的日志
  check_cleared_logs: true
  
  # 要分析的日志文件
  log_files:
    - "/var/log/auth.log"
    - "/var/log/secure"
    - "/var/log/messages"
    - "/var/log/syslog"
    - "/var/log/kern.log"
  
  # 在日志中搜索的可疑模式
  suspicious_patterns:
    - "Failed password"
    - "authentication failure"
    - "Invalid user"
    - "POSSIBLE BREAK-IN ATTEMPT"
    - "Bad protocol version identification"
    - "did not receive identification string"
    - "segfault"
    - "Out of memory"
    - "Accepted password for root"
    - "USER_AUTH_ROOT_PRIV"
```

### 检测能力

1. **认证日志分析**：
   - 识别失败的登录尝试
   - 检测暴力攻击
   - 查找来自异常来源的成功登录
   - 分析root登录尝试

2. **系统日志检查**：
   - 检测系统错误和崩溃
   - 识别内核级问题
   - 查找资源耗尽的证据
   - 检查服务相关错误

3. **应用程序日志分析**：
   - 检查Web服务器日志中的攻击模式
   - 分析数据库日志中的未授权访问
   - 检查应用程序特定日志中的可疑活动

4. **日志篡改检测**：
   - 识别被清除或截断的日志
   - 检测缺失的日志条目
   - 查找日志操作的证据
   - 检查日志文件的权限和所有权

5. **模式识别**：
   - 搜索已知的攻击签名
   - 识别利用尝试
   - 检测权限提升模式
   - 查找成功入侵的证据

### 集成点

- 与用户账户模块协同工作，关联登录活动
- 与SSH模块对接进行SSH相关的日志分析
- 维护基线数据以供将来比较

## 计划任务模块

### 概述

计划任务模块检查cron作业、systemd计时器和其他计划任务，以识别可能用于持久性或恶意活动的未授权条目。

### 实现细节

- **类**：`ScheduledTaskAnalyzer`
- **主要方法**：
  - `analyze()`：运行所有检查的入口点
  - `_check_cron()`：分析cron作业
  - `_check_systemd_timers()`：检查systemd计时器
  - `_check_at()`：检查at作业
  - `_check_hidden()`：检测隐藏的计划任务
  - `_is_suspicious_task()`：评估任务的可疑特征
  - `establish_baseline()`：创建正常计划任务的基线
  - `compare_baseline()`：将当前任务与基线进行比较

### 配置选项

```yaml
scheduled_tasks:
  # 检查cron作业
  check_cron: true
  
  # 检查systemd计时器
  check_systemd_timers: true
  
  # 检查at作业
  check_at: true
  
  # 检查隐藏的计划任务
  check_hidden: true
  
  # 检查cron作业的目录
  cron_directories:
    - "/etc/cron.d"
    - "/etc/cron.hourly"
    - "/etc/cron.daily"
    - "/etc/cron.weekly"
    - "/etc/cron.monthly"
```

### 检测能力

1. **Cron作业分析**：
   - 识别可疑的cron条目
   - 检测具有异常执行时间的作业
   - 查找由意外用户拥有的cron作业
   - 检查cron作业内容中的可疑命令

2. **Systemd计时器检查**：
   - 分析systemd计时器的异常
   - 识别未授权的计时器单元
   - 检查计时器目标服务

3. **At作业检查**：
   - 检查意外的at作业
   - 识别为异常时间安排的作业
   - 分析作业内容中的可疑命令

4. **隐藏任务检测**：
   - 查找隐藏或混淆的计划任务
   - 检测计划任务的非标准位置
   - 识别具有故意误导名称的任务

5. **命令分析**：
   - 检查计划命令中的可疑模式
   - 检测可能下载或执行恶意软件的任务
   - 识别可能用于数据外泄的任务
   - 查找建立持久性的任务

### 集成点

- 与进程模块一起关联运行的进程
- 与文件系统模块对接以验证计划任务脚本
- 维护基线数据以供将来比较

## SSH模块

### 概述

SSH模块检查SSH配置、密钥和连接，以识别可能表明安全漏洞的安全问题和未授权访问。

### 实现细节

- **类**：`SSHAnalyzer`
- **主要方法**：
  - `analyze()`：运行所有检查的入口点
  - `_check_authorized_keys()`：检查authorized_keys文件
  - `_check_config()`：分析SSH服务器配置
  - `_check_algorithms()`：验证SSH算法安全性
  - `_check_tunnels()`：检测未授权的SSH隧道
  - `establish_baseline()`：创建正常SSH状态的基线
  - `compare_baseline()`：将当前SSH状态与基线进行比较

### 配置选项

```yaml
ssh:
  # 检查authorized keys
  check_authorized_keys: true
  
  # 检查SSH配置文件
  check_config: true
  
  # 检查弱算法
  check_algorithms: true
  
  # 检查SSH隧道
  check_tunnels: true
  
  # 配置建议
  recommended_settings:
    PermitRootLogin: "no"
    PasswordAuthentication: "no"
    X11Forwarding: "no"
    MaxAuthTries: 3
    AllowAgentForwarding: "no"
    AllowTcpForwarding: "no"
    PermitEmptyPasswords: "no"
```

### 检测能力

1. **授权密钥分析**：
   - 检查authorized_keys文件中的未授权条目
   - 检测没有限制的密钥
   - 识别具有异常权限的密钥
   - 检查对密钥文件的未授权访问

2. **配置安全审核**：
   - 根据安全最佳实践验证SSH服务器配置
   - 检测不安全设置（root登录、密码认证）
   - 识别弱算法配置
   - 检查不必要的服务功能

3. **算法安全验证**：
   - 识别弱加密算法
   - 检测已弃用或易受攻击的算法
   - 确保符合安全标准

4. **SSH隧道检测**：
   - 识别活动的SSH隧道
   - 检测未授权的端口转发
   - 分析隧道端点的可疑活动

5. **SSH连接分析**：
   - 检查SSH连接模式
   - 识别来自异常来源的连接
   - 检测潜在的暴力尝试

### 集成点

- 与用户账户模块协同工作，关联用户访问
- 与网络模块对接进行SSH连接分析
- 维护基线数据以供将来比较

## 内核模块

### 概述

内核模块分析已加载的内核模块，查找可能表明rootkit或其他低级系统入侵的可疑或恶意代码。

### 实现细节

- **类**：`KernelModuleAnalyzer`
- **主要方法**：
  - `analyze()`：运行所有检查的入口点
  - `_check_unsigned()`：验证模块签名
  - `_check_suspicious()`：识别可疑的模块特征
  - `_check_hidden()`：检测隐藏的内核模块
  - `_is_suspicious_module()`：评估模块的可疑特征
  - `establish_baseline()`：创建正常内核模块的基线
  - `compare_baseline()`：将当前模块与基线进行比较

### 配置选项

```yaml
kernel:
  # 检查未签名的模块
  check_unsigned: true
  
  # 检查可疑模块
  check_suspicious: true
  
  # 已知的可疑模块名称
  suspicious_modules:
    - "hide"
    - "rootkit"
    - "cleaner"
    - "diamorphine"
    - "modhide"
    - "kbeast"
```

### 检测能力

1. **模块签名验证**：
   - 验证已加载模块的数字签名
   - 识别具有安全启动的系统中未签名的模块
   - 检测已签名模块的篡改

2. **可疑模块检测**：
   - 识别具有可疑名称或行为的模块
   - 检测隐藏进程、文件或连接的模块
   - 检查与已知rootkit相关的模块

3. **隐藏模块分析**：
   - 检测对标准列表工具隐藏的模块
   - 识别不同模块枚举方法之间的差异
   - 查找模块隐藏技术的证据

4. **模块加载模式分析**：
   - 检查模块何时以及如何加载
   - 识别异常的模块加载序列
   - 检测潜在的持久性rootkit组件

5. **功能分析**：
   - 检查模块功能的可疑行为
   - 识别拦截系统调用的模块
   - 检测可能用于键盘记录或数据包嗅探的模块

### 集成点

- 与Rootkit模块协同工作，关联发现
- 与进程模块对接以识别隐藏进程
- 维护基线数据以供将来比较

## 库模块

### 概述

库模块检查库劫持和其他可能用于危害系统安全的库相关问题。

### 实现细节

- **类**：`LibraryAnalyzer`
- **主要方法**：
  - `analyze()`：运行所有检查的入口点
  - `_check_preload()`：检查LD_PRELOAD配置
  - `_check_hijacking()`：检测潜在的库劫持
  - `_check_ld_config()`：分析动态链接器配置
  - `establish_baseline()`：创建正常库状态的基线
  - `compare_baseline()`：将当前库状态与基线进行比较

### 配置选项

```yaml
libraries:
  # 检查预加载库
  check_preload: true
  
  # 检查库劫持
  check_hijacking: true
  
  # 检查动态链接器配置
  check_ld_config: true
```

### 检测能力

1. **预加载库检测**：
   - 检查可疑的LD_PRELOAD条目
   - 检查/etc/ld.so.preload中的未授权条目
   - 识别可能影响库加载的环境变量

2. **库劫持分析**：
   - 检测潜在的库路径劫持
   - 识别可疑的库位置
   - 检查具有意外所有者或权限的库

3. **动态链接器配置检查**：
   - 分析/etc/ld.so.conf和/etc/ld.so.conf.d/
   - 识别异常的库搜索路径
   - 检测潜在的恶意链接器配置

4. **共享对象分析**：
   - 检查共享对象的可疑特征
   - 识别具有异常符号或依赖关系的库
   - 检测潜在的后门库

5. **库加载模式分析**：
   - 检查进程库加载的异常
   - 识别异常的库加载顺序
   - 检测潜在的基于库的rootkit

### 集成点

- 与进程模块协同工作，检查进程库使用情况
- 与文件系统模块对接进行文件完整性验证
- 维护基线数据以供将来比较

## 权限模块

### 概述

权限模块检测权限提升向量和可能被利用以危害系统安全的不安全权限。

### 实现细节

- **类**：`PrivilegeAnalyzer`
- **主要方法**：
  - `analyze()`：运行所有检查的入口点
  - `_check_suid_sgid()`：检查SUID/SGID文件
  - `_check_world_writable()`：识别全局可写文件
  - `_check_capabilities()`：分析文件能力
  - `_is_suspicious_suid()`：评估SUID文件的可疑特征
  - `establish_baseline()`：创建正常权限状态的基线
  - `compare_baseline()`：将当前状态与基线进行比较

### 配置选项

```yaml
privileges:
  # 检查SUID/SGID文件
  check_suid_sgid: true
  
  # 检查全局可写文件
  check_world_writable: true
  
  # 检查能力
  check_capabilities: true
  
  # 预期的SUID/SGID文件（仅检查意外的文件）
  expected_suid_files: []
```

### 检测能力

1. **SUID/SGID文件分析**：
   - 识别意外的SUID/SGID二进制文件
   - 检测新添加的SUID/SGID文件
   - 检查现有文件的权限更改

2. **全局可写文件检测**：
   - 查找敏感位置的全局可写文件
   - 识别可写的配置文件
   - 检测可能导致入侵的不安全权限

3. **能力分析**：
   - 分析文件能力中的过度权限
   - 识别异常的能力分配
   - 检测潜在的基于能力的权限提升

4. **权限链分析**：
   - 检查目录权限链
   - 识别父目录中的权限弱点
   - 检测潜在的基于路径的权限问题

5. **权限提升向量识别**：
   - 检测常见的权限提升向量
   - 识别具有过度权限的易受攻击应用程序
   - 检查可利用的配置问题

### 集成点

- 与文件系统模块协同工作进行文件权限分析
- 与进程模块对接以关联运行的进程
- 维护基线数据以供将来比较

## Rootkit检测模块

### 概述

Rootkit检测模块专门寻找rootkit感染的迹象，包括隐藏的进程、文件和网络连接。

### 实现细节

- **类**：`RootkitDetector`
- **主要方法**：
  - `analyze()`：运行所有检查的入口点
  - `_check_hidden_processes()`：检测隐藏进程
  - `_check_hidden_ports()`：识别隐藏的网络端口
  - `_check_hidden_files()`：查找隐藏文件
  - `_check_system_commands()`：验证系统命令的完整性
  - `_use_chkrootkit()`：如果可用，运行chkrootkit工具
  - `_use_rkhunter()`：如果可用，运行rkhunter工具
  - `establish_baseline()`：创建正常系统状态的基线
  - `compare_baseline()`：将当前状态与基线进行比较

### 配置选项

```yaml
rootkit:
  # 检查隐藏进程
  check_hidden_processes: true
  
  # 检查隐藏端口
  check_hidden_ports: true
  
  # 检查隐藏文件
  check_hidden_files: true
  
  # 检查修改的系统命令
  check_system_commands: true
  
  # 如果可用，使用chkrootkit
  use_chkrootkit: true
  
  # 如果可用，使用rkhunter
  use_rkhunter: true
  
  # 要验证的系统命令
  commands_to_verify:
    - "ps"
    - "ls"
    - "netstat"
    - "top"
    - "find"
    - "grep"
    - "lsof"
    - "ifconfig"
    - "ss"
    - "ip"
```

### 检测能力

1. **隐藏进程检测**：
   - 识别对标准工具隐藏的进程
   - 检测不同进程枚举方法之间的差异
   - 查找进程隐藏技术的证据

2. **隐藏端口分析**：
   - 检测对标准工具隐藏的网络端口
   - 识别不同端口枚举方法之间的差异
   - 查找网络隐藏技术的证据

3. **隐藏文件检测**：
   - 定位被rootkit隐藏的文件
   - 识别具有可疑命名模式的文件
   - 检测异常的文件系统行为

4. **系统命令验证**：
   - 检查系统命令是否被修改
   - 识别被后门或木马的二进制文件
   - 验证关键系统工具的校验和和完整性

5. **专业工具集成**：
   - 与chkrootkit集成以进行额外的rootkit检测
   - 使用rkhunter识别已知的rootkit签名
   - 结合多种检测方法进行全面覆盖

### 集成点

- 与内核模块协同工作以检测内核级rootkit
- 与进程模块对接以识别隐藏进程
- 维护基线数据以供将来比较

有关详细文档，请参阅[ROOTKIT_DETECTOR_ZH.md](./modules/ROOTKIT_DETECTOR_ZH.md)。