# SSH分析器模块文档

## 概述

SSH分析器模块为SSH服务、配置、密钥、认证日志、连接、隧道和密钥使用模式提供全面的安全分析。它可以检测各种SSH相关的安全问题和异常情况，这些问题可能表明潜在的安全漏洞或配置错误。

## 主要功能

### 1. SSH配置分析
- 检测不安全的SSH服务器配置
- 验证安全的加密算法、MAC和密钥交换算法
- 主机密钥验证和完整性检查
- 配置文件权限验证
- 配置更改的基线比较

### 2. SSH密钥安全分析
- 检测弱密钥类型（DSA、短RSA密钥）
- 验证适当的密钥权限
- 检测未受保护的私钥
- 分析authorized_keys文件的适当限制

### 3. SSH认证日志分析
- 检测暴力破解尝试
- 分析具有可疑模式的成功登录
- 检测无效用户登录尝试
- 历史登录分析和异常检测

### 4. SSH连接监控
- 检测活动SSH连接
- 识别可疑连接
- 分析连接持续时间和模式
- 根用户登录检测
- 异常来源检测

### 5. SSH暴力破解检测
- 历史暴力破解尝试识别
- 基于IP的来源关联
- 基于用户名的关联
- 威胁情报集成

### 6. SSH隧道和端口转发检测
- 分析本地、远程和动态（SOCKS）隧道
- 检测暴露的敏感服务
- 识别可疑的转发配置
- 命令行隧道检测
- 转发设置的配置审查

### 7. SSH密钥使用模式分析
- 跟踪基于密钥的身份验证随时间的变化
- 检测异常的密钥使用模式
- 监控从多个来源使用的密钥
- 分析不寻常时间的登录
- 弱密钥类型使用分析

### 8. SSH密钥自动化分析
- 检测cron作业中使用的SSH密钥
- 分析systemd定时器中的SSH密钥
- 监控自动化脚本中的密钥

### 9. 基线创建和比较
- 创建SSH安全基线
- 检测与基线的变化
- 突出显示安全关键变更
- 主机密钥轮换监控

## 配置选项

SSH分析器支持一套全面的配置选项，可以在默认的`config.yaml`文件中找到：

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
  
  # 配置SSH分析器设置
  auth_log_paths:
    - "/var/log/auth.log"
    - "/var/log/secure"
    - "/var/log/audit/audit.log"
  
  ssh_config_path: "/etc/ssh/sshd_config"
  
  ssh_key_paths:
    - "/etc/ssh"
    - "/root/.ssh"
    - "/home"
  
  # 暴力破解检测设置
  bf_time_window: 300  # 5分钟
  bf_attempt_threshold: 5  # 5次尝试
  
  # 安全加密算法
  secure_ciphers:
    - "chacha20-poly1305@openssh.com"
    - "aes256-gcm@openssh.com"
    - "aes128-gcm@openssh.com"
    - "aes256-ctr"
    - "aes192-ctr"
    - "aes128-ctr"
  
  # 安全MAC算法
  secure_macs:
    - "hmac-sha2-512-etm@openssh.com"
    - "hmac-sha2-256-etm@openssh.com"
    - "umac-128-etm@openssh.com"
    - "hmac-sha2-512"
    - "hmac-sha2-256"
    - "umac-128@openssh.com"
  
  # 安全密钥交换算法
  secure_kex:
    - "curve25519-sha256@libssh.org"
    - "curve25519-sha256"
    - "diffie-hellman-group16-sha512"
    - "diffie-hellman-group18-sha512"
    - "diffie-hellman-group-exchange-sha256"
  
  # 配置推荐
  recommended_settings:
    PermitRootLogin: "no"
    PasswordAuthentication: "no"
    X11Forwarding: "no"
    MaxAuthTries: 3
    AllowAgentForwarding: "no"
    AllowTcpForwarding: "no"
    PermitEmptyPasswords: "no"
    GatewayPorts: "no"
    PermitTunnel: "no"
    LogLevel: "VERBOSE"
    ClientAliveInterval: 300
    ClientAliveCountMax: 2
    LoginGraceTime: 60
```

## 使用示例

### 基本分析

```python
from modules.ssh_analyzer import SSHAnalyzer

# 使用默认配置初始化
analyzer = SSHAnalyzer()

# 运行完整分析
results = analyzer.analyze()

# 检查是否发现任何异常
if results['is_anomalous']:
    print("在SSH配置或使用中检测到安全问题！")
    
    # 如果有，打印配置问题
    if results['config_issues'].get('is_anomalous', False):
        print(f"发现{results['config_issues']['count']}个SSH配置问题")
        for issue in results['config_issues']['issues']:
            print(f" - {issue.get('setting', '未知设置')}: {issue.get('recommendation', '')}")
    
    # 如果有，打印密钥问题
    if results['key_issues'].get('is_anomalous', False):
        print(f"发现{results['key_issues']['count']}个SSH密钥安全问题")
```

### 检查SSH隧道

```python
from modules.ssh_analyzer import SSHAnalyzer

# 初始化分析器
analyzer = SSHAnalyzer()

# 仅检查SSH隧道
results = analyzer._check_ssh_tunnels()

# 检查可疑隧道
if results['is_anomalous']:
    print(f"发现{results['suspicious_count']}个可疑SSH隧道：")
    for tunnel in results['suspicious_tunnels']:
        print(f" - 隧道：{tunnel.get('tunnel_type', '未知')}，来自{tunnel.get('username', '未知用户')}")
        print(f"   风险：{tunnel.get('security_risk', '未知风险')}")
        print(f"   严重性：{tunnel.get('severity', '未知')}")
```

### 建立和比较基线

```python
from modules.ssh_analyzer import SSHAnalyzer

# 初始化分析器
analyzer = SSHAnalyzer()

# 创建基线
analyzer.establish_baseline()
print("基线创建成功。")

# 之后，与基线比较
comparison = analyzer.compare_baseline()

# 检查变更
if comparison['is_anomalous']:
    print("SSH配置自基线以来已更改！")
    
    # 检查配置变更
    if comparison['config_changes'].get('is_anomalous', False):
        for change in comparison['config_changes'].get('changed_settings', []):
            print(f" - 设置{change['setting']}从'{change['old_value']}'更改为'{change['new_value']}'")
            if change.get('security_critical', False):
                print("   (这是一个安全关键更改)")
    
    # 检查主机密钥变更
    for key_change in comparison['config_changes'].get('host_key_changes', []):
        print(f" - 主机密钥({key_change['type']})已更改！")
        print(f"   旧：{key_change.get('old_fingerprint', '未知')}")
        print(f"   新：{key_change.get('new_fingerprint', '未知')}")
```

## 安全建议

根据SSH分析器模块的分析，我们建议采取以下SSH安全最佳实践：

1. **配置安全**
   - 禁用root登录（`PermitRootLogin no`）
   - 禁用密码认证（`PasswordAuthentication no`）
   - 仅使用强加密算法
   - 为SSH配置文件设置适当的权限（0600）
   - 使用ED25519密钥代替RSA/DSA
   - 设置适当的登录宽限时间和最大认证尝试次数

2. **密钥安全**
   - 尽可能使用ED25519密钥
   - 始终使用强密码短语保护私钥
   - 为密钥设置适当的权限（私钥0600，公钥0644）
   - 使用authorized_keys中的`from=`和`command=`选项限制密钥
   - 定期轮换主机密钥

3. **认证安全**
   - 实施fail2ban或类似工具以防暴力破解
   - 监控日志中的可疑登录模式
   - 尽可能将SSH访问限制到特定IP范围
   - 考虑使用端口敲门或单包授权

4. **隧道安全**
   - 除非特别需要，否则禁用TCP转发（`AllowTcpForwarding no`）
   - 禁用网关端口（`GatewayPorts no`）
   - 禁用隧道设备转发（`PermitTunnel no`）
   - 监控未授权的隧道

5. **一般安全**
   - 保持SSH软件更新
   - 使用详细日志记录
   - 考虑更改默认端口（虽然不是强有力的安全措施）
   - 实施适当的网络分段
   - 对关键系统使用带有硬件安全模块的密钥

## 威胁情报集成

SSH分析器可以与威胁情报服务集成，以增强其检测能力。启用威胁情报集成后，分析器可以：

1. 根据已知威胁源检查源IP
2. 识别来自高风险地区的登录尝试
3. 将暴力破解尝试与已知攻击模式关联
4. 为可疑的SSH隧道和连接提供额外的上下文

要启用威胁情报集成，请在SharpEye主配置文件中配置`threat_intelligence`部分。

## 性能考虑

SSH分析器设计为高效，但在分析大型日志文件或具有许多SSH密钥的系统时可能会消耗资源。考虑以下性能提示：

1. 配置适当的日志文件路径，避免不必要的搜索
2. 为暴力破解检测设置合理的阈值
3. 当不扫描整个系统时，限制密钥路径的范围
4. 在非高峰时段安排基线比较
5. 使用分析结果中的性能指标来调整配置

---

## 发布历史

- **v1.0（2025年5月8日）**：初始发布，具有全面的SSH安全分析功能
  - 完整的SSH配置、密钥、认证和连接分析
  - 基线创建和比较功能
  - 威胁情报集成

- **v1.1（2025年5月8日）**：增强功能
  - 添加SSH隧道和端口转发检测
  - 添加SSH密钥使用模式分析
  - 添加性能优化指标
  - 改进威胁情报集成