# 用户账户分析器模块文档

## 概述

用户账户分析器模块为Linux系统提供全面的用户账户安全分析。它检测可疑的用户账户、未授权的权限提升、弱密码策略、不安全的家目录配置、缺失的多因素认证和可能表明潜在安全漏洞的异常登录模式。

## 主要功能

### 1. Root账户分析
- 检测多个具有UID 0（root权限）的账户
- 验证正确的root账户配置
- 监控root账户安全

### 2. 用户Shell分析
- 检测具有登录shell的系统账户
- 验证有效的登录shell
- 识别可疑的shell配置

### 3. Sudo用户分析
- 检测具有sudo权限的用户
- 监控sudo组成员资格
- 分析sudo配置文件
- 识别意外的sudo组

### 4. 可疑账户检测
- 检测无密码账户
- 识别隐藏用户账户（UID < 1000）
- 检测UID/GID不一致
- 分析可疑的账户属性

### 5. 账户变更监控
- 检测最近修改的账户信息
- 监控密码年龄和变更
- 分析账户添加和修改
- 验证账户到期设置

### 6. 登录活动分析
- 监控最近的登录活动
- 检测失败的登录尝试
- 识别来自可疑来源的登录
- 检测暴力攻击尝试

### 7. 家目录安全分析
- 验证适当的家目录权限
- 检测不安全的SSH密钥存储
- 分析shell配置文件的安全问题
- 识别启动文件中的可疑内容

### 8. 密码策略分析
- 验证密码复杂性要求
- 检查密码老化设置
- 分析PAM配置的密码安全性
- 识别过期或陈旧的密码

### 9. 组成员资格分析
- 检测敏感组中的用户（root、sudo、wheel、docker等）
- 识别可疑的组名
- 分析组成员资格模式
- 基于组成员资格评估权限

### 10. 权限提升检测
- 检测不寻常位置的SUID/SGID二进制文件
- 识别root拥有的全局可写文件
- 分析具有危险能力的二进制文件
- 检测潜在的权限提升向量

### 11. MFA状态检查
- 验证MFA模块的安装和配置
- 识别没有MFA的特权用户
- 检查关键账户上的MFA使用情况
- 分析PAM配置的MFA设置

### 12. 登录模式分析
- 检测非正常时间的登录
- 识别来自多个源IP的登录
- 分析同时活动的会话
- 检测可疑的登录频率模式

### 13. 威胁情报集成
- 检查已知威胁数据库中的登录源
- 将可疑活动与威胁源相关联
- 用威胁上下文丰富安全发现
- 基于威胁情报进行风险评估

## 配置选项

用户账户分析器支持一套全面的配置选项，可以在默认的`config.yaml`文件中找到：

```yaml
user_accounts:
  # 启用/禁用特定检查
  check_sudo: true
  check_shell: true
  check_auth_logs: true
  check_home_security: true
  check_password_policy: true
  check_group_membership: true
  check_privilege_escalation: true
  check_mfa_status: true
  check_login_patterns: true
  
  # 存储基线数据的路径
  baseline_file: "/var/lib/sharpeye/baselines/accounts.json"
  
  # 被认为是正常的预期sudo组
  expected_sudo_groups:
    - "sudo"
    - "wheel"
    - "admin"
  
  # 监控的可疑IP列表
  suspicious_ips:
    - "192.168.1.100"
  
  # 暴力攻击检测阈值
  brute_force_threshold: 5
  
  # 威胁情报集成设置
  threat_intelligence:
    enabled: false
    api_key: ""
    check_login_sources: true
    check_usernames: true
```

## 使用示例

### 基本分析

```python
from modules.user_accounts import UserAccountAnalyzer

# 使用默认配置初始化
analyzer = UserAccountAnalyzer()

# 运行完整分析
results = analyzer.analyze()

# 检查是否发现任何异常
if results['is_anomalous']:
    print("在用户账户中检测到安全问题！")
    
    # 检查root账户问题
    if results['root_accounts'].get('is_anomalous', False):
        print(f"发现 {results['root_accounts']['count']} 个root账户（预期：1）")
    
    # 检查可疑账户
    if results['suspicious_accounts'].get('is_anomalous', False):
        print(f"发现 {results['suspicious_accounts']['total_count']} 个可疑账户")
        print(f"高严重性：{results['suspicious_accounts']['high_severity_count']}")
        print(f"中等严重性：{results['suspicious_accounts']['medium_severity_count']}")
```

### 检查家目录安全问题

```python
from modules.user_accounts import UserAccountAnalyzer

# 初始化分析器
analyzer = UserAccountAnalyzer()

# 仅检查家目录安全
results = analyzer._check_home_directory_security()

# 检查问题
if results['is_anomalous']:
    print(f"发现 {results['total_count']} 个家目录安全问题：")
    for issue in results['issues']:
        username = issue.get('username', '未知')
        issue_desc = issue.get('issue', '未知问题')
        severity = issue.get('severity', '未知')
        print(f" - 用户 {username}：{issue_desc}（严重性：{severity}）")
```

### 建立和比较基线

```python
from modules.user_accounts import UserAccountAnalyzer

# 初始化分析器
analyzer = UserAccountAnalyzer()

# 创建基线
analyzer.establish_baseline()
print("用户账户基线创建成功。")

# 之后，与基线比较
comparison = analyzer.compare_baseline()

# 检查变更
if comparison['is_anomalous']:
    print("用户账户配置自基线以来已更改！")
    
    # 检查新用户
    if comparison.get('new_users', []):
        print("检测到新用户：")
        for user in comparison['new_users']:
            print(f" - {user['username']}（UID：{user.get('uid', '未知')}）")
    
    # 检查修改的用户
    if comparison.get('modified_users', []):
        print("检测到修改的用户：")
        for user in comparison['modified_users']:
            print(f" - {user['username']} 变更了：{', '.join(k for k, v in user.get('changes', {}).items() if v)}")
    
    # 检查新的sudo用户
    if comparison.get('new_sudo_users', []):
        print("检测到新的sudo用户：")
        for user in comparison['new_sudo_users']:
            print(f" - {user['username']}（来源：{user.get('source', '未知')}）")
```

## 安全建议

根据用户账户分析器模块的分析，我们建议以下账户安全最佳实践：

1. **用户账户管理**
   - 只维护一个具有UID 0的账户（root）
   - 禁用直接root登录
   - 实施适当的账户生命周期管理
   - 定期审计用户账户和权限

2. **密码安全**
   - 强制实施强密码策略（长度、复杂性、历史）
   - 配置适当的密码老化（最长90天）
   - 实施账户锁定（在失败尝试后）
   - 禁用空密码和弱配置

3. **家目录安全**
   - 设置适当的权限（0750或更严格）
   - 保护SSH目录和密钥（.ssh目录权限为0700，私钥权限为0600）
   - 监控shell初始化文件中的可疑内容
   - 防止全局可读的家目录

4. **权限管理**
   - 实施最小权限原则
   - 限制sudo访问仅授予必要的用户
   - 尽可能使用带有命令限制的sudo
   - 监控特权组中的用户（wheel、docker等）

5. **SUID/SGID安全**
   - 定期审计SUID/SGID二进制文件
   - 移除不必要的SUID/SGID位
   - 谨慎对待用户家目录中的SUID二进制文件
   - 监控权限设置中的特权访问

6. **多因素认证**
   - 为所有特权账户实施MFA
   - 强制远程访问使用MFA
   - 验证MFA模块配置
   - 定期审计MFA合规性

7. **登录安全**
   - 监控登录时间和模式
   - 配置账户锁定策略
   - 限制来自可疑位置的访问
   - 为敏感账户实施基于IP的访问控制

8. **组管理**
   - 定期审计组成员资格
   - 限制特权组中的成员
   - 实施基于组的适当访问控制
   - 监控可疑的组名或配置

## 威胁情报集成

用户账户分析器可以与威胁情报服务集成，以增强其检测能力。启用威胁情报集成后，分析器可以：

1. 检查登录源IP是否在已知威胁源中
2. 识别来自高风险区域的登录尝试
3. 将用户名与已知攻击模式相关联
4. 为可疑的登录活动提供额外上下文

要启用威胁情报集成，请在SharpEye主配置文件的`threat_intelligence`部分进行配置。

## 性能考虑

用户账户分析器设计为高效，但在具有大量用户或大量登录历史的系统上可能会消耗较多资源。请考虑以下性能提示：

1. 禁用与您的环境不相关的检查
2. 配置适当的基线文件位置
3. 将权限提升检查的范围限制在关键区域
4. 使用分析结果中的性能指标调整配置
5. 在非高峰时段安排基线比较

---

## 发布历史

- **v1.0（2025年5月8日）**：初始发布，具有基本的用户账户安全分析功能
  - Root账户、shell、sudo和可疑账户检测
  - 账户变更监控和登录活动分析
  - 基线创建和比较功能

- **v1.1（2025年5月8日）**：增强功能
  - 添加家目录安全分析
  - 添加密码策略分析
  - 添加组成员资格分析
  - 添加权限提升检测
  - 添加MFA状态检查
  - 添加登录模式分析
  - 添加威胁情报集成
  - 改进性能指标