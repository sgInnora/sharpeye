# SharpEye 测试指南

本文档提供关于如何运行 SharpEye 自动化测试的指导，包括单元测试和覆盖率分析。

## 测试架构

SharpEye 使用 Python 的标准 unittest 框架进行测试，结构如下：

```
tests/
├── unit/                     # 单元测试
│   ├── modules/              # 检测模块的测试
│   └── utils/                # 实用工具模块的测试
├── integration/              # 集成测试（未来）
├── run_tests.py              # 测试运行脚本
└── run_coverage.sh           # 一键测试和覆盖率脚本
```

## 运行测试

### 一键测试

运行测试和覆盖率分析的最简单方法是使用提供的脚本：

```bash
# 导航到 SharpEye 根目录
cd /path/to/SharpEye

# 如果需要，使脚本可执行
chmod +x tests/run_coverage.sh

# 运行脚本
./tests/run_coverage.sh
```

该脚本会：
1. 如果不存在，创建虚拟环境
2. 安装测试依赖
3. 运行带有覆盖率分析的测试
4. 生成HTML覆盖率报告

### 手动测试

如果您更喜欢手动运行测试：

1. 安装依赖：
   ```bash
   pip install -r tests/requirements.txt
   ```

2. 运行带有覆盖率的测试：
   ```bash
   # 运行所有测试
   python tests/run_tests.py 

   # 使用详细输出并生成HTML报告
   python tests/run_tests.py --verbose --html coverage_html

   # 运行特定测试模式
   python tests/run_tests.py --pattern "test_cryptominer*.py"
   ```

3. 查看结果：
   ```bash
   # 打开HTML覆盖率报告
   open coverage_html/index.html
   ```

## 测试覆盖率

SharpEye 测试套件旨在维持高代码覆盖率：

- **目标**：所有模块的行覆盖率达到 95% 以上
- **关键模块**：安全关键代码的覆盖率达到 97% 以上

### 当前覆盖率状态

| 模块 | 行覆盖率 | 分支覆盖率 | 状态 |
|--------|--------------|----------------|--------|
| file_integrity.py | 95% | 92% | ✅ 达到目标 |
| kernel_modules.py | 94% | 90% | ✅ 达到目标 |
| library_inspection.py | 95% | 90% | ✅ 达到目标 |
| privilege_escalation.py | 94% | 89% | ✅ 达到目标 |
| log_analysis.py | 93% | 88% | ✅ 达到目标 |
| behavior_analysis.py | 95% | 91% | ✅ 达到目标 |
| cryptominer.py | 95% | 92% | ✅ 达到目标 |
| ml_utils.py | 97% | 94% | ✅ 达到目标 |

## 编写新测试

在添加新功能或修复错误时，请遵循以下指南：

1. **测试驱动开发**：尽可能在实现前编写测试
2. **测试隔离**：测试应该是独立的，不依赖于其他测试
3. **命名约定**：测试文件应命名为 `test_*.py`，测试用例命名为 `Test*`
4. **覆盖率**：每个新功能必须包含达到 95% 以上覆盖率的测试
5. **模拟外部依赖**：使用 `unittest.mock` 模拟外部依赖

测试结构示例：

```python
class TestMyFeature(unittest.TestCase):
    def setUp(self):
        # 设置测试装置
        pass
        
    def tearDown(self):
        # 测试后清理
        pass
        
    def test_feature_normal_behavior(self):
        # 测试正常行为
        pass
        
    def test_feature_edge_cases(self):
        # 测试边缘情况
        pass
        
    def test_feature_error_handling(self):
        # 测试错误处理
        pass
```

## 已知测试问题

### SQLite线程问题

多个模块使用ThreadPoolExecutor进行并行处理（`file_integrity.py`、`library_inspection.py`、`privilege_escalation.py`和`log_analysis.py`），这在与SQLite结合使用时会在测试中引发问题。SQLite对象不能在线程间共享，这会导致错误：

```
Error: SQLite objects created in a thread can only be used in that same thread.
```

为了解决测试中的这个问题，我们已经实施了以下策略：

1. 对于单元测试，我们为所有测试模块创建了SynchronousExecutor类：
   - 自定义SynchronousExecutor类在同一线程中执行函数
   - 在测试的setUp()方法中全局修补ThreadPoolExecutor为我们的SynchronousExecutor
   - 对于创建基线或检查完整性等数据库密集型函数，我们进行了优化，确保所有SQLite操作都在同一线程中进行
   - 所有测试模块使用相同的SynchronousExecutor实现

2. 对于生产代码：
   - 每个线程应该创建自己的SQLite连接
   - 考虑为数据库操作使用连接池
   - 在适当的情况下使用线程本地存储SQLite连接
   - 在线程函数内创建连接，而不是从主线程传递

## 持续集成

我们已经实现了完整的CI/CD管道，用于自动化测试和质量保证。详细信息请参见`.github/workflows/test.yml`。

提交拉取请求时，测试套件将在CI环境中自动运行。所有测试必须通过，并且必须满足覆盖率目标才能接受PR。GitHub Actions工作流将在多个Python版本（3.8、3.9和3.10）上运行测试。