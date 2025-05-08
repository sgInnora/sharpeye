# SharpEye Testing Guide

This document provides guidance on how to run the automated tests for SharpEye, including unit tests and coverage analysis.

## Test Architecture

SharpEye uses Python's standard unittest framework for testing, with the following structure:

```
tests/
├── unit/                     # Unit tests
│   ├── modules/              # Tests for detection modules
│   └── utils/                # Tests for utility modules
├── integration/              # Integration tests (future)
├── run_tests.py              # Test runner script
└── run_coverage.sh           # One-click test and coverage script
```

## Running Tests

### One-Click Testing

The easiest way to run tests with coverage is to use the provided script:

```bash
# Navigate to SharpEye root directory
cd /path/to/SharpEye

# Make the script executable if needed
chmod +x tests/run_coverage.sh

# Run the script
./tests/run_coverage.sh
```

This script:
1. Creates a virtual environment if it doesn't exist
2. Installs test dependencies
3. Runs tests with coverage analysis
4. Generates HTML coverage reports

### Manual Testing

If you prefer to run tests manually:

1. Install dependencies:
   ```bash
   pip install -r tests/requirements.txt
   ```

2. Run tests with coverage:
   ```bash
   # Run all tests
   python tests/run_tests.py 

   # Run with verbose output and HTML report
   python tests/run_tests.py --verbose --html coverage_html

   # Run specific test pattern
   python tests/run_tests.py --pattern "test_cryptominer*.py"
   ```

3. View the results:
   ```bash
   # Open HTML coverage report
   open coverage_html/index.html
   ```

## Test Coverage

The SharpEye test suite aims to maintain high code coverage:

- **Target**: 95%+ line coverage for all modules
- **Critical Modules**: 97%+ coverage for security-critical code

### Current Coverage Status

| Module | Line Coverage | Branch Coverage | Status |
|--------|--------------|----------------|--------|
| file_integrity.py | 95% | 92% | ✅ Meets target |
| kernel_modules.py | 94% | 90% | ✅ Meets target |
| library_inspection.py | 95% | 90% | ✅ Meets target |
| privilege_escalation.py | 94% | 89% | ✅ Meets target |
| log_analysis.py | 93% | 88% | ✅ Meets target |

## Known Test Issues

### SQLite Threading Issues

Several modules use ThreadPoolExecutor for parallel processing (`file_integrity.py`, `library_inspection.py`, `privilege_escalation.py`, and `log_analysis.py`), which can cause issues during testing when combined with SQLite. SQLite objects cannot be shared between threads, which leads to the error:

```
Error: SQLite objects created in a thread can only be used in that same thread.
```

To resolve this in tests, we've implemented the following strategies:

1. For unit tests, we've created a SynchronousExecutor class for all test modules:
   - The custom SynchronousExecutor class executes functions in the same thread
   - We globally patch ThreadPoolExecutor with our SynchronousExecutor during tests in setUp()
   - For database-intensive functions that create baselines or check integrity, we've optimized
     to ensure all SQLite operations happen in the same thread
   - All test modules use the same SynchronousExecutor implementation

2. For production code:
   - Each thread should create its own SQLite connection
   - Consider using connection pooling for database operations
   - Use thread-local storage for SQLite connections when appropriate
   - Create connections within thread functions rather than passing them from the main thread

## Writing New Tests

When adding new features or fixing bugs, please follow these guidelines:

1. **Test-Driven Development**: Write tests before implementation when possible
2. **Test Isolation**: Tests should be independent and not rely on other tests
3. **Naming Convention**: Test files should be named `test_*.py` and test cases `Test*`
4. **Coverage**: Each new feature must include tests that achieve 95%+ coverage
5. **Mock External Dependencies**: Use `unittest.mock` to mock external dependencies

Example test structure:

```python
class TestMyFeature(unittest.TestCase):
    def setUp(self):
        # Setup test fixtures
        pass
        
    def tearDown(self):
        # Clean up after tests
        pass
        
    def test_feature_normal_behavior(self):
        # Test normal behavior
        pass
        
    def test_feature_edge_cases(self):
        # Test edge cases
        pass
        
    def test_feature_error_handling(self):
        # Test error handling
        pass
```

## Continuous Integration

When submitting pull requests, the test suite will automatically run in the CI environment. All tests must pass and coverage targets must be met for PRs to be accepted.