# SQLite Threading in SharpEye

This document provides comprehensive guidance on handling SQLite connections in multi-threaded environments within the SharpEye project. It addresses common issues, solutions, and best practices.

## Overview of the Issue

SQLite has a fundamental constraint: **SQLite objects created in a thread can only be used in that same thread**. In SharpEye, several modules use ThreadPoolExecutor for parallel processing, which creates a conflict when SQLite connections are passed between threads.

The error typically appears as:
```
Error: SQLite objects created in a thread can only be used in that same thread.
```

Affected modules include:
- `file_integrity.py`
- `library_inspection.py`
- `privilege_escalation.py`
- `log_analysis.py`

## Solutions for Production Code

### 1. Thread-Local SQLite Connections

Create separate SQLite connections in each thread:

```python
def process_in_thread(file_path, data):
    # Create a new SQLite connection inside the thread
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    try:
        # Perform database operations
        cursor.execute("INSERT INTO files VALUES (?, ?, ?)", (file_path, data['hash'], data['size']))
        conn.commit()
    finally:
        cursor.close()
        conn.close()
```

### 2. Connection Pooling

Implement a connection pool with thread-aware behavior:

```python
class SQLiteConnectionPool:
    def __init__(self, database_path, max_connections=10):
        self.database_path = database_path
        self.max_connections = max_connections
        self._local = threading.local()
        self._lock = threading.Lock()
        
    def get_connection(self):
        # Check if this thread already has a connection
        if not hasattr(self._local, 'connection'):
            # Create a new connection for this thread
            self._local.connection = sqlite3.connect(self.database_path)
        return self._local.connection
        
    def close_all(self):
        if hasattr(self._local, 'connection'):
            self._local.connection.close()
            delattr(self._local, 'connection')
```

Usage:
```python
# Initialize the pool
pool = SQLiteConnectionPool(database_path)

def worker_function(data):
    # Get a thread-local connection
    conn = pool.get_connection()
    cursor = conn.cursor()
    
    # Use the connection...
    cursor.execute("SELECT * FROM files")
    
    # No need to close - the pool manages connections per thread
```

### 3. Database Access Layer

Create a database access layer that manages connections internally:

```python
class DatabaseManager:
    def __init__(self, database_path):
        self.database_path = database_path
        self._local = threading.local()
        
    def _get_connection(self):
        if not hasattr(self._local, 'connection'):
            self._local.connection = sqlite3.connect(self.database_path)
        return self._local.connection
    
    def execute(self, query, params=None):
        conn = self._get_connection()
        cursor = conn.cursor()
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        return cursor
    
    def commit(self):
        if hasattr(self._local, 'connection'):
            self._local.connection.commit()
    
    def close(self):
        if hasattr(self._local, 'connection'):
            self._local.connection.close()
            delattr(self._local, 'connection')
```

### 4. Serialized Database Operations

If performance requirements allow, avoid threading for database operations:

```python
def process_files(file_list):
    # Instead of parallel processing, handle one at a time
    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()
    
    try:
        for file_path in file_list:
            # Process files serially
            data = process_file(file_path)
            cursor.execute("INSERT INTO files VALUES (?, ?)", (file_path, data))
        conn.commit()
    finally:
        cursor.close()
        conn.close()
```

## Solutions for Test Code

### 1. SynchronousExecutor Pattern

For unit testing, we've implemented a SynchronousExecutor class that executes tasks in the same thread, avoiding SQLite threading issues:

```python
class SynchronousExecutor:
    def __init__(self, max_workers=None):
        self.max_workers = max_workers

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def submit(self, fn, *args, **kwargs):
        class FakeFuture:
            def __init__(self, result):
                self._result = result

            def result(self):
                return self._result

        # Execute the function synchronously
        result = fn(*args, **kwargs)
        return FakeFuture(result)
```

Usage in test files:

```python
def setUp(self):
    # Patch ThreadPoolExecutor to use our synchronous executor
    self.thread_pool_patcher = patch('concurrent.futures.ThreadPoolExecutor', SynchronousExecutor)
    self.thread_pool_patcher.start()
    
def tearDown(self):
    # Stop the patcher
    self.thread_pool_patcher.stop()
```

### 2. Database Operation Mocking

For faster tests, consider mocking database operations:

```python
@patch('sqlite3.connect')
def test_database_function(self, mock_connect):
    # Setup mock connection and cursor
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_connect.return_value = mock_conn
    mock_conn.cursor.return_value = mock_cursor
    
    # Set up cursor return values
    mock_cursor.fetchall.return_value = [
        ("file1.txt", "hash1", 100),
        ("file2.txt", "hash2", 200)
    ]
    
    # Test the function
    result = my_module.get_files()
    
    # Verify correct queries were made
    mock_cursor.execute.assert_called_with("SELECT * FROM files")
```

### 3. In-Memory Database for Testing

Use in-memory SQLite databases for testing:

```python
def setUp(self):
    # Create an in-memory database for testing
    self.conn = sqlite3.connect(':memory:')
    self.cursor = self.conn.cursor()
    
    # Create test tables
    self.cursor.execute('''
    CREATE TABLE files (
        path TEXT PRIMARY KEY,
        hash TEXT,
        size INTEGER
    )
    ''')
    self.conn.commit()
    
    # Initialize the module with the test database
    self.module = MyModule(database=':memory:')
```

## Best Practices

1. **Never share SQLite connections between threads**
   - Create connections within the thread that will use them
   - Use thread-local storage to manage connections

2. **Properly close connections when done**
   - Implement proper cleanup to avoid resource leaks
   - Use try/finally blocks to ensure connections are closed

3. **Consider performance implications**
   - Database operations often become the bottleneck in multi-threaded applications
   - Benchmark different approaches to find the optimal solution for your use case

4. **Implement robust error handling**
   - Catch and handle SQLite exceptions properly
   - Include retry logic for temporary failures like database locks

5. **Test thoroughly**
   - Test both with SynchronousExecutor and with actual threading
   - Verify correct behavior under load and edge cases

## Module-Specific Recommendations

### File Integrity Module

This module processes many files in parallel. Recommended approach:
- Use a thread-local connection pool
- Create a baseline database first, then read from it in parallel
- For checking, generate results in parallel then write serially

### Library Inspection Module

This module analyzes libraries and their symbols. Recommended approach:
- Use connection pooling
- Keep database operations outside of the analyze_library function
- Collect results in memory, then write to the database serially

### Privilege Escalation Module

This module checks multiple privilege escalation vectors. Recommended approach:
- Create separate connections for each vector check function
- Use a database manager class to abstract connection handling
- Implement proper error handling for database operations

### Log Analysis Module

This module processes log files and correlates events. Recommended approach:
- Process logs in parallel but write events serially
- Use connection pooling for read operations
- Implement a staged approach: collect, analyze, then store

## Conclusion

Managing SQLite connections in a multi-threaded environment requires careful attention to SQLite's threading limitations. By using the patterns and practices described in this document, you can avoid common pitfalls and create robust, reliable code.

Remember that different solutions have different trade-offs in terms of complexity, performance, and maintainability. Choose the approach that best fits your specific requirements and constraints.

## Resources

- [SQLite and Multiple Threads](https://www.sqlite.org/threadsafe.html)
- [Python sqlite3 documentation](https://docs.python.org/3/library/sqlite3.html)
- [Threading in Python](https://docs.python.org/3/library/threading.html)
- [concurrent.futures.ThreadPoolExecutor](https://docs.python.org/3/library/concurrent.futures.html#threadpoolexecutor)