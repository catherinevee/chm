# CLAUDE Anti-Patterns for CHM

## Purpose
This document defines code anti-patterns that must be avoided in the CHM codebase to maintain high quality standards.

## Critical Anti-Patterns to Avoid

### 1. Placeholder Code
**NEVER** leave placeholder implementations:
```python
# BAD - Anti-pattern
def get_metrics():
    # TODO: Implement this
    pass

# GOOD - Actual implementation
def get_metrics():
    metrics = query_database()
    return process_metrics(metrics)
```

### 2. Empty Exception Handlers
**NEVER** silently swallow exceptions:
```python
# BAD - Anti-pattern
try:
    risky_operation()
except:
    pass

# GOOD - Proper error handling
try:
    risky_operation()
except Exception as e:
    logger.error(f"Operation failed: {e}")
    raise
```

### 3. None Returns Without Purpose
**NEVER** return None as a placeholder:
```python
# BAD - Anti-pattern
def process_data(data):
    # Not implemented yet
    return None

# GOOD - Meaningful return
def process_data(data):
    if not data:
        return []
    return [transform(item) for item in data]
```

### 4. Commented Out Code
**NEVER** leave commented code in production:
```python
# BAD - Anti-pattern
def calculate():
    result = 10
    # result = 20  # Old calculation
    # return result * 2
    return result

# GOOD - Clean code
def calculate():
    result = 10
    return result
```

### 5. Duplicate Code
**NEVER** copy-paste code blocks:
```python
# BAD - Anti-pattern
def process_user(user):
    if user.age > 18:
        user.status = "adult"
    return user

def process_account(account):
    if account.user.age > 18:
        account.user.status = "adult"
    return account

# GOOD - DRY principle
def set_adult_status(obj):
    if obj.age > 18:
        obj.status = "adult"
    return obj
```

### 6. Magic Numbers
**NEVER** use unexplained numeric literals:
```python
# BAD - Anti-pattern
if response_time > 5000:
    alert()

# GOOD - Named constants
MAX_RESPONSE_TIME_MS = 5000
if response_time > MAX_RESPONSE_TIME_MS:
    alert()
```

### 7. Global State Mutation
**NEVER** modify global state unexpectedly:
```python
# BAD - Anti-pattern
connected_users = []

def add_user(user):
    connected_users.append(user)  # Modifies global

# GOOD - Explicit state management
class UserManager:
    def __init__(self):
        self.connected_users = []
    
    def add_user(self, user):
        self.connected_users.append(user)
```

### 8. Inconsistent Naming
**NEVER** mix naming conventions:
```python
# BAD - Anti-pattern
def getUserData():  # camelCase
    user_name = get_name()  # snake_case
    UserAge = get_age()  # PascalCase
    return user_name, UserAge

# GOOD - Consistent snake_case
def get_user_data():
    user_name = get_name()
    user_age = get_age()
    return user_name, user_age
```

### 9. Deep Nesting
**NEVER** create deeply nested code:
```python
# BAD - Anti-pattern
def process():
    if condition1:
        if condition2:
            if condition3:
                if condition4:
                    do_something()

# GOOD - Early returns
def process():
    if not condition1:
        return
    if not condition2:
        return
    if not condition3:
        return
    if condition4:
        do_something()
```

### 10. Broad Exception Catching
**NEVER** catch Exception without reason:
```python
# BAD - Anti-pattern
try:
    database_operation()
except Exception:
    print("Something went wrong")

# GOOD - Specific exceptions
try:
    database_operation()
except DatabaseError as e:
    logger.error(f"Database error: {e}")
    raise
except NetworkError as e:
    logger.error(f"Network error: {e}")
    retry_operation()
```

## Required Patterns

### Always Use:
1. **Logging** instead of print statements
2. **Type hints** for function signatures
3. **Docstrings** for classes and functions
4. **Context managers** for resource handling
5. **Constants** for configuration values

### Always Include:
1. **Error handling** for all external calls
2. **Validation** for all inputs
3. **Tests** for all business logic
4. **Documentation** for all APIs
5. **Security checks** for all user inputs

## Enforcement

These anti-patterns are checked by:
- Code review process
- Automated linting (flake8, pylint)
- Pre-commit hooks
- CI/CD pipeline checks

## Compliance

All code in CHM must:
- Have ZERO occurrences of these anti-patterns
- Pass all automated checks
- Follow Python PEP 8 style guide
- Maintain 80%+ test coverage

---
*This document defines the quality standards for the CHM codebase*