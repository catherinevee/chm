# 100% Actual Code Coverage Implementation Plan

## Current Situation Analysis

### Coverage Status
- **Current Coverage**: 35-36%
- **Problem**: Tests use extensive mocking, preventing actual code execution
- **Root Cause**: Mock-based tests don't execute the real implementation

### Key Issues Identified
1. **Over-mocking**: Services and dependencies are mocked instead of executed
2. **No Real Database**: Tests don't use actual database connections
3. **No API Execution**: Endpoints aren't called through TestClient
4. **Missing Branch Coverage**: If/else branches not tested
5. **Untested Error Paths**: Exception handlers never triggered

---

## Strategy for 100% Real Coverage

### Core Principles
1. **Execute, Don't Mock**: Run actual code wherever possible
2. **Use Test Database**: SQLite in-memory for real DB operations
3. **TestClient for APIs**: Actually call endpoints through FastAPI TestClient
4. **Trigger All Paths**: Execute every branch and error condition
5. **Minimal Mocking**: Only mock external services (email, SMS, etc.)

---

## Implementation Phases

### Phase 1: Test Infrastructure Setup (Foundation)
**Goal**: Create infrastructure for real code execution

#### 1.1 Database Test Setup
```python
# Real database for tests
@pytest.fixture
async def real_test_db():
    """Create real SQLite database for testing"""
    DATABASE_URL = "sqlite+aiosqlite:///:memory:"
    engine = create_async_engine(DATABASE_URL)
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    async_session = sessionmaker(engine, class_=AsyncSession)
    
    async with async_session() as session:
        yield session
    
    await engine.dispose()
```

#### 1.2 TestClient Setup
```python
@pytest.fixture
def test_client(real_test_db):
    """Create TestClient with real app"""
    from main import app
    
    # Override database dependency
    app.dependency_overrides[get_db] = lambda: real_test_db
    
    with TestClient(app) as client:
        yield client
```

#### 1.3 Minimal Mock Configuration
```python
@pytest.fixture
def minimal_mocks():
    """Only mock external services"""
    with patch('backend.services.email_service.send_email') as mock_email:
        mock_email.return_value = True
        yield {'email': mock_email}
```

---

### Phase 2: API Endpoint Coverage (100% execution)
**Goal**: Execute every API endpoint with TestClient

#### 2.1 Authentication Endpoints
```python
def test_all_auth_endpoints(test_client):
    # Register - executes registration code
    response = test_client.post("/api/v1/auth/register", json={
        "username": "testuser",
        "email": "test@example.com",
        "password": "Test123!@#"
    })
    assert response.status_code in [200, 201]
    
    # Login - executes authentication code
    response = test_client.post("/api/v1/auth/login", data={
        "username": "testuser",
        "password": "Test123!@#"
    })
    token = response.json()["access_token"]
    
    # Protected endpoint - executes authorization code
    headers = {"Authorization": f"Bearer {token}"}
    response = test_client.get("/api/v1/auth/me", headers=headers)
    assert response.status_code == 200
    
    # Logout - executes session cleanup
    response = test_client.post("/api/v1/auth/logout", headers=headers)
    assert response.status_code == 200
    
    # Error paths
    # Invalid login - executes error handling
    response = test_client.post("/api/v1/auth/login", data={
        "username": "invalid",
        "password": "wrong"
    })
    assert response.status_code == 401
```

#### 2.2 Device Endpoints (All CRUD operations)
```python
def test_all_device_endpoints(test_client, auth_headers):
    # Create device
    device_data = {
        "name": "test-router",
        "ip_address": "192.168.1.1",
        "device_type": "router"
    }
    response = test_client.post("/api/v1/devices", 
                                json=device_data, 
                                headers=auth_headers)
    device_id = response.json()["id"]
    
    # Get device - executes retrieval code
    response = test_client.get(f"/api/v1/devices/{device_id}", 
                               headers=auth_headers)
    assert response.status_code == 200
    
    # Update device - executes update logic
    response = test_client.put(f"/api/v1/devices/{device_id}",
                              json={"name": "updated-router"},
                              headers=auth_headers)
    assert response.status_code == 200
    
    # List devices - executes query and pagination
    response = test_client.get("/api/v1/devices?page=1&limit=10",
                              headers=auth_headers)
    assert response.status_code == 200
    
    # Delete device - executes soft delete
    response = test_client.delete(f"/api/v1/devices/{device_id}",
                                 headers=auth_headers)
    assert response.status_code == 204
    
    # Error paths
    # Not found - executes 404 handling
    response = test_client.get("/api/v1/devices/invalid-id",
                              headers=auth_headers)
    assert response.status_code == 404
```

#### 2.3 Metrics Endpoints (All operations)
```python
def test_all_metrics_endpoints(test_client, auth_headers, device_id):
    # Record metric
    metric_data = {
        "device_id": device_id,
        "metric_type": "cpu_usage",
        "value": 75.5,
        "timestamp": datetime.utcnow().isoformat()
    }
    response = test_client.post("/api/v1/metrics",
                                json=metric_data,
                                headers=auth_headers)
    assert response.status_code == 201
    
    # Get metrics - with filters
    response = test_client.get(
        f"/api/v1/metrics?device_id={device_id}&metric_type=cpu_usage",
        headers=auth_headers
    )
    assert response.status_code == 200
    
    # Aggregated metrics
    response = test_client.get(
        f"/api/v1/metrics/aggregate?device_id={device_id}&interval=hourly",
        headers=auth_headers
    )
    assert response.status_code == 200
```

---

### Phase 3: Service Layer Coverage (Direct execution)
**Goal**: Execute all service methods with real data

#### 3.1 AuthService Complete Coverage
```python
async def test_auth_service_complete(real_test_db):
    service = AuthService(db=real_test_db)
    
    # Password operations
    hashed = service.get_password_hash("Test123!")
    assert service.verify_password("Test123!", hashed)
    assert not service.verify_password("Wrong", hashed)
    
    # User registration - executes all validation
    user = await service.register_user(
        username="testuser",
        email="test@example.com",
        password="Test123!@#"
    )
    assert user.id is not None
    
    # Duplicate registration - executes conflict handling
    with pytest.raises(ConflictException):
        await service.register_user(
            username="testuser",
            email="test@example.com",
            password="Test123!@#"
        )
    
    # Authentication - executes auth logic
    auth_user = await service.authenticate_user("testuser", "Test123!@#")
    assert auth_user.id == user.id
    
    # Failed auth - executes error path
    auth_user = await service.authenticate_user("testuser", "Wrong")
    assert auth_user is None
    
    # Token operations
    token = service.create_access_token({"sub": str(user.id)})
    payload = service.verify_token(token)
    assert payload["sub"] == str(user.id)
    
    # Expired token - executes expiry handling
    expired_token = service.create_access_token(
        {"sub": str(user.id)},
        expires_delta=timedelta(seconds=-1)
    )
    with pytest.raises(JWTError):
        service.verify_token(expired_token)
```

#### 3.2 DeviceService Complete Coverage
```python
async def test_device_service_complete(real_test_db):
    service = DeviceService(db=real_test_db)
    
    # Create device - executes creation logic
    device = await service.create_device({
        "name": "test-device",
        "ip_address": "192.168.1.1",
        "device_type": "router"
    })
    assert device.id is not None
    
    # Get device - executes retrieval
    fetched = await service.get_device(device.id)
    assert fetched.name == "test-device"
    
    # Update device - executes update logic
    await service.update_device(device.id, {"name": "updated"})
    updated = await service.get_device(device.id)
    assert updated.name == "updated"
    
    # List devices - executes query builder
    devices = await service.list_devices(
        filters={"device_type": "router"},
        page=1,
        limit=10
    )
    assert len(devices) == 1
    
    # Delete device - executes soft delete
    await service.delete_device(device.id)
    deleted = await service.get_device(device.id)
    assert deleted is None  # Soft deleted
    
    # Monitor device - executes monitoring logic
    metrics = await service.monitor_device(device.id)
    assert "status" in metrics
```

---

### Phase 4: Database Operations Coverage
**Goal**: Execute all database queries and operations

#### 4.1 Model Operations
```python
async def test_all_model_operations(real_test_db):
    # User model operations
    user = User(
        username="testuser",
        email="test@example.com",
        hashed_password="hashed"
    )
    real_test_db.add(user)
    await real_test_db.commit()
    
    # Relationships
    role = Role(name="admin")
    user.roles.append(role)
    await real_test_db.commit()
    
    # Query operations
    result = await real_test_db.execute(
        select(User).where(User.username == "testuser")
    )
    found_user = result.scalar_one()
    assert found_user.id == user.id
    
    # Update operations
    found_user.email = "new@example.com"
    await real_test_db.commit()
    
    # Delete operations
    await real_test_db.delete(found_user)
    await real_test_db.commit()
```

#### 4.2 Complex Queries
```python
async def test_complex_database_queries(real_test_db):
    # Joins
    query = select(Device).join(Alert).where(Alert.severity == "critical")
    result = await real_test_db.execute(query)
    
    # Aggregations
    query = select(func.count(Device.id)).where(Device.status == "active")
    count = await real_test_db.scalar(query)
    
    # Subqueries
    subquery = select(Device.id).where(Device.vendor == "cisco").subquery()
    query = select(Alert).where(Alert.device_id.in_(subquery))
    result = await real_test_db.execute(query)
```

---

### Phase 5: Exception and Error Path Coverage
**Goal**: Trigger every exception handler and error condition

#### 5.1 API Error Handlers
```python
def test_all_error_handlers(test_client):
    # 400 Bad Request
    response = test_client.post("/api/v1/auth/register", json={})
    assert response.status_code == 400
    
    # 401 Unauthorized
    response = test_client.get("/api/v1/devices")
    assert response.status_code == 401
    
    # 403 Forbidden
    user_headers = get_user_headers(test_client)  # Non-admin
    response = test_client.get("/api/v1/admin/users", headers=user_headers)
    assert response.status_code == 403
    
    # 404 Not Found
    response = test_client.get("/api/v1/devices/nonexistent")
    assert response.status_code == 404
    
    # 409 Conflict
    # Create duplicate
    test_client.post("/api/v1/devices", json=device_data)
    response = test_client.post("/api/v1/devices", json=device_data)
    assert response.status_code == 409
    
    # 422 Validation Error
    response = test_client.post("/api/v1/devices", json={
        "ip_address": "invalid-ip"
    })
    assert response.status_code == 422
    
    # 500 Internal Server Error
    with patch('some_service.method', side_effect=Exception("Test")):
        response = test_client.get("/api/v1/devices")
        assert response.status_code == 500
```

#### 5.2 Service Exception Handling
```python
async def test_service_exception_handling(real_test_db):
    service = DeviceService(db=real_test_db)
    
    # Database errors
    with patch.object(real_test_db, 'commit', side_effect=IntegrityError("", "", "")):
        with pytest.raises(ConflictException):
            await service.create_device(device_data)
    
    # Validation errors
    with pytest.raises(ValidationException):
        await service.create_device({"ip_address": "invalid"})
    
    # Not found errors
    with pytest.raises(NotFoundException):
        await service.get_device("nonexistent-id")
    
    # Authorization errors
    with pytest.raises(AuthorizationException):
        await service.delete_device(device_id, user_id=non_owner_id)
```

---

### Phase 6: Branch Coverage
**Goal**: Execute every if/else branch

#### 6.1 Conditional Logic Coverage
```python
def test_all_conditional_branches():
    # Test both branches of every if statement
    
    # Example: Password strength validation
    validator = PasswordValidator()
    
    # Weak password branch
    result = validator.validate("weak")
    assert not result.is_strong
    
    # Strong password branch  
    result = validator.validate("Str0ng!P@ssw0rd")
    assert result.is_strong
    
    # Example: Rate limiting
    limiter = RateLimiter()
    
    # Under limit branch
    for i in range(5):
        assert limiter.check_limit("user1") is True
    
    # Over limit branch
    assert limiter.check_limit("user1") is False
    
    # Example: Cache hit/miss
    cache = CacheService()
    
    # Cache miss branch
    result = cache.get("key1")
    assert result is None
    
    # Cache hit branch
    cache.set("key1", "value1")
    result = cache.get("key1")
    assert result == "value1"
```

#### 6.2 Loop Coverage
```python
def test_all_loops():
    # Empty list - loop doesn't execute
    result = process_items([])
    assert result == []
    
    # Single item - loop executes once
    result = process_items([1])
    assert len(result) == 1
    
    # Multiple items - loop executes multiple times
    result = process_items([1, 2, 3])
    assert len(result) == 3
    
    # Break condition
    result = process_until_condition([1, 2, -1, 3])
    assert len(result) == 2  # Stops at -1
    
    # Continue condition
    result = process_with_skip([1, 0, 2, 0, 3])
    assert result == [1, 2, 3]  # Skips 0s
```

---

### Phase 7: Integration Tests
**Goal**: Test complete workflows end-to-end

#### 7.1 Complete User Journey
```python
async def test_complete_user_journey(test_client, real_test_db):
    # 1. Register user
    register_response = test_client.post("/api/v1/auth/register", json={
        "username": "newuser",
        "email": "new@example.com",
        "password": "SecureP@ss123"
    })
    assert register_response.status_code == 201
    
    # 2. Login
    login_response = test_client.post("/api/v1/auth/login", data={
        "username": "newuser",
        "password": "SecureP@ss123"
    })
    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # 3. Create device
    device_response = test_client.post("/api/v1/devices", json={
        "name": "my-router",
        "ip_address": "192.168.1.1",
        "device_type": "router"
    }, headers=headers)
    device_id = device_response.json()["id"]
    
    # 4. Monitor device
    metrics_response = test_client.post("/api/v1/metrics", json={
        "device_id": device_id,
        "metric_type": "cpu_usage",
        "value": 95.0
    }, headers=headers)
    
    # 5. Create alert (auto-triggered by high metric)
    alerts_response = test_client.get(f"/api/v1/alerts?device_id={device_id}",
                                      headers=headers)
    alerts = alerts_response.json()
    assert len(alerts) > 0
    assert alerts[0]["severity"] == "critical"
    
    # 6. Acknowledge alert
    alert_id = alerts[0]["id"]
    ack_response = test_client.post(f"/api/v1/alerts/{alert_id}/acknowledge",
                                    headers=headers)
    assert ack_response.status_code == 200
    
    # 7. Resolve alert
    resolve_response = test_client.post(f"/api/v1/alerts/{alert_id}/resolve",
                                        json={"notes": "Issue fixed"},
                                        headers=headers)
    assert resolve_response.status_code == 200
    
    # 8. View history
    history_response = test_client.get("/api/v1/audit/logs",
                                       headers=headers)
    assert len(history_response.json()) > 0
```

---

### Phase 8: WebSocket Coverage
**Goal**: Test WebSocket connections and messages

```python
def test_websocket_coverage():
    from fastapi.testclient import TestClient
    from main import app
    
    client = TestClient(app)
    
    with client.websocket_connect("/ws") as websocket:
        # Send message
        websocket.send_json({"type": "subscribe", "channel": "alerts"})
        
        # Receive message
        data = websocket.receive_json()
        assert data["type"] == "subscribed"
        
        # Trigger alert broadcast
        test_client.post("/api/v1/test/trigger-alert")
        
        # Receive broadcast
        alert_data = websocket.receive_json()
        assert alert_data["type"] == "alert"
        
        # Close connection
        websocket.close()
```

---

### Phase 9: Background Tasks Coverage
**Goal**: Execute all background tasks

```python
def test_background_tasks():
    from backend.tasks import celery_app
    
    # Device polling task
    result = celery_app.send_task('poll_devices')
    assert result.get(timeout=10) is not None
    
    # Metric aggregation task
    result = celery_app.send_task('aggregate_metrics')
    assert result.get(timeout=10) is not None
    
    # Alert escalation task
    result = celery_app.send_task('escalate_alerts')
    assert result.get(timeout=10) is not None
    
    # Cleanup task
    result = celery_app.send_task('cleanup_old_data')
    assert result.get(timeout=10) is not None
```

---

## Implementation Order

### Priority 1: Core Infrastructure (Day 1)
1. Set up real test database fixture
2. Configure TestClient with minimal mocks
3. Create authentication helpers

### Priority 2: API Coverage (Day 2-3)
1. Auth endpoints (login, register, logout)
2. CRUD endpoints (devices, alerts, metrics)
3. Error handlers (all status codes)

### Priority 3: Service Layer (Day 4-5)
1. AuthService methods
2. DeviceService methods
3. AlertService methods
4. MetricsService methods

### Priority 4: Database Coverage (Day 6)
1. Model operations
2. Relationships
3. Complex queries
4. Transactions

### Priority 5: Edge Cases (Day 7)
1. All error paths
2. All branches
3. All loops
4. All exceptions

### Priority 6: Integration (Day 8)
1. End-to-end workflows
2. WebSocket operations
3. Background tasks

---

## Success Metrics

### Coverage Targets
- **Line Coverage**: 100%
- **Branch Coverage**: 100%
- **Function Coverage**: 100%
- **Class Coverage**: 100%

### Quality Metrics
- All tests pass
- No flaky tests
- Execution time < 5 minutes
- Can run in CI/CD

---

## Common Pitfalls to Avoid

1. **Don't Mock What You're Testing**: Only mock external dependencies
2. **Don't Skip Error Paths**: Test exceptions and error handlers
3. **Don't Ignore Branches**: Test all if/else conditions
4. **Don't Forget Loops**: Test empty, single, and multiple iterations
5. **Don't Miss Edge Cases**: Test boundaries and limits

---

## Verification Process

### Local Verification
```bash
# Run with coverage
pytest --cov=. --cov-report=html --cov-report=term --cov-branch

# Check coverage
coverage report --fail-under=100
```

### CI/CD Integration
```yaml
- name: Test with Coverage
  run: |
    pytest --cov=. --cov-report=xml --cov-branch
    coverage report --fail-under=100
    
- name: Upload to Codecov
  uses: codecov/codecov-action@v3
  with:
    file: ./coverage.xml
    fail_ci_if_error: true
    verbose: true
```

---

## Maintenance Strategy

### Keep Coverage at 100%
1. **Pre-commit Hook**: Check coverage before commit
2. **PR Requirement**: No merge without 100% coverage
3. **Regular Audits**: Weekly coverage reports
4. **Documentation**: Document why any line is excluded

### Coverage Exclusions (if necessary)
```python
# Only exclude if truly unreachable
if TYPE_CHECKING:  # pragma: no cover
    import SomeType

# Or defensive programming that should never execute
else:  # pragma: no cover
    raise RuntimeError("This should never happen")
```

---

## Timeline

### Week 1
- Days 1-2: Infrastructure setup
- Days 3-5: API endpoint coverage

### Week 2  
- Days 6-7: Service layer coverage
- Days 8-9: Database and edge cases
- Day 10: Integration and verification

### Total Effort
- **Estimated**: 10 working days
- **Result**: 100% actual code coverage

---

## Conclusion

This plan focuses on **executing real code** rather than testing mocks. By following this approach:

1. **Every line** of production code will be executed
2. **Every branch** will be tested
3. **Every error** will be triggered
4. **Every feature** will be validated

The result will be **true 100% code coverage** that actually validates the application works correctly, not just that tests exist.