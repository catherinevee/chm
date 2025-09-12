# API v1 Migration Notice

## ⚠️ DEPRECATED - Use backend/api Instead

This directory (`api/v1`) contains compatibility stubs only. The actual implementation has been moved to `backend/api/routers`.

## Migration Required

All files in this directory now redirect to their new locations in `backend/api/routers`. You should update your imports:

### Import Changes Required

```python
# ❌ Old (Deprecated)
from api.v1.auth import router
from api.v1.devices import router
from api.v1.router import api_router

# ✅ New (Recommended)
from backend.api.routers.auth import router
from backend.api.routers.devices import router
from backend.api.main import app
```

## Why This Change?

1. **Eliminate Duplication**: Two parallel API implementations violated DRY principles
2. **Better Implementation**: backend/api has more features and better error handling
3. **CLAUDE.md Compliance**: Reduces anti-pattern violations
4. **Maintenance**: Single source of truth for API implementation

## Compatibility Period

These compatibility stubs will be maintained for:
- **Phase 1** (Current): Deprecation warnings on all imports
- **Phase 2** (1 month): Stronger warnings, testing migration
- **Phase 3** (2 months): Remove compatibility stubs entirely

## Action Required

1. Update all imports from `api.v1` to `backend.api.routers`
2. Test your application thoroughly
3. Remove any dependencies on old API structure

## Getting Help

If you encounter issues during migration:
1. Check the migration guide in `/archive/legacy_api/README.md`
2. Review the new API documentation
3. Compare old and new implementations for differences

## Timeline

- **Deprecated**: December 2024
- **Final Removal**: February 2025