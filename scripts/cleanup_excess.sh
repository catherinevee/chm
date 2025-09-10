#!/bin/bash
# CHM Cleanup Script - Remove components that exceed documented requirements

set -e

echo "CHM Cleanup - Removing unnecessary components"
echo "============================================="

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if we're in the CHM directory
if [ ! -f "main.py" ] || [ ! -d "backend" ]; then
    echo -e "${RED}Error: This script must be run from the CHM root directory${NC}"
    exit 1
fi

echo -e "${YELLOW}This will remove components that exceed the documented CHM requirements.${NC}"
read -p "Do you want to continue? (yes/no): " confirm
if [ "$confirm" != "yes" ]; then
    echo "Cleanup cancelled"
    exit 0
fi

# 1. Remove duplicate services directory
if [ -d "services" ]; then
    echo -e "${GREEN}Removing duplicate services directory...${NC}"
    rm -rf services/
    echo "  ✓ Removed services/ directory"
fi

# 2. Remove redundant alert services
echo -e "${GREEN}Removing redundant alert services...${NC}"
for file in backend/services/alert_engine.py \
            backend/services/alert_escalation_engine.py \
            backend/services/alerting_system.py \
            backend/services/alert_correlation_engine.py; do
    if [ -f "$file" ]; then
        rm "$file"
        echo "  ✓ Removed $(basename $file)"
    fi
done

# 3. Remove advanced features not in scope
echo -e "${GREEN}Removing advanced features not in scope...${NC}"
for file in backend/services/advanced_*.py \
            backend/services/asset_integration.py \
            backend/services/component_discovery.py \
            backend/services/reporting_analytics.py \
            backend/services/topology_service.py \
            backend/services/sla_monitor.py; do
    if [ -f "$file" ]; then
        rm "$file"
        echo "  ✓ Removed $(basename $file)"
    fi
done

# 4. Remove duplicate cache service
if [ -f "backend/services/cache_service.py" ]; then
    echo -e "${GREEN}Removing duplicate cache service...${NC}"
    rm backend/services/cache_service.py
    echo "  ✓ Removed cache_service.py"
fi

# 5. Remove enhanced notification services
echo -e "${GREEN}Removing redundant notification services...${NC}"
for file in backend/services/enhanced_notification_service.py \
            backend/services/notification_dispatcher.py; do
    if [ -f "$file" ]; then
        rm "$file"
        echo "  ✓ Removed $(basename $file)"
    fi
done

# 6. Clean up duplicate monitoring endpoints
echo -e "${GREEN}Cleaning up duplicate API endpoints...${NC}"
for file in backend/api/monitoring_api.py; do
    if [ -f "$file" ]; then
        rm "$file"
        echo "  ✓ Removed $(basename $file)"
    fi
done

# 7. Remove unnecessary workflow files (keep only essential ones)
echo -e "${GREEN}Cleaning up GitHub workflows...${NC}"
if [ -d ".github/workflows" ]; then
    cd .github/workflows
    for file in daily-security-scan.yml \
                weekly-security-audit.yml \
                dependency-review.yml \
                owasp-zap.yml; do
        if [ -f "$file" ]; then
            rm "$file"
            echo "  ✓ Removed $file"
        fi
    done
    cd ../..
fi

# 8. Optional: Remove performance testing (uncomment if desired)
# echo -e "${GREEN}Removing performance testing...${NC}"
# if [ -d "tests/performance" ]; then
#     rm -rf tests/performance/
#     echo "  ✓ Removed performance tests"
# fi

# 9. Optional: Remove Helm charts (uncomment if not using Helm)
# echo -e "${GREEN}Removing Helm charts...${NC}"
# if [ -d "helm" ]; then
#     rm -rf helm/
#     echo "  ✓ Removed Helm charts"
# fi

# 10. Optional: Remove external monitoring stack (uncomment if not needed)
# echo -e "${GREEN}Removing external monitoring stack...${NC}"
# if [ -d "monitoring" ]; then
#     rm -rf monitoring/
#     echo "  ✓ Removed monitoring stack"
# fi

# 11. Clean up Python cache files
echo -e "${GREEN}Cleaning Python cache files...${NC}"
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.pyc" -delete 2>/dev/null || true
echo "  ✓ Cleaned Python cache"

# 12. Update imports in files that might reference removed services
echo -e "${YELLOW}Note: You may need to update imports in the following files:${NC}"
echo "  - main.py"
echo "  - api/v1/router.py"
echo "  - backend/main.py"
echo ""
echo -e "${YELLOW}Run the test suite to ensure everything still works:${NC}"
echo "  python run_chm_tests.py"

echo ""
echo -e "${GREEN}✅ Cleanup completed successfully!${NC}"
echo ""

# Show disk space saved
AFTER_SIZE=$(du -sh . | cut -f1)
echo "Current directory size: $AFTER_SIZE"