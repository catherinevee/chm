# CHM Catalyst Health Monitor - Development Makefile
# Provides easy access to development, testing, and quality tools

.PHONY: help install install-dev test test-coverage lint format security docs clean build docker-build docker-run docker-stop deploy-staging deploy-prod

# Default target
help:
	@echo "CHM Catalyst Health Monitor - Development Commands"
	@echo "=================================================="
	@echo ""
	@echo "Installation:"
	@echo "  install          Install production dependencies"
	@echo "  install-dev      Install development dependencies"
	@echo ""
	@echo "Testing:"
	@echo "  test             Run all tests"
	@echo "  test-coverage    Run tests with coverage report"
	@echo "  test-performance Run performance tests"
	@echo "  test-security    Run security tests"
	@echo ""
	@echo "Code Quality:"
	@echo "  lint             Run all linting checks"
	@echo "  format           Format code with Black and Prettier"
	@echo "  type-check       Run type checking"
	@echo ""
	@echo "Security:"
	@echo "  security         Run security scans"
	@echo "  audit            Audit dependencies"
	@echo ""
	@echo "Documentation:"
	@echo "  docs             Build documentation"
	@echo "  docs-serve       Serve documentation locally"
	@echo ""
	@echo "Building:"
	@echo "  build            Build frontend and backend"
	@echo "  docker-build     Build Docker images"
	@echo "  docker-run       Run with Docker Compose"
	@echo "  docker-stop      Stop Docker containers"
	@echo ""
	@echo "Deployment:"
	@echo "  deploy-staging   Deploy to staging"
	@echo "  deploy-prod      Deploy to production"
	@echo ""
	@echo "Quality:"
	@echo "  quality-score    Calculate overall quality score"
	@echo "  badges           Generate and update README badges"
	@echo ""
	@echo "Utilities:"
	@echo "  clean            Clean build artifacts"
	@echo "  reset            Reset development environment"
	@echo "  pre-commit       Install pre-commit hooks"

# Installation
install:
	@echo "Installing production dependencies..."
	pip install -r requirements.txt
	cd frontend && npm ci --only=production

install-dev:
	@echo "Installing development dependencies..."
	pip install -r requirements.txt
	pip install -r requirements-dev.txt
	cd frontend && npm ci
	pre-commit install

# Testing
test:
	@echo "Running tests..."
	pytest backend/tests/ -v
	cd frontend && npm test -- --watchAll=false

test-coverage:
	@echo "Running tests with coverage..."
	pytest backend/tests/ --cov=backend --cov-report=html --cov-report=xml --cov-report=term-missing --cov-fail-under=90
	cd frontend && npm run test:coverage

test-performance:
	@echo "Running performance tests..."
	pytest backend/tests/performance/ --benchmark-only --benchmark-sort=mean

test-security:
	@echo "Running security tests..."
	bandit -r backend/ -f json -o bandit-report.json
	safety check --json --output safety-report.json
	cd frontend && npm audit --audit-level=high

# Code Quality
lint:
	@echo "Running linting checks..."
	black --check --diff backend/
	flake8 backend/ --max-line-length=88 --extend-ignore=E203,W503
	isort --check-only --diff backend/
	mypy backend/ --ignore-missing-imports
	cd frontend && npm run lint

format:
	@echo "Formatting code..."
	black backend/
	isort backend/
	cd frontend && npm run format

type-check:
	@echo "Running type checks..."
	mypy backend/ --ignore-missing-imports
	cd frontend && npm run type-check

# Security
security:
	@echo "Running security scans..."
	bandit -r backend/ -f json -o bandit-report.json
	safety check --json --output safety-report.json
	semgrep scan --config=auto backend/
	cd frontend && npm audit

audit:
	@echo "Auditing dependencies..."
	pip-audit
	safety check
	cd frontend && npm audit

# Documentation
docs:
	@echo "Building documentation..."
	cd docs && make html

docs-serve:
	@echo "Serving documentation..."
	cd docs/_build/html && python -m http.server 8000

# Building
build:
	@echo "Building frontend..."
	cd frontend && npm run build
	@echo "Building backend..."
	python -m py_compile backend/**/*.py

docker-build:
	@echo "Building Docker images..."
	docker build -t chm-backend:latest ./backend
	docker build -t chm-frontend:latest ./frontend

docker-run:
	@echo "Starting Docker containers..."
	docker-compose up -d

docker-stop:
	@echo "Stopping Docker containers..."
	docker-compose down

# Deployment
deploy-staging:
	@echo "Deploying to staging..."
	# Add your staging deployment logic here
	@echo "Staging deployment completed"

deploy-prod:
	@echo "Deploying to production..."
	# Add your production deployment logic here
	@echo "Production deployment completed"

# Quality
quality-score:
	@echo "Calculating quality score..."
	python scripts/calculate_quality_score.py

badges:
	@echo "Generating badges..."
	python scripts/generate_badges.py

# Utilities
clean:
	@echo "Cleaning build artifacts..."
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -delete
	find . -type d -name ".pytest_cache" -delete
	find . -type d -name "htmlcov" -delete
	find . -type f -name "coverage.xml" -delete
	find . -type f -name "*.log" -delete
	cd frontend && rm -rf build/ coverage/ node_modules/

reset:
	@echo "Resetting development environment..."
	make clean
	rm -rf .venv/
	cd frontend && rm -rf node_modules/ package-lock.json
	@echo "Development environment reset. Run 'make install-dev' to reinstall."

pre-commit:
	@echo "Installing pre-commit hooks..."
	pre-commit install
	pre-commit install --hook-type commit-msg

# CI/CD
ci-backend:
	@echo "Running backend CI checks..."
	pytest backend/tests/ --cov=backend --cov-report=xml --cov-report=html --cov-fail-under=90
	black --check --diff backend/
	flake8 backend/ --max-line-length=88 --extend-ignore=E203,W503
	isort --check-only --diff backend/
	mypy backend/ --ignore-missing-imports
	bandit -r backend/ -f json -o bandit-report.json
	safety check --json --output safety-report.json

ci-frontend:
	@echo "Running frontend CI checks..."
	cd frontend && npm ci
	cd frontend && npm run lint
	cd frontend && npm run format:check
	cd frontend && npm run type-check
	cd frontend && npm run test:ci

ci-all: ci-backend ci-frontend
	@echo "All CI checks completed"

# Performance
benchmark:
	@echo "Running benchmarks..."
	pytest backend/tests/performance/ --benchmark-only --benchmark-sort=mean --benchmark-autosave

load-test:
	@echo "Running load tests..."
	locust -f backend/tests/performance/locustfile.py --host=http://localhost:8000

# Monitoring
monitor:
	@echo "Starting monitoring..."
	python -m backend.monitoring.monitoring_server

# Database
db-migrate:
	@echo "Running database migrations..."
	alembic upgrade head

db-rollback:
	@echo "Rolling back database..."
	alembic downgrade -1

db-reset:
	@echo "Resetting database..."
	alembic downgrade base
	alembic upgrade head

# API
api-docs:
	@echo "Generating API documentation..."
	python scripts/check_api_docs.py

# Development
dev-setup:
	@echo "Setting up development environment..."
	make install-dev
	make pre-commit
	make db-migrate
	@echo "Development environment setup complete!"

dev-start:
	@echo "Starting development servers..."
	@echo "Starting backend..."
	python -m backend.main &
	@echo "Starting frontend..."
	cd frontend && npm start &
	@echo "Development servers started!"

# Quick checks
quick-check:
	@echo "Running quick checks..."
	black --check backend/
	flake8 backend/ --max-line-length=88 --extend-ignore=E203,W503 --select=E9,F63,F7,F82
	mypy backend/ --ignore-missing-imports --no-error-summary

# Helpers
check-deps:
	@echo "Checking dependency versions..."
	pip list --outdated
	cd frontend && npm outdated

update-deps:
	@echo "Updating dependencies..."
	pip install --upgrade -r requirements.txt
	pip install --upgrade -r requirements-dev.txt
	cd frontend && npm update

# Environment
env-create:
	@echo "Creating virtual environment..."
	python -m venv .venv
	@echo "Virtual environment created. Activate with: source .venv/bin/activate"

env-activate:
	@echo "Activating virtual environment..."
	@echo "Run: source .venv/bin/activate"

# Git helpers
git-setup:
	@echo "Setting up Git hooks..."
	pre-commit install
	pre-commit install --hook-type commit-msg
	@echo "Git hooks installed!"

git-clean:
	@echo "Cleaning Git repository..."
	git clean -fd
	git reset --hard HEAD

# Backup and restore
backup:
	@echo "Creating backup..."
	tar -czf chm-backup-$(shell date +%Y%m%d-%H%M%S).tar.gz --exclude=node_modules --exclude=.venv --exclude=__pycache__ .

restore:
	@echo "Restoring from backup..."
	@echo "Usage: make restore BACKUP_FILE=filename.tar.gz"
	@if [ -z "$(BACKUP_FILE)" ]; then echo "Please specify BACKUP_FILE"; exit 1; fi
	tar -xzf $(BACKUP_FILE)

# Health checks
health-check:
	@echo "Running health checks..."
	python scripts/health_check.py

# Reports
reports:
	@echo "Generating reports..."
	make quality-score
	make api-docs
	@echo "Reports generated in current directory"

# All-in-one commands
full-test:
	@echo "Running full test suite..."
	make lint
	make test-coverage
	make test-performance
	make security
	make docs
	@echo "Full test suite completed!"

full-build:
	@echo "Running full build..."
	make clean
	make install-dev
	make test
	make build
	make docker-build
	@echo "Full build completed!"

# Development workflow
dev-workflow:
	@echo "Development workflow..."
	make quick-check
	make test
	make format
	make lint
	@echo "Development workflow completed!"

# Production preparation
prod-prep:
	@echo "Preparing for production..."
	make clean
	make install
	make test-coverage
	make security
	make build
	make docker-build
	@echo "Production preparation completed!"

# Help for specific areas
help-testing:
	@echo "Testing Commands:"
	@echo "  test             - Run all tests"
	@echo "  test-coverage    - Run tests with coverage"
	@echo "  test-performance - Run performance tests"
	@echo "  test-security    - Run security tests"

help-quality:
	@echo "Quality Commands:"
	@echo "  lint             - Run linting checks"
	@echo "  format           - Format code"
	@echo "  type-check       - Run type checking"
	@echo "  quality-score    - Calculate quality score"

help-deployment:
	@echo "Deployment Commands:"
	@echo "  build            - Build application"
	@echo "  docker-build     - Build Docker images"
	@echo "  deploy-staging   - Deploy to staging"
	@echo "  deploy-prod      - Deploy to production"
