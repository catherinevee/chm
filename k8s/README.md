# CHM Kubernetes Deployment

This directory contains Kubernetes manifests for deploying the CHM (Catalyst Health Monitor) application to a Kubernetes cluster.

## Prerequisites

- Kubernetes cluster (1.21+)
- kubectl configured
- Helm (optional, for cert-manager and ingress-nginx)
- Persistent volume provisioner

## Quick Start

### 1. Deploy using kubectl

```bash
# Create namespace and deploy all resources
kubectl apply -f namespace.yaml
kubectl apply -f .

# Or use kustomize
kubectl apply -k .
```

### 2. Deploy using Kustomize

```bash
# Preview the deployment
kubectl kustomize .

# Deploy
kubectl apply -k .
```

## Components

### Core Application
- **deployment.yaml**: Main CHM application (3 replicas)
- **celery.yaml**: Background task workers and scheduler
- **postgres.yaml**: PostgreSQL database (StatefulSet)
- **redis.yaml**: Redis cache and message broker

### Networking
- **ingress.yaml**: NGINX ingress configuration with TLS
- **network-policy.yaml**: Network segmentation and security

### Configuration
- **namespace.yaml**: CHM namespace definition
- **rbac.yaml**: Service accounts and RBAC permissions
- **kustomization.yaml**: Kustomize configuration

### Monitoring & Scaling
- **monitoring.yaml**: Prometheus ServiceMonitor and alerts
- **hpa.yaml**: Horizontal Pod Autoscaler configurations
- **pod-disruption-budget.yaml**: Availability guarantees

## Configuration

### Secrets

Before deploying, update the secrets in `deployment.yaml`:

```yaml
stringData:
  database-url: "postgresql://user:password@postgres-service:5432/chm_db"
  secret-key: "your-super-secret-key-change-in-production"
```

### ConfigMaps

Application configuration is managed through ConfigMaps:

```yaml
data:
  redis-url: "redis://redis-service:6379/0"
  allowed-hosts: "chm.local,*.chm.local"
```

### Environment Variables

Key environment variables:
- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string
- `SECRET_KEY`: JWT signing key
- `ENVIRONMENT`: Deployment environment (production/staging)
- `LOG_LEVEL`: Application log level

## Ingress Configuration

The application is exposed via NGINX ingress:

- **API**: `https://api.chm.local`
- **Metrics**: `https://chm.local/metrics`

### TLS Certificate

Using cert-manager:

```bash
# Install cert-manager
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml

# Create ClusterIssuer
kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@chm.local
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: nginx
EOF
```

## Monitoring

### Prometheus Integration

The deployment includes:
- ServiceMonitor for metrics scraping
- PrometheusRule for alerting
- Grafana dashboard configuration

Metrics endpoint: `/api/v1/monitoring/metrics`

### Health Checks

- **Liveness**: `/api/v1/monitoring/liveness`
- **Readiness**: `/api/v1/monitoring/readiness`

## Scaling

### Horizontal Pod Autoscaler

Auto-scaling configuration:
- **CHM App**: 3-10 replicas (CPU: 70%, Memory: 80%)
- **Celery Workers**: 2-8 replicas (CPU: 80%, Memory: 85%)

### Manual Scaling

```bash
# Scale the main application
kubectl scale deployment chm-app -n chm --replicas=5

# Scale Celery workers
kubectl scale deployment celery-worker -n chm --replicas=4
```

## Storage

### Persistent Volumes

- **PostgreSQL**: 20Gi for database storage
- **Audit Logs**: 10Gi for compliance logging

### Volume Claims

```bash
# Check PVC status
kubectl get pvc -n chm

# Resize a PVC (if supported)
kubectl patch pvc postgres-storage-postgres-0 -n chm -p '{"spec":{"resources":{"requests":{"storage":"50Gi"}}}}'
```

## Security

### Network Policies

Implemented network segmentation:
- Frontend → Backend (port 8000)
- Backend → Database (port 5432)
- Backend → Redis (port 6379)
- Backend → External networks (SNMP/SSH)

### RBAC

Service account permissions:
- Read access to pods, services, endpoints
- ConfigMap management
- Secret read access

## Troubleshooting

### Check Pod Status

```bash
# View all pods
kubectl get pods -n chm

# Check pod logs
kubectl logs -n chm deployment/chm-app

# Describe pod
kubectl describe pod -n chm <pod-name>
```

### Database Connection

```bash
# Connect to PostgreSQL
kubectl exec -it -n chm postgres-0 -- psql -U chm_user -d chm_db

# Check database status
kubectl exec -n chm postgres-0 -- pg_isready
```

### Redis Connection

```bash
# Connect to Redis
kubectl exec -it -n chm deployment/redis -- redis-cli

# Check Redis status
kubectl exec -n chm deployment/redis -- redis-cli ping
```

### Application Debugging

```bash
# Port forward to access locally
kubectl port-forward -n chm service/chm-service 8000:8000

# Access the application
curl http://localhost:8000/health
```

## Backup and Recovery

### Database Backup

```bash
# Create backup
kubectl exec -n chm postgres-0 -- pg_dump -U chm_user chm_db > backup.sql

# Restore backup
kubectl exec -i -n chm postgres-0 -- psql -U chm_user chm_db < backup.sql
```

### Application State

```bash
# Export configurations
kubectl get configmap -n chm -o yaml > configmaps-backup.yaml
kubectl get secret -n chm -o yaml > secrets-backup.yaml
```

## Maintenance

### Rolling Updates

```bash
# Update image
kubectl set image deployment/chm-app -n chm chm=chm:v2.1.0

# Check rollout status
kubectl rollout status deployment/chm-app -n chm

# Rollback if needed
kubectl rollout undo deployment/chm-app -n chm
```

### Drain Node for Maintenance

```bash
# Cordon node
kubectl cordon <node-name>

# Drain pods
kubectl drain <node-name> --ignore-daemonsets --delete-emptydir-data

# Uncordon after maintenance
kubectl uncordon <node-name>
```

## Production Checklist

- [ ] Update all secrets and passwords
- [ ] Configure proper domain names in ingress
- [ ] Set up TLS certificates
- [ ] Configure resource limits appropriately
- [ ] Enable monitoring and alerting
- [ ] Set up backup strategy
- [ ] Configure network policies
- [ ] Review and apply security policies
- [ ] Test disaster recovery procedures
- [ ] Document operational procedures

## Support

For issues or questions:
- Check application logs: `kubectl logs -n chm deployment/chm-app`
- Review metrics: `https://chm.local/metrics`
- Monitor alerts in Prometheus/Grafana