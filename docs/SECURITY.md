# Security Policy

## Supported Versions

We release patches for security vulnerabilities. Currently supported versions:

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| 1.x.x   | :x:                |

## Reporting a Vulnerability

We take the security of CHM seriously. If you believe you have found a security vulnerability, please report it to us as described below.

### Please do NOT:
- Open a public GitHub issue for security vulnerabilities
- Post about the vulnerability on social media

### Please DO:
- Email us at: security@chm-monitor.com
- Include the following information:
  - Type of vulnerability (e.g., SQL injection, XSS, etc.)
  - Full paths of source file(s) related to the vulnerability
  - Location of the affected source code (tag/branch/commit or direct URL)
  - Any special configuration required to reproduce the issue
  - Step-by-step instructions to reproduce the issue
  - Proof-of-concept or exploit code (if possible)
  - Impact of the issue, including how an attacker might exploit it

### What to expect:
- You'll receive a response from us within 48 hours acknowledging your report
- We'll confirm the vulnerability and determine its impact within 7 days
- We'll release a fix as soon as possible, typically within 30 days
- We'll publicly disclose the vulnerability after the fix is released

## Security Measures

### Current Security Features:
- **Authentication**: JWT-based authentication with refresh tokens
- **Authorization**: Role-Based Access Control (RBAC)
- **Encryption**: All sensitive data encrypted at rest using AES-256
- **Password Security**: Bcrypt hashing with salt
- **API Security**: Rate limiting, CORS configuration, input validation
- **SQL Injection Prevention**: Parameterized queries via SQLAlchemy ORM
- **XSS Protection**: Input sanitization and output encoding
- **CSRF Protection**: Token-based CSRF protection
- **Dependency Scanning**: Automated security scanning with Trivy, FOSSA, and pip-audit
- **Container Security**: Regular Docker image scanning
- **Network Security**: TLS/SSL enforcement in production

### Security Best Practices:
1. **Never commit secrets**: Use environment variables for sensitive configuration
2. **Keep dependencies updated**: Regular dependency updates and security patches
3. **Use strong passwords**: Enforce password complexity requirements
4. **Enable MFA**: Multi-factor authentication available for all accounts
5. **Audit logging**: All security-relevant actions are logged
6. **Principle of least privilege**: Users only get necessary permissions

## Security Scanning

Our CI/CD pipeline includes multiple security scanning stages:

### Automated Scans:
- **FOSSA**: License compliance and vulnerability scanning
- **Trivy**: Container and dependency vulnerability scanning
- **Bandit**: Python security linting
- **Safety**: Python dependency security checks
- **pip-audit**: Python package vulnerability scanning
- **CodeQL**: Semantic code analysis for security vulnerabilities

### Manual Security Reviews:
- Code reviews for all PRs
- Periodic penetration testing
- Security architecture reviews

## Compliance

CHM is designed to help meet common compliance requirements:

- **GDPR**: Data privacy and protection features
- **SOC 2**: Security controls and audit logging
- **HIPAA**: Encryption and access controls (when properly configured)
- **PCI DSS**: Secure credential storage and transmission

## Security Headers

Recommended security headers for production deployment:

```nginx
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
Strict-Transport-Security: max-age=31536000; includeSubDomains
Referrer-Policy: strict-origin-when-cross-origin
```

## Contact

For security concerns, please contact:
- Email: security@chm-monitor.com
- GPG Key: [Available on request]

For general support:
- GitHub Issues: https://github.com/catherinevee/chm/issues
- Documentation: https://github.com/catherinevee/chm/wiki