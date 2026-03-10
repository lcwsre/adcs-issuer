# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in ADCS Issuer, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email us at: **lcwsre@lcwaikiki.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge your report within **48 hours** and aim to provide a fix within **7 days** for critical issues.

## Security Best Practices

When using ADCS Issuer:

1. **Credentials**: Always use Kubernetes Secrets for ADCS credentials. Never hardcode passwords in values files committed to version control.
2. **RBAC**: Use `ClusterAdcsIssuer` with minimal namespace access where possible.
3. **Network**: Ensure ADCS server communication is over HTTPS with valid TLS certificates.
4. **Auth Mode**: Use `kerberos` (SPNEGO) for domain-integrated environments, or `basic` for non-domain-joined clusters. Always ensure TLS is enforced.
