# Security

This repository is an early synthetic demo and must not process sensitive or real tenant data or be deployed publicly. The default interface is unauthenticated and synthetic. An optional, default-off experimental bearer API contains authentication, tenant-scoped authorization and audit, but has not passed comprehensive production security, TLS/proxy, operational or isolation validation. Secure file uploads, quarantine and chain of custody are not implemented. See `SECURITY_STATUS.md` and `BLOCKERS.md` for current limitations.

Bind services to trusted local interfaces. Report vulnerabilities privately to repository maintainers; do not include secrets in issues.
