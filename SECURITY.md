# Security policy

## Supported versions

Security fixes are provided for the latest released minor version. The project is pre-`1.0`, so users should update to the newest release when a security fix is published.

## Reporting a vulnerability

Do not open a public issue for suspected vulnerabilities. Use GitHub private vulnerability reporting:

`Security` → `Advisories` → `Report a vulnerability`

Include:

- affected version and configuration;
- minimal reproduction using synthetic data;
- impact and realistic attack scenario;
- suggested mitigation, if known;
- whether public disclosure has already occurred.

Do not include real user data, production credentials, private repository content, or active third-party targets.

## Response goals

Maintainers aim to acknowledge a complete report within seven days. Validation, remediation, and disclosure timing depend on severity and reproducibility. These are goals rather than a service-level agreement.

## Security boundaries

UGC Guard is a defensive helper. It does not replace output encoding, sanitization, framework security controls, authentication, authorization, distributed rate limiting, malware scanning, URL reputation, or professional security review.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and [SECURITY_REVIEW.md](SECURITY_REVIEW.md).
