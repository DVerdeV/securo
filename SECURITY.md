# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Securo, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email: **info@usesecuro.com** (or open a private security advisory on GitHub)

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response timeline

- Acknowledgment within 48 hours
- Status update within 7 days
- Fix and disclosure coordinated with the reporter

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | Yes       |

## Best Practices for Self-Hosting

- Keep `SECRET_KEY` and `AGENTS_MCP_JWT_SECRET` secret. Leave them unset to have
  random ones generated on first start (stored in the data volume), or set your own
  with `openssl rand -hex 32`. Placeholder values that older versions shipped are
  ignored, with a warning in the logs
- Use HTTPS in production
- Keep dependencies updated
- Restrict database access to the backend service only
- Review environment variables before deploying
