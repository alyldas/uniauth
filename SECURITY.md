# Security Policy

`@alyldas/uniauth` is an identity orchestration core. Security-sensitive behavior must be explicit,
tested, and documented.

## Supported Versions

The package is pre-1.0. Security fixes target the latest published `0.x` line.

## Reporting

Report security issues privately through the repository security contact or private advisory flow.
You can also contact `alyldas@ya.ru` for private coordination.
Do not disclose takeover, linking, verification, or session bugs publicly before a fix is available.

## Security Scope

Core is responsible for:

- identity/user separation;
- no silent merge;
- policy-driven linking;
- local session records;
- verification secret hashing;
- configurable verification secret hashing for application-owned pepper/key policies;
- neutral public errors;
- audit events for sensitive operations.

Core is not responsible for:

- HTTP cookies;
- CSRF protection;
- provider SDK verification;
- SMTP/SMS transport security;
- database migration hardening.

See [Security model](docs/security.md) for the current threat model and versioned hardening notes.
