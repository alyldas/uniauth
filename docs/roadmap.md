# Roadmap

## v0.1 - Domain Core

- Domain entities, branded IDs, ports, policies, and stable errors.
- `AuthService` orchestration for sign-in, linking, unlinking, merge, sessions, and verifications.
- In-memory testing implementation.
- Security tests for account takeover and linking invariants.
- Package exports, CI, `npm run check`, and `npm pack --dry-run`.

## v0.2 - Email OTP Sign-In

- Email OTP sign-in over the `EmailSender` port.
- Neutral start-flow response.
- Hashed OTP verification secrets.
- Consume-once finish flow that creates a local session.
- In-memory email sender for tests, demos, and examples.

## v0.3 - Additional Local Auth Methods

- Email magic link.
- Phone OTP.
- Password credential with Argon2id.
- Rate limit integration ports.

## v0.4 - Messenger Providers

- Telegram Mini App `initData` contracts and reference implementation.
- MAX WebApp `initData` contracts and reference implementation.

## v0.5 - OAuth / OIDC Layer

- Generic OAuth/OIDC adapter contract.
- Trusted provider policy.
- Provider profile mapping into `ProviderIdentityAssertion`.
- Optional Better Auth and Auth.js bridge adapters.

## v0.6 - Reference Persistence

- Postgres reference storage.
- SQL schema example.
- Transactional merge flow.
- Indexes and constraints.

## v0.7 - Production Hardening

- Threat model documentation.
- Anti-takeover tests.
- Merge idempotency tests.
- Audit coverage.
- Migration docs and example applications.
- Backend recipes for Express, Fastify, Nest, and Next.

## Examples Backlog

- Link and unlink flow.
- Email OTP wiring.
- OAuth adapter wiring.
- Telegram and MAX adapter wiring.

## Versioning

- `0.x`: active stabilization of public contracts.
- `1.0.0`: first stable public API after the core contracts, package exports, and security model are
  considered settled.
- All releases should keep a changelog entry and follow semver-compatible versioning.
