# Threat Model

This document describes the attacker-centric view of UniAuth.

Use it together with the [Security model](security.md), [Architecture](architecture.md), and
[Local auth flows](local-auth.md).

## Security Boundary

UniAuth owns:

- local users, identities, credentials, verifications, sessions, and audit events;
- exact `(provider, providerUserId)` identity matching;
- policy-driven link, unlink, re-auth, and merge orchestration;
- verification lifecycle and hash-only secret persistence;
- rate-limit integration points and transaction boundaries.

The application still owns:

- HTTP handlers, cookies, CSRF, browser headers, and frontend UX;
- provider SDK setup, OAuth state/nonce, and callback transport;
- SMTP/SMS vendors, queues, retries, bounce handling, and dead-letter processing;
- database rollout, migrations, indexes, isolation tuning, and operational monitoring;
- secret loading, pepper rotation, token storage, and key management.

## Protected Assets

- user-to-identity ownership;
- provider identity uniqueness;
- verification secrets and password hashes;
- local session validity and revocation state;
- merge and unlink authorization decisions;
- audit integrity without secret leakage.

## Main Threats

### Account Takeover Through Attribute Matching

Threat:

- an attacker presents a verified-looking email or phone claim and tries to get attached to an
  existing local user without proving ownership of the exact provider identity.

UniAuth response:

- exact `(provider, providerUserId)` match wins before any email or phone hint;
- default policy does not auto-link by email or phone;
- merge is explicit and denied by default;
- trust context can tighten auto-link, explicit link, and merge decisions.

Current coverage:

- [test/core.test.ts](../test/core.test.ts)
- [test/provider-policy.test.ts](../test/provider-policy.test.ts)
- [test/bridges.test.ts](../test/bridges.test.ts)

Residual risk:

- provider trust assignment is still application-owned;
- the normalization boundary is now documented in [Normalization boundary](normalization.md), but
  strict validator/canonicalizer rollout is still application-owned or future work.

### Provider Identity Confusion

Threat:

- framework callbacks or provider adapters provide inconsistent subject fields, or an integrator
  accidentally maps the wrong provider identifier into UniAuth.

UniAuth response:

- OAuth/OIDC provider contracts map validated provider subjects into one stable assertion shape;
- bridge helpers reject mismatched Auth.js and Better Auth subjects instead of silently choosing
  one;
- provider namespace remains explicit, so application-specific provider IDs can stay distinct from
  framework-owned IDs.

Current coverage:

- [test/oauth-oidc.test.ts](../test/oauth-oidc.test.ts)
- [test/messenger.test.ts](../test/messenger.test.ts)
- [test/bridges.test.ts](../test/bridges.test.ts)

Residual risk:

- provider signature validation, OAuth state/nonce validation, token storage, and callback CSRF
  remain outside core and must be handled by the application.

### Verification Abuse

Threat:

- attackers enumerate accounts through OTP, magic-link, or recovery starts;
- replay or brute-force verification codes;
- persist recovery or sign-in secrets in plaintext.

UniAuth response:

- start responses stay neutral;
- verification secrets are stored only as hashes;
- finish flows consume valid secrets once;
- rate-limit decisions can deny start and finish before side effects or secret consumption.

Current coverage:

- [test/core.test.ts](../test/core.test.ts)
- [test/magic-link.test.ts](../test/magic-link.test.ts)
- [test/password.test.ts](../test/password.test.ts)
- [test/rate-limit.test.ts](../test/rate-limit.test.ts)
- [test/otp-options.test.ts](../test/otp-options.test.ts)

Residual risk:

- delivery retries, queue isolation, abuse controls at SMTP/SMS providers, and dead-letter policy
  remain application-owned;
- delivery orchestration boundary is documented in [OTP delivery boundary](otp-delivery.md), but
  provider-specific workers, retries, and webhooks still remain outside core.

### Session Creation, Revocation, and Residual Access

Threat:

- sign-in succeeds without a local session record;
- revoked or merged accounts retain live local sessions;
- applications assume core revocation also deletes browser cookies or remote sessions.

UniAuth response:

- successful sign-in creates a local session record;
- explicit `revokeSession()` changes local session state;
- merge revokes active source sessions inside the same transaction-aware flow.

Current coverage:

- [test/core.test.ts](../test/core.test.ts)
- [test/service-edges.test.ts](../test/service-edges.test.ts)
- [test/postgres.test.ts](../test/postgres.test.ts)
- [test/postgres-store.test.ts](../test/postgres-store.test.ts)

Residual risk:

- browser cookie deletion, gateway token revocation, and distributed session invalidation remain
  outside core and must be coordinated by the application.

### Merge and Unlink Abuse

Threat:

- a user unlinks the last active sign-in method and locks themselves out;
- a merge partially moves state and leaves the source account in an inconsistent condition;
- audit logs leak secrets during merge denial or retry handling.

UniAuth response:

- default unlink policy blocks removal of the last active identity;
- merge is explicit, policy-gated, and re-auth protected by default;
- transaction-aware stores can keep merge writes atomic;
- merge audit metadata stays structural and secret-free.

Current coverage:

- [test/core.test.ts](../test/core.test.ts)
- [test/provider-policy.test.ts](../test/provider-policy.test.ts)
- [test/service-edges.test.ts](../test/service-edges.test.ts)
- [test/postgres.test.ts](../test/postgres.test.ts)

Residual risk:

- operational confidence still depends on stronger anti-takeover and merge idempotency regression
  coverage tracked in `#44`;
- production databases must enforce the expected uniqueness and transaction guarantees.

## Production Hardening Assumptions

UniAuth is safer in production only if the application also does the following:

- runs behind HTTPS and owns secure cookie/session transport;
- provides a real `RateLimiter` backed by application storage or infrastructure;
- uses a stronger verification `SecretHasher`, for example `createHmacSecretHasher` with an
  application-owned pepper;
- chooses and tunes the password hashing runtime and parameters;
- validates OAuth state/nonce and provider-specific signatures before creating assertions;
- stores provider tokens outside UniAuth if they must survive past profile fetch;
- applies database constraints and operational alerts around identity uniqueness, verification
  growth, and merge failures.

## Non-Goals

This threat model does not claim that UniAuth solves:

- UI and browser security;
- framework ownership of routes, middleware, cookies, or session transport;
- ORM lock-in or one mandatory database schema;
- provider SDK lock-in or provider-hosted token lifecycle management.
