# Roadmap

## Released

### v0.1 - Domain Core

- Domain entities, branded IDs, ports, policies, and stable errors.
- `AuthService` orchestration for sign-in, linking, unlinking, merge, sessions, and verifications.
- In-memory testing implementation.
- Security tests for account takeover and linking invariants.
- Package exports, CI, `npm run check`, and `npm pack --dry-run`.

### v0.2 - Email OTP Sign-In

- Email OTP sign-in over the `EmailSender` port.
- Neutral start-flow response.
- Hashed OTP verification secrets.
- Consume-once finish flow that creates a local session.
- In-memory email sender for tests, demos, and examples.

### v0.3 - Generic OTP Challenges

- Shared `startOtpChallenge`, `finishOtpChallenge`, and `finishOtpSignIn` API.
- Email OTP sign-in backed by the shared challenge lifecycle.
- Phone OTP sign-in over the `SmsSender` port.
- In-memory SMS sender for tests, demos, and examples.

### v0.4 - Canonical UniAuth API

- Canonical `UniAuth` public API casing.
- Attribution metadata and About/Legal notice helper.
- PolyForm Strict public license metadata and commercial contact docs.

### v0.5 - Internal Orchestration and Package Hygiene

- Decomposed `DefaultAuthService` into focused application use-case modules.
- Shared internal optional-property helper for exact optional TypeScript objects.
- OTP delivery mapping split from OTP lifecycle orchestration.
- Trimmed pre-1.0 public API surface by removing unused credential and provider start-flow
  contracts from the core package.
- Added configurable verification secret hashing with an HMAC helper for app-owned peppers.
- Split broad coverage tests into focused service, provider/policy, in-memory, and utility suites.
- Blank verification targets rejected by the generic verification API.
- `publint` and `attw --pack . --profile esm-only` validate package exports, published files, and
  ESM consumer type resolution.
- Published package files restricted to public entry points, public declaration dependencies, docs,
  examples, and license files.
- Changelog and merge policy documented for the Release Please workflow.

### v0.6 - Local Auth Hardening

- Email magic link on the shared verification lifecycle.
- Password credential with an app-owned `PasswordHasher` port.
- Rate limit integration ports for provider sign-in, OTP, magic-link, password, and recovery
  attempts.
- Unified OTP sign-in API without email-specific wrappers.
- Configurable OTP code generation and email OTP subject.
- Shared verification lifecycle tests for magic link, OTP, and password recovery.
- Public docs for choosing local auth flows without leaking account state.

### v0.7 - Messenger Providers

- Telegram Mini App `initData` contracts and reference implementation.
- MAX WebApp `initData` contracts and reference implementation.
- Shared signed WebApp launch-data validation boundary.
- Messenger provider docs and examples.

Tracking issues: #33, #34, #35, #36.

### v0.8 - OAuth / OIDC Layer

- Provider adapter module layout before adding OAuth/OIDC adapters.
- Generic OAuth/OIDC adapter contract.
- Provider profile mapping into `ProviderIdentityAssertion`.

Tracking issues: #37, #49.

### v0.9 - Trusted Provider Policy

- Trusted provider policy hooks.
- Provider trust context on assertions and linked identities.
- Backward-compatible policy extension point for explicit link decisions.
- Policy and docs alignment for post-OAuth account-linking trust decisions.

Tracking issues: #38.

### v0.10 - Reference Persistence

- Postgres reference storage.
- Indexes and constraints.
- SQL schema example.

Tracking issues: #40, #42.

### v0.11 - Transactional Merge and Testing Boundaries

- Transactional merge flow.
- Merge idempotency and partial-failure prevention.
- Audit coverage for merge decisions without secret leakage.
- In-memory testing kit decomposition aligned with reference persistence boundaries.
- Stable `@alyldas/uniauth/testing` public exports preserved after the testing-kit split.

Tracking issues: #41, #47.

### v0.12 - Optional Auth Bridges

- Optional Better Auth and Auth.js bridge helpers that do not add hard dependencies to core.
- Bridge boundaries that preserve UniAuth account-linking and policy invariants.
- Documentation that explains what external auth libraries own and what UniAuth still owns.

Tracking issues: #39.

### v0.13 - Production Hardening and Normalization

- Threat model documentation.
- Production email and phone normalization boundary, migration guidance, and follow-up strict
  implementation.
- OTP delivery orchestration boundary documented for queue, retry, and dead-letter adapters without
  moving sender side effects into core.
- Anti-takeover tests.
- Merge idempotency tests.
- Audit coverage.
- Shared runtime-level normalization boundary with compatibility defaults and strict app-owned
  wiring.

Tracking issues: #28, #29, #43, #44, #73.

### v0.14 - Integration Recipes and Internal Simplification

- Migration docs and example applications.
- Backend recipes for Express, Fastify, Nest, and Next.
- Public domain and service contract source-module decomposition.
- Password auth use-case decomposition.
- Additional runnable examples for link/unlink and provider-finish wiring.

Tracking issues: #45, #46, #48, #83.

### v0.15 - Example Coverage and Provider Wiring

- HTTP-facing OTP wiring example.
- OAuth/OIDC adapter wiring example using the public provider factory.
- Telegram Mini App and MAX WebApp wiring examples with application-owned token loading and payload
  transport.

Tracking issues: #86, #87, #88.

### v0.16 - Framework Module Examples and Session Transport

- Express auth module example with app-owned sender, cookie, and error-mapping boundaries.
- Fastify auth module example with schema-driven request validation and finish-flow cookie issuance.
- Session transport recipes for browser cookies, bearer/API transport, and mobile/native clients.

Tracking issues: #93, #94, #95.

## Next Release

### v0.17 - Session Read API and Secret Storage Hardening

- Public session read-side API through `AuthService.resolveSession`.
- One-time `sessionToken` return value for sign-in and explicit session creation flows.
- Server-side session token hashing with token-hash lookup in in-memory and Postgres adapters.
- Default verification secret hashing moved from fast SHA-256 storage to salted `scrypt`.
- Package gate alignment between local `npm run check` and CI, including dependency audit.

Tracking issues: #99.

## Versioning

- `0.x`: active stabilization of public contracts.
- `1.0.0`: first stable public API after the core contracts, package exports, and security model are
  considered settled.
- Before `1.0.0`, public API simplifications should still ship as explicit minor releases with a
  changelog entry.
