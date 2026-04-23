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
- Email OTP wrappers backed by the shared challenge lifecycle.
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

## Next Release

### v0.6 - Local Auth Hardening

- Email magic link.
- Password credential with Argon2id.
- Rate limit integration ports.
- Shared verification lifecycle tests for magic link, OTP, and password recovery.
- Public docs for choosing local auth flows without leaking account state.

## Planned

### v0.7 - Messenger Providers

- Telegram Mini App `initData` contracts and reference implementation.
- MAX WebApp `initData` contracts and reference implementation.

### v0.8 - OAuth / OIDC Layer

- Generic OAuth/OIDC adapter contract.
- Trusted provider policy.
- Provider profile mapping into `ProviderIdentityAssertion`.
- Optional Better Auth and Auth.js bridge adapters.

### v0.9 - Reference Persistence

- Postgres reference storage.
- SQL schema example.
- Transactional merge flow.
- Indexes and constraints.

### v0.10 - Production Hardening

- Threat model documentation.
- Anti-takeover tests.
- Merge idempotency tests.
- Audit coverage.
- Migration docs and example applications.
- Backend recipes for Express, Fastify, Nest, and Next.

## Examples Backlog

- Link and unlink flow.
- OTP wiring.
- OAuth adapter wiring.
- Telegram and MAX adapter wiring.

## Versioning

- `0.x`: active stabilization of public contracts.
- `1.0.0`: first stable public API after the core contracts, package exports, and security model are
  considered settled.
- Before `1.0.0`, public API simplifications should still ship as explicit minor releases with a
  changelog entry.
