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

### v0.17 - Session Read API and Secret Storage Hardening

- Public session read-side API through `AuthService.resolveSession`.
- One-time `sessionToken` return value for sign-in and explicit session creation flows.
- Server-side session token hashing with token-hash lookup in in-memory and Postgres adapters.
- Default verification secret hashing moved from fast SHA-256 storage to salted `scrypt`.
- Package gate alignment between local `npm run check` and CI, including dependency audit.

Tracking issues: #99.

### v0.18 - Session Activity

- Public session activity touch API for updating `lastSeenAt` after successful token resolution.

Tracking issues: #104.

### v0.19 - Provider Token Persistence Boundary

- App-owned OAuth/OIDC token persistence helper and typed binding contract.
- Explicit rotation and provider-side revocation ownership outside UniAuth core.
- OAuth/OIDC wiring example updated to persist tokens under callback state and rebind them to the
  local session.

Tracking issues: #106.

### v0.20 - Session Middleware Recipes

- Express and Fastify middleware recipes for mapping `sessionToken` into request auth context.

Tracking issues: #105.

### v0.21 - User Session Read Side

- Public `getUserSessions(userId)` API for listing local sessions of an active user.
- Integrator-facing support for account-security, device-list, and session-management screens
  without reaching into storage adapters directly.

Tracking issues: #118.

### v0.22 - Bulk Session Revocation

- Public bulk local session revocation through `revokeUserSessions(...)`.
- Optional `exceptSessionId` support for sign-out-other-devices account-security flows.

Tracking issues: #122.

### v0.23 - User Read Side

- Public `getUser(userId)` API for loading the active local user snapshot by id.
- Integrator-facing support for middleware and account-screen flows that already use local
  sessions and identities.

Tracking issues: #127.

### v0.24 - Account Security Read Side

- Public `getUserCredentials(userId)` and `getVerification(verificationId)` APIs.
- Account-security recipes for sign-in-method and device-management screens on top of the public
  service layer.

Tracking issues: #131, #132, #133.

### v0.25 - Safe Read-Side Projections

- Public safe projection helpers for account-security and verification-status flows.
- Examples and docs moved from ad hoc serializers to the shared public helper layer.

Tracking issues: #137.

### v0.26 - Account Security Aggregate Read Side

- Public `getAccountSecuritySnapshot(userId)` API for one-shot account-security pages and API
  handlers.
- Examples and docs moved from manual multi-call composition to the aggregate read-side method.

Tracking issues: #148.

### v0.27 - Audit Read Side and Internal Cleanup

- Public audit-event read-side API for trusted security timelines and support tooling.
- Split Postgres persistence by repository slice so storage changes stay smaller and easier to
  review.
- Split core and Postgres integration suites by behavior so regressions are easier to localize.
- Decompose provider sign-in orchestration into smaller internal steps without widening the public
  API.
- Reduce overlap across backend, session, and account-security guides after the new aggregate
  read-side surface landed.

Tracking issues: #149, #150, #151, #152, #162.

### v0.28 - Trusted Inspection Aggregate and Security Hardening

- Public `getAccountInspectionSnapshot({ userId, auditLimit? })` API for trusted backend support
  and admin inspection flows.
- Safe audit-event view projection for operator-facing inspection surfaces without raw metadata by
  default.
- Support/admin inspection docs moved from ad hoc multi-call composition to the aggregate helper.
- Account-security action recipes for revoke, unlink, and password-management flows.
- Additional regression coverage around password, verification-secret, and session-token hash-only
  storage.

Tracking issues: #163, #164, #165, #175.

### Post-v0.28 Maintenance Batch (Completed On Main Without Package Release)

- Decompose the remaining account mutation flows into smaller internal modules with clearer
  ownership boundaries.
- Split the remaining broad service-edge and provider-policy suites into smaller behavior-aligned
  test files.

Tracking issues: #176, #177.

### v0.29 - Session Auth Context Resolution

- Public `resolveSessionContext({ sessionToken, touch?, now? })` API for backend middleware and
  request-auth assembly.
- Neutral collapse of stale local auth state so disabled or missing users behind a still-present
  session record do not leak a different failure shape.
- Framework examples and session-transport recipes moved from manual `resolveSession` +
  `getUser` orchestration to the aggregate helper.
- Focused regression coverage for stale-session and disabled-user auth-context flows across
  in-memory and Postgres-backed service setups.

Tracking issues: #184, #185, #186.

### v0.30 - Audit Timeline Pagination

- Extend `getAuditEvents(...)` with stable cursor semantics for trusted backend timelines.
- Extend `getAccountInspectionSnapshot(...)` with continuation-friendly audit windows so support and
  admin tooling can stay on the aggregate helper for follow-up pages.
- Add parity coverage and operator-facing recipes for cursor boundaries, ordering, and paginated
  inspection flows across in-memory and Postgres-backed service setups.

Tracking issues: #190, #191, #192.

### v0.31 - Audit Page Metadata and Trusted Support Pagination

- Add page-oriented `getAuditEventPage(...)` to the public read-side service surface so trusted
  backend tooling can consume `events + nextCursor` directly.
- Extend `getAccountInspectionSnapshot(...)` with aggregate-owned `nextAuditCursor` metadata so
  operator tooling can stay on the inspection helper for continuation-friendly windows.
- Add raw-vs-aggregate parity coverage for audit page metadata and update support inspection
  recipes so aggregate pagination remains the canonical trusted path.

Tracking issues: #199, #200, #201.

### v0.32 - Verification Resend Windows and Abuse-Control Helpers

- Add public `getVerificationResendWindow(...)` so OTP and magic-link backends can read
  cooldown, expiry, and resend-eligibility state without reaching into repositories.
- Add public rate-limit helper surface for stable key composition and typed extraction of neutral
  `rate_limited` metadata from `UniAuthError`.
- Add focused resend-window and rate-limit parity coverage across in-memory and Postgres-backed
  service setups.
- Add abuse-control recipes for OTP, magic link, and password-recovery flows that preserve
  neutral public behavior while exposing trusted server-side cooldown and retry state.

Tracking issues: #207, #208, #209, #210.

### v0.33 - Resend Execution Flows

- Add public resend execution APIs for OTP challenges, email magic-link sign-in, and email
  password recovery.
- Replace the active pending verification on successful resend while keeping public behavior
  neutral and preserving existing secret-storage invariants.
- Add focused resend replacement, cooldown, and delivery-failure coverage across in-memory and
  Postgres-backed service setups.
- Add backend abuse-control and resend execution recipes for OTP, magic link, and recovery flows.

Tracking issues: #214, #215, #216, #217.

### v0.34 - Verification Cancellation Flows

- Add a trusted public `cancelVerification(...)` API for explicitly invalidating active pending
  verifications without direct repository access.
- Add flow-aware cancellation helpers for OTP, email magic-link sign-in, and email
  password-recovery verifications.
- Add focused cancellation, resend-after-cancel, and audit parity coverage across in-memory and
  Postgres-backed service setups.
- Add trusted backend recipes for cancellation endpoints next to the existing resend and cooldown
  flows.

Tracking issues: #221, #222, #223, #224.

### v0.35 - Package Boundary Hardening

- Keep `v0.35` inside one package; this is boundary hardening, not a monorepo migration.
- Introduce a narrow public contracts boundary that future storage, provider, bridge, and testing
  packages can depend on without importing implementation modules.
- Move pure domain rules out of application support so package extraction does not drag service
  orchestration internals across layers.
- Separate runtime composition from application use cases and replace derived repository patches
  with explicit patch contracts where the persistence boundary needs them.
- Add provider-specific subpath exports and enforce source import boundaries so the public package
  shape matches the intended long-term split.
- Document extraction criteria and migration expectations before any physical multi-package move, so
  future package extraction happens only after the subpath boundary is already explicit.

Tracking issues: #225, #226, #227, #228, #229, #230, #231.

### v0.36 - Current-Account Security Helpers

- Added `getCurrentAccountSecuritySnapshot({ sessionToken, touch?, now? })` for self-service
  account-security routes that already trust a local session token.
- Added token-based self-service session revoke helpers for current-session logout and
  sign-out-other-devices flows without rebuilding session + user ownership checks in every backend.
- Added parity coverage for the current-account helper layer across in-memory and Postgres-backed
  service setups, including stale-session neutrality and current-session markers.
- Updated account-security and session-transport recipes so current-account routes use the aggregate
  helper layer instead of manual multi-call composition.

Tracking issues: #244, #245, #246, #247.

### v0.37 - Current-Account Inspection Helpers

- Added `getCurrentAccountInspectionSnapshot({ sessionToken, touch?, now?, audit? })` so self-service
  security routes can load current-account snapshot state and a bounded audit window through one
  trusted local-session helper.
- Added `getCurrentAccountAuditEventPage({ sessionToken, touch?, now?, ...filters })` so current
  account security timelines can paginate through the same neutral trusted-session boundary without
  re-resolving ownership in each route.
- Added parity coverage for current-account aggregate inspection and page helpers across in-memory and
  Postgres-backed service setups, including stale-session neutrality and current-session markers.
- Updated account-security, session-transport, backend, and architecture docs so self-service
  security routes use the current-account inspection layer instead of mixing admin inspection with
  manual session resolution.

Tracking issues: #251, #252, #253, #254.

### v0.38 - Current-Account Action Helpers

- Added token-based current-account write-side helpers for selected-session revoke, sign-in-method
  unlink, and local password setup or change after transport resolution.
- Added parity and neutrality coverage for those helpers across in-memory and Postgres-backed
  service setups, including disabled-account session-token paths.
- Updated account-security, backend, session-transport, and README recipes so self-service routes
  stay on the trusted `sessionToken` boundary instead of bouncing back to raw `userId` mutations.

Tracking issues: #258, #259, #260, #261.

### v0.39 - Current-Account Re-Auth Helpers

- Added trusted current-account OTP re-auth helpers so self-service security routes can bootstrap
  recent-auth challenges from a local `sessionToken` boundary instead of rebuilding owned-target
  verification flows in application code.
- Added a current-account password re-auth confirmation helper that proves the current password on
  the trusted session boundary without mutating local credentials or widening neutral failure
  shapes.
- Added parity and neutrality coverage for current-account re-auth helpers across in-memory and
  Postgres-backed service setups, including stale-session, disabled-account, and owned-target edge
  cases.
- Added canonical backend and account-security recipes for app-owned recent-auth persistence, OTP
  re-auth challenge routes, and sensitive current-account actions that consume `reAuthenticatedAt`.

Tracking issues: #265, #266, #267, #268.

### v0.40 - Current-Account Recent-Auth Guards

- Added a trusted current-account recent-auth status helper so self-service routes can ask whether
  a specific sensitive action currently requires recent auth without duplicating policy checks or
  owned-session resolution in application code.
- Added a trusted current-account recent-auth assertion helper so backend routes can enforce the
  same `ReAuthRequired` policy boundary and audit trail before app-owned side effects continue.
- Added parity and neutrality coverage for the recent-auth helper layer across in-memory and
  Postgres-backed service setups, including stale-session, disabled-account, and token-based
  password-action paths.
- Added canonical docs for current-account recent-auth status reads and guard assertions while
  keeping `reAuthenticatedAt` persistence app-owned.

Tracking issues: #273, #274, #275, #276.

### v0.41 - Current-Account Identity Linking

- Added a trusted `linkCurrentIdentityByToken(...)` helper so self-service account-management
  routes can keep identity linking on the same `sessionToken` boundary as current-account
  inspection, session revoke, password actions, and recent-auth helpers.
- Added provider-finish parity for that helper so OAuth/OIDC, messenger, and other adapter-backed
  identity linking can stay on the trusted current-account boundary instead of dropping back to raw
  `userId` orchestration.
- Added focused in-memory and Postgres parity coverage for same-user relinks, exact already-linked
  conflicts, policy-denied paths, and stale or disabled current-account neutrality.
- Added canonical account-security, backend, architecture, and local-auth docs for current-account
  re-auth plus self-service identity linking route recipes.

Tracking issues: #280, #281, #282, #283.

## Next Release

### v0.42 - Backlog To Be Defined

- Define the next releasable feature set after current-account identity linking.
- Keep `v0.42` scoped to product-facing additions rather than another maintenance-only batch.

Tracking issues: none yet.

## Versioning

- `0.x`: active stabilization of public contracts.
- `1.0.0`: first stable public API after the core contracts, package exports, and security model are
  considered settled.
- Before `1.0.0`, public API simplifications should still ship as explicit minor releases with a
  changelog entry.
