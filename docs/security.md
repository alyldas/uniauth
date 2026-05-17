# Security Model

For the attacker-centric view, trust boundaries, production hardening assumptions, and residual
risks, see [Threat model](threat-model.md).

## Invariants

- User IDs are local and never derived from external provider IDs.
- Exact `(provider, providerUserId)` match wins before profile matching.
- Successful sign-in always creates a local session record.
- Auto-linking is disabled unless policy explicitly allows it.
- Existing users are never silently merged by email or phone.
- The last active identity cannot be unlinked under the default policy.
- Merge is an explicit operation and disabled by default.
- Client session tokens are returned once and stored only as hashes.
- Verification secrets are stored as hashes.
- Verification hashing uses salted `scrypt` by default and can be replaced through `SecretHasher`
  when an application needs peppered or storage-specific hashing.
- OTP start responses are neutral and do not expose whether an account exists.
- OTP finish consumes a sign-in verification once before creating a local session.
- Phone OTP uses the same verification lifecycle as email OTP.
- Email magic links use hashed verification secrets and consume-once finish semantics.
- Password credentials store only adapter-produced password hashes and never expose password hashes
  as sign-in secrets.
- Password sign-in uses neutral invalid-credential errors for missing users, wrong passwords, and
  inconsistent credential state.
- Password recovery uses hashed verification secrets and consume-once finish semantics.
- Current-account contact changes update local email or phone only after OTP proof of the new
  target.
- OTP delivery failures do not expose account state; the app-owned sender adapter decides retry,
  dead-letter, and cleanup behavior.
- Queue-backed delivery may wrap sender ports, but delivery attempts and exhausted-delivery state
  remain outside core.
- Rate-limit denials do not create users or sessions, do not consume pending verifications, and do not
  reveal whether a target account exists.
- Trusted resend cooldown reads stay server-owned and do not require exposing raw verification
  entities or repository reach-through to clients.
- Public errors avoid exposing which user owns an identity.

## Policy Matrix

- Auto-link by verified email/phone: denied by default; extension point:
  `AuthPolicy.canAutoLink`. The context includes the incoming assertion trust and the matched
  existing identities so policy can reject low-trust provider claims.
- Link provider identity: allowed by default; extension point: `AuthPolicy.canLinkIdentity`.
- Unlink identity: allowed only when another active identity remains; extension point:
  `AuthPolicy.canUnlinkIdentity`.
- Merge users: denied by default; extension point: `AuthPolicy.canMergeUsers`. `mergeAccounts(...)`
  requires `sourceSessionToken` for active source accounts and should only be available through
  trusted backend/admin flows when product policy requires stronger approval. The merge context
  includes source and target active identities so policy can inspect provider trust and metadata.
- Re-auth: required for merge by default; extension point: `AuthPolicy.requiresReAuth`.
- Current-account contact change: allowed by default after trusted session resolution and OTP proof;
  optional recent-auth enforcement uses `AuthPolicy.requiresReAuth` with
  `AuthPolicyAction.UpdateContact`.

## Threats Covered in v0.1

- Account takeover through untrusted email profile matching.
- Silent merge of two existing local users.
- Losing the last usable sign-in method.
- Verification token persistence in plaintext.
- Provider identity reuse across users.
- Plaintext verification secret persistence.

## Threats Covered in v0.2

- Email OTP account enumeration through start-flow responses.
- Email OTP replay through consumed verification reuse.
- Email OTP plaintext persistence in verification storage.
- Short OTP values use salted `scrypt` by default and can be further hardened with
  `createHmacSecretHasher` or a custom `SecretHasher`.

## Threats Covered in v0.3

- Divergent email and phone OTP behavior through duplicated flow code.
- Phone OTP replay through consumed verification reuse.
- Phone OTP plaintext persistence in verification storage.

## Threats Covered in v0.6

- Provider sign-in, OTP, magic-link, password sign-in, and password recovery attempts can be gated
  through an app-owned `RateLimiter`.
- Rate-limited provider sign-in does not create a user, identity, or session.
- Rate-limited OTP start does not create a verification or send a message.
- Rate-limited OTP finish does not consume the pending verification.
- Rate-limited magic-link and password-recovery starts do not create a verification or send a
  message.
- Rate-limited magic-link and password-recovery finishes do not consume the pending verification.
- Rate-limited password sign-in does not create a session.
- Email magic-link sign-in reuses the same anti-enumeration, hash-only secret storage, and
  consume-once guarantees as OTP sign-in.
- OTP code generation can be configured without changing the hash-only verification storage model.
- Password credentials use `PasswordHasher` and optional `PasswordPolicy` ports so production apps
  can choose hashing runtime, parameters, strength rules, and breached-password checks without
  adding mandatory dependencies to core.
- Password recovery reuses the verification lifecycle and rate-limit port without creating sessions
  during reset.

## Threats Covered in v0.9

- Low-trust provider claims can be denied during auto-link and explicit link policy decisions.
- Merge policy can inspect active identities on both sides before moving provider-linked accounts.
- Provider adapters can expose normalized trust context without leaking provider SDK objects into
  the core policy contract.

## Threats Covered in v0.32

- Trusted resend countdown and cooldown reads can stay on one safe public API instead of ad hoc
  repository lookups or raw verification serialization.
- Rate-limit helper output can be handled through a typed public helper instead of parsing
  arbitrary error details by hand.
- OTP, magic-link, and password-recovery abuse-control docs now use one canonical server-owned
  recipe for resend and 429 shaping.

## Threats Covered in v0.46

- Current-account email and phone updates prove the new target through the shared OTP verification
  lifecycle before mutating local user contact fields.
- Contact-change verifications are scoped to the current user and cannot be finished from another
  trusted session.
- Contact-change helpers update only `User.email` or `User.phone`; sign-in identities and password
  credential subjects are not silently rewritten.
- Recent-auth requirements for contact changes can be enforced through the existing policy hook.

## Threats Covered in v0.11

- Merge retries can return a stable no-op result after the source account has already been merged.
- Password credential conflicts abort merge before disabling the source user or moving partial state.
- Merge denial and success audit metadata stay free of credential subjects, passwords, and
  verification secrets.
- Transaction-aware stores can roll merge state back when persistence fails after intermediate
  updates.

## Out of Scope for Core

- Cookie flags and browser session transport.
- CSRF controls.
- Provider SDK signature verification.
- SMTP/SMS delivery security.
- SMTP/SMS retry, bounce handling, and dead-letter queues.
- Magic-link route handling, browser redirects, cookie issuance, and request parsing.
- Password strength-policy implementation, breached-password data sources, password hashing
  parameter selection, pepper loading, and password reset UI.
- Production rate-limit storage, distributed counters, edge runtime integration, and response
  headers.
- Database migrations and production SQL constraints.
- Application secret loading, pepper rotation, and key management.

See [OTP delivery boundary](otp-delivery.md) for the intended queue/retry/DLQ composition around
the current sender-port model.

See [Normalization boundary](normalization.md) for the intended compatibility defaults, production
strictness guidance, and migration cautions around email and phone canonicalization.
