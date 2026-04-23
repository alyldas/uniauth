# Security Model

## Invariants

- User IDs are local and never derived from external provider IDs.
- Exact `(provider, providerUserId)` match wins before profile matching.
- Successful sign-in always creates a local session record.
- Auto-linking is disabled unless policy explicitly allows it.
- Existing users are never silently merged by email or phone.
- The last active identity cannot be unlinked under the default policy.
- Merge is an explicit operation and disabled by default.
- Verification secrets are stored as hashes.
- Verification hashing can be replaced through `SecretHasher`; production OTP flows should use an
  application-owned pepper or stronger storage-specific hasher.
- OTP start responses are neutral and do not expose whether an account exists.
- OTP finish consumes a sign-in verification once before creating a local session.
- Phone OTP uses the same verification lifecycle as email OTP.
- Email magic links use hashed verification secrets and consume-once finish semantics.
- Password credentials store only adapter-produced password hashes and never expose password hashes
  as sign-in secrets.
- Password sign-in uses neutral invalid-credential errors for missing users, wrong passwords, and
  inconsistent credential state.
- Password recovery uses hashed verification secrets and consume-once finish semantics.
- OTP delivery failures do not expose account state; the app-owned sender adapter decides retry,
  dead-letter, and cleanup behavior.
- Rate-limit denials do not create users or sessions, do not consume pending verifications, and do not
  reveal whether a target account exists.
- Public errors avoid exposing which user owns an identity.

## Policy Matrix

- Auto-link by verified email/phone: denied by default; extension point:
  `AuthPolicy.canAutoLink`.
- Unlink identity: allowed only when another active identity remains; extension point:
  `AuthPolicy.canUnlinkIdentity`.
- Merge users: denied by default; extension point: `AuthPolicy.canMergeUsers`.
- Re-auth: required for merge by default; extension point: `AuthPolicy.requiresReAuth`.

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
- Weak OTP hash deployments can be hardened with `createHmacSecretHasher` or a custom
  `SecretHasher`.

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
- Password credentials use a `PasswordHasher` port so production apps can choose a password hashing
  runtime without adding a mandatory dependency to core.
- Password recovery reuses the verification lifecycle and rate-limit port without creating sessions
  during reset.

## Out of Scope for Core

- Cookie flags and browser session transport.
- CSRF controls.
- Provider SDK signature verification.
- SMTP/SMS delivery security.
- SMTP/SMS retry, bounce handling, and dead-letter queues.
- Magic-link route handling, browser redirects, cookie issuance, and request parsing.
- Password strength policy, breached-password checks, password hashing parameter selection, pepper
  loading, and password reset UI.
- Production rate-limit storage, distributed counters, edge runtime integration, and response
  headers.
- Database migrations and production SQL constraints.
- Application secret loading, pepper rotation, and key management.
