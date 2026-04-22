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
- Email OTP start responses are neutral and do not expose whether an account exists.
- Email OTP finish consumes a sign-in verification once before creating a local session.
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

## Threats Covered in v0.2

- Email OTP account enumeration through start-flow responses.
- Email OTP replay through consumed verification reuse.
- Email OTP plaintext persistence in verification storage.

## Out of Scope for Core

- Cookie flags and browser session transport.
- CSRF controls.
- Provider SDK signature verification.
- SMTP/SMS delivery security.
- Database migrations and production SQL constraints.
