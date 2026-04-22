# Architecture

`@alyldas/uniauth` is split into four layers.

## Domain

Domain exports stable types for users, identities, verifications, sessions, provider assertions,
audit events, branded IDs, and utility constructors.

The central invariant is that `User` and `AuthIdentity` are different entities. A user can have many
identities, and email/phone are optional identity attributes.

## Application

`DefaultAuthService` owns use-case orchestration:

- `signIn`
- `startOtpChallenge`
- `finishOtpChallenge`
- `finishOtpSignIn`
- `startEmailOtpSignIn`
- `finishEmailOtpSignIn`
- `link`
- `unlink`
- `mergeAccounts`
- `createSession`
- `revokeSession`
- `createVerification`
- `consumeVerification`

It delegates authorization decisions to `AuthPolicy` and storage/provider/sender work to ports.

## Ports

Core defines repository ports, provider registry, sender ports, audit log port, secret hashing
extension point, and `UnitOfWork`.

OTP challenges use `EmailSender` for email delivery and `SmsSender` for phone delivery. Core
creates and hashes the verification secret, tracks the verification lifecycle, and maps successful
sign-in challenges to local provider identities. The application owns the real SMTP, transactional
email, SMS gateway, or queue adapter.

Verification hashing is delegated to `SecretHasher`. The default hasher is sufficient for local
development and compatibility tests; production OTP deployments should pass a custom hasher, for
example `createHmacSecretHasher` with an application-owned pepper loaded during bootstrap.

Delivery happens after the verification record has been created inside `UnitOfWork`. If a sender
fails, the pending verification stays in storage until normal expiry or adapter cleanup; core does
not roll back storage after an external delivery side effect fails.

`UnitOfWork` is intentionally part of v0.1 so storage adapters can provide real transaction
boundaries for link, unlink, merge, session, and verification flows.

## Testing Adapter

`@alyldas/uniauth/testing` provides an in-memory implementation for tests, demos, and examples. It
includes in-memory email and SMS senders so OTP flows can be exercised without SMTP or an SMS
gateway. It is not a production persistence adapter.

## Adapter Requirements

Storage adapters should:

- enforce unique active provider identities by `(provider, providerUserId)`;
- keep user, identity, session, verification, and audit records separate;
- apply `UnitOfWork` to sensitive multi-write flows;
- store only hashed verification secrets;
- avoid email/phone ownership inference outside the policy-controlled flow.

Provider adapters should expose `finish()` and return a `ProviderIdentityAssertion`. Core does not
own provider SDK setup, redirect routes, raw provider payload storage, or signature validation.

## Repository Shape

The project starts as a single package so the core domain contracts can stabilize before adapters
become separate packages.

Future provider, persistence, and HTTP integrations should stay outside the core package unless they
are small reference contracts. If the ecosystem grows into multiple maintained adapters, the project
can move to a monorepo with packages for storage, providers, and framework-specific HTTP wiring.
