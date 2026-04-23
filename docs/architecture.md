# Architecture

`@alyldas/uniauth` is split into four layers.

## Domain

Domain exports stable types for users, identities, credentials, verifications, sessions, provider
assertions, audit events, branded IDs, and utility constructors.

The central invariant is that `User` and `AuthIdentity` are different entities. A user can have many
identities, and email/phone are optional identity attributes.

## Application

`DefaultAuthService` owns use-case orchestration:

- `signIn`
- `startOtpChallenge`
- `finishOtpChallenge`
- `finishOtpSignIn`
- `startEmailMagicLinkSignIn`
- `finishEmailMagicLinkSignIn`
- `signInWithPassword`
- `setPassword`
- `changePassword`
- `startEmailPasswordRecovery`
- `finishEmailPasswordRecovery`
- `link`
- `unlink`
- `mergeAccounts`
- `createSession`
- `revokeSession`
- `createVerification`
- `consumeVerification`

It delegates authorization decisions to `AuthPolicy` and storage/provider/sender work to ports.

## Ports

Core defines repository ports, credential ports, provider registry, sender ports, rate-limit port,
password hashing port, audit log port, verification secret hashing extension point, and
`UnitOfWork`.

OTP challenges use `EmailSender` for email delivery and `SmsSender` for phone delivery. Core
creates and hashes the verification secret, tracks the verification lifecycle, and maps successful
sign-in challenges to local provider identities. The application owns the real SMTP, transactional
email, SMS gateway, or queue adapter.

OTP sign-in uses the unified `startOtpChallenge` and `finishOtpSignIn` API for both email and phone.
The built-in generator stays numeric, with configurable length from 4 to 8 digits, and applications
can provide a custom generator for app-owned formats. The built-in email OTP subject is configurable
without replacing the whole `EmailSender`.

Verification records keep core-owned routing fields such as `provider` and `channel` separate from
app-owned `metadata`. Adapters should persist those fields explicitly instead of inferring core flow
state from arbitrary metadata.

Email magic links use the same verification lifecycle and the existing `EmailSender` port. The
application provides `createLink` per start request, so routes, domains, redirect handling, cookies,
and query parameter conventions remain outside core.

Password credentials use `CredentialRepo` for stored password hashes and `PasswordHasher` for
hash/verify work. Core does not bundle a password hashing runtime; production applications pass an
adapter backed by their chosen algorithm, parameters, and secret-loading policy, while the testing
package provides only a deterministic test hasher. Password identity records use the local
`password` provider so unlink and last-sign-in-method policy remains shared with other identities.

Verification hashing is delegated to `SecretHasher`. The default hasher is sufficient for local
development and compatibility tests; production OTP deployments should pass a custom hasher, for
example `createHmacSecretHasher` with an application-owned pepper loaded during bootstrap.

Rate limiting is delegated to `RateLimiter`. Core only defines stable actions and calls the port
before security-sensitive attempts such as provider sign-in, OTP start/finish, magic-link
start/finish, password sign-in, and password recovery. Applications own the real Redis, database,
edge runtime, or hosted rate-limit adapter and decide exact bucket sizes, key hashing, and retry
headers.

Messenger WebApp providers are reference `AuthProvider` factories, not SDK integrations. They
validate signed Telegram Mini App and MAX WebApp launch data with an application-provided bot token,
map the signed user into `ProviderIdentityAssertion`, and leave bot setup, frontend bridge code,
HTTP transport, cookies, and persistence to the application. Raw launch payloads are not copied into
assertion metadata.

OAuth/OIDC providers use the same `AuthProvider` boundary. Core reads an authorization-code finish
input, delegates code exchange and profile fetching to an application-owned client, maps the
validated profile into `ProviderIdentityAssertion`, and leaves authorization URL creation, callback
routes, state and nonce validation, redirect URI policy, provider secrets, HTTP clients, and token
storage outside core.

Delivery happens after the verification record has been created inside `UnitOfWork`. If a sender
fails, the pending verification stays in storage until normal expiry or adapter cleanup; core does
not roll back storage after an external delivery side effect fails.

`UnitOfWork` is intentionally part of v0.1 so storage adapters can provide real transaction
boundaries for link, unlink, merge, session, and verification flows.

## Testing Adapter

`@alyldas/uniauth/testing` provides an in-memory implementation for tests, demos, and examples. It
includes in-memory email and SMS senders, a rate limiter, and a deterministic password hasher so
local auth flows can be exercised without SMTP, SMS, Redis, or password-hashing runtime setup. It is
not a production persistence adapter.

## Adapter Requirements

Storage adapters should:

- enforce unique active provider identities by `(provider, providerUserId)`;
- keep user, identity, session, verification, and audit records separate;
- keep password credentials separate from identities and store only password hashes;
- apply `UnitOfWork` to sensitive multi-write flows;
- store only hashed verification secrets;
- avoid email/phone ownership inference outside the policy-controlled flow.

Provider adapters should expose `finish()` and return a `ProviderIdentityAssertion`. Core does not
own provider SDK setup, redirect routes, raw provider payload storage, or application secrets.
Provider-specific signature validation can live in a small reference adapter when it does not force
SDK, framework, or storage dependencies into the core package.

## Provider Adapter Layout

Reference provider adapters use root package exports only. Provider-specific source modules may live
under `src/providers`, but those paths are internal implementation details and must not be added to
`package.json` subpath exports without a package-level reason.

Each provider family should keep the same rough split when it reduces real complexity:

- a root-facing source barrel, such as `src/messenger.ts`;
- provider IDs and small constants;
- payload extraction from `FinishInput`;
- provider-specific validation and freshness checks;
- assertion mapping into `ProviderIdentityAssertion`;
- provider factory functions that return `AuthProvider`.

Adapter code should stay SDK-free unless the adapter is moved out of core into a dedicated package.
Framework handlers, redirects, callbacks, cookies, secret loading, and provider SDK clients remain
application-owned.

## Repository Shape

The project starts as a single package so the core domain contracts can stabilize before adapters
become separate packages.

Future provider, persistence, and HTTP integrations should stay outside the core package unless they
are small reference contracts. If the ecosystem grows into multiple maintained adapters, the project
can move to a monorepo with packages for storage, providers, and framework-specific HTTP wiring.
