# Comparison

## Better Auth and Auth.js

Better Auth and Auth.js are application auth frameworks. They can own provider integration,
framework integration, route handling, session transport, and application-facing auth flows.

`@alyldas/uniauth` is lower-level. It focuses on the identity domain and policy-driven orchestration:

- local users with multiple identities;
- no email-centric user requirement;
- explicit linking and merge policy;
- storage/provider ports;
- framework-neutral sessions and audit events.

## Intended Relationship

`@alyldas/uniauth` now exposes optional bridge helpers through `@alyldas/uniauth/bridges`.

Those helpers only map framework-owned OAuth callback or account data into a stable
`ProviderIdentityAssertion`.

They do not make UniAuth the primary session engine, route owner, cookie owner, or token store for
either framework.
