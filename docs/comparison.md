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

`@alyldas/uniauth` can later expose bridge adapters around Better Auth or Auth.js, but core should
not depend on either library.
