# Session Transport Recipes

UniAuth creates and revokes local session records. The application still owns how that session ID
travels between client and server.

This document keeps the boundary explicit for three common transports:

- browser cookies;
- API bearer transport;
- mobile or native client token storage.

## Browser Cookies

Browser-first applications usually map `result.session.id` into a session cookie immediately after a
successful finish flow.

Minimum expectations:

- `httpOnly: true`;
- `secure: true` in production;
- explicit `sameSite`;
- explicit `path`;
- separate cookie clearing on logout or revoke.

Example shape:

```ts
const result = await authService.finishOtpSignIn({
  verificationId: body.verificationId,
  secret: body.code,
})

response.cookie('session', result.session.id, {
  httpOnly: true,
  secure: true,
  sameSite: 'lax',
  path: '/',
})
```

What stays application-owned:

- CSRF protection for browser POST requests;
- domain and subdomain scoping;
- cookie signing or encryption policy;
- reverse-proxy HTTPS behavior;
- cookie clearing on logout.

## Bearer Transport

API-first applications may choose to return the local UniAuth session ID in the JSON response and
then send it back in an `Authorization` header or another app-owned header.

Example shape:

```ts
const result = await authService.signInWithPassword({
  email: body.email,
  password: body.password,
})

return {
  sessionToken: result.session.id,
  userId: result.user.id,
}
```

What stays application-owned:

- TLS-only transport;
- token forwarding rules between services;
- gateway or edge header normalization;
- server middleware that resolves the session ID back into application auth context;
- log redaction so session identifiers do not leak into access logs.

## Mobile And Native Clients

Mobile or native applications often keep the local session identifier in platform-owned secure
storage instead of browser cookies.

Recommended boundary:

1. UniAuth returns a local session ID.
2. The API returns it to the client over TLS.
3. The client stores it in Keychain, Keystore, or another secure app-owned store.
4. Future API calls send that session ID through an app-owned header or bearer transport.

What stays application-owned:

- secure storage choice;
- app logout UX;
- biometric gating before reuse;
- device binding, if required;
- session refresh or re-issuance policy.

## Logout And Revocation

UniAuth revokes the local session record, but it does not clear browser cookies or client storage.

Treat logout as two coordinated steps:

1. call `authService.revokeSession(sessionId)`;
2. remove the transport artifact:
   - clear the cookie;
   - delete the bearer token from client state;
   - delete the mobile-stored session ID.

## Security Notes

- Session transport is not part of the package public API surface; it is deployment policy.
- Do not mix browser cookie assumptions into mobile or API bearer flows.
- Keep CSRF analysis only for cookie-based browser flows.
- Keep replay and theft analysis for bearer-like transports in the application threat model.

See also:

- [Backend integration recipes](backend-recipes.md)
- [Local auth flows](local-auth.md)
- [Security model](security.md)
- [Threat model](threat-model.md)
