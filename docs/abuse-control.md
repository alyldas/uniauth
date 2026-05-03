# OTP and Magic-Link Abuse-Control Recipes

Use this document when a trusted backend needs to expose resend cooldown, neutral 429 payloads, or
polling status for OTP, magic-link, or password-recovery flows.

UniAuth still does not own HTTP middleware, client timers, CAPTCHA, Redis counters, or edge
throttling infrastructure. It gives you the verification lifecycle and rate-limit integration
surface; the application owns the outward transport and response shaping.

Use [Local auth flows](local-auth.md) for the core start and finish APIs. Use
[OTP delivery boundary](otp-delivery.md) for queue/retry ownership.

## Trusted Boundary

Keep all abuse-control reads and writes server-owned:

- browser and mobile clients should never talk directly to repository-backed verification records;
- resend cooldown state should be read through a trusted backend route;
- rate-limit errors should be shaped by the server, not by leaking raw `details` blindly.

## Canonical Rate-Limit Handling

UniAuth raises a stable `rate_limited` error shape. Applications can read it through the public
helper instead of parsing arbitrary `details` objects:

```ts
import { getRateLimitedErrorDetails } from '@alyldas/uniauth'

function toRateLimitedResponse(error: unknown) {
  const details = getRateLimitedErrorDetails(error)

  if (!details) {
    throw error
  }

  return {
    status: 429,
    body: {
      error: 'rate_limited',
      retryAfterSeconds: details.retryAfterSeconds ?? null,
      resetAt: details.resetAt ?? null,
    },
  }
}
```

Keep the outward payload neutral. Do not expose whether a target account exists, whether the sender
already delivered a message, or which internal bucket implementation denied the attempt.

## Resend Cooldown Read-Side

After a trusted backend creates an OTP, magic-link, or password-recovery verification, it can
serve a cooldown endpoint through the new resend window API:

```ts
const window = await authService.getVerificationResendWindow({
  verificationId,
  cooldownSeconds: 60,
})
```

The returned shape is safe for trusted server serialization:

```ts
return {
  id: window.id,
  purpose: window.purpose,
  status: window.status,
  provider: window.provider ?? null,
  channel: window.channel ?? null,
  expiresAt: window.expiresAt.toISOString(),
  consumedAt: window.consumedAt?.toISOString() ?? null,
  resendAllowed: window.resendAllowed,
  expired: window.expired,
  resendAvailableAt: window.resendAvailableAt.toISOString(),
  cooldownSeconds: window.cooldownSeconds,
  cooldownRemainingSeconds: window.cooldownRemainingSeconds,
}
```

Recommended semantics:

- `resendAllowed = true` only when the verification is still pending, not expired, and the
  configured cooldown has elapsed;
- consumed and expired verifications remain visible as such and do not masquerade as resendable;
- the server, not the client, chooses the cooldown policy.

## OTP Start Endpoint

One practical trusted backend pattern:

```ts
async function postOtpStart(email: string) {
  try {
    const challenge = await authService.startOtpChallenge({
      purpose: VerificationPurpose.SignIn,
      channel: OtpChannel.Email,
      target: email,
    })

    return {
      status: 202,
      body: {
        verificationId: challenge.verificationId,
        delivery: challenge.delivery,
      },
    }
  } catch (error) {
    return toRateLimitedResponse(error)
  }
}
```

That keeps the start response neutral while still giving the trusted backend enough information to
poll resend state by `verificationId`.

## Magic-Link Start Endpoint

The same pattern applies to magic-link sign-in:

```ts
async function postMagicLinkStart(email: string) {
  try {
    const challenge = await authService.startEmailMagicLinkSignIn({
      email,
      createLink: ({ verificationId, secret }) =>
        `/auth/magic?verification=${verificationId}&token=${secret}`,
    })

    return {
      status: 202,
      body: {
        verificationId: challenge.verificationId,
        delivery: challenge.delivery,
      },
    }
  } catch (error) {
    return toRateLimitedResponse(error)
  }
}
```

If the application later wants to show resend state, it should use
`getVerificationResendWindow(...)` from a trusted backend route rather than deriving timers in the
browser.

## Recovery Flows

Password-recovery start can reuse the exact same pattern:

```ts
async function postPasswordRecoveryStart(email: string) {
  try {
    const challenge = await authService.startEmailPasswordRecovery({
      email,
      createLink: ({ verificationId, secret }) =>
        `/auth/recovery?verification=${verificationId}&token=${secret}`,
    })

    return {
      status: 202,
      body: {
        verificationId: challenge.verificationId,
        delivery: challenge.delivery,
      },
    }
  } catch (error) {
    return toRateLimitedResponse(error)
  }
}
```

The recovery token route remains application-owned. UniAuth only owns the verification lifecycle,
hash-only secret persistence, and neutral rate-limit error shape.

## Key Composition

If the surrounding application or test harness needs to reproduce the same low-level key format as
core, use the public `rateLimitKey(...)` helper rather than hand-joining strings:

```ts
import { OtpChannel, rateLimitKey } from '@alyldas/uniauth'

const targetKey = rateLimitKey(OtpChannel.Email, 'alice@example.com')
```

This helper exists for integration symmetry. It does not replace the `RateLimiter` port or dictate
which storage backend should hold counters.

## Related Documents

- [Local auth flows](local-auth.md)
- [OTP delivery boundary](otp-delivery.md)
- [Security model](security.md)
- [Backend integration recipes](backend-recipes.md)
