# OTP, Magic-Link, and Verification Cancellation Recipes

Use this document when a trusted backend needs to expose resend cooldown, neutral 429 payloads,
polling status, or explicit cancellation for OTP, magic-link, or password-recovery flows.

UniAuth still does not own HTTP middleware, client timers, CAPTCHA, Redis counters, or edge
throttling infrastructure. It gives you the verification lifecycle and rate-limit integration
surface; the application owns the outward transport and response shaping.

Use [Local auth flows](local-auth.md) for the core start and finish APIs. Use
[OTP delivery boundary](otp-delivery.md) for queue/retry ownership.

## Trusted Boundary

Keep all abuse-control reads and writes server-owned:

- browser and mobile clients should never talk directly to repository-backed verification records;
- resend cooldown state should be read through a trusted backend route;
- cancellation should happen through a trusted backend route instead of direct client-side storage
  access;
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
const window = await authService.admin.verifications.resendWindow({
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

## Resend Execution

Trusted backends can convert a resend request into a fresh verification plus a fresh delivery
attempt:

```ts
const resent = await authService.public.otp.resend({
  verificationId,
})
```

The same pattern exists for email-link flows:

```ts
const resentMagic = await authService.public.magicLink.resend({
  verificationId,
  createLink: ({ verificationId, secret }) =>
    `/auth/magic?verification=${verificationId}&token=${secret}`,
})

const resentRecovery = await authService.public.passwordRecovery.resend({
  verificationId,
  createLink: ({ verificationId, secret }) =>
    `/auth/recovery?verification=${verificationId}&token=${secret}`,
})
```

Recommended semantics:

- every successful resend returns a fresh `verificationId`;
- every successful resend uses a fresh secret and fresh delivery payload;
- the previously active verification becomes unusable for later finish attempts;
- cooldown denial should stay neutral and use the same `rate_limited` shape as other abuse-control
  flows.

## Cancellation Execution

Trusted backends can explicitly terminate the active pending verification:

```ts
await authService.admin.verifications.cancel({
  verificationId,
  metadata: { reason: 'user_cancelled' },
})
```

For the common local-auth flows, use the narrower helpers when the backend already knows the flow
type:

```ts
await authService.admin.verifications.cancelOtp({
  verificationId,
  channel: OtpChannel.Email,
})

await authService.admin.verifications.cancelMagicLink({
  verificationId,
})

await authService.admin.verifications.cancelPasswordRecovery({
  verificationId,
})
```

Recommended semantics:

- cancellation should keep the outward HTTP response neutral;
- cancelled verifications should fall back to the existing expired path for later finish/resend
  attempts;
- trusted backends should prefer flow-aware helpers over ad hoc repository checks when the flow type
  is already known.

## OTP Start Endpoint

One practical trusted backend pattern:

```ts
async function postOtpStart(email: string) {
  try {
    const challenge = await authService.public.otp.start({
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

One resend endpoint can stay equally neutral:

```ts
async function postOtpResend(verificationId: string) {
  try {
    const challenge = await authService.public.otp.resend({
      verificationId,
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

And one explicit cancellation endpoint can stay equally small:

```ts
async function postOtpCancel(verificationId: string) {
  await authService.admin.verifications.cancelOtp({
    verificationId,
    channel: OtpChannel.Email,
  })

  return {
    status: 204,
    body: null,
  }
}
```

## Magic-Link Start Endpoint

The same pattern applies to magic-link sign-in:

```ts
async function postMagicLinkStart(email: string) {
  try {
    const challenge = await authService.public.magicLink.start({
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
`admin.verifications.resendWindow(...)` from a trusted backend route rather than deriving timers in the
browser.

For resend execution:

```ts
async function postMagicLinkResend(verificationId: string) {
  try {
    const challenge = await authService.public.magicLink.resend({
      verificationId,
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

Cancellation can stay just as narrow:

```ts
async function postMagicLinkCancel(verificationId: string) {
  await authService.admin.verifications.cancelMagicLink({
    verificationId,
  })

  return {
    status: 204,
    body: null,
  }
}
```

## Recovery Flows

Password-recovery start can reuse the exact same pattern:

```ts
async function postPasswordRecoveryStart(email: string) {
  try {
    const challenge = await authService.public.passwordRecovery.start({
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

Resend execution follows the same server-owned pattern:

```ts
async function postPasswordRecoveryResend(verificationId: string) {
  try {
    const challenge = await authService.public.passwordRecovery.resend({
      verificationId,
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

And the matching cancellation endpoint:

```ts
async function postPasswordRecoveryCancel(verificationId: string) {
  await authService.admin.verifications.cancelPasswordRecovery({
    verificationId,
  })

  return {
    status: 204,
    body: null,
  }
}
```

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
