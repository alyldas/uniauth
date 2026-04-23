# Messenger Providers

UniAuth includes SDK-free provider factories for signed messenger WebApp launch data:

- Telegram Mini App `initData`.
- MAX WebApp `initData` / `WebAppData`.

These adapters validate the signed launch payload, map the signed user into
`ProviderIdentityAssertion`, and then delegate all account decisions to the existing
`AuthService`, `ProviderRegistry`, and `AuthPolicy` flow.

## Public API

```ts
import {
  MAX_WEBAPP_PROVIDER_ID,
  TELEGRAM_MINI_APP_PROVIDER_ID,
  createMaxWebAppProvider,
  createTelegramMiniAppProvider,
  validateSignedWebAppInitData,
} from '@alyldas/uniauth'
```

The shared validator follows the signed WebApp launch-data algorithm used by Telegram and MAX:

- parse URL-encoded `key=value` launch parameters;
- require exactly one `hash`;
- URL-decode values through `URLSearchParams`;
- sort launch parameters by key;
- sign the data-check string with `HMAC-SHA256`;
- compare the received hash with a timing-safe comparison;
- optionally enforce `auth_date` freshness through `maxAgeSeconds`.

The built-in validator is for bot-token HMAC validation. Telegram third-party Ed25519 signature
validation is a separate flow and is intentionally not part of this provider boundary.

## Telegram Mini App

Register a provider at bootstrap:

```ts
const telegramProvider = createTelegramMiniAppProvider({
  botToken: process.env.TELEGRAM_BOT_TOKEN!,
  maxAgeSeconds: 60 * 60,
})

providerRegistry.register(telegramProvider)
```

Finish a sign-in with raw `Telegram.WebApp.initData`:

```ts
const result = await service.signIn({
  provider: TELEGRAM_MINI_APP_PROVIDER_ID,
  finishInput: {
    payload: {
      initData: request.body.initData,
    },
  },
})
```

The provider maps the signed `user.id` into `providerUserId`. Display fields such as
`first_name`, `last_name`, `username`, `language_code`, and `photo_url` become normalized assertion
display/metadata fields. Raw `initData` is not added to assertion metadata.

## MAX WebApp

MAX exposes signed data through `window.WebApp.initData`. Some server-side flows may also receive a
full URL or URL fragment containing `WebAppData`.

```ts
const maxProvider = createMaxWebAppProvider({
  botToken: process.env.MAX_BOT_TOKEN!,
  maxAgeSeconds: 60 * 60,
})

providerRegistry.register(maxProvider)
```

Direct `initData`:

```ts
await service.signIn({
  provider: MAX_WEBAPP_PROVIDER_ID,
  finishInput: {
    payload: {
      initData: request.body.initData,
    },
  },
})
```

Full URL or fragment:

```ts
await service.signIn({
  provider: MAX_WEBAPP_PROVIDER_ID,
  finishInput: {
    payload: {
      url: request.body.userUrl,
    },
  },
})
```

`createMaxWebAppProvider` extracts `WebAppData` when the payload contains that parameter. If the
payload is already direct `initData`, it validates it as-is.

## Security Notes

- Keep bot tokens in application bootstrap code. UniAuth never reads environment variables itself.
- Set `maxAgeSeconds` for production sign-in endpoints so old launch payloads cannot be replayed
  indefinitely.
- Do not use `initDataUnsafe` for authentication. Only signed `initData` / `WebAppData` should
  reach the provider.
- Do not persist raw launch payloads unless your application has a separate audit policy for them.
  The built-in providers only emit reduced metadata.
- Exact `(provider, providerUserId)` matching still wins. Email, phone, username, and display fields
  are profile hints, not account ownership proof.
- Auto-link remains controlled by `AuthPolicy`; messenger providers do not silently merge users.
