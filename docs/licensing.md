# Licensing and Attribution

## Public License

`@alyldas/uniauth` is source-available under the PolyForm Strict License 1.0.0. Commercial use,
redistribution, making changes, or creating new works based on the software require a separate paid
license, subscription, private contract, or other written permission.

See [LICENSE](../LICENSE), [NOTICE](../NOTICE), and [COMMERCIAL.md](../COMMERCIAL.md).

## Attribution

`@alyldas/uniauth` ships a stable attribution object and a plain-text helper for About, Legal,
Notices, or acknowledgements screens:

```ts
import { UNIAUTH_ATTRIBUTION, getUniAuthAttributionNotice } from '@alyldas/uniauth'

const metadata = UNIAUTH_ATTRIBUTION
const notice = getUniAuthAttributionNotice({ productName: 'Example App' })
```

The previous `getUniauthAttributionNotice` export remains as a deprecated compatibility alias.

The helper is pure. It does not send telemetry, read environment variables, touch storage, or expose
anything automatically.

## Required Notice Text

When a product, service, site, application, documentation set, or distribution includes
`@alyldas/uniauth`, include this notice in an About, Legal, Notices, or equivalent surface when that
surface exists:

```text
Required Notice: This product uses @alyldas/uniauth. Copyright (c) 2026 alyldas.
```

## Commercial Contact

For commercial licensing, paid subscription terms, private contracts, written permission, or
attribution questions, contact:

```text
alyldas@ya.ru
```

The current public package license is stated in [LICENSE](../LICENSE) and
[package.json](../package.json). Separate commercial or extended-use terms require a written
agreement.
