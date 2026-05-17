# Changelog

## [0.47.0](https://github.com/alyldas/uniauth/compare/v0.46.0...v0.47.0) (2026-05-17)


### Features

* добавлены фасады сервиса и политика паролей ([27612ac](https://github.com/alyldas/uniauth/commit/27612ac2f5ba07f7f6767fe778f380b1ba707438))


### Bug Fixes

* accept repository class containers ([282ca7f](https://github.com/alyldas/uniauth/commit/282ca7f3cbe6439f11301e15f9a6e5620a4fb301))
* harden current account metadata and store parity ([19eff04](https://github.com/alyldas/uniauth/commit/19eff04e2110f561f00d26469beb0e24b0185534))
* harden password runtime inputs ([abe8070](https://github.com/alyldas/uniauth/commit/abe8070900286bfb46c20a5461d9ab76e62e2845))
* harden postgres writes and provider metadata ([0d21f70](https://github.com/alyldas/uniauth/commit/0d21f70ae8b544ac6dc1e71ed5ab23ff074d26d6))
* normalize postgres mapper errors ([1f967cb](https://github.com/alyldas/uniauth/commit/1f967cb321bcfcaa3914ebf0bb008f65a9d084bd))
* normalize provider registry ids ([f4df0a8](https://github.com/alyldas/uniauth/commit/f4df0a802417fa091545fb90ef3ec9151d47aec1))
* reject blank hmac peppers ([a32b1a1](https://github.com/alyldas/uniauth/commit/a32b1a12cb0f6064f16e328955b8cf0fc4050494))
* reject blank verification secrets ([02fd06a](https://github.com/alyldas/uniauth/commit/02fd06a408d72f5636b08683b51dfd9755b1ada9))
* reject invalid current-account display names ([8bcfee1](https://github.com/alyldas/uniauth/commit/8bcfee1831c575971d3bc86203b0f673edfbe233))
* reject invalid provider assertion claims ([f1cb223](https://github.com/alyldas/uniauth/commit/f1cb223830ccdef1f26bd4babebb367633ac7a34))
* reject invalid resend cooldown dates ([4f9b36d](https://github.com/alyldas/uniauth/commit/4f9b36d29533342c00aca19dc7b32d1948716893))
* reject invalid ttl expirations ([790b0e9](https://github.com/alyldas/uniauth/commit/790b0e9f894448aa72be4500d6f6a4a9f0e12219))
* reject invalid webapp auth dates ([84487e8](https://github.com/alyldas/uniauth/commit/84487e83037ce3ef18bfe7ab9118699f035fea5d))
* reject invalid webapp max-age times ([058694f](https://github.com/alyldas/uniauth/commit/058694f585605be05ac5b15e3f45662b1099c39b))
* reject non-string audit event types ([f16dc32](https://github.com/alyldas/uniauth/commit/f16dc32299e4ac3a20b6e753627ac0ea2778ba4f))
* reject non-string magic-link emails ([002c992](https://github.com/alyldas/uniauth/commit/002c9924d944918c3954ea3878c1eec396e39cf1))
* reject non-string otp targets ([3110cc0](https://github.com/alyldas/uniauth/commit/3110cc0901c67cf8b24a9f3dce42ee5082e6af6c))
* reject non-string session tokens ([bd618d6](https://github.com/alyldas/uniauth/commit/bd618d6735d8b2e39ce0a07fde6c71c8e0df0947))
* reject non-string verification targets ([e7d4f1e](https://github.com/alyldas/uniauth/commit/e7d4f1ef5d27a6b81e3f191036e02c11d7d852cc))
* validate audit query containers ([fda3e38](https://github.com/alyldas/uniauth/commit/fda3e386e28894c1b40a9878db597db1f0068698))
* validate auth service runtime inputs ([f4cb4c7](https://github.com/alyldas/uniauth/commit/f4cb4c72af0fe63959e09de1f59ab364b0a35915))
* validate bridge and rate-limit helpers ([31e4ef4](https://github.com/alyldas/uniauth/commit/31e4ef4d69a8952944f55f0bfb99b2e2337ecd7f))
* validate bridge oauth metadata ([#347](https://github.com/alyldas/uniauth/issues/347)) ([843edf0](https://github.com/alyldas/uniauth/commit/843edf075d475583b726c1d86134c1d70c6a73c9))
* validate date-shaped runtime inputs ([ef713bc](https://github.com/alyldas/uniauth/commit/ef713bcc2fda08778d55bfaf383bf3a8bf88538b))
* validate default policy runtime inputs ([fbdf363](https://github.com/alyldas/uniauth/commit/fbdf36341be35d12b588a22b21823ef4d57ed6fa))
* validate domain rule dates ([2b9aaaf](https://github.com/alyldas/uniauth/commit/2b9aaafa8c0a605922636e02a0cf8ce1fb5b18c9))
* validate generated secret lengths ([9c49678](https://github.com/alyldas/uniauth/commit/9c49678b621892e6643355393ed0bafc93b19a13))
* validate in-memory testing helpers ([902ff69](https://github.com/alyldas/uniauth/commit/902ff6902282875d3adcbb793ef8901dcd161437))
* validate inspection input containers ([ea7ef08](https://github.com/alyldas/uniauth/commit/ea7ef086beb3fafd4a12097cf7b24983f1323d20))
* validate normalizer and time helpers ([89093a3](https://github.com/alyldas/uniauth/commit/89093a398cdf12a1968cbdb14057d27b27a6552a))
* validate oauth token metadata ([c2987d5](https://github.com/alyldas/uniauth/commit/c2987d5efba85e1e9170be3cc008dbfc2eaa28c7))
* validate provider runtime inputs ([6135352](https://github.com/alyldas/uniauth/commit/61353522fc943180dee9c3a6ebbcffb151fc3b8a))
* validate public helper runtime inputs ([a3a7306](https://github.com/alyldas/uniauth/commit/a3a730631a437a8fde40e8fc2bf5c97e1fd3e0ef))
* validate rate-limit decision metadata ([7bd3407](https://github.com/alyldas/uniauth/commit/7bd34072d922afa5fc89a96485ae367d995777a1))
* validate rate-limit detail actions ([064a63a](https://github.com/alyldas/uniauth/commit/064a63ababca2111f14220781ac7cb6987fb4889))
* validate request metadata across flows ([69129e4](https://github.com/alyldas/uniauth/commit/69129e4fb7a6599ccc274d8345bca2748fa1bde1))
* validate resend window helper inputs ([28f70f6](https://github.com/alyldas/uniauth/commit/28f70f67d65b22e6793b9a2612b5451ad6e769e0))
* validate runtime boundary times ([160e16f](https://github.com/alyldas/uniauth/commit/160e16ff22101cf10f4970480af2b918be2e81b7))
* исправлена очистка HTML-тегов в markdown-якорях ([0691c6d](https://github.com/alyldas/uniauth/commit/0691c6d9c1d49a6e9e11d4ad07dbec425be6e169))

## [0.46.0](https://github.com/alyldas/uniauth/compare/v0.45.0...v0.46.0) (2026-05-12)


### Features

* add current-account verified contact changes ([a966b1d](https://github.com/alyldas/uniauth/commit/a966b1de1ddbea6addc9eb12706072f876773dcd))

## [0.45.0](https://github.com/alyldas/uniauth/compare/v0.44.0...v0.45.0) (2026-05-05)


### Features

* add current-account profile update helper ([73517f1](https://github.com/alyldas/uniauth/commit/73517f17e163a4f8b114c9ad265d9e9b58e508f8))

## [0.44.0](https://github.com/alyldas/uniauth/compare/v0.43.0...v0.44.0) (2026-05-05)


### Features

* add current-account closure export snapshot ([d357159](https://github.com/alyldas/uniauth/commit/d357159ade71061106c9c567de72da36ead8024a))

## [0.43.0](https://github.com/alyldas/uniauth/compare/v0.42.0...v0.43.0) (2026-05-05)


### Features

* add current-account account closure helper ([bc6cd13](https://github.com/alyldas/uniauth/commit/bc6cd1377c18a891dcf09a70e70143aad90c14fd))

## [0.42.0](https://github.com/alyldas/uniauth/compare/v0.41.0...v0.42.0) (2026-05-04)


### Features

* add current-account OTP re-auth management helpers ([b9d6c37](https://github.com/alyldas/uniauth/commit/b9d6c3729cfefe6d76383288838dfad74bb1205e))

## [0.41.0](https://github.com/alyldas/uniauth/compare/v0.40.0...v0.41.0) (2026-05-04)


### Features

* add current-account identity linking helper ([de0da1f](https://github.com/alyldas/uniauth/commit/de0da1f05721271cb1d01eb1a7fc2a0413f571f9))

## [0.40.0](https://github.com/alyldas/uniauth/compare/v0.39.0...v0.40.0) (2026-05-04)


### Features

* add current-account recent-auth guards ([b53df0e](https://github.com/alyldas/uniauth/commit/b53df0e7ef78fea3d71b0b2e60f03b2b38420add))

## [0.39.0](https://github.com/alyldas/uniauth/compare/v0.38.0...v0.39.0) (2026-05-04)


### Features

* add current-account re-auth helpers ([95e75c2](https://github.com/alyldas/uniauth/commit/95e75c227fb9b2f9d386b06edc8dbdbb3dcd8551))

## [0.38.0](https://github.com/alyldas/uniauth/compare/v0.37.0...v0.38.0) (2026-05-04)


### Features

* add current-account action helpers ([4f8e9bd](https://github.com/alyldas/uniauth/commit/4f8e9bd95164deeb2c34886d36da13f65cc5c927))

## [0.37.0](https://github.com/alyldas/uniauth/compare/v0.36.0...v0.37.0) (2026-05-04)


### Features

* add current-account inspection helpers ([832875d](https://github.com/alyldas/uniauth/commit/832875d721abf0c0b5ea43970af37c783e8e4739))

## [0.36.0](https://github.com/alyldas/uniauth/compare/v0.35.0...v0.36.0) (2026-05-04)


### Features

* add current-account security helpers ([1ead604](https://github.com/alyldas/uniauth/commit/1ead604291fd3569916c30ddb7383fc5d8762d3e))

## [0.35.0](https://github.com/alyldas/uniauth/compare/v0.34.0...v0.35.0) (2026-05-04)


### Features

* add provider family subpath exports ([b6aacb7](https://github.com/alyldas/uniauth/commit/b6aacb7af7ffc30529bf767f3d38237559f80df0))

## [0.34.0](https://github.com/alyldas/uniauth/compare/v0.33.0...v0.34.0) (2026-05-04)


### Features

* add verification cancellation flows ([346de8a](https://github.com/alyldas/uniauth/commit/346de8a19d6bcb8582822117881ece1eb00e0be5))

## [0.33.0](https://github.com/alyldas/uniauth/compare/v0.32.0...v0.33.0) (2026-05-03)


### Features

* add resend execution flows ([8dd8146](https://github.com/alyldas/uniauth/commit/8dd8146b0a09f25eae402411709ce584479f226b))

## [0.32.0](https://github.com/alyldas/uniauth/compare/v0.31.0...v0.32.0) (2026-05-03)


### Features

* add resend windows and abuse-control helpers ([8414019](https://github.com/alyldas/uniauth/commit/84140194e682e3cf13bc3a94368428cee63b1119))

## [0.31.0](https://github.com/alyldas/uniauth/compare/v0.30.0...v0.31.0) (2026-05-03)


### Features

* add audit event page API ([85248bc](https://github.com/alyldas/uniauth/commit/85248bcf7bd0e9852a7a20f8a4a314b3746fc3d5))
* add inspection audit page metadata ([ed133fa](https://github.com/alyldas/uniauth/commit/ed133fac49759e28d105ea5534b6aec0aaf8a348))

## [0.30.0](https://github.com/alyldas/uniauth/compare/v0.29.0...v0.30.0) (2026-05-02)


### Features

* add audit timeline cursor queries ([16a5fad](https://github.com/alyldas/uniauth/commit/16a5fade887954c0795d159d3f82d6c58b2d7384))
* add inspection audit windows ([e3c6e2f](https://github.com/alyldas/uniauth/commit/e3c6e2f6194228549c45881d8083af735b7c5616))

## [0.29.0](https://github.com/alyldas/uniauth/compare/v0.28.0...v0.29.0) (2026-05-01)


### Features

* add session auth context resolution ([3bbcc10](https://github.com/alyldas/uniauth/commit/3bbcc108d9748038bc4f3a2dbd8cbad1433ca721))

## [0.28.0](https://github.com/alyldas/uniauth/compare/v0.27.0...v0.28.0) (2026-05-01)


### Features

* add trusted account inspection aggregate ([b33634d](https://github.com/alyldas/uniauth/commit/b33634d87f543266abaa4d3ad888b81c3b720729))

## [0.27.0](https://github.com/alyldas/uniauth/compare/v0.26.0...v0.27.0) (2026-05-01)


### Features

* add audit-event read-side API ([440a03c](https://github.com/alyldas/uniauth/commit/440a03c694ef5764a2ca63354ef33d83a5ee40a8))

## [0.26.0](https://github.com/alyldas/uniauth/compare/v0.25.1...v0.26.0) (2026-04-30)


### Features

* add account security snapshot read-side API ([368d14f](https://github.com/alyldas/uniauth/commit/368d14fe75b92a9d587f0eac869ab954bfe19c16))

## [0.25.1](https://github.com/alyldas/uniauth/compare/v0.25.0...v0.25.1) (2026-04-29)


### Bug Fixes

* harden in-memory password hashing ([#143](https://github.com/alyldas/uniauth/issues/143)) ([89d666f](https://github.com/alyldas/uniauth/commit/89d666fbfffe87f9661f11a94d94b479f2f2ee42))
* seal example session cookies ([#145](https://github.com/alyldas/uniauth/issues/145)) ([6f37350](https://github.com/alyldas/uniauth/commit/6f37350b629e7ee8932baf39161b495f42f4e140))

## [0.25.0](https://github.com/alyldas/uniauth/compare/v0.24.0...v0.25.0) (2026-04-29)


### Features

* add safe read-side projection helpers ([2cc32ba](https://github.com/alyldas/uniauth/commit/2cc32ba5e293b62e16eed5bec7adf61db09c4c6e))

## [0.24.0](https://github.com/alyldas/uniauth/compare/v0.23.0...v0.24.0) (2026-04-29)


### Features

* add account security read-side APIs ([8550109](https://github.com/alyldas/uniauth/commit/85501095753b6a113f659b28ad91af49c1287dc4))

## [0.23.0](https://github.com/alyldas/uniauth/compare/v0.22.0...v0.23.0) (2026-04-29)


### Features

* add public user read-side API ([78333ef](https://github.com/alyldas/uniauth/commit/78333ef1057fa409bd38cb24ecb896084120139b))

## [0.22.0](https://github.com/alyldas/uniauth/compare/v0.21.0...v0.22.0) (2026-04-29)


### Features

* add bulk user session revocation API ([3119ec4](https://github.com/alyldas/uniauth/commit/3119ec461ab25f0a767e62150f9ca7f8ecaeec5b))

## [0.21.0](https://github.com/alyldas/uniauth/compare/v0.20.0...v0.21.0) (2026-04-29)


### Features

* add public user session listing API ([25bfb92](https://github.com/alyldas/uniauth/commit/25bfb9281aa98a1224b6e29f154f6c75c5819487))

## [0.20.0](https://github.com/alyldas/uniauth/compare/v0.19.0...v0.20.0) (2026-04-29)


### Features

* add session middleware recipes ([6e230ab](https://github.com/alyldas/uniauth/commit/6e230ab816a83020168405e25308a2855b07944f))

## [0.19.0](https://github.com/alyldas/uniauth/compare/v0.18.0...v0.19.0) (2026-04-29)


### Features

* add provider token persistence boundary ([ca8a2d6](https://github.com/alyldas/uniauth/commit/ca8a2d6bc175a83b45f7190b004ed69610360f63))

## [0.18.0](https://github.com/alyldas/uniauth/compare/v0.17.0...v0.18.0) (2026-04-29)


### Features

* add session activity touch API ([65a80cb](https://github.com/alyldas/uniauth/commit/65a80cb24005a2fed666e63b1fa848a65bdb93f5))

## [0.17.0](https://github.com/alyldas/uniauth/compare/v0.16.0...v0.17.0) (2026-04-29)


### Features

* add session token resolution API ([8b7aa03](https://github.com/alyldas/uniauth/commit/8b7aa034d21fd8bf0f61c24ae7792abd1b34301e))

## [0.16.0](https://github.com/alyldas/uniauth/compare/v0.15.0...v0.16.0) (2026-04-28)


### Features

* add framework auth examples ([ca1bb96](https://github.com/alyldas/uniauth/commit/ca1bb9681a2d732c371eb11a4c760c26400dd8b2))

## [0.15.0](https://github.com/alyldas/uniauth/compare/v0.14.0...v0.15.0) (2026-04-28)


### Features

* add provider wiring examples ([a8524e3](https://github.com/alyldas/uniauth/commit/a8524e37268577a6062c877ebf008c75587e76da))

## [0.14.0](https://github.com/alyldas/uniauth/compare/v0.13.1...v0.14.0) (2026-04-28)


### Features

* add example applications ([66e38f5](https://github.com/alyldas/uniauth/commit/66e38f58232bdcd3b71713c76e1b4f550a1f09bd))

## [0.13.1](https://github.com/alyldas/uniauth/compare/v0.13.0...v0.13.1) (2026-04-28)


### Bug Fixes

* restore normalization boundary semantics ([94d459b](https://github.com/alyldas/uniauth/commit/94d459b20e2e6e99d3309d535d7217a1391a2f30))

## [0.13.0](https://github.com/alyldas/uniauth/compare/v0.12.0...v0.13.0) (2026-04-28)


### Features

* add configurable normalization boundary ([d431ae9](https://github.com/alyldas/uniauth/commit/d431ae983a15459a00733334b948f5d162b62a62))

## [0.12.0](https://github.com/alyldas/uniauth/compare/v0.11.1...v0.12.0) (2026-04-28)


### Features

* add optional auth bridge helpers ([5ff7607](https://github.com/alyldas/uniauth/commit/5ff760793d401a0547fb3c9169cd1ac2c318b41f))

## [0.11.1](https://github.com/alyldas/uniauth/compare/v0.11.0...v0.11.1) (2026-04-23)


### Bug Fixes

* keep testing public exports stable ([18795bb](https://github.com/alyldas/uniauth/commit/18795bb26c289155eaed37f39b00221c3a05d26f))

## [0.11.0](https://github.com/alyldas/uniauth/compare/v0.10.0...v0.11.0) (2026-04-23)


### Features

* harden transactional account merge flow ([8b718ac](https://github.com/alyldas/uniauth/commit/8b718ac0949b2d9a840bd417320cf33b693d39f2))

## [0.10.0](https://github.com/alyldas/uniauth/compare/v0.9.0...v0.10.0) (2026-04-23)


### Features

* add Postgres reference persistence ([0423f65](https://github.com/alyldas/uniauth/commit/0423f65a3d7004be83725d2ae9dba85773df9ff2))

## [0.9.0](https://github.com/alyldas/uniauth/compare/v0.8.0...v0.9.0) (2026-04-23)


### Features

* add trusted provider policy hooks ([d308ae2](https://github.com/alyldas/uniauth/commit/d308ae21aae6b0ff1fd8e34a7ecafa31baaa55a4))

## [0.8.0](https://github.com/alyldas/uniauth/compare/v0.7.0...v0.8.0) (2026-04-23)


### Features

* add OAuth OIDC provider contract ([b4a1c37](https://github.com/alyldas/uniauth/commit/b4a1c370673056417b1730133fa05c696c2909a8))

## [0.7.0](https://github.com/alyldas/uniauth/compare/v0.6.0...v0.7.0) (2026-04-23)


### Features

* add messenger WebApp providers ([651348f](https://github.com/alyldas/uniauth/commit/651348ff0e22fe6cc1444a0f769e5d2cf0d937f0))

## [0.6.0](https://github.com/alyldas/uniauth/compare/v0.5.0...v0.6.0) (2026-04-23)


### Features

* add local auth hardening flows ([84194e7](https://github.com/alyldas/uniauth/commit/84194e73617b49df46161fc32d9fd8d15f7578d4))

## [0.5.0](https://github.com/alyldas/uniauth/compare/v0.4.0...v0.5.0) (2026-04-22)


### Features

* simplify the public auth core API before 1.0.0 ([169ebd9](https://github.com/alyldas/uniauth/commit/169ebd93b5244803c7eb0534f8d63fd771f97624))
* split auth orchestration into account, sign-in, session, OTP, verification, and support modules ([169ebd9](https://github.com/alyldas/uniauth/commit/169ebd93b5244803c7eb0534f8d63fd771f97624))
* add configurable verification secret hashing with SHA-256 default and HMAC-SHA-256 helper ([169ebd9](https://github.com/alyldas/uniauth/commit/169ebd93b5244803c7eb0534f8d63fd771f97624))
* keep internal helpers private with positive and negative package export smoke coverage ([169ebd9](https://github.com/alyldas/uniauth/commit/169ebd93b5244803c7eb0534f8d63fd771f97624))


### Package and Release Hygiene

* switch published output to ESM-only and remove CommonJS build artifacts ([169ebd9](https://github.com/alyldas/uniauth/commit/169ebd93b5244803c7eb0534f8d63fd771f97624))
* replace custom consumer and registry smoke scripts with `publint`, `attw`, Vitest export smoke, and `npm pack --dry-run` ([169ebd9](https://github.com/alyldas/uniauth/commit/169ebd93b5244803c7eb0534f8d63fd771f97624))
* add issue templates, PR template, Dependabot grouping, and solo-repo branch protection settings ([169ebd9](https://github.com/alyldas/uniauth/commit/169ebd93b5244803c7eb0534f8d63fd771f97624))
* document adapter authoring, generated files, release hygiene, licensing, and security policy updates ([169ebd9](https://github.com/alyldas/uniauth/commit/169ebd93b5244803c7eb0534f8d63fd771f97624))

## [0.4.0](https://github.com/alyldas/uniauth/compare/v0.3.0...v0.4.0) (2026-04-22)


### Features

* add UniAuth-cased public API names for errors, attribution, and service helpers ([c69c7f6](https://github.com/alyldas/uniauth/commit/c69c7f64005caaf3bd18e7b02dfa9cd3c900e47e))
* update public export smoke coverage for the UniAuth-cased names ([c69c7f6](https://github.com/alyldas/uniauth/commit/c69c7f64005caaf3bd18e7b02dfa9cd3c900e47e))
* align README and licensing examples with the final UniAuth casing ([c69c7f6](https://github.com/alyldas/uniauth/commit/c69c7f64005caaf3bd18e7b02dfa9cd3c900e47e))

## [0.3.0](https://github.com/alyldas/uniauth/compare/v0.2.0...v0.3.0) (2026-04-22)


### Features

* add generic OTP challenge start and finish flows for reusable verification orchestration ([ed568f8](https://github.com/alyldas/uniauth/commit/ed568f8ce4b96d4caa58139c606c223621bd77af))
* extend domain types, in-memory testing support, examples, and smoke coverage for OTP challenges ([ed568f8](https://github.com/alyldas/uniauth/commit/ed568f8ce4b96d4caa58139c606c223621bd77af))
* document OTP architecture, roadmap, and security behavior ([ed568f8](https://github.com/alyldas/uniauth/commit/ed568f8ce4b96d4caa58139c606c223621bd77af))

## [0.2.0](https://github.com/alyldas/uniauth/compare/v0.1.1...v0.2.0) (2026-04-22)


### Features

* add email OTP sign-in support to the auth service ([8b3b806](https://github.com/alyldas/uniauth/commit/8b3b806046a2c3c6e814e1f5985dd97f7787b372))
* add verification domain types, secret handling, in-memory sender support, and integration tests for email OTP flows ([8b3b806](https://github.com/alyldas/uniauth/commit/8b3b806046a2c3c6e814e1f5985dd97f7787b372))
* update examples, package smoke checks, architecture docs, roadmap, and security notes for email OTP ([8b3b806](https://github.com/alyldas/uniauth/commit/8b3b806046a2c3c6e814e1f5985dd97f7787b372))

## [0.1.1](https://github.com/alyldas/uniauth/compare/v0.1.0...v0.1.1) (2026-04-22)


### Bug Fixes

* add registry smoke release verification for published package imports ([8f5edd8](https://github.com/alyldas/uniauth/commit/8f5edd8ba5b8d93a8b73dced097bc8edfa55a478))
* document GitHub Packages registry verification in the README ([8f5edd8](https://github.com/alyldas/uniauth/commit/8f5edd8ba5b8d93a8b73dced097bc8edfa55a478))

## 0.1.0 (2026-04-22)


### Features

* add the initial headless auth domain core and public package surface ([e603371](https://github.com/alyldas/uniauth/commit/e60337107bc7ae8871863ac956ec41e8fafc5d36))
* establish the first TypeScript library structure, tests, docs, and examples ([e603371](https://github.com/alyldas/uniauth/commit/e60337107bc7ae8871863ac956ec41e8fafc5d36))


### Miscellaneous Chores

* prepare the initial Release Please workflow and generated-file ignore policy ([d9ca65f](https://github.com/alyldas/uniauth/commit/d9ca65f0ebd25fb3ddfe6d6100414fe9700cdb29))
