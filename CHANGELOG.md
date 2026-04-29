# Changelog

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
