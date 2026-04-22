# Contributing

## Local Setup

```sh
npm ci
npm run check
```

Use focused commands while developing:

```sh
npm run test
npm run typecheck
npm run lint
```

## Package Gate

Before opening or updating a pull request, run:

```sh
npm run check
```

This matches the CI class of checks for the package: format check, lint, typecheck, 100% coverage,
export smoke tests, and `npm pack --dry-run`.

## Commit Messages

Commit messages are checked with Commitlint and the Conventional Commits format:

```text
feat: add provider registry
fix: prevent unsafe identity unlink
docs: update release checklist
```

Husky installs the local `commit-msg` hook from `npm run prepare` when the project is inside a git
repository. Outside git, the hook installer exits without changing anything.

## Contributor Licensing

By contributing to this repository, you agree that your contribution may be distributed under the
public package license and under separate commercial licenses or private agreements offered by the
project maintainer.

## Design Rules

- Keep core headless and framework-agnostic.
- Add provider, storage, and HTTP integrations around core, not inside core.
- Do not add silent account merge behavior.
- Keep public errors stable and avoid leaking account ownership state.
- Add tests for security-sensitive behavior before changing policy or orchestration.

## Useful Docs

- [Architecture](docs/architecture.md)
- [Security model](docs/security.md)
- [Roadmap](docs/roadmap.md)
