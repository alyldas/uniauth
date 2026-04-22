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

## Release Flow

Use Conventional Commits and let Release Please prepare releases. Regular development commits should
not manually change release metadata.

Release Please owns these files in its release PR:

- `package.json`: package version.
- `package-lock.json`: lockfile package version.
- `CHANGELOG.md`: release section and compare links.

After changes land on `main`, Release Please opens or updates the release PR. Merge that release PR
to let the release workflow create the `v*` tag, GitHub release notes, and GitHub Packages publish.

## Changelog Policy

`CHANGELOG.md` is release metadata. Do not edit it in regular feature, fix, refactor, docs, or test
pull requests.

Release Please creates and updates changelog entries from the Conventional Commits that land on
`main`. Keep commit messages user-facing enough to become release notes without heavy editing.

Every changelog bullet must link to the commit that introduced the change. Release Please does this
automatically for conventional commits. If a release PR needs manual changelog cleanup, keep the
commit links and compare links intact.

Prefer concrete release notes over vague summaries. Good entries name the behavior, API, package
contract, or operational workflow that changed. Avoid entries that only say "cleanup", "refactor",
or "misc changes" unless that is genuinely the public release impact.

Manual changelog edits are allowed only in Release Please PRs or dedicated documentation cleanup
pull requests. When a large feature was already squash-merged, multiple clarified changelog bullets
may point to the same squash commit, but future large changes should preserve individual commits so
the generated changelog is naturally granular.

## Merge Policy

The repository is configured for a solo-maintainer workflow:

- `main` requires pull requests.
- The required status check is `check`.
- Branches must be up to date before merge.
- Conversations must be resolved before merge.
- Force pushes and branch deletion are blocked.
- Administrator enforcement is enabled.
- Required approving reviews are disabled until the project has more maintainers.

Use rebase merge for regular feature, API, security, and package-hygiene pull requests. Keep each
change as a small, Conventional Commit so Release Please can build useful changelog entries from the
commits that land on `main`.

Do not squash large feature, API, or package-hygiene pull requests if the release should have a
useful changelog. Squash merge turns the entire pull request into one commit, so Release Please can
only create one changelog entry.

Squash merge is acceptable for small single-purpose pull requests and for Release Please pull
requests such as `chore(main): release 0.5.0`.

Merge commits are disabled for this repository. Prefer a linear `main` history with rebase merges
for development PRs and squash merges for release PRs.

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
