# Versioning policy

`rrcd` uses Semantic Versioning (SemVer 2.0.0): `MAJOR.MINOR.PATCH`.

## Compatibility promises

- **Patch** releases are for bug fixes and internal refactors that do not change public behavior.
- **Minor** releases may add functionality in a backwards-compatible way.
- **Major** releases may include breaking changes.

### Pre-1.0 (current)

Before `1.0.0`, the project is still stabilizing. We still try to avoid breaking changes, but:

- Breaking changes may occur in **minor** releases.
- When possible, we will call out breaking changes prominently in the changelog.

## What counts as a breaking change

A change is considered breaking if it requires updating an existing deployment or client setup, including:

- Changes to the RRC hub on-wire behavior that existing clients depend on
- Changes to configuration keys or defaults that change behavior in surprising ways
- Changes to persisted file formats (`rrcd.toml`, `rooms.toml`) that are not backwards-compatible

## Deprecation policy

When we can do so safely, we prefer deprecation over immediate removal:

- Deprecations are documented in the changelog.
- A deprecation may include a warning period before removal (typically at least one minor release).

## Release notes

Every release updates CHANGELOG.md.
