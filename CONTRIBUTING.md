# Contributing

## Releasing

1. Update `version` in `package.json` and add an entry to `CHANGELOG.md`.
2. Merge to `main` and wait for CI to pass.
3. Push a tag `v<version>` (for example `v0.1.1`). Tags with a pre-release suffix (`v0.2.0-rc.1`) publish under the `next` dist-tag; others publish under `latest`.
4. The `Release` workflow checks that the tag matches `package.json`, runs typecheck, build and tests, and publishes with provenance.

Publishing uses npm trusted publishing (OIDC) when it is configured for this repository; otherwise it falls back to the `NPM_TOKEN` repository secret. The first version of a new package has to be published by hand by a member of the `@relyt` npm organization, because trusted publishing can only be configured on an existing package.
