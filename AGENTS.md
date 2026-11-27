# Apassy releases

- Every release bumps all six components together to one new version: iOS app,
  macOS app, Linux CLI (`apassy-team`), browser extension, relay, and website.
  This applies even when a component has no functional changes. Never publish a
  same-version rebuild as a new release or leave components on different versions.
- Update `release-versions.json`, app/core Cargo manifests and lockfile, iOS
  `MARKETING_VERSION`, extension manifest, and dated changelog together. The website
  derives its version from the changelog. The relay is the crate `crates/apassy-relay`
  of this workspace (ADR 0037); its package version, with the edge Worker package,
  also versions the Linux CLI. Its own rules are in `crates/apassy-relay/AGENTS.md`.
- The `linux-cli` component is the Linux node (`apassy`, from `crates/apassy-app` built
  `--no-default-features --features node`; packages from `relay-image.yml`, see
  `docs/operations/release.md`, "Linux node packages"); its version is the relay crate's.
- Run `python3 scripts/check-release-versions.py` with Python 3.12 before publication.
  Local source checks do not prove publication.
- iOS `CURRENT_PROJECT_VERSION` / `APASSY_IOS_BUILD` is an upload build number,
  separate from the shared marketing version. Check App Store Connect for a usable
  higher build number; incrementing it alone is not a new release.
- Verify each delivered artifact and live version: signed macOS download and
  `latest.json`, processed TestFlight build and intended group, public extension
  listing/package, Linux download/checksum/version, running relay version, and live
  website/changelog. Pending store review is not published.
- Do not report a complete release until all six are live at the shared version.
  If blocked, identify each unfinished component, its actual version, and the blocker.
- `deploy/plugins/` is not a release component. Its plugin version follows the repository
  version, but a marketplace listing is published separately, and only with the owner's OK.

# Pull requests and CI

- Open each pull request as a draft (`gh pr create --draft`) and keep it a draft
  while you still push fixes. Mark it ready (`gh pr ready`) when the work is
  complete; that runs the full suite, macOS test groups included.
- A draft run skips the macOS test groups because the account has five macOS
  runners for all runs. A green draft run is not a green PR: merge only after the
  run of the ready PR succeeds.
- CI runs the Rust tests with cargo-nextest (`.config/nextest.toml`): each test in
  its own process, several at a time. Run them the same way:
  `cargo nextest run --all-features --all-targets` and
  `cargo nextest run -p apassy-relay -p apassy-core`; nextest skips doc tests, so
  also run `cargo test --features vault --doc`. A test that uses a fixed port, a
  fixed path, or the Keychain must not run beside other tests: give it a free port
  and a temporary directory, or put it in the `serial` test group with the reason.

# Local tests on the Mac mini

- Use GitHub Actions for full test suites and release builds.
  Use CI artifacts for local app checks when possible.
- Limit local builds to focused tests, native UI checks, and device or simulator checks.
  Run other local builds only when the user requests them.
- When the tools support it, use a separate target directory for each local test session.
- After each local test session, remove the build files that the session created.
  This applies after failed tests too.
  Keep required test evidence outside `target` before cleanup.
- Before cleanup, make sure all related builds, tests, apps, and simulator runs have stopped.
  Never remove a target directory that another session uses.
- If the session created the whole target directory, remove it after the checks.
  If the directory existed before the session, remove only build files from that session.
  Do not remove source files, user data, or files from another session.
- If cleanup is blocked, report the remaining path, size, and reason.
  Report the test result and available disk space after cleanup.
