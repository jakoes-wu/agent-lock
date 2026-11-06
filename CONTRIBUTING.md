# Contributing

Thanks for your interest in agent-lock.

## Ground rules

- The tool uses the Python standard library only and must keep working on
  Python 3.8. Avoid syntax and APIs that 3.8 rejects (`list[str]` without
  `from __future__ import annotations`, `X | Y` unions, `match`).
- Do not run commands that create a user, write sudoers, load nftables, load
  pf, or create Windows firewall rules as part of development or tests.
  Generate the files and command lines. Tests assert that text.
- Never log the controller secret. `state.json` is mode `0600`. Wrappers,
  firewall rules, and `doctor --json` must not contain it.
- `agentnet` must not be placed in `sudo`, `wheel`, or Administrators.
- Keep paths such as `/Users/...` or `/home/...` out of the tests. CI rejects
  them. The macOS account home belongs in `src/`, not in a test literal.

## Development

```sh
python3 -m unittest discover -s tests -t tests
python3 -m pyflakes src tests
shellcheck -s sh install.sh
```

Installer tests pass `--prefix` to a temporary directory. They do not install
into your real home and they do not call `agent-lock install`.

`install.sh` honors `AGENT_LOCK_TEST_MODE=1` together with
`AGENT_LOCK_TEST_CRASH_SWAP` to stop between the two renames of an update.
A crash variable without test mode must not change a real install.

## Releasing

1. Open a release PR that bumps `__version__` in `src/agent_lock/__init__.py`
   and moves the `Unreleased` section of `CHANGELOG.md` under the new version.
2. After it is merged and CI on `main` passes, tag the merge commit and publish
   the release with your own credentials:
   `gh release create vX.Y.Z --notes-file ...` (a release created with the
   workflow token would not trigger the release workflows).
3. The `Release assets` workflow then uploads `agent-lock-vX.Y.Z.tar.gz` and
   `SHA256SUMS`. It fails if `__version__` does not match the tag. The tag is
   passed to the script only through the `TAG` environment variable.
4. Confirm both assets are on the release page and that
   `curl -fsSL .../install.sh | sh` prints `verified sha256` before announcing
   the release. Until the assets are uploaded, installs are unverified.
   The checksum detects a corrupted download. It does not prove the GitHub
   account was not compromised.
5. The `PyPI` workflow builds the package `agent-lock-cli` and publishes it
   through Trusted Publishing (environment `pypi`, no API token). Check that
   `pipx install agent-lock-cli` installs the new version. The command remains
   `agent-lock`. The wheel filename is
   `agent_lock_cli-<version>-py3-none-any.whl`.
6. After the first release asset exists, add the Homebrew formula in
   `jakoes-wu/homebrew-tap`: point `url` at `agent-lock-<tag>.tar.gz` and set
   `sha256` from `SHA256SUMS`.

## Pull requests

1. Open an issue first for larger changes.
2. Add or update tests for the behavior you change.
3. Update both `README.md` and `README.zh-CN.md` when user-facing behavior
   changes, and add an entry to `CHANGELOG.md`.
