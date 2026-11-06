# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.1] - 2026-11-05

### Changed

- The PyPI distribution name is `agent-lock-cli`. The command remains `agent-lock`.
  PyPI already publishes `agentlock`, and it treats `agent-lock` as that same name.

## [0.1.0] - 2026-11-05

### Added

- `agent-lock install`, `uninstall`, `doctor`, `exec`, `bind-bin`, and
  `completion` for bash, zsh, fish, and PowerShell.
- Linux nftables, macOS pf, and Windows Firewall rule generation that locks
  the unprivileged user `agentnet` to the local Clash mixed port, plus
  optional `--allow-tcp` loopback exceptions.
- `doctor` classification of the proxy curl, the direct probe, and platform
  counters, with `--json` schema version 1 and `--repair` for credential ACLs.
- `install.sh` with release asset `agent-lock-<tag>.tar.gz` and `SHA256SUMS`,
  matching the multi-claude installer flow. The checksum detects a corrupted
  download. It does not prove the GitHub account was not compromised.
