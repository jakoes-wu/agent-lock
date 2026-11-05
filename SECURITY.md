# Security Policy

## Supported versions

Only the latest release receives security fixes.

## Reporting a vulnerability

Please report vulnerabilities privately through
[GitHub Security Advisories](https://github.com/jakoes-wu/agent-lock/security/advisories/new)
instead of opening a public issue. Include the version, your platform, and the
steps to reproduce. You should receive a reply within a week.

## Scope notes

- `state.json` is mode `0600` in the installing owner's state directory. It
  may hold the mihomo controller secret. The secret must not appear in
  wrappers, nftables or pf text, Windows rule names, logs, or `doctor --json`.
- `agentnet` is not an administrator. Install refuses to continue if that
  account is in `sudo`, `wheel`, `adm`, or Administrators. Passwordless sudo
  is granted only for `/usr/local/sbin/agent-lock`, and the root branch of
  that switcher drops to `agentnet` before it runs the requested command.
- Shared credential files are readable by `agentnet` because the agent runs
  as that user. The macOS Claude keychain is not shared.
- A human with the sudo password can undo the firewall. Unix domain sockets
  are not filtered by the packet rules.
- The release checksum detects a corrupted download. It does not prove the
  GitHub account was not compromised.
