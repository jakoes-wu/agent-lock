# agent-lock

**English** | [简体中文](README.zh-CN.md)

[![Release](https://img.shields.io/github/v/release/jakoes-wu/agent-lock)](https://github.com/jakoes-wu/agent-lock/releases)
[![CI](https://github.com/jakoes-wu/agent-lock/actions/workflows/ci.yml/badge.svg)](https://github.com/jakoes-wu/agent-lock/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/agent-lock-cli)](https://pypi.org/project/agent-lock-cli/)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Lock agent commands to the local HTTP proxy by running them as the user `agentnet`.

Codex and Claude, and the programs they start, run as an unprivileged account. The firewall of that account accepts TCP only to the local Clash / mihomo mixed port (`http://127.0.0.1:<mixed-port>`) and to loopback ports you name with `--allow-tcp`. Other TCP, UDP, and ICMP from that account is dropped. The firewall matches the account, not a process path.

`agent-lock` does not start your proxy and it does not edit `multi-codex` or `multi-claude`. netcheck is not this tool. The checks in this repository generate firewall text and classify command output. They do not load nftables, pf, or Windows Firewall on the machine that runs them.

## Install the command

From a clone:

```sh
git clone https://github.com/jakoes-wu/agent-lock.git
cd agent-lock
./install.sh
```

Or directly:

```sh
curl -fsSL https://raw.githubusercontent.com/jakoes-wu/agent-lock/main/install.sh | sh
```

The command is installed under `~/.local` (`--prefix` changes that). The installer prints a `PATH` hint and does not edit your shell profile.

From PyPI: `pipx install agent-lock-cli`. Use either pipx or `install.sh`, not both: they both provide an `agent-lock` command. The PyPI project is `agent-lock-cli` because `agentlock` is already published there.

The Homebrew formula is added after the first release asset exists. Until then, use the installer or pipx.

**Verified downloads.** A release publishes `agent-lock-<tag>.tar.gz` and `SHA256SUMS`. The remote installer checks the SHA-256 before it installs. A mismatch stops the install. Branches, and releases that have no such asset, are installed unverified (the installer says so). Set `AGENT_LOCK_REQUIRE_CHECKSUM=1` to refuse those. The checksum detects a corrupted download. It does not prove the GitHub account was not compromised.

`./install.sh` only installs the Python command. It does not create `agentnet` and it does not load a firewall. That is `agent-lock install`, below.

## Lock the account

Point Clash / mihomo at a loopback mixed port, then:

```sh
sudo agent-lock install
agent-lock doctor
agent-lock exec -- true
```

`install` discovers `mixed-port` from the controller (`GET /configs`). If discovery fails, pass `--port`. A later install without `--allow-tcp` clears the extra loopback list. A loopback service that then dials the network is a second exit beside the proxy.

On Linux and macOS, `install` writes `CLAUDE_CODE_PROCESS_WRAPPER` to the Claude settings it records, after `claude daemon stop --any`. That variable does not apply on Windows. This repository does not write Windows Claude settings, does not change scheduled tasks, and does not store a password. Windows Claude must be started from `runas /user:agentnet`. There is no passwordless `runas`.

`doctor` checks the account, the firewall text, the wrappers, and (where the platform allows it) that a direct connection from `agentnet` fails while the proxy and the owner's own direct TCP still work. `doctor --json` prints schema version 1 and does not print the controller secret. `doctor --repair` reapplies credential ACLs only. It does not change the port and it does not chown launchers.

`uninstall` removes the lock this tool installed. It does not follow or delete the directories you shared, and it does not remove a home directory.

## What you are accepting

- `agentnet` can read the credential files you share (`~/.codex`, `~/.cx`, `~/.claude`, `~/.cc`, and `--share-dir`). That is the cost of running the agent as that user. The macOS Claude keychain is not shared.
- On macOS, Desktop, Documents, and Downloads (including iCloud Mobile Documents) are TCC-protected. Keep repositories outside those folders. `--share-dir` refuses them.
- With umask 002, new files in a bind-bin directory become 0664 and are writable by agentnet, and new subdirectories inherit setgid. A new subdirectory created with umask 002 is 2775, so run `bind-bin` on it again. `bind-bin` is Linux only. Launchers themselves are not written by this repository.
- Unix domain sockets are not filtered. If `agentnet` can connect to the mihomo unix socket, `doctor` fails that check. It does not chmod the socket.
- A human with the sudo password can undo the firewall.
- `agentnet` is not an administrator and is not added to `sudo` or Administrators. An existing disabled account is left alone and install fails. An existing enabled account keeps its password.

## Shell completion

Completion is generated from the same argparse parser as the help text. `agent-lock completion <shell>` prints the script even when the lock is not installed.

```sh
# bash, in ~/.bashrc (macOS bash 3.2, no bash-completion package)
eval "$(agent-lock completion bash)"

# zsh, after compinit
eval "$(agent-lock completion zsh)"

# fish
agent-lock completion fish | source

# PowerShell
agent-lock completion powershell | Out-String | Add-Content $PROFILE
```

Filename completion is only offered for `--claude-dir`, `--share-dir`, `--trust-exec`, and the `bind-bin` directory. `--port`, `--allow-tcp`, `--controller`, and the command after `exec --` do not complete filenames.

## Platforms

| | Firewall | Account |
| --- | --- | --- |
| Linux | nftables `inet` table, one transaction, output hook on the uid | `useradd` when missing, `passwd -l`, home `/var/lib/agentnet` |
| macOS | pf `user` rules in an anchor inserted before `anchor "com.apple/*"` | `sysadminctl` when missing |
| Windows | block rules for literal non-loopback ranges and for loopback ports other than the mixed port | `New-LocalUser`, not an Administrator |

firewalld, a pf `pass quick` already sitting before the Apple anchor, or a Windows policy that does not merge local firewall rules is unsupported (`exit 4`). Install does not run `pfctl -d`. nftables that rejects `destroy table` is also unsupported and install exits 4. nftables 1.0.2 on Ubuntu 22.04 is one of those builds.

## Development

Python 3.8 or newer, standard library only.

```sh
python3 -m pyflakes src tests
python3 -m unittest discover -s tests -t tests -v
shellcheck -s sh install.sh
```

Tests must pass without root, without nft, without pfctl, and without Windows. Do not run `install.sh` against your real home while developing; the installer tests pass `--prefix` to a temporary directory. Do not run `agent-lock install` on a machine unless you intend to create `agentnet` and load a firewall.
