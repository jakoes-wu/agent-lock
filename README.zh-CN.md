# agent-lock

[English](README.md) | **简体中文**

[![Release](https://img.shields.io/github/v/release/jakoes-wu/agent-lock)](https://github.com/jakoes-wu/agent-lock/releases)
[![CI](https://github.com/jakoes-wu/agent-lock/actions/workflows/ci.yml/badge.svg)](https://github.com/jakoes-wu/agent-lock/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/agent-lock)](https://pypi.org/project/agent-lock/)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

把代理命令锁到本机 HTTP 代理上：以用户 `agentnet` 运行它们。

Codex、Claude，以及它们拉起的程序，都跑在这个没有管理员权限的账户里。该账户的防火墙只放行到本机 Clash / mihomo 混合端口的 TCP（`http://127.0.0.1:<mixed-port>`），以及你用 `--allow-tcp` 点名的回环端口。这个账户发出的其它 TCP、UDP 和 ICMP 会被丢掉。防火墙认的是账户，不是进程路径。

`agent-lock` 不启动你的代理，也不修改 `multi-codex` 或 `multi-claude`。netcheck is not this tool. 本仓库的测试只生成防火墙文本、并给命令输出分类。它们不会在跑测试的机器上加载 nftables、pf 或 Windows 防火墙。

## 安装命令

从克隆安装：

```sh
git clone https://github.com/jakoes-wu/agent-lock.git
cd agent-lock
./install.sh
```

或者：

```sh
curl -fsSL https://raw.githubusercontent.com/jakoes-wu/agent-lock/main/install.sh | sh
```

命令装在 `~/.local`（可用 `--prefix` 换位置）。安装脚本只打印 `PATH` 提示，不改你的 shell 配置。

也可以从 PyPI 安装：`pipx install agent-lock`。`pipx` 和 `install.sh` 二选一，它们都会提供 `agent-lock` 命令。

Homebrew 公式会在第一个 release 附件存在之后再加上。在那之前用安装脚本或 pipx。

**校验下载。** 每个 release 发布 `agent-lock-<tag>.tar.gz` 和 `SHA256SUMS`。远程安装会先核对 SHA-256，不一致就停止。分支，以及没有这两个附件的 release，会在提示后未校验安装。设置 `AGENT_LOCK_REQUIRE_CHECKSUM=1` 可以拒绝它们。The checksum detects a corrupted download. It does not prove the GitHub account was not compromised.

`./install.sh` 只安装 Python 命令。它不创建 `agentnet`，也不加载防火墙。那是下面的 `agent-lock install`。

## 锁住账户

先让 Clash / mihomo 监听一个回环混合端口，然后：

```sh
sudo agent-lock install
agent-lock doctor
agent-lock exec -- true
```

`install` 从控制器 `GET /configs` 读取 `mixed-port`。发现失败时请传 `--port`。之后再跑一次安装且不带 `--allow-tcp`，会清空额外回环端口。A loopback service that then dials the network is a second exit beside the proxy.

在 Linux 和 macOS 上，`install` 会先执行 `claude daemon stop --any`，再把 `CLAUDE_CODE_PROCESS_WRAPPER` 写到它记录的 Claude 设置里。这个变量 does not apply on Windows。本仓库不写 Windows 上的 Claude 设置，不改计划任务，也不保存密码。Windows Claude must be started from `runas /user:agentnet`。没有免密码的 `runas`。

`doctor` 检查账户、防火墙文本和包装脚本，并在平台允许时确认：`agentnet` 的直连失败，而代理和原用户自己的直连 TCP 仍然成功。`doctor --json` 打印第 1 版结构，且不打印控制器密钥。`doctor --repair` 只重新应用凭据 ACL。它不改端口，也不 chown 启动脚本。

`uninstall` 去掉本工具装上的锁。它不跟随、也不删除你共享出去的目录，也不删除家目录。

## 你需要接受的事

- `agentnet` 能读取你共享的凭据文件（`~/.codex`、`~/.cx`、`~/.claude`、`~/.cc`，以及 `--share-dir`）。这是让代理以该用户运行的代价。macOS 上的 Claude 钥匙串不会被共享。
- 在 macOS 上，Desktop、Documents、Downloads（含 iCloud Mobile Documents）受 TCC 保护。仓库请放在这些目录外面。`--share-dir` 会拒绝它们。
- With umask 002, new files in a bind-bin directory become 0664 and are writable by agentnet, and new subdirectories inherit setgid. umask 002 下新建的子目录是 2775，需要对它再跑一次 `bind-bin`。`bind-bin` 只在 Linux 上使用。本仓库不写启动脚本本身。
- Unix domain sockets are not filtered. 如果 `agentnet` 能连上 mihomo 的 unix 套接字，`doctor` 的这项检查失败。它不会去 chmod 那个套接字。
- A human with the sudo password can undo the firewall.
- `agentnet` 不是管理员，也不会被加入 `sudo` 或 Administrators。已经存在但被禁用的账户不会被动过，安装会失败。已经启用的账户保留原密码。

## 补全

补全脚本和帮助文本来自同一个 argparse 解析器。即使还没装锁，`agent-lock completion <shell>` 也会把脚本打出来。

```sh
# bash，写入 ~/.bashrc（macOS bash 3.2，不需要 bash-completion）
eval "$(agent-lock completion bash)"

# zsh，放在 compinit 之后
eval "$(agent-lock completion zsh)"

# fish
agent-lock completion fish | source

# PowerShell
agent-lock completion powershell | Out-String | Add-Content $PROFILE
```

只有 `--claude-dir`、`--share-dir`、`--trust-exec` 和 `bind-bin` 的目录做文件名补全。`--port`、`--allow-tcp`、`--controller`，以及 `exec --` 后面的命令，不补文件名。

## 平台

| | 防火墙 | 账户 |
| --- | --- | --- |
| Linux | nftables `inet` 表，一次事务，按 uid 的 output 钩子 | 没有用户时 `useradd`，`passwd -l`，家目录 `/var/lib/agentnet` |
| macOS | pf `user` 规则，锚点插在 `anchor "com.apple/*"` 之前 | 没有用户时 `sysadminctl` |
| Windows | 用字面非回环地址段拦截，回环上只拦混合端口以外的端口 | `New-LocalUser`，不是 Administrator |

firewalld 正在运行、Apple 锚点之前已经有 `pass quick`，或者 Windows 策略不合并本地防火墙规则时，安装不受支持（退出码 4）。安装不会执行 `pfctl -d`。不接受 `destroy table` 的 nftables 同样不受支持，安装退出 4。Ubuntu 22.04 自带的 nftables 1.0.2 就是这种情况。

## 开发

需要 Python 3.8 或更新版本，只用标准库。

```sh
python3 -m pyflakes src tests
python3 -m unittest discover -s tests -t tests -v
shellcheck -s sh install.sh
```

测试必须在没有 root、没有 nft、没有 pfctl、也没有 Windows 的机器上通过。开发时不要对真实的家目录运行 `install.sh`；安装脚本的测试会把 `--prefix` 指到临时目录。除非你打算创建 `agentnet` 并加载防火墙，否则不要在机器上运行 `agent-lock install`。
