"""Linux nftables table, systemd oneshot, setfacl, and the agentnet user.

Subprocess calls that change the machine go through `run`, which tests replace.
Nothing here loads a ruleset unless `load_nft` is called.
"""

import os
import shutil
import stat
import subprocess

from .errors import AgentLockError, Unsupported
from .state import AGENT_USER, LINUX_AGENT_HOME

NFT_CONF = "/etc/agent-lock/nftables.conf"
UNIT_PATH = "/etc/systemd/system/agent-lock-nft.service"
UNIT_NAME = "agent-lock-nft.service"
TABLE = "inet agentlock"
NOLOGIN = "/usr/sbin/nologin"


def run(argv, check=False, input_text=None, timeout=30):
    return subprocess.run(
        argv,
        input=input_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        timeout=timeout,
        check=check,
    )


def render_nft(uid, port, extra_tcp):
    """One nft -f transaction: destroy, declare counters, then the chain."""
    uid = int(uid)
    port = int(port)
    extras = _normalize_extra(extra_tcp)
    lines = [
        "destroy table inet agentlock",
        "table inet agentlock {",
        "    counter agentlock_accept_v4 { }",
        "    counter agentlock_accept_v6 { }",
        "    counter agentlock_drop { }",
    ]
    for extra_port in _extra_ports(extras):
        lines.append("    counter agentlock_accept_v4_{0} {{ }}".format(extra_port))
        lines.append("    counter agentlock_accept_v6_{0} {{ }}".format(extra_port))
    lines.extend([
        "    chain output {",
        "        type filter hook output priority -10; policy accept;",
        "        meta skuid {uid} ip daddr 127.0.0.1 tcp dport {port} "
        "counter name agentlock_accept_v4 accept".format(uid=uid, port=port),
        "        meta skuid {uid} ip6 daddr ::1 tcp dport {port} "
        "counter name agentlock_accept_v6 accept".format(uid=uid, port=port),
    ])
    for host, extra_port in extras:
        if host == "127.0.0.1":
            lines.append(
                "        meta skuid {uid} ip daddr 127.0.0.1 tcp dport {port} "
                "counter name agentlock_accept_v4_{port} accept".format(uid=uid, port=extra_port))
        else:
            lines.append(
                "        meta skuid {uid} ip6 daddr ::1 tcp dport {port} "
                "counter name agentlock_accept_v6_{port} accept".format(uid=uid, port=extra_port))
    lines.extend([
        "        meta skuid {uid} counter name agentlock_drop drop".format(uid=uid),
        "    }",
        "}",
        "",
    ])
    return "\n".join(lines)


def _extra_ports(extras):
    seen = []
    for _host, extra_port in extras:
        if extra_port not in seen:
            seen.append(extra_port)
    return seen


def _normalize_extra(extra_tcp):
    from .allow import parse_allow_tcp_value
    items = []
    for value in extra_tcp or []:
        items.append(parse_allow_tcp_value(value))
    return items


def render_unit(nft_bin="/usr/sbin/nft", conf_path=NFT_CONF):
    return """[Unit]
Description=Load agent-lock nftables table
After=nftables.service ufw.service firewalld.service
Before=systemd-user-sessions.service display-manager.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={nft} -f {conf}
ExecStop=-{nft} delete table inet agentlock

[Install]
WantedBy=multi-user.target
""".format(nft=nft_bin, conf=conf_path)


def bind_bin_mode(old):
    """(old | setgid | group read | group exec) with group write cleared."""
    return (old | stat.S_ISGID | stat.S_IRGRP | stat.S_IXGRP) & ~stat.S_IWGRP


def validate_bind_bin(euid, is_link, is_dir, uid, owner_uid):
    """Return (exit code, message). 0 means the directory may be marked."""
    if euid != 0:
        return 1, "agent-lock: bind-bin needs root; run it with sudo"
    if is_link or not is_dir:
        return 2, "agent-lock: bind-bin refuses a symlink or a non-directory"
    if uid != owner_uid:
        return 1, "agent-lock: bind-bin refuses a directory not owned by the installing user"
    return 0, ""


def user_plan(user_exists, group_exists, home_exists, current_shell):
    """Commands to converge the account.

    An existing user is not passed to useradd and its password is not changed.
    --create-home is omitted when the home directory is already there.
    passwd -l runs only for a user created in this round.
    """
    commands = []
    created = False
    if user_exists:
        if current_shell != NOLOGIN:
            commands.append(["usermod", "--shell", NOLOGIN, AGENT_USER])
    elif group_exists:
        commands.append(_useradd(home_exists, group=True))
        created = True
    else:
        commands.append(_useradd(home_exists, group=False))
        created = True
    if created:
        commands.append(["passwd", "-l", AGENT_USER])
    return commands, created


def _useradd(home_exists, group):
    command = ["useradd", "--system"]
    if group:
        command.extend(["--gid", AGENT_USER])
    else:
        command.append("--user-group")
    command.extend(["--home-dir", LINUX_AGENT_HOME, "--shell", NOLOGIN])
    if not home_exists:
        command.append("--create-home")
    command.append(AGENT_USER)
    return command


def firewalld_is_active(runner=None):
    runner = runner or run
    try:
        result = runner(["systemctl", "is-active", "firewalld.service"])
    except (OSError, subprocess.SubprocessError):
        return False
    stdout = getattr(result, "stdout", "") or ""
    code = getattr(result, "returncode", 1)
    return code == 0 and stdout.strip() == "active"


def require_firewalld_inactive(runner=None):
    if firewalld_is_active(runner):
        raise Unsupported(
            "firewalld is active; agent-lock does not install while firewalld would drop the table")


def find_nft():
    return shutil.which("nft")


def find_runuser():
    return shutil.which("runuser")


def nft_check_argv(nft_bin, conf_path):
    return [nft_bin, "-c", "-f", conf_path]


def nft_load_argv(nft_bin, conf_path):
    return [nft_bin, "-f", conf_path]


def parent_dirs(path, owner_home):
    """Parents from the owner home down to, but not including, path. Traverse only."""
    path = os.path.abspath(path)
    home = os.path.abspath(owner_home)
    parents = []
    current = os.path.dirname(path)
    while current and current != os.path.dirname(current):
        if _is_same_or_under(current, home) or current == home:
            parents.append(current)
        if current == home:
            break
        current = os.path.dirname(current)
    parents.reverse()
    return parents


def _is_same_or_under(path, root):
    path = os.path.abspath(path)
    root = os.path.abspath(root)
    if path == root:
        return True
    prefix = root.rstrip(os.sep) + os.sep
    return path.startswith(prefix)


def setfacl_commands(entries):
    """entries are (path, kind) with kind in {dir, file, parent}. No default ACL."""
    commands = []
    for path, kind in entries:
        if kind == "dir":
            spec = "u:{user}:rwX,m::rwX".format(user=AGENT_USER)
        elif kind == "file":
            spec = "u:{user}:rw-,m::rw-".format(user=AGENT_USER)
        elif kind == "parent":
            spec = "u:{user}:--x,m::--x".format(user=AGENT_USER)
        else:
            raise AgentLockError("unknown setfacl kind")
        commands.append(["setfacl", "-m", spec, path])
    return commands


def credential_entries(roots, owner_home, classify):
    """classify(path) -> 'dir', 'file', 'link', or 'missing'. Symlinks are skipped."""
    entries = []
    seen_parents = set()
    for root in roots:
        if classify(root) == "missing":
            continue
        for parent in parent_dirs(root, owner_home):
            if parent not in seen_parents:
                seen_parents.add(parent)
                entries.append((parent, "parent"))
        _walk(root, classify, entries)
    return entries


def _walk(path, classify, entries):
    kind = classify(path)
    if kind == "link" or kind == "missing":
        return
    if kind == "file":
        entries.append((path, "file"))
        return
    if kind != "dir":
        return
    entries.append((path, "dir"))
    try:
        names = os.listdir(path)
    except OSError:
        return
    for name in sorted(names):
        _walk(os.path.join(path, name), classify, entries)


def classify_path(path):
    try:
        st = os.lstat(path)
    except OSError:
        return "missing"
    if stat.S_ISLNK(st.st_mode):
        return "link"
    if stat.S_ISDIR(st.st_mode):
        return "dir"
    if stat.S_ISREG(st.st_mode):
        return "file"
    return "other"
