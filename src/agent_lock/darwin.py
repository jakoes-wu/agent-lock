"""macOS pf anchor. The enable token is released with pfctl -X. pf is never disabled."""

import os

from .errors import AgentLockError
from .state import AGENT_USER, DARWIN_AGENT_HOME

PF_CONF = "/etc/pf.conf"
PF_BACKUP = "/etc/pf.conf.agent-lock-bak"
ANCHOR_PATH = "/etc/pf.anchors/agentlock"
ANCHOR_NAME = "agentlock"
BEGIN = "# agent-lock begin"
END = "# agent-lock end"
APPLE_ANCHOR = 'anchor "com.apple/*"'
ACL_ENTRY = (
    "agentnet allow read,write,execute,delete,add_file,add_subdirectory,"
    "file_inherit,directory_inherit"
)
HOME_ACL_ENTRY = "agentnet allow execute"

TCC_TOP = ("Desktop", "Documents", "Downloads")


class PfRefuse(AgentLockError):
    """A pass quick rule already sits before the only legal insertion point."""

    def __init__(self, message):
        super(PfRefuse, self).__init__(message, 1)


def anchor_block():
    return (
        "# agent-lock begin\n"
        'anchor "agentlock"\n'
        'load anchor "agentlock" from "/etc/pf.anchors/agentlock"\n'
        "# agent-lock end\n"
    )


def render_anchor(port, extra_tcp):
    """Anchor body. Extra pass rules only when extra_tcp is non-empty."""
    from .allow import parse_allow_tcp_value
    port = int(port)
    lines = [
        "# agent-lock anchor. Safe to delete this file on uninstall.",
        "pass out quick inet proto tcp to 127.0.0.1 port {0} user {1} keep state".format(
            port, AGENT_USER),
        "pass out quick inet6 proto tcp to ::1 port {0} user {1} keep state".format(
            port, AGENT_USER),
    ]
    for value in extra_tcp or []:
        host, extra_port = parse_allow_tcp_value(value)
        family = "inet" if host == "127.0.0.1" else "inet6"
        lines.append(
            "pass out quick {family} proto tcp to {host} port {port} user {user} keep state".format(
                family=family, host=host, port=extra_port, user=AGENT_USER))
    lines.append(
        "block drop out quick proto { tcp, udp, icmp, ipv6-icmp } user %s" % AGENT_USER)
    lines.append("")
    return "\n".join(lines)


def _lines(text):
    if text == "":
        return []
    # Keep the newline on every line except possibly the last empty split.
    return text.splitlines(keepends=True)


def _join(lines):
    return "".join(lines)


def _apple_index(lines):
    for index, line in enumerate(lines):
        if line.strip() == APPLE_ANCHOR:
            return index
    return None


def _is_pass_quick(line):
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return False
    return "pass" in stripped and "quick" in stripped


def _pass_quick_before(lines, marker_index):
    for line in lines[:marker_index]:
        if _is_pass_quick(line):
            return True
    return False


def _marker_span(lines):
    begin = None
    end = None
    for index, line in enumerate(lines):
        if line.strip() == BEGIN:
            begin = index
        elif line.strip() == END and begin is not None and end is None:
            end = index
            break
    if begin is None and end is None:
        return None
    if begin is None or end is None or end < begin:
        raise PfRefuse("agent-lock pf markers are incomplete")
    return begin, end


def patch_pf_conf(text):
    """Insert or replace the anchor block before anchor "com.apple/*".

    If that line is missing, the block goes at the start of the file, not the end.
    A pass quick rule before the block is a refusal, not a reason to append.
    """
    lines = _lines(text)
    if text and not text.endswith("\n"):
        # splitlines(keepends) already dropped a missing final newline.
        pass
    span = _marker_span(lines)
    block_lines = _lines(anchor_block())
    if span is None:
        apple = _apple_index(lines)
        if apple is None:
            lines = block_lines + lines
        else:
            lines = lines[:apple] + block_lines + lines[apple:]
    else:
        begin, end = span
        lines = lines[:begin] + block_lines + lines[end + 1:]
    span = _marker_span(lines)
    if span is None:
        raise PfRefuse("agent-lock pf markers were not written")
    if _pass_quick_before(lines, span[0]):
        raise PfRefuse(
            "refusing to install: a pass quick rule is before the agent-lock anchor")
    apple = _apple_index(lines)
    if apple is not None and span[0] > apple:
        raise PfRefuse('agent-lock anchor is not before anchor "com.apple/*"')
    rendered = _join(lines)
    if text.endswith("\n") or text == "":
        if not rendered.endswith("\n"):
            rendered += "\n"
    return rendered


def unpatch_pf_conf(text):
    """Drop the agent-lock anchor block. Leave every other line in place."""
    lines = _lines(text)
    span = _marker_span(lines)
    if span is None:
        return text
    begin, end = span
    return _join(lines[:begin] + lines[end + 1:])


def user_plan(exists):
    """Skip sysadminctl when the account already exists. Password is not an argument."""
    if exists:
        return []
    return [
        [
            "sysadminctl", "-addUser", AGENT_USER, "-fullName", AGENT_USER,
            "-password", "-", "-home", DARWIN_AGENT_HOME, "-shell", "/usr/bin/false",
        ],
        ["dscl", ".", "-create", "/Users/%s" % AGENT_USER, "IsHidden", "1"],
    ]


def is_tcc_path(path, home):
    """Desktop, Documents, Downloads, and iCloud container trees are refused."""
    path = os.path.abspath(path)
    home = os.path.abspath(home)
    relative = os.path.relpath(path, home)
    if relative.startswith(".."):
        return False
    parts = [] if relative == "." else relative.split(os.sep)
    if parts and parts[0] in TCC_TOP:
        return True
    if len(parts) >= 2 and parts[0] == "Library" and parts[1] == "Mobile Documents":
        return True
    return False


def acl_commands(directories, owner_home, home_needs_execute):
    """NFSv4 ACL. -a then +a keeps a single entry. No launcher chown."""
    commands = []
    if home_needs_execute:
        commands.append(["chmod", "-a", HOME_ACL_ENTRY, owner_home])
        commands.append(["chmod", "+a", HOME_ACL_ENTRY, owner_home])
    for directory in directories:
        commands.append(["chmod", "-a", ACL_ENTRY, directory])
        commands.append(["chmod", "+a", ACL_ENTRY, directory])
    return commands


def parse_enable_token(output):
    """Pull the token printed by pfctl -E. Empty output yields an empty token."""
    token = ""
    for line in (output or "").splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("token"):
            _label, _sep, value = stripped.partition(":")
            value = value.strip()
            if value:
                token = value
    return token


def enable_argv():
    return ["pfctl", "-E"]


def release_token_argv(token):
    """None when there is no token. Never disables the packet filter."""
    if not token:
        return None
    return ["pfctl", "-X", token]


def check_conf_argv(path=PF_CONF):
    return ["pfctl", "-nf", path]


def load_conf_argv(path=PF_CONF):
    return ["pfctl", "-f", path]


def load_anchor_argv(path=ANCHOR_PATH):
    return ["pfctl", "-a", ANCHOR_NAME, "-f", path]
