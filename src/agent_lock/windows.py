"""Windows outbound Block rules. No Allow rules. No RemoteAddress keywords.

A Block must not match 127.0.0.1:PORT or ::1:PORT. Loopback TCP uses dash
ranges and omits an empty range when the port is 1 or 65535.
"""

import ipaddress
import os

from .errors import AgentLockError, Unsupported
from .state import AGENT_USER

# Doctor rejects these. They are not written into rules.
REMOTE_KEYWORDS = (
    "Internet",
    "Intranet",
    "IntranetRemoteAccess",
    "LocalSubnet",
    "DNS",
    "DHCP",
    "WINS",
    "DefaultGateway",
)

NON_LOOPBACK = (
    ("v4-below-loopback", "0.0.0.0-126.255.255.255", "Any"),
    ("v4-above-loopback", "128.0.0.0-255.255.255.255", "Any"),
    ("v4-linklocal", "169.254.0.0/16", "Any"),
    ("v4-multicast", "224.0.0.0/4", "Any"),
    ("v4-reserved", "240.0.0.0/4", "Any"),
    ("v6-linklocal", "fe80::/10", "Any"),
    ("v6-ula", "fc00::/7", "Any"),
    ("v6-multicast", "ff00::/8", "Any"),
    ("v6-unspec", "::/128", "Any"),
    ("v6-rest", "::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "Any"),
)


def user_action(exists, enabled):
    """'create' prompts once. 'keep' does not. Disabled accounts fail."""
    if not exists:
        return "create"
    if enabled:
        return "keep"
    raise AgentLockError("agentnet exists but is disabled; refusing to reset its password", 1)


def _holes(port, extra_tcp, host):
    from .allow import parse_allow_tcp_value
    holes = {int(port)}
    for value in extra_tcp or []:
        extra_host, extra_port = parse_allow_tcp_value(value)
        if extra_host == host:
            holes.add(extra_port)
    return holes


def blocked_ranges(holes):
    """Inclusive ranges inside 1..65535 that are not in holes. Empty ranges omitted."""
    ordered = sorted(port for port in holes if 1 <= port <= 65535)
    ranges = []
    cursor = 1
    for hole in ordered:
        if hole > cursor:
            ranges.append((cursor, hole - 1))
        cursor = max(cursor, hole + 1)
    if cursor <= 65535:
        ranges.append((cursor, 65535))
    return ranges


def _range_text(start, end):
    return "{}-{}".format(start, end)


def _sddl(sid):
    return "D:(A;;CC;;;%s)" % sid


def _rule(suffix, remote_address, protocol, remote_port, sid):
    rule = {
        "name": "agent-lock-{}".format(suffix),
        "direction": "Outbound",
        "action": "Block",
        "protocol": protocol,
        "remote_address": remote_address,
        "remote_port": remote_port,
        "profile": "Any",
        "enabled": True,
        "local_user": _sddl(sid),
    }
    return rule


def build_rules(port, extra_tcp, sid):
    port = int(port)
    if port < 1 or port > 65535:
        raise AgentLockError("port out of range", 2)
    rules = []
    for suffix, address, protocol in NON_LOOPBACK:
        rules.append(_rule(suffix, address, protocol, None, sid))
    families = (
        ("lo", "127.0.0.0/8", "127.0.0.1"),
        ("lo6", "::1", "::1"),
    )
    for prefix, address, host in families:
        ranges = blocked_ranges(_holes(port, extra_tcp, host))
        plain = not extra_tcp
        for start, end in ranges:
            if plain and start == 1:
                suffix = "{}-tcp-low".format(prefix)
            elif plain and end == 65535:
                suffix = "{}-tcp-high".format(prefix)
            else:
                suffix = "{}-tcp-{}-{}".format(prefix, start, end)
            rules.append(_rule(suffix, address, "TCP", _range_text(start, end), sid))
        rules.append(_rule("{}-udp".format(prefix), address, "UDP", None, sid))
        icmp = "ICMPv4" if prefix == "lo" else "ICMPv6"
        rules.append(_rule("{}-icmp".format(prefix), address, icmp, None, sid))
    for rule in rules:
        if rule["action"] != "Block":
            raise AgentLockError("internal error: Allow rules are not permitted")
        if rule_covers_proxy(rule, port):
            raise AgentLockError("internal error: a Block covers the proxy port")
    return rules


def rule_names(rules):
    return [rule["name"] for rule in rules]


def uninstall_commands(names):
    """Delete only the names stored in state. No display-name prefix sweep."""
    return [["Remove-NetFirewallRule", "-Name", name] for name in names]


def _split_ip_range(spec):
    # One dash separates the two addresses. IPv6 text itself has no dash.
    if "-" not in spec:
        return None
    left, right = spec.split("-", 1)
    try:
        return ipaddress.ip_address(left), ipaddress.ip_address(right)
    except ValueError:
        return None


def address_contains(spec, ip_text):
    """True when spec is any, a keyword, or a literal that includes ip_text."""
    if spec is None:
        return True
    text = str(spec).strip()
    if text == "" or text.lower() in ("any", "*"):
        return True
    if text in REMOTE_KEYWORDS:
        return True
    try:
        target = ipaddress.ip_address(ip_text)
    except ValueError:
        return False
    try:
        if "/" in text:
            network = ipaddress.ip_network(text, strict=False)
            if network.version != target.version:
                return False
            return target in network
        pair = _split_ip_range(text)
        if pair is not None:
            if pair[0].version != target.version:
                return False
            return pair[0] <= target <= pair[1]
        other = ipaddress.ip_address(text)
        if other.version != target.version:
            return False
        return other == target
    except ValueError:
        # Unparseable tokens are treated as dangerous: they might be a keyword.
        return True


def port_contains(spec, port):
    if spec is None:
        return True
    text = str(spec).strip()
    if text == "" or text.lower() in ("any", "*"):
        return True
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            left, right = part.split("-", 1)
            if int(left) <= port <= int(right):
                return True
        elif int(part) == port:
            return True
    return False


def rule_covers_proxy(rule, port):
    """True when this Block matches TCP to 127.0.0.1:port or ::1:port."""
    if str(rule.get("action", "")).lower() != "block":
        return False
    if rule.get("enabled") is False:
        return False
    protocol = str(rule.get("protocol", "")).upper()
    if protocol not in ("ANY", "TCP"):
        return False
    if not port_contains(rule.get("remote_port"), int(port)):
        return False
    address = rule.get("remote_address")
    return address_contains(address, "127.0.0.1") or address_contains(address, "::1")


def gpo_problem(profiles):
    """Fail when local firewall rules are not merged.

    AllowLocalFirewallRules is read first. When that property is missing,
    AllowLocalPolicyMerge 0 is a failure. Both names are required.
    """
    for profile in profiles or []:
        name = profile.get("name") or "profile"
        allow = profile.get("AllowLocalFirewallRules", None)
        if allow is False or allow == 0:
            return "AllowLocalFirewallRules is false for {}".format(name)
        if allow is None:
            merge = profile.get("AllowLocalPolicyMerge", None)
            if merge is False or merge == 0:
                return "AllowLocalPolicyMerge is 0 for {}".format(name)
    return None


def default_outbound_problem(profiles):
    for profile in profiles or []:
        action = profile.get("DefaultOutboundAction")
        if action is not None and str(action).lower() == "block":
            return "DefaultOutboundAction is Block for {}".format(profile.get("name") or "profile")
    return None


def require_supported(profiles):
    problem = gpo_problem(profiles)
    if problem:
        raise Unsupported(problem)
    problem = default_outbound_problem(profiles)
    if problem:
        raise Unsupported(problem)


def share_icacls(paths):
    """Shared credential directories. Modify, inherited. Not a traverse-only grant."""
    return [
        ["icacls", path, "/grant", "{}:(OI)(CI)M".format(AGENT_USER)]
        for path in paths
    ]


def icacls_commands(owner_home, trust_exec, directory_fn):
    """Owner home gets traverse (X) only. Python home from --trust-exec gets (OI)(CI)(RX)."""
    commands = [["icacls", owner_home, "/grant", "{}:(X)".format(AGENT_USER)]]
    homes = []
    for path in trust_exec or []:
        if directory_fn(path):
            grant = "{}:(OI)(CI)(RX)".format(AGENT_USER)
            commands.append(["icacls", path, "/grant", grant])
        else:
            commands.append(["icacls", path, "/grant", "{}:(RX)".format(AGENT_USER)])
            parent = os.path.dirname(path)
            if parent and parent not in homes:
                homes.append(parent)
    for home in homes:
        commands.append(["icacls", home, "/grant", "{}:(OI)(CI)(RX)".format(AGENT_USER)])
    return commands


def create_profile_script(sid):
    """userenv!CreateProfile. Already-exists, or a profile directory, continues.

    The SID is interpolated into PowerShell, so it has to be a literal SID.
    """
    if not sid or any(ch not in "S-0123456789" for ch in sid) or not sid.startswith("S-1-"):
        raise AgentLockError("could not read the agentnet SID")
    return (
        "$signature = @'\n"
        "using System;\n"
        "using System.Runtime.InteropServices;\n"
        "using System.Text;\n"
        "public class AgentLockUserEnv {{\n"
        "  [DllImport(\"userenv.dll\", CharSet = CharSet.Unicode, SetLastError = true)]\n"
        "  public static extern int CreateProfile(string pszUserSid, string pszUserName,\n"
        "    StringBuilder pszProfilePath, int cchProfilePath);\n"
        "}}\n"
        "'@\n"
        "if (-not ('AgentLockUserEnv' -as [type])) {{ Add-Type -TypeDefinition $signature }}\n"
        "$buf = New-Object System.Text.StringBuilder 260\n"
        "$code = [AgentLockUserEnv]::CreateProfile('{sid}', '{user}', $buf, 260)\n"
        "$path = $env:SystemDrive + '\\Users\\{user}'\n"
        "# 0 is success. -2147024713 is HRESULT ERROR_ALREADY_EXISTS (0x800700B7).\n"
        "if ($code -eq 0 -or $code -eq -2147024713 -or (Test-Path -LiteralPath $path)) {{ exit 0 }}\n"
        "Write-Error ('CreateProfile failed: ' + $code)\n"
        "exit 1\n"
    ).format(sid=sid, user=AGENT_USER)


def link_plan(profile_ready, links):
    """CreateProfile (or an existing profile) before any junction."""
    steps = ["CreateProfile"]
    if not profile_ready:
        steps.append("fail-profile")
    else:
        for link, target in links:
            steps.append("mklink /J {} {}".format(link, target))
    return steps


def new_local_user_script():
    """Create the account. Does not add Administrators and does not save the password."""
    return (
        "$pw = Read-Host -AsSecureString -Prompt 'agentnet password'\n"
        "New-LocalUser -Name '{user}' -Password $pw -PasswordNeverExpires "
        "-UserMayNotChangePassword:$false | Out-Null\n"
    ).format(user=AGENT_USER)


def render_rule_script(rules):
    """PowerShell that creates Block rules. RemotePort is omitted when empty."""
    lines = []
    for rule in rules:
        parts = [
            "New-NetFirewallRule",
            "-Name '{}'".format(rule["name"]),
            "-DisplayName '{}'".format(rule["name"]),
            "-Direction {}".format(rule["direction"]),
            "-Action {}".format(rule["action"]),
            "-Protocol {}".format(rule["protocol"]),
            "-RemoteAddress '{}'".format(rule["remote_address"]),
            "-Profile {}".format(rule["profile"]),
            "-Enabled True",
            "-LocalUser '{}'".format(rule["local_user"]),
        ]
        if rule.get("remote_port"):
            parts.append("-RemotePort '{}'".format(rule["remote_port"]))
        lines.append(" ".join(parts))
    return "\n".join(lines) + ("\n" if lines else "")
