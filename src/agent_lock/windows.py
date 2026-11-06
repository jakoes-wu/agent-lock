"""Windows outbound Block rules. No Allow rules. No RemoteAddress keywords.

A Block must not match 127.0.0.1:PORT or ::1:PORT. Loopback TCP uses dash
ranges and omits an empty range when the port is 1 or 65535.
"""

import base64
import ipaddress
import os
import re
import sys

from .errors import AgentLockError, Unsupported, UsageError
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
                suffix = "{}-tcp-{}-low".format(prefix, port)
            elif plain and end == 65535:
                suffix = "{}-tcp-{}-high".format(prefix, port)
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


def _outbound_action(value):
    """Allow is 2, Block is 4. PowerShell 5.1 emits the enum as a number."""
    if isinstance(value, bool) or value is None:
        return ""
    if isinstance(value, int):
        return {2: "allow", 4: "block"}.get(value, "")
    text = str(value).strip().lower()
    if text.isdigit():
        return {2: "allow", 4: "block"}.get(int(text), "")
    if text in ("allow", "block"):
        return text
    return ""


def default_outbound_problem(profiles):
    for profile in profiles or []:
        action = _outbound_action(profile.get("DefaultOutboundAction"))
        if action == "block":
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


def _is_reparse(path):
    if os.path.islink(path):
        return True
    if sys.platform != "win32" or not path or not os.path.exists(path):
        return False
    import ctypes
    attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))
    if attrs in (-1, 0xFFFFFFFF):
        return False
    return bool(int(attrs) & 0x400)


def _traverse_ancestors(path, owner_home):
    """Directories between the path and the home. The home itself is excluded."""
    home = os.path.abspath(owner_home)
    current = os.path.dirname(os.path.abspath(path))
    found = []
    while current and os.path.normcase(current) != os.path.normcase(home):
        parent = os.path.dirname(current)
        if parent == current:
            break
        try:
            if os.path.commonpath([current, home]) != home:
                break
        except ValueError:
            break
        found.append(current)
        current = parent
    found.reverse()
    return found


def icacls_commands(owner_home, trust_exec, directory_fn):
    """Home gets (X) only. A directory gets inherited RX. A file gets (RX) only."""
    commands = [["icacls", owner_home, "/grant", "{}:(X)".format(AGENT_USER)]]
    seen = {os.path.normcase(os.path.abspath(owner_home))}
    for path in trust_exec or []:
        if _is_reparse(path):
            raise UsageError("refusing a symlink: {}".format(path))
        if directory_fn(path):
            grant = "{}:(OI)(CI)(RX)".format(AGENT_USER)
        else:
            grant = "{}:(RX)".format(AGENT_USER)
        commands.append(["icacls", path, "/grant", grant])
        for ancestor in _traverse_ancestors(path, owner_home):
            key = os.path.normcase(os.path.abspath(ancestor))
            if key in seen:
                continue
            seen.add(key)
            commands.append(["icacls", ancestor, "/grant", "{}:(X)".format(AGENT_USER)])
    return commands


def state_acl_commands(path, owner_name):
    """SYSTEM and Administrators full control, installing user read. No Users ACE."""
    if not owner_name or any(ch in owner_name for ch in "\\/\"\r\n\t &|<>"):
        raise AgentLockError("installing user name is not safe for an ACL")
    if owner_name.lower() in ("users", "agentnet", "everyone", "authenticated users"):
        raise AgentLockError("refusing a state ACL for {}".format(owner_name))
    return [
        "icacls", path, "/inheritance:r", "/grant:r",
        "*S-1-5-18:(F)",
        "*S-1-5-32-544:(F)",
        "{}:(R)".format(owner_name),
    ]


def apply_state_acl(path, owner_name, runner=None):
    """Explicit DACL. A failed icacls leaves the inherited Users ACE, so it raises."""
    command = state_acl_commands(path, owner_name)
    if runner is None:
        import subprocess
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True, check=False)
        code = result.returncode
        detail = (result.stderr or result.stdout or "").strip()
    else:
        result = runner(command)
        code = getattr(result, "returncode", 1) if result else 1
        detail = ""
        if result:
            detail = (getattr(result, "stderr", "") or getattr(result, "stdout", "") or "").strip()
    if code != 0:
        raise AgentLockError("state ACL was not applied: {}".format(detail or "icacls failed"))


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


def link_plan(links):
    """Junction argv lists. CreateProfile is a separate call, not a plan step."""
    return [["cmd", "/c", "mklink", "/J", link, target] for link, target in links]


def rule_phases(old_names, new_names):
    """Names to create, then stored names that are not in the new set."""
    old_names = list(old_names or [])
    new_names = list(new_names or [])
    old_set = set(old_names)
    new_set = set(new_names)
    create = [name for name in new_names if name not in old_set]
    remove = [name for name in old_names if name not in new_set]
    return create, remove


def _ports_in_spec(spec):
    if spec is None:
        return set(range(1, 65536))
    text = str(spec).strip()
    if text == "" or text.lower() in ("any", "*"):
        return set(range(1, 65536))
    found = set()
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            left, right = part.split("-", 1)
            found.update(range(int(left), int(right) + 1))
        elif part.isdigit():
            found.add(int(part))
    return found


def windows_observed(rules, port):
    """(blocks leave the proxy open, extra loopback TCP holes).

    `None` extras means the ruleset was not parsed. An empty list means no extra hole.
    """
    if not rules:
        return False, None
    port = int(port)
    covers = any(rule_covers_proxy(rule, port) for rule in rules)
    extras = []
    families_blocked = True
    for host in ("127.0.0.1", "::1"):
        blocked = set()
        saw = False
        for rule in rules:
            if str(rule.get("action", "")).lower() != "block":
                continue
            protocol = str(rule.get("protocol", "")).upper()
            if protocol not in ("ANY", "TCP"):
                continue
            if rule.get("enabled") is False:
                continue
            if not address_contains(rule.get("remote_address"), host):
                continue
            saw = True
            blocked.update(_ports_in_spec(rule.get("remote_port")))
        if not saw:
            families_blocked = False
        for candidate in range(1, 65536):
            if candidate == port or candidate in blocked:
                continue
            extras.append("{}:{}".format(host, candidate))
            if len(extras) > 32:
                break
    return (not covers) and families_blocked and len(extras) <= 32, extras


_PROTO_NUMBERS = {
    "1": "ICMPv4",
    "6": "TCP",
    "17": "UDP",
    "58": "ICMPv6",
    "256": "ANY",
}


def normalize_firewall_rule(item):
    proto = item.get("Protocol", item.get("protocol", ""))
    if isinstance(proto, int):
        proto = str(proto)
    proto = _PROTO_NUMBERS.get(str(proto), str(proto))
    address = item.get("RemoteAddress", item.get("remote_address"))
    if isinstance(address, list):
        address = address[0] if address else None
    remote_port = item.get("RemotePort", item.get("remote_port"))
    if isinstance(remote_port, list):
        remote_port = ",".join(str(part) for part in remote_port)
    enabled = item.get("Enabled", item.get("enabled", True))
    return {
        "name": item.get("Name", item.get("name")),
        "action": item.get("Action", item.get("action", "Block")),
        "protocol": proto,
        "remote_address": address,
        "remote_port": remote_port,
        "enabled": enabled,
    }


def windows_firewall_report(profiles, rules, port):
    """gpo, outbound, firewall_ok, extra_tcp_observed from already-parsed objects."""
    gpo = gpo_problem(profiles)
    outbound = default_outbound_problem(profiles)
    cleaned = []
    for rule in rules or []:
        if "remote_address" in rule or "protocol" in rule:
            cleaned.append(rule)
        else:
            cleaned.append(normalize_firewall_rule(rule))
    ok, extras = windows_observed(cleaned, port)
    if gpo or outbound:
        ok = False
    return gpo, outbound, ok, extras


def windows_profile_script():
    return (
        "Get-NetFirewallProfile | "
        "Select-Object Name, AllowLocalFirewallRules, AllowLocalPolicyMerge, DefaultOutboundAction | "
        "ConvertTo-Json -Compress"
    )


def windows_rule_script(sid):
    """Outbound Block rules for this SID. LocalUser lives on the security filter."""
    if not sid or any(ch not in "S-0123456789" for ch in sid) or not sid.startswith("S-1-"):
        raise AgentLockError("could not read the agentnet SID")
    return (
        "Get-NetFirewallRule -Direction Outbound -Action Block -Enabled True | "
        "Where-Object { [string](($_ | Get-NetFirewallSecurityFilter).LocalUser) -like '*"
        + sid + "*' } | ForEach-Object { "
        "$port = $_ | Get-NetFirewallPortFilter; "
        "$addr = $_ | Get-NetFirewallAddressFilter; "
        "[PSCustomObject]@{ Name=$_.Name; Action='Block'; Protocol=$port.Protocol; "
        "RemoteAddress=$addr.RemoteAddress; RemotePort=$port.RemotePort; Enabled=$true } "
        "} | ConvertTo-Json -Compress"
    )


def windows_user_script():
    """Name and Enabled. Does not read group membership."""
    return (
        "Get-LocalUser -Name 'agentnet' -ErrorAction SilentlyContinue | "
        "Select-Object Name, Enabled | ConvertTo-Json -Compress\n"
    )


def windows_path_executable(text):
    """True when an icacls ACE for the agentnet account grants execute.

    The account is `agentnet:`, not the word anywhere in the path. A path
    that merely contains that word must not inherit another user's (F).
    """
    pattern = re.compile(r"(?:^|[\s\\.])agentnet:((?:\([^)]*\))+)", re.IGNORECASE)
    for line in (text or "").splitlines():
        match = pattern.search(line)
        if not match:
            continue
        grant = match.group(1)
        if "(F)" in grant or "(M)" in grant:
            return True
        if re.search(r"\([^)]*X", grant):
            return True
    return False


def _ps_single(text):
    return "'" + str(text).replace("'", "''") + "'"


def parse_locked_batch(text):
    """Exit codes and captured streams from the agentnet probe batch."""
    found = {}
    for line in (text or "").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        found[key.strip()] = value

    def decode(name):
        raw = found.get(name, "")
        if not raw:
            return ""
        try:
            return base64.b64decode(raw).decode("utf-8", "replace")
        except (ValueError, TypeError):
            return ""

    def code(name):
        raw = found.get(name, "").strip()
        if raw.lstrip("-").isdigit():
            return int(raw)
        return None

    return {
        "probe_code": code("PROBE_CODE"),
        "probe_stdout": decode("PROBE_OUT_B64"),
        "probe_stderr": decode("PROBE_ERR_B64"),
        "proxy_code": code("PROXY_CODE"),
        "proxy_stderr": decode("PROXY_ERR_B64"),
        "noproxy_code": code("NOPROXY_CODE"),
        "noproxy_stderr": decode("NOPROXY_ERR_B64"),
    }


def windows_locked_command(sid, python, probe_source, proxy_argv, noproxy_argv):
    """One PowerShell process that runs the probe and both curls as agentnet.

    agent-lock.cmd exits 126 unless the caller is already that SID, so doctor
    does not invoke it. When this process is already agentnet the payload
    starts directly. Otherwise one Get-Credential logon starts the child;
    the password is not written to state or to the command line. Exit 126
    is not a result of this script.

    The probe is `python -` with the source on that child's stdin. A script
    file in the installing user's temp directory is not readable by agentnet.
    """
    if not sid or any(ch not in "S-0123456789" for ch in sid) or not sid.startswith("S-1-"):
        raise AgentLockError("could not read the agentnet SID")
    if not proxy_argv or not noproxy_argv or not python or not probe_source:
        raise AgentLockError("locked probe was not run as agentnet")

    def arguments(argv):
        return " ".join('"' + str(part).replace('"', '\\"') + '"' for part in argv[1:])

    probe_args = arguments([python, "-"])
    proxy_args = arguments(proxy_argv)
    direct_args = arguments(noproxy_argv)
    lines = [
        "$ErrorActionPreference = 'Continue'",
        "$sid = " + _ps_single(sid),
        "$me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
        "$cred = $null",
        "if ($me -ne $sid) {",
        "  if (-not [Environment]::UserInteractive) { exit 127 }",
        "  $cred = Get-Credential -UserName '.\\agentnet' -Message 'agent-lock doctor'",
        "  if (-not $cred) { exit 127 }",
        "}",
        "function Invoke-Locked([string]$Name, [string]$File, [string]$Arguments, [string]$Stdin) {",
        "  $psi = New-Object System.Diagnostics.ProcessStartInfo",
        "  $psi.FileName = $File",
        "  $psi.Arguments = $Arguments",
        "  $psi.UseShellExecute = $false",
        "  $psi.RedirectStandardOutput = $true",
        "  $psi.RedirectStandardError = $true",
        "  if ($Stdin) { $psi.RedirectStandardInput = $true }",
        "  if ($me -ne $sid) {",
        "    $psi.UserName = 'agentnet'",
        "    $psi.Domain = '.'",
        "    $psi.Password = $cred.Password",
        "    $psi.LoadUserProfile = $true",
        "  }",
        "  $proc = [System.Diagnostics.Process]::Start($psi)",
        "  if ($Stdin) {",
        "    $proc.StandardInput.Write($Stdin)",
        "    $proc.StandardInput.Close()",
        "  }",
        "  $out = $proc.StandardOutput.ReadToEnd()",
        "  $err = $proc.StandardError.ReadToEnd()",
        "  $proc.WaitForExit()",
        "  $outB = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$out))",
        "  $errB = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$err))",
        "  Write-Output ($Name + '_CODE=' + $proc.ExitCode)",
        "  Write-Output ($Name + '_OUT_B64=' + $outB)",
        "  Write-Output ($Name + '_ERR_B64=' + $errB)",
        "}",
        "Invoke-Locked 'PROBE' " + _ps_single(python) + " " + _ps_single(probe_args) + " " + _ps_single(probe_source),
        "Invoke-Locked 'PROXY' " + _ps_single(proxy_argv[0]) + " " + _ps_single(proxy_args) + " ''",
        "Invoke-Locked 'NOPROXY' " + _ps_single(noproxy_argv[0]) + " " + _ps_single(direct_args) + " ''",
        "exit 0",
    ]
    script = "\n".join(lines) + "\n"
    return ["powershell", "-NoProfile", "-Command", script]


def windows_admin_script():
    return (
        "$hit = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | "
        "Where-Object { $_.Name -eq 'agentnet' -or $_.Name -like '*\\agentnet' }\n"
        "if ($hit) { 'yes' } else { 'no' }\n"
    )


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
