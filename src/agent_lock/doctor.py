"""Classify doctor observations. Live probes are injectable; tests pass fakes.

Exit 3 when nothing is installed, before any network probe. Exit 4 beats exit 1
when local firewall policy or the outbound default makes the lock impossible.
"""

import json
import os
import re
import stat
import sys

from .errors import AgentLockError
from .darwin import acl_commands
from .state import CREDENTIAL_DIRS, LINUX_AGENT_HOME, load_state, secret_label
from .wrapper import CLAUDE_WRAPPER_PATH

MIN_CLAUDE = (2, 1, 208)
PROCESS_WRAPPER_HINT = (2, 1, 210)

PROBE_SOURCE = (
    "import socket, sys\n"
    "try:\n"
    '    socket.create_connection(("1.1.1.1", 443), 3)\n'
    "except OSError as e:\n"
    '    sys.stdout.write("agent-lock-probe: denied %s\\n" % (e.errno,))\n'
    "    sys.exit(1)\n"
    'sys.stdout.write("agent-lock-probe: connected\\n")\n'
    "sys.exit(0)\n"
)

NOPROXY_TEXT = (
    "Connection timed out",
    "Connection refused",
    "Network is unreachable",
    "Operation not permitted",
)

_ADMIN_GROUPS = ("sudo", "wheel", "admin", "adm", "Administrators")


def noproxy_locked(code, stderr):
    """True only for curl 28, curl 7, or the listed error text.

    Exit 0, 126, and 127 are not a lock. 126 is the cmd refusing the owner.
    """
    if code in (28, 7):
        return True
    if code in (0, 126, 127, None):
        return False
    text = stderr or ""
    return any(marker in text for marker in NOPROXY_TEXT)


def probe_denied(stdout, stderr, code):
    """True only when the probe printed denied and did not connect.

    Exit 126 is the Windows cmd refusing a caller who is not agentnet.
    That refusal did not attempt the connection, so it is not a lock.
    """
    if code in (126, 127, None):
        return False
    text = (stdout or "") + (stderr or "")
    if "ModuleNotFoundError" in text or "agent-lock-probe: connected" in (stdout or ""):
        return False
    return "agent-lock-probe: denied" in (stdout or "")


def probe_connected(stdout, stderr, code):
    if code != 0:
        return False
    text = (stdout or "") + (stderr or "")
    if "ModuleNotFoundError" in text or "agent-lock-probe: denied" in (stdout or ""):
        return False
    return "agent-lock-probe: connected" in (stdout or "")


def parse_claude_version(text):
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", text or "")
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def version_status(text):
    """Return (level, detail). Missing claude is a skip. Below 2.1.208 fails."""
    if text is None:
        return "skip", "skipped: claude is not on PATH"
    found = parse_claude_version(text)
    if found is None:
        return "fail", "could not parse claude --version"
    if found < MIN_CLAUDE:
        return "fail", "claude {} is older than 2.1.208".format(".".join(str(p) for p in found))
    if found < PROCESS_WRAPPER_HINT:
        return "warn", "warn: the processWrapper key needs Claude Code 2.1.210; agent-lock does not write that key"
    return "pass", "claude {} accepts CLAUDE_CODE_PROCESS_WRAPPER".format(".".join(str(p) for p in found))


def sudo_env_problem(expected, seen):
    """expected and seen map user/logname/home to a string or None when unset."""
    if seen is None:
        return "sudo-env did not run"
    bad = False
    for key in ("user", "logname", "home"):
        if expected.get(key) != seen.get(key):
            bad = True
        value = seen.get(key)
        if value in ("root", "agentnet", "/root", LINUX_AGENT_HOME) and expected.get(key) != value:
            bad = True
    if bad:
        return "sudo rewrote the login name or home directory, not the firewall"
    return None


def bin_dir_problem(entry, agent_gid):
    if entry.get("is_link") or not entry.get("is_dir"):
        return "not a real directory"
    mode = entry.get("mode") or 0
    if not mode & stat.S_ISGID:
        return "missing setgid"
    if entry.get("gid") != agent_gid:
        return "group is not agentnet"
    if not (mode & stat.S_IRGRP and mode & stat.S_IXGRP):
        return "group cannot read and execute"
    if mode & stat.S_IWGRP:
        return "group writable"
    return None


def settings_problem(document, wrapper, proxy):
    if not isinstance(document, dict):
        return "settings are not a JSON object"
    env = document.get("env")
    if not isinstance(env, dict):
        return "settings have no env object"
    if env.get("CLAUDE_CODE_PROCESS_WRAPPER") != wrapper:
        return "CLAUDE_CODE_PROCESS_WRAPPER is not the claude wrapper"
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        if key in env and env[key] != proxy:
            return "{} does not match the locked proxy".format(key)
    if "ALL_PROXY" in env or "all_proxy" in env:
        return "settings set ALL_PROXY"
    process_wrapper = document.get("processWrapper")
    if process_wrapper is not None and process_wrapper != wrapper:
        return "processWrapper does not match the claude wrapper"
    return None


def wrapper_problems(text, port, claude_text, darwin=False):
    problems = []
    if not text:
        return ["switcher is missing"]
    if "wrapper_port={}".format(port) not in text:
        problems.append("switcher port does not match state")
    if "export IFS" in text:
        problems.append("switcher exports IFS")
    printf_at = text.find("IFS=$(/usr/bin/printf ' \\t\\n.')")
    strip_at = text.find("IFS=${IFS%.}")
    if "unset IFS" not in text:
        problems.append("switcher does not unset IFS after the loader loop")
    if "sudo -n -l" not in text:
        problems.append("preflight is not sudo -n -l")
    if "sudo -n -v" in text:
        problems.append("preflight uses the wrong sudo check")
    snap = text.find("AGENT_LOCK_OWNER_USER=${USER-}")
    pre = text.find("/usr/bin/sudo -n -l")
    if snap < 0 or pre < 0 or snap > pre:
        problems.append("owner snapshot is not before the sudo preflight")
    if "unset _np" in text or re.search(r"(?<![A-Za-z0-9])_h(?![A-Za-z0-9])", text):
        problems.append("switcher uses a helper variable")
    unset_at = text.find("unset IFS")
    if darwin:
        marker = "sudo --preserve-env -u"
    else:
        marker = "--preserve-environment -u"
    root_at = text.find(marker)
    if unset_at < 0 or root_at < 0 or root_at < unset_at:
        problems.append("root branch does not drop privileges after stripping loader variables")
    if printf_at < 0 or strip_at < 0 or root_at < 0 or printf_at > root_at or strip_at > root_at:
        problems.append("root branch does not set IFS from printf before exec")
    for line in text.splitlines():
        if marker in line and line.strip().startswith("exec ") and '"$@"' in line and SWITCHER_MARK not in line:
            problems.append("root branch execs the user command")
    if claude_text is None:
        problems.append("claude wrapper is missing")
    else:
        if "unset" in claude_text:
            problems.append("claude wrapper contains unset")
        if "wrapper_port={}".format(port) not in claude_text:
            problems.append("claude wrapper port does not match state")
    return problems


SWITCHER_MARK = "/usr/local/sbin/agent-lock"


def windows_cmd_problems(text, port, sid):
    if not text:
        return ["windows switcher is missing"]
    problems = []
    if "wrapper_port={}".format(port) not in text:
        problems.append("cmd port does not match state")
    if sid and sid not in text:
        problems.append("cmd SID does not match state")
    if "NO_PROXY" in text or "no_proxy" in text:
        problems.append("cmd assigns NO_PROXY")
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        if name not in text:
            problems.append("cmd does not set {}".format(name))
    return problems


def counter_status(before, after, denied_ok):
    """Linux drop counter. A missing denied marker cannot be turned into a pass."""
    if not denied_ok:
        return "fail", "probe did not show denied; the drop counter cannot pass the lock"
    if before is None or after is None:
        return "fail", "drop counter was not readable"
    if after - before < 1:
        return "fail", "drop counter did not increase"
    return "pass", "drop counter increased by {}".format(after - before)


def pf_counter_status(parsed, before, after):
    """Unparsed macOS counters warn. Parsed counters that did not increase fail."""
    if not parsed:
        return "warn", "warn: pf counters could not be parsed"
    if before is None or after is None or after - before < 1:
        return "fail", "pf block counter did not increase"
    return "pass", "pf block counter increased by {}".format(after - before)


def _check(name, level, detail):
    return {
        "name": name,
        "ok": level in ("pass", "warn", "skip"),
        "detail": detail,
        "level": level,
    }


def _level_detail(problem, ok_detail):
    if problem:
        return "fail", problem
    return "pass", ok_detail


def evaluate(report):
    """Turn a facts dict into checks and an exit code. Does not touch the network."""
    if not report.get("installed"):
        detail = report.get("installed_detail") or "state file or switcher is missing"
        return [_check("installed", "fail", detail)], 3

    platform = report.get("platform") or "linux"
    checks = []
    state = report.get("state") or {}
    port = state.get("port")
    checks.append(_check("installed", "pass", "state, switcher, and account are present"))

    checks.append(_account_check(report, platform))
    checks.append(_firewall_check(report, platform, port))
    checks.append(_wrapper_check(report, platform, port, state))
    if platform != "windows":
        problem = sudo_env_problem(report.get("expected_identity") or {}, report.get("seen_identity"))
        level, detail = _level_detail(problem, "USER, LOGNAME, and HOME match the owner")
        checks.append(_check("sudo-env", level, detail))
        if platform == "linux":
            checks.append(_bin_dir_check(report, state))
        checks.append(_settings_check(report, state))
        level, detail = version_status(report.get("claude_version"))
        checks.append(_check("claude-wrapper-version", level, detail))
        checks.append(_login_check(report))
        checks.append(_daemon_check(report))
    else:
        warn = report.get("windows_claude_warn") or ""
        if warn:
            checks.append(_check("windows-claude", "warn", "warn: " + warn))
        else:
            checks.append(_check(
                "windows-claude", "pass",
                "no task or service running as the owner was found that would start Claude"))
    checks.append(_controller_check(report, port))
    proxy_level, proxy_detail = _proxy_check(report)
    checks.append(_check("proxy-ok", proxy_level, proxy_detail))
    checks.append(_noproxy_check(report))
    denied_ok = probe_denied(
        report.get("probe_stdout"), report.get("probe_stderr"), report.get("probe_code"))
    if denied_ok:
        checks.append(_check("raw-tcp-fail", "pass", "agent-lock-probe: denied"))
    else:
        checks.append(_check(
            "raw-tcp-fail", "fail",
            "the lock is not in effect; expected agent-lock-probe: denied"))
    if probe_connected(report.get("owner_probe_stdout"), report.get("owner_probe_stderr"),
                       report.get("owner_probe_code")):
        checks.append(_check("owner-tcp-ok", "pass", "agent-lock-probe: connected"))
    else:
        checks.append(_check("owner-tcp-ok", "fail", "the owner direct TCP probe did not connect"))
    if platform == "linux":
        level, detail = counter_status(report.get("drop_before"), report.get("drop_after"), denied_ok)
        checks.append(_check("counter", level, detail))
    elif platform == "darwin":
        level, detail = pf_counter_status(
            report.get("pf_counter_parsed"), report.get("pf_before"), report.get("pf_after"))
        checks.append(_check("pf-counter", level, detail))
    checks.append(_unix_check(report))
    if report.get("home_traversable"):
        checks.append(_check("home-traverse", "pass", "agentnet can traverse the owner home"))
    else:
        checks.append(_check(
            "home-traverse", "warn",
            "warn: agentnet cannot traverse the owner home; credential ACLs are not enough"))
    if report.get("exec_access_ok") is True:
        checks.append(_check("exec-access", "pass", report.get("exec_access_detail") or "recorded paths are executable"))
    else:
        checks.append(_check("exec-access", "fail", report.get("exec_access_detail") or "a recorded path is not executable"))
    if platform == "windows":
        gpo = report.get("gpo_problem")
        outbound = report.get("outbound_problem")
        if gpo:
            checks.append(_check("gpo", "unsupported", gpo))
        else:
            checks.append(_check("gpo", "pass", "AllowLocalFirewallRules permits local rules"))
        if outbound:
            checks.append(_check("default-outbound", "unsupported", outbound))
        else:
            checks.append(_check("default-outbound", "pass", "DefaultOutboundAction is not Block"))
    return checks, _exit_code(checks)


def _exit_code(checks):
    levels = [item["level"] for item in checks]
    if "unsupported" in levels:
        return 4
    if "fail" in levels:
        return 1
    return 0


def _account_check(report, platform):
    account = report.get("account") or {}
    if not account.get("exists"):
        return _check("user", "fail", "agentnet does not exist")
    groups = account.get("groups") or []
    for name in _ADMIN_GROUPS:
        if name in groups:
            return _check("user", "fail", "agentnet is in the {} group".format(name))
    if platform == "linux":
        if account.get("shell") != "/usr/sbin/nologin":
            return _check("user", "fail", "agentnet shell is not nologin")
        if not account.get("locked"):
            return _check("user", "fail", "agentnet password is not locked")
        expected_home = account.get("home")
        if expected_home and expected_home != LINUX_AGENT_HOME:
            return _check("user", "fail", "agentnet home is not /var/lib/agentnet")
    if platform == "windows" and not account.get("enabled", True):
        return _check("user", "fail", "agentnet is disabled")
    return _check("user", "pass", "agentnet exists and is not an administrator")


def switcher_mode_problem(uid, mode, platform, owner_name=""):
    """Root (Administrators on Windows) and, on POSIX, not group-writable.

    CPython reports a writable Windows file as 0o666. That bit is not an ACL,
    so Windows fails only when the owner is not Administrators or the mode
    was not read.
    """
    if mode is None:
        return "switcher mode was not read"
    if platform == "windows":
        if "administrators" not in (owner_name or "").lower():
            return "windows switcher is not owned by Administrators"
        return None
    if mode & stat.S_IWGRP:
        return "switcher is group-writable"
    if uid != 0:
        return "switcher is not owned by root"
    return None


def _firewall_check(report, platform, port):
    if report.get("firewall_unsupported"):
        return _check("firewall", "unsupported", report.get("firewall_detail") or "firewall backend is unsupported")
    if not report.get("firewall_ok"):
        return _check("firewall", "fail", report.get("firewall_detail") or "firewall does not match state")
    extra = report.get("extra_tcp_observed")
    expected = report.get("state", {}).get("extra_tcp") or []
    if extra is None or sorted(extra) != sorted(expected):
        return _check("firewall", "fail", "extra loopback allows do not match state.extra_tcp")
    return _check("firewall", "pass", "firewall matches port {}".format(port))


def _wrapper_check(report, platform, port, state):
    if platform == "windows":
        problems = windows_cmd_problems(report.get("cmd_text"), port, state.get("agent_sid") or "")
    else:
        problems = wrapper_problems(
            report.get("switcher_text"), port, report.get("claude_text"),
            darwin=(platform == "darwin"))
    mode_problem = switcher_mode_problem(
        report.get("switcher_uid"), report.get("switcher_mode"), platform,
        report.get("switcher_owner") or "")
    if mode_problem:
        problems.append(mode_problem)
    if problems:
        return _check("wrapper", "fail", "; ".join(problems))
    return _check("wrapper", "pass", "wrappers match port {}".format(port))


def _bin_dir_check(report, state):
    entries = report.get("bin_dirs")
    if entries is None:
        entries = []
    agent_gid = state.get("agent_gid")
    problems = []
    for entry in entries:
        problem = bin_dir_problem(entry, agent_gid)
        if problem:
            problems.append("{}: {}".format(entry.get("path"), problem))
    if problems:
        return _check("bin-dir", "fail", "; ".join(problems))
    return _check("bin-dir", "pass", "bin directories are setgid and not group-writable" if entries else "no bin directories")


def _settings_check(report, state):
    wrapper = state.get("claude_wrapper") or CLAUDE_WRAPPER_PATH
    proxy = state.get("proxy")
    problems = []
    for item in report.get("settings") or []:
        problem = settings_problem(item.get("document"), wrapper, proxy)
        if problem:
            problems.append("{}: {}".format(item.get("path"), problem))
    if problems:
        return _check("settings", "fail", "; ".join(problems))
    if not (report.get("settings") or state.get("claude_settings")):
        return _check("settings", "skip", "skipped: no claude settings were recorded")
    return _check("settings", "pass", "CLAUDE_CODE_PROCESS_WRAPPER points at the claude wrapper")


def _login_check(report):
    status = report.get("claude_login") or "skip"
    detail = report.get("claude_login_detail") or ""
    if status == "skip":
        return _check("claude-login", "skip", detail or "skipped: Claude is not in use")
    if status == "pass":
        return _check("claude-login", "pass", detail or "agentnet can see a Claude login")
    return _check("claude-login", "fail", detail or "agentnet cannot see a Claude login")


def _daemon_check(report):
    if report.get("daemon_running_as_owner"):
        return _check("claude-daemon", "fail", "claude daemon is running as the owner, not agentnet")
    if report.get("daemon_service_file"):
        return _check(
            "claude-daemon", "warn",
            "warn: the claude daemon service file is still installed; LaunchAgent, deep links, "
            "and the Chrome host stay on the owner until they run inside agentnet")
    return _check("claude-daemon", "pass", "no owner claude daemon is running")


def _controller_check(report, port):
    if report.get("controller_error"):
        return _check("controller", "fail", report["controller_error"])
    if report.get("allow_lan"):
        return _check("controller", "fail", "allow-lan is true")
    if report.get("controller_port") != port:
        return _check("controller", "fail", "controller port does not match state")
    return _check("controller", "pass", "controller mixed-port matches state; {}".format(
        secret_label("x" if report.get("secret_set") else "")))


def _proxy_check(report):
    if report.get("proxy_missing"):
        return "fail", "curl is missing; the proxy check did not run"
    code = report.get("proxy_code")
    if code == 126:
        return "fail", "exit 126 is not a successful proxy check"
    if code == 0:
        return "pass", "proxy curl exited 0"
    stderr = report.get("proxy_stderr") or ""
    if "Connection refused" in stderr or code == 7:
        return "fail", "the proxy is not up"
    return "fail", "proxy curl failed ({})".format(code)


def _noproxy_check(report):
    if report.get("noproxy_missing"):
        return _check("noproxy-fail", "fail", "curl is missing; a missing curl is not a lock")
    code = report.get("noproxy_code")
    stderr = report.get("noproxy_stderr") or ""
    if code == 127:
        return _check("noproxy-fail", "fail", "curl exited 127; the direct connection was not attempted")
    if noproxy_locked(code, stderr):
        return _check("noproxy-fail", "pass", "direct curl was blocked")
    if code == 0:
        return _check("noproxy-fail", "fail", "direct curl exited 0")
    return _check("noproxy-fail", "fail", "direct curl failed without a lock error ({})".format(code))


def _unix_check(report):
    state = report.get("unix_socket")
    if state is None:
        return _check("unix-controller", "skip", "skipped: no unix controller socket")
    if state == "open":
        return _check("unix-controller", "fail", "agentnet can connect to the unix controller")
    return _check("unix-controller", "pass", "agentnet cannot connect to the unix controller")


def public_checks(checks):
    return [{"name": item["name"], "ok": item["ok"], "detail": item["detail"]} for item in checks]


def format_json(checks):
    payload = {"version": 1, "checks": public_checks(checks)}
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def format_text(checks):
    lines = []
    for item in checks:
        mark = "ok" if item["ok"] else "FAIL"
        if item["level"] == "warn":
            mark = "warn"
        elif item["level"] == "skip":
            mark = "skip"
        lines.append("{:<24} {}  {}".format(item["name"], mark, item["detail"]))
    return "\n".join(lines) + "\n"


def emit(checks, as_json, stdout, stderr):
    if as_json:
        stdout.write(format_json(checks))
        for item in checks:
            if item["level"] == "warn":
                stderr.write(item["detail"] + "\n")
    else:
        stdout.write(format_text(checks))


def repair_plan(state, platform, classify):
    """setfacl or macOS ACL only. Does not chown launchers and does not change the port."""
    roots = list(state.get("share_dirs") or [])
    home = state.get("owner_home") or ""
    for name in CREDENTIAL_DIRS:
        path = os.path.join(home, name)
        if classify(path) != "missing":
            roots.append(path)
    if platform == "linux":
        from .linux import credential_entries as walk
        from .linux import setfacl_commands as commands
        return commands(walk(roots, home, classify))
    if platform == "darwin":
        directories = []
        for root in roots:
            if classify(root) == "dir":
                directories.append(root)
        return acl_commands(directories, home)
    return []


def annotate_probe_messages(checks):
    """When the proxy is down and the lock did not engage, say both."""
    names = {item["name"]: item for item in checks}
    proxy = names.get("proxy-ok")
    raw = names.get("raw-tcp-fail")
    if not proxy or not raw or proxy.get("ok") or raw.get("ok"):
        return checks
    if "the proxy is not up" not in proxy["detail"]:
        proxy["detail"] = proxy["detail"] + "; the proxy is not up"
    if "the lock is not in effect" not in raw["detail"]:
        raw["detail"] = raw["detail"] + "; the lock is not in effect"
    return checks


def run_doctor(args, stdout=None, stderr=None):
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    try:
        state = load_state()
    except AgentLockError as exc:
        checks = [_check("installed", "fail", str(exc))]
        emit(checks, getattr(args, "json", False), stdout, stderr)
        return 1
    if not state:
        checks = [_check("installed", "fail", "agent-lock is not installed")]
        emit(checks, getattr(args, "json", False), stdout, stderr)
        return 3
    if getattr(args, "repair", False):
        return _repair(state, stdout, stderr)
    report = build_report(state)
    checks, code = evaluate(report)
    annotate_probe_messages(checks)
    emit(checks, getattr(args, "json", False), stdout, stderr)
    return code


def _repair(state, stdout, stderr):
    from .linux import classify_path
    platform = _platform()
    commands = repair_plan(state, platform, classify_path)
    for command in commands:
        if command and command[0] == "chmod" and command[1] == "-a":
            _run(command)
        else:
            result = _run(command)
            if result is not None and result.returncode != 0:
                stderr.write("repair failed: {}\n".format(" ".join(command)))
                return 1
    stdout.write("repaired ACLs; port was not changed\n")
    return 0


def _platform():
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "darwin":
        return "darwin"
    if sys.platform == "win32":
        return "windows"
    return "other"


def _run(argv, timeout=20):
    import subprocess
    try:
        return subprocess.run(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None


def _read(path):
    if not path:
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


def build_report(state):
    """Best-effort facts for a live doctor. Missing tools fail the related check."""
    platform = _platform()
    report = {
        "installed": bool(state) and bool(_switcher_present(state, platform)),
        "platform": platform,
        "state": state,
        "secret_set": bool(state.get("secret")),
        "switcher_text": _read(state.get("wrapper")),
        "claude_text": _read(state.get("claude_wrapper")) if platform != "windows" else None,
        "cmd_text": _read(state.get("wrapper")) if platform == "windows" else "",
        "account": _account_facts(state, platform),
        "firewall_ok": False,
        "firewall_detail": "firewall was not queried",
        "expected_identity": {
            "user": state.get("owner") or None,
            "logname": state.get("owner") or None,
            "home": state.get("owner_home") or None,
        },
        "seen_identity": None,
        "bin_dirs": _bin_dir_facts(state) if platform == "linux" else [],
        "settings": _settings_facts(state) if platform != "windows" else [],
        "claude_version": _claude_version() if platform != "windows" else None,
        "claude_login": "skip",
        "claude_login_detail": "skipped: Claude login was not probed",
        "daemon_running_as_owner": False,
        "daemon_service_file": False,
        "windows_claude_warn": "",
        "controller_error": "controller was not re-read",
        "controller_port": None,
        "allow_lan": False,
        "proxy_missing": _which("curl") is None,
        "proxy_code": None,
        "proxy_stderr": "",
        "noproxy_missing": _which("curl") is None,
        "noproxy_code": None,
        "noproxy_stderr": "",
        "probe_stdout": "",
        "probe_stderr": "",
        "probe_code": 127,
        "owner_probe_stdout": "",
        "owner_probe_stderr": "",
        "owner_probe_code": 127,
        "drop_before": None,
        "drop_after": None,
        "pf_counter_parsed": False,
        "pf_before": None,
        "pf_after": None,
        "unix_socket": None,
        "home_traversable": False,
        "exec_access_ok": False,
        "exec_access_detail": "",
        "extra_tcp_observed": None,
        "gpo_problem": None,
        "outbound_problem": None,
        "switcher_uid": None,
        "switcher_mode": None,
        "switcher_owner": "",
    }
    uid, mode = _switcher_stat(state.get("wrapper"))
    report["switcher_uid"] = uid
    report["switcher_mode"] = mode
    if not report["installed"]:
        report["installed_detail"] = "switcher or account is missing"
        return report
    _fill_network(report, state, platform)
    _fill_claude(report, state, platform)
    return report


def _switcher_stat(path):
    if not path:
        return None, None
    try:
        st = os.lstat(path)
    except OSError:
        return None, None
    return st.st_uid, stat.S_IMODE(st.st_mode)


def _switcher_present(state, platform):
    path = state.get("wrapper") or ""
    if platform != "windows" and not os.path.isfile(path):
        return False
    if platform == "windows" and path and not os.path.isfile(path):
        return False
    return bool(state.get("agent_user"))


def _which(name):
    import shutil
    return shutil.which(name)


def _account_facts(state, platform):
    facts = {"exists": False, "groups": [], "shell": "", "locked": False, "enabled": True, "home": ""}
    if platform == "linux":
        result = _run(["getent", "passwd", "agentnet"])
        if result and result.returncode == 0 and result.stdout.strip():
            parts = result.stdout.strip().split(":")
            facts["exists"] = True
            if len(parts) > 6:
                facts["home"] = parts[5]
                facts["shell"] = parts[6]
        groups = _run(["id", "-nG", "agentnet"])
        if groups and groups.returncode == 0:
            facts["groups"] = groups.stdout.split()
        status = _run(["passwd", "-S", "agentnet"])
        if status and status.returncode == 0:
            # passwd -S prints "agentnet L ..." when locked.
            fields = status.stdout.split()
            facts["locked"] = len(fields) > 1 and fields[1].startswith("L")
    elif platform == "darwin":
        result = _run(["id", "agentnet"])
        facts["exists"] = bool(result and result.returncode == 0)
        groups = _run(["id", "-Gn", "agentnet"])
        if groups and groups.returncode == 0:
            facts["groups"] = groups.stdout.split()
    elif platform == "windows":
        from .windows import windows_admin_script, windows_user_script
        result = _run(["powershell", "-NoProfile", "-Command", windows_user_script()])
        raw = (result.stdout or "").strip() if result and result.returncode == 0 else ""
        data = None
        if raw:
            try:
                data = json.loads(raw)
            except ValueError:
                data = None
        if isinstance(data, list):
            data = data[0] if data else None
        if isinstance(data, dict) and data.get("Name"):
            facts["exists"] = True
            enabled = data.get("Enabled")
            facts["enabled"] = enabled is True or str(enabled).lower() == "true"
        admin = _run(["powershell", "-NoProfile", "-Command", windows_admin_script()])
        if admin and "yes" in (admin.stdout or "").lower():
            facts["groups"] = ["Administrators"]
    return facts


def _bin_dir_facts(state):
    facts = []
    for path in state.get("bin_dirs") or []:
        try:
            st = os.lstat(path)
        except OSError:
            facts.append({"path": path, "is_dir": False, "is_link": False, "mode": 0, "gid": 0})
            continue
        facts.append({
            "path": path,
            "is_dir": stat.S_ISDIR(st.st_mode),
            "is_link": stat.S_ISLNK(st.st_mode),
            "mode": stat.S_IMODE(st.st_mode),
            "gid": st.st_gid,
        })
    return facts


def _settings_facts(state):
    items = []
    for entry in state.get("claude_settings") or []:
        path = entry.get("path") if isinstance(entry, dict) else None
        document = {}
        if path and os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    document = json.load(handle)
            except (OSError, ValueError):
                document = {}
        items.append({"path": path, "document": document})
    return items


def _claude_version():
    if _which("claude") is None:
        return None
    result = _run(["claude", "--version"], timeout=15)
    if not result:
        return ""
    return (result.stdout or "") + (result.stderr or "")


def _fill_windows_probes(report, state):
    """Owner probe stays this process. Locked probe and curls run as agentnet.

    agent-lock.cmd is not a switch: it exits 126 for the installing user.
    """
    import tempfile
    from .windows import parse_locked_batch, windows_locked_command
    python = sys.executable or "python3"
    proxy = ["curl", "-sS", "-o", os.devnull, "--max-time", "5",
             "-x", state.get("proxy") or "", "https://example.com"]
    direct = ["curl", "-sS", "-o", os.devnull, "--max-time", "3",
              "--noproxy", "*", "https://1.1.1.1/"]
    fd, probe_path = tempfile.mkstemp(prefix="agent-lock-probe-", suffix=".py")
    try:
        os.write(fd, PROBE_SOURCE.encode("utf-8"))
    finally:
        os.close(fd)
    try:
        try:
            command = windows_locked_command(
                state.get("agent_sid") or "", python, probe_path, proxy, direct)
        except AgentLockError:
            command = None
        result = _run(command, timeout=60) if command else None
        if not result or result.returncode != 0:
            code = 126 if result and result.returncode == 126 else 127
            report["probe_code"] = code
            report["probe_stderr"] = "locked probe was not run as agentnet"
            report["proxy_code"] = code
            report["noproxy_code"] = code
        else:
            parsed = parse_locked_batch(result.stdout or "")
            report["probe_code"] = parsed["probe_code"] if parsed["probe_code"] is not None else 127
            report["probe_stdout"] = parsed["probe_stdout"]
            report["probe_stderr"] = parsed["probe_stderr"]
            report["proxy_code"] = parsed["proxy_code"]
            report["proxy_stderr"] = parsed["proxy_stderr"]
            report["noproxy_code"] = parsed["noproxy_code"]
            report["noproxy_stderr"] = parsed["noproxy_stderr"]
    finally:
        try:
            os.remove(probe_path)
        except OSError:
            pass
    owner = _run([python, "-c", PROBE_SOURCE], timeout=10)
    if owner:
        report["owner_probe_code"] = owner.returncode
        report["owner_probe_stdout"] = owner.stdout
        report["owner_probe_stderr"] = owner.stderr


def _fill_network(report, state, platform):
    """Run the curl and TCP probes. Firewall queries use sudo and may fail closed."""
    python = sys.executable or "python3"
    switcher = state.get("wrapper") or ""
    probe = [python, "-c", PROBE_SOURCE]
    if platform == "linux":
        report["drop_before"] = _linux_drop_packets()
    elif platform == "darwin":
        parsed, count = _pf_block_count()
        report["pf_counter_parsed"] = parsed
        report["pf_before"] = count
    if platform == "windows":
        _fill_windows_probes(report, state)
    else:
        if switcher and os.path.isfile(switcher):
            locked = _run([switcher] + probe, timeout=15)
            if locked:
                report["probe_code"] = locked.returncode
                report["probe_stdout"] = locked.stdout
                report["probe_stderr"] = locked.stderr
            if not report["proxy_missing"]:
                proxy = _run([switcher, "curl", "-sS", "-o", os.devnull, "--max-time", "5",
                              "-x", state.get("proxy") or "", "https://example.com"], timeout=15)
                if proxy:
                    report["proxy_code"] = proxy.returncode
                    report["proxy_stderr"] = proxy.stderr
                direct = _run([switcher, "curl", "-sS", "-o", os.devnull, "--max-time", "3",
                               "--noproxy", "*", "https://1.1.1.1/"], timeout=15)
                if direct:
                    report["noproxy_code"] = direct.returncode
                    report["noproxy_stderr"] = direct.stderr
        owner = _run(probe, timeout=10)
        if owner:
            report["owner_probe_code"] = owner.returncode
            report["owner_probe_stdout"] = owner.stdout
            report["owner_probe_stderr"] = owner.stderr
    if platform == "linux":
        report["drop_after"] = _linux_drop_packets()
    elif platform == "darwin":
        parsed, count = _pf_block_count()
        if not parsed:
            report["pf_counter_parsed"] = False
        report["pf_after"] = count
    report["firewall_ok"] = False
    report["firewall_detail"] = "firewall was not queried"
    if platform == "linux":
        _fill_linux_firewall(report, state)
    elif platform == "darwin":
        _fill_darwin_firewall(report, state)
    elif platform == "windows":
        _fill_windows_firewall(report, state)
    _fill_controller(report, state)
    _fill_identity(report, state, platform)
    _fill_home(report, state, platform)
    _fill_unix(report, state, platform)
    return report


def _fill_linux_firewall(report, state):
    from .linux import nft_observed
    nft = _which("nft")
    if not nft:
        report["firewall_unsupported"] = True
        report["firewall_detail"] = "nft is not installed"
        report["extra_tcp_observed"] = None
        return
    result = _run(["sudo", nft, "-j", "list", "table", "inet", "agentlock"], timeout=20)
    if not result or result.returncode != 0:
        report["firewall_ok"] = False
        report["firewall_detail"] = "could not list table inet agentlock"
        report["extra_tcp_observed"] = None
        return
    try:
        data = json.loads(result.stdout)
    except ValueError:
        report["firewall_detail"] = "nft JSON was not readable"
        report["extra_tcp_observed"] = None
        report["firewall_ok"] = False
        return
    ok, extras = nft_observed(data, state.get("port") or 0)
    report["extra_tcp_observed"] = extras
    report["firewall_ok"] = bool(ok)
    if ok:
        report["firewall_detail"] = "nft table matches the saved port"
    else:
        report["firewall_detail"] = "nft table does not match the saved port"


def _fill_darwin_firewall(report, state):
    from .darwin import anchor_observed, pf_conf_problem
    text = _read("/etc/pf.conf")
    problem = pf_conf_problem(text)
    if problem:
        report["firewall_ok"] = False
        report["firewall_detail"] = problem
        report["extra_tcp_observed"] = None
        return
    result = _run(["sudo", "pfctl", "-a", "agentlock", "-sr"], timeout=20)
    if not result or result.returncode != 0:
        report["firewall_ok"] = False
        report["firewall_detail"] = "could not read the agentlock anchor"
        report["extra_tcp_observed"] = None
        return
    ok, extras = anchor_observed(result.stdout or "", state.get("port") or 0)
    report["extra_tcp_observed"] = extras
    report["firewall_ok"] = bool(ok)
    if ok:
        report["firewall_detail"] = "pf anchor passes the state port and blocks other traffic"
    else:
        report["firewall_detail"] = "pf anchor does not pass the state port and block other traffic"


def _fill_windows_firewall(report, state):
    from .windows import windows_firewall_report, windows_profile_script, windows_rule_script
    profile = _run(["powershell", "-NoProfile", "-Command", windows_profile_script()], timeout=30)
    if not profile or profile.returncode != 0 or not (profile.stdout or "").strip():
        report["firewall_ok"] = False
        report["firewall_detail"] = "could not query Windows firewall profiles"
        report["extra_tcp_observed"] = None
        return
    sid = state.get("agent_sid") or ""
    try:
        rule_script = windows_rule_script(sid)
    except AgentLockError as exc:
        report["firewall_ok"] = False
        report["firewall_detail"] = str(exc)
        report["extra_tcp_observed"] = None
        return
    rules = _run(["powershell", "-NoProfile", "-Command", rule_script], timeout=30)
    if not rules or rules.returncode != 0:
        report["firewall_ok"] = False
        report["firewall_detail"] = "could not query Windows firewall rules"
        report["extra_tcp_observed"] = None
        return
    try:
        profiles = json.loads(profile.stdout)
        parsed_rules = json.loads(rules.stdout) if (rules.stdout or "").strip() else []
    except ValueError:
        report["firewall_ok"] = False
        report["firewall_detail"] = "Windows firewall query was not JSON"
        report["extra_tcp_observed"] = None
        return
    if isinstance(profiles, dict):
        profiles = [profiles]
    if isinstance(parsed_rules, dict):
        parsed_rules = [parsed_rules]
    gpo, outbound, ok, extras = windows_firewall_report(profiles, parsed_rules, state.get("port") or 0)
    report["gpo_problem"] = gpo
    report["outbound_problem"] = outbound
    report["firewall_ok"] = bool(ok)
    report["extra_tcp_observed"] = extras
    if gpo or outbound:
        report["firewall_detail"] = gpo or outbound
    elif ok:
        report["firewall_detail"] = "Windows firewall blocks this SID except the proxy port"
    else:
        report["firewall_detail"] = "Windows firewall does not match the saved port"
    owner = _run(["powershell", "-NoProfile", "-Command",
                  "(Get-Acl -LiteralPath '{}').Owner".format(state.get("wrapper") or "")], timeout=20)
    if owner and owner.returncode == 0:
        report["switcher_owner"] = (owner.stdout or "").strip()


def _linux_drop_packets():
    nft = _which("nft")
    if not nft:
        return None
    result = _run(["sudo", nft, "-j", "list", "counter", "inet", "agentlock", "agentlock_drop"], timeout=15)
    if not result or result.returncode != 0:
        return None
    try:
        data = json.loads(result.stdout or "")
    except ValueError:
        return None
    items = data.get("nftables") if isinstance(data, dict) else None
    if not isinstance(items, list):
        return None
    for item in items:
        counter = item.get("counter") if isinstance(item, dict) else None
        if isinstance(counter, dict) and counter.get("name") == "agentlock_drop":
            packets = counter.get("packets")
            if isinstance(packets, int):
                return packets
    return None


def _pf_block_count():
    """(parsed, packets). Unparsed stays a warning in pf_counter_status."""
    result = _run(["sudo", "pfctl", "-a", "agentlock", "-sr", "-v"], timeout=15)
    if not result or result.returncode != 0 or not result.stdout:
        return False, None
    packets = None
    pending = False
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("block "):
            pending = True
            continue
        if pending and "Packets:" in stripped:
            for token in stripped.replace("Packets:", " ").split():
                if token.isdigit():
                    packets = int(token)
                    pending = False
                    break
    if packets is None:
        return False, None
    return True, packets


def _fill_controller(report, state):
    address = state.get("controller") or ""
    if not address:
        report["controller_error"] = "no controller address is stored"
        report["controller_port"] = None
        return
    from .discover import Candidate, default_fetch, discover
    kind = "unix" if str(address).startswith("unix:") else "tcp"
    secret = state.get("secret") or ""
    try:
        found = discover([Candidate(address, secret, "state", kind)], default_fetch, None)
    except Exception as exc:
        # discover redacts the secret; do not attach the raw exception if it still holds it.
        text = str(exc)
        if secret and secret in text:
            text = text.replace(secret, secret_label(secret))
        report["controller_error"] = text or "controller was not readable"
        return
    report["controller_error"] = None
    report["controller_port"] = found.get("port")
    report["allow_lan"] = False


def identity_commands(switcher):
    """One printenv per name so an unset variable stays unset instead of shifting lines."""
    return [[switcher, "/usr/bin/printenv", name] for name in ("USER", "LOGNAME", "HOME")]


def identity_expected(environ):
    found = {}
    for key, name in (("user", "USER"), ("logname", "LOGNAME"), ("home", "HOME")):
        found[key] = environ[name] if name in environ else None
    return found


def identity_from_results(results):
    """(returncode, stdout) per name. A non-zero status is an unset variable."""
    if not results or any(item is None for item in results):
        return None
    seen = {}
    for key, item in zip(("user", "logname", "home"), results):
        code, stdout = item
        if code != 0:
            seen[key] = None
        else:
            lines = (stdout or "").splitlines()
            seen[key] = lines[0] if lines else None
    return seen


def _fill_identity(report, state, platform):
    if platform == "windows":
        return
    report["expected_identity"] = identity_expected(os.environ)
    _run(["sudo", "-k"])
    switcher = state.get("wrapper") or ""
    if not switcher or not os.path.isfile(switcher):
        report["seen_identity"] = None
        return
    results = []
    for command in identity_commands(switcher):
        result = _run(command)
        if result is None:
            results.append(None)
        else:
            results.append((result.returncode, result.stdout))
    report["seen_identity"] = identity_from_results(results)


def _fill_home(report, state, platform):
    home = state.get("owner_home") or ""
    switcher = state.get("wrapper") or ""
    if not home or platform == "windows" or not switcher:
        report["home_traversable"] = False
        return
    result = _run([switcher, "test", "-x", home])
    report["home_traversable"] = bool(result and result.returncode == 0)


def _fill_unix(report, state, platform):
    if platform == "windows":
        return
    paths = []
    controller = state.get("controller") or ""
    if str(controller).startswith("unix:"):
        paths.append(controller[len("unix:"):])
    home = state.get("owner_home") or ""
    if home:
        paths.append(os.path.join(home, ".local", "share", "mihomo-cli", "mihomo.sock"))
    existing = [path for path in paths if path and os.path.exists(path)]
    if not existing:
        report["unix_socket"] = None
        return
    # Fail closed when the socket is there and we cannot prove agentnet is blocked.
    report["unix_socket"] = "open"
    code = (
        "import socket, sys\n"
        "s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
        "s.settimeout(3)\n"
        "try:\n"
        "    s.connect(sys.argv[1])\n"
        "except OSError:\n"
        "    sys.exit(1)\n"
        "sys.exit(0)\n"
    )
    python = sys.executable or "python3"
    switcher = state.get("wrapper") or ""
    for path in existing:
        if not switcher:
            return
        result = _run([switcher, python, "-c", code, path])
        if result is None:
            return
        if result.returncode == 0:
            report["unix_socket"] = "open"
            return
    report["unix_socket"] = "closed"


def classify_login(probe):
    """probe keys: attempted, keychain_account, credentials_account, owner.

    keychain_account is only set when the agentnet probe succeeded. The owner's
    own keychain does not count.
    """
    if not probe or not probe.get("attempted"):
        return "skip", "skipped: Claude login was not probed"
    owner = probe.get("owner") or ""
    if owner and probe.get("keychain_account") == owner:
        return "pass", "agentnet keychain has the owner account"
    if owner and probe.get("credentials_account") == owner:
        return "pass", "agentnet can read a Claude credential for the owner"
    return "fail", "agentnet cannot see a Claude login"


def credentials_account(text, owner):
    if not text or not owner:
        return None
    try:
        data = json.loads(text)
    except ValueError:
        return None
    found = []

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key.lower() in ("account", "user", "email", "username") and isinstance(value, str):
                    found.append(value)
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(data)
    if owner in found:
        return owner
    return None


def classify_daemon(rows, agent_uid, service_file):
    """Fail when a claude daemon is running as someone other than agentnet.

    A service file warns only when no daemon process is running.
    """
    owner_running = False
    agent_running = False
    for uid, command in rows or []:
        text = command or ""
        if "claude-daemon" not in text and "com.anthropic.claude-daemon" not in text:
            continue
        if agent_uid and int(uid) == int(agent_uid):
            agent_running = True
        else:
            owner_running = True
    if owner_running:
        return True, False
    if service_file and not agent_running:
        return False, True
    return False, False


def parse_ps_uid_command(text):
    rows = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        uid, _sep, command = line.partition(" ")
        if uid.isdigit():
            rows.append((int(uid), command.strip()))
    return rows


def exec_access_problem(codes):
    if any(code != 0 for code in codes):
        return "a recorded path is not executable"
    return None


def daemon_service_paths(home):
    home = home or ""
    return [
        os.path.join(home, "Library", "LaunchAgents", "com.anthropic.claude-daemon.plist"),
        os.path.join(home, ".config", "systemd", "user", "claude-daemon.service"),
    ]


def _fill_claude(report, state, platform):
    if platform == "windows":
        from .windows import windows_path_executable
        paths = list(state.get("exec_paths") or [])
        if not paths:
            report["exec_access_ok"] = True
            report["exec_access_detail"] = "no recorded launchers"
            return
        codes = []
        for path in paths:
            result = _run(["icacls", path])
            text = (result.stdout or "") if result and result.returncode == 0 else ""
            codes.append(0 if windows_path_executable(text) else 1)
        problem = exec_access_problem(codes)
        report["exec_access_ok"] = problem is None
        report["exec_access_detail"] = problem or "recorded paths are executable"
        return
    switcher = state.get("wrapper") or ""
    owner = state.get("owner") or ""
    home = state.get("owner_home") or ""
    cred_path = os.path.join(home, ".claude", ".credentials.json") if home else ""
    probe = {"attempted": False, "owner": owner, "keychain_account": None, "credentials_account": None}
    if switcher and os.path.isfile(switcher):
        probe["attempted"] = True
        if platform == "darwin" and owner:
            keychain = _run([
                switcher, "security", "find-generic-password", "-a", owner, "-s", "Claude Code",
            ])
            if keychain and keychain.returncode == 0:
                probe["keychain_account"] = owner
        if cred_path:
            cred = _run([switcher, "/bin/cat", cred_path])
            if cred and cred.returncode == 0:
                probe["credentials_account"] = credentials_account(cred.stdout, owner)
    status, detail = classify_login(probe)
    report["claude_login"] = status
    report["claude_login_detail"] = detail
    rows = []
    ps = _run(["ps", "-ax", "-o", "uid=,command="])
    if ps and ps.returncode == 0:
        rows = parse_ps_uid_command(ps.stdout)
    service = any(os.path.isfile(path) for path in daemon_service_paths(home))
    running, service_only = classify_daemon(rows, state.get("agent_uid"), service)
    report["daemon_running_as_owner"] = running
    report["daemon_service_file"] = service_only
    paths = []
    launcher = state.get("claude_wrapper") or ""
    if launcher:
        paths.append(launcher)
    paths.extend(state.get("exec_paths") or [])
    if not paths:
        report["exec_access_ok"] = True
        report["exec_access_detail"] = "no recorded launchers"
        return
    if not switcher:
        report["exec_access_ok"] = False
        report["exec_access_detail"] = "a recorded path is not executable"
        return
    codes = []
    for path in paths:
        result = _run([switcher, "test", "-x", path])
        codes.append(1 if result is None else result.returncode)
    problem = exec_access_problem(codes)
    report["exec_access_ok"] = problem is None
    report["exec_access_detail"] = problem or "recorded paths are executable"
