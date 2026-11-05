"""Install and uninstall. Mutating commands go through `runner`, which tests replace.

Nothing in this module runs at import time. `runner` defaults to a subprocess
call, so unit tests must not invoke cmd_install or cmd_uninstall.
"""

import json
import os
import shutil
import stat
import subprocess
import sys

from . import doctor
from .discover import (
    choose_port,
    collect_candidates,
    controller_candidate,
    default_fetch,
    mihomo_home,
    read_secret_stdin,
    verge_paths,
)
from .errors import AgentLockError, NotInstalled, Unsupported, UsageError
from .linux import (
    NFT_CONF,
    UNIT_NAME,
    UNIT_PATH,
    classify_path,
    credential_entries,
    find_nft,
    find_runuser,
    nft_check_argv,
    nft_load_argv,
    render_nft,
    render_unit,
    require_firewalld_inactive,
    setfacl_commands,
    user_plan,
)
from .darwin import (
    ANCHOR_PATH,
    PF_BACKUP,
    PF_CONF,
    acl_commands,
    check_conf_argv,
    enable_argv,
    is_tcc_path,
    load_anchor_argv,
    load_conf_argv,
    parse_enable_token,
    patch_pf_conf,
    release_token_argv,
    render_anchor,
    unpatch_pf_conf,
    user_plan as darwin_user_plan,
)
from .state import (
    AGENT_USER,
    CLAUDE_WRAPPER_PATH,
    LINUX_AGENT_HOME,
    SUDOERS_PATH,
    SWITCHER_PATH,
    WINDOWS_CMD,
    apply_install_fields,
    atomic_write,
    config_base,
    extra_tcp_from_args,
    is_root,
    load_state,
    merge_claude_settings,
    new_state,
    proxy_url,
    resolve_owner,
    save_state,
    strip_claude_settings,
)
from .windows import (
    build_rules,
    create_profile_script,
    icacls_commands,
    link_plan,
    new_local_user_script,
    render_rule_script,
    require_supported,
    rule_names,
    share_icacls,
    uninstall_commands,
    user_action,
)
from .wrapper import render_claude, render_sudoers, render_switcher, render_windows_cmd
from .linux import bind_bin_mode, validate_bind_bin


def _runner(argv, check=False, input_text=None, timeout=60):
    return subprocess.run(
        argv,
        input=input_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        timeout=timeout,
        check=check,
    )


def _ok(runner, argv, input_text=None):
    result = runner(argv, input_text=input_text)
    if getattr(result, "returncode", 1) != 0:
        detail = (getattr(result, "stderr", "") or getattr(result, "stdout", "") or "").strip()
        raise AgentLockError("{} failed: {}".format(argv[0], detail or "exit {}".format(
            getattr(result, "returncode", 1))))
    return result


def _read_text(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return None


def _expand(path, owner_home):
    if path == "~":
        return owner_home
    if path.startswith("~/") or path.startswith("~\\"):
        return os.path.join(owner_home, path[2:])
    if os.path.isabs(path):
        return path
    return os.path.abspath(path)


def _owner_env(owner):
    env = dict(os.environ)
    if owner.get("sudo"):
        for key in ("MIHOMO_CLI_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "APPDATA"):
            value = env.get(key) or ""
            if value.startswith("/root") or value.startswith("/var/root"):
                env.pop(key, None)
    return env


def _process_argvs(runner):
    found = []
    if sys.platform.startswith("linux"):
        try:
            names = os.listdir("/proc")
        except OSError:
            return found
        for name in names:
            if not name.isdigit():
                continue
            try:
                with open(os.path.join("/proc", name, "cmdline"), "rb") as handle:
                    raw = handle.read()
            except OSError:
                continue
            parts = [part.decode("utf-8", "replace") for part in raw.split(b"\0") if part]
            if parts:
                found.append(parts)
        return found
    if sys.platform == "darwin":
        try:
            result = runner(["ps", "-axww", "-o", "args="])
        except OSError:
            return found
        import shlex
        for line in (getattr(result, "stdout", "") or "").splitlines():
            try:
                found.append(shlex.split(line))
            except ValueError:
                continue
    return found


def _gather(args, owner, runner):
    secret = ""
    if getattr(args, "secret_stdin", False):
        secret = read_secret_stdin(sys.stdin.readline)
    env = _owner_env(owner)
    if args.controller:
        candidates = [controller_candidate(args.controller, secret)]
    else:
        appdata = env.get("APPDATA") if sys.platform == "win32" else None
        candidates = collect_candidates(
            _process_argvs(runner),
            _read_text,
            owner.get("home"),
            mihomo_home(owner.get("home"), env),
            verge_paths(owner.get("home"), appdata),
        )
        if secret:
            for candidate in candidates:
                if candidate.kind == "tcp":
                    candidate.secret = secret
    found = choose_port(args.port, bool(args.controller), candidates, default_fetch)
    return found


def _credential_roots(owner_home, share_dirs):
    roots = []
    for name in (".codex", ".cx", ".claude", ".cc"):
        path = os.path.join(owner_home, name)
        if classify_path(path) != "missing":
            roots.append(path)
    for path in share_dirs:
        roots.append(path)
    return roots


def _account_dirs(owner):
    base = config_base(owner)
    if not base:
        return []
    path = os.path.join(base, "multi-claude", "config.json")
    text = _read_text(path)
    if not text:
        return []
    try:
        data = json.loads(text)
    except ValueError:
        return []
    root = _expand(data.get("root") or "~/.cc", owner["home"])
    accounts = data.get("accounts") or {}
    paths = []
    if isinstance(accounts, dict):
        for name, account in accounts.items():
            directory = name
            if isinstance(account, dict) and account.get("dir"):
                directory = account["dir"]
            paths.append(os.path.join(root, str(directory)))
    return paths


def _write_settings(paths, wrapper):
    """POSIX only. Records {path, created}. Does not write proxy variables."""
    written = []
    for path in paths:
        directory = os.path.dirname(path)
        if directory and not os.path.isdir(directory):
            if os.path.basename(directory) == ".claude" or path.endswith(os.path.join(".claude", "settings.json")):
                os.makedirs(directory, exist_ok=True)
            else:
                continue
        created = not os.path.exists(path)
        document = {}
        if os.path.isfile(path) and not os.path.islink(path):
            text = _read_text(path) or ""
            try:
                document = json.loads(text) if text.strip() else {}
            except ValueError:
                raise AgentLockError("cannot parse Claude settings: {}".format(path))
        elif os.path.islink(path):
            raise AgentLockError("refusing to follow a symlinked settings file: {}".format(path))
        document = merge_claude_settings(document, wrapper)
        atomic_write(path, json.dumps(document, indent=2, sort_keys=True) + "\n", 0o600)
        written.append({"path": path, "created": created})
    return written


def _snapshot(paths):
    saved = []
    for path in paths:
        try:
            st = os.lstat(path)
            with open(path, "rb") as handle:
                saved.append((path, handle.read(), stat.S_IMODE(st.st_mode)))
        except OSError:
            saved.append((path, None, None))
    return saved


def _restore(saved):
    for path, data, mode in saved:
        if data is None:
            if os.path.lexists(path) and not os.path.isdir(path):
                os.remove(path)
            continue
        atomic_write(path, data, mode or 0o644)


def _linux_identity():
    import grp
    import pwd
    try:
        user = pwd.getpwnam(AGENT_USER)
        user_exists = True
        shell = user.pw_shell
        uid = user.pw_uid
        gid = user.pw_gid
    except KeyError:
        user_exists = False
        shell = ""
        uid = 0
        gid = 0
    try:
        group = grp.getgrnam(AGENT_USER)
        group_exists = True
        if not user_exists:
            gid = group.gr_gid
    except KeyError:
        group_exists = False
    return user_exists, group_exists, os.path.isdir(LINUX_AGENT_HOME), shell, uid, gid


def _proxy_check(runner, prefix, proxy):
    result = runner(list(prefix) + [
        "curl", "-fsS", "--max-time", "5", "-x", proxy, "https://example.com",
    ])
    return getattr(result, "returncode", 1) == 0


def _install_sudoers(owner_name, runner):
    text = render_sudoers(owner_name)
    directory = os.path.dirname(SUDOERS_PATH)
    fd, tmp = __import__("tempfile").mkstemp(dir=directory if os.path.isdir(directory) else None, prefix="agent-lock-sudoers.")
    os.close(fd)
    try:
        atomic_write(tmp, text, 0o440)
        _ok(runner, ["visudo", "-cf", tmp])
        atomic_write(SUDOERS_PATH, text, 0o440)
    finally:
        if os.path.exists(tmp) and tmp != SUDOERS_PATH:
            try:
                os.remove(tmp)
            except OSError:
                pass


def _linux_apply(args, owner, found, extra, runner, stdout):
    require_firewalld_inactive(runner)
    nft = find_nft()
    runuser = find_runuser()
    if not nft or not runuser:
        raise Unsupported("nft or runuser was not found")
    user_exists, group_exists, home_exists, shell, uid, gid = _linux_identity()
    commands, created = user_plan(user_exists, group_exists, home_exists, shell)
    for command in commands:
        _ok(runner, command)
    if created or uid == 0:
        user_exists, group_exists, home_exists, shell, uid, gid = _linux_identity()
    if not user_exists:
        raise AgentLockError("agentnet was not created")
    result = runner(["id", "-nG", AGENT_USER])
    groups = (getattr(result, "stdout", "") or "").split()
    for name in ("sudo", "wheel", "adm"):
        if name in groups:
            raise AgentLockError("agentnet is in the {} group".format(name))
    port = int(found["port"])
    share = [_expand(path, owner["home"]) for path in (args.share_dir or [])]
    for path in share:
        if not os.path.isdir(path):
            raise UsageError("share-dir is not a directory: {}".format(path))
    trust = [_expand(path, owner["home"]) for path in (args.trust_exec or [])]
    switcher = render_switcher(port, runuser, darwin=False)
    claude = render_claude(port)
    rules = render_nft(uid, port, extra)
    saved = _snapshot([NFT_CONF, UNIT_PATH, SWITCHER_PATH, CLAUDE_WRAPPER_PATH, SUDOERS_PATH])
    fd, tmp = __import__("tempfile").mkstemp(prefix="agent-lock-nft.")
    os.close(fd)
    try:
        atomic_write(tmp, rules, 0o644)
        _ok(runner, nft_check_argv(nft, tmp))
        os.makedirs(os.path.dirname(NFT_CONF), exist_ok=True)
        atomic_write(NFT_CONF, rules, 0o644)
        _ok(runner, nft_load_argv(nft, NFT_CONF))
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    atomic_write(UNIT_PATH, render_unit(nft, NFT_CONF), 0o644)
    runner(["systemctl", "daemon-reload"])
    _ok(runner, ["systemctl", "enable", "--now", UNIT_NAME])
    atomic_write(SWITCHER_PATH, switcher, 0o755)
    atomic_write(CLAUDE_WRAPPER_PATH, claude, 0o755)
    _install_sudoers(owner["name"], runner)
    roots = _credential_roots(owner["home"], share)
    entries = credential_entries(roots, owner["home"], classify_path)
    for command in setfacl_commands(entries):
        _ok(runner, command)
    for path in trust:
        if os.path.isdir(path) and not os.path.islink(path):
            spec = "u:{}:r-x,m::r-x".format(AGENT_USER)
        else:
            spec = "u:{}:r-x,m::r-x".format(AGENT_USER)
        _ok(runner, ["setfacl", "-m", spec, path])
    runner(["claude", "daemon", "stop", "--any"])
    setting_paths = [os.path.join(owner["home"], ".claude", "settings.json")]
    for path in args.claude_dir or []:
        setting_paths.append(os.path.join(_expand(path, owner["home"]), "settings.json"))
    for path in _account_dirs(owner):
        setting_paths.append(os.path.join(path, "settings.json"))
    settings = _write_settings(setting_paths, CLAUDE_WRAPPER_PATH)
    old = load_state()
    if not _proxy_check(runner, [runuser, "--preserve-environment", "-u", AGENT_USER, "--", SWITCHER_PATH], proxy_url(port)):
        _restore(saved)
        if old and old.get("port"):
            _ok(runner, nft_load_argv(nft, NFT_CONF))
        else:
            runner([nft, "delete", "table", "inet", "agentlock"])
        raise AgentLockError("proxy check failed; kept the previous port")
    data = apply_install_fields(old, port, extra, found.get("controller") or "", found.get("secret") or "")
    if not old:
        data = new_state(owner, port, found.get("controller") or "", found.get("secret") or "", extra)
    data["agent_uid"] = uid
    data["agent_gid"] = gid
    data["agent_home"] = LINUX_AGENT_HOME
    data["runuser_path"] = runuser
    data["wrapper"] = SWITCHER_PATH
    data["claude_wrapper"] = CLAUDE_WRAPPER_PATH
    data["created_user"] = bool(created or (old or {}).get("created_user"))
    data["share_dirs"] = share
    data["exec_paths"] = trust
    data["claude_settings"] = settings
    data["pf_enable_token"] = ""
    save_state(data)
    for line in found.get("logs") or []:
        stdout.write(line + "\n")
    stdout.write("installed agent-lock on port {}\n".format(port))
    return 0


def _darwin_apply(args, owner, found, extra, runner, stdout):
    if not shutil.which("pfctl"):
        raise Unsupported("pfctl was not found")
    share = [_expand(path, owner["home"]) for path in (args.share_dir or [])]
    for path in share:
        if is_tcc_path(path, owner["home"]):
            raise UsageError("share-dir is in Desktop, Documents, or Downloads: {}".format(path))
        if not os.path.isdir(path):
            raise UsageError("share-dir is not a directory: {}".format(path))
    import pwd
    try:
        pwd.getpwnam(AGENT_USER)
        exists = True
    except KeyError:
        exists = False
    if not exists:
        password = subprocess.run(
            ["openssl", "rand", "-base64", "32"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, check=False)
        secret_pw = (password.stdout or "").strip()
        if not secret_pw:
            raise AgentLockError("could not generate a password")
        for command in darwin_user_plan(False):
            _ok(runner, command, input_text=secret_pw + "\n" if command[0] == "sysadminctl" else None)
        secret_pw = ""
    port = int(found["port"])
    anchor = render_anchor(port, extra)
    current = _read_text(PF_CONF) or ""
    already = 'anchor "agentlock"' in current
    saved = _snapshot([PF_CONF, ANCHOR_PATH, SWITCHER_PATH, CLAUDE_WRAPPER_PATH])
    if not already:
        patched = patch_pf_conf(current)
        if not os.path.exists(PF_BACKUP):
            atomic_write(PF_BACKUP, current, 0o644)
        fd, tmp = __import__("tempfile").mkstemp(prefix="agent-lock-pf.")
        os.close(fd)
        try:
            atomic_write(tmp, patched, 0o644)
            _ok(runner, check_conf_argv(tmp))
            atomic_write(PF_CONF, patched, 0o644)
            _ok(runner, load_conf_argv(PF_CONF))
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)
    os.makedirs(os.path.dirname(ANCHOR_PATH), exist_ok=True)
    atomic_write(ANCHOR_PATH, anchor, 0o644)
    _ok(runner, load_anchor_argv(ANCHOR_PATH))
    token = (load_state() or {}).get("pf_enable_token") or ""
    if not token:
        enabled = _ok(runner, enable_argv())
        token = parse_enable_token(getattr(enabled, "stdout", "") + "\n" + getattr(enabled, "stderr", ""))
    atomic_write(SWITCHER_PATH, render_switcher(port, "", darwin=True), 0o755)
    atomic_write(CLAUDE_WRAPPER_PATH, render_claude(port), 0o755)
    directories = [path for path in _credential_roots(owner["home"], share) if classify_path(path) == "dir"]
    for command in acl_commands(directories, owner["home"], True):
        if command[1] == "-a":
            runner(command)
        else:
            _ok(runner, command)
    runner(["claude", "daemon", "stop", "--any"])
    setting_paths = [os.path.join(owner["home"], ".claude", "settings.json")]
    for path in args.claude_dir or []:
        setting_paths.append(os.path.join(_expand(path, owner["home"]), "settings.json"))
    for path in _account_dirs(owner):
        setting_paths.append(os.path.join(path, "settings.json"))
    settings = _write_settings(setting_paths, CLAUDE_WRAPPER_PATH)
    if not _proxy_check(
            runner, ["/usr/bin/sudo", "--preserve-env", "-u", AGENT_USER, "--", SWITCHER_PATH], proxy_url(port)):
        _restore(saved)
        if already:
            runner(load_anchor_argv(ANCHOR_PATH))
        raise AgentLockError("proxy check failed; kept the previous port")
    old = load_state()
    data = new_state(owner, port, found.get("controller") or "", found.get("secret") or "", extra) if not old else apply_install_fields(
        old, port, extra, found.get("controller") or "", found.get("secret") or "")
    try:
        user = pwd.getpwnam(AGENT_USER)
        data["agent_uid"] = user.pw_uid
        data["agent_gid"] = user.pw_gid
    except KeyError:
        pass
    try:
        data["agent_home"] = pwd.getpwnam(AGENT_USER).pw_dir
    except KeyError:
        data["agent_home"] = ""
    data["runuser_path"] = ""
    data["wrapper"] = SWITCHER_PATH
    data["claude_wrapper"] = CLAUDE_WRAPPER_PATH
    data["created_user"] = bool((not exists) or (old or {}).get("created_user"))
    data["share_dirs"] = share
    data["exec_paths"] = [_expand(path, owner["home"]) for path in (args.trust_exec or [])]
    data["claude_settings"] = settings
    data["pf_enable_token"] = token
    save_state(data)
    for line in found.get("logs") or []:
        stdout.write(line + "\n")
    stdout.write("installed agent-lock on port {}\n".format(port))
    return 0


def _windows_profiles(runner):
    script = (
        "Get-NetFirewallProfile | "
        "Select-Object Name, AllowLocalFirewallRules, AllowLocalPolicyMerge, DefaultOutboundAction | "
        "ConvertTo-Json -Compress"
    )
    result = runner(["powershell", "-NoProfile", "-Command", script])
    raw = (getattr(result, "stdout", "") or "").strip()
    if not raw:
        raise AgentLockError("could not read Windows firewall profiles")
    try:
        data = json.loads(raw)
    except ValueError:
        raise AgentLockError("could not read Windows firewall profiles")
    if isinstance(data, dict):
        return [data]
    return list(data)


def _windows_apply(args, owner, found, extra, runner, stdout):
    require_supported(_windows_profiles(runner))
    port = int(found["port"])
    action = user_action(False, True)
    # The live lookup is PowerShell. A disabled account fails inside the script.
    script = (
        "$u = Get-LocalUser -Name '{user}' -ErrorAction SilentlyContinue\n"
        "if ($null -eq $u) {{ 'missing' }} elseif ($u.Enabled) {{ 'enabled' }} else {{ 'disabled' }}\n"
    ).format(user=AGENT_USER)
    result = runner(["powershell", "-NoProfile", "-Command", script])
    text = (getattr(result, "stdout", "") or "").strip()
    if text == "disabled":
        action = user_action(True, False)
    elif text == "enabled":
        action = user_action(True, True)
    else:
        action = user_action(False, True)
    if action == "create":
        _ok(runner, ["powershell", "-NoProfile", "-Command", new_local_user_script()])
    sid_result = _ok(runner, ["powershell", "-NoProfile", "-Command",
                              "(Get-LocalUser -Name '{}').Sid.Value".format(AGENT_USER)])
    sid = (sid_result.stdout or "").strip()
    if not sid.startswith("S-"):
        raise AgentLockError("could not read the agentnet SID")
    rules = build_rules(port, extra, sid)
    for line in render_rule_script(rules).splitlines():
        if line.strip():
            _ok(runner, ["powershell", "-NoProfile", "-Command", line])
    links = []
    home = owner.get("home") or ""
    agent_home = os.path.join(os.environ.get("SystemDrive", "C:") + "\\", "Users", AGENT_USER)
    for name in (".codex", ".cx", ".claude", ".cc"):
        target = os.path.join(home, name)
        if os.path.isdir(target):
            links.append((os.path.join(agent_home, name), target))
    # CreateProfile before any junction. A missing profile is not a reason to skip the call.
    _ok(runner, ["powershell", "-NoProfile", "-Command", create_profile_script(sid)])
    steps = link_plan(True, links)
    for step in steps:
        if step.startswith("mklink"):
            _ok(runner, ["cmd", "/c", step])
    atomic_write(WINDOWS_CMD, render_windows_cmd(port, sid), 0o644)
    for command in share_icacls([target for _link, target in links]):
        runner(command)
    for command in icacls_commands(home, [_expand(path, home) for path in (args.trust_exec or [])], os.path.isdir):
        runner(command)
    if not _proxy_check(runner, [], proxy_url(port)):
        for command in uninstall_commands(rule_names(rules)):
            runner(["powershell", "-NoProfile", "-Command", " ".join(command)])
        raise AgentLockError("proxy check failed; kept the previous port")
    old = load_state()
    data = new_state(owner, port, found.get("controller") or "", found.get("secret") or "", extra) if not old else apply_install_fields(
        old, port, extra, found.get("controller") or "", found.get("secret") or "")
    data["agent_sid"] = sid
    data["agent_home"] = agent_home
    data["wrapper"] = WINDOWS_CMD
    data["claude_wrapper"] = ""
    data["claude_settings"] = []
    data["windows_rules"] = rule_names(rules)
    data["links"] = [link for link, _target in links]
    data["share_dirs"] = [_expand(path, home) for path in (args.share_dir or [])]
    data["exec_paths"] = [_expand(path, home) for path in (args.trust_exec or [])]
    data["created_user"] = bool(action == "create" or (old or {}).get("created_user"))
    data["runuser_path"] = ""
    save_state(data)
    for line in found.get("logs") or []:
        stdout.write(line + "\n")
    stdout.write("installed agent-lock on port {}\n".format(port))
    return 0


def cmd_install(args, stdout=None, stderr=None, runner=None):
    stdout = stdout or sys.stdout
    runner = runner or _runner
    if sys.platform != "win32" and not is_root():
        raise AgentLockError("run sudo agent-lock install", 1)
    owner = resolve_owner()
    if owner is None:
        raise AgentLockError("cannot resolve the installing user; refusing to write state as root", 1)
    extra = extra_tcp_from_args(args.allow_tcp)
    if sys.platform.startswith("linux"):
        found = _gather(args, owner, runner)
        return _linux_apply(args, owner, found, extra, runner, stdout)
    if sys.platform == "darwin":
        found = _gather(args, owner, runner)
        return _darwin_apply(args, owner, found, extra, runner, stdout)
    if sys.platform == "win32":
        found = _gather(args, owner, runner)
        return _windows_apply(args, owner, found, extra, runner, stdout)
    raise Unsupported("this operating system is not supported")


def _remove_user_keep_home(state, runner):
    """Remove the account record when we created it or it lives in the expected home.

    The home directory is left on disk. There is no recursive home removal.
    """
    home = state.get("agent_home") or ""
    if not (state.get("created_user") or home == LINUX_AGENT_HOME):
        return
    if sys.platform.startswith("linux"):
        runner(["userdel", AGENT_USER])
    elif sys.platform == "darwin" and state.get("created_user"):
        runner(["dscl", ".", "-delete", "/Users/{}".format(AGENT_USER)])


def _unlink_recorded(path):
    if not path:
        return
    if not os.path.lexists(path):
        return
    if os.path.islink(path):
        os.unlink(path)
        return
    # A junction is a directory. Only remove it when it is not a normal directory
    # we could mistake for the user's real tree: require the recorded path's target
    # to differ, which lstat-only removal cannot see. Refuse real directories.
    raise AgentLockError("recorded link is not a symlink; left it in place: {}".format(path))


def _strip_settings(entries):
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        path = entry.get("path")
        if not path or os.path.islink(path) or not os.path.isfile(path):
            continue
        text = _read_text(path) or ""
        try:
            document = json.loads(text) if text.strip() else {}
        except ValueError:
            continue
        document, empty = strip_claude_settings(document)
        if entry.get("created") and empty:
            os.remove(path)
        else:
            atomic_write(path, json.dumps(document, indent=2, sort_keys=True) + "\n", 0o600)


def cmd_uninstall(args, stdout=None, stderr=None, runner=None):
    stdout = stdout or sys.stdout
    runner = runner or _runner
    state = load_state()
    if not state:
        raise NotInstalled()
    if sys.platform.startswith("linux"):
        runner(["systemctl", "disable", "--now", UNIT_NAME])
        nft = find_nft() or "nft"
        runner([nft, "delete", "table", "inet", "agentlock"])
        for path in (UNIT_PATH, NFT_CONF, SUDOERS_PATH, SWITCHER_PATH, CLAUDE_WRAPPER_PATH):
            if os.path.lexists(path) and not os.path.isdir(path):
                os.remove(path)
        runner(["systemctl", "daemon-reload"])
    elif sys.platform == "darwin":
        release = release_token_argv(state.get("pf_enable_token") or "")
        if release:
            runner(release)
        current = _read_text(PF_CONF)
        if current is not None:
            updated = unpatch_pf_conf(current)
            atomic_write(PF_CONF, updated, 0o644)
            runner(check_conf_argv(PF_CONF))
            runner(load_conf_argv(PF_CONF))
        if os.path.lexists(ANCHOR_PATH) and not os.path.islink(ANCHOR_PATH):
            os.remove(ANCHOR_PATH)
        for path in (SWITCHER_PATH, CLAUDE_WRAPPER_PATH):
            if os.path.lexists(path) and not os.path.isdir(path):
                os.remove(path)
    elif sys.platform == "win32":
        for command in uninstall_commands(state.get("windows_rules") or []):
            runner(["powershell", "-NoProfile", "-Command", " ".join(command)])
        if os.path.isfile(WINDOWS_CMD):
            os.remove(WINDOWS_CMD)
    for path in state.get("links") or []:
        _unlink_recorded(path)
    if sys.platform != "win32":
        _strip_settings(state.get("claude_settings"))
    _remove_user_keep_home(state, runner)
    path = None
    from .state import state_path
    path = state_path()
    if path and os.path.isfile(path):
        os.remove(path)
    stdout.write("uninstalled agent-lock; linked directories were kept\n")
    return 0


def cmd_exec(tail):
    if not tail:
        raise UsageError("missing command after --")
    state = load_state()
    wrapper = (state or {}).get("wrapper")
    if not state or not wrapper or not os.path.isfile(wrapper):
        raise NotInstalled()
    os.execv(wrapper, [wrapper] + list(tail))
    return 1


def cmd_bind_bin(args):
    if sys.platform == "darwin":
        raise Unsupported("bind-bin is not used on macOS")
    if sys.platform == "win32":
        raise Unsupported("bind-bin is not used on Windows")
    euid = os.geteuid() if hasattr(os, "geteuid") else 0
    code, message = validate_bind_bin(euid, False, True, 0, 0)
    if euid != 0:
        raise AgentLockError(message, code)
    path = args.path
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise UsageError(str(exc))
    owner = resolve_owner()
    if owner is None:
        raise AgentLockError("cannot resolve the installing user", 1)
    code, message = validate_bind_bin(
        euid, stat.S_ISLNK(st.st_mode), stat.S_ISDIR(st.st_mode), st.st_uid, owner["uid"])
    if code == 2:
        raise UsageError(message)
    if code:
        raise AgentLockError(message, code)
    state = load_state()
    if not state:
        raise NotInstalled()
    import grp
    gid = grp.getgrnam(AGENT_USER).gr_gid
    os.chown(path, -1, gid)
    os.chmod(path, bind_bin_mode(stat.S_IMODE(st.st_mode)))
    absolute = os.path.abspath(path)
    dirs = list(state.get("bin_dirs") or [])
    if absolute not in dirs:
        dirs.append(absolute)
    state["bin_dirs"] = dirs
    state["agent_gid"] = gid
    save_state(state)
    return 0


def cmd_doctor(args, stdout=None, stderr=None):
    return doctor.run_doctor(args, stdout=stdout, stderr=stderr)


