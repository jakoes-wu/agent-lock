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
    PF_DYNAMIC_ANCHOR_WARNING,
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
    CREDENTIAL_DIRS,
    LINUX_AGENT_HOME,
    SUDOERS_PATH,
    SWITCHER_PATH,
    WINDOWS_CMD,
    _within,
    apply_install_fields,
    atomic_write,
    config_base,
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
    rule_phases,
    share_icacls,
    uninstall_commands,
    user_action,
    windows_admin_script,
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


def _ok(runner, argv, input_text=None, unsupported=False):
    result = runner(argv, input_text=input_text)
    if getattr(result, "returncode", 1) != 0:
        detail = (getattr(result, "stderr", "") or getattr(result, "stdout", "") or "").strip()
        if unsupported:
            base = os.path.basename(str(argv[0]))
            if base == "nft":
                raise Unsupported(
                    "nft must understand destroy and named counters: {}".format(
                        detail or "syntax check failed"))
            raise Unsupported("pf syntax check failed: {}".format(detail or "pfctl -nf failed"))
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


def _confine(path, owner_home, kind):
    """realpath under the installing user's home. Symlinks and .. escapes are refused."""
    expanded = _expand(path, owner_home)
    if os.path.lexists(expanded) and os.path.islink(expanded):
        raise UsageError("refusing a symlink: {}".format(path))
    real = os.path.realpath(expanded)
    home = os.path.realpath(owner_home)
    if not _within(real, home):
        raise UsageError("path is outside the installing user's home: {}".format(path))
    if kind == "share" and os.path.normcase(os.path.normpath(real)) == os.path.normcase(os.path.normpath(home)):
        raise UsageError("refusing to share the home directory")
    if sys.platform == "darwin" and is_tcc_path(real, home):
        raise UsageError("path is in Desktop, Documents, or Downloads: {}".format(path))
    return real


def _claude_dirname_ok(directory):
    name = os.path.basename(os.path.normpath(directory))
    return name == ".claude" or name.endswith(".claude")


def _state_after_install(old, owner, port, extra, found):
    """--port keeps a stored controller and secret. A real discovery may clear them."""
    controller = None
    secret = None
    if found and found.get("source") != "--port":
        controller = found.get("controller")
        if controller is None:
            controller = ""
        secret = found.get("secret")
        if secret is None:
            secret = ""
    if not old:
        return new_state(owner, port, controller or "", secret or "", extra)
    return apply_install_fields(old, port, extra, controller, secret)


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
            owner.get("uid"),
        )
    found = choose_port(args.port, bool(args.controller), candidates, default_fetch)
    return found


def _credential_roots(owner_home, share_dirs):
    roots = []
    for name in CREDENTIAL_DIRS:
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


def _chown_installer(path, owner):
    """Root's write is given back to the installing user. Not used for switcher or firewall files."""
    if sys.platform == "win32" or not is_root() or not owner or not owner.get("uid"):
        return
    import pwd
    try:
        gid = pwd.getpwuid(int(owner["uid"])).pw_gid
    except KeyError:
        return
    os.chown(path, int(owner["uid"]), gid)


def _write_settings(paths, wrapper, owner):
    """POSIX only. Records {path, created}. Does not write proxy variables."""
    written = []
    for path in paths:
        directory = os.path.dirname(path)
        if not directory or not _claude_dirname_ok(directory):
            continue
        if os.path.islink(directory):
            raise AgentLockError("refusing a symlinked settings directory: {}".format(directory))
        created_dir = False
        if not os.path.isdir(directory):
            os.makedirs(directory, exist_ok=True)
            created_dir = True
        if os.path.islink(path):
            raise AgentLockError("refusing to follow a symlinked settings file: {}".format(path))
        created = not os.path.isfile(path)
        previous_mode = 0o600
        document = {}
        if os.path.isfile(path):
            st = os.lstat(path)
            previous_mode = stat.S_IMODE(st.st_mode)
            text = _read_text(path) or ""
            try:
                document = json.loads(text) if text.strip() else {}
            except ValueError:
                raise AgentLockError("cannot parse Claude settings: {}".format(path))
        document = merge_claude_settings(document, wrapper)
        atomic_write(path, json.dumps(document, indent=2, sort_keys=True) + "\n", previous_mode)
        _chown_installer(path, owner)
        if created_dir:
            _chown_installer(directory, owner)
        written.append({"path": path, "created": created})
    return written


def _snapshot(paths):
    saved = []
    for path in paths:
        try:
            st = os.lstat(path)
            with open(path, "rb") as handle:
                saved.append((path, handle.read(), stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid))
        except OSError:
            saved.append((path, None, None, None, None))
    return saved


def _restore(saved):
    for item in saved:
        path, data, mode = item[0], item[1], item[2]
        uid = item[3] if len(item) > 3 else None
        gid = item[4] if len(item) > 4 else None
        if data is None:
            if os.path.lexists(path) and not os.path.isdir(path):
                os.remove(path)
            continue
        atomic_write(path, data, mode or 0o644)
        if uid is not None and gid is not None and is_root():
            try:
                os.chown(path, uid, gid)
            except OSError:
                pass


def _stop_claude_daemon(runner):
    if shutil.which("claude") is None:
        sys.stderr.write("warning: claude is not on PATH; skipped daemon stop\n")
        return
    result = runner(["claude", "daemon", "stop", "--any"])
    if getattr(result, "returncode", 1) != 0:
        raise AgentLockError("claude daemon stop failed", 1)


def _share_paths(args, owner):
    paths = []
    for path in args.share_dir or []:
        real = _confine(path, owner["home"], "share")
        if not os.path.isdir(real) or os.path.islink(real):
            raise UsageError("share-dir is not a directory: {}".format(path))
        paths.append(real)
    return paths


def _trust_paths(args, owner):
    paths = []
    for path in args.trust_exec or []:
        real = _confine(path, owner["home"], "trust")
        if os.path.islink(real):
            raise UsageError("refusing a symlink: {}".format(path))
        paths.append(real)
    return paths


def _posix_settings_paths(args, owner):
    paths = []
    home_dir = os.path.join(owner["home"], ".claude")
    if _claude_dirname_ok(home_dir):
        paths.append(os.path.join(home_dir, "settings.json"))
    for path in args.claude_dir or []:
        directory = _confine(path, owner["home"], "claude")
        if not _claude_dirname_ok(directory):
            raise UsageError("claude-dir must be named .claude")
        paths.append(os.path.join(directory, "settings.json"))
    for path in _account_dirs(owner):
        try:
            directory = _confine(path, owner["home"], "claude")
        except UsageError:
            continue
        if _claude_dirname_ok(directory):
            paths.append(os.path.join(directory, "settings.json"))
    return paths


def _refuse_groups(runner, names, flag):
    result = runner(["id", flag, AGENT_USER])
    groups = (getattr(result, "stdout", "") or "").split()
    for name in names:
        if name in groups:
            raise AgentLockError("agentnet is in the {} group".format(name))


def _pf_reload(runner, path, strict):
    sys.stderr.write(PF_DYNAMIC_ANCHOR_WARNING)
    if strict:
        _ok(runner, load_conf_argv(path))
    else:
        runner(load_conf_argv(path))


def _reload_darwin_firewall(runner):
    """pfctl -f the restored main ruleset, then the restored anchor if it is still a file."""
    _pf_reload(runner, PF_CONF, False)
    if os.path.isfile(ANCHOR_PATH) and not os.path.islink(ANCHOR_PATH):
        runner(load_anchor_argv(ANCHOR_PATH))


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
    _refuse_groups(runner, ("sudo", "wheel", "adm"), "-nG")
    port = int(found["port"])
    share = _share_paths(args, owner)
    trust = _trust_paths(args, owner)
    switcher = render_switcher(port, runuser, darwin=False)
    claude = render_claude(port)
    rules = render_nft(uid, port, extra)
    saved = _snapshot([NFT_CONF, UNIT_PATH, SWITCHER_PATH, CLAUDE_WRAPPER_PATH, SUDOERS_PATH])
    fd, tmp = __import__("tempfile").mkstemp(prefix="agent-lock-nft.")
    os.close(fd)
    try:
        atomic_write(tmp, rules, 0o644)
        _ok(runner, nft_check_argv(nft, tmp), unsupported=True)
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
    spec = "u:{}:r-x,m::r-x".format(AGENT_USER)
    for path in trust:
        if os.path.islink(path):
            raise UsageError("refusing a symlink: {}".format(path))
        _ok(runner, ["setfacl", "-h", "-m", spec, path])
    setting_paths = _posix_settings_paths(args, owner)
    settings_saved = _snapshot(setting_paths)
    old = load_state()
    try:
        _stop_claude_daemon(runner)
    except AgentLockError:
        _restore(saved)
        if old and old.get("port"):
            _ok(runner, nft_load_argv(nft, NFT_CONF))
        else:
            runner([nft, "delete", "table", "inet", "agentlock"])
        raise
    settings = _write_settings(setting_paths, CLAUDE_WRAPPER_PATH, owner)
    if not _proxy_check(runner, [runuser, "--preserve-environment", "-u", AGENT_USER, "--", SWITCHER_PATH], proxy_url(port)):
        _restore(saved + settings_saved)
        if old and old.get("port"):
            _ok(runner, nft_load_argv(nft, NFT_CONF))
        else:
            runner([nft, "delete", "table", "inet", "agentlock"])
        raise AgentLockError("proxy check failed; kept the previous port")
    data = _state_after_install(old, owner, port, extra, found)
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
    save_state(data, owner=owner)
    for line in found.get("logs") or []:
        stdout.write(line + "\n")
    stdout.write("installed agent-lock on port {}\n".format(port))
    return 0


def _darwin_apply(args, owner, found, extra, runner, stdout):
    if not shutil.which("pfctl"):
        raise Unsupported("pfctl was not found")
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
        for command in darwin_user_plan():
            _ok(runner, command, input_text=secret_pw + "\n" if command[0] == "sysadminctl" else None)
        secret_pw = ""
    _refuse_groups(runner, ("admin",), "-Gn")
    share = _share_paths(args, owner)
    trust = _trust_paths(args, owner)
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
            _ok(runner, check_conf_argv(tmp), unsupported=True)
            atomic_write(PF_CONF, patched, 0o644)
            _pf_reload(runner, PF_CONF, True)
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
    for command in acl_commands(directories, owner["home"]):
        if command[1] == "-a":
            runner(command)
        else:
            _ok(runner, command)
    setting_paths = _posix_settings_paths(args, owner)
    settings_saved = _snapshot(setting_paths)
    try:
        _stop_claude_daemon(runner)
    except AgentLockError:
        _restore(saved)
        _reload_darwin_firewall(runner)
        raise
    settings = _write_settings(setting_paths, CLAUDE_WRAPPER_PATH, owner)
    if not _proxy_check(
            runner, ["/usr/bin/sudo", "--preserve-env", "-u", AGENT_USER, "--", SWITCHER_PATH], proxy_url(port)):
        _restore(saved + settings_saved)
        if already:
            runner(load_anchor_argv(ANCHOR_PATH))
        else:
            _reload_darwin_firewall(runner)
        raise AgentLockError("proxy check failed; kept the previous port")
    old = load_state()
    data = _state_after_install(old, owner, port, extra, found)
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
    data["exec_paths"] = trust
    data["claude_settings"] = settings
    data["pf_enable_token"] = token
    save_state(data, owner=owner)
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
    admin = runner(["powershell", "-NoProfile", "-Command", windows_admin_script()])
    if (getattr(admin, "stdout", "") or "").strip().lower() == "yes":
        raise AgentLockError("agentnet is in the Administrators group")
    sid_result = _ok(runner, ["powershell", "-NoProfile", "-Command",
                              "(Get-LocalUser -Name '{}').Sid.Value".format(AGENT_USER)])
    sid = (sid_result.stdout or "").strip()
    if not sid.startswith("S-"):
        raise AgentLockError("could not read the agentnet SID")
    old = load_state()
    rules = build_rules(port, extra, sid)
    new_names = rule_names(rules)
    create_names, remove_names = rule_phases((old or {}).get("windows_rules"), new_names)
    by_name = {rule["name"]: rule for rule in rules}
    for name in create_names:
        _ok(runner, ["powershell", "-NoProfile", "-Command", render_rule_script([by_name[name]]).strip()])
    for command in uninstall_commands(remove_names):
        runner(["powershell", "-NoProfile", "-Command", " ".join(command)])
    home = owner.get("home") or ""
    share = _share_paths(args, owner)
    trust = _trust_paths(args, owner)
    links = []
    agent_home = os.path.join(os.environ.get("SystemDrive", "C:") + "\\", "Users", AGENT_USER)
    for name in CREDENTIAL_DIRS:
        target = os.path.join(home, name)
        if os.path.islink(target):
            continue
        if os.path.isdir(target):
            links.append((os.path.join(agent_home, name), target))
    _ok(runner, ["powershell", "-NoProfile", "-Command", create_profile_script(sid)])
    for command in link_plan(links):
        _ok(runner, command)
    cmd_saved = _snapshot([WINDOWS_CMD])
    atomic_write(WINDOWS_CMD, render_windows_cmd(port, sid), 0o644)
    for command in share_icacls([target for _link, target in links]):
        runner(command)
    for command in icacls_commands(home, trust, os.path.isdir):
        runner(command)
    if not _proxy_check(runner, [], proxy_url(port)):
        _restore(cmd_saved)
        for command in uninstall_commands(create_names):
            runner(["powershell", "-NoProfile", "-Command", " ".join(command)])
        if old and old.get("port") and remove_names:
            previous = build_rules(old["port"], old.get("extra_tcp") or [], sid)
            restore_names = set(remove_names)
            for rule in previous:
                if rule["name"] in restore_names:
                    runner(["powershell", "-NoProfile", "-Command", render_rule_script([rule]).strip()])
        raise AgentLockError("proxy check failed; kept the previous port")
    data = _state_after_install(old, owner, port, extra, found)
    data["agent_sid"] = sid
    data["agent_home"] = agent_home
    data["wrapper"] = WINDOWS_CMD
    data["claude_wrapper"] = ""
    data["claude_settings"] = []
    data["windows_rules"] = rule_names(rules)
    data["links"] = [link for link, _target in links]
    data["share_dirs"] = share
    data["exec_paths"] = trust
    data["created_user"] = bool(action == "create" or (old or {}).get("created_user"))
    data["runuser_path"] = ""
    save_state(data, owner=owner)
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
    extra = list(args.allow_tcp or [])
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


def _is_junction(path):
    """Windows reparse directory. A real directory is not a junction."""
    if os.path.islink(path) or not os.path.isdir(path):
        return False
    if sys.platform != "win32":
        return False
    import ctypes
    attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))
    if attrs in (-1, 0xFFFFFFFF):
        return False
    return bool(int(attrs) & 0x400)


def agent_uid_busy(text, agent_uid):
    """True when a process uid matches agentnet. uid 0 is never treated as agentnet."""
    try:
        agent_uid = int(agent_uid)
    except (TypeError, ValueError):
        return False
    if agent_uid <= 0:
        return False
    for line in (text or "").splitlines():
        token = line.strip()
        if token.isdigit() and int(token) == agent_uid:
            return True
    return False


def _refuse_if_agent_busy(state, runner):
    if sys.platform == "win32":
        sid = state.get("agent_sid") or ""
        if not sid or any(ch not in "S-0123456789" for ch in sid) or not sid.startswith("S-1-"):
            return
        script = (
            "Get-CimInstance Win32_Process | ForEach-Object { "
            "$out = Invoke-CimMethod -InputObject $_ -MethodName GetOwnerSid; "
            "if ($out.Sid -eq '" + sid + "') { 'busy' } }"
        )
        result = runner(["powershell", "-NoProfile", "-Command", script])
        if result and "busy" in (getattr(result, "stdout", "") or "").lower():
            raise AgentLockError("agentnet processes are still running", 1)
        return
    result = runner(["ps", "-ax", "-o", "uid="])
    if agent_uid_busy(getattr(result, "stdout", "") if result else "", state.get("agent_uid")):
        raise AgentLockError("agentnet processes are still running", 1)


def _unlink_recorded(path):
    """Remove a symlink or a junction. A real directory is left untouched."""
    if not path or not os.path.lexists(path):
        return
    if os.path.islink(path):
        os.unlink(path)
        return
    if _is_junction(path):
        os.rmdir(path)
        return
    raise AgentLockError("recorded link is not a symlink or junction; left it in place: {}".format(path))


def _strip_settings(entries, state=None):
    owner_uid = (state or {}).get("owner_uid")
    owner_gid = None
    if owner_uid and is_root():
        import pwd
        try:
            owner_gid = pwd.getpwuid(int(owner_uid)).pw_gid
            owner_uid = int(owner_uid)
        except (KeyError, TypeError, ValueError):
            owner_uid = None
            owner_gid = None
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        path = entry.get("path")
        if not path or os.path.islink(path) or not os.path.isfile(path):
            continue
        st = os.lstat(path)
        mode = stat.S_IMODE(st.st_mode)
        uid, gid = st.st_uid, st.st_gid
        text = _read_text(path) or ""
        try:
            document = json.loads(text) if text.strip() else {}
        except ValueError:
            continue
        document, empty = strip_claude_settings(document)
        if entry.get("created") and empty:
            os.remove(path)
            continue
        atomic_write(path, json.dumps(document, indent=2, sort_keys=True) + "\n", mode)
        if is_root():
            target_uid = owner_uid if owner_uid else uid
            target_gid = owner_gid if owner_gid is not None else gid
            try:
                os.chown(path, target_uid, target_gid)
            except OSError:
                pass


def cmd_uninstall(args, stdout=None, stderr=None, runner=None):
    stdout = stdout or sys.stdout
    runner = runner or _runner
    state = load_state()
    if not state:
        raise NotInstalled()
    _refuse_if_agent_busy(state, runner)
    for path in state.get("links") or []:
        _unlink_recorded(path)
    if sys.platform.startswith("linux"):
        runner(["systemctl", "disable", "--now", UNIT_NAME])
        nft = find_nft() or "nft"
        runner([nft, "delete", "table", "inet", "agentlock"])
        for path in (UNIT_PATH, NFT_CONF, SUDOERS_PATH, SWITCHER_PATH, CLAUDE_WRAPPER_PATH):
            if os.path.lexists(path) and not os.path.isdir(path):
                os.remove(path)
        runner(["systemctl", "daemon-reload"])
    elif sys.platform == "darwin":
        current = _read_text(PF_CONF)
        if current is not None:
            atomic_write(PF_CONF, unpatch_pf_conf(current), 0o644)
        if os.path.lexists(ANCHOR_PATH) and not os.path.islink(ANCHOR_PATH):
            os.remove(ANCHOR_PATH)
        runner(check_conf_argv(PF_CONF))
        _pf_reload(runner, PF_CONF, False)
        release = release_token_argv(state.get("pf_enable_token") or "")
        if release:
            runner(release)
        for path in (SWITCHER_PATH, CLAUDE_WRAPPER_PATH):
            if os.path.lexists(path) and not os.path.isdir(path):
                os.remove(path)
    elif sys.platform == "win32":
        for command in uninstall_commands(state.get("windows_rules") or []):
            runner(["powershell", "-NoProfile", "-Command", " ".join(command)])
        if os.path.isfile(WINDOWS_CMD):
            os.remove(WINDOWS_CMD)
    if sys.platform != "win32":
        _strip_settings(state.get("claude_settings"), state)
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


def open_directory_nofollow(path):
    """Open a directory fd that fails when the path is a symlink."""
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    elif os.path.islink(path):
        raise OSError("refusing a symlink")
    return os.open(path, flags)


def prepare_bind_dir(path, euid, owner_uid, gid):
    """fchown and fchmod the directory fd. A replaced symlink never receives the mode."""
    if euid != 0:
        raise AgentLockError("agent-lock: bind-bin needs root; run it with sudo", 1)
    try:
        fd = open_directory_nofollow(path)
    except OSError:
        raise UsageError("agent-lock: bind-bin refuses a symlink or a non-directory")
    try:
        st = os.fstat(fd)
        code, message = validate_bind_bin(
            euid, False, stat.S_ISDIR(st.st_mode), st.st_uid, owner_uid)
        if code == 2:
            raise UsageError(message)
        if code:
            raise AgentLockError(message, code)
        os.fchown(fd, -1, gid)
        os.fchmod(fd, bind_bin_mode(stat.S_IMODE(st.st_mode)))
    finally:
        os.close(fd)


def cmd_bind_bin(args):
    if sys.platform == "darwin":
        raise Unsupported("bind-bin is not used on macOS")
    if sys.platform == "win32":
        raise Unsupported("bind-bin is not used on Windows")
    euid = os.geteuid() if hasattr(os, "geteuid") else 0
    if euid != 0:
        raise AgentLockError("agent-lock: bind-bin needs root; run it with sudo", 1)
    owner = resolve_owner()
    if owner is None:
        raise AgentLockError("cannot resolve the installing user", 1)
    state = load_state()
    if not state:
        raise NotInstalled()
    import grp
    gid = grp.getgrnam(AGENT_USER).gr_gid
    prepare_bind_dir(args.path, euid, owner["uid"], gid)
    absolute = os.path.abspath(args.path)
    dirs = list(state.get("bin_dirs") or [])
    if absolute not in dirs:
        dirs.append(absolute)
    state["bin_dirs"] = dirs
    state["agent_gid"] = gid
    save_state(state)
    return 0


def cmd_doctor(args, stdout=None, stderr=None):
    return doctor.run_doctor(args, stdout=stdout, stderr=stderr)


