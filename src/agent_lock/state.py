"""Owner state.json. Mode 0600. Never log the controller secret stored here."""

import json
import os
import sys
import tempfile

from .errors import AgentLockError

AGENT_USER = "agentnet"
SWITCHER_PATH = "/usr/local/sbin/agent-lock"
CLAUDE_WRAPPER_PATH = "/usr/local/sbin/agent-lock-claude"
SUDOERS_PATH = "/etc/sudoers.d/agent-lock"
LINUX_AGENT_HOME = "/var/lib/agentnet"
DARWIN_AGENT_HOME = "/Users/agentnet"
WINDOWS_DIR = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "agent-lock")
WINDOWS_CMD = os.path.join(WINDOWS_DIR, "agent-lock.cmd")
CREDENTIAL_DIRS = (".codex", ".cx", ".claude", ".cc")

STATE_DEFAULTS = {
    "version": 1,
    "owner": "",
    "owner_uid": 0,
    "owner_home": "",
    "agent_user": AGENT_USER,
    "agent_uid": 0,
    "agent_gid": 0,
    "agent_sid": "",
    "agent_home": "",
    "port": 0,
    "proxy": "",
    "controller": "",
    "secret": "",
    "wrapper": SWITCHER_PATH,
    "claude_wrapper": CLAUDE_WRAPPER_PATH,
    "runuser_path": "",
    "extra_tcp": [],
    "claude_settings": [],
    "links": [],
    "share_dirs": [],
    "bin_dirs": [],
    "exec_paths": [],
    "windows_rules": [],
    "pf_enable_token": "",
    "created_user": False,
}


def proxy_url(port):
    return "http://127.0.0.1:{}".format(int(port))


def is_root():
    if sys.platform == "win32":
        return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _within(path, root):
    path = os.path.abspath(path)
    root = os.path.abspath(root)
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def resolve_owner():
    """The installing user. Root uses SUDO_USER, never root's home."""
    if sys.platform == "win32":
        name = os.environ.get("USERNAME") or ""
        home = os.environ.get("USERPROFILE") or ""
        if not name or not home:
            return None
        return {"name": name, "uid": 0, "home": home, "sudo": False}
    import pwd
    if is_root():
        sudo_user = os.environ.get("SUDO_USER") or ""
        if not sudo_user or sudo_user == "root":
            return None
        try:
            pw = pwd.getpwnam(sudo_user)
        except KeyError:
            return None
        return {"name": pw.pw_name, "uid": pw.pw_uid, "home": pw.pw_dir, "sudo": True}
    pw = pwd.getpwuid(os.geteuid())
    return {"name": pw.pw_name, "uid": pw.pw_uid, "home": pw.pw_dir, "sudo": False}


def config_base(owner):
    """XDG config directory of the owner. Root does not fall back to /root."""
    if owner is None:
        return None
    xdg = os.environ.get("XDG_CONFIG_HOME") or ""
    home = owner["home"]
    if owner.get("sudo"):
        if xdg and _within(xdg, home):
            return xdg
        return os.path.join(home, ".config")
    if xdg:
        return xdg
    return os.path.join(home, ".config")


def state_path(owner=None):
    if sys.platform == "win32":
        return os.path.join(WINDOWS_DIR, "state.json")
    if owner is None:
        owner = resolve_owner()
    base = config_base(owner)
    if not base:
        return None
    return os.path.join(base, "agent-lock", "state.json")


def atomic_write(path, text, mode=0o600):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory or None, prefix=".agent-lock-")
    try:
        data = text.encode("utf-8") if not isinstance(text, bytes) else text
        os.write(fd, data)
        os.close(fd)
        fd = None
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except Exception:
        if fd is not None:
            os.close(fd)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def new_state(owner, port, controller, secret, extra_tcp):
    data = dict(STATE_DEFAULTS)
    data["owner"] = owner["name"]
    data["owner_uid"] = owner["uid"]
    data["owner_home"] = owner["home"]
    data["port"] = int(port)
    data["proxy"] = proxy_url(port)
    data["controller"] = controller or ""
    data["secret"] = secret or ""
    data["extra_tcp"] = list(extra_tcp)
    data["claude_settings"] = []
    data["links"] = []
    data["share_dirs"] = []
    data["bin_dirs"] = []
    data["exec_paths"] = []
    data["windows_rules"] = []
    return data


def apply_install_fields(old, port, extra_tcp, controller, secret):
    """Port and extra_tcp come from this install. Omitted --allow-tcp clears the list."""
    data = dict(STATE_DEFAULTS)
    if old:
        data.update(old)
    data["version"] = 1
    data["port"] = int(port)
    data["proxy"] = proxy_url(port)
    data["extra_tcp"] = list(extra_tcp)
    if controller is not None:
        data["controller"] = controller
    if secret is not None:
        data["secret"] = secret
    return data


def load_state(path=None):
    if path is None:
        path = state_path()
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        raise AgentLockError("cannot read state: {}".format(exc))
    if not isinstance(data, dict) or data.get("version") != 1:
        raise AgentLockError("state file is not version 1")
    merged = dict(STATE_DEFAULTS)
    merged.update(data)
    if not isinstance(merged.get("extra_tcp"), list):
        merged["extra_tcp"] = []
    if not isinstance(merged.get("claude_settings"), list):
        merged["claude_settings"] = []
    return merged


def save_state(data, path=None, owner=None):
    if path is None:
        path = state_path()
    if not path:
        raise AgentLockError("no state directory for the installing user; refusing to write as root")
    payload = json.dumps(data, indent=2, sort_keys=True) + "\n"
    atomic_write(path, payload, 0o600)
    _own_state_file(path, data, owner)
    return path


def _own_state_file(path, data, owner):
    """POSIX: chown back to the installing user. Windows: explicit ACL, not chmod."""
    if sys.platform == "win32":
        name = ""
        if owner:
            name = owner.get("name") or ""
        if not name:
            name = data.get("owner") or ""
        if name:
            from .windows import apply_state_acl
            apply_state_acl(path, name)
        return
    if not is_root():
        return
    uid = owner.get("uid") if owner else None
    if not uid:
        uid = data.get("owner_uid")
    if not uid:
        return
    import pwd
    try:
        gid = pwd.getpwuid(int(uid)).pw_gid
    except KeyError:
        return
    os.chown(path, int(uid), gid)
    directory = os.path.dirname(path)
    if directory:
        try:
            os.chown(directory, int(uid), gid)
        except OSError:
            pass


def secret_label(secret):
    return "secret set" if secret else "secret not set"


def merge_claude_settings(document, wrapper_path):
    """Add env.CLAUDE_CODE_PROCESS_WRAPPER. Do not write proxy variables."""
    if not isinstance(document, dict):
        document = {}
    else:
        document = dict(document)
    env = document.get("env")
    if not isinstance(env, dict):
        env = {}
    else:
        env = dict(env)
    env["CLAUDE_CODE_PROCESS_WRAPPER"] = wrapper_path
    document["env"] = env
    return document


def strip_claude_settings(document):
    """Remove only the wrapper key. Return (document, empty)."""
    if not isinstance(document, dict):
        return {}, True
    document = dict(document)
    env = document.get("env")
    if isinstance(env, dict):
        env = dict(env)
        env.pop("CLAUDE_CODE_PROCESS_WRAPPER", None)
        if env:
            document["env"] = env
        else:
            document.pop("env", None)
    empty = document == {}
    return document, empty



