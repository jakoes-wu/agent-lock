"""Review fixes. Fakes only: no nft, pf, useradd, or Windows firewall."""

import io
import os
import stat
import sys
import tempfile
import unittest

import support

from agent_lock import doctor, install, state
from agent_lock.darwin import anchor_observed, pf_conf_problem, render_anchor
from agent_lock.discover import Candidate, choose_port, collect_candidates
from agent_lock.doctor import (
    classify_daemon,
    classify_login,
    evaluate,
    exec_access_problem,
    identity_commands,
    identity_from_results,
    switcher_mode_problem,
    wrapper_problems,
)
from agent_lock.errors import AgentLockError, Unsupported, UsageError
from agent_lock.install import (
    _confine,
    _gather,
    _posix_settings_paths,
    _state_after_install,
    _strip_settings,
    _unlink_recorded,
    _write_settings,
    agent_uid_busy,
    cmd_uninstall,
    open_directory_nofollow,
    prepare_bind_dir,
)
from agent_lock.linux import nft_observed, parent_dirs, setfacl_commands
from agent_lock.state import save_state
from agent_lock.windows import (
    apply_state_acl,
    build_rules,
    default_outbound_problem,
    icacls_commands,
    parse_locked_batch,
    require_supported,
    rule_names,
    rule_phases,
    state_acl_commands,
    windows_firewall_report,
    windows_locked_command,
    windows_observed,
    windows_path_executable,
    windows_rule_script,
    windows_user_script,
)
from agent_lock.wrapper import render_claude, render_sudoers, render_switcher
from test_doctor_parse import _report

support.install = None


class Result(object):
    def __init__(self, code, out="", err=""):
        self.returncode = code
        self.stdout = out
        self.stderr = err


class Patches(object):
    def __init__(self):
        self._saved = []

    def set(self, obj, name, value):
        self._saved.append((obj, name, getattr(obj, name)))
        setattr(obj, name, value)

    def restore(self):
        while self._saved:
            obj, name, value = self._saved.pop()
            setattr(obj, name, value)


def _args(**kwargs):
    class Args(object):
        pass

    args = Args()
    args.controller = None
    args.port = None
    args.secret_stdin = False
    args.share_dir = []
    args.trust_exec = []
    args.claude_dir = []
    args.allow_tcp = None
    args.path = ""
    for key, value in kwargs.items():
        setattr(args, key, value)
    return args


def _owner(home):
    return {"name": "alice", "uid": os.getuid(), "home": home, "sudo": False}


class DiscoverySecurityTest(unittest.TestCase):
    def test_scanned_tcp_does_not_receive_another_users_secret(self):
        root = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        config = os.path.join(root, "config.yaml")
        with open(config, "w", encoding="utf-8") as handle:
            handle.write("secret: FROMFILE\nexternal-controller: 127.0.0.1:9090\n")
        argv = ["clash", "-ext-ctl", "127.0.0.1:1", "-f", config, "-secret", "LEAK",
                "-ext-ctl-unix", os.path.join(root, "c.sock")]
        seen = []

        def read_text(path):
            seen.append(path)
            with open(path, "r", encoding="utf-8") as handle:
                return handle.read()

        hidden = collect_candidates([argv], read_text, root, None, [config], os.getuid() + 1)
        self.assertEqual(seen, [])
        self.assertFalse(any(item.kind == "tcp" for item in hidden))
        self.assertFalse(any(item.secret for item in hidden))
        owned = collect_candidates([argv], read_text, root, None, [], os.getuid())
        tcp = [item for item in owned if item.kind == "tcp"]
        self.assertEqual(len(tcp), 1)
        self.assertEqual(tcp[0].address, "http://127.0.0.1:9090")
        self.assertEqual(tcp[0].secret, "FROMFILE")
        self.assertNotIn("LEAK", tcp[0].secret)
        self.assertNotIn(":1", tcp[0].address.split("9090")[-1])

    def test_port_fallback_does_not_clear_a_stored_secret(self):
        def down(_address, _secret):
            return 401, "{}"

        found = choose_port(7897, False, [Candidate("http://127.0.0.1:9090", "LEAK", "scan", "tcp")], down)
        self.assertEqual(found["source"], "--port")
        owner = _owner(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(owner["home"], ignore_errors=True))
        old = {"version": 1, "port": 1, "secret": "keep", "controller": "http://127.0.0.1:9", "extra_tcp": []}
        leaky = dict(found)
        leaky["secret"] = "LEAK"
        leaky["controller"] = "http://127.0.0.1:1"
        updated = _state_after_install(old, owner, 7897, [], leaky)
        self.assertEqual(updated["secret"], "keep")
        self.assertEqual(updated["controller"], "http://127.0.0.1:9")
        cleared = _state_after_install(old, owner, 7897, [], {
            "source": "file", "port": 7897, "controller": "http://127.0.0.1:9090", "secret": "",
        })
        self.assertEqual(cleared["secret"], "")
        missing = _state_after_install(old, owner, 7897, [], {"source": "file", "port": 7897})
        self.assertEqual(missing["secret"], "")
        self.assertEqual(missing["controller"], "")

    def test_gather_does_not_stamp_stdin_secret_on_scanned_tcp(self):
        sent = []
        patches = Patches()
        stdin = sys.stdin
        try:
            sys.stdin = io.StringIO("STDINSECRET\n")
            patches.set(install, "default_fetch", lambda address, secret: sent.append((address, secret)) or (200, "{}"))
            patches.set(install, "_process_argvs", lambda _runner: [
                ["sleep", "-ext-ctl", "127.0.0.1:9", "-f", os.path.join(tempfile.gettempdir(), "nope.yaml")],
            ])
            home = tempfile.mkdtemp()
            self.addCleanup(lambda: __import__("shutil").rmtree(home, ignore_errors=True))
            found = _gather(_args(port=7897, secret_stdin=True), _owner(home), lambda *_a, **_k: Result(0))
        finally:
            sys.stdin = stdin
            patches.restore()
        self.assertEqual(found["source"], "--port")
        self.assertFalse(any(secret == "STDINSECRET" for _address, secret in sent))
        self.assertFalse(any(address.startswith("http://") for address, _secret in sent))
        kept = _state_after_install(
            {"version": 1, "port": 1, "secret": "keep", "controller": "http://127.0.0.1:9", "extra_tcp": []},
            _owner(home), found["port"], [], found)
        self.assertEqual(kept["secret"], "keep")
        self.assertEqual(kept["controller"], "http://127.0.0.1:9")


class OwnershipAndAclTest(unittest.TestCase):
    def test_state_acl_is_explicit_and_save_chowns_on_posix(self):
        command = state_acl_commands("state.json", "alice")
        blob = " ".join(command)
        self.assertIn("*S-1-5-18:(F)", command)
        self.assertIn("*S-1-5-32-544:(F)", command)
        self.assertIn("alice:(R)", command)
        self.assertNotIn("Users", blob)
        self.assertNotIn("agentnet", blob)
        root = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        path = os.path.join(root, "state.json")
        calls = []
        patches = Patches()
        try:
            patches.set(state.os, "geteuid", lambda: 0)
            patches.set(state.os, "chown", lambda target, uid, gid: calls.append((target, uid, gid)))
            save_state({"version": 1, "owner": "alice", "owner_uid": os.getuid()}, path=path,
                       owner={"name": "alice", "uid": os.getuid()})
        finally:
            patches.restore()
        self.assertIn((path, os.getuid(), os.getgid() if False else calls[0][2]), [(path, os.getuid(), calls[0][2])])
        self.assertTrue(all(item[0] == path or item[0] == root for item in calls))
        self.assertNotIn("switcher", " ".join(item[0] for item in calls))

    def test_settings_keep_mode_and_only_new_directories_are_chowned(self):
        root = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        existing = os.path.join(root, ".claude")
        os.mkdir(existing)
        settings = os.path.join(existing, "settings.json")
        with open(settings, "w", encoding="utf-8") as handle:
            handle.write("{}\n")
        os.chmod(settings, 0o640)
        created = os.path.join(root, "work.claude")
        created_file = os.path.join(created, "settings.json")
        calls = []
        patches = Patches()
        owner = _owner(root)
        try:
            patches.set(install.os, "geteuid", lambda: 0)
            patches.set(state.os, "geteuid", lambda: 0)
            patches.set(install.os, "chown", lambda target, uid, gid: calls.append(target))
            written = _write_settings([settings, created_file], "wrapper", owner)
        finally:
            patches.restore()
        self.assertEqual(stat.S_IMODE(os.stat(settings).st_mode), 0o640)
        self.assertEqual(stat.S_IMODE(os.stat(created_file).st_mode), 0o600)
        self.assertIn(created, calls)
        self.assertNotIn(existing, calls)
        self.assertEqual(len(written), 2)
        link_dir = os.path.join(root, "link.claude")
        os.mkdir(link_dir)
        link = os.path.join(link_dir, "settings.json")
        os.symlink(settings, link)
        with self.assertRaises(AgentLockError):
            _write_settings([link], "wrapper", owner)

    def test_confine_rejects_escape_symlink_home_and_tcc(self):
        root = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        owner = _owner(root)
        with self.assertRaises(UsageError):
            _confine(root, root, "share")
        with self.assertRaises(UsageError):
            _confine(os.path.join(root, "..", ".."), root, "trust")
        target = os.path.join(root, "real")
        os.mkdir(target)
        link = os.path.join(root, "link")
        os.symlink(target, link)
        with self.assertRaises(UsageError):
            _confine(link, root, "share")
        desk = os.path.join(root, "Desktop", "proj")
        os.makedirs(desk)
        with self.assertRaises(UsageError):
            _confine(desk, root, "share")
        kept = _confine(target, root, "share")
        self.assertTrue(kept.startswith(os.path.realpath(root)))
        outside = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(outside, ignore_errors=True))
        inside = os.path.join(root, "work.claude")
        os.mkdir(inside)
        patches = Patches()
        try:
            patches.set(install, "_account_dirs", lambda _owner_arg: [outside, inside])
            paths = _posix_settings_paths(_args(), owner)
        finally:
            patches.restore()
        real_inside = os.path.realpath(inside)
        real_outside = os.path.realpath(outside)
        self.assertTrue(any(path.startswith(real_inside + os.sep) for path in paths))
        self.assertFalse(any(
            path == real_outside or path.startswith(real_outside + os.sep) for path in paths))
        with self.assertRaises(UsageError):
            _posix_settings_paths(_args(claude_dir=[os.path.join(root, "notes")]), owner)


class BindAndAclPathTest(unittest.TestCase):
    def test_bind_dir_uses_nofollow_fd(self):
        root = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        target = os.path.join(root, "bin")
        os.mkdir(target)
        before = os.stat(target).st_mode
        link = os.path.join(root, "link")
        os.symlink(target, link)
        with self.assertRaises(OSError):
            open_directory_nofollow(link)
        self.assertEqual(os.stat(target).st_mode, before)
        with self.assertRaises(UsageError):
            prepare_bind_dir(link, 0, os.stat(target).st_uid, 9)
        self.assertEqual(os.stat(target).st_mode, before)
        with self.assertRaises(AgentLockError):
            prepare_bind_dir(target, os.geteuid(), os.stat(target).st_uid, 9)
        calls = []
        patches = Patches()
        try:
            patches.set(install.os, "fchown", lambda fd, uid, gid: calls.append(("fchown", fd, uid, gid)))
            patches.set(install.os, "fchmod", lambda fd, mode: calls.append(("fchmod", fd, mode)))
            patches.set(install.os, "chmod", lambda path, mode: calls.append(("chmod", path, mode)))
            prepare_bind_dir(target, 0, os.stat(target).st_uid, 9)
        finally:
            patches.restore()
        self.assertEqual(calls[0][0], "fchown")
        self.assertIsInstance(calls[0][1], int)
        self.assertEqual(calls[0][2:], (-1, 9))
        self.assertEqual(calls[1][0], "fchmod")
        self.assertFalse(any(item[0] == "chmod" for item in calls))

    def test_file_trust_does_not_inherit_rx_and_setfacl_is_physical(self):
        root = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        folder = os.path.join(root, "bin")
        os.mkdir(folder)
        target = os.path.join(folder, "tool")
        with open(target, "w", encoding="utf-8") as handle:
            handle.write("x")
        commands = icacls_commands(root, [target], os.path.isdir)
        blob = "\n".join(" ".join(command) for command in commands)
        self.assertNotIn("(OI)(CI)(RX)", blob)
        file_grant = [command for command in commands if command[1] == target][0]
        self.assertIn("(RX)", file_grant[-1])
        self.assertNotIn("(OI)(CI)", file_grant[-1])
        parent = [command for command in commands if command[1] == folder][0]
        self.assertTrue(parent[-1].endswith("(X)"))
        link = os.path.join(root, "tool-link")
        os.symlink(target, link)
        with self.assertRaises(UsageError):
            icacls_commands(root, [link], os.path.isdir)
        facl = setfacl_commands([(folder, "dir"), (target, "file"), (root, "parent")])
        self.assertTrue(all(command[1] == "-h" for command in facl))
        blob = "\n".join(" ".join(command) for command in facl)
        self.assertNotIn(" -d", " " + blob)

    def test_switcher_quotes_runuser_and_rejects_bad_owner_names(self):
        text = render_switcher(7897, "/usr/sbin/runuser", darwin=False)
        self.assertIn("exec /usr/sbin/runuser --preserve-environment -u agentnet -- ", text)
        with self.assertRaises(Unsupported):
            render_switcher(7897, "/tmp/evil;id", darwin=False)
        with self.assertRaises(Unsupported):
            render_switcher(7897, "", darwin=False)
        self.assertNotIn("unset", render_claude(7897))
        self.assertIn("alice ALL=(root) NOPASSWD:SETENV:", render_sudoers("alice"))
        with self.assertRaises(UsageError):
            render_sudoers("alice\nALL")


class FirewallObservationTest(unittest.TestCase):
    def test_live_rules_not_a_copy_of_state(self):
        checks, code = evaluate(_report(extra_tcp_observed=None, firewall_ok=True))
        self.assertEqual(code, 1)
        firewall = [item for item in checks if item["name"] == "firewall"][0]
        self.assertFalse(firewall["ok"])
        checks, _code = evaluate(_report(extra_tcp_observed=["127.0.0.1:9"]))
        firewall = [item for item in checks if item["name"] == "firewall"][0]
        self.assertFalse(firewall["ok"])
        data = {"nftables": [
            {"rule": {"expr": [
                {"match": {"left": {"payload": {"field": "daddr"}}, "right": "127.0.0.1"}},
                {"match": {"left": {"payload": {"field": "dport"}}, "right": 7897}},
                {"accept": None},
            ]}},
            {"rule": {"expr": [
                {"match": {"left": {"payload": {"field": "daddr"}}, "right": "::1"}},
                {"match": {"left": {"payload": {"field": "dport"}}, "right": 7897}},
                {"accept": None},
            ]}},
            {"rule": {"expr": [{"drop": None}]}},
            {"rule": {"expr": [
                {"match": {"left": {"payload": {"field": "daddr"}}, "right": "127.0.0.1"}},
                {"match": {"left": {"payload": {"field": "dport"}}, "right": 9}},
                {"accept": None},
            ]}},
        ]}
        ok, extras = nft_observed(data, 7897)
        self.assertTrue(ok)
        self.assertEqual(extras, ["127.0.0.1:9"])
        ok, extras = anchor_observed(render_anchor(7897, []), 7897)
        self.assertTrue(ok)
        self.assertEqual(extras, [])
        ok, extras = anchor_observed(render_anchor(7897, ["::1:9"]), 7897)
        self.assertEqual(extras, ["::1:9"])
        good = 'anchor "com.apple/*"\n'
        from agent_lock.darwin import patch_pf_conf
        self.assertIsNone(pf_conf_problem(patch_pf_conf("")))
        self.assertIsNone(pf_conf_problem(patch_pf_conf(good)))
        late = "# agent-lock begin\nanchor \"agentlock\"\n# agent-lock end\n"
        self.assertIsNotNone(pf_conf_problem(good + late))
        quick = "pass quick all\n" + patch_pf_conf("")
        self.assertIsNotNone(pf_conf_problem(quick))

    def test_windows_rules_and_doctor_query(self):
        old = rule_names(build_rules(7897, [], "S-1-5-21-1"))
        new = rule_names(build_rules(8000, [], "S-1-5-21-1"))
        create, remove = rule_phases(old, new)
        self.assertIn("agent-lock-v4-below-loopback", old)
        self.assertNotIn("agent-lock-v4-below-loopback", create)
        self.assertNotIn("agent-lock-v4-below-loopback", remove)
        self.assertTrue(any("lo-tcp-8000" in name for name in create))
        self.assertTrue(any("lo-tcp-7897" in name for name in remove))
        ok, extras = windows_observed(build_rules(7897, [], "S-1-5-21-1"), 7897)
        self.assertTrue(ok)
        self.assertEqual(extras, [])
        ok, extras = windows_observed(build_rules(7897, ["127.0.0.1:9"], "S-1-5-21-1"), 7897)
        self.assertIn("127.0.0.1:9", extras)
        self.assertNotIn("::1:9", extras)
        profiles = [{"name": "Private", "AllowLocalFirewallRules": False, "DefaultOutboundAction": "Block"}]
        gpo, outbound, firewall_ok, _extras = windows_firewall_report(profiles, build_rules(7897, [], "S-1-5-21-1"), 7897)
        self.assertTrue(gpo)
        self.assertTrue(outbound)
        self.assertFalse(firewall_ok)
        calls = []

        def fake_run(argv, timeout=20):
            calls.append(list(argv))
            return None

        patches = Patches()
        try:
            patches.set(doctor, "_which", lambda name: "/usr/sbin/nft" if name == "nft" else None)
            patches.set(doctor, "_run", fake_run)
            doctor._linux_drop_packets()
            doctor._pf_block_count()
        finally:
            patches.restore()
        self.assertEqual(calls[0][0], "sudo")
        self.assertIn("nft", calls[0][1])
        self.assertEqual(calls[1][:4], ["sudo", "pfctl", "-a", "agentlock"])

    def test_wrapper_mode_and_printf_ifs(self):
        rendered = render_switcher(7897, "/usr/sbin/runuser")
        self.assertEqual(wrapper_problems(rendered, 7897, render_claude(7897)), [])
        broken = rendered.replace("IFS=$(/usr/bin/printf ' \\t\\n.')", "IFS= ")
        self.assertTrue(wrapper_problems(broken, 7897, render_claude(7897)))
        self.assertIsNone(switcher_mode_problem(0, 0o755, "linux"))
        self.assertTrue(switcher_mode_problem(1, 0o755, "linux"))
        self.assertTrue(switcher_mode_problem(0, 0o775, "linux"))
        self.assertTrue(switcher_mode_problem(None, None, "linux"))
        self.assertIsNone(switcher_mode_problem(None, 0o755, "windows", "BUILTIN\\Administrators"))
        self.assertIsNone(switcher_mode_problem(None, 0o666, "windows", "BUILTIN\\Administrators"))
        self.assertTrue(switcher_mode_problem(0, 0o666, "linux"))
        self.assertTrue(switcher_mode_problem(None, None, "windows", "Administrators"))
        self.assertTrue(switcher_mode_problem(None, 0o644, "windows", "Users"))
        self.assertTrue(switcher_mode_problem(None, 0o755, "windows", "Users"))
        checks, code = evaluate(_report())
        self.assertEqual(code, 0, checks)


class DoctorFactsTest(unittest.TestCase):
    def test_identity_login_daemon_and_exec(self):
        switcher = os.path.join(tempfile.gettempdir(), "agent-lock")
        commands = identity_commands(switcher)
        self.assertEqual(commands[0], [switcher, "/usr/bin/printenv", "USER"])
        self.assertEqual(len(commands), 3)
        seen = identity_from_results([(1, ""), (0, "alice\n"), (0, "")])
        self.assertEqual(seen, {"user": None, "logname": "alice", "home": None})
        self.assertIsNone(identity_from_results(None))
        status, _detail = classify_login({"attempted": False, "owner": "alice"})
        self.assertEqual(status, "skip")
        status, _detail = classify_login({
            "attempted": True, "owner": "alice", "keychain_account": None, "credentials_account": None,
        })
        self.assertEqual(status, "fail")
        status, _detail = classify_login({
            "attempted": True, "owner": "alice", "keychain_account": "alice", "credentials_account": None,
        })
        self.assertEqual(status, "pass")
        running, service_only = classify_daemon([(1000, "com.anthropic.claude-daemon")], 50, False)
        self.assertTrue(running)
        self.assertFalse(service_only)
        running, service_only = classify_daemon([(50, "claude-daemon")], 50, True)
        self.assertFalse(running)
        self.assertFalse(service_only)
        running, service_only = classify_daemon([], 50, True)
        self.assertFalse(running)
        self.assertTrue(service_only)
        self.assertIsNone(exec_access_problem([0, 0]))
        self.assertTrue(exec_access_problem([0, 1]))
        checks, code = evaluate(_report(controller_error="no controller address is stored", controller_port=None))
        self.assertEqual(code, 1)
        controller = [item for item in checks if item["name"] == "controller"][0]
        self.assertFalse(controller["ok"])


class InstallFlowTest(unittest.TestCase):
    def _paths(self):
        root = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        names = (
            "PF_CONF", "PF_BACKUP", "ANCHOR_PATH", "SWITCHER_PATH", "CLAUDE_WRAPPER_PATH",
            "NFT_CONF", "UNIT_PATH", "SUDOERS_PATH", "WINDOWS_CMD",
        )
        return root, {name: os.path.join(root, name.lower()) for name in names}

    def _patch_paths(self, patches, paths):
        for name, value in paths.items():
            patches.set(install, name, value)
        patches.set(state, "state_path", lambda owner=None: os.path.join(os.path.dirname(paths["PF_CONF"]), "missing-state.json"))

    def test_linux_refuses_sudo_group_and_syntax_before_load(self):
        _root, paths = self._paths()
        calls = []

        def runner(argv, input_text=None):
            calls.append(list(argv))
            if argv[:3] == ["systemctl", "is-active", "firewalld.service"]:
                return Result(3, "inactive\n")
            if argv[:2] == ["id", "-nG"]:
                return Result(0, "sudo\n")
            return Result(0, "")

        patches = Patches()
        try:
            self._patch_paths(patches, paths)
            patches.set(install, "find_nft", lambda: "/usr/sbin/nft")
            patches.set(install, "find_runuser", lambda: "/usr/sbin/runuser")
            patches.set(install, "_linux_identity", lambda: (True, True, True, "/usr/sbin/nologin", 50, 50))
            patches.set(install, "load_state", lambda path=None: None)
            with self.assertRaises(AgentLockError) as caught:
                install._linux_apply(_args(), _owner(tempfile.mkdtemp()), {"port": 7897, "source": "--port"}, [], runner, io.StringIO())
        finally:
            patches.restore()
        self.assertNotIn("nft", caught.exception.args[0])
        self.assertFalse(any(os.path.basename(str(item[0])) == "nft" for item in calls))

        calls[:] = []

        def syntax_runner(argv, input_text=None):
            calls.append(list(argv))
            if argv[:3] == ["systemctl", "is-active", "firewalld.service"]:
                return Result(3, "inactive\n")
            if argv[:2] == ["id", "-nG"]:
                return Result(0, "agentnet\n")
            if len(argv) > 1 and argv[1] == "-c":
                return Result(1, "", "bad destroy")
            return Result(0, "")

        patches = Patches()
        try:
            self._patch_paths(patches, paths)
            patches.set(install, "find_nft", lambda: "/usr/sbin/nft")
            patches.set(install, "find_runuser", lambda: "/usr/sbin/runuser")
            patches.set(install, "_linux_identity", lambda: (True, True, True, "/usr/sbin/nologin", 50, 50))
            patches.set(install, "load_state", lambda path=None: None)
            with self.assertRaises(Unsupported) as caught:
                install._linux_apply(_args(), _owner(tempfile.mkdtemp()), {"port": 7897, "source": "--port"}, [], syntax_runner, io.StringIO())
        finally:
            patches.restore()
        self.assertEqual(caught.exception.code, 4)
        self.assertFalse(any(item[0].endswith("nft") and "-c" not in item and "-f" in item for item in calls))

    def test_darwin_admin_and_pf_syntax_skip_the_load(self):
        _root, paths = self._paths()
        calls = []

        def runner(argv, input_text=None):
            calls.append(list(argv))
            if argv[:2] == ["id", "-Gn"]:
                return Result(0, "staff admin\n")
            if "-nf" in argv:
                return Result(1, "", "syntax")
            return Result(0, "")

        import pwd
        patches = Patches()

        class Record(object):
            pw_uid = 4
            pw_gid = 4
            pw_dir = tempfile.gettempdir()
            pw_name = "agentnet"

        try:
            self._patch_paths(patches, paths)
            patches.set(pwd, "getpwnam", lambda name: Record() if name == "agentnet" else pwd.getpwnam(name))
            with self.assertRaises(AgentLockError):
                install._darwin_apply(_args(), _owner(tempfile.mkdtemp()), {"port": 7897, "source": "--port"}, [], runner, io.StringIO())
        finally:
            patches.restore()
        self.assertTrue(any(item[:2] == ["id", "-Gn"] for item in calls))
        self.assertFalse(any(item[:1] == ["pfctl"] and "-f" in item for item in calls))

        calls[:] = []

        def syntax_runner(argv, input_text=None):
            calls.append(list(argv))
            if argv[:2] == ["id", "-Gn"]:
                return Result(0, "staff\n")
            if "-nf" in argv:
                return Result(1, "", "syntax")
            return Result(0, "")

        home = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(home, ignore_errors=True))
        patches = Patches()
        try:
            self._patch_paths(patches, paths)
            patches.set(pwd, "getpwnam", lambda name: Record())
            with self.assertRaises(Unsupported) as caught:
                install._darwin_apply(_args(), _owner(home), {"port": 7897, "source": "--port"}, [], syntax_runner, io.StringIO())
        finally:
            patches.restore()
        self.assertEqual(caught.exception.code, 4)
        self.assertFalse(any(item[0] == "pfctl" and "-f" in item and "-nf" not in item for item in calls))

    def test_daemon_stop_and_proxy_failure_restore_settings(self):
        _root, paths = self._paths()
        home = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(home, ignore_errors=True))
        os.mkdir(os.path.join(home, ".claude"))
        settings = os.path.join(home, ".claude", "settings.json")
        with open(settings, "w", encoding="utf-8") as handle:
            handle.write('{"keep": true}\n')
        trust = os.path.join(home, "tool")
        with open(trust, "w", encoding="utf-8") as handle:
            handle.write("x")
        os.chmod(trust, 0o755)
        calls = []

        def runner(argv, input_text=None):
            calls.append(list(argv))
            if argv[:3] == ["systemctl", "is-active", "firewalld.service"]:
                return Result(3, "inactive\n")
            if argv[:1] == ["claude"]:
                return Result(1, "", "still running")
            return Result(0, "")

        patches = Patches()
        try:
            self._patch_paths(patches, paths)
            patches.set(install, "find_nft", lambda: "/usr/sbin/nft")
            patches.set(install, "find_runuser", lambda: "/usr/sbin/runuser")
            patches.set(install, "_linux_identity", lambda: (True, True, True, "/usr/sbin/nologin", 50, 50))
            patches.set(install, "load_state", lambda path=None: None)
            patches.set(install.shutil, "which", lambda name: "/usr/bin/claude" if name == "claude" else None)
            with self.assertRaises(AgentLockError) as caught:
                install._linux_apply(
                    _args(trust_exec=[trust]), _owner(home),
                    {"port": 7897, "source": "--port"}, [], runner, io.StringIO())
        finally:
            patches.restore()
        self.assertEqual(caught.exception.code, 1)
        self.assertIn("daemon", str(caught.exception))
        self.assertTrue(any(item[:2] == ["setfacl", "-h"] for item in calls))
        claude_at = next(i for i, item in enumerate(calls) if item[:1] == ["claude"])
        self.assertTrue(any(
            i > claude_at and item[1:5] == ["delete", "table", "inet", "agentlock"]
            for i, item in enumerate(calls)))
        with open(settings, "r", encoding="utf-8") as handle:
            self.assertIn("keep", handle.read())

        calls[:] = []
        with open(paths["NFT_CONF"], "w", encoding="utf-8") as handle:
            handle.write("old-table\n")

        def previous_runner(argv, input_text=None):
            calls.append(list(argv))
            if argv[:3] == ["systemctl", "is-active", "firewalld.service"]:
                return Result(3, "inactive\n")
            if argv[:1] == ["claude"]:
                return Result(1, "", "still running")
            return Result(0, "")

        patches = Patches()
        try:
            self._patch_paths(patches, paths)
            patches.set(install, "find_nft", lambda: "/usr/sbin/nft")
            patches.set(install, "find_runuser", lambda: "/usr/sbin/runuser")
            patches.set(install, "_linux_identity", lambda: (True, True, True, "/usr/sbin/nologin", 50, 50))
            patches.set(install, "load_state", lambda path=None: {"version": 1, "port": 7000})
            patches.set(install.shutil, "which", lambda name: "/usr/bin/claude" if name == "claude" else None)
            with self.assertRaises(AgentLockError) as caught:
                install._linux_apply(
                    _args(trust_exec=[trust]), _owner(home),
                    {"port": 7897, "source": "--port"}, [], previous_runner, io.StringIO())
        finally:
            patches.restore()
        self.assertEqual(caught.exception.code, 1)
        self.assertIn("daemon", str(caught.exception))
        claude_at = next(i for i, item in enumerate(calls) if item[:1] == ["claude"])
        reloads = [
            item for i, item in enumerate(calls)
            if i > claude_at and str(item[0]).endswith("nft") and "-f" in item and "-c" not in item
        ]
        self.assertTrue(reloads)
        self.assertFalse(any(
            i > claude_at and item[1:3] == ["delete", "table"] for i, item in enumerate(calls)))
        with open(paths["NFT_CONF"], "r", encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "old-table\n")

    def test_windows_admin_skips_rules_and_proxy_restores_cmd(self):
        _root, paths = self._paths()
        with open(paths["WINDOWS_CMD"], "w", encoding="utf-8") as handle:
            handle.write("OLDCMD")
        calls = []

        def runner(argv, input_text=None):
            calls.append(list(argv))
            blob = " ".join(str(part) for part in argv)
            if "Get-NetFirewallProfile" in blob:
                return Result(0, '[{"Name":"Private","AllowLocalFirewallRules":true,"DefaultOutboundAction":"Allow"}]')
            if "Administrators" in blob:
                return Result(0, "yes\n")
            if "Enabled" in blob:
                return Result(0, "enabled\n")
            return Result(0, "S-1-5-21-1\n")

        home = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(home, ignore_errors=True))
        patches = Patches()
        try:
            self._patch_paths(patches, paths)
            with self.assertRaises(AgentLockError):
                install._windows_apply(_args(), _owner(home), {"port": 7897, "source": "--port"}, [], runner, io.StringIO())
        finally:
            patches.restore()
        self.assertFalse(any("New-NetFirewallRule" in " ".join(item) for item in calls))

        calls[:] = []
        saved = {}
        sid = "S-1-5-21-1"
        old_rules = rule_names(build_rules(7897, [], sid))

        def proxy_runner(argv, input_text=None):
            calls.append(list(argv))
            blob = " ".join(str(part) for part in argv)
            if "Get-NetFirewallProfile" in blob:
                return Result(0, '[{"Name":"Private","AllowLocalFirewallRules":true,"DefaultOutboundAction":"Allow"}]')
            if "Administrators" in blob:
                return Result(0, "no\n")
            if "Sid.Value" in blob:
                return Result(0, sid + "\n")
            if "Enabled" in blob:
                return Result(0, "enabled\n")
            if argv[:1] == ["curl"]:
                return Result(1, "", "down")
            return Result(0, "")

        patches = Patches()
        try:
            self._patch_paths(patches, paths)
            patches.set(install, "load_state", lambda path=None: {
                "version": 1, "port": 7897, "extra_tcp": [], "windows_rules": old_rules,
                "secret": "keep", "controller": "http://127.0.0.1:9", "owner": "alice", "owner_uid": 1,
            })
            patches.set(install, "save_state", lambda *a, **k: saved.setdefault("called", True))
            with self.assertRaises(AgentLockError):
                install._windows_apply(
                    _args(), _owner(home),
                    {"port": 8000, "source": "config", "controller": "http://127.0.0.1:9", "secret": "keep"},
                    [], proxy_runner, io.StringIO())
        finally:
            patches.restore()
        self.assertNotIn("called", saved)
        with open(paths["WINDOWS_CMD"], "r", encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "OLDCMD")
        self.assertTrue(any("New-NetFirewallRule" in " ".join(item) for item in calls))
        self.assertTrue(any("Remove-NetFirewallRule" in " ".join(item) for item in calls))

    def test_uninstall_busy_link_and_pf_order(self):
        self.assertTrue(agent_uid_busy("0\n50\n", 50))
        self.assertFalse(agent_uid_busy("0\n1\n", 50))
        self.assertFalse(agent_uid_busy("0\n", 0))
        root = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        recorded = os.path.join(root, "recorded")
        os.mkdir(recorded)
        marker = os.path.join(recorded, "keep")
        with open(marker, "w", encoding="utf-8") as handle:
            handle.write("x")
        calls = []

        def runner(argv, input_text=None):
            calls.append(list(argv))
            if argv[:1] == ["ps"]:
                return Result(0, "1\n")
            return Result(0, "")

        patches = Patches()
        try:
            patches.set(install, "load_state", lambda path=None: {
                "agent_uid": 50, "agent_user": "agentnet", "created_user": False,
                "links": [recorded], "pf_enable_token": "TOK", "agent_home": root,
            })
            with self.assertRaises(AgentLockError):
                _unlink_recorded(recorded)
            self.assertTrue(os.path.isfile(marker))
            with self.assertRaises(AgentLockError):
                cmd_uninstall(_args(), stdout=io.StringIO(), runner=runner)
        finally:
            patches.restore()
        self.assertTrue(os.path.isfile(marker))
        self.assertFalse(any(item[:1] == ["pfctl"] for item in calls))

        junction = os.path.join(root, "junction")
        os.mkdir(junction)
        removed = []
        patches = Patches()
        try:
            original_rmdir = install.os.rmdir
            patches.set(install, "_is_junction", lambda path: os.path.abspath(path) == os.path.abspath(junction))
            patches.set(install.os, "rmdir", lambda path: removed.append(path) or original_rmdir(path))
            _unlink_recorded(junction)
        finally:
            patches.restore()
        self.assertEqual(os.path.abspath(removed[0]), os.path.abspath(junction))

        _root, paths = self._paths()
        from agent_lock.darwin import patch_pf_conf
        with open(paths["PF_CONF"], "w", encoding="utf-8") as handle:
            handle.write(patch_pf_conf('anchor "com.apple/*"\n'))
        with open(paths["ANCHOR_PATH"], "w", encoding="utf-8") as handle:
            handle.write("anchor\n")
        calls[:] = []
        stderr = io.StringIO()

        def pf_runner(argv, input_text=None):
            calls.append(list(argv))
            if argv[:1] == ["ps"]:
                return Result(0, "1\n")
            return Result(0, "")

        real_stderr = sys.stderr
        patches = Patches()
        try:
            sys.stderr = stderr
            self._patch_paths(patches, paths)
            patches.set(install, "load_state", lambda path=None: {
                "agent_uid": 50, "agent_user": "agentnet", "created_user": False,
                "links": [], "pf_enable_token": "TOK", "agent_home": root,
            })
            cmd_uninstall(_args(), stdout=io.StringIO(), stderr=stderr, runner=pf_runner)
        finally:
            sys.stderr = real_stderr
            patches.restore()
        pfctl = [item for item in calls if item[:1] == ["pfctl"]]
        self.assertEqual(pfctl[0][1], "-nf")
        self.assertEqual(pfctl[1][1], "-f")
        self.assertEqual(pfctl[2][:2], ["pfctl", "-X"][:2] if False else ["pfctl", "-X"])
        self.assertEqual(pfctl[2][1], "-X")
        self.assertEqual(pfctl[2][2], "TOK")
        self.assertLess(calls.index(pfctl[1]), calls.index(pfctl[2]))
        self.assertNotIn("pfctl -d", stderr.getvalue())
        self.assertIn("pfctl -f drops anchors", stderr.getvalue())
        self.assertFalse(os.path.exists(paths["ANCHOR_PATH"]))

    def test_darwin_failure_reloads_restored_rules(self):
        import pwd
        _root, paths = self._paths()
        home = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(home, ignore_errors=True))
        os.mkdir(os.path.join(home, ".claude"))
        settings = os.path.join(home, ".claude", "settings.json")
        original_settings = '{"keep": true}\n'
        with open(settings, "w", encoding="utf-8") as handle:
            handle.write(original_settings)
        original_pf = "# original rules\n"
        with open(paths["PF_CONF"], "w", encoding="utf-8") as handle:
            handle.write(original_pf)
        with open(paths["ANCHOR_PATH"], "w", encoding="utf-8") as handle:
            handle.write("old-anchor\n")

        class Record(object):
            pw_uid = 4
            pw_gid = 4
            pw_dir = tempfile.gettempdir()
            pw_name = "agentnet"

        def which(name):
            if name == "pfctl":
                return "/sbin/pfctl"
            if name == "claude":
                return "/usr/bin/claude"
            return None

        def conf_loads(calls, after):
            return [i for i, item in enumerate(calls) if i > after and item[:2] == ["pfctl", "-f"]]

        def anchor_loads(calls, after):
            return [
                i for i, item in enumerate(calls)
                if i > after and item[:3] == ["pfctl", "-a", "agentlock"]
            ]

        calls = []

        def stop_runner(argv, input_text=None):
            calls.append(list(argv))
            if argv[:2] == ["id", "-Gn"]:
                return Result(0, "staff\n")
            if argv[:1] == ["claude"]:
                return Result(1, "", "still running")
            return Result(0, "")

        def proxy_runner(argv, input_text=None):
            calls.append(list(argv))
            if argv[:2] == ["id", "-Gn"]:
                return Result(0, "staff\n")
            if "curl" in argv:
                return Result(1, "", "down")
            return Result(0, "")

        real_stderr = sys.stderr
        stderr = io.StringIO()
        patches = Patches()
        try:
            sys.stderr = stderr
            self._patch_paths(patches, paths)
            patches.set(pwd, "getpwnam", lambda name: Record())
            patches.set(install.shutil, "which", which)
            patches.set(install, "load_state", lambda path=None: None)
            with self.assertRaises(AgentLockError) as caught:
                install._darwin_apply(
                    _args(), _owner(home), {"port": 7897, "source": "--port"}, [],
                    stop_runner, io.StringIO())
        finally:
            sys.stderr = real_stderr
            patches.restore()
        self.assertEqual(caught.exception.code, 1)
        self.assertIn("daemon", str(caught.exception))
        claude_at = next(i for i, item in enumerate(calls) if item[:1] == ["claude"])
        self.assertTrue(conf_loads(calls, claude_at))
        self.assertTrue(anchor_loads(calls, claude_at))
        self.assertFalse(any(item[:2] == ["pfctl", "-d"] for item in calls))
        with open(paths["PF_CONF"], "r", encoding="utf-8") as handle:
            self.assertEqual(handle.read(), original_pf)
        with open(paths["ANCHOR_PATH"], "r", encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "old-anchor\n")
        with open(settings, "r", encoding="utf-8") as handle:
            self.assertEqual(handle.read(), original_settings)

        calls[:] = []
        with open(paths["PF_CONF"], "w", encoding="utf-8") as handle:
            handle.write(original_pf)
        with open(paths["ANCHOR_PATH"], "w", encoding="utf-8") as handle:
            handle.write("old-anchor\n")
        stderr = io.StringIO()
        patches = Patches()
        try:
            sys.stderr = stderr
            self._patch_paths(patches, paths)
            patches.set(pwd, "getpwnam", lambda name: Record())
            patches.set(install.shutil, "which", which)
            patches.set(install, "load_state", lambda path=None: None)
            with self.assertRaises(AgentLockError) as caught:
                install._darwin_apply(
                    _args(), _owner(home), {"port": 7897, "source": "--port"}, [],
                    proxy_runner, io.StringIO())
        finally:
            sys.stderr = real_stderr
            patches.restore()
        self.assertIn("proxy", str(caught.exception))
        curl_at = next(i for i, item in enumerate(calls) if "curl" in item)
        self.assertTrue(conf_loads(calls, curl_at))
        self.assertTrue(anchor_loads(calls, curl_at))
        self.assertFalse(any(item[:2] == ["pfctl", "-d"] for item in calls))
        with open(paths["PF_CONF"], "r", encoding="utf-8") as handle:
            self.assertEqual(handle.read(), original_pf)
        with open(settings, "r", encoding="utf-8") as handle:
            self.assertEqual(handle.read(), original_settings)

        calls[:] = []
        with open(paths["PF_CONF"], "w", encoding="utf-8") as handle:
            handle.write('anchor "agentlock"\n')
        with open(paths["ANCHOR_PATH"], "w", encoding="utf-8") as handle:
            handle.write("old-anchor\n")
        stderr = io.StringIO()
        patches = Patches()
        try:
            sys.stderr = stderr
            self._patch_paths(patches, paths)
            patches.set(pwd, "getpwnam", lambda name: Record())
            patches.set(install.shutil, "which", which)
            patches.set(install, "load_state", lambda path=None: None)
            with self.assertRaises(AgentLockError):
                install._darwin_apply(
                    _args(), _owner(home), {"port": 7897, "source": "--port"}, [],
                    proxy_runner, io.StringIO())
        finally:
            sys.stderr = real_stderr
            patches.restore()
        curl_at = next(i for i, item in enumerate(calls) if "curl" in item)
        self.assertFalse(conf_loads(calls, curl_at))
        self.assertTrue(anchor_loads(calls, curl_at))
        self.assertFalse(any(item[:2] == ["pfctl", "-f"] for item in calls))


class RereviewTest(unittest.TestCase):
    def test_one_within_helper(self):
        self.assertFalse(hasattr(install, "_under_home"))
        self.assertFalse(hasattr(install, "_discovered_fields"))
        from agent_lock import linux
        self.assertFalse(hasattr(linux, "_is_same_or_under"))
        root = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        home = os.path.join(root, "ownerhome")
        leaf_dir = os.path.join(home, "proj", "bin")
        os.makedirs(leaf_dir)
        leaf = os.path.join(leaf_dir, "tool")
        with open(leaf, "w", encoding="utf-8") as handle:
            handle.write("x")
        parents = parent_dirs(leaf, home)
        self.assertEqual(parents, [
            os.path.abspath(home),
            os.path.abspath(os.path.join(home, "proj")),
            os.path.abspath(leaf_dir),
        ])
        self.assertNotIn(os.path.abspath(leaf), parents)
        self.assertEqual(parent_dirs(home, home), [])
        outside = os.path.join(root, "other", "tool")
        os.makedirs(os.path.dirname(outside))
        self.assertEqual(parent_dirs(outside, home), [])

    def test_strip_settings_preserves_mode_and_owner(self):
        import pwd
        root = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        path = os.path.join(root, "settings.json")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write('{"env": {"CLAUDE_CODE_PROCESS_WRAPPER": "w", "OTHER": "1"}, "keep": 1}\n')
        os.chmod(path, 0o640)
        calls = []
        patches = Patches()
        try:
            patches.set(state.os, "geteuid", lambda: 0)
            patches.set(install.os, "chown", lambda target, uid, gid: calls.append((target, uid, gid)))
            _strip_settings([{"path": path, "created": False}], {"owner_uid": os.getuid()})
            self.assertEqual(stat.S_IMODE(os.lstat(path).st_mode), 0o640)
            with open(path, "r", encoding="utf-8") as handle:
                text = handle.read()
            self.assertIn('"keep"', text)
            self.assertIn("OTHER", text)
            self.assertNotIn("CLAUDE_CODE_PROCESS_WRAPPER", text)
            self.assertEqual(calls[-1][0], path)
            self.assertEqual(calls[-1][1], os.getuid())
            self.assertEqual(calls[-1][2], pwd.getpwuid(os.getuid()).pw_gid)
            empty = os.path.join(root, "created.json")
            with open(empty, "w", encoding="utf-8") as handle:
                handle.write('{"env": {"CLAUDE_CODE_PROCESS_WRAPPER": "w"}}\n')
            before = len(calls)
            _strip_settings([{"path": empty, "created": True}], {"owner_uid": os.getuid()})
            self.assertFalse(os.path.exists(empty))
            self.assertEqual(len(calls), before)
        finally:
            patches.restore()

    def test_rule_script_reads_the_security_filter(self):
        script = windows_rule_script("S-1-5-21-9")
        self.assertIn("Get-NetFirewallSecurityFilter", script)
        self.assertNotIn("$_.LocalUser", script)
        self.assertIn("Get-NetFirewallPortFilter", script)
        self.assertIn("S-1-5-21-9", script)
        with self.assertRaises(AgentLockError):
            windows_rule_script("nope")

    def test_numeric_outbound_action_exits_4(self):
        self.assertIsNone(default_outbound_problem([{"DefaultOutboundAction": 2}]))
        self.assertIsNone(default_outbound_problem([{"DefaultOutboundAction": "2"}]))
        self.assertIsNone(default_outbound_problem([{"DefaultOutboundAction": "Allow"}]))
        self.assertIsNone(default_outbound_problem([{"DefaultOutboundAction": True}]))
        self.assertTrue(default_outbound_problem([{"name": "Private", "DefaultOutboundAction": 4}]))
        self.assertTrue(default_outbound_problem([{"DefaultOutboundAction": "4"}]))
        self.assertTrue(default_outbound_problem([{"DefaultOutboundAction": "Block"}]))
        with self.assertRaises(Unsupported) as caught:
            require_supported([{
                "name": "Private", "AllowLocalFirewallRules": True, "DefaultOutboundAction": 4,
            }])
        self.assertEqual(caught.exception.code, 4)
        with self.assertRaises(Unsupported) as caught:
            require_supported([{
                "name": "Private", "AllowLocalFirewallRules": 0, "DefaultOutboundAction": 2,
            }])
        self.assertEqual(caught.exception.code, 4)
        require_supported([{
            "name": "Private", "AllowLocalFirewallRules": True, "DefaultOutboundAction": "Allow",
        }])
        _gpo, outbound, ok, _extras = windows_firewall_report(
            [{"name": "Private", "AllowLocalFirewallRules": True, "DefaultOutboundAction": 4}],
            build_rules(7897, [], "S-1-5-21-1"), 7897)
        self.assertTrue(outbound)
        self.assertFalse(ok)
        _checks, code = evaluate(_report(
            platform="windows", outbound_problem=outbound, firewall_ok=True, extra_tcp_observed=[],
        ))
        self.assertEqual(code, 4)

        def fake_run(argv, timeout=20):
            blob = " ".join(str(part) for part in argv)
            if "Get-NetFirewallProfile" in blob:
                return Result(
                    0, '{"Name":"Private","AllowLocalFirewallRules":1,"DefaultOutboundAction":4}')
            if "Get-NetFirewallSecurityFilter" in blob:
                self.assertNotIn("$_.LocalUser", blob)
                return Result(0, "[]")
            if "Get-Acl" in blob:
                return Result(0, "BUILTIN\\Administrators\n")
            return Result(1, "", "unexpected")

        report = {}
        patches = Patches()
        try:
            patches.set(doctor, "_run", fake_run)
            doctor._fill_windows_firewall(report, {
                "agent_sid": "S-1-5-21-1", "port": 7897, "wrapper": "agent-lock.cmd",
            })
        finally:
            patches.restore()
        self.assertTrue(report.get("outbound_problem"))
        self.assertFalse(report.get("firewall_ok"))

    def test_windows_account_facts(self):
        text = windows_user_script()
        self.assertIn("Get-LocalUser", text)
        self.assertIn("Enabled", text)
        self.assertNotIn("Administrators", text)

        def run_with(user_out, admin_out):
            def fake_run(argv, timeout=20):
                blob = " ".join(str(part) for part in argv)
                if "Get-LocalUser" in blob:
                    return Result(0, user_out)
                if "Administrators" in blob:
                    return Result(0, admin_out)
                return Result(1, "")

            patches = Patches()
            try:
                patches.set(doctor, "_run", fake_run)
                return doctor._account_facts({}, "windows")
            finally:
                patches.restore()

        missing = run_with("", "no\n")
        self.assertFalse(missing["exists"])
        check = doctor._account_check({"account": missing}, "windows")
        self.assertEqual(check["level"], "fail")
        self.assertIn("does not exist", check["detail"])

        disabled = run_with('{"Name":"agentnet","Enabled":false}', "no\n")
        self.assertTrue(disabled["exists"])
        self.assertFalse(disabled["enabled"])
        check = doctor._account_check({"account": disabled}, "windows")
        self.assertIn("disabled", check["detail"])

        admin = run_with('{"Name":"agentnet","Enabled":true}', "yes\n")
        self.assertEqual(admin["groups"], ["Administrators"])
        check = doctor._account_check({"account": admin}, "windows")
        self.assertIn("Administrators", check["detail"])

        healthy = run_with('{"Name":"agentnet","Enabled":true}', "no\n")
        check = doctor._account_check({"account": healthy}, "windows")
        self.assertEqual(check["level"], "pass")

    def test_windows_locked_probes_are_not_the_cmd(self):
        import base64
        sid = "S-1-5-21-1"
        proxy = ["curl", "-sS", "-o", os.devnull, "--max-time", "5",
                 "-x", "http://127.0.0.1:7897", "https://example.com"]
        direct = ["curl", "-sS", "-o", os.devnull, "--max-time", "3",
                  "--noproxy", "*", "https://1.1.1.1/"]
        command = windows_locked_command(sid, "python", "probe.py", proxy, direct)
        script = command[-1]
        self.assertEqual(command[0], "powershell")
        self.assertIn("Get-Credential", script)
        self.assertIn("WindowsIdentity", script)
        self.assertNotIn("agent-lock.cmd", script)
        self.assertNotIn("exit 126", script)
        self.assertNotIn("runas", script.lower())
        with self.assertRaises(AgentLockError):
            windows_locked_command("not-a-sid", "python", "probe.py", proxy, direct)

        denied = base64.b64encode(b"agent-lock-probe: denied 1\n").decode("ascii")
        empty = base64.b64encode(b"").decode("ascii")
        batch = "\n".join([
            "PROBE_CODE=1",
            "PROBE_OUT_B64=" + denied,
            "PROBE_ERR_B64=" + empty,
            "PROXY_CODE=0",
            "PROXY_ERR_B64=" + empty,
            "NOPROXY_CODE=28",
            "NOPROXY_ERR_B64=" + empty,
        ])
        parsed = parse_locked_batch(batch)
        self.assertEqual(parsed["probe_code"], 1)
        self.assertIn("denied", parsed["probe_stdout"])
        self.assertEqual(parsed["noproxy_code"], 28)

        calls = []

        def fake_run(argv, timeout=20):
            calls.append(list(argv))
            if argv[:1] == ["powershell"]:
                blob = " ".join(str(part) for part in argv)
                self.assertNotIn("agent-lock.cmd", blob)
                self.assertIn("Get-Credential", blob)
                self.assertIn("WindowsIdentity", blob)
                return Result(0, batch)
            return Result(0, "agent-lock-probe: connected\n")

        report = {}
        patches = Patches()
        try:
            patches.set(doctor, "_run", fake_run)
            doctor._fill_windows_probes(report, {"agent_sid": sid, "proxy": "http://127.0.0.1:7897"})
        finally:
            patches.restore()
        self.assertEqual(report["probe_code"], 1)
        self.assertEqual(report["proxy_code"], 0)
        self.assertEqual(report["noproxy_code"], 28)
        self.assertEqual(report["owner_probe_code"], 0)
        self.assertIn("connected", report["owner_probe_stdout"])
        self.assertEqual(calls[0][0], "powershell")
        self.assertEqual(calls[1][1], "-c")
        self.assertNotIn("powershell", calls[1][0])

        calls[:] = []

        def refused(argv, timeout=20):
            calls.append(list(argv))
            if argv[:1] == ["powershell"]:
                return Result(126, "", "not agentnet")
            return Result(0, "agent-lock-probe: connected\n")

        report = {}
        patches = Patches()
        try:
            patches.set(doctor, "_run", refused)
            doctor._fill_windows_probes(report, {"agent_sid": sid, "proxy": "http://127.0.0.1:7897"})
        finally:
            patches.restore()
        self.assertEqual(report["probe_code"], 126)
        self.assertEqual(report["proxy_code"], 126)
        self.assertEqual(report["noproxy_code"], 126)
        self.assertFalse(doctor.probe_denied(
            report.get("probe_stdout"), report.get("probe_stderr"), report["probe_code"]))
        self.assertFalse(doctor.noproxy_locked(report["noproxy_code"], report.get("noproxy_stderr")))
        level, detail = doctor._proxy_check(report)
        self.assertEqual(level, "fail")
        self.assertIn("126", detail)
        self.assertEqual(report["owner_probe_code"], 0)

        calls[:] = []
        report = {}
        patches = Patches()
        try:
            patches.set(doctor, "_run", fake_run)
            doctor._fill_windows_probes(report, {"agent_sid": "bogus", "proxy": "http://127.0.0.1:7897"})
        finally:
            patches.restore()
        self.assertEqual(report["probe_code"], 127)
        self.assertEqual(report["owner_probe_code"], 0)
        self.assertEqual(len(calls), 1)
        self.assertNotEqual(calls[0][0], "powershell")

    def test_windows_exec_access_reads_the_agentnet_ace(self):
        self.assertFalse(windows_path_executable(
            "C:\\dir\\agentnet\\tool.exe NT AUTHORITY\\SYSTEM:(F)\n"))
        self.assertFalse(windows_path_executable(
            "C:\\dir\\agentnet\\tool.exe BUILTIN\\Users:(R)\n"))
        self.assertFalse(windows_path_executable("MACHINE\\agentnet:(R)\n"))
        self.assertTrue(windows_path_executable("MACHINE\\agentnet:(RX)\n"))
        self.assertTrue(windows_path_executable("  MACHINE\\agentnet:(OI)(CI)(RX)\n"))
        self.assertTrue(windows_path_executable("agentnet:(F)\n"))
        self.assertTrue(windows_path_executable("agentnet:(M)\n"))

        report = {}

        def boom(*_args, **_kwargs):
            raise AssertionError("empty exec list must not probe")

        patches = Patches()
        try:
            patches.set(doctor, "_run", boom)
            doctor._fill_claude(report, {"exec_paths": []}, "windows")
        finally:
            patches.restore()
        self.assertTrue(report["exec_access_ok"])
        self.assertIn("no recorded", report["exec_access_detail"])

        calls = []

        def ok_run(argv, timeout=20):
            calls.append(list(argv))
            return Result(0, "C:\\dir\\tool.exe MACHINE\\agentnet:(RX)\n")

        patches = Patches()
        try:
            patches.set(doctor, "_run", ok_run)
            doctor._fill_claude(report, {"exec_paths": ["C:\\dir\\tool.exe"]}, "windows")
        finally:
            patches.restore()
        self.assertTrue(report["exec_access_ok"])
        self.assertEqual(calls[0][0], "icacls")
        self.assertNotIn("agent-lock.cmd", calls[0])

        def bad_run(argv, timeout=20):
            return Result(0, "C:\\dir\\agentnet\\tool.exe BUILTIN\\Users:(F)\n")

        patches = Patches()
        try:
            patches.set(doctor, "_run", bad_run)
            doctor._fill_claude(report, {"exec_paths": ["C:\\dir\\agentnet\\tool.exe"]}, "windows")
        finally:
            patches.restore()
        self.assertFalse(report["exec_access_ok"])

        def fail_run(argv, timeout=20):
            return Result(1, "MACHINE\\agentnet:(RX)\n", "denied")

        patches = Patches()
        try:
            patches.set(doctor, "_run", fail_run)
            doctor._fill_claude(report, {"exec_paths": ["C:\\dir\\tool.exe"]}, "windows")
        finally:
            patches.restore()
        self.assertFalse(report["exec_access_ok"])

    def test_state_acl_failure_raises(self):
        seen = []

        def ok(argv):
            seen.append(list(argv))
            return Result(0)

        apply_state_acl("state.json", "alice", runner=ok)
        blob = " ".join(seen[0])
        self.assertIn("*S-1-5-18:(F)", seen[0])
        self.assertIn("*S-1-5-32-544:(F)", seen[0])
        self.assertNotIn("Users", blob)
        self.assertNotIn("agentnet", blob)
        with self.assertRaises(AgentLockError):
            apply_state_acl("state.json", "alice", runner=lambda argv: Result(1, "", "denied"))
        with self.assertRaises(AgentLockError):
            apply_state_acl("state.json", "alice", runner=lambda argv: None)


if __name__ == "__main__":
    unittest.main()
