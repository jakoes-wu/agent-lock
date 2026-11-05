"""Doctor classification from fake observations. No live firewall."""

import json
import unittest

import support

from agent_lock.doctor import (
    annotate_probe_messages,
    evaluate,
    format_json,
    noproxy_locked,
    pf_counter_status,
    probe_connected,
    probe_denied,
    repair_plan,
)
from agent_lock.state import LINUX_AGENT_HOME
from agent_lock.wrapper import render_claude, render_switcher

support.install = None

PORT = 7897


def _report(**overrides):
    switcher = render_switcher(PORT, "/usr/sbin/runuser")
    claude = render_claude(PORT)
    report = {
        "installed": True,
        "platform": "linux",
        "state": {
            "port": PORT,
            "proxy": "http://127.0.0.1:{}".format(PORT),
            "extra_tcp": [],
            "agent_gid": 50,
            "claude_wrapper": "/usr/local/sbin/agent-lock-claude",
            "secret": "not-in-json",
            "owner": "alice",
            "owner_home": "/var/lib/owner-home",
            "claude_settings": [],
        },
        "account": {
            "exists": True,
            "groups": ["agentnet"],
            "shell": "/usr/sbin/nologin",
            "locked": True,
            "home": LINUX_AGENT_HOME,
            "enabled": True,
        },
        "firewall_ok": True,
        "firewall_detail": "ok",
        "extra_tcp_observed": [],
        "switcher_text": switcher,
        "claude_text": claude,
        "cmd_text": "",
        "expected_identity": {"user": "alice", "logname": "alice", "home": "/var/lib/owner-home"},
        "seen_identity": {"user": "alice", "logname": "alice", "home": "/var/lib/owner-home"},
        "bin_dirs": [],
        "settings": [],
        "claude_version": None,
        "claude_login": "skip",
        "claude_login_detail": "skipped",
        "daemon_running_as_owner": False,
        "daemon_service_file": False,
        "windows_claude_warn": "",
        "controller_error": None,
        "controller_port": PORT,
        "allow_lan": False,
        "secret_set": True,
        "proxy_missing": False,
        "proxy_code": 0,
        "proxy_stderr": "",
        "noproxy_missing": False,
        "noproxy_code": 28,
        "noproxy_stderr": "",
        "probe_stdout": "agent-lock-probe: denied 1\n",
        "probe_stderr": "",
        "probe_code": 1,
        "owner_probe_stdout": "agent-lock-probe: connected\n",
        "owner_probe_stderr": "",
        "owner_probe_code": 0,
        "drop_before": 3,
        "drop_after": 4,
        "pf_counter_parsed": False,
        "pf_before": None,
        "pf_after": None,
        "unix_socket": None,
        "home_traversable": True,
        "exec_access_ok": True,
    }
    report.update(overrides)
    return report


def _by_name(checks):
    return {item["name"]: item for item in checks}


class DoctorParseTest(unittest.TestCase):
    def test_curl_and_probe_classification(self):
        self.assertTrue(noproxy_locked(28, ""))
        self.assertTrue(noproxy_locked(7, ""))
        self.assertTrue(noproxy_locked(56, "Connection timed out"))
        self.assertFalse(noproxy_locked(0, "Connection timed out"))
        self.assertFalse(noproxy_locked(127, "Connection refused"))
        self.assertFalse(noproxy_locked(None, ""))
        self.assertTrue(probe_denied("agent-lock-probe: denied 1\n", "", 1))
        self.assertFalse(probe_denied("agent-lock-probe: connected\n", "", 0))
        self.assertFalse(probe_denied("", "ModuleNotFoundError", 1))
        self.assertFalse(probe_denied("", "", 127))
        self.assertTrue(probe_connected("agent-lock-probe: connected\n", "", 0))
        self.assertFalse(probe_connected("agent-lock-probe: connected\n", "", 127))

    def test_locked_report_exits_0(self):
        checks, code = evaluate(_report())
        self.assertEqual(code, 0, checks)
        names = _by_name(checks)
        self.assertTrue(names["noproxy-fail"]["ok"])
        self.assertTrue(names["raw-tcp-fail"]["ok"])
        self.assertTrue(names["counter"]["ok"])
        payload = json.loads(format_json(checks))
        self.assertEqual(payload["version"], 1)
        blob = json.dumps(payload)
        self.assertNotIn("not-in-json", blob)

    def test_curl_127_and_missing_marker_fail(self):
        checks, code = evaluate(_report(noproxy_code=127, probe_stdout="", probe_code=127))
        self.assertEqual(code, 1)
        names = _by_name(checks)
        self.assertFalse(names["noproxy-fail"]["ok"])
        self.assertIn("127", names["noproxy-fail"]["detail"])
        self.assertFalse(names["raw-tcp-fail"]["ok"])
        self.assertFalse(names["counter"]["ok"])

    def test_both_failure_sentences(self):
        checks, _code = evaluate(_report(proxy_code=28, proxy_stderr="timed out", probe_stdout="", probe_code=1))
        annotate_probe_messages(checks)
        names = _by_name(checks)
        self.assertIn("the proxy is not up", names["proxy-ok"]["detail"])
        self.assertIn("the lock is not in effect", names["raw-tcp-fail"]["detail"])

    def test_sudo_env_and_bin_dir(self):
        checks, code = evaluate(_report(seen_identity={"user": "root", "logname": "root", "home": "/root"}))
        self.assertEqual(code, 1)
        self.assertIn("not the firewall", _by_name(checks)["sudo-env"]["detail"])
        bad_dir = {"path": "bin", "is_link": False, "is_dir": True, "mode": 0o2775, "gid": 50}
        checks, code = evaluate(_report(bin_dirs=[bad_dir]))
        self.assertEqual(code, 1)
        self.assertFalse(_by_name(checks)["bin-dir"]["ok"])

    def test_pf_counter_warns_when_unparsed(self):
        level, detail = pf_counter_status(False, None, None)
        self.assertEqual(level, "warn")
        self.assertTrue(detail.startswith("warn:"))
        level, _detail = pf_counter_status(True, 1, 1)
        self.assertEqual(level, "fail")
        report = _report(platform="darwin", pf_counter_parsed=False)
        checks, code = evaluate(report)
        names = _by_name(checks)
        self.assertEqual(names["pf-counter"]["level"], "warn")
        self.assertTrue(names["pf-counter"]["ok"])
        # The probe marker is still required.
        report["probe_stdout"] = ""
        checks, code = evaluate(report)
        self.assertEqual(code, 1)
        self.assertFalse(_by_name(checks)["raw-tcp-fail"]["ok"])

    def test_not_installed_is_3_and_windows_warn_does_not_fail(self):
        checks, code = evaluate({"installed": False})
        self.assertEqual(code, 3)
        self.assertEqual(len(checks), 1)
        report = _report(platform="windows", windows_claude_warn="a task would start Claude")
        checks, code = evaluate(report)
        names = _by_name(checks)
        self.assertEqual(names["windows-claude"]["level"], "warn")
        self.assertTrue(names["windows-claude"]["ok"])
        self.assertNotIn("sudo-env", names)

    def test_repair_plan_does_not_chown_or_touch_the_port(self):
        state = {"owner_home": "/var/lib/owner-home", "share_dirs": [], "port": PORT}

        def classify(_path):
            return "missing"

        commands = repair_plan(state, "linux", classify)
        self.assertEqual(commands, [])
        for command in commands:
            self.assertNotEqual(command[0], "chown")
            self.assertNotIn(str(PORT), " ".join(command))


if __name__ == "__main__":
    unittest.main()
