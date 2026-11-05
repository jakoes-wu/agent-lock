"""Switcher, Claude wrapper, sudoers, and the Windows cmd."""

import unittest

import support

from agent_lock.state import SWITCHER_PATH
from agent_lock.wrapper import SUDOERS_ENV_DELETE, render_claude, render_sudoers, render_switcher, render_windows_cmd

support.install = None


class WrapperTest(unittest.TestCase):
    def test_ifs_and_preflight(self):
        text = render_switcher(7897, "/usr/sbin/runuser", darwin=False)
        self.assertIn("IFS=$(/usr/bin/printf ' \\t\\n.')", text)
        self.assertIn("IFS=${IFS%.}", text)
        self.assertIn("unset IFS", text)
        self.assertNotIn("export IFS", text)
        self.assertIn("sudo -n -l " + SWITCHER_PATH, text)
        self.assertNotIn("sudo -n -v", text)
        snap = text.index("AGENT_LOCK_OWNER_USER=${USER-}")
        pre = text.index("/usr/bin/sudo -n -l")
        self.assertLess(snap, pre)
        self.assertIn("AGENT_LOCK_OWNER_LOGNAME=${LOGNAME-}", text)
        self.assertIn("AGENT_LOCK_OWNER_HOME=${HOME-}", text)
        self.assertIn("AGENT_LOCK_SAVED_PATH", text)
        self.assertIn("exec /usr/sbin/runuser --preserve-environment -u agentnet -- " + SWITCHER_PATH, text)
        self.assertNotIn('exec "$@"', text.split("if [ \"$(/usr/bin/id -u)\" -eq 0 ]", 1)[1].split("fi", 1)[0])

    def test_claude_wrapper_has_no_unset(self):
        text = render_claude(7897)
        self.assertNotIn("unset", text)
        self.assertNotIn("ALL_PROXY", text)
        self.assertIn("exec \"$@\"", text)
        self.assertIn("http://127.0.0.1:7897", text)
        self.assertIn("case \",${NO_PROXY-},\"", text)

    def test_sudoers_literals(self):
        text = render_sudoers("alice")
        self.assertIn("!env_reset, !set_logname, !set_home, !always_set_home", text)
        self.assertIn("alice ALL=(root) NOPASSWD:SETENV: " + SWITCHER_PATH, text)
        self.assertIn("No wildcard", text)
        for name in SUDOERS_ENV_DELETE:
            self.assertIn('env_delete+="%s"' % name, text)
        self.assertNotIn("env_delete+=*", text)
        self.assertNotIn("LD_*", text)
        self.assertNotIn("DYLD_*", text)

    def test_windows_cmd_sets_four_proxies(self):
        text = render_windows_cmd(7897, "S-1-5-21-EXAMPLE")
        self.assertNotIn("NO_PROXY", text)
        self.assertNotIn("no_proxy", text)
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            self.assertIn(name, text)
        self.assertIn("S-1-5-21-EXAMPLE", text)
        self.assertIn("runas /user:agentnet", text)
        self.assertNotIn("password", text.lower())


if __name__ == "__main__":
    unittest.main()
