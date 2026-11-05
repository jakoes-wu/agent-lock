"""pf anchor placement. Does not load a ruleset or disable pf."""

import os
import unittest

import support

from agent_lock.darwin import PfRefuse, patch_pf_conf, release_token_argv, render_anchor
from agent_lock.errors import AgentLockError

support.install = None

APPLE = 'anchor "com.apple/*"'


class PfTest(unittest.TestCase):
    def test_anchor_before_apple_and_no_extra_when_empty(self):
        text = "scrub in all\n{}\npass out quick proto tcp to any\n".format(APPLE)
        patched = patch_pf_conf(text)
        self.assertLess(patched.index('anchor "agentlock"'), patched.index(APPLE))
        self.assertLess(patched.index("# agent-lock end"), patched.index("pass out quick"))
        body = render_anchor(7897, [])
        self.assertIn("pass out quick inet proto tcp to 127.0.0.1 port 7897", body)
        self.assertIn("pass out quick inet6 proto tcp to ::1 port 7897", body)
        self.assertEqual(body.count("pass out quick"), 2)
        self.assertIn("block drop out quick proto { tcp, udp, icmp, ipv6-icmp }", body)

    def test_extra_pass_only_when_requested(self):
        empty = render_anchor(7897, [])
        self.assertNotIn("11434", empty)
        extra = render_anchor(7897, ["127.0.0.1:11434"])
        self.assertIn("to 127.0.0.1 port 11434", extra)
        self.assertEqual(extra.count("pass out quick"), 3)

    def test_no_apple_anchor_inserts_at_the_start(self):
        text = "pass out quick all\n"
        patched = patch_pf_conf(text)
        self.assertTrue(patched.startswith("# agent-lock begin\n"))
        self.assertLess(patched.index('anchor "agentlock"'), patched.index("pass out quick all"))

    def test_pass_quick_before_apple_is_refused(self):
        text = "pass out quick all\n{}\n".format(APPLE)
        with self.assertRaises(PfRefuse) as caught:
            patch_pf_conf(text)
        self.assertEqual(caught.exception.code, 1)
        self.assertIsInstance(caught.exception, AgentLockError)

    def test_release_token_never_disables(self):
        self.assertIsNone(release_token_argv(""))
        self.assertEqual(release_token_argv("42"), ["pfctl", "-X", "42"])
        root = os.path.join(support.ROOT, "src")
        for dirpath, _dirs, names in os.walk(root):
            for name in names:
                if not name.endswith(".py"):
                    continue
                with open(os.path.join(dirpath, name), encoding="utf-8") as handle:
                    text = handle.read()
                self.assertNotIn("pfctl -d", text, name)
                self.assertNotIn("userdel -r", text, name)


if __name__ == "__main__":
    unittest.main()
