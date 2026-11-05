"""nftables text, user plan, and firewalld exit 4. Does not load a ruleset."""

import shutil
import subprocess
import tempfile
import unittest

import support

from agent_lock.errors import Unsupported
from agent_lock.linux import (
    NOLOGIN,
    firewalld_is_active,
    render_nft,
    render_unit,
    require_firewalld_inactive,
    setfacl_commands,
    user_plan,
)
from agent_lock.state import AGENT_USER

support.install = None


class _Result(object):
    def __init__(self, code, out):
        self.returncode = code
        self.stdout = out
        self.stderr = ""


class NftTest(unittest.TestCase):
    def test_empty_extra_has_three_counters_then_drop(self):
        text = render_nft(1000, 7897, [])
        self.assertTrue(text.startswith("destroy table inet agentlock\n"))
        chain = text.index("chain output")
        for name in ("agentlock_accept_v4", "agentlock_accept_v6", "agentlock_drop"):
            declared = text.index("counter {} {{".format(name))
            self.assertLess(declared, chain)
        accept_v4 = text.index("counter name agentlock_accept_v4 accept")
        accept_v6 = text.index("counter name agentlock_accept_v6 accept")
        drop = text.index("counter name agentlock_drop drop")
        self.assertLess(accept_v4, accept_v6)
        self.assertLess(accept_v6, drop)
        self.assertNotIn("agentlock_accept_v4_", text)
        self.assertNotIn("agentlock_accept_v6_", text)
        self.assertIn("meta skuid 1000", text)
        self.assertIn("tcp dport 7897", text)

    def test_extra_counters_before_use(self):
        text = render_nft(5, 7897, ["127.0.0.1:11434", "::1:11434"])
        chain = text.index("chain output")
        for name in ("agentlock_accept_v4_11434", "agentlock_accept_v6_11434"):
            self.assertLess(text.index("counter {} {{".format(name)), chain)
            self.assertLess(chain, text.index("counter name {} accept".format(name)))
        drop = text.index("counter name agentlock_drop drop")
        self.assertLess(text.index("dport 11434"), drop)
        self.assertLess(text.index("dport 7897"), text.index("dport 11434"))

    def test_unit_order(self):
        text = render_unit("/usr/sbin/nft", "/etc/agent-lock/nftables.conf")
        self.assertIn("Before=systemd-user-sessions.service", text)
        self.assertIn("After=nftables.service ufw.service firewalld.service", text)
        self.assertIn("ExecStart=/usr/sbin/nft -f /etc/agent-lock/nftables.conf", text)

    def test_firewalld_exit_4(self):
        def active(_argv, **_kwargs):
            return _Result(0, "active\n")

        def inactive(_argv, **_kwargs):
            return _Result(3, "inactive\n")

        self.assertTrue(firewalld_is_active(active))
        self.assertFalse(firewalld_is_active(inactive))
        with self.assertRaises(Unsupported) as caught:
            require_firewalld_inactive(active)
        self.assertEqual(caught.exception.code, 4)

    def test_user_plan_locks_only_new_accounts(self):
        commands, created = user_plan(True, True, True, "/bin/sh")
        self.assertFalse(created)
        self.assertEqual(commands, [["usermod", "--shell", NOLOGIN, AGENT_USER]])
        commands, created = user_plan(True, True, True, NOLOGIN)
        self.assertEqual(commands, [])
        commands, created = user_plan(False, False, True, "")
        self.assertTrue(created)
        self.assertNotIn("--create-home", commands[0])
        self.assertEqual(commands[-1], ["passwd", "-l", AGENT_USER])
        commands, created = user_plan(False, True, False, "")
        self.assertIn("--create-home", commands[0])
        self.assertIn("--gid", commands[0])

    def test_setfacl_has_no_default_acl(self):
        commands = setfacl_commands([("dir", "dir"), ("file", "file"), ("parent", "parent")])
        blob = "\n".join(" ".join(command) for command in commands)
        self.assertNotIn(" -d", " " + blob)
        self.assertIn("m::rwX", blob)
        self.assertIn("m::rw-", blob)
        self.assertIn("m::--x", blob)

    @unittest.skipUnless(shutil.which("nft"), "nft is not installed")
    def test_nft_check_only(self):
        text = render_nft(1000, 7897, ["127.0.0.1:11434"])
        with tempfile.NamedTemporaryFile("w", suffix=".nft") as handle:
            handle.write(text)
            handle.flush()
            proc = subprocess.run(
                ["nft", "-c", "-f", handle.name],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()
