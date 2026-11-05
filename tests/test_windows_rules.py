"""Windows Block rules. No keywords, no Block of the proxy, stored names only."""

import unittest

import support

from agent_lock.windows import (
    REMOTE_KEYWORDS,
    build_rules,
    create_profile_script,
    link_plan,
    port_contains,
    render_rule_script,
    rule_covers_proxy,
    uninstall_commands,
)

support.install = None


class WindowsRuleTest(unittest.TestCase):
    def test_rules_do_not_block_the_proxy(self):
        rules = build_rules(7897, [], "S-1-5-21-1")
        script = render_rule_script(rules)
        for keyword in REMOTE_KEYWORDS:
            self.assertNotIn(keyword, script)
        self.assertNotIn("-Action Allow", script)
        for rule in rules:
            self.assertEqual(rule["action"], "Block")
            self.assertFalse(rule_covers_proxy(rule, 7897))
        joined = " ".join(rule["remote_port"] or "" for rule in rules)
        self.assertIn("1-7896", joined)
        self.assertIn("7898-65535", joined)

    def test_empty_ranges_omitted(self):
        for port in (1, 65535):
            rules = build_rules(port, [], "S-1-5-21-1")
            for rule in rules:
                self.assertFalse(rule_covers_proxy(rule, port), rule["name"])
                spec = rule["remote_port"]
                if spec:
                    self.assertFalse(port_contains(spec, port), spec)
            ports = [rule["remote_port"] for rule in rules if rule["remote_port"]]
            self.assertTrue(ports)
            if port == 1:
                self.assertFalse(any(item.startswith("1-") for item in ports))
            if port == 65535:
                self.assertFalse(any(item.endswith("-65535") for item in ports))

    def test_extra_punches_only_that_family(self):
        rules = build_rules(7897, ["127.0.0.1:11434"], "S-1-5-21-1")
        v4 = " ".join(rule["remote_port"] or "" for rule in rules if rule["name"].startswith("agent-lock-lo-tcp"))
        v6 = " ".join(rule["remote_port"] or "" for rule in rules if rule["name"].startswith("agent-lock-lo6-tcp"))
        self.assertNotIn("11434", v4)
        self.assertNotIn("11434", v6)
        self.assertIn("11435-65535", v4)
        self.assertIn("7898-65535", v6)

    def test_create_profile_script_before_junctions(self):
        script = create_profile_script("S-1-5-21-9")
        self.assertIn("userenv.dll", script)
        self.assertIn("CreateProfile", script)
        self.assertIn("S-1-5-21-9", script)
        self.assertNotIn("mklink", script)
        self.assertRaises(Exception, create_profile_script, "S-1-5-21-9'; calc")
        blocked = link_plan(False, [("C:\\Users\\agentnet\\.codex", "C:\\owner\\.codex")])
        self.assertIn("fail-profile", blocked)
        self.assertFalse(any(step.startswith("mklink") for step in blocked))
        ready = link_plan(True, [("C:\\Users\\agentnet\\.codex", "C:\\owner\\.codex")])
        self.assertLess(ready.index("CreateProfile"), ready.index("mklink /J C:\\Users\\agentnet\\.codex C:\\owner\\.codex"))

    def test_uninstall_deletes_only_stored_names(self):
        names = ["agent-lock-lo-udp", "agent-lock-v4-below-loopback"]
        commands = uninstall_commands(names)
        self.assertEqual(
            commands,
            [["Remove-NetFirewallRule", "-Name", name] for name in names],
        )
        blob = " ".join(" ".join(command) for command in commands)
        self.assertNotIn("-DisplayName", blob)
        self.assertNotIn("*", blob)


if __name__ == "__main__":
    unittest.main()
