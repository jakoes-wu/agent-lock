"""--allow-tcp parsing and clear-on-reinstall."""

import unittest
from io import StringIO
from contextlib import redirect_stderr

import support

from agent_lock.allow import parse_allow_tcp_value
from agent_lock.cli import main
from agent_lock.state import apply_install_fields, extra_tcp_from_args

support.install = None


class AllowTest(unittest.TestCase):
    def test_legal_values(self):
        self.assertEqual(parse_allow_tcp_value("127.0.0.1:11434"), ("127.0.0.1", 11434))
        self.assertEqual(parse_allow_tcp_value("::1:1"), ("::1", 1))
        self.assertEqual(parse_allow_tcp_value("::1:65535"), ("::1", 65535))

    def test_illegal_values_exit_2(self):
        for value in ("10.1.1.1:80", "127.0.0.1:01", "127.0.0.1:0", "::1:65536", "localhost:80", ""):
            buf = StringIO()
            with redirect_stderr(buf):
                code = main(["install", "--allow-tcp", value])
            self.assertEqual(code, 2, value)

    def test_omitted_flag_clears(self):
        self.assertEqual(extra_tcp_from_args(None), [])
        self.assertEqual(extra_tcp_from_args([]), [])
        old = {"version": 1, "extra_tcp": ["127.0.0.1:9"], "port": 1, "secret": "keep"}
        updated = apply_install_fields(old, 7897, extra_tcp_from_args(None), None, None)
        self.assertEqual(updated["extra_tcp"], [])
        self.assertEqual(updated["port"], 7897)
        self.assertEqual(updated["secret"], "keep")
        again = apply_install_fields(updated, 7897, ["::1:9"], "http://127.0.0.1:9090", "s")
        self.assertEqual(again["extra_tcp"], ["::1:9"])


if __name__ == "__main__":
    unittest.main()
