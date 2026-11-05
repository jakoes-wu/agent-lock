"""Help examples: 2-4 each, <= 79 columns, and they parse."""

import argparse
import shlex
import unittest
from io import StringIO
from contextlib import redirect_stderr, redirect_stdout

import support

from agent_lock.cli import COMMAND_EXAMPLES, HELP_EXAMPLES, _examples_text, build_parser, main

support.install = None


class HelpTest(unittest.TestCase):
    def test_every_command_has_examples(self):
        parser = build_parser()
        names = set()
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                names = set(action.choices)
        self.assertEqual(set(COMMAND_EXAMPLES), names)
        self.assertEqual(len(names), 6)
        for name, examples in COMMAND_EXAMPLES.items():
            self.assertGreaterEqual(len(examples), 2, name)
            self.assertLessEqual(len(examples), 4, name)
            buf = StringIO()
            with redirect_stdout(buf), redirect_stderr(StringIO()):
                code = main([name, "-h"])
            self.assertEqual(code, 0, name)
            text = buf.getvalue()
            self.assertIn("examples:", text)
            self.assertIn(examples[0][0], text)

    def test_top_help(self):
        buf = StringIO()
        with redirect_stdout(buf), redirect_stderr(StringIO()):
            code = main(["-h"])
        self.assertEqual(code, 0)
        text = buf.getvalue()
        self.assertIn("examples:", text)
        self.assertIn("Run agent-lock COMMAND -h for more examples.", text)
        self.assertIn("Lock agent commands to the local HTTP proxy", text)

    def test_examples_fit_and_parse(self):
        parser = build_parser()
        self.assertFalse(parser.allow_abbrev)
        for line in HELP_EXAMPLES.splitlines():
            self.assertLessEqual(len(line), 79, line)
        for name, examples in COMMAND_EXAMPLES.items():
            rendered = _examples_text(examples)
            for line in rendered.splitlines():
                self.assertLessEqual(len(line), 79, line)
            sub = None
            for action in parser._actions:
                if isinstance(action, argparse._SubParsersAction):
                    sub = action.choices[name]
            self.assertFalse(sub.allow_abbrev)
            for command, _summary in examples:
                if command.startswith("eval ") or "|" in command:
                    if "completion bash" in command:
                        parser.parse_args(["completion", "bash"])
                    if "completion zsh" in command:
                        parser.parse_args(["completion", "zsh"])
                    if "completion fish" in command:
                        parser.parse_args(["completion", "fish"])
                    continue
                parts = shlex.split(command)
                if command.startswith("sudo agent-lock "):
                    self.assertEqual(parts[:2], ["sudo", "agent-lock"])
                    parsed = parts[2:]
                elif command.startswith("agent-lock "):
                    parsed = parts[1:]
                else:
                    self.fail(command)
                if "--" in parsed:
                    parsed = parsed[:parsed.index("--")]
                parser.parse_args(parsed)

    def test_allow_tcp_help_mentions_second_exit(self):
        buf = StringIO()
        with redirect_stdout(buf):
            main(["install", "-h"])
        self.assertIn("second exit beside the proxy", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
