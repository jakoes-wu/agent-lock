"""Completion scripts are generated from the parser."""

import shutil
import subprocess
import tempfile
import unittest
from io import StringIO
from contextlib import redirect_stdout

import support

from agent_lock.cli import build_parser, main
from agent_lock.completion import command_spec, script

support.install = None


class CompletionTest(unittest.TestCase):
    def setUp(self):
        self.parser = build_parser()
        self.scripts = {shell: script(shell, self.parser) for shell in ("bash", "zsh", "fish", "powershell")}
        self.spec = command_spec(self.parser)

    def test_contains_commands_and_options(self):
        for shell, text in self.scripts.items():
            for name in self.spec:
                self.assertIn(name, text, shell)
            for name, (options, _valued) in self.spec.items():
                for option in options:
                    if shell == "fish" and option.startswith("--"):
                        self.assertIn("-l " + option[2:], text, option)
                    elif shell == "fish" and option.startswith("-") and not option.startswith("--"):
                        self.assertIn("-s " + option[1:], text, option)
                    else:
                        self.assertIn(option, text, "{} {}".format(shell, option))

    def test_powershell_null_and_ascii(self):
        text = self.scripts["powershell"]
        self.assertTrue(all(ord(char) < 128 for char in text))
        self.assertIn("[System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)", text)
        self.assertNotIn("CompletionResult]::Null", text)
        self.assertEqual(text.count("return $null"), 4)
        self.assertIn("return $null", text)
        # Path positions bare-return and are listed before the $null returns.
        null_at = text.index("return $null")
        for option in ("--claude-dir", "--share-dir", "--trust-exec"):
            line = "if ($skip -and $lastOpt -eq '{}') {{ return }}".format(option)
            self.assertIn(line, text)
            self.assertLess(text.index(line), null_at)
        self.assertLess(text.index("bind-bin"), null_at)
        self.assertIn("-a '(__fish_complete_path)'", self.scripts["fish"])
        fish = self.scripts["fish"]
        self.assertIn("complete -c agent-lock -f\n", fish)
        for option in ("share-dir", "trust-exec", "claude-dir"):
            matched = [line for line in fish.splitlines() if "-l " + option in line]
            self.assertTrue(matched, option)
            self.assertIn("-r -F", matched[0])
        for option in ("port", "allow-tcp", "controller"):
            matched = [line for line in fish.splitlines() if "-l " + option in line]
            self.assertTrue(matched, option)
            self.assertNotIn("-F", matched[0])

    def test_bash_does_not_complete_files_by_default(self):
        bash = self.scripts["bash"]
        self.assertNotIn("-o default", bash)
        self.assertNotIn("compopt", bash)
        self.assertNotIn("COMP_WORDS", bash)
        self.assertNotIn("COMP_CWORD", bash)
        self.assertIn("COMP_LINE", bash)
        self.assertIn('complete -F _agent_lock agent-lock', bash)
        self.assertIn("--port|--allow-tcp|--controller", bash)
        self.assertIn("COMPREPLY=(); return 0", bash)

    def test_prints_without_being_installed(self):
        buf = StringIO()
        with redirect_stdout(buf):
            code = main(["completion", "bash"])
        self.assertEqual(code, 0)
        self.assertIn("_agent_lock", buf.getvalue())
        err = StringIO()
        from contextlib import redirect_stderr
        with redirect_stderr(err):
            code = main(["completion", "nope"])
        self.assertEqual(code, 2)

    def test_syntax(self):
        shells = (
            ("bash", ["bash", "-n"]),
            ("zsh", ["zsh", "-n"]),
            ("fish", ["fish", "--no-execute"]),
        )
        for shell, argv in shells:
            if not shutil.which(argv[0]):
                continue
            with tempfile.NamedTemporaryFile("w", suffix="." + shell) as handle:
                handle.write(self.scripts[shell])
                handle.flush()
                proc = subprocess.run(argv + [handle.name], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      universal_newlines=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()
