"""Static checks for package metadata, release workflows, and the README."""

import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as handle:
        return handle.read()


class PackagingTest(unittest.TestCase):
    def test_version_and_project_metadata(self):
        project = read("pyproject.toml")
        self.assertIn('name = "agent-lock"', project)
        self.assertIn('agent-lock = "agent_lock.cli:main"', project)
        self.assertIn('requires-python = ">=3.8"', project)
        self.assertIn("Changelog = ", project)
        self.assertIn("Issues = ", project)
        self.assertIn('__version__ = "0.1.0"', read("src/agent_lock/__init__.py"))
        self.assertIn("Copyright (c) 2026 agent-lock contributors", read("LICENSE"))
        self.assertIn("[0.1.0] - 2026-11-05", read("CHANGELOG.md"))

    def test_release_workflow_uses_the_tag_env(self):
        text = read(".github/workflows/release.yml")
        self.assertIn('prefix="agent-lock-${TAG}/"', text)
        self.assertIn('agent-lock-${TAG}.tar.gz', text)
        self.assertIn("SHA256SUMS", text)
        self.assertIn("src/agent_lock/__init__.py", text)
        self.assertIn("TAG:", text)
        run = text.split("- name: Build the source archive", 1)[1]
        self.assertNotIn("${{", run)

    def test_pypi_workflow_uses_trusted_publishing(self):
        text = read(".github/workflows/pypi.yml")
        self.assertIn("types: [published]", text)
        self.assertIn("workflow_dispatch:", text)
        self.assertIn("environment: pypi", text)
        self.assertIn("id-token: write", text)
        self.assertNotIn("PYPI_API_TOKEN", text)
        self.assertNotIn("password:", text)
        self.assertIn("dist/agent_lock-${version}-py3-none-any.whl", text)
        self.assertIn("dist/agent_lock-${version}.tar.gz", text)

    def test_readme_states_limits_and_completion(self):
        for name in ("README.md", "README.zh-CN.md"):
            text = read(name)
            self.assertIn("https://github.com/jakoes-wu/agent-lock", text, name)
            self.assertIn("pipx install agent-lock", text, name)
            self.assertIn("install.sh", text, name)
            self.assertIn(
                "The checksum detects a corrupted download. "
                "It does not prove the GitHub account was not compromised.",
                text,
                name,
            )
            self.assertIn("Homebrew", text, name)
            self.assertIn("0664", text, name)
            self.assertIn("setgid", text, name)
            self.assertIn("Unix domain sockets are not filtered.", text, name)
            self.assertIn("A human with the sudo password can undo the firewall.", text, name)
            self.assertIn("netcheck is not this tool.", text, name)
            self.assertIn("runas /user:agentnet", text, name)
            self.assertIn("second exit beside the proxy", text, name)
            self.assertIn('eval "$(agent-lock completion bash)"', text, name)
            self.assertIn('eval "$(agent-lock completion zsh)"', text, name)
            self.assertIn("agent-lock completion fish | source", text, name)
            self.assertIn(
                "agent-lock completion powershell | Out-String | Add-Content $PROFILE",
                text,
                name,
            )
        english = read("README.md")
        chinese = read("README.zh-CN.md")
        self.assertIn("README.zh-CN.md", english)
        self.assertIn("README.md", chinese)
        self.assertIn("CLAUDE_CODE_PROCESS_WRAPPER", english)
        self.assertIn("does not apply on Windows", english)


if __name__ == "__main__":
    unittest.main()
