"""install.sh: local install, checksummed release downloads, recovery, uninstall."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INSTALL = os.path.join(ROOT, "install.sh")


class InstallTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="agent-lock-install-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.prefix = os.path.join(self.tmp, "prefix")
        self.env = dict(os.environ)
        self.env.pop("PYTHONPATH", None)
        self.env["AGENT_LOCK_TEST_MODE"] = "1"
        self.env["PATH"] = os.environ.get("PATH", "/usr/bin:/bin")

    def install(self, *args, env=None, script=INSTALL):
        full_env = dict(self.env)
        full_env.update(env or {})
        return subprocess.run(
            ["sh", script, "--prefix", self.prefix] + list(args),
            env=full_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )

    def tool(self, *args):
        return subprocess.run(
            [os.path.join(self.prefix, "bin", "agent-lock")] + list(args),
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )

    def make_tarball(self):
        path = os.path.join(self.tmp, "src.tar.gz")
        with tarfile.open(path, "w:gz") as archive:
            for name in ("src", "install.sh", "README.md"):
                full = os.path.join(ROOT, name)
                if os.path.exists(full):
                    archive.add(
                        full,
                        arcname=os.path.join("agent-lock-main", name),
                        filter=lambda info: None if "__pycache__" in info.name else info,
                    )
        return path

    def snapshot(self, root):
        found = {}
        if not os.path.isdir(root):
            return found
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(name for name in dirnames if name != "__pycache__")
            for name in sorted(filenames):
                if name.endswith(".pyc"):
                    continue
                path = os.path.join(dirpath, name)
                with open(path, "rb") as handle:
                    found[os.path.relpath(path, root)] = hashlib.sha256(handle.read()).hexdigest()
        return found

    def test_local_install_is_idempotent(self):
        first = self.install()
        self.assertEqual(first.returncode, 0, first.stderr)
        second = self.install()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(second.stdout.count("unchanged"), 2, second.stdout)
        self.assertEqual(self.tool("--version").returncode, 0)
        self.assertIn("0.1.0", self.tool("--version").stdout)

    def test_version_manager_shim_is_resolved(self):
        shims = os.path.join(self.tmp, "pyenv", "shims")
        os.makedirs(shims)
        shim = os.path.join(shims, "python3")
        with open(shim, "w") as handle:
            handle.write('#!/bin/sh\nexec "{}" "$@"\n'.format(sys.executable))
        os.chmod(shim, 0o755)
        real = subprocess.run(
            [sys.executable, "-c", "import sys; print(sys.executable)"],
            stdout=subprocess.PIPE,
            universal_newlines=True,
        ).stdout.strip()
        result = self.install(env={"PATH": shims + os.pathsep + self.env["PATH"]})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("instead of the shim", result.stdout)
        with open(os.path.join(self.prefix, "bin", "agent-lock")) as handle:
            wrapper = handle.read()
        self.assertIn("exec '{}' -m agent_lock".format(real), wrapper)
        self.assertNotIn("/shims/", wrapper)
        self.assertEqual(self.tool("--version").returncode, 0)

    def test_path_hint_names_the_shell_profile(self):
        expected = {
            "/bin/zsh": ">> ~/.zshrc",
            "/bin/bash": ">> ~/.bash_profile" if sys.platform == "darwin" else ">> ~/.bashrc",
            "/usr/bin/fish": "fish_add_path '{}'".format(os.path.join(self.prefix, "bin")),
            "": "add it in your shell profile",
        }
        for shell, text in expected.items():
            with self.subTest(shell=shell):
                result = self.install(env={"SHELL": shell})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("is not on PATH", result.stdout)
                self.assertIn(text, result.stdout)

    def test_remote_install_from_tarball(self):
        script = os.path.join(self.tmp, "install.sh")
        shutil.copy(INSTALL, script)
        result = self.install(env={"AGENT_LOCK_TARBALL": "file://" + self.make_tarball()}, script=script)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("downloading", result.stdout)
        self.assertEqual(self.tool("--version").returncode, 0)

    def test_no_release_without_ref(self):
        script = os.path.join(self.tmp, "install.sh")
        shutil.copy(INSTALL, script)
        env = {"AGENT_LOCK_API": "file://" + os.path.join(self.tmp, "no-api")}
        result = self.install(env=env, script=script)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("AGENT_LOCK_REF", result.stderr)

    def test_interrupted_swap_recovers(self):
        self.assertEqual(self.install().returncode, 0)
        package = os.path.join(self.prefix, "share", "agent-lock", "agent_lock", "__init__.py")
        with open(package, "a") as handle:
            handle.write("# older\n")
        normal = self.install(env={"AGENT_LOCK_TEST_CRASH_SWAP": "1", "AGENT_LOCK_TEST_MODE": "0"})
        self.assertEqual(normal.returncode, 0, normal.stderr)
        with open(package, "a") as handle:
            handle.write("# older\n")
        crashed = self.install(env={"AGENT_LOCK_TEST_CRASH_SWAP": "1"})
        self.assertEqual(crashed.returncode, 137)
        self.assertTrue(os.path.isdir(os.path.join(self.prefix, "share", "agent-lock.old")))
        recovered = self.install()
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.prefix, "share", "agent-lock.old")))
        self.assertEqual(self.tool("--version").returncode, 0)

    def test_stale_old_dir_is_removed(self):
        self.assertEqual(self.install().returncode, 0)
        stale = os.path.join(self.prefix, "share", "agent-lock.old")
        os.makedirs(stale)
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(os.path.exists(stale))

    def test_piped_install_ignores_clone_in_current_directory(self):
        with open(INSTALL) as handle:
            script = handle.read()
        env = dict(self.env)
        env["AGENT_LOCK_API"] = "file://" + os.path.join(self.tmp, "no-api")
        proc = subprocess.run(
            ["sh", "-s", "--", "--prefix", self.prefix],
            input=script,
            env=env,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("AGENT_LOCK_REF", proc.stderr)

    def test_uninstall_removes_only_the_command(self):
        self.assertEqual(self.install().returncode, 0)
        result = self.install("--uninstall")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.prefix, "bin", "agent-lock")))
        self.assertFalse(os.path.isdir(os.path.join(self.prefix, "share", "agent-lock")))
        again = self.install("--uninstall")
        self.assertIn("unchanged", again.stdout)

    def test_help_and_bad_arguments(self):
        help_result = subprocess.run(
            ["sh", INSTALL, "--help"], stdout=subprocess.PIPE, universal_newlines=True)
        self.assertEqual(help_result.returncode, 0)
        self.assertIn("--prefix", help_result.stdout)
        self.assertIn("--uninstall", help_result.stdout)
        self.assertNotIn("--config", help_result.stdout)
        bad = subprocess.run(
            ["sh", INSTALL, "--bogus"], stderr=subprocess.PIPE, universal_newlines=True)
        self.assertNotEqual(bad.returncode, 0)

    @unittest.skipUnless(shutil.which("shellcheck"), "shellcheck is not installed")
    def test_shellcheck(self):
        proc = subprocess.run(
            ["shellcheck", "-s", "sh", INSTALL], stdout=subprocess.PIPE, universal_newlines=True)
        self.assertEqual(proc.returncode, 0, proc.stdout)


class ChecksumTest(unittest.TestCase):
    """Release assets are fetched and checked with file:// URLs. Nothing is published."""

    REPO = "jakoes-wu/agent-lock"
    TAG = "v9.9.9"

    def setUp(self):
        self.install_case = InstallTest()
        self.install_case.setUp()
        self.addCleanup(self.install_case.doCleanups)
        self.install = self.install_case.install
        self.tool = self.install_case.tool
        self.make_tarball = self.install_case.make_tarball
        self.snapshot = self.install_case.snapshot
        self.prefix = self.install_case.prefix
        self.env = self.install_case.env
        self.tmp = self.install_case.tmp
        self.script = os.path.join(self.tmp, "install.sh")
        shutil.copy(INSTALL, self.script)
        self.api = os.path.join(self.tmp, "api")
        self.codeload = os.path.join(self.tmp, "codeload")
        self.assets = os.path.join(self.tmp, "assets")
        os.makedirs(self.assets)
        self.tarball = self.make_tarball()
        self.asset_name = "agent-lock-{}.tar.gz".format(self.TAG)
        shutil.copy(self.tarball, os.path.join(self.assets, self.asset_name))
        with open(self.tarball, "rb") as handle:
            self.sha = hashlib.sha256(handle.read()).hexdigest()
        self.env["AGENT_LOCK_API"] = "file://" + self.api
        self.env["AGENT_LOCK_CODELOAD"] = "file://" + self.codeload

    def write(self, path, text):
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w") as handle:
            handle.write(text)
        return path

    def release(self, endpoint, with_assets=True, sums=None):
        assets = []
        if with_assets:
            sums_path = os.path.join(self.assets, "SHA256SUMS")
            self.write(sums_path, sums if sums is not None else "{}  {}\n".format(self.sha, self.asset_name))
            assets = [
                {"name": self.asset_name,
                 "browser_download_url": "file://" + os.path.join(self.assets, self.asset_name)},
                {"name": "SHA256SUMS", "browser_download_url": "file://" + sums_path},
            ]
        self.write(
            os.path.join(self.api, "repos", self.REPO, "releases", endpoint),
            json.dumps({"tag_name": self.TAG, "assets": assets}),
        )

    def run_install(self, env=None):
        return self.install(env=env, script=self.script)

    def test_verified_install(self):
        self.release("latest")
        result = self.run_install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("verified sha256 " + self.sha, result.stdout)
        self.assertEqual(self.tool("--version").returncode, 0)

    def test_mismatch_leaves_installation_alone(self):
        self.assertEqual(self.install().returncode, 0)
        share = os.path.join(self.prefix, "share", "agent-lock")
        before = self.snapshot(share)
        self.release("latest", sums="{}  {}\n".format("0" * 64, self.asset_name))
        result = self.run_install()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("checksum mismatch", result.stderr)
        self.assertEqual(before, self.snapshot(share))

    def test_missing_entry(self):
        self.release("latest", sums="{}  other.tar.gz\n".format(self.sha))
        result = self.run_install()
        self.assertEqual(result.returncode, 1)
        self.assertIn("no entry", result.stderr)

    def test_binary_mode_sums(self):
        self.release("latest", sums="{} *{}\n".format(self.sha, self.asset_name))
        self.assertIn("verified sha256", self.run_install().stdout)
        self.release("latest", sums="{} *{}\n".format(self.sha.upper(), self.asset_name))
        self.assertIn("verified sha256", self.run_install().stdout)

    def test_release_without_assets(self):
        self.release("latest", with_assets=False)
        tar_dir = os.path.join(self.codeload, self.REPO, "tar.gz")
        os.makedirs(tar_dir)
        shutil.copy(self.tarball, os.path.join(tar_dir, self.TAG))
        result = self.run_install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("is not verified", result.stdout)
        result = self.run_install(env={"AGENT_LOCK_REQUIRE_CHECKSUM": "1"})
        self.assertEqual(result.returncode, 1)

    def test_refs(self):
        self.release("tags/" + self.TAG)
        result = self.run_install(env={"AGENT_LOCK_REF": self.TAG})
        self.assertIn("verified sha256", result.stdout, result.stderr)
        result = self.run_install(env={"AGENT_LOCK_REF": "v8.8.8"})
        self.assertEqual(result.returncode, 1)
        self.assertIn("cannot read release v8.8.8", result.stderr)
        tar_dir = os.path.join(self.codeload, self.REPO, "tar.gz")
        os.makedirs(tar_dir, exist_ok=True)
        for branch in ("main", "v2-dev"):
            with self.subTest(branch=branch):
                shutil.copy(self.tarball, os.path.join(tar_dir, branch))
                result = self.run_install(env={"AGENT_LOCK_REF": branch})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("is not verified", result.stdout)

    def test_tarball_with_expected_sha(self):
        env = {"AGENT_LOCK_TARBALL": "file://" + self.tarball}
        verified = self.run_install(env=dict(env, AGENT_LOCK_SHA256=self.sha.upper()))
        self.assertIn("verified sha256", verified.stdout, verified.stderr)
        self.assertEqual(self.run_install(env=dict(env, AGENT_LOCK_SHA256="0" * 64)).returncode, 1)
        self.assertEqual(self.run_install(env=dict(env, AGENT_LOCK_REQUIRE_CHECKSUM="1")).returncode, 1)

    def test_piped_install_with_assets(self):
        self.release("latest")
        with open(INSTALL) as handle:
            script = handle.read()
        proc = subprocess.run(
            ["sh", "-s", "--", "--prefix", self.prefix],
            input=script,
            env=self.env,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("verified sha256", proc.stdout)


if __name__ == "__main__":
    unittest.main()
