"""bind-bin mode math. Does not chown or chmod anything."""

import stat
import unittest

import support

from agent_lock.linux import bind_bin_mode, validate_bind_bin

support.install = None


class BindBinTest(unittest.TestCase):
    def test_mode_math(self):
        self.assertEqual(bind_bin_mode(0o775), 0o2755)
        self.assertEqual(bind_bin_mode(0o755), 0o2755)
        self.assertEqual(bind_bin_mode(0o700), 0o2750)
        mode = bind_bin_mode(0o775)
        self.assertTrue(mode & stat.S_ISGID)
        self.assertFalse(mode & stat.S_IWGRP)
        self.assertTrue(mode & stat.S_IRGRP)
        self.assertTrue(mode & stat.S_IXGRP)

    def test_validate_before_mutation(self):
        code, message = validate_bind_bin(1, False, True, 10, 10)
        self.assertEqual(code, 1)
        self.assertIn("sudo", message)
        code, _message = validate_bind_bin(0, True, True, 10, 10)
        self.assertEqual(code, 2)
        code, _message = validate_bind_bin(0, False, False, 10, 10)
        self.assertEqual(code, 2)
        code, _message = validate_bind_bin(0, False, True, 11, 10)
        self.assertEqual(code, 1)
        code, message = validate_bind_bin(0, False, True, 10, 10)
        self.assertEqual(code, 0)
        self.assertEqual(message, "")


if __name__ == "__main__":
    unittest.main()
