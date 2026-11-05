"""Controller discovery must not echo a secret, including a 401 body."""

import unittest

import support

from agent_lock.discover import (
    Candidate,
    DiscoverFailure,
    choose_port,
    interpret_response,
    probe_candidate,
    read_secret_stdin,
)
from agent_lock.errors import UsageError

support.install = None

TOKEN = "SECRETTOKEN_401_BODY_9f3c"


class DiscoverTest(unittest.TestCase):
    def test_401_body_is_not_in_the_error_or_the_log(self):
        body = '{"authorization":"%s","mixed-port":7897}' % TOKEN
        with self.assertRaises(DiscoverFailure) as caught:
            interpret_response(401, body, TOKEN)
        self.assertNotIn(TOKEN, str(caught.exception))
        self.assertNotIn(TOKEN, repr(caught.exception))
        candidate = Candidate("http://127.0.0.1:9090", TOKEN, "test", "tcp")

        def fetch(_address, _secret):
            return 401, body

        found, line = probe_candidate(candidate, fetch)
        self.assertIsNone(found)
        self.assertNotIn(TOKEN, line)
        self.assertIn("needs a secret", line)

        def explode(_address, _secret):
            raise OSError("leaked " + TOKEN)

        with self.assertRaises(DiscoverFailure) as caught:
            probe_candidate(candidate, explode)
        self.assertNotIn(TOKEN, str(caught.exception))
        self.assertNotIn(TOKEN, repr(caught.exception))

    def test_port_fallback_and_mismatch(self):
        candidate = Candidate("http://127.0.0.1:9090", "", "test", "tcp")

        def down(_address, _secret):
            raise OSError("unreachable")

        found = choose_port(7897, False, [candidate], down)
        self.assertEqual(found["port"], 7897)
        self.assertEqual(found["secret"], "")
        with self.assertRaises(DiscoverFailure):
            choose_port(7897, True, [candidate], down)

        def ok(_address, _secret):
            return 200, '{"mixed-port": 7897, "allow-lan": false}'

        with self.assertRaises(DiscoverFailure) as caught:
            choose_port(1, False, [candidate], ok)
        self.assertIn("does not match", str(caught.exception))
        self.assertNotIn(TOKEN, str(caught.exception))

    def test_empty_secret_exits_2(self):
        with self.assertRaises(UsageError) as caught:
            read_secret_stdin(lambda: "\n")
        self.assertEqual(caught.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
