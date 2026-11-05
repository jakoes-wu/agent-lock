"""--allow-tcp values. Only 127.0.0.1:PORT and ::1:PORT."""

import argparse
import re

_VALUE = re.compile(r"^(127\.0\.0\.1|::1):([0-9]+)$")


def parse_allow_tcp_value(value):
    """Return (host, port) or raise ValueError. Used by firewall renderers."""
    match = _VALUE.match(value or "")
    if not match:
        raise ValueError(value)
    port = int(match.group(2))
    if match.group(2) != str(port):
        # Reject leading zeros so the stored form is canonical.
        raise ValueError(value)
    if port < 1 or port > 65535:
        raise ValueError(value)
    return match.group(1), port


def allow_tcp_arg(value):
    """argparse type. Illegal values are exit 2."""
    try:
        host, port = parse_allow_tcp_value(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            "must be 127.0.0.1:PORT or ::1:PORT (port 1-65535), not {!r}".format(value))
    return "{}:{}".format(host, port)


def port_arg(value):
    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("port must be an integer")
    if str(port) != str(value).lstrip("+") or port < 1 or port > 65535:
        raise argparse.ArgumentTypeError("port must be 1-65535")
    return port
