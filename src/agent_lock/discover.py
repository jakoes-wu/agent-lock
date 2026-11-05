"""Find the mihomo mixed port. The controller secret is never placed in an error or a log line."""

import json
import os
import re
import socket
import sys
import urllib.parse

from .errors import AgentLockError, UsageError
from .state import proxy_url, secret_label

TIMEOUT = 3
MAX_BODY = 64 * 1024
PIPE_PREFIX = "\\\\.\\pipe\\"
VERGE_DIR = "io.github.clash-verge-rev.clash-verge-rev"
_STRING_FLAGS = ("d", "f", "ext-ctl", "ext-ctl-unix", "ext-ctl-pipe", "secret")
_CONTROLLER_FLAGS = ("ext-ctl", "ext-ctl-unix", "ext-ctl-pipe")
_CONFIG_KEY = re.compile(r"^(external-controller(?:-unix|-pipe)?|secret)\s*:(.*)$")
_LOOPBACK_BIND = ("127.0.0.1", "::1", "localhost")


class DiscoverFailure(AgentLockError):
    def __init__(self, message, secret=None, code=1):
        if secret:
            message = message.replace(secret, secret_label(secret))
        super(DiscoverFailure, self).__init__(message, code)


def read_secret_stdin(readline):
    """One line, trailing newline removed. Empty input is exit 2."""
    line = readline()
    if line is None:
        raise UsageError("empty secret on stdin")
    if line.endswith("\n"):
        line = line[:-1]
    if line.endswith("\r"):
        line = line[:-1]
    if line == "":
        raise UsageError("empty secret on stdin")
    if "\n" in line or "\r" in line:
        raise UsageError("secret must be a single line")
    return line


def effective_port(data):
    """mixed-port if it is a positive int, else port. SOCKS-only is an error."""
    if not isinstance(data, dict):
        raise DiscoverFailure("controller JSON was not an object")
    mixed = _positive_int(data.get("mixed-port"))
    if mixed:
        return mixed
    http_port = _positive_int(data.get("port"))
    if http_port:
        return http_port
    if _positive_int(data.get("socks-port")):
        raise DiscoverFailure("only a SOCKS port is open; Claude Code does not support SOCKS")
    raise DiscoverFailure("controller JSON has no mixed-port or port")


def _positive_int(value):
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    if value > 0:
        return value
    return 0


def check_lan_and_bind(data):
    if data.get("allow-lan") is True:
        raise DiscoverFailure("allow-lan is true; turn it off before installing")
    bind = data.get("bind-address")
    if bind is not None and str(bind) not in _LOOPBACK_BIND:
        raise DiscoverFailure("bind-address is not loopback ({})".format(bind))


def interpret_response(status, body, secret):
    """Return parsed JSON or raise. The body is never copied into the error."""
    if status == 401:
        raise DiscoverFailure("needs a secret", secret=secret)
    if status is None:
        raise DiscoverFailure("controller unreachable", secret=secret)
    if status != 200:
        raise DiscoverFailure("controller returned HTTP {}".format(status), secret=secret)
    try:
        if isinstance(body, bytes):
            text = body.decode("utf-8", "replace")
        else:
            text = body or ""
        data = json.loads(text)
    except ValueError:
        raise DiscoverFailure("controller did not return JSON", secret=secret)
    if secret and isinstance(body, str) and secret in body:
        # Parsed data may contain the secret echoed by a broken controller.
        # Callers must not log `data` verbatim. Port selection does not.
        pass
    return data


def _is_fatal(text):
    return text.startswith((
        "allow-lan",
        "bind-address",
        "only a SOCKS",
        "refusing the external-controller",
    ))


def log_line(address, source, detail):
    """A controller log line: address, source, and mixed-port. No secret."""
    return "{} ({}) {}".format(address, source, detail)


def parse_flags(args):
    """Four flag spellings: -name value, -name=value, --name value, --name=value."""
    flags = {}
    index = 0
    while index < len(args):
        token = args[index]
        index += 1
        if not token.startswith("-") or token in ("-", "--"):
            continue
        name = token[2:] if token.startswith("--") else token[1:]
        if "=" in name:
            name, value = name.split("=", 1)
            if name in _STRING_FLAGS:
                flags[name] = value
        elif name in _STRING_FLAGS and index < len(args):
            flags[name] = args[index]
            index += 1
    return flags


def _is_loopback(host):
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        import ipaddress
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def normalize_tcp(value):
    """Return (display, host, port) or None when the address is not local."""
    try:
        parts = urllib.parse.urlsplit("//" + value)
        port = parts.port
        host = parts.hostname or ""
    except ValueError:
        return None
    if port is None:
        return None
    if host in ("", "0.0.0.0"):
        host = "127.0.0.1"
    elif host == "::":
        host = "::1"
    if not _is_loopback(host):
        return None
    if ":" in host:
        display = "[{}]:{}".format(host, port)
    else:
        display = "{}:{}".format(host, port)
    return display, host, port


class Candidate(object):
    def __init__(self, address, secret, source, kind):
        self.address = address
        self.secret = secret or ""
        self.source = source
        self.kind = kind  # tcp, unix, pipe


def collect_candidates(argv_list, read_text, owner_home, mihomo_home, verge_paths):
    """Ordered candidates. Unix and pipes carry no secret into state."""
    found = []
    seen = set()

    def add(candidate):
        key = (candidate.kind, candidate.address)
        if key in seen:
            return
        seen.add(key)
        found.append(candidate)

    for argv in argv_list or []:
        if not argv:
            continue
        flags = parse_flags(argv[1:])
        program = os.path.basename(str(argv[0]).replace("\\", "/")).lower()
        if "mihomo" not in program and "clash" not in program and not any(
                name in flags for name in _CONTROLLER_FLAGS):
            continue
        source = "process " + (os.path.basename(str(argv[0]).replace("\\", "/")) or str(argv[0]))
        home = flags.get("d")
        if home is not None and not os.path.isabs(home):
            home = None
        flag_secret = flags.get("secret")
        file_secret = ""
        config_path = None
        if "f" in flags and os.path.isabs(flags["f"]):
            config_path = flags["f"]
        elif home is not None:
            config_path = os.path.join(home, "config.yaml")
        if config_path:
            file_secret = _collect_config(add, config_path, home, flag_secret, source + " config", read_text)
        if "ext-ctl-unix" in flags:
            _add_unix(add, flags["ext-ctl-unix"], home, source)
        if "ext-ctl-pipe" in flags:
            add(Candidate(flags["ext-ctl-pipe"], "", source, "pipe"))
        if "ext-ctl" in flags:
            secret = flag_secret if flag_secret is not None else file_secret
            parsed = normalize_tcp(flags["ext-ctl"])
            if parsed:
                _display, host, port = parsed
                add(Candidate(_tcp_address(host, port), secret, source, "tcp"))
    for path in verge_paths or []:
        if read_text(path) is not None:
            _collect_config(add, path, os.path.dirname(path), None, "config " + path, read_text)
    if mihomo_home:
        sock = os.path.join(mihomo_home, "mihomo.sock")
        add(Candidate("unix:" + sock, "", "mihomo-cli socket", "unix"))
    return found


def _tcp_address(host, port):
    if ":" in host:
        return "http://[{}]:{}".format(host, port)
    return "http://{}:{}".format(host, port)


def _add_unix(add, path, home, source):
    if not os.path.isabs(path):
        if not home:
            return
        path = os.path.join(home, path)
    add(Candidate("unix:" + path, "", source, "unix"))


def _collect_config(add, path, home, secret_override, source, read_text):
    text = read_text(path)
    values = _read_config_text(text)
    if values is None:
        return ""
    file_secret = values.get("secret", "")
    if values.get("external-controller-unix"):
        _add_unix(add, values["external-controller-unix"], home, source)
    if values.get("external-controller-pipe"):
        add(Candidate(values["external-controller-pipe"], "", source, "pipe"))
    if values.get("external-controller"):
        parsed = normalize_tcp(values["external-controller"])
        if parsed:
            _display, host, port = parsed
            secret = secret_override if secret_override is not None else file_secret
            add(Candidate(_tcp_address(host, port), secret, source, "tcp"))
    return file_secret


def _read_config_text(text):
    if text is None:
        return None
    values = {}
    for line in text.splitlines():
        match = _CONFIG_KEY.match(line)
        if match and match.group(1) not in values:
            values[match.group(1)] = _yaml_scalar(match.group(2))
    return values


def _yaml_scalar(raw):
    text = raw.strip()
    if text[:1] == '"':
        out = []
        index = 1
        while index < len(text) and text[index] != '"':
            if text[index] == "\\" and index + 1 < len(text):
                index += 1
            out.append(text[index])
            index += 1
        return "".join(out)
    if text[:1] == "'":
        out = []
        index = 1
        while index < len(text):
            if text[index] == "'":
                if text[index + 1:index + 2] != "'":
                    break
                index += 1
            out.append(text[index])
            index += 1
        return "".join(out)
    if text.startswith("#"):
        return ""
    return text.split(" #", 1)[0].strip()


def verge_paths(owner_home, appdata):
    """macOS and Windows Verge paths only. Linux is not guessed. Root skips /root."""
    if sys.platform == "darwin" and owner_home:
        return [os.path.join(owner_home, "Library", "Application Support", VERGE_DIR, "config.yaml")]
    if sys.platform == "win32" and appdata:
        return [os.path.join(appdata, VERGE_DIR, "config.yaml")]
    return []


def mihomo_home(owner_home, environ):
    """MIHOMO_CLI_HOME only when already in the environment. Otherwise the owner home."""
    explicit = (environ or {}).get("MIHOMO_CLI_HOME")
    if explicit:
        return explicit
    if not owner_home:
        return None
    return os.path.join(owner_home, ".local", "share", "mihomo-cli")


def controller_port(address):
    """TCP port of an http controller, or None for unix and pipes."""
    if not address or not address.startswith("http://"):
        return None
    try:
        parts = urllib.parse.urlsplit(address)
        return parts.port
    except ValueError:
        return None


def select_port(data, controller_address):
    port = effective_port(data)
    check_lan_and_bind(data)
    managed = controller_port(controller_address)
    if managed is not None and port == managed:
        raise DiscoverFailure("refusing the external-controller port as the proxy")
    return port


def probe_candidate(candidate, fetch):
    """fetch(address, secret) -> (status, body). Errors do not include the secret."""
    secret = candidate.secret if candidate.kind == "tcp" else ""
    try:
        status, body = fetch(candidate.address, secret)
    except DiscoverFailure:
        raise
    except Exception as exc:
        message = "controller unreachable"
        # Do not attach the exception text if it swallowed the secret.
        if secret and secret in str(exc):
            raise DiscoverFailure(message, secret=secret)
        detail = str(exc)
        if secret and secret in detail:
            detail = detail.replace(secret, secret_label(secret))
        raise DiscoverFailure("{}: {}".format(message, detail), secret=secret)
    try:
        data = interpret_response(status, body, secret)
    except DiscoverFailure as exc:
        text = str(exc)
        if text == "needs a secret":
            return None, log_line(candidate.address, candidate.source, "needs a secret")
        if _is_fatal(text):
            raise
        return None, log_line(candidate.address, candidate.source, text)
    try:
        port = select_port(data, candidate.address)
    except DiscoverFailure as exc:
        text = str(exc)
        if _is_fatal(text):
            raise
        return None, log_line(candidate.address, candidate.source, text)
    # Unix and pipe candidates do not keep a file secret.
    kept_secret = secret if candidate.kind == "tcp" else ""
    return {
        "port": port,
        "proxy": proxy_url(port),
        "controller": candidate.address,
        "secret": kept_secret,
        "source": candidate.source,
    }, log_line(candidate.address, candidate.source, "mixed-port={}".format(port))


def controller_candidate(text, secret):
    """One explicit --controller value. Loopback TCP, or a unix: path."""
    raw = (text or "").strip()
    if not raw:
        raise UsageError("--controller needs a value")
    if raw.startswith("unix:"):
        return Candidate(raw, "", "--controller", "unix")
    if "://" not in raw:
        raw = "http://" + raw
    parts = urllib.parse.urlsplit(raw)
    host = parts.hostname
    port = parts.port
    if host is None or port is None:
        raise UsageError("controller must be host:port or unix:PATH")
    if not _is_loopback(host):
        raise UsageError("controller must be loopback")
    return Candidate(raw, secret or "", "--controller", "tcp")


def _port_only(port, note):
    return {
        "port": int(port),
        "proxy": proxy_url(port),
        "controller": "",
        "secret": "",
        "source": "--port",
        "logs": [note],
    }


def choose_port(forced_port, explicit_controller, candidates, fetch):
    """Pick the mixed port.

    An explicit --controller must succeed. Without one, --port is the fallback
    when nothing answers. A successful read that disagrees with --port does not
    install. allow-lan, a bad bind, SOCKS-only, and the controller port stay fatal.
    """
    if explicit_controller and not candidates:
        raise DiscoverFailure("controller was not readable")
    if not candidates:
        if forced_port is None:
            raise DiscoverFailure(
                "could not read /configs; pass --port, or --controller and --secret-stdin")
        return _port_only(forced_port, "warning: using --port; controller was not found")
    try:
        return discover(candidates, fetch, forced_port=forced_port)
    except DiscoverFailure as exc:
        text = str(exc)
        fallback = (
            forced_port is not None
            and not explicit_controller
            and not _is_fatal(text)
            and "does not match" not in text
        )
        if not fallback:
            raise
        return _port_only(forced_port, "warning: " + text)


def discover(candidates, fetch, forced_port=None):
    """Try candidates in order. The first JSON with a usable port wins.

    Logs are a list of strings safe to print. `forced_port` cross-checks.
    """
    logs = []
    winner = None
    for candidate in candidates:
        found, line = probe_candidate(candidate, fetch)
        logs.append(line)
        if found is not None and winner is None:
            winner = found
            break
    if winner is None:
        raise DiscoverFailure(
            "could not read /configs; pass --port, or --controller and --secret-stdin")
    if forced_port is not None and int(forced_port) != int(winner["port"]):
        raise DiscoverFailure(
            "--port {} does not match controller mixed-port {}".format(forced_port, winner["port"]))
    winner["logs"] = logs
    return winner


def http_get(address, secret, timeout=TIMEOUT, max_body=MAX_BODY):
    """GET /configs. Returns (status, body). Raises DiscoverFailure without the secret."""
    try:
        if address.startswith("unix:"):
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect(address[len("unix:"):])
            host_header = "localhost"
        elif address.lower().startswith(PIPE_PREFIX.lower()) or address.startswith("\\\\.\\pipe\\"):
            raise DiscoverFailure("named pipe controllers are not readable from this process", secret=secret)
        else:
            parts = urllib.parse.urlsplit(address)
            host = parts.hostname
            port = parts.port
            if host is None or port is None:
                raise DiscoverFailure("controller address has no host or port", secret=secret)
            sock = socket.create_connection((host, port), timeout)
            host_header = host
        try:
            header = "GET /configs HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n".format(host_header)
            if secret:
                header += "Authorization: Bearer {}\r\n".format(secret)
            header += "\r\n"
            sock.sendall(header.encode("ascii", "strict"))
            chunks = []
            remaining = max_body + 8192
            while remaining > 0:
                block = sock.recv(min(4096, remaining))
                if not block:
                    break
                chunks.append(block)
                remaining -= len(block)
        finally:
            sock.close()
    except DiscoverFailure:
        raise
    except Exception as exc:
        text = str(exc)
        if secret and secret in text:
            text = text.replace(secret, secret_label(secret))
        raise DiscoverFailure("controller unreachable: {}".format(text), secret=secret)
    raw = b"".join(chunks)
    if len(raw) > max_body + 8192:
        raw = raw[:max_body + 8192]
    header_blob, _sep, body = raw.partition(b"\r\n\r\n")
    if not header_blob.startswith(b"HTTP/"):
        raise DiscoverFailure("controller did not return HTTP", secret=secret)
    first = header_blob.split(b"\r\n", 1)[0].decode("ascii", "replace")
    parts = first.split()
    if len(parts) < 2 or not parts[1].isdigit():
        raise DiscoverFailure("controller returned an unreadable status", secret=secret)
    status = int(parts[1])
    if len(body) > max_body:
        body = body[:max_body]
    return status, body


def default_fetch(address, secret):
    return http_get(address, secret)
