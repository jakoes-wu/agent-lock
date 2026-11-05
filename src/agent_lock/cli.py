"""agent-lock command line. Help text and examples come from this module."""

import argparse
import sys

from . import __version__
from .allow import allow_tcp_arg, port_arg
from .completion import SHELLS, script
from .errors import AgentLockError
from .install import cmd_bind_bin, cmd_doctor, cmd_exec, cmd_install, cmd_uninstall

COMMAND_GROUPS = (
    ("Setup", (
        ("install", "install the account, firewall, and wrappers"),
        ("uninstall", "remove the lock and keep linked directories"),
        ("bind-bin", "mark a directory setgid for new launchers"),
        ("completion", "print a shell completion script"),
    )),
    ("Everyday", (
        ("doctor", "check the lock and repair cleared ACLs"),
        ("exec", "run one command as agentnet"),
    )),
)
COMMAND_SUMMARY = {name: summary for _title, commands in COMMAND_GROUPS for name, summary in commands}

TOP_EXAMPLES = (
    ("agent-lock install", "install the lock"),
    ("agent-lock doctor", "check the lock"),
    ("agent-lock exec -- true", "run one command as agentnet"),
    ("agent-lock completion bash", "print a bash script"),
)

COMMAND_EXAMPLES = {
    "install": (
        ("agent-lock install", "install lock"),
        ("agent-lock install --port 7897 --allow-tcp 127.0.0.1:11434", "pin the port"),
        ("agent-lock install --controller 127.0.0.1:9097 --secret-stdin", "read secret"),
        ("agent-lock install --share-dir ~/.cx --trust-exec ~/bin", "share paths"),
    ),
    "uninstall": (
        ("agent-lock uninstall", "remove the lock"),
        ("agent-lock uninstall", "safe to repeat"),
    ),
    "doctor": (
        ("agent-lock doctor", "run every check"),
        ("agent-lock doctor --json", "print version 1 JSON"),
        ("agent-lock doctor --repair", "restore cleared ACLs"),
    ),
    "exec": (
        ("agent-lock exec -- true", "run true as agentnet"),
        ("agent-lock exec -- curl -I https://example.com", "only via the proxy"),
        ("agent-lock exec -- git status", "run git as agentnet"),
    ),
    "bind-bin": (
        ("sudo agent-lock bind-bin ~/.local/bin", "setgid this directory"),
        ("sudo agent-lock bind-bin /tmp/bin", "clear group write again"),
    ),
    "completion": (
        ("eval \"$(agent-lock completion bash)\"", "add this to ~/.bashrc"),
        ("eval \"$(agent-lock completion zsh)\"", "run this after compinit"),
        ("agent-lock completion fish | source", "load the fish script"),
        ("agent-lock completion powershell", "print the PowerShell script"),
    ),
}

ALLOW_TCP_HELP = (
    "loopback TCP port to allow (127.0.0.1:PORT or ::1:PORT). "
    "A loopback service that then dials the network is a second exit beside the proxy."
)


def _examples_text(examples):
    """examples: epilog. Command lines are padded to the longest plus two."""
    width = max(len(command) for command, _summary in examples) + 2
    lines = ["examples:"]
    lines.extend("  {}{}".format(command.ljust(width), summary) for command, summary in examples)
    return "\n".join(lines) + "\n"


def _grouped_commands_text():
    width = max(len(name) for name in COMMAND_SUMMARY) + 2
    lines = []
    for title, commands in COMMAND_GROUPS:
        lines.append("{}:".format(title))
        lines.extend("  {}{}".format(name.ljust(width), summary) for name, summary in commands)
        lines.append("")
    return "\n".join(lines).rstrip("\n")


HELP_EXAMPLES = _examples_text(TOP_EXAMPLES) + "\nRun agent-lock COMMAND -h for more examples.\n"


def build_parser():
    parser = argparse.ArgumentParser(
        prog="agent-lock",
        allow_abbrev=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Lock agent commands to the local HTTP proxy by running them as the user agentnet.\n\n"
        + _grouped_commands_text(),
        epilog=HELP_EXAMPLES,
    )
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    install = sub.add_parser("install", description=COMMAND_SUMMARY["install"], allow_abbrev=False)
    install.add_argument("--port", type=port_arg, help="mixed port; required when discovery fails")
    install.add_argument("--controller", help="loopback controller (host:port or unix:PATH)")
    install.add_argument("--secret-stdin", action="store_true", help="read one secret line from stdin")
    install.add_argument("--claude-dir", action="append", default=None, help="extra Claude settings directory")
    install.add_argument("--share-dir", action="append", default=None, help="extra directory to share with agentnet")
    install.add_argument("--trust-exec", action="append", default=None, help="program or directory agentnet may execute")
    install.add_argument("--allow-tcp", action="append", default=None, type=allow_tcp_arg, help=ALLOW_TCP_HELP)

    sub.add_parser("uninstall", description=COMMAND_SUMMARY["uninstall"], allow_abbrev=False)

    doctor = sub.add_parser("doctor", description=COMMAND_SUMMARY["doctor"], allow_abbrev=False)
    doctor.add_argument("--json", action="store_true", help="print version 1 JSON")
    doctor.add_argument("--repair", action="store_true", help="reapply credential ACLs; does not change the port")

    sub.add_parser("exec", description=COMMAND_SUMMARY["exec"], allow_abbrev=False)

    bind = sub.add_parser("bind-bin", description=COMMAND_SUMMARY["bind-bin"], allow_abbrev=False)
    bind.add_argument("path", metavar="PATH", help="directory to mark setgid for the agentnet group")

    completion = sub.add_parser("completion", description=COMMAND_SUMMARY["completion"], allow_abbrev=False)
    completion.add_argument("shell", choices=SHELLS, help="bash, zsh, fish, or powershell")

    for name, subparser in sub.choices.items():
        subparser.formatter_class = argparse.RawDescriptionHelpFormatter
        subparser.epilog = _examples_text(COMMAND_EXAMPLES[name])
        subparser.allow_abbrev = False
    return parser


def _split_exec(argv):
    """Drop the command tail at the first --. Flags such as -h stay on the parser side."""
    if not argv or argv[0] != "exec":
        return argv, None
    if "--" not in argv:
        return argv, None
    index = argv.index("--")
    return argv[:index] or ["exec"], argv[index + 1:]


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    argv = list(argv)
    argv, tail = _split_exec(argv)
    try:
        parser = build_parser()
        if argv and argv[0] == "completion":
            # Print the script even when agent-lock is not installed.
            args = parser.parse_args(argv)
            sys.stdout.write(script(args.shell, parser))
            return 0
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code
        if code is None:
            return 0
        return int(code)
    try:
        if args.command == "install":
            return cmd_install(args)
        if args.command == "uninstall":
            return cmd_uninstall(args)
        if args.command == "doctor":
            return cmd_doctor(args)
        if args.command == "exec":
            return cmd_exec(tail)
        if args.command == "bind-bin":
            return cmd_bind_bin(args)
        if args.command == "completion":
            sys.stdout.write(script(args.shell, parser))
            return 0
    except AgentLockError as exc:
        sys.stderr.write("agent-lock: {}\n".format(exc))
        return int(exc.code)
    return 2
