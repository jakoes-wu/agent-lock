"""Generate bash, zsh, fish, and PowerShell completion from the argparse parser.

Subcommand names, options, and choices are read when the script is generated.
There is no second word list and no account lookup. Filename completion is only
for --claude-dir, --share-dir, --trust-exec, and the bind-bin positional.
"""

import argparse

SHELLS = ("bash", "zsh", "fish", "powershell")

# These options take a path. Every other valued option completes nothing.
PATH_OPTIONS = ("--claude-dir", "--share-dir", "--trust-exec")
# Printed as separate `return $null` statements, in this order, then exec --.
NO_FILE_OPTIONS = ("--port", "--allow-tcp", "--controller")


def command_spec(parser):
    """Return {subcommand: (options, valued options)}. Help actions are skipped."""
    spec = {}
    for action in parser._actions:  # noqa: SLF001 — argparse has no public walker
        if not isinstance(action, argparse._SubParsersAction):  # noqa: SLF001
            continue
        for name, sub in action.choices.items():
            options = []
            valued = []
            for sub_action in sub._actions:  # noqa: SLF001
                if not sub_action.option_strings or sub_action.help == argparse.SUPPRESS:
                    continue
                if isinstance(sub_action, argparse._HelpAction):  # noqa: SLF001
                    continue
                options.extend(sub_action.option_strings)
                if sub_action.nargs != 0:
                    valued.extend(sub_action.option_strings)
            spec[name] = (options, valued)
    return spec


def _positional_choices(parser):
    """{(command, index): [words]} for positionals that declare choices."""
    found = {}
    for action in parser._actions:  # noqa: SLF001
        if not isinstance(action, argparse._SubParsersAction):  # noqa: SLF001
            continue
        for name, sub in action.choices.items():
            index = 0
            for sub_action in sub._actions:  # noqa: SLF001
                if sub_action.option_strings or sub_action.help == argparse.SUPPRESS:
                    continue
                if isinstance(sub_action, argparse._HelpAction):  # noqa: SLF001
                    continue
                if sub_action.choices and sub_action.nargs in (None, "?"):
                    found[(name, index)] = [str(choice) for choice in sub_action.choices]
                if sub_action.nargs != "*":
                    index += 1
    return found


def _file_positions(parser):
    """Positionals that complete as paths. bind-bin's path is the only one."""
    found = []
    for action in parser._actions:  # noqa: SLF001
        if not isinstance(action, argparse._SubParsersAction):  # noqa: SLF001
            continue
        for name, sub in action.choices.items():
            index = 0
            for sub_action in sub._actions:  # noqa: SLF001
                if sub_action.option_strings or sub_action.help == argparse.SUPPRESS:
                    continue
                if isinstance(sub_action, argparse._HelpAction):  # noqa: SLF001
                    continue
                if not sub_action.choices and name == "bind-bin" and index == 0:
                    found.append((name, index))
                if sub_action.nargs != "*":
                    index += 1
    return found


def _path_options(spec):
    present = []
    valued = set()
    for _name, pair in spec.items():
        valued.update(pair[1])
    for option in PATH_OPTIONS:
        if option in valued:
            present.append(option)
    return present


def _no_file_options(spec):
    valued = set()
    for _name, pair in spec.items():
        valued.update(pair[1])
    return [option for option in NO_FILE_OPTIONS if option in valued]


def script(shell, parser):
    spec = command_spec(parser)
    choices = _positional_choices(parser)
    files = _file_positions(parser)
    if shell == "bash":
        return _bash(spec, choices, files)
    if shell == "zsh":
        return _zsh(spec, choices, files)
    if shell == "fish":
        return _fish(spec, choices, files)
    if shell == "powershell":
        return _powershell(spec, choices, files)
    raise ValueError(shell)


def _words(items):
    return " ".join(items)


def _option_cases_bash(spec):
    lines = []
    for name, pair in sorted(spec.items()):
        lines.append("    {name}) opts={opts}; vopts={vopts} ;;".format(
            name=name,
            opts=_sq(_words(pair[0])),
            vopts=_sq(_words(pair[1])),
        ))
    return "\n".join(lines)


def _sq(text):
    return "'" + text.replace("'", "'\\''") + "'"


def _bash(spec, choices, files):
    commands = sorted(spec)
    path_pattern = "|".join(_path_options(spec)) or "__no_path_option__"
    no_file_pattern = "|".join(_no_file_options(spec)) or "__no_value_option__"
    positional = []
    for key, words in sorted(choices.items()):
        positional.append("      {cmd}:{index}) candidates={words} ;;".format(
            cmd=key[0], index=key[1], words=_sq(_words(words))))
    for command, index in files:
        positional.append(
            "      {cmd}:{index}) COMPREPLY=($(compgen -f -- \"$cur\")); return 0 ;;".format(
                cmd=command, index=index))
    return """# bash completion for agent-lock. Generated from the parser. No bash-completion package.
_agent_lock() {{
  # Split the raw line on whitespace. The default word breaks include a colon,
  # which would cut 127.0.0.1:PORT and ::1:PORT into extra words.
  local line="${{COMP_LINE:0:COMP_POINT}}"
  local cur="${{line##* }}"
  local before="${{line%%"$cur"}}"
  local -a words
  read -r -a words <<< "$before"
  local cmd="" i w
  for ((i = 1; i < ${{#words[@]}}; i++)); do
    if [[ "${{words[i]}}" != -* ]]; then cmd="${{words[i]}}"; break; fi
  done
  local opts="" vopts=""
  case "$cmd" in
{option_cases}
  esac
  local npos=0 skip=0 prev=""
  for ((i = i + 1; i < ${{#words[@]}}; i++)); do
    w="${{words[i]}}"
    if ((skip)); then skip=0; prev=""; continue; fi
    if [[ "$w" == "--" ]]; then npos=-1; break; fi
    if [[ "$w" == -* ]]; then
      if [[ " $vopts " == *" $w "* ]]; then skip=1; prev="$w"; fi
      continue
    fi
    ((npos++))
  done
  local candidates=""
  if ((skip)); then
    case "$prev" in
      {path_pattern}) COMPREPLY=($(compgen -f -- "$cur")); return 0 ;;
      {no_file_pattern}) COMPREPLY=(); return 0 ;;
      *) COMPREPLY=(); return 0 ;;
    esac
  elif [[ -z "$cmd" ]]; then
    candidates="{commands} --help --version"
  elif ((npos < 0)); then
    COMPREPLY=(); return 0
  elif [[ "$cur" == -* ]]; then
    candidates="$opts"
  else
    case "$cmd:$npos" in
{positional}
    esac
  fi
  COMPREPLY=($(compgen -W "$candidates" -- "$cur"))
  local j prefix=""
  for ((j = ${{#cur}} - 1; j >= 0; j--)); do
    case "$COMP_WORDBREAKS" in
      *"${{cur:j:1}}"*) prefix="${{cur:0:j+1}}"; break ;;
    esac
  done
  if [[ -n "$prefix" ]]; then
    for i in "${{!COMPREPLY[@]}}"; do COMPREPLY[i]="${{COMPREPLY[i]#"$prefix"}}"; done
  fi
}}
complete -F _agent_lock agent-lock
""".format(
        option_cases=_option_cases_bash(spec),
        commands=_words(commands),
        path_pattern=path_pattern,
        no_file_pattern=no_file_pattern,
        positional="\n".join(positional),
    )


def _zsh(spec, choices, files):
    commands = sorted(spec)
    option_cases = []
    for name, pair in sorted(spec.items()):
        option_cases.append("    {name}) opts=({opts}); vopts=({vopts}) ;;".format(
            name=name,
            opts=_words([_sq(item) for item in pair[0]]),
            vopts=_words([_sq(item) for item in pair[1]]),
        ))
    path_pattern = "|".join(_path_options(spec)) or "__no_path_option__"
    positional = []
    for key, words in sorted(choices.items()):
        positional.append("      {cmd}:{index}) candidates=({words}) ;;".format(
            cmd=key[0], index=key[1], words=_words([_sq(word) for word in words])))
    for command, index in files:
        positional.append("      {cmd}:{index}) _files; return ;;".format(cmd=command, index=index))
    return """#compdef agent-lock
# zsh completion for agent-lock. Generated from the parser.
_agent_lock() {{
  local cmd="" i w
  local -a opts vopts candidates
  for ((i = 2; i < CURRENT; i++)); do
    if [[ "${{words[i]}}" != -* ]]; then cmd="${{words[i]}}"; break; fi
  done
  case "$cmd" in
{option_cases}
  esac
  local npos=0 skip=0 prev=""
  for ((i = i + 1; i < CURRENT; i++)); do
    w="${{words[i]}}"
    if ((skip)); then skip=0; prev=""; continue; fi
    if [[ "$w" == "--" ]]; then npos=-1; break; fi
    if [[ "$w" == -* ]]; then
      if (( ${{vopts[(Ie)$w]}} )); then skip=1; prev="$w"; fi
      continue
    fi
    ((npos++))
  done
  local cur="${{words[CURRENT]}}"
  if ((skip)); then
    case "$prev" in
      {path_pattern}) _files; return ;;
      *) return ;;
    esac
  elif [[ -z "$cmd" ]]; then
    candidates=({commands} --help --version)
  elif ((npos < 0)); then
    return
  elif [[ "$cur" == -* ]]; then
    candidates=($opts)
  else
    case "$cmd:$npos" in
{positional}
    esac
  fi
  compadd -- $candidates
}}
compdef _agent_lock agent-lock
""".format(
        option_cases="\n".join(option_cases),
        commands=_words(commands),
        path_pattern=path_pattern,
        positional="\n".join(positional),
    )


def _fish(spec, choices, files):
    commands = sorted(spec)
    lines = [
        "# fish completion for agent-lock. Generated from the parser.",
        "complete -c agent-lock -f",
        "function __agent_lock_positionals",
        "    set -l tokens (commandline -opc)",
        "    set -l value_options $argv",
        "    set -l seen 0",
        "    set -l skip 0",
        "    set -l count 0",
        "    for token in $tokens[2..-1]",
        "        if test $seen -eq 0",
        "            if not string match -q -- '-*' $token",
        "                set seen 1",
        "            end",
        "            continue",
        "        end",
        "        if test $skip -eq 1",
        "            set skip 0",
        "            continue",
        "        end",
        "        if test \"$token\" = '--'",
        "            echo -1",
        "            return",
        "        end",
        "        if string match -q -- '-*' $token",
        "            if contains -- $token $value_options",
        "                set skip 1",
        "            end",
        "            continue",
        "        end",
        "        set count (math $count + 1)",
        "    end",
        "    echo $count",
        "end",
        "complete -c agent-lock -n __fish_use_subcommand -a {}".format(_sq(_words(commands))),
        "complete -c agent-lock -n __fish_use_subcommand -l help -l version",
    ]
    paths = set(_path_options(spec))
    for name, pair in sorted(spec.items()):
        condition = "__fish_seen_subcommand_from {}".format(name)
        for option in pair[0]:
            flag = "-l {}".format(option[2:]) if option.startswith("--") else "-s {}".format(option[1:])
            requires = " -r" if option in pair[1] else ""
            files_flag = " -F" if option in paths else ""
            lines.append("complete -c agent-lock -n {} {}{}{}".format(
                _sq(condition), flag, requires, files_flag))
        for key, words in sorted(choices.items()):
            if key[0] != name:
                continue
            guard = "{}; and test (__agent_lock_positionals {}) -eq {}".format(
                condition, _words(pair[1]), key[1])
            lines.append("complete -c agent-lock -n {} -a {}".format(
                _sq(guard), _sq(_words(words))))
    for command, index in files:
        pair = spec.get(command, ([], []))
        guard = "__fish_seen_subcommand_from {}; and test (__agent_lock_positionals {}) -eq {}".format(
            command, _words(pair[1]), index)
        lines.append("complete -c agent-lock -n {} -a '(__fish_complete_path)'".format(_sq(guard)))
    return "\n".join(lines) + "\n"


def _ps_quote(text):
    return "'" + text.replace("'", "''") + "'"


def _ps_array(items):
    return "@(" + ", ".join(_ps_quote(item) for item in items) + ")"


def _powershell(spec, choices, files):
    """ASCII only. No-file positions return $null. Path positions bare-return."""
    commands = sorted(spec)
    option_lines = []
    value_lines = []
    for name in commands:
        if spec[name][0]:
            option_lines.append("        {} = {}".format(_ps_quote(name), _ps_array(spec[name][0])))
        if spec[name][1]:
            value_lines.append("        {} = {}".format(_ps_quote(name), _ps_array(spec[name][1])))
    choice_lines = []
    for key, words in sorted(choices.items()):
        choice_lines.append("        {} = {}".format(
            _ps_quote("{}:{}".format(key[0], key[1])), _ps_array(words)))
    path_checks = []
    for option in _path_options(spec):
        path_checks.append("    if ($skip -and $lastOpt -eq {}) {{ return }}".format(_ps_quote(option)))
    for command, index in files:
        path_checks.append(
            "    if ($cmd -eq {cmd} -and -not $skip -and -not $afterDd -and"
            " -not $wordToComplete.StartsWith('-') -and $npos -eq {index}) {{ return }}".format(
                cmd=_ps_quote(command), index=index))
    null_checks = []
    for option in _no_file_options(spec):
        null_checks.append(
            "    if ($skip -and $lastOpt -eq {}) {{ return $null }}".format(_ps_quote(option)))
    null_checks.append("    if ($cmd -eq 'exec' -and $afterDd) { return $null }")
    lines = [
        "# agent-lock PowerShell completion. ASCII only.",
        "Register-ArgumentCompleter -Native -CommandName agent-lock, agent-lock.exe -ScriptBlock {",
        "    param($wordToComplete, $commandAst, $cursorPosition)",
        "    $commands = {}".format(_ps_array(commands)),
        "    $options = @{",
    ]
    lines.extend(option_lines)
    lines.extend([
        "    }",
        "    $valueOptions = @{",
    ])
    lines.extend(value_lines)
    lines.extend([
        "    }",
        "    $positional = @{",
    ])
    lines.extend(choice_lines)
    lines.extend([
        "    }",
        "    $before = @($commandAst.CommandElements | Where-Object { $_.Extent.EndOffset -lt $cursorPosition } |",
        "        ForEach-Object { $_.Extent.Text })",
        "    $cmd = ''",
        "    $npos = 0",
        "    $skip = $false",
        "    $afterDd = $false",
        "    $lastOpt = ''",
        "    foreach ($w in ($before | Select-Object -Skip 1)) {",
        "        if ($cmd -eq '') {",
        "            if (-not $w.StartsWith('-')) { $cmd = $w }",
        "            continue",
        "        }",
        "        if ($w -eq '--') { $afterDd = $true; break }",
        "        if ($skip) { $skip = $false; continue }",
        "        if ($w.StartsWith('-')) {",
        "            if ($valueOptions[$cmd] -contains $w) { $skip = $true; $lastOpt = $w }",
        "        } else {",
        "            $npos++",
        "        }",
        "    }",
    ])
    lines.extend(path_checks)
    lines.extend(null_checks)
    lines.extend([
        "    $candidates = @()",
        "    if ($cmd -eq '') {",
        "        $candidates = $commands",
        "    } elseif ($wordToComplete.StartsWith('-')) {",
        "        $candidates = $options[$cmd]",
        "    } else {",
        "        $candidates = $positional[($cmd + ':' + $npos)]",
        "    }",
        "    $candidates | Where-Object { $_ -and $_.StartsWith($wordToComplete, "
        "[System.StringComparison]::OrdinalIgnoreCase) } |",
        "        ForEach-Object { [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }",
        "}",
        "",
    ])
    return "\n".join(lines)
