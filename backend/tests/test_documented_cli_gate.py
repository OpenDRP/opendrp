"""Every command a page tells an operator to run has to be a command that exists.

The operator CLIs are the platform's recovery and rotation path, and they are
documented as literal commands: `manage_admin mfa-off` is how a locked-out
administrator gets back in, `manage_connector_tokens rotate` is how a leaked
credential is replaced, `rotate_keys rewrap` is the step that makes deleting an
old key safe. A flag that is renamed, or a subcommand that is folded into another,
leaves the page reading as an instruction and the operator discovering otherwise
during the incident it was written for — and no test noticed before this one.

What the gate checks
--------------------
Every `python -m scripts.<tool> ...` inside a fenced block of `README.md`,
`docs/**` (except the dated records under `docs/internal/`) and
`connectors/README.md` is compared with the parser the script actually builds:

* the script has to exist and expose `build_parser()`;
* the subcommand has to be one the parser accepts;
* every flag has to be one the parser accepts — short and long spellings alike;
* a positional argument is checked only for existing at all: its *value* is an
  operator's to choose (`<name>`, `<email>`, a real hostname), so a page cannot be
  expected to write one the parser would accept.

A script that takes no options at all builds no parser, because there is nothing to
parse; `_ARGUMENT_FREE_SCRIPTS` names those, and the gate holds them to the stronger
claim that the documented line passes no argument whatsoever. A script that is
neither in that table nor exposing `build_parser()` is a finding, so the check cannot
degrade into silence as scripts are added.

Required flags are deliberately not checked. A page may show the shortest
invocation of a command whose remaining flags are described in prose, and a gate
that insisted otherwise would make the documentation worse to read.

Words before `python` belong to the wrapper, not to the script. `docker compose -f
docker-compose.yml exec -T backend python ...` puts compose's own flags on the
same line; `_COMPOSE_FLAGS_BEFORE_PYTHON` names them so a reader can see that they
are skipped on purpose rather than by accident.
"""

from __future__ import annotations

import argparse
import importlib
import re
import shlex
from pathlib import Path
from typing import Dict, Iterator, List, Sequence, Tuple

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_SCRIPTS = _ROOT / "backend" / "scripts"

#: A code-fence delimiter, in either spelling Markdown accepts.
_FENCE = re.compile(r"^\s*(?:```|~~~)")

#: A documented invocation: the interpreter, `-m`, and this repository's scripts
#: package. The tool name is captured so it can be imported by name.
_COMMAND = re.compile(
    r"\bpython(?:3(?:\.\d+)?)?\s+-m\s+scripts\.(?P<tool>[a-z_][a-z0-9_]*)"
)

#: Compose's own flags on a `docker compose -f … exec -T … python …` line. The
#: gate begins reading at the interpreter, so none of these is ever compared with
#: the script's parser; the list is here to say so out loud.
_COMPOSE_FLAGS_BEFORE_PYTHON = frozenset(
    {
        "-f",
        "--file",
        "-p",
        "--project-name",
        "-T",
        "--env-file",
        "--profile",
        "--project-directory",
        "--ansi",
        "--progress",
        "--log-level",
        # `docker compose run --rm backend …`: the one-shot run flag.
        "--rm",
    }
)

#: Scripts whose command line takes no arguments. They build no parser because
#: there is nothing to parse, and the gate asserts the documented invocation adds
#: nothing to them rather than assuming the line is fine.
_ARGUMENT_FREE_SCRIPTS = frozenset(
    {
        # Reads the recorded revision and applies the chain: no options.
        "migrate",
        # Compares the ORM with the revisions it reads from the tree: no options.
        "check_schema_drift",
    }
)

#: One parser per tool, built once: `build_parser()` is pure, and two pages
#: documenting the same CLI should not produce two different answers.
_PARSERS: Dict[str, argparse.ArgumentParser] = {}


def documents(root: Path) -> List[Path]:
    """The pages whose commands an operator is expected to type."""
    pages: List[Path] = []
    for name in ("README.md", "connectors/README.md"):
        path = root / name
        if path.is_file():
            pages.append(path)
    docs = root / "docs"
    if docs.is_dir():
        for path in sorted(docs.rglob("*.md")):
            relative = path.relative_to(docs)
            # `docs/internal/**` records what was true when it was written,
            # including the commands of that time; it is history, not guidance.
            if relative.parts and relative.parts[0] == "internal":
                continue
            if path.is_file():
                pages.append(path)
    return pages


def _tokenise(command: str) -> List[str]:
    """Split a documented command the way a shell would, or keep the words."""
    try:
        return shlex.split(command, comments=True)
    except ValueError:  # an unbalanced quote in a sample: fall back to words
        return command.split()


def fenced_commands(
    text: str,
) -> Iterator[Tuple[int, str, List[str], List[str]]]:
    """Yield `(line_number, tool, arguments, wrapper_flags)` per fenced invocation.

    `line_number` is the line the command starts on, counted from one, because
    that is what a reader and an editor both mean by "line 962". `wrapper_flags`
    are the dash-words before the interpreter (`docker compose -f … exec -T`),
    which belong to the wrapper and are never compared with the script's parser.
    """
    lines = text.splitlines()
    in_fence = False
    index = 0
    while index < len(lines):
        line = lines[index]
        if _FENCE.match(line):
            in_fence = not in_fence
            index += 1
            continue
        if not in_fence:
            index += 1
            continue

        start = index + 1
        match = _COMMAND.search(line)
        if match is None:
            index += 1
            continue

        command = line
        # A command continued over several lines with a trailing backslash is
        # still one command, and its flags are still the script's.
        while command.rstrip().endswith("\\") and index + 1 < len(lines):
            index += 1
            command = command.rstrip()[:-1] + " " + lines[index]

        tokens = _tokenise(command[match.start():])
        tool = match.group("tool")
        wrapper_flags = _wrapper_flags(command[: match.start()])
        # tokens[:3] is the interpreter, `-m` and `scripts.<tool>`; what remains
        # is the command line the page is asking the operator to type.
        yield start, tool, tokens[3:], wrapper_flags
        index += 1


def _wrapper_flags(before: str) -> List[str]:
    """The dash-words on the line that belong to no command at all.

    One fenced line may hold two commands (`… && python -m scripts.x`), and a
    `python -m pytest` earlier on it is a command whose `-m` is the interpreter's,
    not a wrapper flag. So the words are split at shell separators and a segment
    that runs an interpreter is a command: its flags are checked where they belong,
    not reported as an undeclared wrapper.
    """
    flags: List[str] = []
    segment: List[str] = []
    for token in _tokenise(before):
        if token in ("&&", "||", ";", "|"):
            flags.extend(_segment_flags(segment))
            segment = []
            continue
        segment.append(token)
    flags.extend(_segment_flags(segment))
    return flags


def _segment_flags(segment: Sequence[str]) -> List[str]:
    """The wrapper flags of one shell segment, unless it runs a command itself."""
    words = [word.strip("'\"`") for word in segment]
    if any(re.fullmatch(r"python[0-9.]*", word.lower()) for word in words):
        return []
    return [word for word in words if word.startswith("-") and word != "-"]


def _parser_for(tool: str) -> argparse.ArgumentParser | None:
    """The parser `scripts.<tool>` builds, or None when there is no such script."""
    if tool in _PARSERS:
        return _PARSERS[tool]
    if not (_SCRIPTS / f"{tool}.py").is_file():
        return None
    module = importlib.import_module(f"scripts.{tool}")
    builder = getattr(module, "build_parser", None)
    if builder is None:
        return None
    parser = builder()
    _PARSERS[tool] = parser
    return parser


def _subcommands(parser: argparse.ArgumentParser) -> Dict[str, argparse.ArgumentParser] | None:
    """The subcommands a parser accepts, or None when it accepts none."""
    for action in parser._actions:  # noqa: SLF001 - argparse has no public view
        if isinstance(action, argparse._SubParsersAction):  # noqa: SLF001
            return dict(action.choices)
    return None


def _positionals(parser: argparse.ArgumentParser) -> list[argparse.Action]:
    return [
        action
        for action in parser._actions  # noqa: SLF001
        if not action.option_strings
        and not isinstance(action, argparse._SubParsersAction)  # noqa: SLF001
    ]


def _takes_value(action: argparse.Action) -> bool:
    """Whether the flag consumes the next word (`--env NAME`) or not (`--force`)."""
    return action.nargs != 0


def _problems(
    parser: argparse.ArgumentParser, arguments: Sequence[str]
) -> List[str]:
    """Everything about `arguments` that `parser` would not accept.

    The walk follows the command line the way argparse does: a word selects a
    subcommand when the current parser has them, a flag's value is skipped
    without being inspected, and a bare word is a positional argument.
    """
    problems: List[str] = []
    current = parser
    subcommands = _subcommands(current)
    positionals = _positionals(current)
    consumed = 0
    index = 0

    while index < len(arguments):
        token = arguments[index]

        if token == "--":
            # Everything after it is positional, whatever it starts with.
            index += 1
            while index < len(arguments):
                if positionals and consumed < len(positionals):
                    consumed += 1
                else:
                    problems.append(
                        f"`{arguments[index]}` is a positional argument the "
                        f"command does not take"
                    )
                index += 1
            break

        if token.startswith("-") and token != "-":
            flag = token.split("=", 1)[0]
            action = current._option_string_actions.get(flag)  # noqa: SLF001
            if action is None:
                problems.append(
                    f"`{flag}` is not a flag of `{current.prog}`: the page tells "
                    f"an operator to type it and the script rejects it"
                )
                # The next word may be this flag's value, and nothing on the line
                # says whether it is: one wrong flag is one finding, not a report
                # about every word that follows it.
                return problems
            if "=" not in token and _takes_value(action) and index + 1 < len(arguments):
                index += 1  # the value is the operator's, not the page's
            index += 1
            continue

        if subcommands is not None:
            chosen = subcommands.get(token)
            if chosen is None:
                problems.append(
                    f"`{token}` is not a subcommand of `{current.prog}`; it "
                    f"accepts {', '.join(sorted(subcommands))}"
                )
                return problems
            current = chosen
            subcommands = _subcommands(current)
            positionals = _positionals(current)
            consumed = 0
            index += 1
            continue

        if not positionals:
            problems.append(
                f"`{token}` is written as a positional argument but "
                f"`{current.prog}` takes none"
            )
            return problems
        if consumed >= len(positionals):
            problems.append(
                f"`{token}` is one positional argument too many for "
                f"`{current.prog}`"
            )
            return problems
        # The name is checked; the value is not. A page writes `<name>` and means
        # "whatever your connector is called".
        consumed += 1
        index += 1

    return problems


def check(root: Path) -> List[str]:
    """Every documented CLI invocation whose command line the script rejects."""
    failures: List[str] = []
    for page in documents(root):
        display = page.relative_to(root).as_posix()
        text = page.read_text(encoding="utf-8")
        for number, tool, arguments, wrapper_flags in fenced_commands(text):
            undeclared = sorted(
                flag
                for flag in wrapper_flags
                if flag.split("=", 1)[0] not in _COMPOSE_FLAGS_BEFORE_PYTHON
            )
            if undeclared:
                failures.append(
                    f"{display}:{number}: the command is wrapped by a tool whose "
                    f"flag(s) {', '.join(undeclared)} are not in "
                    f"`_COMPOSE_FLAGS_BEFORE_PYTHON`: either declare the wrapper "
                    f"or drop it, so no flag on this line goes unchecked by "
                    f"accident"
                )
            if not (_SCRIPTS / f"{tool}.py").is_file():
                failures.append(
                    f"{display}:{number}: `python -m scripts.{tool}` names a "
                    f"script this repository does not have: the operator has no "
                    f"command to run"
                )
                continue
            if tool in _ARGUMENT_FREE_SCRIPTS:
                if arguments:
                    documented = " ".join(["python", "-m", f"scripts.{tool}", *arguments])
                    failures.append(
                        f"{display}:{number}: `{documented}`: `scripts.{tool}` "
                        f"takes no arguments, so the page shows an invocation the "
                        f"script cannot accept"
                    )
                continue
            parser = _parser_for(tool)
            if parser is None:
                failures.append(
                    f"{display}:{number}: `python -m scripts.{tool}` exposes no "
                    f"`build_parser()`, so its documented flags cannot be checked"
                )
                continue
            documented = " ".join(["python", "-m", f"scripts.{tool}", *arguments])
            for problem in _problems(parser, arguments):
                failures.append(f"{display}:{number}: `{documented}`: {problem}")
    return failures


# ==============================================================================
# The shipped tree
# ==============================================================================
@pytest.mark.skipif(
    # A trimmed checkout (the test container mounts the backend subtree) has no
    # pages to read; an empty tree there is a fact about the container, not a
    # clean documentation.
    not (_ROOT / "README.md").is_file() or not (_SCRIPTS / "manage_admin.py").is_file(),
    reason="not a repository checkout",
)
def test_every_documented_command_is_one_its_script_accepts() -> None:
    assert check(_ROOT) == []


# ==============================================================================
# Findings
# ==============================================================================
def _page(tmp_path: Path, body: str) -> Path:
    page = tmp_path / "docs" / "page.md"
    page.parent.mkdir(parents=True, exist_ok=True)
    page.write_text(f"# Page\n\n```bash\n{body}\n```\n", encoding="utf-8")
    return tmp_path


def test_a_documented_flag_the_parser_does_not_have_is_reported(tmp_path: Path) -> None:
    root = _page(
        tmp_path,
        "python -m scripts.manage_connector_tokens rotate dnstwist --environment X\n",
    )

    failures = check(root)

    assert len(failures) == 1, failures
    assert "docs/page.md:4" in failures[0]
    assert "--environment" in failures[0]


def test_a_documented_subcommand_the_parser_does_not_have_is_reported(
    tmp_path: Path,
) -> None:
    root = _page(tmp_path, "python -m scripts.rotate_keys rewrap-keys\n")

    failures = check(root)

    assert len(failures) == 1, failures
    assert "docs/page.md:4" in failures[0]
    assert "rewrap-keys" in failures[0]


def test_a_documented_script_that_does_not_exist_is_reported(tmp_path: Path) -> None:
    root = _page(tmp_path, "python -m scripts.manage_nothing list\n")

    failures = check(root)

    assert len(failures) == 1, failures
    assert "manage_nothing" in failures[0]
    assert "does not have" in failures[0]


def test_an_argument_free_script_rejects_a_documented_flag(tmp_path: Path) -> None:
    """`migrate` reads no options; a page that adds one is showing a command
    nobody can run."""
    root = _page(tmp_path, "python -m scripts.migrate --revision head\n")

    failures = check(root)

    assert len(failures) == 1, failures
    assert "--revision" in failures[0]
    assert "takes no arguments" in failures[0]


def test_a_second_command_on_the_line_is_not_read_as_wrapper_flags(
    tmp_path: Path,
) -> None:
    """`python -m pytest … && python -m scripts.x` — `-m` belongs to pytest."""
    root = _page(
        tmp_path,
        "python -m pytest -q --cov=app && python -m scripts.audit_archive --verify /tmp/m.json\n",
    )

    assert check(root) == []


def test_a_positional_argument_is_checked_by_name_not_by_value(tmp_path: Path) -> None:
    """A page writes `<name>` because the operator supplies the name."""
    root = _page(
        tmp_path,
        "python -m scripts.manage_connector_tokens rotate <name> --env CONNECTOR_TOKEN_<NAME>\n",
    )

    assert check(root) == []


def test_a_command_with_no_subcommand_is_checked_through_its_flags(
    tmp_path: Path,
) -> None:
    """`audit_archive` is a flat CLI: its two modes are flags, not subcommands."""
    root = _page(
        tmp_path,
        "python -m scripts.audit_archive --verify /tmp/manifest.json --limit 10\n"
        "python -m scripts.audit_archive --export-expired\n",
    )

    assert check(root) == []


def test_a_flat_cli_rejects_a_subcommand_shaped_word(tmp_path: Path) -> None:
    """There is nothing to select, so a bare word is a positional it lacks."""
    root = _page(tmp_path, "python -m scripts.audit_archive verify\n")

    failures = check(root)

    assert len(failures) == 1, failures
    assert "positional" in failures[0]


def test_the_wrapper_flags_before_python_are_not_the_scripts(tmp_path: Path) -> None:
    """`docker compose -f … exec -T … python` — compose's flags, not ours."""
    root = _page(
        tmp_path,
        "docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_admin list\n",
    )

    assert check(root) == []


def test_a_command_outside_a_fenced_block_is_prose(tmp_path: Path) -> None:
    """Prose may name a command loosely; a fenced block is what to type."""
    root = tmp_path
    page = root / "docs" / "page.md"
    page.parent.mkdir(parents=True, exist_ok=True)
    page.write_text(
        "# Page\n\nRecovery is `python -m scripts.manage_admin mfa-off --bogus`.\n",
        encoding="utf-8",
    )

    assert check(root) == []


def test_an_internal_record_may_show_the_command_of_its_time(tmp_path: Path) -> None:
    """A dated record quotes a command line that has since changed."""
    root = tmp_path
    page = root / "docs" / "internal" / "audit.md"
    page.parent.mkdir(parents=True, exist_ok=True)
    page.write_text(
        "# Audit\n\n```bash\npython -m scripts.rotate_keys generate --old-flag\n```\n",
        encoding="utf-8",
    )

    assert check(root) == []


def test_a_continuation_line_is_part_of_the_command(tmp_path: Path) -> None:
    """A wrapped command is one command, and a bad flag on either line is found."""
    root = _page(
        tmp_path,
        "python -m scripts.manage_admin create \\\n  --email admin@example.com --nope\n",
    )

    failures = check(root)

    assert len(failures) == 1, failures
    assert "--nope" in failures[0]
