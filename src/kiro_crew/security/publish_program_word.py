"""Program-position reading of a command line for the git-publish floor.

``_runs_runtime_program_publish`` answers whether a command runs the ``push``
subcommand under a program word the shell resolves at run time -- a basename
carrying an expansion or a command substitution, or an unquoted glob that can
expand to ``git`` -- in any program position of the text: after any separator,
inside compound constructs, subshells and ``case`` arms, behind precommands and
redirections.  ``_runtime_publishes`` reports each one, with its ``push``
arguments when the program word reaches exec as exactly one word (a
double-quoted parameter expansion) followed directly by ``push``: git's argv is
then known and ``argv_floor`` judges its target like a literal git push.  Any
other runtime-program publish is unverifiable.

The program is the word's top-level BASENAME: ``"$SDK/platform-tools/adb"`` runs
``adb`` wherever the directory points, so it is not a runtime-resolved program.

These helpers live apart so that the reading does not count against
``argv_floor``'s per-module liveness cap.

Layer.  This module imports only ``shell_normalizer``; ``argv_floor`` imports
these names.
"""

from __future__ import annotations

import re
from typing import NamedTuple

from .shell_normalizer import (
    ENV_ASSIGNMENT_RE,
    _dequote_token,
    _fold_line_continuations,
    _glob_could_expand_to,
    _iter_shell_chars,
    _push_token_redirection,
    _shell_quote_walk,
    _split_shell_words,
)

# Git global flags that consume a separate argument token (appear between
# `git` and the subcommand).
_GIT_ARG_FLAGS = frozenset({"-c", "-C", "--git-dir", "--work-tree", "--namespace"})

#: Words after which the next word is still in program position: the reserved
#: words that open a command list in a compound construct, plus ``!``, which
#: prefixes a pipeline, and ``{``, which opens a group.
_GIT_PROGRAM_LEAD_WORDS = frozenset(
    {"!", "{", "do", "elif", "else", "if", "then", "until", "while"}
)

#: Precommand programs and keywords that run one of their later words as a
#: program, each with the number of positional operands it reads before that
#: program (``timeout 5 <program>``, ``chroot <dir> <program>``).  A literal
#: word right after one of their options is read as that option's value.
_GIT_PRECOMMAND_POSITIONALS = {
    "builtin": 0,
    "chroot": 1,
    "command": 0,
    "coproc": 0,
    "doas": 0,
    "env": 0,
    "exec": 0,
    "flock": 1,
    "ionice": 0,
    "nice": 0,
    "nohup": 0,
    "parallel": 0,
    "setsid": 0,
    "stdbuf": 0,
    "sudo": 0,
    "taskset": 1,
    "time": 0,
    "timeout": 1,
    "unbuffer": 0,
    "watch": 0,
    "xargs": 0,
}


def _opens_substitution(steps: list, position: int) -> bool:
    """True if the ``(`` or ``{`` at *position* opens a substitution or expansion.

    ``$(``, ``${`` and the process substitutions ``<(`` / ``>(``, read in any
    quote state but single quotes: ``"${G}"`` is an expansion too.
    """
    if position == 0:
        return False
    before = steps[position - 1]
    if len(before.text) != 1 or before.state == 1:
        return False
    if before.char == "$":
        return True
    return steps[position].char == "(" and before.char in "<>" and before.active


def _shell_commands(text: str) -> "list[str]":
    """*text* split into the commands the shell runs, at top level only.

    A command ends at an unquoted ``;``, ``|``, newline, or ``&`` that is not
    part of a redirection (``2>&1``, ``&>log``, ``<&0``), and at a bare ``(`` or
    ``)``, which open and close a subshell or end a ``case`` pattern.  Nothing
    inside a ``$(...)``, ``${...}`` or backtick body is split: that is the
    substitution's own command, which the payload walk judges as a source of
    its own.
    """
    steps = list(_iter_shell_chars(text))
    pieces: list[str] = []
    buf: list[str] = []
    depth = 0
    in_backticks = False
    for position, step in enumerate(steps):
        if step.trailing_escape:
            buf.append(step.text)
            break
        char = step.char
        if char == "`" and len(step.text) == 1 and step.state != 1:
            in_backticks = not in_backticks
        elif step.active and not in_backticks:
            if depth:
                if char in "({":
                    depth += 1 if char == "(" or _opens_substitution(steps, position) else 0
                elif char in ")}":
                    depth -= 1
            elif char in "({" and _opens_substitution(steps, position):
                depth = 1
            elif char in ";|\n()" or (char == "&" and not _is_redirection_amp(steps, position)):
                pieces.append("".join(buf))
                buf = []
                continue
        buf.append(step.text)
    pieces.append("".join(buf))
    return [piece for piece in pieces if piece.strip()]


def _is_redirection_amp(steps: list, position: int) -> bool:
    """True if the ``&`` at *position* belongs to a redirection operator."""
    before = steps[position - 1].char if position else ""
    after = steps[position + 1].char if position + 1 < len(steps) else ""
    return before in ("<", ">") or after == ">"


def _active_backticks(word: str) -> int:
    """Backticks in *word* that open or close a substitution (not quoted literals)."""
    return sum(
        1
        for step in _iter_shell_chars(word)
        if step.char == "`" and len(step.text) == 1 and step.state != 1
    )


def _word_span_end(words: "list[str]", start: int) -> int:
    """Index of the word that closes the shell word opened at *start*.

    An unquoted command substitution can span several words (``$(echo git)``
    splits as ``$(echo`` and ``git)``).  The shell word ends at the first word
    where every substitution backtick is paired and every unquoted ``(`` is
    closed.  An unclosed span runs to the last word.
    """
    depth = 0
    backticks = 0
    for index in range(start, len(words)):
        depth += _shell_quote_walk(words[index]).paren_delta
        backticks += _active_backticks(words[index])
        if depth <= 0 and backticks % 2 == 0:
            return index
    return len(words) - 1


def _top_level_basename(raw: str) -> str:
    """The part of raw shell word *raw* after its last top-level ``/``.

    A ``/`` inside a substitution or a parameter expansion is part of what the
    shell produces, not a path separator of the word, so it does not count.
    """
    depth = 0
    in_backticks = False
    last = -1
    steps = list(_iter_shell_chars(raw))
    for position, step in enumerate(steps):
        char = step.char
        if char == "`" and len(step.text) == 1 and step.state != 1:
            in_backticks = not in_backticks
        elif step.state != 1 and len(step.text) == 1 and not in_backticks:
            if char in "({" and _opens_substitution(steps, position):
                depth += 1
            elif char in ")}" and depth:
                depth -= 1
            elif char == "/" and not depth:
                last = step.offset
    # A Windows path separates with ``\``; the program is what follows the last.
    return raw[last + 1 :].rsplit("\\", 1)[-1]


def _runtime_program(raw: str) -> bool:
    """True if raw program word *raw* may name git only once the shell resolves it.

    A basename carrying ``$`` or a backtick is resolved at run time, and so is a
    basename that is an unquoted glob able to expand to ``git``; a quoted glob
    character is literal.
    """
    base = _top_level_basename(raw)
    if "$" in base or "`" in base:
        return True
    if any(quote in base for quote in "'\"\\"):
        return False
    return _glob_could_expand_to(base, ("git",))


def _git_subcommand(words: "list[str]", index: int) -> "tuple[str, int] | None":
    """The dequoted git subcommand at or after *index*, and its last word's index.

    Skips what git and the shell consume before the subcommand: redirections
    with a separated target, empty words, simple flags, and a flag in
    ``_GIT_ARG_FLAGS`` together with the whole span of its value.
    """
    while index < len(words):
        is_redirection, consumes_next = _push_token_redirection(words[index])
        if is_redirection:
            index += 2 if consumes_next else 1
            continue
        end = _word_span_end(words, index)
        word = _dequote_token(" ".join(words[index : end + 1]))
        if word in _GIT_ARG_FLAGS and end + 1 < len(words):
            index = _word_span_end(words, end + 1) + 1
        elif not word.strip() or word.startswith("-"):
            index = end + 1
        else:
            return word, end
    return None


#: A program word the shell hands to exec as exactly ONE word: fully double
#: quoted, carrying parameter expansions only.  A command substitution, a
#: backtick, an escape, or an ``@`` / ``*`` (``"$@"``, ``"${a[@]}"``, which
#: expand to several words) disqualifies it.
_ONE_WORD_EXPANSION_RE = re.compile(r'\A"[^"`\\@*]*\$[^"`\\@*]*"\Z')


class _RuntimePublish(NamedTuple):
    """A ``push`` run under a runtime-resolved program word."""

    #: The raw words after ``push``, when the program word reaches exec as one
    #: word and every word between it and ``push`` is literal, so git's argv
    #: after ``push`` is exactly these words.  None when the publish's
    #: arguments cannot be known.
    args: "list[str] | None"


def _command_runtime_publish(command: str) -> "_RuntimePublish | None":
    """The push *command* runs under a runtime-resolved program word, if any.

    Program position opens at the command's first word, after a word in
    ``_GIT_PROGRAM_LEAD_WORDS``, after the name that follows ``function``, and
    after a precommand's options and positional operands.  Leading
    ``VAR=value`` assignments and redirections keep it open.  Inside a
    precommand a runtime program word that does not run ``push`` is read as an
    operand, since its value may be an option value or another precommand.
    """
    words = _split_shell_words(command)
    positionals: "int | None" = None
    after_option = False
    index = 0
    while index < len(words):
        is_redirection, consumes_next = _push_token_redirection(words[index])
        if is_redirection:
            index += 2 if consumes_next else 1
            continue
        start = index
        end = _word_span_end(words, index)
        raw = " ".join(words[index : end + 1])
        word = _dequote_token(raw)
        index = end + 1
        if word in _GIT_PROGRAM_LEAD_WORDS or ENV_ASSIGNMENT_RE.match(word):
            continue
        if word == "function":
            index += 1
            continue
        if _runtime_program(raw):
            subcommand = _git_subcommand(words, index)
            if subcommand is not None and subcommand[0] == "push":
                one_word = start == end and _ONE_WORD_EXPANSION_RE.match(raw) is not None
                between = " ".join(words[index : subcommand[1] + 1])
                plain = not any(char in between for char in "$`*?[")
                args = words[subcommand[1] + 1 :] if one_word and plain else None
                return _RuntimePublish(args)
            if positionals is None:
                return None
            after_option = False
            continue
        if positionals is not None and word.startswith("-"):
            after_option = "=" not in word
            continue
        base = _top_level_basename(word)
        if base in _GIT_PRECOMMAND_POSITIONALS:
            positionals = _GIT_PRECOMMAND_POSITIONALS[base]
            after_option = False
            continue
        if positionals is not None and after_option:
            after_option = False
            continue
        if positionals:
            positionals -= 1
            continue
        return None
    return None


def _runtime_publishes(text_lower: str) -> "list[_RuntimePublish]":
    """Every push in *text_lower* run under a runtime-resolved program word.

    Line continuations are folded first, as the shell folds them before it
    reads words.
    """
    return [publish for _command, publish in _read_commands(text_lower) if publish is not None]


def _commands_without_runtime_publish(text_lower: str) -> "list[str]":
    """The commands of *text_lower* that run no runtime-program publish."""
    return [command for command, publish in _read_commands(text_lower) if publish is None]


def _read_commands(text_lower: str) -> "list[tuple[str, _RuntimePublish | None]]":
    """Each top-level command of *text_lower* with the runtime publish it runs."""
    if "push" not in _dequote_token(text_lower):
        return [(text_lower, None)]
    return [
        (command, _command_runtime_publish(command))
        for command in _shell_commands(_fold_line_continuations(text_lower))
    ]


def _runs_runtime_program_publish(text_lower: str) -> bool:
    """True if any command in *text_lower* runs a push under a runtime program word.

    Answers False when the text cannot be read, matching the normalizer pass.
    """
    try:
        return bool(_runtime_publishes(text_lower))
    except Exception:
        return False
