"""A bare kill's substitution body must not assemble the protected name at runtime.

The bare-kill window searched each substitution body raw, with parameter
defaults resolved, and per word of the tokenized view -- all static.  A body
whose ``pgrep``/``pidof`` target is built at runtime from constant-output
substitutions (``"$(printf kiro)$(printf crew)"``) or brace expansion
(``kiro{,}crew``, ``kiro{c..c}rew``) slipped every member.  The window now
folds constant ``printf``/``echo`` output and expands braces per word before
searching.

Posture: these forms are DENIED because the floor can compute them exactly.
An unresolvable operand does NOT fail closed: a pattern variable bound outside
the line, and a lookup naming a different product, stay allowed and are
pinned here as deliberate false-positive controls.

The protected verb and name are assembled at runtime so an agent shell can
read and grep this file without tripping the very rule under test.
"""

from __future__ import annotations

import pytest

from kiro_crew.security import argv_floor as _argv_floor
from kiro_crew.security import is_denied

_K = "k" + "ill"
_PG = "pg" + "rep"
_NAME = "kiro" + "crew"
_HEAD = _NAME[:4]
_TAIL = _NAME[4:]
_ESAC_PREFIX = "case x in x) :;; esac; "


def _floor(cmd: str) -> bool:
    """The argv floor's own verdict, independent of the regex tier."""
    return _argv_floor._is_self_kill(cmd.lower())


_SYNTHESIZED_BODIES = [
    # nested constant-output substitutions
    f'{_PG} -f "$(printf {_HEAD})$(printf {_TAIL})"',
    f'{_PG} -f "$(echo -n {_HEAD})$(echo -n {_TAIL})"',
    f"{_PG} -f `printf {_HEAD}`{_TAIL}",
    f'{_PG} -f "$(printf "$(printf {_HEAD})"){_TAIL}"',
    # a computed value carried through a same-line assignment
    f'x=$(printf {_HEAD}); {_PG} -f "${{x}}{_TAIL}"',
    # brace expansion: alternation and a one-character sequence
    f"{_PG} -f {_HEAD}{{,}}{_TAIL}",
    f"{_PG} -f {_HEAD}{{{_TAIL[0]}..{_TAIL[0]}}}{_TAIL[1:]}",
    f"pidof {_HEAD}{{,}}{_TAIL}",
    # a brace product past the cap that could still spell the name
    f"{_PG} -f " + "".join("{" + ch + ",x}" for ch in _NAME) + "{1,2}",
    f"{_PG} -f {_HEAD}" + "{a..z}" * 4,
    # same-line variable concatenation (denied through the tokenized view)
    f'a={_HEAD}; b={_TAIL}; {_PG} -f "$a$b"',
]


@pytest.mark.parametrize("prefix", ["", _ESAC_PREFIX], ids=["plain", "esac-tail"])
@pytest.mark.parametrize("body", _SYNTHESIZED_BODIES)
def test_runtime_synthesized_target_is_denied(prefix: str, body: str) -> None:
    cmd = f"{_K} $({prefix}{body})"
    assert _floor(cmd), cmd
    assert is_denied(cmd)[0], cmd


@pytest.mark.parametrize(
    "cmd",
    [
        # an unresolvable pattern variable is NOT failed closed
        f'{_K} $({_PG} -f "$pattern")',
        f'{_K} $({_PG} -f "${{pattern}}")',
        # a lookup naming a different product
        f"{_K} $({_PG} -f otherproduct)",
        f"{_K} $({_PG} -f other{{,}}product)",
        f'{_K} $({_PG} -f "$(printf other)$(printf product)")',
        # a constant substitution unrelated to the target
        f'{_K} $({_PG} -f "$(printf worker)")',
        # output words bash keeps apart are not joined
        f'{_K} $({_PG} -f "$(echo {_HEAD} {_TAIL}-worker)")',
        # a format conversion is not modelled -- residual, left unfolded
        f'{_K} $({_PG} -f "$(printf %s%s {_HEAD} {_TAIL})")',
        # a printf escape in the operand is a residual (not decoded, no crash)
        f"{_K} $({_PG} -f \"$(printf '{_HEAD}\\n{_TAIL}')\")",
        f"{_K} $({_PG} -f \"$(printf '\\8')\")",
        # an unknown printf escape is kept, not decoded or crashed on
        f"{_K} $({_PG} -f \"$(printf '\\8')\")",
        # output carrying syntax is left unfolded rather than altered
        f"{_K} $({_PG} -f \"$(printf '{_HEAD};{_TAIL}')\")",
        # a numeric range past the cap cannot add letters
        f"{_K} $(lsof -ti tcp:{{3000..3999}})",
        f"{_K} $({_PG} -f {_HEAD}-cli-server-worker-{{1..300}})",
        f"{_K} $({_PG} -f shard-{{a..z}}{{0..9}})",
        # a nested group whose own product overflows the cap, no name in it
        f"{_K} $({_PG} -f 'shard-{{{{a..j}}{{a..z}},main}}')",
        # a trailing (non-leading) echo operand is not an option -> residual
        f'{_K} $({_PG} -f "$(echo {_HEAD} -n)crew")',
        # quoting makes braces and substitutions LITERAL -- bash does not expand
        # them, so neither does the floor (these name no live process)
        f"{_K} $({_PG} -f '{_HEAD}{{c..c}}{_TAIL}')",
        f"{_K} $({_PG} -f '$(printf {_HEAD}){_TAIL}')",
        f"{_K} $({_PG} -f \"$(printf '{_HEAD};')crew\")",
        # a substitution nested inside another's single-quoted arg is inert
        f"{_K} $({_PG} -f \"worker|$(printf '$(printf {_HEAD})'){_TAIL}\")",
        f"{_K} $({_PG} -f {_HEAD}-cli-server-worker-{{a..z}}{{a..z}})",
        # the name built in a DIFFERENT command than the kill
        f"{_K} 4242; echo {_HEAD}{{,}}{_TAIL}",
    ],
)
def test_false_positive_controls_stay_allowed(cmd: str) -> None:
    assert not _floor(cmd), cmd


def test_unrelated_expansion_overflow_stays_allowed() -> None:
    cmd = f"{_K} $({_PG} -f x{{1..9999}})"
    assert not _floor(cmd), cmd


@pytest.mark.parametrize(
    "cmd",
    [
        f"{_K} $({_PG} -f worker{{{{a..z}}{{a..z}}{{a..f}}" + "{a..a}" * 1200 + ",main}})",
        # many single-alternative groups multiplied by local-variable references
        f"{_K} $(x=worker" + "{a..a}" * 1000 + f"; {_PG} -f " + " ".join(["$x" * 40] * 3) + ")",
    ],
    ids=["wide-word", "variable-multiplied"],
)
def test_pathological_brace_work_fails_closed_within_budget(
    cmd: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The expansion work is bounded by one cumulative character budget per body,
    # so the number of group rewrites is a small constant here, not one per group
    # per word (over a hundred thousand for the second command without it).
    rewrites = [0]
    real = _argv_floor._brace_alternatives

    def counting(body: str, cap: int = _argv_floor._BRACE_EXPANSION_CAP) -> "list[str] | None":
        rewrites[0] += 1
        return real(body, cap)

    monkeypatch.setattr(_argv_floor, "_brace_alternatives", counting)
    assert _floor(cmd), "an over-budget brace word must fail closed"
    assert rewrites[0] <= 2000, rewrites[0]


def test_single_literal_resolver_declines_formats_and_multi_operand() -> None:
    from kiro_crew.security import shell_normalizer as sn

    def r(body: str) -> str:
        return sn._single_literal_output(body, _argv_floor._static_substitution_output)

    assert r(f"printf {_NAME}") == _NAME
    assert r(f"echo -n {_NAME}") == _NAME
    assert r("printf '%s@%s' a b") == "\x00"
    assert r(f"echo {_HEAD} {_TAIL}") == "\x00"
    assert r(f"printf '{_HEAD}\\n{_TAIL}'") == "\x00"
