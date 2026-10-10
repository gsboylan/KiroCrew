"""The credential scan stays linear on a long ``eyJ`` run and finds every match ``search`` finds.

On a file of ``eyJ`` repeats, ``_CREDENTIAL_PATTERNS.search`` re-walks the run from every
``eyJ`` (the JWT branch's greedy segment backtracks to the run end each time), so one
batch ``redact()`` of a capped dashboard file read would spend minutes holding the GIL.
``_credential_search`` finds the JWT-branch start separately and jumps a failed run
whole. These tests pin both halves: the match sequence is identical to the plain
``search`` loop, and the cost grows linearly.
"""

from __future__ import annotations

import base64
import json
import random
import re
import time
from typing import Any

import pytest

from kiro_crew.credential_patterns import JWT_MULTI_SEGMENT
from kiro_crew.security import redact, redaction


def _b64(obj: Any) -> str:
    raw = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


_JWS = f"{_b64({'alg': 'HS256', 'typ': 'JWT'})}.{_b64({'sub': 'u1'})}.{_b64(b'sig' * 11)}"
_JWE_DIR = f"{_b64({'alg': 'dir', 'enc': 'A256GCM'})}..{_b64(b'iv' * 6)}.{_b64(b'ct' * 9)}.tag"
_LINK = f"eyJ{'A' * 120}.{'B' * 43}"
_AWS = "AKIAIOSFODNN7EXAMPLE"


def _search_loop(text: str) -> list[tuple[int, int]]:
    """The reference scan: one ``search`` per step from the last match."""
    spans, pos = [], 0
    while (m := redaction._CREDENTIAL_PATTERNS.search(text, pos)) is not None:
        spans.append(m.span())
        pos = max(m.end(), m.start() + 1)
    return spans


def _linear_loop(text: str) -> list[tuple[int, int]]:
    spans, pos, starts = [], 0, [-1, -1]
    while (m := redaction._credential_search(text, pos, starts)) is not None:
        spans.append(m.span())
        pos = max(m.end(), m.start() + 1)
    return spans


_PIECES = (
    "eyJ", ".", "..", "a", "Z9", "-", "_", " ", "=", '"', "\n", "e", "yJ", "k",
    _AWS, "ghp_" + "x" * 36, "Authorization: Bearer ", "://u:p@", "sk-ant-",
    _b64({"alg": "none"}),
)  # fmt: skip


def test_match_sequence_equals_the_plain_search_loop_on_random_text() -> None:
    rng = random.Random(17553)
    for _ in range(20_000):
        text = "".join(rng.choice(_PIECES) for _ in range(rng.randint(0, 40)))
        assert _linear_loop(text) == _search_loop(text), text


@pytest.mark.parametrize(
    "text",
    [
        _JWS,
        f"token {_JWS} end.",
        _JWE_DIR,
        _LINK,
        f"x{_JWS}",
        "eyJ" * 400 + ".a.b",
        "eyJ" * 400 + " " + _JWS,
        "eyJ" * 400 + f" {_AWS}",
        f"{_AWS} " + "eyJ" * 400,
        ("eyJ" * 50 + ".") * 30 + _JWS,
    ],
    ids=lambda text: f"len{len(text)}",
)
def test_every_credential_shape_is_still_redacted(text: str) -> None:
    assert _linear_loop(text) == _search_loop(text)
    out = redact(text)
    for secret in (_JWS, _JWE_DIR, _LINK, _AWS):
        assert secret not in out
    assert "[REDACTED" in out


def test_the_branch_check_agrees_with_the_branch_pattern_at_every_eyj() -> None:
    pattern = re.compile(JWT_MULTI_SEGMENT)
    rng = random.Random(1755)
    for _ in range(5_000):
        text = "".join(rng.choice(("eyJ", ".", "a", "-", " ", "e")) for _ in range(24))
        i = text.find("eyJ")
        while i != -1:
            expected = pattern.match(text, i) is not None
            got = redaction._jwt_branch_matches_at(text, i, redaction._segment_run_end(text, i))
            assert got is expected, (text, i)
            i = text.find("eyJ", i + 1)


def test_a_long_eyj_run_costs_one_branch_attempt(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0
    real = redaction._jwt_branch_matches_at

    def counting(text: str, i: int, run_end: int) -> bool:
        nonlocal calls
        calls += 1
        return real(text, i, run_end)

    monkeypatch.setattr(redaction, "_jwt_branch_matches_at", counting)
    assert list(redaction._credential_matches("eyJ" * 20_000)) == []
    assert calls == 1


def _best_of(text: str, runs: int = 3) -> float:
    best = float("inf")
    for _ in range(runs):
        start = time.perf_counter()
        redact(text)
        best = min(best, time.perf_counter() - start)
    return best


def test_redact_grows_linearly_on_an_eyj_run() -> None:
    small = _best_of("eyJ" * 8_000)
    large = _best_of("eyJ" * 32_000)
    # Four times the input: about 4x when linear, 16x when quadratic.
    assert large <= max(small, 0.005) * 10, (small, large)
