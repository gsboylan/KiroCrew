"""The git-publish floor reads the PROGRAM word of every command it can reach.

A push run under a program word the shell resolves at run time -- a quoted
expansion (``"$G"``), a glob that can name git (``g?t``), a command
substitution -- is found wherever it sits: at the top of the line, after a
newline, a glued or background separator, inside a compound construct
(``if``/``while``/``for``/``select`` bodies, ``case`` arms, subshells, brace
groups, function bodies), behind a precommand and its options or a
redirection, or in a nested shell payload.

When the program word reaches exec as ONE word (a double-quoted parameter
expansion) and the words up to ``push`` are literal, git's argv is known, so the
push is judged by its target exactly like a literal git push: a protected or
bare target is denied, a feature target is allowed. Any other runtime-program
push is unverifiable.

No other command answers for such a push: not a sibling command, and not a
feature push carried among its own arguments.

A program whose BASENAME is literal (``"$SDK/platform-tools/adb"``) is that
program, not a runtime-resolved one, and commands that only MENTION a push stay
allowed.
"""

import pytest

from kiro_crew.security import _is_git_publish, _is_push_to_protected_branch, is_denied

# "pus" + "h" keeps a literal blocked command out of the test source.
P = "pus" + "h"
GIT_FEATURE = f"git {P} origin feature"
UNVERIFIABLE = "git-publish-target-unverifiable"
PROTECTED = "git-publish-push-protected-branch-name"
BARE = "git-publish-push-bare"

#: One-word program words: git's argv is known, so the TARGET decides.
JUDGED_BY_TARGET = [
    (f'"$G" {P} origin main', PROTECTED),
    (f'"$G" -C . {P} origin main', PROTECTED),
    (f'"$G" {P} origin HEAD:main', PROTECTED),
    (f'"$G" {P}', BARE),
    (f'G=git "$G" {P} origin main', PROTECTED),
    (f'"/usr/bin/$G" {P} origin main', PROTECTED),
    (f'"$G" {P} origin main eval {GIT_FEATURE}', PROTECTED),
    (f"\"$G\" {P} origin main eval '{GIT_FEATURE}'", PROTECTED),
]

#: Program words whose expansion can add words, or whose basename is resolved by
#: the shell: git's argv is not known, so the push is unverifiable.
UNVERIFIABLE_PROGRAM_WORDS = [
    f'"${{G}}" {P} origin feature',
    f"g?t {P} origin feature",
    f"/usr/bin/g?t {P} origin feature",
    f"/usr/bin/[g]it {P} origin feature",
    f"$(echo git) {P} origin feature",
    f"`echo git` {P} origin feature",
    f"$G {P} origin feature",
    f'"$@" {P} origin feature',
    f"{{git,}} {P} origin feature",
    f"$(printf %s git) -C $(printf %s .) {P} origin main",
    f"if true; then $(printf %s git | cat) {P} origin main; fi",
]

#: Every program position is read; each row runs a protected push.
PROGRAM_POSITIONS = [
    f'echo ok\n"$G" {P} origin main',
    f'set -e\nG=git\n"$G" {P} origin main',
    f'x=1;"$G" {P} origin main',
    f'cd x;"$G" {P} origin main',
    f'cd x&&"$G" {P} origin main',
    f'cd x||"$G" {P} origin main',
    f'true|"$G" {P} origin main',
    f'true & "$G" {P} origin main',
    f'true &"$G" {P} origin main',
    f'true |& "$G" {P} origin main',
    f"set -- git; echo '`' & \"$1\" {P} origin main",
    f'"$G" \\\n{P} origin main',
    f'2>/dev/null "$G" {P} origin main',
    f'>out "$G" {P} origin main',
    f'"$G" 2>&1 {P} origin main',
    f'"$G" > log {P} origin main',
    "\"$G\" p'ush' origin main",
    f'sudo "$G" {P} origin main',
    f'sudo -u root "$G" {P} origin main',
    f'env -i "$G" {P} origin main',
    f'env -u X "$G" {P} origin main',
    f'exec -a x "$G" {P} origin main',
    f'nice -n 5 "$G" {P} origin main',
    f'timeout 5 "$G" {P} origin main',
    f'setsid "$G" {P} origin main',
    f'ionice -c3 "$G" {P} origin main',
    f'stdbuf -o0 "$G" {P} origin main',
    f'xargs "$G" {P} origin main',
    f'xargs -I{{}} "$G" {P} origin main',
    f'coproc "$G" {P} origin main',
    f'command "$G" {P} origin main',
    f'time -p "$G" {P} origin main',
    f'case x in x) "$G" {P} origin main;; esac',
    f'set -- git; case x in x)"$1" {P} origin main;; esac',
    f'case x in (x) "$G" {P} origin main;; esac',
    f'if true; then "$G" {P}; fi',
    f"if true; then $G {P} origin main; fi",
    f'if "$G" {P} origin main; then :; fi',
    f'if false; then :; else "$G" {P}; fi',
    f'for i in 1; do "$G" {P}; done',
    f'while true; do "$G" {P} origin main; done',
    f'until false; do "$G" {P} origin main; done',
    f'select x in a; do "$G" {P} origin main; done',
    f'if true\nthen\n"$G" {P} origin main\nfi',
    f'( "$G" {P} origin main )',
    f'("$G" {P} origin main)',
    f'{{ "$G" {P} origin main; }}',
    f'f() {{ "$G" {P} origin main; }}; f',
    f'f(){{ "$G" {P} origin main;}};f',
    f'function f {{ "$G" {P} origin main; }}; f',
    f"if true; then `echo git` {P} origin main; fi",
    f'! "$G" {P} origin main',
    f'time "$G" {P} origin main',
    f'"$G" {P} origin main ; {GIT_FEATURE}',
    f'"$G" {P} origin main && {GIT_FEATURE}',
    f'{GIT_FEATURE} ; "$G" {P} origin main',
    f'if true; then "$G" {P}; fi; {GIT_FEATURE}',
    f'case x in x) "$G" {P} origin main;; esac; {GIT_FEATURE}',
    f'( "$G" {P} origin main ); {GIT_FEATURE}',
    f'{{ "$G" {P} origin main; }} && {GIT_FEATURE}',
    f'"$G" {P} origin feature & git log & git {P} origin main',
    f'"$G" {P} origin feature & git {P} origin main',
    f"bash -c '\"$G\" {P} origin main'",
    f"bash -c '\"$G\" {P} origin main' && {GIT_FEATURE}",
    f"eval '\"$G\" {P} origin main'",
    f"sh -c 'if true; then \"$G\" {P}; fi'",
    f"\"$G\" {P} origin main bash -c '{GIT_FEATURE}'",
    f'"$G" {P} origin main <({GIT_FEATURE})',
]

STILL_ALLOWED = [
    GIT_FEATURE,
    f'"$G" {P} origin feature',
    f'"/usr/bin/$G" {P} origin feature',
    f'for i in 1; do "$G" {P} origin feature; done',
    f'"$G" stash {P}',
    '"$G" status',
    f'"$G" log --grep {P}',
    f'echo "$G" {P}',
    f"printf '%s\\n' \"$x\" {P}",
    f'printf \'%s\\n\' "$(date)" "$name" {P}',
    f'echo $(date) "$x" {P}',
    f'echo $(date +%s) "$x" {P}',
    f'echo "a;" "$x" {P}',
    f'echo "a)" "$G" {P} x',
    f'echo "(" "$x" {P} now',
    f"grep -e '{{' \"$f\" {P}",
    f'printf "%s|" "$x" {P}',
    f'echo do "$X" {P} y',
    f'"$PAGER" {P}.txt',
    f"make {P}",
    f"echo {P}",
    '"$EDITOR" file.txt',
    "$CC -o x x.c",
    'for f in *.py; do black "$f"; done',
    f'cd "$dir" && {GIT_FEATURE}',
    f'if [ -n "$X" ]; then {GIT_FEATURE}; fi',
    f"nice -n 5 {GIT_FEATURE}",
    f"bash -c '{GIT_FEATURE}'",
    f"bash -c 'if true; then {GIT_FEATURE}; fi'",
    f"'git' {P} origin feature",
    f"sleep 1 & {GIT_FEATURE}",
    f'"$G" status 2>&1 | grep {P}',
    f'echo $(cat a b) "$x" {P}',
    'case "$1" in a) echo a;; esac',
    f"time {GIT_FEATURE}",
    f'"$ANDROID_HOME/platform-tools/adb" {P} app-debug.apk /data/local/tmp/',
    f'cd android && "$ANDROID_SDK_ROOT/platform-tools/adb" {P} app.apk /sdcard/',
    f'"$VENV/bin/dvc" {P} -r storage',
    f'"$HOME/bin/deploy" {P} origin main',
    f'"$HOME/bin/git" {P} origin feature',
    f'"$HELM" {P} chart-0.1.0.tgz oci://ghcr.io/example-org/charts',
    f'"$CACHIX" {P} example-cache ./result',
    f'sudo echo "$x" {P}',
    f'nice -n 5 make "$T" {P}',
    f'sudo docker "$x" {P}',
]


@pytest.mark.parametrize(("command", "rule"), JUDGED_BY_TARGET)
def test_a_one_word_runtime_program_is_judged_by_its_target(command: str, rule: str) -> None:
    assert _is_git_publish(command.lower()) is True
    reason = is_denied(command)
    assert reason is not None, command
    assert rule in reason, reason


@pytest.mark.parametrize("command", UNVERIFIABLE_PROGRAM_WORDS)
def test_a_program_word_that_can_add_words_is_unverifiable(command: str) -> None:
    assert _is_git_publish(command.lower()) is True
    assert _is_push_to_protected_branch(command.lower()) is True
    reason = is_denied(command)
    assert reason is not None, command
    assert UNVERIFIABLE in reason, reason


@pytest.mark.parametrize("command", PROGRAM_POSITIONS)
def test_every_program_position_is_read(command: str) -> None:
    reason = is_denied(command)
    assert reason is not None, command
    assert "git-publish" in reason or UNVERIFIABLE in reason, reason


@pytest.mark.parametrize("command", STILL_ALLOWED)
def test_commands_that_do_not_run_a_protected_publish_stay_allowed(command: str) -> None:
    assert is_denied(command) is None
