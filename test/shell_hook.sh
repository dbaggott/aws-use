#!/usr/bin/env bash
# Verifies the `aws-use shellenv` hook dispatches correctly. Run it under every
# shell we support (bash 3.2 and zsh) in CI. A stub stands in for the binary so
# no AWS is needed — we're testing the shell function, not the tool.
#
# Usage: <bash|zsh> test/shell_hook.sh ./aws-use
set -u

REAL="${1:?usage: shell_hook.sh <path-to-aws-use-binary>}"
pass=0
fail=0
check() { # desc want got
  if [ "$2" = "$3" ]; then
    echo "ok   - $1"
    pass=$((pass + 1))
  else
    echo "FAIL - $1: want [$2] got [$3]"
    fail=$((fail + 1))
  fi
}

stubdir="$(mktemp -d)"
stub="$stubdir/aws-use"
cat >"$stub" <<'EOF'
#!/bin/sh
case "$1" in
  use) shift; echo "export AWS_PROFILE=switched-${1:-interactive}" ;;
  *)   echo "PASSTHROUGH: $*" ;;
esac
EOF
chmod +x "$stub"

# Point the real hook's `command <bin>` at the stub, so we exercise the real
# dispatch logic (case branches, leading-"use" strip, eval) against a
# controllable backend.
hook="$("$REAL" shellenv)"
emitted="$(printf '%s\n' "$hook" | sed -n 's/^ *command "\(.*\)" "\$@"$/\1/p' | head -1)"
hook="$(printf '%s\n' "$hook" | sed "s#$emitted#$stub#g")"
eval "$hook"

check "passthrough (ls)" "PASSTHROUGH: ls" "$(aws-use ls)"
unset AWS_PROFILE; aws-use >/dev/null 2>&1; check "bare switch" "switched-interactive" "${AWS_PROFILE:-}"
unset AWS_PROFILE; aws-use dnbg admin >/dev/null 2>&1; check "query switch" "switched-dnbg" "${AWS_PROFILE:-}"
unset AWS_PROFILE; aws-use use foo >/dev/null 2>&1; check "explicit use (stripped)" "switched-foo" "${AWS_PROFILE:-}"

echo "---- $pass passed, $fail failed ----"
[ "$fail" -eq 0 ]
