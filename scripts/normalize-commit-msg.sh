#!/usr/bin/env bash
set -euo pipefail

# Normalizes a commit message file in-place to fix common Conventional Commits
# mistakes before the validator rejects them.
#
# Usage:
#   normalize-commit-msg.sh <commit-msg-file>
#   normalize-commit-msg.sh --test          (run self-tests)

normalize_subject() {
  local line="$1"

  # Skip exception patterns (Merge, Revert, fixup/squash/amend).
  if [[ "$line" =~ ^(Merge\ |Revert\ |fixup!\ |squash!\ |amend!\ ) ]]; then
    printf '%s' "$line"
    return
  fi

  # Match Conventional Commits pattern: type[(scope)][!]: description
  # The regex is case-insensitive on the type via alternation of mixed case.
  local cc_re='^([A-Za-z0-9]+)(\([a-zA-Z0-9_/ -]+\))?(!)?: *(.+)$'
  if [[ ! "$line" =~ $cc_re ]]; then
    printf '%s' "$line"
    return
  fi

  local raw_type="${BASH_REMATCH[1]}"
  local scope="${BASH_REMATCH[2]}"
  local bang="${BASH_REMATCH[3]}"
  local desc="${BASH_REMATCH[4]}"

  # Lowercase the type.
  local lower_type
  lower_type="$(printf '%s' "$raw_type" | tr '[:upper:]' '[:lower:]')"

  # Check if the type is valid.
  case "$lower_type" in
    feat|fix|docs|chore|refactor|test|ci|style|perf|build|a11y) ;;
    *)
      printf '%s' "$line"
      return
      ;;
  esac

  # Remove trailing period from description.
  desc="${desc%.}"

  # Lowercase first letter only for Title Case (avoid mangling acronyms like HTTP).
  if [[ "$desc" =~ ^[A-Z][a-z] ]]; then
    local first="${desc:0:1}"
    local rest="${desc:1}"
    first="$(printf '%s' "$first" | tr '[:upper:]' '[:lower:]')"
    desc="${first}${rest}"
  fi

  printf '%s%s%s: %s' "$lower_type" "$scope" "$bang" "$desc"
}

# --test: run self-tests and exit.
if [ "${1:-}" = "--test" ]; then
  pass=0
  fail=0

  assert_eq() {
    local input="$1" expected="$2"
    local actual
    actual="$(normalize_subject "$input")"
    if [ "$actual" = "$expected" ]; then
      pass=$((pass + 1))
    else
      echo "FAIL: normalize_subject '$input'"
      echo "  expected: '$expected'"
      echo "  actual:   '$actual'"
      fail=$((fail + 1))
    fi
  }

  # Lowercase type prefix.
  assert_eq "Feat: add feature"         "feat: add feature"
  assert_eq "FIX(scope): something"     "fix(scope): something"
  assert_eq "DOCS: update readme"       "docs: update readme"
  assert_eq "Chore!: drop legacy"       "chore!: drop legacy"
  assert_eq "CI(build)!: rework pipeline" "ci(build)!: rework pipeline"

  # Missing space after colon.
  assert_eq "fix:quick patch"           "fix: quick patch"
  assert_eq "feat(ui):new button"       "feat(ui): new button"
  assert_eq "chore!:drop old api"       "chore!: drop old api"

  # Trailing period.
  assert_eq "feat: add feature."        "feat: add feature"
  assert_eq "fix(core): patch bug."     "fix(core): patch bug"

  # Excess whitespace after colon.
  assert_eq "feat:  add feature"        "feat: add feature"
  assert_eq "fix:   patch"              "fix: patch"

  # Uppercase description start.
  assert_eq "feat: Add feature"         "feat: add feature"
  assert_eq "fix(core): Handle error"   "fix(core): handle error"

  # Combined fixes.
  assert_eq "FEAT:Add feature."         "feat: add feature"
  assert_eq "Fix(ui):  Big button."     "fix(ui): big button"

  # Acronym preservation — do not lowercase all-caps starts.
  assert_eq "feat: HTTP client support"  "feat: HTTP client support"
  assert_eq "fix: URL parsing bug"       "fix: URL parsing bug"
  assert_eq "FEAT: API overhaul"         "feat: API overhaul"
  assert_eq "fix: CSS reset."            "fix: CSS reset"

  # Already correct — no change.
  assert_eq "feat: add linting"         "feat: add linting"
  assert_eq "fix(ci)!: tighten checks"  "fix(ci)!: tighten checks"
  assert_eq "a11y: improve reader"      "a11y: improve reader"

  # Exception patterns — pass through unchanged.
  assert_eq "Merge branch 'main'"       "Merge branch 'main'"
  assert_eq "Revert \"feat: add\""      "Revert \"feat: add\""
  assert_eq "fixup! feat: add linting"  "fixup! feat: add linting"
  assert_eq "squash! feat: something"   "squash! feat: something"
  assert_eq "amend! fix: thing"         "amend! fix: thing"

  # Non-matching messages — pass through unchanged.
  assert_eq "random commit message"     "random commit message"

  echo ""
  echo "normalize-commit-msg self-tests: $pass passed, $fail failed"
  [ "$fail" -eq 0 ]
  exit
fi

# Normal mode: normalize commit message file in-place.
commit_msg_file="${1:-}"
if [ -z "$commit_msg_file" ]; then
  echo "Usage: normalize-commit-msg.sh <commit-msg-file>" >&2
  echo "       normalize-commit-msg.sh --test" >&2
  exit 2
fi

if [ ! -f "$commit_msg_file" ]; then
  echo "ERROR: commit message file not found: $commit_msg_file" >&2
  exit 2
fi

subject="$(head -1 "$commit_msg_file")"
normalized="$(normalize_subject "$subject")"

if [ "$subject" != "$normalized" ]; then
  # Replace only the first line, preserving the rest of the file exactly.
  tmp_file="${commit_msg_file}.tmp"
  {
    printf '%s\n' "$normalized"
    tail -n +2 "$commit_msg_file"
  } > "$tmp_file" && mv "$tmp_file" "$commit_msg_file"
fi
