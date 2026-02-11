#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  validate-commit-msg.sh [--quiet] --from-file <path>
  validate-commit-msg.sh [--quiet] "<commit-subject>"
EOF
}

quiet=0
mode=""
input=""

while [ $# -gt 0 ]; do
  case "$1" in
    --quiet)
      quiet=1
      shift
      ;;
    --from-file)
      mode="file"
      shift
      if [ $# -eq 0 ]; then
        usage >&2
        exit 2
      fi
      input="$1"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      if [ -n "$mode" ]; then
        usage >&2
        exit 2
      fi
      mode="message"
      input="$1"
      shift
      ;;
  esac
done

if [ -z "$mode" ] || [ -z "$input" ]; then
  usage >&2
  exit 2
fi

if [ "$mode" = "file" ]; then
  if [ ! -f "$input" ]; then
    echo "ERROR: commit message file not found: $input" >&2
    exit 2
  fi
  commit_msg="$(head -1 "$input")"
else
  commit_msg="$input"
fi

# Allowed exceptions.
if echo "$commit_msg" | grep -qE '^Merge '; then
  exit 0
fi
if echo "$commit_msg" | grep -qE '^Revert '; then
  exit 0
fi
if echo "$commit_msg" | grep -qE '^(fixup|squash|amend)! '; then
  exit 0
fi

# Conventional Commits: <type>[(<scope>)][!]: <description>
pattern='^(feat|fix|docs|chore|refactor|test|ci|style|perf|build)(\([a-zA-Z0-9_/ -]+\))?\!?: .+'
if echo "$commit_msg" | grep -qE "$pattern"; then
  exit 0
fi

if [ "$quiet" -eq 1 ]; then
  exit 1
fi

echo >&2 "ERROR: Commit message does not follow Conventional Commits format."
echo >&2 ""
echo >&2 "  Expected: <type>[(<scope>)][!]: <description>"
echo >&2 "  Types:    feat, fix, docs, chore, refactor, test, ci, style, perf, build"
echo >&2 ""
echo >&2 "  Exceptions: Merge ..., Revert ..., fixup!/squash!/amend!"
echo >&2 ""
echo >&2 "  Examples:"
echo >&2 "    feat: add new query mode"
echo >&2 "    fix(server): handle empty database"
echo >&2 "    docs: update README examples"
echo >&2 "    chore!: drop legacy API"
echo >&2 ""
echo >&2 "  Your message: $commit_msg"
exit 1
