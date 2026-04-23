#!/usr/bin/env bash
# roadmap-entropy.sh — Quantify scope creep and drift in the project roadmap.
#
# Computes five metrics, rolls them into an overall entropy score (0–100),
# and outputs a JSON summary.  Exits non-zero when the score exceeds the
# configurable threshold (default 70).
#
# Usage:
#   scripts/roadmap-entropy.sh [--threshold N] [--since DAYS] [--json]
set -euo pipefail

###############################################################################
# Defaults
###############################################################################
THRESHOLD="${ENTROPY_THRESHOLD:-70}"
SINCE_DAYS="${ENTROPY_SINCE_DAYS:-30}"
COMMIT_TYPES="${ENTROPY_COMMIT_TYPES:-feat fix docs chore refactor test ci style perf build}"
JSON_ONLY=0
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
SINCE_DATE=""

###############################################################################
# CLI
###############################################################################
while [ $# -gt 0 ]; do
  case "$1" in
    --threshold)
      [ $# -ge 2 ] || { echo "Missing value for --threshold" >&2; exit 2; }
      THRESHOLD="$2"
      shift 2
      ;;
    --since)
      [ $# -ge 2 ] || { echo "Missing value for --since" >&2; exit 2; }
      SINCE_DAYS="$2"
      shift 2
      ;;
    --json)      JSON_ONLY=1; shift ;;
    -h|--help)
      echo "Usage: roadmap-entropy.sh [--threshold N] [--since DAYS] [--json]"
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

# Validate numeric inputs from CLI/env so arithmetic/date operations are safe.
case "$THRESHOLD" in
  ''|*[!0-9]*)
    echo "Invalid --threshold value: '$THRESHOLD' (expected integer 0-100)" >&2
    exit 2
    ;;
esac
if [ "$THRESHOLD" -lt 0 ] || [ "$THRESHOLD" -gt 100 ]; then
  echo "Invalid --threshold value: '$THRESHOLD' (expected integer 0-100)" >&2
  exit 2
fi

case "$SINCE_DAYS" in
  ''|*[!0-9]*)
    echo "Invalid --since value: '$SINCE_DAYS' (expected integer >= 1)" >&2
    exit 2
    ;;
esac
if [ "$SINCE_DAYS" -lt 1 ]; then
  echo "Invalid --since value: '$SINCE_DAYS' (expected integer >= 1)" >&2
  exit 2
fi
if [ -z "${COMMIT_TYPES//[[:space:]]/}" ]; then
  echo "Invalid ENTROPY_COMMIT_TYPES: expected a non-empty whitespace-separated list" >&2
  exit 2
fi

###############################################################################
# Helpers
###############################################################################
# Portable integer min/max
min() { [ "$1" -le "$2" ] && echo "$1" || echo "$2"; }

# Cross-platform date parsing for "N days ago" with fallback.
compute_since_date() {
  date -v-"${SINCE_DAYS}"d +%Y-%m-%d 2>/dev/null || \
    date -d "${SINCE_DAYS} days ago" +%Y-%m-%d 2>/dev/null || \
    echo "1970-01-01"
}

# Integer division rounded to nearest (avoids bc/awk float dependency).
div_round() {
  local num="$1" den="$2"
  if [ "$den" -eq 0 ]; then echo 0; return; fi
  echo $(( (num + den / 2) / den ))
}

###############################################################################
# M1 — Commit-type distribution (0–100)
#
# A healthy project has a balanced mix of feat/fix/docs/chore/… types.
# We measure the share of the dominant type — if one type accounts for >60 %
# of commits the score rises sharply.
###############################################################################
compute_commit_type_score() {
  local since_date="$SINCE_DATE"

  local totals
  totals="$(
    git log --since="$since_date" --format='%s' 2>/dev/null | awk -v types="$COMMIT_TYPES" '
      BEGIN {
        split(types, type_list, " ")
        for (i in type_list) allowed[type_list[i]] = 1
      }
      /^(Merge |Revert |(fixup|squash|amend)!)/ { next }
      {
        if (match($0, /^[a-z]+/)) {
          t = substr($0, RSTART, RLENGTH)
          rest = substr($0, RLENGTH + 1)
          if (allowed[t] && (substr(rest, 1, 1) == ":" || substr(rest, 1, 1) == "(" || substr(rest, 1, 2) == "!:")) {
            counts[t]++
            total++
          }
        }
      }
      END {
        max_count = 0
        for (t in counts) {
          if (counts[t] > max_count) max_count = counts[t]
        }
        printf "%d %d\n", total, max_count
      }
    '
  )"

  if [ -z "$totals" ]; then
    echo 0
    return
  fi

  local total max_count
  read -r total max_count <<EOF
$totals
EOF

  if [ "$total" -eq 0 ]; then
    echo 0
    return
  fi

  # dominant_pct 0–100
  local dominant_pct
  dominant_pct=$(div_round "$(( max_count * 100 ))" "$total")

  # Score: if dominant_pct <= 40 → 0, rises linearly to 100 at 100 %
  if [ "$dominant_pct" -le 40 ]; then
    echo 0
  else
    div_round "$(( (dominant_pct - 40) * 100 ))" 60
  fi
}

###############################################################################
# M2 — Changelog growth (0–100)
#
# Counts lines added to CHANGELOG.md in the window.  Rapid growth hints at
# scope inflation.  Thresholds: 0 lines → 0, ≥200 lines → 100.
###############################################################################
compute_changelog_score() {
  local changelog="${REPO_ROOT}/CHANGELOG.md"
  if [ ! -f "$changelog" ]; then echo 0; return; fi

  local since_date="$SINCE_DATE"

  local added=0
  while IFS= read -r line; do
    # git log --numstat outputs: added<TAB>deleted<TAB>file
    # Skip blank lines and binary entries (-)
    [ -z "$line" ] && continue
    local a
    a="${line%%$'\t'*}"
    case "$a" in
      ''|'-') continue ;;
    esac
    added=$(( added + a ))
  done < <(git log --since="$since_date" --numstat --format="" -- "$changelog" 2>/dev/null)

  # Clamp to 0–100
  local score
  if [ "$added" -ge 200 ]; then
    score=100
  else
    score=$(( added * 100 / 200 ))
  fi
  echo "$score"
}

###############################################################################
# M3 — Kanban WIP count (0–100)
#
# Scans kanban files for "In Progress" items.  ≥5 concurrent WIP items → 100.
###############################################################################
compute_wip_score() {
  local -a kanban_files=()
  if [ -d "$REPO_ROOT/docs" ]; then
    while IFS= read -r -d '' f; do
      kanban_files+=("$f")
    done < <(find "$REPO_ROOT/docs" -type f \( -name '*kanban*' -o -name '*board*' \) -print0 2>/dev/null)
  fi
  if [ -f "$REPO_ROOT/TODO.md" ]; then
    kanban_files+=("$REPO_ROOT/TODO.md")
  fi

  local wip=0
  if [ ${#kanban_files[@]} -gt 0 ]; then
    wip="$(
      awk '
        FNR == 1 { in_progress = 0 }
        /^##[[:space:]]+In[[:space:]]+Progress([[:space:]]|$)/ { in_progress = 1; next }
        /^##[[:space:]]/ { in_progress = 0 }
        in_progress && /^- / {
          line = tolower($0)
          if (line !~ /^- none([[:space:]]|$)/) count++
        }
        END { print count + 0 }
      ' "${kanban_files[@]}"
    )"
  fi

  # 0 WIP → 0, 5+ WIP → 100
  local score
  score=$(min "$(( wip * 100 / 5 ))" 100)
  echo "$score"
}

###############################################################################
# M4 — Plan staleness (0–100)
#
# How many days since PLAN.md (or similar) was last touched in a commit.
# ≥90 days stale → 100.
###############################################################################
compute_staleness_score() {
  local plan_files=()
  for f in PLAN.md ROADMAP.md TODO.md; do
    [ -f "$REPO_ROOT/$f" ] && plan_files+=("$REPO_ROOT/$f")
  done

  if [ ${#plan_files[@]} -eq 0 ]; then
    echo 0
    return
  fi

  local newest_epoch=0
  for f in "${plan_files[@]}"; do
    local epoch
    epoch="$(git log -1 --format='%ct' -- "$f" 2>/dev/null || true)"
    epoch="${epoch:-0}"
    if [ "$epoch" -gt "$newest_epoch" ]; then newest_epoch="$epoch"; fi
  done

  if [ "$newest_epoch" -eq 0 ]; then
    # File exists but was never committed — treat as maximally stale
    echo 100
    return
  fi

  local now_epoch
  now_epoch="$(date +%s)"
  local days_stale=$(( (now_epoch - newest_epoch) / 86400 ))

  # 0 days → 0, ≥90 days → 100
  local score
  score=$(min "$(div_round "$(( days_stale * 100 ))" 90)" 100)
  echo "$score"
}

###############################################################################
# M5 — Unplanned feature ratio (0–100)
#
# "feat" commits that don't reference an issue number (e.g., #42) are
# considered unplanned.  ≥80% unplanned → 100.
###############################################################################
compute_unplanned_score() {
  local since_date="$SINCE_DATE"

  local total=0 unplanned=0

  while IFS= read -r -d '' message; do
    local subject
    subject="${message%%$'\n'*}"
    case "$subject" in
      'Merge '*|'Revert '*|'fixup!'*|'squash!'*|'amend!'*)
        continue
        ;;
    esac

    if [[ "$subject" =~ ^feat(\(|!:|:) ]]; then
      total=$(( total + 1 ))
      # Check body + subject for an issue reference (#NN)
      if [[ ! "$message" =~ \#[0-9]+ ]]; then
        unplanned=$(( unplanned + 1 ))
      fi
    fi
  done < <(git log --since="$since_date" --format='%B%x00' 2>/dev/null)

  if [ "$total" -eq 0 ]; then
    echo 0
    return
  fi

  local pct=$(( unplanned * 100 / total ))
  # 0 % unplanned → 0, ≥80 % → 100
  if [ "$pct" -le 10 ]; then
    echo 0
  elif [ "$pct" -ge 80 ]; then
    echo 100
  else
    echo $(( (pct - 10) * 100 / 70 ))
  fi
}

###############################################################################
# Main
###############################################################################
SINCE_DATE="$(compute_since_date)"

m1="$(compute_commit_type_score)"
m2="$(compute_changelog_score)"
m3="$(compute_wip_score)"
m4="$(compute_staleness_score)"
m5="$(compute_unplanned_score)"

# Weighted average (commit distribution and unplanned features weigh more).
#   M1: 25%  M2: 15%  M3: 20%  M4: 15%  M5: 25%
overall=$(div_round "$(( m1 * 25 + m2 * 15 + m3 * 20 + m4 * 15 + m5 * 25 ))" 100)
overall=$(min "$overall" 100)

pass="true"
if [ "$overall" -gt "$THRESHOLD" ]; then
  pass="false"
fi

# JSON output
json="$(cat <<EOF
{
  "entropy_score": ${overall},
  "threshold": ${THRESHOLD},
  "pass": ${pass},
  "window_days": ${SINCE_DAYS},
  "metrics": {
    "commit_type_distribution": ${m1},
    "changelog_growth": ${m2},
    "kanban_wip": ${m3},
    "plan_staleness": ${m4},
    "unplanned_feature_ratio": ${m5}
  }
}
EOF
)"

if [ "$JSON_ONLY" -eq 1 ]; then
  echo "$json"
else
  echo "=== Roadmap Entropy Report ==="
  echo ""
  echo "  Window          : last ${SINCE_DAYS} days"
  echo "  Threshold       : ${THRESHOLD}"
  echo ""
  echo "  M1 commit-type  : ${m1}/100"
  echo "  M2 changelog    : ${m2}/100"
  echo "  M3 kanban WIP   : ${m3}/100"
  echo "  M4 plan stale   : ${m4}/100"
  echo "  M5 unplanned    : ${m5}/100"
  echo ""
  echo "  ENTROPY SCORE   : ${overall}/100"
  echo ""
  if [ "$pass" = "true" ]; then
    echo "  Result: PASS"
  else
    echo "  Result: FAIL (exceeds threshold ${THRESHOLD})"
  fi
  echo ""
  echo "$json"
fi

if [ "$pass" = "false" ]; then
  exit 1
fi
