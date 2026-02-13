#!/usr/bin/env bash
set -euo pipefail

# Bus-Factor Analyzer
# Analyzes code ownership concentration using git blame data.
# Outputs a Markdown-formatted report with per-file ownership,
# per-module aggregation, bus-factor score, and high-risk files.

usage() {
  cat <<'EOF'
Usage: bus-factor.sh [OPTIONS]

Analyze code ownership concentration in a git repository.

Options:
  --path <dir>        Repository path (default: current directory)
  --threshold <pct>   Single-author risk threshold percentage (default: 80)
  --format <fmt>      Output format: markdown (default) or json
  -h, --help          Show this help message

Output:
  Per-file and per-module line ownership metrics, bus-factor score,
  and high-risk files where a single author owns more than the threshold.
EOF
}

repo_path="."
risk_threshold=80
output_format="markdown"

json_escape() {
  local s="$1"
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\b'/\\b}
  s=${s//$'\f'/\\f}
  s=${s//$'\t'/\\t}
  s=${s//$'\r'/\\r}
  s=${s//$'\n'/\\n}
  printf '%s' "$s"
}

tsv_escape() {
  local s="$1"
  s=${s//\\/\\\\}
  s=${s//$'\t'/\\t}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  printf '%s' "$s"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --path)
      shift
      if [ $# -eq 0 ] || [[ "$1" == -* ]]; then
        echo "ERROR: --path requires a directory argument" >&2
        usage >&2
        exit 2
      fi
      repo_path="$1"; shift ;;
    --threshold)
      shift
      if [ $# -eq 0 ] || [[ "$1" == -* ]]; then
        echo "ERROR: --threshold requires an integer argument" >&2
        usage >&2
        exit 2
      fi
      risk_threshold="$1"; shift ;;
    --format)
      shift
      if [ $# -eq 0 ] || [[ "$1" == -* ]]; then
        echo "ERROR: --format requires either 'markdown' or 'json'" >&2
        usage >&2
        exit 2
      fi
      output_format="$1"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$risk_threshold" in
  ''|*[!0-9]*)
    echo "ERROR: --threshold must be an integer between 0 and 100" >&2
    exit 2
    ;;
esac
if [ "$risk_threshold" -lt 0 ] || [ "$risk_threshold" -gt 100 ]; then
  echo "ERROR: --threshold must be an integer between 0 and 100" >&2
  exit 2
fi
if [ "$output_format" != "markdown" ] && [ "$output_format" != "json" ]; then
  echo "ERROR: --format must be 'markdown' or 'json'" >&2
  exit 2
fi

if [ ! -d "$repo_path/.git" ] && ! git -C "$repo_path" rev-parse --git-dir >/dev/null 2>&1; then
  echo "ERROR: $repo_path is not a git repository" >&2
  exit 1
fi

# Temporary working directory
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

# Collect all tracked source files (skip generated/build artifacts).
tracked_files="$tmp_dir/tracked_files.zlist"
git -C "$repo_path" ls-files -z -- \
  '*.rs' '*.toml' '*.sh' '*.md' '*.yml' '*.yaml' '*.json' '*.ts' '*.js' '*.py' \
  ':(exclude)target/**' ':(exclude)Cargo.lock' > "$tracked_files"

if [ ! -s "$tracked_files" ]; then
  echo "ERROR: No tracked source files found" >&2
  exit 1
fi

# --- Phase 1: Per-file blame analysis ---
# Output: file | author | line_count
blame_data="$tmp_dir/blame_data.tsv"
touch "$blame_data"
blame_err="$tmp_dir/blame.err"

while IFS= read -r -d '' file; do
  # Skip files that don't exist on disk (deleted but tracked)
  [ -f "$repo_path/$file" ] || continue

  escaped_file=$(tsv_escape "$file")
  if ! git -C "$repo_path" blame --line-porcelain -- "$file" 2>"$blame_err" \
    | BUS_FACTOR_FILE="$escaped_file" awk '
      /^author / {
        name = substr($0, 8)
        gsub(/[\t\r\n]/, " ", name)
        counts[name]++
      }
      END {
        for (a in counts) {
          printf "%s\t%s\t%d\n", ENVIRON["BUS_FACTOR_FILE"], a, counts[a]
        }
      }
    ' >> "$blame_data"; then
    if [ -s "$blame_err" ]; then
      echo "WARN: Skipping file due to git blame failure: $file ($(head -n1 "$blame_err"))" >&2
    else
      echo "WARN: Skipping file due to git blame failure: $file" >&2
    fi
    continue
  fi
done < "$tracked_files"

if [ ! -s "$blame_data" ]; then
  echo "ERROR: No blame data collected" >&2
  exit 1
fi

# --- Phase 2: Compute per-file metrics ---
per_file="$tmp_dir/per_file.tsv"
# For each file: total lines, top author, top author lines, top author pct
awk -F'\t' '
{
  file = $1; author = $2; lines = $3
  total[file] += lines
  if (lines > top_lines[file] || (lines == top_lines[file] && (top_author[file] == "" || author < top_author[file]))) {
    top_lines[file] = lines
    top_author[file] = author
  }
  # count distinct authors
  key = file SUBSEP author
  if (!(key in seen)) {
    seen[key] = 1
    author_count[file]++
  }
}
END {
  for (f in total) {
    pct = (total[f] > 0) ? int(top_lines[f] * 100 / total[f]) : 0
    printf "%s\t%d\t%s\t%d\t%d\t%d\n", f, total[f], top_author[f], top_lines[f], pct, author_count[f]
  }
}' "$blame_data" | sort -t$'\t' -k5 -rn > "$per_file"

# --- Phase 3: Per-module aggregation ---
module_data="$tmp_dir/module_data.tsv"
# Module = top-level directory (or root for top-level files)
awk -F'\t' '
{
  file = $1; author = $2; lines = $3
  n = split(file, parts, "/")
  if (n <= 1) module = "(root)"
  else module = parts[1]
  key = module SUBSEP author
  mod_author_lines[key] += lines
  mod_total[module] += lines
  if (!(key in mod_seen)) {
    mod_seen[key] = 1
    mod_author_count[module]++
  }
}
END {
  # First pass: compute top author per module in O(K), where K=module-author pairs.
  for (key in mod_author_lines) {
    split(key, kp, SUBSEP)
    m = kp[1]
    if (mod_author_lines[key] > mod_top_lines[m] || (mod_author_lines[key] == mod_top_lines[m] && (mod_top_author[m] == "" || kp[2] < mod_top_author[m]))) {
      mod_top_lines[m] = mod_author_lines[key]
      mod_top_author[m] = kp[2]
    }
  }

  # Second pass: emit per-module summary.
  for (m in mod_total) {
    pct = (mod_total[m] > 0) ? int(mod_top_lines[m] * 100 / mod_total[m]) : 0
    printf "%s\t%d\t%s\t%d\t%d\t%d\n", m, mod_total[m], mod_top_author[m], mod_top_lines[m], pct, mod_author_count[m]
  }
}' "$blame_data" | sort -t$'\t' -k5 -rn > "$module_data"

# --- Phase 4: Repository-wide bus-factor ---
# Bus factor = minimum number of authors whose combined lines exceed 50% of total
repo_bus_factor="$tmp_dir/bus_factor.txt"
# Aggregate lines per author, then sort descending
author_summary="$tmp_dir/author_summary.tsv"
awk -F'\t' '{ author_lines[$2] += $3 } END { for (a in author_lines) printf "%d\t%s\n", author_lines[a], a }' \
  "$blame_data" | sort -rn > "$author_summary"

total_authors_count=$(wc -l < "$author_summary" | tr -d ' ')
grand_total=$(awk -F'\t' '{ s += $1 } END { print s+0 }' "$author_summary")
half=$(( grand_total / 2 ))

# Compute bus factor: minimum authors covering >50%
cumulative=0
bf=0
while IFS=$'\t' read -r lines _author; do
  cumulative=$((cumulative + lines))
  bf=$((bf + 1))
  if [ "$cumulative" -gt "$half" ]; then break; fi
done < "$author_summary"

printf "%d\t%d\t%d\n" "$bf" "$total_authors_count" "$grand_total" > "$repo_bus_factor"
if [ "$grand_total" -gt 0 ]; then
  awk -F'\t' -v total="$grand_total" '
  {
    printf "AUTHOR\t%s\t%d\t%.1f\n", $2, $1, ($1 * 100 / total)
  }' "$author_summary" >> "$repo_bus_factor"
fi

bus_factor=$(head -1 "$repo_bus_factor" | cut -f1)
total_authors=$(head -1 "$repo_bus_factor" | cut -f2)
total_lines=$(head -1 "$repo_bus_factor" | cut -f3)

# --- Phase 5: High-risk files ---
high_risk="$tmp_dir/high_risk.tsv"
awk -F'\t' -v thresh="$risk_threshold" '$4 * 100 > thresh * $2 { print }' "$per_file" > "$high_risk"
high_risk_count=$(wc -l < "$high_risk" | tr -d ' ')
total_files=$(wc -l < "$per_file" | tr -d ' ')

# --- Output ---
if [ "$output_format" = "json" ]; then
  # JSON output
  printf '{\n'
  printf '  "bus_factor": %d,\n' "$bus_factor"
  printf '  "total_authors": %d,\n' "$total_authors"
  printf '  "total_lines": %d,\n' "$total_lines"
  printf '  "total_files": %d,\n' "$total_files"
  printf '  "high_risk_files": %d,\n' "$high_risk_count"
  printf '  "risk_threshold": %d,\n' "$risk_threshold"

  printf '  "authors": [\n'
  first=1
  tail -n +2 "$repo_bus_factor" | while IFS=$'\t' read -r _ author lines pct; do
    if [ "$first" -eq 1 ]; then first=0; else printf ',\n'; fi
    author_json=$(json_escape "$author")
    printf '    {"name": "%s", "lines": %d, "percentage": %s}' "$author_json" "$lines" "$pct"
  done
  printf '\n  ],\n'

  printf '  "high_risk": [\n'
  first=1
  while IFS=$'\t' read -r file total top_author top_lines pct authors; do
    if [ "$first" -eq 1 ]; then first=0; else printf ',\n'; fi
    file_json=$(json_escape "$file")
    top_author_json=$(json_escape "$top_author")
    printf '    {"file": "%s", "lines": %d, "top_author": "%s", "ownership_pct": %d}' \
      "$file_json" "$total" "$top_author_json" "$pct"
  done < "$high_risk"
  printf '\n  ]\n'
  printf '}\n'
else
  # Markdown output
  echo "# Bus-Factor Analysis Report"
  echo ""
  echo "## Summary"
  echo ""
  echo "| Metric | Value |"
  echo "|--------|-------|"
  printf "| Bus Factor | **%d** |\n" "$bus_factor"
  printf "| Total Authors | %d |\n" "$total_authors"
  printf "| Total Lines Analyzed | %d |\n" "$total_lines"
  printf "| Total Files Analyzed | %d |\n" "$total_files"
  printf "| High-Risk Files (>%d%% single author) | **%d** |\n" "$risk_threshold" "$high_risk_count"
  echo ""

  echo "## Author Contributions"
  echo ""
  echo "| Author | Lines | % of Total |"
  echo "|--------|------:|----------:|"
  tail -n +2 "$repo_bus_factor" | while IFS=$'\t' read -r _ author lines pct; do
    printf "| %s | %d | %s%% |\n" "$author" "$lines" "$pct"
  done
  echo ""

  echo "## Module Ownership"
  echo ""
  echo "| Module | Lines | Top Author | Ownership % | Authors |"
  echo "|--------|------:|-----------|----------:|--------:|"
  while IFS=$'\t' read -r module total top_author top_lines pct authors; do
    printf "| \`%s\` | %d | %s | %d%% | %d |\n" "$module" "$total" "$top_author" "$pct" "$authors"
  done < "$module_data"
  echo ""

  if [ "$high_risk_count" -gt 0 ]; then
    echo "## High-Risk Files"
    echo ""
    echo "Files where a single author owns >$risk_threshold% of lines:"
    echo ""
    echo "| File | Lines | Top Author | Ownership % | Authors |"
    echo "|------|------:|-----------|----------:|--------:|"
    while IFS=$'\t' read -r file total top_author top_lines pct authors; do
      printf "| \`%s\` | %d | %s | %d%% | %d |\n" "$file" "$total" "$top_author" "$pct" "$authors"
    done < "$high_risk"
    echo ""
  else
    echo "## High-Risk Files"
    echo ""
    echo "No files exceed the $risk_threshold% single-author ownership threshold."
    echo ""
  fi

  echo "## Top 10 Most Concentrated Files"
  echo ""
  echo "| File | Lines | Top Author | Ownership % | Authors |"
  echo "|------|------:|-----------|----------:|--------:|"
  head -10 "$per_file" | while IFS=$'\t' read -r file total top_author top_lines pct authors; do
    printf "| \`%s\` | %d | %s | %d%% | %d |\n" "$file" "$total" "$top_author" "$pct" "$authors"
  done
  echo ""

  echo "---"
  echo "_Bus factor = minimum authors covering >50% of total lines._"
  echo "_A bus factor of 1 means the project is critically dependent on a single contributor._"
fi
