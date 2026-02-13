#!/usr/bin/env bash
# check-privacy-claims.sh — CI-compatible script that detects code patterns
# violating InsPIRe's privacy claims.
#
# Exit code 0: all checks pass
# Exit code 1: one or more violations detected
#
# Usage:
#   ./scripts/check-privacy-claims.sh          # run all checks
#   ./scripts/check-privacy-claims.sh --verbose # show matched lines

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC_DIR="$REPO_ROOT/src"
VERBOSE=false
FAILURES=0

if [[ "${1:-}" == "--verbose" ]]; then
    VERBOSE=true
fi

red()   { printf '\033[0;31m%s\033[0m\n' "$1"; }
green() { printf '\033[0;32m%s\033[0m\n' "$1"; }
yellow(){ printf '\033[0;33m%s\033[0m\n' "$1"; }

check() {
    local description="$1"
    local pattern="$2"
    local search_path="$3"
    local glob_filter="${4:-}"
    local exclude_comments="${5:-false}"

    local rg_args=( --no-heading -n )
    if [[ -n "$glob_filter" ]]; then
        rg_args+=( --glob "$glob_filter" )
    fi

    local matches=""
    local rg_status=0
    set +e
    matches=$(rg "${rg_args[@]}" "$pattern" "$search_path")
    rg_status=$?
    set -e

    # rg exit codes: 0=match, 1=no match, 2+=error.
    if [[ $rg_status -ne 0 && $rg_status -ne 1 ]]; then
        red "FAIL: $description (ripgrep error)"
        FAILURES=$((FAILURES + 1))
        return
    fi

    # Optionally filter out matches that are only in comments.
    if [[ "$exclude_comments" == "true" && -n "$matches" ]]; then
        # Conservative filter: only ignore lines whose matched snippet starts with
        # explicit comment markers. This avoids accidentally hiding real violations.
        matches=$(echo "$matches" | grep -v -E '^[^:]+:[0-9]+:[[:space:]]*(//|/\*|\*|\*/)' || true)
    fi

    if [[ -n "$matches" ]]; then
        red "FAIL: $description"
        if $VERBOSE; then
            echo "$matches" | head -20
            echo ""
        fi
        FAILURES=$((FAILURES + 1))
    else
        green "PASS: $description"
    fi
}

echo "=== InsPIRe Privacy Claims Check ==="
echo "Repository: $REPO_ROOT"
echo ""

# Discover library source directories dynamically (exclude src/bin).
LIB_DIRS=()
for d in "$SRC_DIR"/*; do
    if [[ -d "$d" && "$(basename "$d")" != "bin" ]]; then
        LIB_DIRS+=("$d")
    fi
done

# ---------------------------------------------------------------------------
# 1. No telemetry / analytics imports in library code
# ---------------------------------------------------------------------------
echo "--- Telemetry & Analytics ---"

for dir in "${LIB_DIRS[@]}"; do
    check "No analytics/telemetry crate imports in $(basename "$dir")/" \
        '\b(sentry|segment|amplitude|mixpanel|posthog|datadog|newrelic|bugsnag|rollbar)\b' \
        "$dir" \
        "*.rs"

    check "No phone-home or beacon patterns in $(basename "$dir")/" \
        '(phone.?home|beacon|telemetry_endpoint|analytics_url|tracking_id|usage.?report)' \
        "$dir" \
        "*.rs"
done

# ---------------------------------------------------------------------------
# 2. No PII logging in library code (src/pir/, src/math/, etc.)
#    Binaries (src/bin/) are excluded — they are expected to log operational info.
# ---------------------------------------------------------------------------
echo ""
echo "--- PII Logging in Library Code ---"

for dir in "${LIB_DIRS[@]}"; do
    if [[ -d "$dir" ]]; then
        check "No secret key logging in $(basename "$dir")/" \
            '(println!|info!|debug!|warn!|error!|trace!)\(.*secret' \
            "$dir" \
            "*.rs"
    fi
done

# ---------------------------------------------------------------------------
# 3. No outbound HTTP calls from library code
#    Only binaries should make network requests.
# ---------------------------------------------------------------------------
echo ""
echo "--- Outbound Network Calls in Library Code ---"

for dir in "${LIB_DIRS[@]}"; do
    if [[ -d "$dir" ]]; then
        check "No HTTP client usage in $(basename "$dir")/" \
            '\b(reqwest|hyper::client|curl|ureq|surf|isahc)\b' \
            "$dir" \
            "*.rs"
    fi
done

# ---------------------------------------------------------------------------
# 4. No hardcoded external URLs in library code
# ---------------------------------------------------------------------------
echo ""
echo "--- Hardcoded URLs in Library Code ---"

for dir in "${LIB_DIRS[@]}"; do
    if [[ -d "$dir" ]]; then
        check "No hardcoded URLs in $(basename "$dir")/" \
            '\bhttps?://' \
            "$dir" \
            "*.rs" \
            "true"
    fi
done

# ---------------------------------------------------------------------------
# 5. Secret key serialization safety
#    ClientState should use #[serde(skip)] on secret fields.
# ---------------------------------------------------------------------------
echo ""
echo "--- Secret Key Serialization Safety ---"

# Check that ClientState secret fields have serde(skip)
# This is a structural check: if someone removes #[serde(skip)] from secret_key
# or rlwe_secret_key in ClientState, this will catch it.
if ! rg -q 'pub secret_key\s*:\s*LweSecretKey' "$SRC_DIR/pir/query.rs"; then
    green "PASS: ClientState.secret_key has #[serde(skip)] (field not found)"
elif rg -UPq '#\s*\[serde\([^]]*\bskip\b[^]]*\)\]\s*\n\s*pub secret_key\s*:\s*LweSecretKey' "$SRC_DIR/pir/query.rs"; then
    green "PASS: ClientState.secret_key has #[serde(skip)]"
else
    red "FAIL: ClientState.secret_key missing #[serde(skip)] — secrets could leak over the network"
    FAILURES=$((FAILURES + 1))
fi

if ! rg -q 'pub rlwe_secret_key\s*:\s*RlweSecretKey' "$SRC_DIR/pir/query.rs"; then
    green "PASS: ClientState.rlwe_secret_key has #[serde(skip)] (field not found)"
elif rg -UPq '#\s*\[serde\([^]]*\bskip\b[^]]*\)\]\s*\n\s*pub rlwe_secret_key\s*:\s*RlweSecretKey' "$SRC_DIR/pir/query.rs"; then
    green "PASS: ClientState.rlwe_secret_key has #[serde(skip)]"
else
    red "FAIL: ClientState.rlwe_secret_key missing #[serde(skip)] — secrets could leak over the network"
    FAILURES=$((FAILURES + 1))
fi

# ---------------------------------------------------------------------------
# 6. No std::net or socket usage in library code
# ---------------------------------------------------------------------------
echo ""
echo "--- Raw Network in Library Code ---"

for dir in "${LIB_DIRS[@]}"; do
    if [[ -d "$dir" ]]; then
        check "No std::net / TcpStream in $(basename "$dir")/" \
            '\b(std::net|TcpStream|UdpSocket|TcpListener)\b' \
            "$dir" \
            "*.rs"
    fi
done

# ---------------------------------------------------------------------------
# 7. No environment variable sniffing for PII in library code
# ---------------------------------------------------------------------------
echo ""
echo "--- Environment Variable Access in Library Code ---"

for dir in "${LIB_DIRS[@]}"; do
    if [[ -d "$dir" ]]; then
        check "No env var reads in $(basename "$dir")/" \
            '\bstd::env::(var|vars)\b' \
            "$dir" \
            "*.rs"
    fi
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=== Summary ==="
if [[ $FAILURES -eq 0 ]]; then
    green "All privacy checks passed."
    exit 0
else
    red "$FAILURES check(s) failed."
    exit 1
fi
