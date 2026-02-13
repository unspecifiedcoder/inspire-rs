# Roadmap Entropy Detector

A lightweight shell tool that quantifies scope creep and roadmap drift by
analyzing planning documents and git history.

## Quick start

```bash
# Human-readable report
scripts/roadmap-entropy.sh

# JSON-only (for CI / piping)
scripts/roadmap-entropy.sh --json

# Custom threshold and window
scripts/roadmap-entropy.sh --threshold 60 --since 14
```

## Entropy score

The detector produces a single **entropy score** from 0 (perfectly focused)
to 100 (maximum drift).  Five weighted sub-metrics feed into a
weighted average:

| # | Metric | Weight | What it measures |
|---|--------|--------|-----------------|
| M1 | Commit-type distribution | 25 % | Concentration of one commit type (e.g., all `fix`) |
| M2 | Changelog growth | 15 % | Lines added to `CHANGELOG.md` in the window |
| M3 | Kanban WIP count | 20 % | Items sitting in "In Progress" across kanban boards |
| M4 | Plan staleness | 15 % | Days since `PLAN.md` / `ROADMAP.md` / `TODO.md` was last committed |
| M5 | Unplanned feature ratio | 25 % | `feat` commits lacking an issue reference (`#N`) |

## Metric details

### M1 — Commit-type distribution

Parses Conventional Commit prefixes (`feat`, `fix`, `docs`, …) and computes
the share held by the dominant type.  A single type claiming >60 % of
commits signals tunnel-vision or a reactive-only workflow.

- **≤ 40 % dominant** → score 0
- **100 % dominant** → score 100

### M2 — Changelog growth

Counts lines *added* to `CHANGELOG.md` via `git log --numstat`.  Rapid
changelog growth hints at scope inflation or a release that is trying to
do too much.

- **0 lines** → score 0
- **≥ 200 lines** → score 100

### M3 — Kanban WIP count

Scans files matching `*kanban*` or `*board*` under `docs/` and root `TODO.md`
for an `## In Progress` section.  Items listed there (excluding "None") are
counted.

- **0 WIP items** → score 0
- **≥ 5 WIP items** → score 100

### M4 — Plan staleness

Checks when `PLAN.md`, `ROADMAP.md`, or `TODO.md` were last committed.
Stale plans signal that the documented direction is out of date.

- **0 days** → score 0
- **≥ 90 days** → score 100

### M5 — Unplanned feature ratio

Counts `feat` commits whose subject + body contain no issue reference
(`#<number>`).  A high ratio suggests features are landing without prior
planning or tracking.

- **≤ 10 % unplanned** → score 0
- **≥ 80 % unplanned** → score 100

## Configuration

| Env variable | CLI flag | Default | Description |
|-------------|----------|---------|-------------|
| `ENTROPY_THRESHOLD` | `--threshold` | `70` | Score above which the script exits non-zero |
| `ENTROPY_SINCE_DAYS` | `--since` | `30` | Number of days to look back in git history |

## CI integration

The entropy check runs as a **non-blocking** CI job on pull requests:

```yaml
roadmap-entropy:
  if: github.event_name == 'pull_request'
  runs-on: ubuntu-latest
  continue-on-error: true          # advisory, never blocks merge
  steps:
    - uses: actions/checkout@v4
      with:
        fetch-depth: 0
    - name: Roadmap entropy check
      run: scripts/roadmap-entropy.sh --json
```

The job uses `continue-on-error: true`, so a high entropy score shows as a
warning annotation but does **not** block merging.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Entropy within threshold |
| 1 | Entropy exceeds threshold |
| 2 | Usage error |
