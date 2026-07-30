#!/usr/bin/env bash
# reproduce_full_pfcp_open5gs_5g.sh — Full end-to-end run for iFinder on one target.
#
# Scope    : open5gs v2.7.5  ×  all 6 patterns (PA1, PA2, PB1, PB2, PB3, PC1)
#            ×  every FEASIBLE candidate (no slicing)
# Stages   : DA → VA → EA  per pattern; tear down testbed between patterns
# Expect   : 1–4 HOURS wall-clock (≈ 6 patterns × (~5 min DA + N×~1 min VA + M×~3 min EA)).
#            Costs real Anthropic tokens; budget accordingly.
# Outputs  : populates iFinder_artifact-v4/outputs/{discovery,vetting,exploitation}_results/open5gs_275/
#            (existing artifacts OVERWRITTEN — back them up first if you need the baseline)
# Final    : prints a per-pattern summary table (candidates / feasible / confirmed)
#
# Prereqs  : same as reproduce_one_candidate_open5gs_5g.sh
#            (docker compose v2, go, python3, claude CLI, ANTHROPIC_API_KEY or iFinder_artifact-v4/.env,
#             `pip install -e iFinder_artifact-v4/src`)
#
# Usage    : bash iFinder_artifact-v4/scripts/reproduce_full_pfcp_open5gs_5g.sh   (from anywhere)
#            PATTERNS=PA1,PB1 bash iFinder_artifact-v4/scripts/reproduce_full_pfcp_open5gs_5g.sh   (subset, comma-separated)

set -euo pipefail

# ───────────────────────── paths ─────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IFINDER="$(cd "$SCRIPT_DIR/.." && pwd)"      # iFinder_artifact-v4/scripts/ -> iFinder_artifact-v4/
CODE="$IFINDER/src"
TARGET="$IFINDER/target/open5gs_code/open5gs_275"
TARGET_NAME="open5gs_275"
SCOPE="../scope/pfcp/scope_open5gs_275.json"
COMPOSE="../testbed/docker-open5gs/compose-files/basic/docker-compose.yaml"
ENVFILE="../testbed/docker-open5gs/.env"

DA_DIR="$IFINDER/outputs/discovery_results/${TARGET_NAME}"
VA_DIR="$IFINDER/outputs/vetting_results/${TARGET_NAME}"
EA_DIR="$IFINDER/outputs/exploitation_results/${TARGET_NAME}"

# Load optional local credentials. This file should contain shell-compatible
# assignments such as: ANTHROPIC_API_KEY=...
LOCAL_ENV="$IFINDER/.env"
EXPORTED_ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-}"
if [[ -f "$LOCAL_ENV" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$LOCAL_ENV"
    set +a
    if [[ -z "${ANTHROPIC_API_KEY:-}" && -n "$EXPORTED_ANTHROPIC_API_KEY" ]]; then
        export ANTHROPIC_API_KEY="$EXPORTED_ANTHROPIC_API_KEY"
    fi
fi

PATTERNS="${PATTERNS:-PA1,PA2,PB1,PB2,PB3,PC1}"
IFS=',' read -ra PATTERN_LIST <<< "$PATTERNS"

# ───────────────────────── ui ─────────────────────────
if [[ -t 1 ]]; then
    BOLD=$'\033[1m'; GREEN=$'\033[32m'; RED=$'\033[31m'; YELLOW=$'\033[33m'; RESET=$'\033[0m'
else
    BOLD=''; GREEN=''; RED=''; YELLOW=''; RESET=''
fi
hdr()  { printf "\n${BOLD}── %s ──${RESET}\n" "$1"; }
pass() { printf "       ${GREEN}PASS${RESET}  %s\n" "$1"; }
fail() { printf "       ${RED}FAIL${RESET}  %s\n" "$1"; }
warn() { printf "       ${YELLOW}WARN${RESET}  %s\n" "$1"; }
info() { printf "       %s\n" "$1"; }

START_TIME=$(date +%s)

# ───────────────────────── cleanup trap ─────────────────────────
TESTBED_DOWN=""

cleanup() {
    local rc=$?
    if [[ "$TESTBED_DOWN" == "1" ]]; then
        echo "[cleanup] tearing down testbed"
        (cd "$CODE" && docker compose -f "$COMPOSE" --env-file "$ENVFILE" down -v >/dev/null 2>&1) || true
    fi
    exit "$rc"
}
trap cleanup EXIT INT TERM

# ───────────────────────── preflight ─────────────────────────
printf "${BOLD}=== iFinder Full Reproduce ===${RESET}\n"
printf "target  : open5gs v2.7.5\n"
printf "patterns: %s  (%d total)\n" "$PATTERNS" "${#PATTERN_LIST[@]}"
printf "stages  : DA → VA → EA  (per pattern, no slicing)\n"
printf "expect  : 1–4 hours wall-clock; real Anthropic token cost\n\n"

hdr "preflight"
for bin in docker go python3 claude ifinder; do
    command -v "$bin" >/dev/null 2>&1 || { fail "$bin not on PATH"; exit 1; }
done
docker compose version >/dev/null 2>&1 || { fail "docker compose v2 required"; exit 1; }
if [[ -z "${ANTHROPIC_API_KEY:-}" && ! -f "${HOME}/.claude/.credentials.json" ]]; then
    fail "no Claude credentials (set ANTHROPIC_API_KEY, fill iFinder_artifact-v4/.env, or run 'claude' once to log in)"
    exit 1
fi
# Pin $TARGET to open5gs v2.7.5 in one of two modes, so the unpacked release tarball works
# without git or network:
#   .git present -> require a clean tree and checkout the tag; no .git -> verify via meson.build.
EXPECTED_VER="2.7.5"
if [[ -d "$TARGET/.git" ]]; then
    if [[ -n "$(git -C "$TARGET" status --porcelain)" ]]; then
        fail "$TARGET has uncommitted changes; refusing to checkout"
        git -C "$TARGET" status --short
        exit 1
    fi
    cur_tag="$(git -C "$TARGET" describe --tags --always 2>/dev/null || echo unknown)"
    if [[ "$cur_tag" != "v$EXPECTED_VER" ]]; then
        info "checking out v$EXPECTED_VER in $TARGET (currently $cur_tag)"
        git -C "$TARGET" fetch --tags --quiet 2>/dev/null || true
        git -C "$TARGET" checkout --quiet "v$EXPECTED_VER"
    fi
    pass "preflight OK (open5gs @ v$EXPECTED_VER, git)"
else
    src_ver="$(sed -nE "s/^[[:space:]]*version[[:space:]]*:[[:space:]]*'([0-9][0-9.]*)'.*/\1/p" "$TARGET/meson.build" 2>/dev/null)"
    [[ "$src_ver" == "$EXPECTED_VER" ]] || {
        fail "$TARGET: no .git and meson.build version='${src_ver:-?}' (expected $EXPECTED_VER)"
        exit 1
    }
    pass "preflight OK (open5gs @ v$src_ver from meson.build; no .git, tarball mode)"
fi

# ── ensure EA testbed images exist; build them once via 'make all' only if any are missing ──
ensure_testbed_images() {
    local testbed_dir="$IFINDER/testbed/docker-open5gs"
    local compose_abs="$testbed_dir/compose-files/basic/docker-compose.yaml"
    local ver
    ver="$(sed -nE 's/^OPEN5GS_VERSION=(.*)$/\1/p' "$testbed_dir/.env" 2>/dev/null)"
    ver="${ver:-v$EXPECTED_VER}"
    # images the basic compose builds locally = base-open5gs + every NF image tagged OPEN5GS_VERSION
    local need=(base-open5gs) n missing=()
    for n in $(grep -oE 'image: *"[a-z0-9_-]+:\$\{OPEN5GS_VERSION\}"' "$compose_abs" 2>/dev/null \
                 | sed -E 's/.*"([a-z0-9_-]+):.*/\1/' | sort -u || true); do
        need+=("$n")
    done
    for n in "${need[@]}"; do
        docker image inspect "${n}:${ver}" >/dev/null 2>&1 || missing+=("${n}:${ver}")
    done
    if [[ ${#missing[@]} -eq 0 ]]; then
        pass "testbed images present (${ver}; ${#need[@]} images) — skipping 'make all'"
        return 0
    fi
    warn "${#missing[@]}/${#need[@]} testbed image(s) missing — building"
    info "missing: ${missing[*]}"
    command -v make >/dev/null 2>&1 || { fail "make not on PATH (needed to build testbed images)"; exit 1; }
    info "running 'make all' in $testbed_dir (one-time; may take several minutes)…"
    if ! ( cd "$testbed_dir" && make all ); then
        fail "'make all' failed in $testbed_dir"
        exit 1
    fi
    pass "testbed images built (${ver})"
}
ensure_testbed_images

cd "$CODE"

# ───────────────────────── per-pattern loop ─────────────────────────
# Per-pattern stats (parallel arrays indexed by pattern name)
declare -A CAND_COUNT FEAS_COUNT CONF_COUNT

for P in "${PATTERN_LIST[@]}"; do
    hdr "pattern $P"

    # ── DA ──────────────────────────────────────────────────────────
    info "DA: discovering $P candidates (~5 min)"
    if ! ifinder run --scope "$SCOPE" --patterns "$P" --target "$TARGET_NAME" --stage discovery 2>&1 \
            | tail -6 | sed 's/^/       │ /'; then
        fail "DA for $P failed"; continue
    fi
    DA_FILE="$DA_DIR/${P}.json"
    if [[ ! -f "$DA_FILE" ]]; then
        fail "DA did not produce $DA_FILE"; CAND_COUNT[$P]=0; continue
    fi
    N_CAND=$(DA_FILE="$DA_FILE" python3 -c \
        "import json,os; print(len(json.load(open(os.environ['DA_FILE']))['candidates']))")
    CAND_COUNT[$P]=$N_CAND
    pass "DA $P → $N_CAND candidate(s)"

    if [[ "$N_CAND" -eq 0 ]]; then
        FEAS_COUNT[$P]=0; CONF_COUNT[$P]=0; continue
    fi

    # ── VA ──────────────────────────────────────────────────────────
    info "VA: vetting all $N_CAND $P candidate(s) (≈ $((N_CAND)) min — one session per candidate)"
    if ! ifinder run --scope "$SCOPE" --patterns "$P" --target "$TARGET_NAME" --stage vetting 2>&1 \
            | tail -4 | sed 's/^/       │ /'; then
        fail "VA for $P failed"; FEAS_COUNT[$P]=0; CONF_COUNT[$P]=0; continue
    fi
    VA_FILE="$VA_DIR/${P}.json"
    if [[ ! -f "$VA_FILE" ]]; then
        fail "VA did not produce $VA_FILE"; FEAS_COUNT[$P]=0; CONF_COUNT[$P]=0; continue
    fi
    N_FEAS=$(VA_FILE="$VA_FILE" python3 -c \
        "import json,os; print(json.load(open(os.environ['VA_FILE']))['statistics']['feasible'])")
    FEAS_COUNT[$P]=$N_FEAS
    pass "VA $P → $N_FEAS feasible / $N_CAND total"

    if [[ "$N_FEAS" -eq 0 ]]; then
        CONF_COUNT[$P]=0; continue
    fi

    # ── EA (all FEASIBLE candidates for this pattern) ───────────────
    info "EA: exploiting $N_FEAS FEASIBLE $P candidate(s) (testbed up/down per candidate, ≈ $((N_FEAS*3)) min)"
    TESTBED_DOWN=1
    if ! ifinder run --scope "$SCOPE" --patterns "$P" --target "$TARGET_NAME" --stage exploitation \
            --compose-file "$COMPOSE" --env-file "$ENVFILE" 2>&1 \
            | tail -8 | sed 's/^/       │ /'; then
        fail "EA for $P failed mid-run; partial results may still be in $EA_DIR"
    fi
    TESTBED_DOWN=""   # ifinder's pipeline ran its own down -v

    # Count CONFIRMED EA results emitted for this pattern's FEASIBLE candidate ids
    N_CONF=$(P="$P" VA_FILE="$VA_FILE" EA_DIR="$EA_DIR" python3 <<'PY'
import json, os, pathlib
v = json.load(open(os.environ['VA_FILE']))
feas = [r['candidate_id'] for r in v['results'] if r['verdict'] == 'FEASIBLE']
ea = pathlib.Path(os.environ['EA_DIR'])
n = 0
for cid in feas:
    p = ea / f"{cid}.json"
    if p.exists():
        try:
            if json.load(p.open()).get('validation_result') == 'CONFIRMED':
                n += 1
        except Exception:
            pass
print(n)
PY
)
    CONF_COUNT[$P]=$N_CONF
    pass "EA $P → $N_CONF confirmed / $N_FEAS feasible"
done

# ───────────────────────── final summary ─────────────────────────
hdr "summary"
printf "       ${BOLD}%-8s %12s %12s %12s${RESET}\n" "PATTERN" "CANDIDATES" "FEASIBLE" "CONFIRMED"
printf "       %-8s %12s %12s %12s\n" "-------" "----------" "--------" "---------"
TOT_C=0; TOT_F=0; TOT_X=0
for P in "${PATTERN_LIST[@]}"; do
    c=${CAND_COUNT[$P]:-0}; f=${FEAS_COUNT[$P]:-0}; x=${CONF_COUNT[$P]:-0}
    printf "       %-8s %12d %12d %12d\n" "$P" "$c" "$f" "$x"
    TOT_C=$((TOT_C+c)); TOT_F=$((TOT_F+f)); TOT_X=$((TOT_X+x))
done
printf "       %-8s %12s %12s %12s\n" "-------" "----------" "--------" "---------"
printf "       ${BOLD}%-8s %12d %12d %12d${RESET}\n" "TOTAL" "$TOT_C" "$TOT_F" "$TOT_X"

elapsed=$(( $(date +%s) - START_TIME ))
mins=$((elapsed/60)); secs=$((elapsed%60))

if [[ "$TOT_X" -gt 0 ]]; then
    printf "\n${BOLD}FULL REPRODUCE: ${GREEN}OK${RESET}  ($TOT_X confirmed iTrue(s); %d min %02d s)\n" "$mins" "$secs"
    exit 0
else
    printf "\n${BOLD}FULL REPRODUCE: ${RED}NO CONFIRMED${RESET}  ($TOT_C candidates / $TOT_F feasible / 0 confirmed; %d min %02d s)\n" "$mins" "$secs"
    info "if all FEASIBLE EAs returned UNCONFIRMED, inspect $EA_DIR/*.json for refinement traces"
    exit 1
fi
