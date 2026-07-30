#!/usr/bin/env bash
# reproduce_full_gtpc_oai_epc.sh — Full end-to-end run for iFinder on GTP-C (OAI EPC SPGW-C).
#
# Scope    : OAI EPC SPGW-C (GTPv2-C)  ×  all 6 patterns (PA1, PA2, PB1, PB2, PB3, PC1)
#            ×  every FEASIBLE candidate (no slicing)
# Stages   : DA → VA → EA  per pattern; tear down testbed between patterns
# Target   : target/openairinterface_code/openair-epc-fed  (oai-spgwc/src/gtpv2c)
# Testbed  : testbed/.../spgw-pfcp-gtpc  (oai_spgwc + oai_spgwu, dockerhub images)
# Expect   : 1–4 HOURS wall-clock; real Anthropic token cost.
# Outputs  : populates iFinder_artifact-v4/outputs/{discovery,vetting,exploitation}_results/oai_epc_gtpc/
#            (existing artifacts OVERWRITTEN — back them up first if you need the baseline)
# Final    : prints a per-pattern summary table (candidates / feasible / confirmed)
#
# Note     : the spgw-pfcp-gtpc testbed runs OAI's release images (no ASan), so memory-safety
#            overflows may corrupt silently without crashing; assertion-style flaws still crash.
#            For reliable confirmation of memory bugs, run an ASan-instrumented SPGW-C build.
#
# Prereqs  : docker compose v2, go, python3, claude CLI, ANTHROPIC_API_KEY or iFinder_artifact-v4/.env,
#            `pip install -e iFinder_artifact-v4/src`
#
# Usage    : bash iFinder_artifact-v4/scripts/reproduce_full_gtpc_oai_epc.sh   (from anywhere)
#            PATTERNS=PA1,PB1 bash iFinder_artifact-v4/scripts/reproduce_full_gtpc_oai_epc.sh   (subset, comma-separated)

set -euo pipefail

# ───────────────────────── paths ─────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IFINDER="$(cd "$SCRIPT_DIR/.." && pwd)"      # iFinder_artifact-v4/scripts/ -> iFinder_artifact-v4/
CODE="$IFINDER/src"
TARGET="$IFINDER/target/openairinterface_code/openair-epc-fed"
TARGET_NAME="oai_epc_gtpc"
SCOPE="../scope/gtpc/scope_oai_epc_gtpc.json"
COMPOSE="../testbed/openair-epc-fed/docker-compose/spgw-pfcp-gtpc/docker-compose.yml"

DA_DIR="$IFINDER/outputs/discovery_results/${TARGET_NAME}"
VA_DIR="$IFINDER/outputs/vetting_results/${TARGET_NAME}"
EA_DIR="$IFINDER/outputs/exploitation_results/${TARGET_NAME}"

# Load optional local credentials (ANTHROPIC_API_KEY=...).
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
        (cd "$CODE" && docker compose -f "$COMPOSE" down -v >/dev/null 2>&1) || true
    fi
    exit "$rc"
}
trap cleanup EXIT INT TERM

# ───────────────────────── preflight ─────────────────────────
printf "${BOLD}=== iFinder Full Reproduce (GTP-C) ===${RESET}\n"
printf "target  : OAI EPC SPGW-C (GTPv2-C)\n"
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

# GTP-C target = OAI EPC SPGW-C source; verify the codebase + the gtpv2c scan dirs exist.
[[ -d "$TARGET" ]] || { fail "target codebase missing: $TARGET"; exit 1; }
for d in component/oai-spgwc/src/gtpv2c component/oai-spgwu-tiny/src/gtpv2c; do
    [[ -d "$TARGET/$d" ]] || { fail "scan dir missing: $TARGET/$d"; exit 1; }
done

# Ensure the OAI testbed images exist; pull them (dockerhub) only if missing — no 'make all' here.
ensure_testbed_images() {
    local compose_abs="$IFINDER/testbed/openair-epc-fed/docker-compose/spgw-pfcp-gtpc/docker-compose.yml"
    local imgs missing=() img
    imgs="$(grep -oE 'image:\s*\S+' "$compose_abs" 2>/dev/null | awk '{print $2}' | sort -u)"
    for img in $imgs; do
        docker image inspect "$img" >/dev/null 2>&1 || missing+=("$img")
    done
    if [[ ${#missing[@]} -eq 0 ]]; then
        return 0
    fi
    warn "${#missing[@]} testbed image(s) missing: ${missing[*]}"
    info "pulling via 'docker compose pull' (first time may take a few minutes)…"
    if ! ( cd "$CODE" && docker compose -f "$COMPOSE" pull ); then
        fail "docker compose pull failed (need network for first pull)"; exit 1
    fi
}
ensure_testbed_images
pass "preflight OK (OAI EPC SPGW-C target + GTP-C scan dirs + testbed images)"

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
    info "EA: exploiting $N_FEAS FEASIBLE $P candidate(s) over GTPv2-C S11 (testbed up/down per candidate, ≈ $((N_FEAS*3)) min)"
    TESTBED_DOWN=1
    if ! ifinder run --scope "$SCOPE" --patterns "$P" --target "$TARGET_NAME" --stage exploitation \
            --compose-file "$COMPOSE" 2>&1 \
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
    printf "\n${BOLD}FULL REPRODUCE (GTP-C): ${GREEN}OK${RESET}  ($TOT_X confirmed iTrue(s); %d min %02d s)\n" "$mins" "$secs"
    exit 0
else
    printf "\n${BOLD}FULL REPRODUCE (GTP-C): ${YELLOW}NO CONFIRMED${RESET}  ($TOT_C candidates / $TOT_F feasible / 0 confirmed; %d min %02d s)\n" "$mins" "$secs"
    info "release-image testbed (no ASan) may not crash on memory overflows; inspect $EA_DIR/*.json or use an ASan SPGW-C build"
    exit 0
fi
