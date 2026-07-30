#!/usr/bin/env bash
# reproduce_one_candidate_eupf.sh — One-shot end-to-end reproduction for iFinder on eUPF.
#
# Scope    : eUPF v0.7.1 (PFCP/N4)  ×  pattern PA1  ×  one FEASIBLE candidate
#            (DA emits N; VA walks them in order, picks the first one VA marks FEASIBLE,
#             up to MAX_VA_TRIES=5 tries; EA then exploits that one)
# Stages   : DA → VA(loop) → EA → assert all three stages produced their artifacts
#            (EA verdict CONFIRMED *or* UNCONFIRMED both count: smoke proves the PFCP
#             pipeline is wired end-to-end, not that any specific bug must crash)
# Target   : target/eupf_code/eupf  (cmd/core — the Go PFCP control plane)
# Testbed  : testbed/docker-eupf  (single eUPF NF, pulled image, EA sends crafted PFCP at N4)
# Expect   : ~10 min wall-clock; idempotent (restores DA result and prior EA baseline on exit)
#
# Note     : the eUPF runtime image has no ASan, but eUPF's PFCP control plane is Go — an iTrue
#            in cmd/core/ surfaces as a Go panic + stack trace on stdout, which the EA detects via
#            `docker compose logs`. So memory-safety crashes are still observable without ASan.
#
# Prereqs  : docker (compose v2), go, python3, claude CLI on PATH with credentials
#            (ANTHROPIC_API_KEY env var, iFinder_artifact-v4/.env, or ~/.claude/.credentials.json), and
#            `pip install -e iFinder_artifact-v4/src` so the `ifinder` console-script is on PATH.
#
# Usage    : bash scripts/reproduce_one_candidate_eupf.sh            (from anywhere)
#            PATTERN=PB1 bash scripts/reproduce_one_candidate_eupf.sh (other pattern)

set -euo pipefail

# ───────────────────────── paths ─────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IFINDER="$(cd "$SCRIPT_DIR/.." && pwd)"      # scripts/ -> artifact root
CODE="$IFINDER/src"
TARGET="$IFINDER/target/eupf_code/eupf"
TARGET_NAME="eupf"
PATTERN="${PATTERN:-PA1}"
SCOPE="../scope/pfcp/scope_eupf.json"
COMPOSE="../testbed/docker-eupf/docker-compose.yml"   # no env-file needed for this stack
EXPECTED_VER="v0.7.1"

DA_OUT="$IFINDER/outputs/discovery_results/${TARGET_NAME}/${PATTERN}.json"
VA_OUT="$IFINDER/outputs/vetting_results/${TARGET_NAME}/${PATTERN}.json"
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

# ───────────────────────── ui ─────────────────────────
if [[ -t 1 ]]; then
    BOLD=$'\033[1m'; GREEN=$'\033[32m'; RED=$'\033[31m'; YELLOW=$'\033[33m'; RESET=$'\033[0m'
else
    BOLD=''; GREEN=''; RED=''; YELLOW=''; RESET=''
fi
step() { printf "${BOLD}[%s/4]${RESET} %s\n" "$1" "$2"; }
pass() { printf "       ${GREEN}PASS${RESET}  %s\n" "$1"; }
fail() { printf "       ${RED}FAIL${RESET}  %s\n" "$1"; }
warn() { printf "       ${YELLOW}WARN${RESET}  %s\n" "$1"; }
info() { printf "       %s\n" "$1"; }

START_TIME=$(date +%s)

# ───────────────────────── cleanup trap (idempotency) ─────────────────────────
RESTORE_DA=""     # path to DA backup if we sliced it
RESTORE_EA=""     # path to EA baseline backup if we overwrote it
TESTBED_DOWN=""   # "1" if compose is up but not yet torn down

cleanup() {
    local rc=$?
    if [[ -n "$RESTORE_DA" && -f "$RESTORE_DA" ]]; then
        mv -f "$RESTORE_DA" "$DA_OUT" 2>/dev/null && echo "[cleanup] restored DA result"
    fi
    if [[ -n "$RESTORE_EA" && -f "$RESTORE_EA" ]]; then
        mv -f "$RESTORE_EA" "${RESTORE_EA%.smoke.bak}" 2>/dev/null && echo "[cleanup] restored prior EA baseline"
    fi
    if [[ "$TESTBED_DOWN" == "1" ]]; then
        echo "[cleanup] tearing down testbed"
        (cd "$CODE" && docker compose -f "$COMPOSE" down -v >/dev/null 2>&1) || true
    fi
    exit "$rc"
}
trap cleanup EXIT INT TERM

# ───────────────────────── 0/4 preflight ─────────────────────────
printf "${BOLD}=== iFinder One-Candidate Reproduce (eUPF) ===${RESET}\n"
printf "target  : eUPF %s (PFCP/N4)\n" "$EXPECTED_VER"
printf "pattern : %s\n" "$PATTERN"
printf "stages  : DA → VA → EA → assert pipeline ran (CONFIRMED *or* UNCONFIRMED both OK)\n"
printf "expect  : ~10 min wall-clock\n\n"

step 0 "preflight checks"
for bin in docker go python3 claude ifinder; do
    command -v "$bin" >/dev/null 2>&1 || { fail "$bin not on PATH"; exit 1; }
done
docker compose version >/dev/null 2>&1 || { fail "docker compose v2 required"; exit 1; }
if [[ -z "${ANTHROPIC_API_KEY:-}" && ! -f "${HOME}/.claude/.credentials.json" ]]; then
    fail "no Claude credentials (set ANTHROPIC_API_KEY, fill iFinder_artifact-v4/.env, or run 'claude' once to log in)"
    exit 1
fi
pass "all dependencies present"

# Pin $TARGET to eUPF v0.7.1. The artifact ships a clean source snapshot (no .git), so:
#   .git present -> checkout the tag (developer / fresh-clone mode)
#   no .git      -> snapshot mode: just verify the PFCP scan dir exists.
if [[ -d "$TARGET/.git" ]]; then
    if [[ -n "$(git -C "$TARGET" status --porcelain)" ]]; then
        fail "$TARGET has uncommitted changes; refusing to checkout (clean it first)"; exit 1
    fi
    cur_tag="$(git -C "$TARGET" describe --tags --always 2>/dev/null || echo unknown)"
    if [[ "$cur_tag" != "$EXPECTED_VER" ]]; then
        info "checking out $EXPECTED_VER in $TARGET (currently $cur_tag)"
        git -C "$TARGET" fetch --tags --quiet 2>/dev/null || true
        git -C "$TARGET" checkout --quiet "$EXPECTED_VER"
    fi
    pass "pinned to $EXPECTED_VER (git)"
else
    [[ -d "$TARGET/cmd/core" ]] || { fail "$TARGET/cmd/core missing — eUPF source not in place"; exit 1; }
    pass "eUPF source present (snapshot; pinned $EXPECTED_VER)"
fi

# ── ensure the eUPF testbed image is present; pull once if missing ──
ensure_testbed_image() {
    local compose_abs="$IFINDER/testbed/docker-eupf/docker-compose.yml" img
    img="$(grep -E '^[[:space:]]*image:' "$compose_abs" | head -1 | sed -E 's/.*image:[[:space:]]*([^[:space:]#]+).*/\1/')"
    [[ -n "$img" ]] || { fail "could not read image from $compose_abs"; exit 1; }
    if docker image inspect "$img" >/dev/null 2>&1; then
        pass "eUPF image present ($img)"
    else
        warn "eUPF image missing — pulling $img (one-time)"
        docker pull "$img" || { fail "docker pull $img failed"; exit 1; }
        pass "pulled $img"
    fi
}
ensure_testbed_image

# ───────────────────────── 1/4 DA ─────────────────────────
step 1 "DA: discover $PATTERN on eUPF $EXPECTED_VER (~5 min)"
cd "$CODE"

ifinder run --scope "$SCOPE" --patterns "$PATTERN" --target "$TARGET_NAME" --stage discovery 2>&1 \
    | tail -8 | sed 's/^/       │ /'

[[ -f "$DA_OUT" ]] || { fail "DA did not produce $DA_OUT"; exit 1; }

TOTAL="$(DA_OUT="$DA_OUT" python3 -c "import json,os; print(len(json.load(open(os.environ['DA_OUT']))['candidates']))")"
[[ "$TOTAL" -gt 0 ]] || { fail "DA emitted 0 candidates"; exit 1; }
pass "DA emitted $TOTAL candidate(s) (will walk in order until VA marks one FEASIBLE)"

# ───────────────────────── 2/4 VA (loop: slice DA → 1 candidate → vet → next if INFEASIBLE) ─────────────────────────
MAX_VA_TRIES=5
step 2 "VA: try candidates in DA order, stop at first FEASIBLE (≤ $MAX_VA_TRIES tries × ~1 min)"
RESTORE_DA="${DA_OUT}.smoke.bak"
cp -f "$DA_OUT" "$RESTORE_DA"

CANDIDATE_ID=""
VA_VERDICT=""

LIMIT=$(( TOTAL < MAX_VA_TRIES ? TOTAL : MAX_VA_TRIES ))
for try in $(seq 1 "$LIMIT"); do
    CID="$(RESTORE_DA_PATH="$RESTORE_DA" IDX="$((try-1))" python3 <<'PY'
import json, os
d = json.load(open(os.environ['RESTORE_DA_PATH']))
print(d['candidates'][int(os.environ['IDX'])]['id'])
PY
)"
    CAND_SUMMARY="$(RESTORE_DA_PATH="$RESTORE_DA" CID="$CID" python3 <<'PY'
import json, os
d = json.load(open(os.environ['RESTORE_DA_PATH']))
c = next(c for c in d['candidates'] if c['id'] == os.environ['CID'])
s = c['vulnerable_site']
f = s.get('file', '?')
f = f.split('/eupf/')[-1] if '/eupf/' in f else f
print(f"{c.get('trigger_message','?')} / {c.get('trigger_ie','?')} -> {f}:{s.get('line','?')} ({s.get('function','?')})")
PY
)"
    info "try $try/$LIMIT: $CID  —  $CAND_SUMMARY"

    # slice DA artifact to just this candidate (so VA only judges this one)
    DA_OUT_PATH="$DA_OUT" RESTORE_DA_PATH="$RESTORE_DA" CID="$CID" python3 <<'PY'
import json, os
d = json.load(open(os.environ['RESTORE_DA_PATH']))
d['candidates'] = [c for c in d['candidates'] if c['id'] == os.environ['CID']]
json.dump(d, open(os.environ['DA_OUT_PATH'], 'w'), indent=2)
PY

    ifinder run --scope "$SCOPE" --patterns "$PATTERN" --target "$TARGET_NAME" --stage vetting 2>&1 \
        | tail -4 | sed 's/^/       │ /'

    [[ -f "$VA_OUT" ]] || { fail "VA did not produce $VA_OUT"; exit 1; }

    VA_VERDICT="$(VA_OUT="$VA_OUT" CID="$CID" python3 <<'PY'
import json, os
v = json.load(open(os.environ['VA_OUT']))
dec = next((r for r in v['results'] if r['candidate_id'] == os.environ['CID']), None)
print(dec['verdict'] if dec else 'MISSING')
PY
)"

    if [[ "$VA_VERDICT" == "FEASIBLE" ]]; then
        CANDIDATE_ID="$CID"
        pass "VA → FEASIBLE on try $try ($CID)"
        break
    fi
    info "  → $VA_VERDICT, next candidate..."
done

# restore the full DA result NOW (success or fail)
mv -f "$RESTORE_DA" "$DA_OUT"; RESTORE_DA=""

if [[ -z "$CANDIDATE_ID" ]]; then
    fail "no FEASIBLE candidate found in the first $LIMIT of $TOTAL DA candidate(s)"
    info "rerun for a different DA sample, or bump MAX_VA_TRIES in this script"
    exit 1
fi

# ───────────────────────── 3/4 EA ─────────────────────────
step 3 "EA: PoC + testbed (~3-10 min; CONFIRMED or UNCONFIRMED both count as pipeline-OK)"
EA_OUT="$EA_DIR/${CANDIDATE_ID}.json"
if [[ -f "$EA_OUT" ]]; then
    RESTORE_EA="${EA_OUT}.smoke.bak"
    cp -f "$EA_OUT" "$RESTORE_EA"
fi

TESTBED_DOWN=1
ifinder run --scope "$SCOPE" --patterns "$PATTERN" --target "$TARGET_NAME" --stage exploitation \
    --candidate "$CANDIDATE_ID" \
    --compose-file "$COMPOSE" 2>&1 \
    | tail -12 | sed 's/^/       │ /'
TESTBED_DOWN=""     # ifinder's pipeline ran its own `down -v` in its finally-block

[[ -f "$EA_OUT" ]] || { fail "EA did not produce $EA_OUT"; exit 1; }

read -r VERDICT ATTEMPTS CRASH < <(EA_OUT="$EA_OUT" python3 <<'PY'
import json, os
r = json.load(open(os.environ['EA_OUT']))
te = r.get('trigger_evidence') or {}
crash = (te.get('type') or '').replace(' ', '_')
print(r['validation_result'], r.get('attempts', '?'), crash or '-')
PY
)

case "$VERDICT" in
    CONFIRMED)
        pass "EA → CONFIRMED  (attempts=$ATTEMPTS, crash=${CRASH//_/ })"
        ;;
    UNCONFIRMED)
        warn "EA → UNCONFIRMED (attempts=$ATTEMPTS) — pipeline ran fine, candidate not exploitable in $ATTEMPTS attempts"
        info "inspect $EA_OUT for refinement traces; rerun for a different candidate"
        ;;
    *)
        fail "EA verdict: $VERDICT (expected CONFIRMED or UNCONFIRMED)"
        info "inspect $EA_OUT"
        exit 1
        ;;
esac

# ───────────────────────── 4/4 gate ─────────────────────────
step 4 "final gate"
pass "DA emitted candidate, VA judged FEASIBLE, EA produced artifact (verdict=$VERDICT)"

elapsed=$(( $(date +%s) - START_TIME ))
printf "\n${BOLD}REPRODUCE (eUPF): ${GREEN}OK${RESET}  (%d min %02d s)\n" $((elapsed/60)) $((elapsed%60))
