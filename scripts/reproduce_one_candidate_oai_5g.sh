#!/usr/bin/env bash
# reproduce_one_candidate_oai_5g.sh — One-shot end-to-end reproduction for iFinder on OAI CN5G (5G PFCP).
#
# Scope    : OAI CN5G v2.2.0 (PFCP/N4: SMF + UPF)  ×  pattern PA1  ×  one FEASIBLE candidate
#            (DA emits N; VA walks them in order, picks the first one VA marks FEASIBLE,
#             up to MAX_VA_TRIES=5 tries; EA then exploits that one)
# Stages   : DA → VA(loop) → EA → assert all three stages produced their artifacts
#            (EA verdict CONFIRMED *or* UNCONFIRMED both count: smoke proves the PFCP
#             pipeline is wired end-to-end, not that any specific bug must crash)
# Target   : target/openairinterface_code/oai-cn5g-fed  (component/oai-{smf,upf}/src/pfcp)
# Testbed  : testbed/oai-cn5g-fed  (full CN5G via docker-compose-basic-nrf.yaml; images PULLED from
#            Docker Hub, pinned to v2.2.0 to match the analyzed source; EA sends crafted PFCP at N4)
# Expect   : ~10 min wall-clock; idempotent (restores DA result and prior EA baseline on exit)
#
# Prereqs  : docker (compose v2), go, python3, claude CLI on PATH with credentials
#            (ANTHROPIC_API_KEY env var, iFinder_artifact-v4/.env, or ~/.claude/.credentials.json), and
#            `pip install -e iFinder_artifact-v4/src` so the `ifinder` console-script is on PATH.
#
# Usage    : bash scripts/reproduce_one_candidate_oai_5g.sh            (from anywhere)
#            PATTERN=PB1 bash scripts/reproduce_one_candidate_oai_5g.sh (other pattern)

set -euo pipefail

# ───────────────────────── paths ─────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IFINDER="$(cd "$SCRIPT_DIR/.." && pwd)"      # scripts/ -> artifact root
CODE="$IFINDER/src"
TARGET="$IFINDER/target/openairinterface_code/oai-cn5g-fed"
TARGET_NAME="oai_220"
PATTERN="${PATTERN:-PA1}"
SCOPE="../scope/pfcp/scope_oai_220.json"
COMPOSE="../testbed/oai-cn5g-fed/docker-compose/docker-compose-basic-nrf.yaml"   # no env-file for this stack
EXPECTED_VER="2.2.0"

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
printf "${BOLD}=== iFinder One-Candidate Reproduce (OAI CN5G / 5G PFCP) ===${RESET}\n"
printf "target  : OAI CN5G v%s (PFCP/N4: SMF + UPF)\n" "$EXPECTED_VER"
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

# OAI CN5G target = the SMF + UPF PFCP sources. The artifact ships a clean source snapshot (no .git),
# so we verify the PFCP scan dirs are in place; the testbed images are pinned to v2.2.0 to match.
[[ -d "$TARGET" ]] || { fail "target codebase missing: $TARGET"; exit 1; }
for d in component/oai-smf/src/pfcp component/oai-upf/src/pfcp; do
    [[ -d "$TARGET/$d" ]] || { fail "scan dir missing: $TARGET/$d — OAI CN5G source not in place"; exit 1; }
done
pass "OAI CN5G target + PFCP scan dirs present (pinned $EXPECTED_VER; testbed images v$EXPECTED_VER)"

# ── ensure the CN5G testbed images are present; pull (Docker Hub) only if missing — no local build ──
ensure_testbed_images() {
    local compose_abs="$IFINDER/testbed/oai-cn5g-fed/docker-compose/docker-compose-basic-nrf.yaml"
    local missing=() img
    while IFS= read -r img; do
        [[ -z "$img" ]] && continue
        docker image inspect "$img" >/dev/null 2>&1 || missing+=("$img")
    done < <(docker compose -f "$compose_abs" config --images 2>/dev/null | sort -u)
    if [[ ${#missing[@]} -eq 0 ]]; then
        pass "testbed images present (v$EXPECTED_VER) — skipping pull"
        return 0
    fi
    warn "${#missing[@]} testbed image(s) missing — pulling from Docker Hub (one-time, may take a few minutes)"
    info "missing: ${missing[*]}"
    if ! ( cd "$IFINDER/testbed/oai-cn5g-fed/docker-compose" && docker compose -f docker-compose-basic-nrf.yaml pull ); then
        fail "docker compose pull failed (need network for first pull)"; exit 1
    fi
    pass "testbed images pulled (v$EXPECTED_VER)"
}
ensure_testbed_images

# ───────────────────────── 1/4 DA ─────────────────────────
step 1 "DA: discover $PATTERN on OAI CN5G v$EXPECTED_VER PFCP (smf/upf) (~5 min)"
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
f = f.split('oai-cn5g-fed/')[-1] if 'oai-cn5g-fed/' in f else f
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
printf "\n${BOLD}REPRODUCE (OAI CN5G / 5G PFCP): ${GREEN}OK${RESET}  (%d min %02d s)\n" $((elapsed/60)) $((elapsed%60))
