#!/usr/bin/env bash
# reproduce_one_candidate_sdcore.sh — One-shot end-to-end reproduction for iFinder on SD-Core.
#
# Scope    : SD-Core (PFCP/N4)  ×  pattern PA1  ×  one FEASIBLE candidate
#            ONE scope target `sdcore` whose scan_dirs cover BOTH NFs — smf/pfcp/ + smf/context/
#            (SMF v3.0.1) and upf/pfcpiface/ (UPF v2.1.2) — so a single DA pass mines both. Each
#            candidate is tagged SMF or UPF by the DA, and the EA auto-routes it to that NF
#            (SMF=10.100.1.5 / UPF=10.100.1.4) — you never pick the NF.
#            (DA emits N; VA walks them in DA order, picks the first VA marks FEASIBLE, up to
#             MAX_VA_TRIES=5 tries; EA then exploits that one.)
# Stages   : DA → VA(loop) → EA → assert all three stages produced their artifacts
#            (EA verdict CONFIRMED *or* UNCONFIRMED both count: smoke proves the PFCP pipeline is
#             wired end-to-end, not that any specific bug must crash)
# Target   : target/sdcore_code  (smf/{pfcp,context} + upf/pfcpiface — the omec Go PFCP code)
# Testbed  : testbed/docker-sdcore  (full SD-Core; this script brings it up and hands the EA a ready
#            stack — the EA sends crafted PFCP at the candidate's NF and scrapes its logs for a panic)
# Expect   : ~10-12 min wall-clock; idempotent (restores DA result + prior EA baseline, tears down)
#
# Note     : omec SMF/UPF are Go — an iTrue in the scanned dirs surfaces as a Go panic + stack trace
#            on stdout, which the EA detects via `docker compose logs` (no ASan needed).
#
# Caveat   : a UPF-side winner is exploitable but coarser — the EA restarts the `upf`(bessd) container
#            between attempts and pfcpiface shares its netns, so UPF resets are blunter than the SMF's
#            single-container restart.
#
# Prereqs  : docker (compose v2), go, python3, claude CLI on PATH with credentials
#            (ANTHROPIC_API_KEY env var, iFinder_artifact-v4/.env, or ~/.claude/.credentials.json), and
#            `pip install -e iFinder_artifact-v4/src` so the `ifinder` console-script is on PATH.
#            The BESS UPF needs hugepages; the testbed self-provisions them (privileged) — see
#            testbed/docker-sdcore/README.md if `upf` fails to start.
#
# Usage    : bash scripts/reproduce_one_candidate_sdcore.sh            (from anywhere)
#            PATTERN=PB1 bash scripts/reproduce_one_candidate_sdcore.sh (other pattern)

set -euo pipefail

# ───────────────────────── paths ─────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IFINDER="$(cd "$SCRIPT_DIR/.." && pwd)"      # scripts/ -> artifact root
CODE="$IFINDER/src"
TARGET="$IFINDER/target/sdcore_code"
TARGET_NAME="sdcore"
PATTERN="${PATTERN:-PA1}"
SCOPE="../scope/pfcp/scope_sdcore.json"
COMPOSE="../testbed/docker-sdcore/docker-compose.yml"   # no env-file needed for this stack
COMPOSE_DIR="$IFINDER/testbed/docker-sdcore"            # absolute; our own compose calls pin
COMPOSE_ABS="$COMPOSE_DIR/docker-compose.yml"           # --project-directory so ./configs ./upf resolve
SCAN_DIRS=(smf/pfcp smf/context upf/pfcpiface)          # snapshot-mode presence check
EXPECTED_VER="smf-v3.0.1 / upf-v2.1.2"

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
        docker compose -f "$COMPOSE_ABS" --project-directory "$COMPOSE_DIR" down -v --remove-orphans >/dev/null 2>&1 || true
    fi
    exit "$rc"
}
trap cleanup EXIT INT TERM

# ───────────────────────── 0/4 preflight ─────────────────────────
printf "${BOLD}=== iFinder One-Candidate Reproduce (SD-Core) ===${RESET}\n"
printf "target  : %s (%s, PFCP/N4)\n" "$TARGET_NAME" "$EXPECTED_VER"
printf "pattern : %s\n" "$PATTERN"
printf "stages  : DA → VA → EA → assert pipeline ran (CONFIRMED *or* UNCONFIRMED both OK)\n"
printf "routing : one DA scans SMF+UPF; EA auto-routes each candidate to its NF\n\n"

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

# The artifact ships clean source snapshots (no .git) for smf/ and upf/, so just verify the scan
# dirs exist. (SMF v3.0.1 and UPF v2.1.2 are separate repos under target/sdcore_code/.)
for d in "${SCAN_DIRS[@]}"; do
    [[ -d "$TARGET/$d" ]] || { fail "$TARGET/$d missing — SD-Core source not in place"; exit 1; }
done
pass "SD-Core source present (snapshot; $EXPECTED_VER)"

# ── ensure all testbed images are present; pull the stack once if any missing ──
missing=0
while IFS= read -r img; do
    [[ -z "$img" ]] && continue
    docker image inspect "$img" >/dev/null 2>&1 || { warn "missing image: $img"; missing=1; }
done < <(docker compose -f "$COMPOSE_ABS" config --images 2>/dev/null)
if [[ "$missing" == "1" ]]; then
    warn "pulling testbed images (one-time) ..."
    docker compose -f "$COMPOSE_ABS" pull || { fail "docker compose pull failed"; exit 1; }
fi
pass "testbed images present"

# ───────────────────────── 1/4 DA ─────────────────────────
step 1 "DA: discover $PATTERN on $TARGET_NAME ($EXPECTED_VER) — one pass over SMF+UPF (~5 min)"
cd "$CODE"

ifinder run --scope "$SCOPE" --patterns "$PATTERN" --target "$TARGET_NAME" --stage discovery 2>&1 \
    | tail -8 | sed 's/^/       │ /'

[[ -f "$DA_OUT" ]] || { fail "DA did not produce $DA_OUT"; exit 1; }

TOTAL="$(DA_OUT="$DA_OUT" python3 -c "import json,os; print(len(json.load(open(os.environ['DA_OUT']))['candidates']))")"
[[ "$TOTAL" -gt 0 ]] || { fail "DA emitted 0 candidates"; exit 1; }
pass "DA emitted $TOTAL candidate(s) across SMF+UPF (will walk until VA marks one FEASIBLE)"

# ───────────────────────── 2/4 VA (loop: slice DA → 1 candidate → vet → next if INFEASIBLE) ─────────────────────────
MAX_VA_TRIES=5
step 2 "VA: try candidates in DA order, stop at first FEASIBLE (≤ $MAX_VA_TRIES tries × ~1 min)"
RESTORE_DA="${DA_OUT}.smoke.bak"
cp -f "$DA_OUT" "$RESTORE_DA"

CANDIDATE_ID=""
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
s = c.get('vulnerable_site', {})
f = s.get('file', '?'); f = f.split('/sdcore_code/')[-1] if '/sdcore_code/' in f else f
print(f"[{c.get('network_function','?')}] {c.get('trigger_message','?')} / {c.get('trigger_ie','?')} -> {f}:{s.get('line','?')} ({s.get('function','?')})")
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

# winning candidate's NF (mirrors the EA's own routing: default UPF when unset) -> which N4 to await
NF="$(RESTORE_DA_PATH="$RESTORE_DA" CID="${CANDIDATE_ID:-}" python3 <<'PY'
import json, os
cid = os.environ.get('CID') or ''
try:
    d = json.load(open(os.environ['RESTORE_DA_PATH']))
    c = next((c for c in d['candidates'] if c['id'] == cid), None)
    print((c.get('network_function') if c else None) or 'UPF')
except Exception:
    print('UPF')
PY
)"

# restore the full DA result NOW (success or fail)
mv -f "$RESTORE_DA" "$DA_OUT"; RESTORE_DA=""

if [[ -z "$CANDIDATE_ID" ]]; then
    fail "no FEASIBLE candidate found in the first $LIMIT of $TOTAL DA candidate(s)"
    info "rerun for a different DA sample, or bump MAX_VA_TRIES in this script"
    exit 1
fi

if [[ "$NF" == "SMF" ]]; then
    READY_SVC="smf"; READY_RE="Listen on .*:8805"
else
    READY_SVC="upf"; READY_RE="listening for new PFCP connections"
fi

# ───────────────────────── 3/4 EA ─────────────────────────
step 3 "EA: bring up SD-Core, hand the EA a ready testbed, PoC the $NF candidate (~3-10 min)"
EA_OUT="$EA_DIR/${CANDIDATE_ID}.json"
if [[ -f "$EA_OUT" ]]; then
    RESTORE_EA="${EA_OUT}.smoke.bak"
    cp -f "$EA_OUT" "$RESTORE_EA"
fi

# Bring the multi-container stack up ourselves and wait for the winner NF's N4 listener, then let the
# EA reuse it (--no-manage-testbed). More reliable than racing the slow boot with the EA's fixed wait
# (mongo replica-set init → webconsole → smf), which could otherwise burn EA refinement attempts.
info "docker compose up -d (full SD-Core stack)"
docker compose -f "$COMPOSE_ABS" --project-directory "$COMPOSE_DIR" up -d >/dev/null 2>&1
TESTBED_DOWN=1

info "waiting for '$READY_SVC' N4 listener (/$READY_RE/) ..."
ready=""
for _ in $(seq 1 40); do
    if docker compose -f "$COMPOSE_ABS" --project-directory "$COMPOSE_DIR" logs --no-color "$READY_SVC" 2>/dev/null | grep -qE "$READY_RE"; then
        ready=1; break
    fi
    sleep 3
done
# Fallback: if the marker wasn't seen but the container is Up (e.g. a reused stack whose startup
# log scrolled), proceed anyway — the EA resets the NF before each attempt regardless.
if [[ -z "$ready" ]] && docker compose -f "$COMPOSE_ABS" --project-directory "$COMPOSE_DIR" ps "$READY_SVC" --format '{{.Status}}' 2>/dev/null | grep -q "Up"; then
    warn "'$READY_SVC' is Up but N4 marker not seen in logs — proceeding"
    ready=1
fi
[[ -n "$ready" ]] || { fail "'$READY_SVC' never reached '/$READY_RE/' and is not Up"; docker compose -f "$COMPOSE_ABS" --project-directory "$COMPOSE_DIR" logs --tail 20 "$READY_SVC" 2>&1 | sed 's/^/       │ /'; exit 1; }
pass "'$READY_SVC' N4 listener ready (:8805)"

ifinder run --scope "$SCOPE" --patterns "$PATTERN" --target "$TARGET_NAME" --stage exploitation \
    --candidate "$CANDIDATE_ID" \
    --compose-file "$COMPOSE" --no-manage-testbed 2>&1 \
    | tail -12 | sed 's/^/       │ /'
# EA reused the running stack; the cleanup trap tears it down (TESTBED_DOWN stays 1)

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
pass "DA emitted candidate, VA judged FEASIBLE, EA produced artifact ($NF, verdict=$VERDICT)"

elapsed=$(( $(date +%s) - START_TIME ))
printf "\n${BOLD}REPRODUCE (SD-Core): ${GREEN}OK${RESET}  (%d min %02d s)\n" $((elapsed/60)) $((elapsed%60))
