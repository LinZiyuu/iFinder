#!/usr/bin/env bash
# reproduce_one_candidate_free5gc.sh — One-shot end-to-end reproduction for iFinder on free5GC.
#
# Scope    : free5GC v4.1.0 (PFCP/N4)  ×  pattern PA1  ×  one FEASIBLE candidate
#            ONE scope target `free5gc_410` whose scan_dirs cover BOTH NFs —
#            NFs/smf/internal/pfcp/ (SMF v1.4.0) and NFs/upf/internal/pfcp/ +
#            NFs/upf/internal/forwarder/ (go-upf v1.2.7) — so a single DA pass mines both. Each
#            candidate is tagged SMF or UPF by the DA, and the EA auto-routes it to that NF
#            (SMF=10.100.200.14 / UPF=10.100.200.5) — you never pick the NF.
#            (DA emits N; VA walks them in DA order, picks the first VA marks FEASIBLE, up to
#             MAX_VA_TRIES=5 tries; EA then exploits that one.)
# Stages   : DA → VA(loop) → EA → assert all three stages produced their artifacts
#            (EA verdict CONFIRMED *or* UNCONFIRMED both count: smoke proves the PFCP pipeline is
#            wired end-to-end, not that any specific bug must crash)
# Target   : target/free5gc_code/free5gc_410  (free5GC monorepo @ v4.1.0; NFs/* are git submodules)
# Testbed  : testbed/free5gc-compose  (full free5GC @ v4.1.0, images pulled from DockerHub; this
#            script brings up just the winner NF + its deps and hands the EA a ready stack — the EA
#            sends crafted PFCP at the candidate's NF and scrapes its logs for a Go panic)
# Expect   : ~10-12 min wall-clock; idempotent (restores DA result + prior EA baseline, tears down)
#
# Note     : free5GC SMF/UPF are Go — an iTrue in the scanned dirs surfaces as a Go panic + stack
#            trace on stdout, which the EA detects via `docker compose logs` (no ASan needed).
#
# Caveat   : the free5GC UPF needs the host gtp5g kernel module to start its forwarder. An SMF-side
#            winner does NOT need it; a UPF-side winner DOES (this script fails fast with a hint if
#            the module is absent and the winner is the UPF). See testbed/README.md §2.
#
# Prereqs  : docker (compose v2), go, python3, claude CLI on PATH with credentials
#            (ANTHROPIC_API_KEY env var, iFinder_artifact-v4/.env, or ~/.claude/.credentials.json), and
#            `pip install -e iFinder_artifact-v4/src` so the `ifinder` console-script is on PATH.
#            UPF candidates additionally need the gtp5g module loaded (`sudo modprobe gtp5g`).
#
# Usage    : bash scripts/reproduce_one_candidate_free5gc.sh             (from anywhere)
#            PATTERN=PB1 bash scripts/reproduce_one_candidate_free5gc.sh (other pattern)

set -euo pipefail

# ───────────────────────── paths ─────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IFINDER="$(cd "$SCRIPT_DIR/.." && pwd)"      # scripts/ -> artifact root
CODE="$IFINDER/src"
TARGET="$IFINDER/target/free5gc_code/free5gc_410"
TARGET_NAME="free5gc_410"
PATTERN="${PATTERN:-PA1}"
SCOPE="../scope/pfcp/scope_free5gc_410.json"
COMPOSE="../testbed/free5gc-compose/docker-compose.yaml"   # no env-file needed for this stack
COMPOSE_DIR="$IFINDER/testbed/free5gc-compose"             # absolute; our own compose calls pin
COMPOSE_ABS="$COMPOSE_DIR/docker-compose.yaml"             # --project-directory so ./config ./cert resolve
SCAN_DIRS=(NFs/smf/internal/pfcp NFs/upf/internal/pfcp NFs/upf/internal/forwarder)  # presence + non-empty check
EXPECTED_VER="v4.1.0 (smf v1.4.0 / go-upf v1.2.7)"

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
printf "${BOLD}=== iFinder One-Candidate Reproduce (free5GC) ===${RESET}\n"
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

# The free5GC monorepo pulls NFs/* via git submodules, so an unpopulated checkout looks like
# present-but-empty scan dirs. Verify each scan dir exists AND has Go sources (catches a clone
# whose submodules were never `git submodule update --init`-ed).
for d in "${SCAN_DIRS[@]}"; do
    [[ -d "$TARGET/$d" ]] || { fail "$TARGET/$d missing — free5GC source not in place"; exit 1; }
    if ! compgen -G "$TARGET/$d/*.go" >/dev/null && [[ -z "$(ls -A "$TARGET/$d" 2>/dev/null)" ]]; then
        fail "$TARGET/$d is empty — submodules not initialized (run: git -C $TARGET submodule update --init --recursive)"
        exit 1
    fi
done
# If it's a git checkout, confirm the tag; tolerate snapshot (no .git) too.
if [[ -d "$TARGET/.git" ]]; then
    cur_tag="$(git -C "$TARGET" describe --tags --always 2>/dev/null || echo unknown)"
    if [[ "$cur_tag" == v4.1.0* ]]; then
        pass "free5GC source present @ $cur_tag ($EXPECTED_VER)"
    else
        warn "free5GC checkout is '$cur_tag' (expected v4.1.0) — proceeding, but testbed images are v4.1.0"
    fi
else
    pass "free5GC source present (snapshot; $EXPECTED_VER)"
fi

# gtp5g host module: required by the UPF forwarder, NOT by the SMF. Probe now and remember; we only
# hard-fail later if the VA-chosen winner turns out to be the UPF (so SMF-only runs need no module).
GTP5G_LOADED=""
if lsmod 2>/dev/null | grep -qE '^gtp5g\b'; then
    GTP5G_LOADED=1
    pass "gtp5g kernel module loaded (UPF candidates exploitable)"
else
    warn "gtp5g kernel module NOT loaded — SMF candidates are fine; a UPF winner will be rejected"
    info "to enable UPF: install free5gc/gtp5g and 'sudo modprobe gtp5g' (see testbed/README.md §2)"
fi

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
f = s.get('file', '?'); f = f.split('/free5gc_410/')[-1] if '/free5gc_410/' in f else f
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

# free5GC NF -> docker service + N4 readiness marker
if [[ "$NF" == "SMF" ]]; then
    READY_SVC="free5gc-smf"; READY_RE="Listen on .*:8805"
else
    READY_SVC="free5gc-upf"; READY_RE="UPF started"
    # The UPF forwarder cannot start without gtp5g; refuse rather than burn EA attempts on a dead NF.
    if [[ -z "$GTP5G_LOADED" ]]; then
        fail "winner is a UPF candidate but the gtp5g kernel module is not loaded"
        info "load it (sudo modprobe gtp5g; see testbed/README.md §2) and rerun, or restrict the"
        info "scope's scan_dirs to NFs/smf/internal/pfcp/ to stay on the SMF (no module needed)"
        exit 1
    fi
fi

# ───────────────────────── 3/4 EA ─────────────────────────
step 3 "EA: bring up free5GC ($NF + deps), hand the EA a ready testbed, PoC the $NF candidate (~3-10 min)"
EA_OUT="$EA_DIR/${CANDIDATE_ID}.json"
if [[ -f "$EA_OUT" ]]; then
    RESTORE_EA="${EA_OUT}.smoke.bak"
    cp -f "$EA_OUT" "$RESTORE_EA"
fi

# Bring up just the winner NF + its compose deps ourselves and wait for its N4 listener, then let the
# EA reuse it (--no-manage-testbed). More reliable than racing the boot with the EA's fixed wait.
# (For SMF this also starts nrf+upf via depends_on; the UPF may crash-loop without gtp5g but that does
#  not block the SMF's own PFCP listener.)
info "docker compose up -d $READY_SVC (+deps)"
docker compose -f "$COMPOSE_ABS" --project-directory "$COMPOSE_DIR" up -d "$READY_SVC" >/dev/null 2>&1
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
printf "\n${BOLD}REPRODUCE (free5GC): ${GREEN}OK${RESET}  (%d min %02d s)\n" $((elapsed/60)) $((elapsed%60))
