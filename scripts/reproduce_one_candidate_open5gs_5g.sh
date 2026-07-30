#!/usr/bin/env bash
# reproduce_one_candidate_open5gs_5g.sh — One-shot end-to-end reproduction for iFinder.
#
# Scope    : open5gs v2.7.5  ×  pattern PA1  ×  one FEASIBLE candidate
#            (DA emits N; VA walks them in order, picks the first one VA marks FEASIBLE,
#             up to MAX_VA_TRIES=5 tries; EA then exploits that one)
# Stages   : DA → VA(loop) → EA → assert all three stages produced their artifacts
#            (EA verdict CONFIRMED *or* UNCONFIRMED both count: smoke proves the
#             pipeline is wired end-to-end, not that any specific bug must crash)
# Expect   : ~10 minutes wall-clock; idempotent (restores DA result and prior EA baseline on exit)
#
# Prereqs  : docker (compose v2), go, python3, claude CLI on PATH with credentials
#            (ANTHROPIC_API_KEY env var, iFinder_artifact-v4/.env, or ~/.claude/.credentials.json), and
#            `pip install -e iFinder_artifact-v4/src` so the `ifinder` console-script is on PATH.
#
# Usage    : bash iFinder_artifact-v4/scripts/reproduce_one_candidate_open5gs_5g.sh   (from anywhere)

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

DA_OUT="$IFINDER/outputs/discovery_results/${TARGET_NAME}/PA1.json"
VA_OUT="$IFINDER/outputs/vetting_results/${TARGET_NAME}/PA1.json"
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
        (cd "$CODE" && docker compose -f "$COMPOSE" --env-file "$ENVFILE" down -v >/dev/null 2>&1) || true
    fi
    exit "$rc"
}
trap cleanup EXIT INT TERM

# ───────────────────────── 0/4 preflight ─────────────────────────
printf "${BOLD}=== iFinder One-Candidate Reproduce ===${RESET}\n"
printf "target  : open5gs v2.7.5\n"
printf "pattern : PA1 (Malformed Field)\n"
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

# Pin $TARGET to open5gs v2.7.5 in one of two modes, so the unpacked release tarball works
# without git or network:
#   .git present -> require a clean tree and checkout the tag (developer / fresh-clone mode)
#   no .git      -> verify the version straight from meson.build (tarball mode)
EXPECTED_VER="2.7.5"
if [[ -d "$TARGET/.git" ]]; then
    if [[ -n "$(git -C "$TARGET" status --porcelain)" ]]; then
        fail "$TARGET has uncommitted changes; refusing to checkout (clean it first)"
        git -C "$TARGET" status --short
        exit 1
    fi
    cur_tag="$(git -C "$TARGET" describe --tags --always 2>/dev/null || echo unknown)"
    if [[ "$cur_tag" != "v$EXPECTED_VER" ]]; then
        info "checking out v$EXPECTED_VER in $TARGET (currently $cur_tag)"
        git -C "$TARGET" fetch --tags --quiet 2>/dev/null || true
        git -C "$TARGET" checkout --quiet "v$EXPECTED_VER"
        pass "pinned to v$EXPECTED_VER (git)"
    else
        pass "already at v$EXPECTED_VER (git)"
    fi
else
    src_ver="$(sed -nE "s/^[[:space:]]*version[[:space:]]*:[[:space:]]*'([0-9][0-9.]*)'.*/\1/p" "$TARGET/meson.build" 2>/dev/null)"
    [[ "$src_ver" == "$EXPECTED_VER" ]] || {
        fail "$TARGET: no .git and meson.build version='${src_ver:-?}' (expected $EXPECTED_VER)"
        exit 1
    }
    pass "verified open5gs $src_ver from meson.build (no .git; tarball mode)"
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

# ───────────────────────── 1/4 DA ─────────────────────────
step 1 "DA: discover PA1 on open5gs v2.7.5 (~5 min)"
cd "$CODE"

ifinder run --scope "$SCOPE" --patterns PA1 --target "$TARGET_NAME" --stage discovery 2>&1 \
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
    # pick the try-th candidate id from the ORIGINAL DA artifact (backup)
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
print(f"{c.get('trigger_message','?')} / {c.get('trigger_ie','?')} -> {s.get('file','?').split('open5gs/')[-1]}:{s.get('line','?')} ({s.get('function','?')})")
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

    # run VA on just this candidate
    ifinder run --scope "$SCOPE" --patterns PA1 --target "$TARGET_NAME" --stage vetting 2>&1 \
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
ifinder run --scope "$SCOPE" --patterns PA1 --target "$TARGET_NAME" --stage exploitation \
    --candidate "$CANDIDATE_ID" \
    --compose-file "$COMPOSE" --env-file "$ENVFILE" 2>&1 \
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
        # Pipeline is fine — EA ran the full refine budget and produced an artifact.
        # The picked candidate just happened not to be 1-shot exploitable (e.g. SDF Filter
        # bug whose downstream bounds check defends against the malformed payload).
        # Smoke goal is "DA → VA → EA all wire end-to-end", not "this specific bug crashes".
        warn "EA → UNCONFIRMED (attempts=$ATTEMPTS) — pipeline ran fine, candidate not exploitable in $ATTEMPTS attempts"
        info "inspect $EA_OUT for refinement traces; rerun for a different candidates[0]"
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
printf "\n${BOLD}REPRODUCE: ${GREEN}OK${RESET}  (%d min %02d s)\n" $((elapsed/60)) $((elapsed%60))
