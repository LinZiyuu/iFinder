#!/bin/bash
# SPDX-License-Identifier: LicenseRef-CSSL-1.0

# *   Description:
# **   The Core Network Functions are built parallely.
# **   Each NF is cloned from GitLab, checked out at a specific commit,
# **   associated with a shared 'common-src' submodule commit, and then
# **   built into a Docker image.
# **   CPU cores are allocated per NF to enable efficient parallel builds.

# *   Inputs:
# **    <nfJson-file>
# ***     Path to a JSON file that maps Core Network Function (NF) names
# ***     to their corresponding Git commits or branches and common-src commits/branches to be built.


# **    <archives>
# ***     Directory where build logs, docker image metadata and the list of failed
# ***     Network Function names will be stored.

# *   Variables:
# **   NF_JSON_FILE              - Path to the JSON file mapping NF names to
# **                               their corresponding Git commits or branches
# **   COMMON_SRC_MAP            - Associative array mapping NF names to their
# **                               specific common-src commits from the JSON file
# **   LOG_ARCHIVES              - Directory where build logs
# **                               and failure reports are stored
# **   BASE_URL                  - Base GitLab URL for cloning NF repositories
# **   CLONE_DIR                 - Local directory where NF repositories are cloned
# **   FAILED_NFS_FILE           - File containing the list of NFs whose builds failed (relative path)
# **   FULL_FAILED_NFS_PATH      - Full path to the failed NFs file, used for logging and final check
# **   DOCKER_METADATA_FILE      - File storing Docker inspect metadata for built images (relative path)
# **   FULL_DOCKER_METADATA_PATH - Full path to Docker metadata file
# **   CORES_PER_BUILD           - Number of CPU cores allocated per NF build
# **   MAX_PARALLEL              - Maximum number of NF builds executed in parallel
# **   NUMA1_FIRST_HALF_START    - Starting CPU core ID for the first NUMA block
# **   NUMA1_SECOND_HALF_START   - Starting CPU core ID for the second NUMA block
# **   NUMA1_FIRST_IDX           - Index counter for CPU allocation in the first NUMA block
# **   NUMA1_SECOND_IDX          - Index counter for CPU allocation in the second NUMA block
# **   jobs_running              - Number of NF build jobs currently running in parallel
# **   BATCH_PIDS                - Array of background PIDs for a batch of parallel NF Builds
# **   NF_MAP                    - Associative array mapping NF names to NF commits/branches
# **   NF_SHA                    - Short SHA of the NF repository commit being built
# **   COMMON_SRC_SHA            - Short SHA of the common-src submodule for the NF
# **   IMAGE_TAG                 - Docker image tag for the NF, includes NF_SHA and COMMON_SRC_SHA

# *   Functionality:
# **    Validate the input arguments.
# **    Initialize the core network function directories.
# **    Parse the NF Json file.
# **    Build NFs in parallel using the network functions commits
# **    and common-src submodule commits  provided in the JSON file.
# **    When the number of running jobs reach MAX_PARALLEL,
# **    then the script waits for all builds in current batch to finish via wait_for_batch().
# **    wait_for_batch() waits for all PIDs and if any NF fails,
# **    batch_failed=1, an error is logged and the script exits.
# **    This script launches NF Builds in batches of MAX_PARALLEL.
# ***      Example: Batch 2 (udm, smf, upf), smf fails → batch_failed=1, logs error,
# ***      smf recorded in $FAILED_NFS_FILE, script exits.
# ***      Batch 3 (nrf, udr, ausf) never starts, but wait still completes for udm & upf in Batch 2.
# ***      Note: NFs in remaining batches are never started if a previous batch NF fails.
# ***      only failed NFs in this batch are recorded in $FAILED_NFS_FILE
# ***      Remaining NFs can be considered "skipped" and won't appear in the log or failed list

set -e

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$1] $2"
}

log "INFO" "Script started at $(date)"

if [ $# -ne 2 ]; then
    echo "Usage: $0 <nfJson-file> <archives>"
    echo "Example: ./build_ubuntu_core_images.sh nf_map.json archives"
    exit 1
fi


NF_JSON_FILE=$1
LOG_ARCHIVES=$2

BASE_URL="https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g"
CLONE_DIR="$PWD/oai-cn5g-repos"
mkdir -p "$CLONE_DIR"
mkdir -p "$LOG_ARCHIVES"

# Failed NFs file
FAILED_NFS_FILE="$LOG_ARCHIVES/failed_network_functions.txt"
touch "$FAILED_NFS_FILE"
FULL_FAILED_NFS_PATH=$(realpath "$FAILED_NFS_FILE")

# Docker metadata file
DOCKER_METADATA_FILE="$LOG_ARCHIVES/docker_images_metadata.json"
touch "$DOCKER_METADATA_FILE"
FULL_DOCKER_METADATA_PATH=$(realpath "$DOCKER_METADATA_FILE")

# Now you can use the variable anywhere
echo "Failed NFs file: $FULL_FAILED_NFS_PATH"

# --- CPU / parallel build settings ---
CORES_PER_BUILD=5 # each NF
MAX_PARALLEL=3 # Limits the max parallel docker builds
NUMA1_FIRST_HALF_START=16 # starting CPU ID
NUMA1_SECOND_HALF_START=48 # starting CPU ID
NUMA1_FIRST_IDX=0 # index/counter for NUMA
NUMA1_SECOND_IDX=0 # index/counter for NUMA
jobs_running=0 # How many builds are running in the background
BATCH_PIDS=()   # PIDs of all NF builds in the current batch

# --- Parse NF JSON into associative array ---
declare -A NF_MAP
declare -A COMMON_SRC_MAP

while IFS="=" read -r nf; do
    # Remove brackets and quotes, split by comma
    nf_commit=$(jq -r --arg nf "$nf" '.[$nf].nf' "$NF_JSON_FILE")
    common_src_commit=$(jq -r --arg nf "$nf" '.[$nf]["common-src"]' "$NF_JSON_FILE")

    # If common-src commit is empty, log warning
    if [ -z "$common_src_commit" ]; then
        log "WARNING" "No common-src commit provided for $nf"
    fi

    NF_MAP["$nf"]="$nf_commit"
    COMMON_SRC_MAP["$nf"]="$common_src_commit"

done < <(jq -r 'keys[]' "$NF_JSON_FILE")

# --- Build function ---
build_nf() {
    NF_NAME=$1
    NF_COMMIT=$2
    COMMON_SRC_COMMIT=$3

    # Assign CPU cores
    if (( NUMA1_FIRST_IDX < 8 )); then
        CPU_START=$(( NUMA1_FIRST_HALF_START + NUMA1_FIRST_IDX * CORES_PER_BUILD ))
        CPU_END=$(( CPU_START + CORES_PER_BUILD - 1 ))
        NUMA1_FIRST_IDX=$(( NUMA1_FIRST_IDX + 1 ))
    else
        CPU_START=$(( NUMA1_SECOND_HALF_START + NUMA1_SECOND_IDX * CORES_PER_BUILD ))
        CPU_END=$(( CPU_START + CORES_PER_BUILD - 1 ))
        NUMA1_SECOND_IDX=$(( NUMA1_SECOND_IDX + 1 ))
    fi

    NF_DIR="$CLONE_DIR/oai-cn5g-${NF_NAME}"
    LOG_FILE="$LOG_ARCHIVES/${NF_NAME}.log"

    {
        log "INFO" "Processing NF: $NF_NAME at commit/branch: $NF_COMMIT (CPUs ${CPU_START}-${CPU_END})"
        rm -rf "$NF_DIR"

        # Clone repo
        if ! git clone "${BASE_URL}-${NF_NAME}.git" "$NF_DIR"; then
            log "ERROR" "Clone failed for $NF_NAME"
            echo "$NF_NAME" >> "$FAILED_NFS_FILE"
            exit 1
        fi

        cd "$NF_DIR"

        # Checkout NF commit
        if ! git checkout "$NF_COMMIT"; then
            log "ERROR" "Failed to checkout $NF_COMMIT for $NF_NAME"
            echo "$NF_NAME" >> "$FAILED_NFS_FILE"
            exit 1
        fi

        git submodule update --init --recursive

        # Checkout common-src
        COMMON_SRC_PATH=$(git config --file .gitmodules --get-regexp path | grep common-src | awk '{print $2}')
        if [ -d "$COMMON_SRC_PATH" ]; then
            if [ -n "$COMMON_SRC_COMMIT" ]; then
                git -C "$COMMON_SRC_PATH" checkout "$COMMON_SRC_COMMIT"
            else
                log "ERROR" "common-src checkout failed for $NF_NAME because commit is empty"
                echo "$NF_NAME" >> "$FAILED_NFS_FILE"
                exit 1
            fi
        else
            log "WARNING" "No common-src submodule found for $NF_NAME"
        fi

        NF_SHA=$(git rev-parse --short=8 HEAD)
        COMMON_SRC_SHA=$(git -C "$COMMON_SRC_PATH" rev-parse --short=8 HEAD)
        log "INFO" "NF: $NF_NAME | NF commit: $NF_SHA | common-src commit: $COMMON_SRC_SHA"

        # Submodule status
        git submodule status | while read line; do
            log "INFO" "Submodule: $line"
        done

        # Build Docker image
        IMAGE_TAG="${NF_NAME}-${NF_SHA}-common-src-${COMMON_SRC_SHA}"
        log "INFO" "NF Docker Image: $IMAGE_TAG"
        if ! DOCKER_BUILDKIT=0 docker buildx build \
            --no-cache \
            --target "oai-${NF_NAME}" \
            --tag "oai-${NF_NAME}:${IMAGE_TAG}" \
            --cpuset-cpus="${CPU_START}-${CPU_END}" \
            --build-arg GIT_COMMIT="${NF_SHA}" \
            --file "docker/Dockerfile.${NF_NAME}.ubuntu" .; then
            log "ERROR" "Docker build failed for $NF_NAME"
            echo "$NF_NAME" >> "$FULL_FAILED_NFS_PATH"
            exit 1
        fi

        # Only log metadata if build succeeds
        docker inspect "oai-${NF_NAME}:${IMAGE_TAG}" --format "NF: $NF_NAME
        ID: {{.Id}}
        RepoTags: {{.RepoTags}}
        Created: {{.Created}}
        Labels: {{json .Config.Labels}}
        ------------------------" >> "$FULL_DOCKER_METADATA_PATH"
        cd - &> /dev/null
        log "INFO" "Finished building $NF_NAME (see $LOG_FILE)"
    } > "$LOG_FILE" 2>&1

}

# --- Helper function to wait for a batch of PIDs ---
wait_for_batch() {
    local batch_pids=("$@")
    local batch_failed=0

    for pid in "${batch_pids[@]}"; do
        if ! wait "$pid"; then
            batch_failed=1
        fi
    done

    if [ "$batch_failed" -ne 0 ]; then
        log "ERROR" "One or more NF builds failed in this batch"
        exit 1
    fi
}

# --- Launch NF builds in parallel ---
for nf in "${!NF_MAP[@]}"; do
    build_nf "$nf" "${NF_MAP[$nf]}" "${COMMON_SRC_MAP[$nf]}" &
    BATCH_PIDS+=($!) # store PID for batch tracking
    jobs_running=$(( jobs_running + 1 ))

    if (( jobs_running >= MAX_PARALLEL )); then
       log "INFO" "Batch PIDs: ${BATCH_PIDS[*]}"
        wait_for_batch "${BATCH_PIDS[@]}"
        # Reset for next batch
        BATCH_PIDS=()
        jobs_running=0
    fi
done

# --- Wait for remaining jobs in the final batch ---
if [ "${#BATCH_PIDS[@]}" -ne 0 ]; then
    wait_for_batch "${BATCH_PIDS[@]}"
fi

# --- Check if any NF builds failed ---
if [ -s "$FULL_FAILED_NFS_PATH" ]; then
    log "ERROR" "Some NF Docker builds failed. See $FAILED_NFS_FILE"
    exit 1
fi

log "INFO" "All NFs processed and Docker images built"
log "INFO" "Script finished at $(date)"
