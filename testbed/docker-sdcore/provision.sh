#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Push the network-slice + device-group into the webconsole so the SMF learns
# about the UPF and starts the N4/PFCP association.
#
# Usage:  ./provision.sh            (defaults to the published webconsole on :5000)
#         WEBUI=http://host:5000 ./provision.sh
set -euo pipefail
cd "$(dirname "$0")"

WEBUI="${WEBUI:-http://localhost:5000}"
DG="internet"
SLICE="slice1"

echo "==> waiting for webconsole config API at ${WEBUI} ..."
for _ in $(seq 1 60); do
  if curl -fsS -o /dev/null "${WEBUI}/config/v1/device-group"; then break; fi
  sleep 2
done

echo "==> POST device-group '${DG}'"
curl -fsS -X POST "${WEBUI}/config/v1/device-group/${DG}" \
  -H 'Content-Type: application/json' \
  --data @provision/device-group.json
echo

echo "==> POST network-slice '${SLICE}'  (UPF = upf-bess:8805)"
curl -fsS -X POST "${WEBUI}/config/v1/network-slice/${SLICE}" \
  -H 'Content-Type: application/json' \
  --data @provision/network-slice.json
echo

echo
echo "==> done. The SMF polls the webconsole every 5s; within ~10s it should"
echo "    build the UPF node and send a PFCP Association Setup Request to upf-bess."
echo
echo "    Verify what the SMF will receive:"
echo "      curl -s ${WEBUI%:*}:5001/nfconfig/session-management | jq ."
echo "    Watch the association come up:"
echo "      docker compose logs -f smf | grep -i -E 'assoc|upf|pfcp'"
