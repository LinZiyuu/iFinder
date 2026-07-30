#!/usr/bin/env bash
# Register the test subscriber (IMSI 001010000000001) into the open5gs Mongo DB so a UERANSIM UE
# can authenticate and establish a PDU session (which makes the SMF hold a session — required to
# reach SMF-side N4 handlers like ogs_pfcp_parse_volume_measurement).
#
# Self-contained: runs mongosh from the mongo image against the open5gs-db container on the
# "open5gs" bridge. Idempotent (skips if the IMSI already exists).
#
# Usage:  ./register-subscriber.sh          (run once, after the core network is up)
set -euo pipefail

IMSI="${IMSI:-001010000000001}"
K="${K:-465B5CE8B199B49FAA5F0A2EE238A6BC}"
OPC="${OPC:-E8ED289DEBA952E4283B54E88E6183CA}"
MONGO_IMAGE="${MONGO_IMAGE:-mongo:8.0}"     # matches MONGODB_VERSION in .env
DB_HOST="${DB_HOST:-10.33.33.2}"            # open5gs-db on the open5gs bridge
NETWORK="${NETWORK:-open5gs}"

echo "[*] Registering subscriber ${IMSI} into mongodb://${DB_HOST}:27017/open5gs ..."

docker run --rm --network "${NETWORK}" "${MONGO_IMAGE}" \
  mongosh "mongodb://${DB_HOST}:27017/open5gs" --quiet --eval '
    const imsi = "'"${IMSI}"'";
    const k    = "'"${K}"'";
    const opc  = "'"${OPC}"'";
    if (db.subscribers.findOne({ imsi: imsi })) {
        print("[*] subscriber " + imsi + " already exists; nothing to do");
        quit(0);
    }
    db.subscribers.insertOne({
        schema_version: 1,
        imsi: imsi,
        msisdn: [], imeisv: [], mme_host: [], mme_realm: [], purge_flag: [],
        security: { k: k, op: null, opc: opc, amf: "8000" },
        ambr: { downlink: { value: 1, unit: 3 }, uplink: { value: 1, unit: 3 } },
        slice: [{
            sst: 1, sd: "000001", default_indicator: true,
            session: [{
                name: "internet", type: 3,
                qos: { index: 9, arp: { priority_level: 8,
                       pre_emption_capability: 1, pre_emption_vulnerability: 1 } },
                ambr: { downlink: { value: 1, unit: 3 }, uplink: { value: 1, unit: 3 } },
                pcc_rule: []
            }]
        }],
        access_restriction_data: 32,
        subscriber_status: 0,
        operator_determined_barring: 0,
        network_access_mode: 0,
        subscribed_rau_tau_timer: 12,
        __v: 0
    });
    print("[+] inserted subscriber " + imsi);
  '

echo "[+] done. Verify with: docker logs open5gs-ue | grep -i \"PDU Session\""
