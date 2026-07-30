## Install

```bash
pip install -e .
```

## Run

`ifinder run` takes a **scope** (which target + which code dirs to scan), one or more
**patterns** (`PA1,PA2,PB1,PB2,PB3,PC1`), and an optional **stage**. Omit `--stage` to run
the full DA → VA → EA pipeline; pass `--stage {discovery,vetting,exploitation}` to run a
single stage (downstream stages load the upstream artifact from disk).

Scopes carry a `protocol` field and live under `../scope/<protocol>/`:
- **PFCP** (`scope/pfcp/`): `scope_open5gs_{272,275,2414}.json`, `scope_free5gc_{202,330,410}.json`, `scope_oai_220.json`, `scope_eupf.json`, `scope_sdcore.json` (5G cores).
- **GTP-C** (`scope/gtpc/`): `scope_oai_epc_gtpc.json` (OAI 4G EPC), `scope_open5gs_275_gtpc.json` (Open5GS LTE).

(A bare scope name is also resolved automatically anywhere under `../scope/`.)

### DA + VA only — static analysis, no Docker

Identical for every core; just swap the scope. This path needs no host setup or testbed:

```bash
ifinder run --scope ../scope/pfcp/scope_open5gs_275.json \
    --patterns PA1,PA2,PB1,PB2,PB3,PC1 --no-exploit
```

Single stage (e.g. DA, then VA off the saved DA artifact):

```bash
ifinder run --scope ../scope/pfcp/scope_open5gs_275.json --patterns PA1 \
    --target open5gs_275 --stage discovery
ifinder run --scope ../scope/pfcp/scope_open5gs_275.json --patterns PA1 \
    --target open5gs_275 --stage vetting
```

### Full pipeline incl. EA (DA → VA → EA)

The EA stage needs a **running Docker testbed** and you must pass `--compose-file`
explicitly — there is **no testbed auto-discovery, so without `--compose-file` the EA stage
is silently skipped**. The compose file (and whether an env-file is needed) differs per core.
See `../testbed/README.md` for the host prerequisites of each testbed.

Omit `--stage` (as below) to run DA → VA → EA in one go, or add `--stage exploitation` to run
only EA off a saved VA artifact. `--patterns` takes a comma-separated list.

**open5gs** — testbed v2.7.5 (matches `scope_open5gs_275`). Images are built locally; first
set `DOCKER_HOST_IP` in the env-file and run `make base-open5gs` (see testbed README). This
is the **only** core that takes `--env-file`:

```bash
ifinder run --scope ../scope/pfcp/scope_open5gs_275.json --patterns PA1 --target open5gs_275 \
    --compose-file ../testbed/docker-open5gs/compose-files/basic/docker-compose.yaml \
    --env-file    ../testbed/docker-open5gs/.env
```

**free5gc** — testbed v4.1.0. Requires the **gtp5g kernel module loaded on the host** (the
UPF will not start without it) and a `docker compose pull` first. No `--env-file`:

```bash
ifinder run --scope ../scope/pfcp/scope_free5gc_410.json --patterns PA1 --target free5gc_410 \
    --compose-file ../testbed/free5gc-compose/docker-compose.yaml
```

**OAI CN5G** — testbed v2.2.0 (matches the OAI source). Images are pulled from DockerHub. No
`--env-file` (the compose pins static IPs for `oai-smf`/`oai-upf` so the EA can reach them on
N4):

```bash
ifinder run --scope ../scope/pfcp/scope_oai_220.json --patterns PA1 --target oai_220 \
    --compose-file ../testbed/oai-cn5g-fed/docker-compose/docker-compose-basic-nrf.yaml
```

**OAI EPC (4G, GTP-C)** — analyzed source `spgwc@2021.w29 / spgwu@2021.w40`, testbed runtime images
`v1.2.0` (minor skew, documented in the compose file) (`scope/gtpc/scope_oai_epc_gtpc.json` → the OAI
EPC GTPv2-C control plane on S11/S5). The `spgw-pfcp-gtpc/` testbed pulls its images from DockerHub with static IPs pinned,
no `--env-file`, so the EA can reach the EPC on S11. The PoC drives `go-gtp` over S11 (UDP 2123):

```bash
ifinder run --scope ../scope/gtpc/scope_oai_epc_gtpc.json --patterns PA1 --target oai_epc_gtpc \
    --compose-file ../testbed/openair-epc-fed/docker-compose/spgw-pfcp-gtpc/docker-compose.yml
```


Full CLI reference: `ifinder run --help`.
