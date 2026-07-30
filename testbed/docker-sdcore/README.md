# SD-Core testbed — SMF v3.0.1 + UPF v2.1.2 (N4/PFCP)

A minimal docker-compose bring-up of the [omec-project](https://github.com/omec-project)
**SMF v3.0.1** and **UPF (upf-epc) v2.1.2**, wired so the **N4/PFCP association
between them actually comes up** — suitable for PFCP / N4 signaling testing.

## Why it isn't literally "just two containers"

omec **SMF v3.0.1 has no static UPF list**. Unlike the free5gc-style SMF, it
learns the slice + UPF dynamically: every 5 s it does

```
GET  http://webconsole:5001/nfconfig/session-management
```

and from the returned slice it builds the UPF node and **initiates** the PFCP
association itself. So to get a live N4 link the minimal set is:

```
mongo ──> webconsole ──(poll)──> smf ──(N4/PFCP 8805/udp)──> upf (pfcpiface)
              ▲                                                   │ (--bess, gRPC)
              └──── ./provision.sh  (device-group + slice)        └──> upf-bess (bessd)
```

| Component      | Image                                   | Role |
|----------------|-----------------------------------------|------|
| `mongo`        | `mongo:7.0`                             | config store (single-node **replica set** — the webconsole requires one) |
| `mongo-init`   | `mongo:7.0`                             | one-shot: initiates the `rs0` replica set, then exits |
| `webconsole`   | `omecproject/5gc-webui:rel-2.1.3`       | config API `:5000` + NFConfig API `:5001` (SMF polls this) |
| `smf`          | `omecproject/5gc-smf:rel-3.0.1`         | session management; initiates N4 |
| `upf`          | `omecproject/upf-epc-pfcpiface:rel-2.1.2` | PFCP/N4 control plane (pfcpiface), passive — answers SMF |
| `upf-bess`     | `omecproject/upf-epc-bess:rel-2.1.2`    | BESS af_packet datapath; `upf` reaches it over the net (`--bess upf-bess:10514`) |

> **Why the UPF is two containers, NOT one shared-netns pod:** `upf` (pfcpiface) runs
> the PFCP code and owns the N4 IP; `upf-bess` (bessd) is the datapath in its **own**
> netns/IP, reached over the network. This keeps `upf.isConnected()` Ready (so the SMF
> association is *accepted*, not "datapath down") while leaving `upf` a single
> restartable container — which iFinder's EA can restart/tail to observe a crash.
> (A shared netns would make the EA watch bessd while pfcpiface is the one that panics.)

> `mongo-init` shows as `Exited (0)` once it has set up the replica set — that
> is expected, not a failure.

> Docker tags use the `rel-X.Y.Z` form, which maps to the git tags `vX.Y.Z` you
> referenced (SMF `v3.0.1` → `rel-3.0.1`, UPF `v2.1.2` → `rel-2.1.2`).
> webconsole **rel-2.1.3** is the latest release still on `openapi v1`, which is
> the schema SMF v3.0.1 expects on `/nfconfig/session-management`.

## Quick start

```bash
cd testbed/docker-sdcore
docker compose up -d          # pulls images, starts all 5 containers
./provision.sh                # push the slice -> SMF learns the UPF
docker compose logs -f smf | grep -i -E 'assoc|pfcp|upf'
```

Within ~10 s of provisioning you should see the SMF send a PFCP Association
Setup Request to `upf` and mark it associated, e.g.:

```
smf  ... sent PFCP Association Request to NodeID[<upf ip>]
smf  ... handle PFCP Association Setup Response
smf  ... upf status updated to AssociatedSetUpSuccess for NodeID[upf]
```

and on the UPF side:

```
upf-pfcpiface ... handized association setup request ... association setup
```

### Inspect what the SMF is fed

```bash
curl -s http://localhost:5001/nfconfig/session-management | jq .
# -> [{"sliceName":"slice1","plmnId":{...},"snssai":{"sst":1,"sd":"010203"},
#      "upf":{"hostname":"upf","port":8805}, ...}]
```

### Watch the N4 packets

```bash
docker exec sdcore-upf tcpdump -ni any udp port 8805 -vv
```

## What is / isn't exercised

- **N4 / PFCP control plane** — fully live (association, heartbeats, and PFCP
  session establishment when you drive PDU sessions). This is the interface to
  test/fuzz — and the omec UPF's PFCP message handlers run regardless of any
  datapath, so malformed N4 messages reach them directly.
- **User plane** — `upf-bess` (bessd) runs the af_packet pipeline on its own veths,
  but with no gNB/UE/DN there is no end-to-end GTP-U traffic. Its real job here is to
  answer `upf`'s gRPC so the association is accepted; the pipeline is best-effort.

## Tweaks

- **Make the UPF initiate instead of the SMF**: set `cpiface.peers` in
  `configs/upf.jsonc` to the SMF IP (then it sends the Association Setup Request
  to the SMF). Default is empty = passive (SMF-initiated, the SD-Core flow).
- **Change PLMN / S-NSSAI / DNN / UE pool**: edit `provision/network-slice.json`
  and `provision/device-group.json`, then re-run `./provision.sh`.
- **Point the SMF elsewhere**: `webuiUri` / `pfcp.addr` / `nrfUri` live in
  `configs/smfcfg.yaml`.

## Troubleshooting

- **`upf` logs `connection refused` to `upf-bess:10514` at startup** — transient.
  bessd (with its hugepages + pipeline) takes ~15-20 s to come up; once its gRPC is
  Ready, `upf.isConnected()` is true and the SMF association is accepted.
- **`upf-bess` restarts / "Cannot allocate memory"** — bessd needs ~1 GiB of 2 MiB
  hugepages; `upf/bess-entrypoint.sh` self-provisions them (drops page cache if the
  host is short). If it can't, run `sudo sysctl -w vm.nr_hugepages=1100` and restart.
- **SMF logs `host [upf] ... lookup failed`** — the UPF container isn't up
  yet; it resolves once `upf` is running (the SMF retries every few s).
- **No association after provisioning** — confirm the slice reached the SMF:
  `curl -s localhost:5001/nfconfig/session-management | jq` should show a non-
  empty array with `upf.hostname = upf`.
- **NRF warnings in SMF logs** — expected. No NRF is deployed; registration
  retries in the background and does not affect N4.

## iFinder integration (Exploitation Agent)

This stack is the EA testbed for iFinder's PFCP scope `scope_sdcore.json`, whose
single target `sdcore` scans both NFs in one pass (`smf/pfcp`, `smf/context`,
`upf/pfcpiface`). Two things make the stack EA-routable:

- services are named `smf` / `upf` → `discover_nf_endpoints` maps them to NF
  "SMF" / "UPF". The container the EA restarts/tails (`upf`) is **pfcpiface** — the
  one that runs the PFCP code and panics. bessd lives in a separate `upf-bess`
  service (name doesn't map to "UPF") in its own netns, so the EA's restart of `upf`
  never disturbs it. (Shared-netns bessd+pfcpiface would make the EA watch bessd
  while pfcpiface crashes → it would never see the panic.)
- each is pinned to a fixed, host-routable IP — **`smf` = 10.100.1.5**,
  **`upf` = 10.100.1.4** (subnet `10.100.1.0/24`) — so the EA's PoC can send
  crafted PFCP straight at `:8805` and a Go panic surfaces in `docker logs`.

One-shot reproduce (DA → VA → EA over one candidate). You do **not** choose the
NF: one DA pass mines SMF+UPF together, each candidate is tagged SMF/UPF, and the
EA auto-routes the winner to its NF via `candidate.network_function`:

```bash
bash scripts/reproduce_one_candidate_sdcore.sh
```

EA fuzzing does **not** need `./provision.sh` — the SMF/UPF parse incoming PFCP
regardless of whether an association exists.

## Teardown

```bash
docker compose down            # keep the mongo volume
docker compose down -v         # also wipe provisioned config
```
