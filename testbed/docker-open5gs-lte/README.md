# Open5GS 4G/LTE EPC testbed — v2.7.5 (GTP-C + PFCP)

A docker-compose bring-up of the **Open5GS 4G EPC** (MME / SGW-C / SGW-U / SMF(=PGW-C) /
UPF(=PGW-U) / HSS / PCRF), wired so the inter-NF links — **S6a, S11, Sxa, S5, Sxb, Gx** —
actually come up at idle. It is the **GTP-C** (S11/S5/S8) and **PFCP** (Sxa/Sxb) attack
surface for iFinder's Exploitation Agent, and the runtime companion to the GTP-C source scope
[`scope/gtpc/scope_open5gs_275_gtpc.json`](../../scope/gtpc/scope_open5gs_275_gtpc.json)
(target `open5gs_275_gtpc`, which scans `lib/gtp` + `src/{sgwc,smf,mme}`).

This is the **4G** sibling of the 5G [`docker-open5gs/`](../docker-open5gs/) — *the same Open5GS
source build*. Every 4G daemon already lives in the `base-open5gs:v2.7.5` image that the 5G
testbed builds, so this stack just runs those daemons (`open5gs-mmed`, `-sgwcd`, …) out of the
image's install prefix with mounted configs — **no new image to build**.

## Architecture

```
                 S6a (Diameter)
        MME ───────────────────────► HSS ──┐
         │                                  │ MongoDB
         │ S11 (GTP-C, 2123/udp)            │
         ▼                                  │
       SGW-C ──Sxa (PFCP, 8805)──► SGW-U    │
         │                                  │
         │ S5 (GTP-C, 2123/udp)             │
         ▼                                  │
    SMF / PGW-C ──Sxb (PFCP, 8805)──► UPF / PGW-U
         │                                  │
         │ Gx (Diameter)                    │
         ▼                                  │
        PCRF ─────────────────────────────►┘  (NRF: SBI registry the SMF must register with)
```

| Component | Image | Pinned IP | Role |
|-----------|-------|-----------|------|
| `mongo` | `mongo:8.0` | 10.100.2.2 | subscriber/policy store for HSS + PCRF |
| `nrf`  | `base-open5gs:v2.7.5` | 10.100.2.7 | SBI registry — required by the converged SMF/PGW-C |
| `hss`  | `base-open5gs:v2.7.5` | 10.100.2.8 | S6a Diameter ⟷ MME |
| `pcrf` | `base-open5gs:v2.7.5` | 10.100.2.9 | Gx Diameter ⟷ SMF/PGW-C |
| `mme`  | `base-open5gs:v2.7.5` | 10.100.2.10 | **MME** — S1AP, S11 GTP-C, S6a |
| `sgwc` | `base-open5gs:v2.7.5` | 10.100.2.11 | **SGW-C** — S11 GTP-C, Sxa PFCP (EA default GTP-C target) |
| `sgwu` | `base-open5gs:v2.7.5` | 10.100.2.12 | SGW-U — Sxa PFCP, GTP-U relay |
| `smf`  | `base-open5gs:v2.7.5` | 10.100.2.13 | **SMF/PGW-C** — S5 GTP-C, Sxb PFCP, Gx |
| `upf`  | `base-open5gs:v2.7.5` | 10.100.2.14 | UPF/PGW-U — Sxb PFCP, GTP-U (`ogstun`) |

> **Why an NRF in a 4G EPC?** Open5GS' SMF is a converged 5G-SMF/4G-PGW-C: it registers over
> SBI at startup and **aborts** (`[No-NRF:No-SCP] … should not be reached`) if it has no NRF,
> even when only the 4G PGW-C path is used. A minimal NRF satisfies that; it is not a
> GTP-C/PFCP target. The other 4G NFs (MME/SGW-C/SGW-U/HSS/PCRF) have no SBI and need no NRF.

## Prerequisite — build the base image (one-time)

The NFs run from `base-open5gs:v2.7.5` (it bundles every open5gs daemon, lib, freeDiameter
extension and TLS cert). Build it via the 5G testbed's Makefile:

```bash
cd ../docker-open5gs && make base-open5gs && cd -
# (verify) docker images | grep base-open5gs   ->  base-open5gs   v2.7.5
```

## Quick start

```bash
cd testbed/docker-open5gs-lte
docker compose up -d                      # starts all 9 containers
```

Within ~15 s the inter-NF links come up. Confirm:

```bash
# GTP-C (S11/S5) listeners bound on MME / SGW-C / SMF
docker compose logs mme sgwc smf | grep -E 'gtp_server\(\).*2123'

# PFCP associations:  Sxa (SGW-C<->SGW-U)  and  Sxb (SMF<->UPF)
docker compose logs sgwc upf | grep -i 'PFCP associat'

# Diameter peers:     S6a (MME<->HSS)  and  Gx (SMF<->PCRF)
docker compose logs mme smf | grep -i "CONNECTED TO"

# SMF registered with the NRF
docker compose logs smf | grep 'NF registered'
```

A healthy idle EPC shows, e.g.:

```
mme   ... gtp_server() [10.100.2.10]:2123
sgwc  ... PFCP associated [10.100.2.12]:8805
upf   ... PFCP associated [10.100.2.13]:8805
mme   ... CONNECTED TO 'hss.localdomain' (SCTP,...)
smf   ... CONNECTED TO 'pcrf.localdomain' (SCTP,...)
smf   ... NF registered [Heartbeat:10s]
```

## What is / isn't exercised

- **GTP-C control plane (S11/S5/S8)** — fully live. The MME/SGW-C/SMF GTP-C listeners bind at
  startup and parse incoming GTPv2-C **regardless of any session**, so malformed Create Session
  / Modify Bearer / etc. reach the parsers directly. This is the interface to test/fuzz.
- **PFCP control plane (Sxa/Sxb)** — live (association + heartbeats); the same handlers the 5G
  N4 surface uses.
- **eNB / UE attach** — **not** run (no S1AP eNB / 4G UE simulator). Not needed: the EA sends
  crafted GTP-C straight at a pinned NF IP and watches that container's `docker logs` for a
  crash (`ogs_assert` / SIGABRT). Provisioning a subscriber is likewise unnecessary for fuzzing.

## iFinder integration (Exploitation Agent)

This stack is the EA testbed for the GTP-C scope `scope_open5gs_275_gtpc.json`. Two things make
it EA-routable (`src/ifinder/testbed.py::discover_nf_endpoints`, protocol `gtpc`):

- services are named so the NF labels resolve — `mme` → **MME**, `sgwc` → **SGW-C** (the EA's
  default GTP-C target), `smf` → **PGW-C**. Each is a single container that runs the GTP-C code,
  owns its S11/S5 IP, and logs its own panics, so the EA restarts/tails the right one.
- each NF is pinned to a fixed, host-routable IP (`mme`=10.100.2.10, `sgwc`=10.100.2.11,
  `smf`=10.100.2.13) so the PoC can send crafted GTPv2-C straight at `:2123`.

One-candidate reproduce (DA → VA → EA over the GTP-C scope; the EA drives a `go-gtp` PoC over
S11 and auto-routes the winner to its NF):

```bash
ifinder run --scope scope/gtpc/scope_open5gs_275_gtpc.json --target open5gs_275_gtpc \
    --patterns PA1 --stage discovery
ifinder run --scope scope/gtpc/scope_open5gs_275_gtpc.json --target open5gs_275_gtpc \
    --patterns PA1 --stage vetting
ifinder run --scope scope/gtpc/scope_open5gs_275_gtpc.json --target open5gs_275_gtpc \
    --patterns PA1 --stage exploitation \
    --compose-file testbed/docker-open5gs-lte/docker-compose.yml
```

## Troubleshooting

- **`smf` logs `Retry registration with NRF`, then `NF registered`** — expected. The SMF starts
  before the NRF is ready and retries until it registers (it no longer aborts, because an NRF
  client *is* configured).
- **`pcrf`/`hss` `Transport endpoint is not connected` during the first ~10 s** — expected
  Diameter (SCTP) reconnect churn while peers come up; it settles into `CONNECTED TO …`.
- **`upf` needs `ogstun`** — the `upf` service runs `privileged` + `NET_ADMIN` to create the TUN
  device (mirrors the 5G UPF). On hosts without `/dev/net/tun` the UPF won't start; the GTP-C
  surface (MME/SGW-C/SMF) is unaffected.
- **Non-amd64 hosts** — the mounted configs hardcode the install lib path
  `/open5gs/install/lib/x86_64-linux-gnu` (`LD_LIBRARY_PATH` in `docker-compose.yml`, and the
  `LoadExtension`/`TLS_Cred` paths in `freeDiameter/*.conf`). On arm64, replace that triplet
  with `aarch64-linux-gnu`.

## Teardown

```bash
docker compose down       # keep the mongo volume
docker compose down -v    # also wipe the mongo volume
```
