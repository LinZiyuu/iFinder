# Testbeds

Seven Docker Compose core-network testbeds (5G + 4G). Requires Docker Engine + Docker Compose v2 (`docker compose`).

| Testbed | Directory | Version | Images | Host prerequisite |
|---------|-----------|---------|--------|-------------------|
| Open5GS | `docker-open5gs/` | v2.7.5 | built locally | none |
| free5GC | `free5gc-compose/` | v4.1.0 | pulled from DockerHub | gtp5g kernel module |
| OAI CN5G | `oai-cn5g-fed/` | v2.2.0 | pulled from DockerHub | none |
| OAI EPC (4G) | `openair-epc-fed/` | SPGW v1.2.0 | pulled from DockerHub | none |
| eUPF | `docker-eupf/` | v0.7.1 | `ghcr.io/edgecomllc/eupf:0.7.1` | Linux kernel > 5.14, privileged (eBPF/XDP) |
| SD-Core | `docker-sdcore/` | SMF rel-3.0.1 / UPF rel-2.1.2 | pulled from DockerHub | none (Mongo runs as a single-node replica set) |
| Open5GS LTE (4G) | `docker-open5gs-lte/` | v2.7.5 | `base-open5gs:v2.7.5` (built locally) + `mongo:8.0` | none (privileged UPF for `ogstun`) |

## 1) Open5GS (`docker-open5gs/`)

Images are built locally (the `basic` deployment depends on the `base-open5gs` base image).

```bash
cd docker-open5gs

# (1) Set a host-reachable IP (default in .env is the placeholder 192.0.2.1)
HOST_IP=$(hostname -I | awk '{print $1}')
sed -i "s/^DOCKER_HOST_IP=.*/DOCKER_HOST_IP=${HOST_IP}/" .env

# (2) Build the base image
make base-open5gs

# (3) Start the basic core (first run builds each NF image, takes a few minutes)
docker compose -f compose-files/basic/docker-compose.yaml --env-file=.env up -d --build
```

Verify / stop:
```bash
docker compose -f compose-files/basic/docker-compose.yaml --env-file=.env ps
docker compose -f compose-files/basic/docker-compose.yaml --env-file=.env down
```

## 2) free5GC (`free5gc-compose/`)

The UPF requires the gtp5g kernel module on the host.

```bash
cd free5gc-compose

# (0) Install and load the gtp5g kernel module (required by the UPF)
git clone --branch v0.9.5 --depth 1 https://github.com/free5gc/gtp5g.git /tmp/gtp5g
cd /tmp/gtp5g && make && sudo make install && sudo modprobe gtp5g
lsmod | grep gtp5g          # confirm it is loaded
cd -

# (1) Pull images, then start (default compose includes a UERANSIM gNB)
docker compose pull
docker compose up -d
```

Verify / stop:
```bash
docker compose ps
docker compose down
```

## 3) OAI CN5G (`oai-cn5g-fed/`)

Pulls prebuilt images `oaisoftwarealliance/oai-*:v2.2.0`; the testbed runs entirely from these images.

```bash
cd oai-cn5g-fed/docker-compose    # must run from docker-compose/ (configs are mounted by relative path)

docker compose -f docker-compose-basic-nrf.yaml up -d
docker compose -f docker-compose-basic-nrf.yaml down
```

## 4) OAI EPC — 4G SPGW (`openair-epc-fed/`)

4G EPC core for PFCP/Sx + GTP-C testing. The `spgw-pfcp-gtpc/` deployment is a minimal **SPGW-C + SPGW-U** stack extracted from `inria-oai-mme-legacy/` (MME/HSS/Cassandra/trf-gen removed — not needed to exercise the SPGW PFCP & GTP-C parsers). Images are pulled from DockerHub (`oaisoftwarealliance/oai-spgw*:v1.2.0`).

```bash
cd openair-epc-fed/docker-compose/spgw-pfcp-gtpc

docker compose up -d        # first run pulls the v1.2.0 images
```

Verify / stop:
```bash
docker compose ps                    # SPGW-C and SPGW-U should be (healthy)
docker compose logs -f oai_spgwu     # watch the Sx/PFCP heartbeat with SPGW-C
docker compose down
```

## 5) eUPF (`docker-eupf/`)

A single eUPF NF for PFCP/N4 testing — the EA sends crafted PFCP straight at the UPF, so no SMF / full core is needed. Pulls the published image `ghcr.io/edgecomllc/eupf:0.7.1` (matching the analyzed source `target/eupf_code/eupf` @ v0.7.1; the ghcr tag has **no** leading `v`). Requires a recent kernel (> 5.14) and runs `privileged` for eBPF/XDP. The eUPF is pinned at `10.100.0.10` (PFCP/N4 `8805/udp`, REST API `8080/tcp`, metrics `9090/tcp`).

```bash
cd docker-eupf

docker compose up -d        # first run pulls the 0.7.1 image
```

Verify / stop:
```bash
docker compose ps           # `eupf` should be (healthy)
docker compose logs -f upf  # Go control-plane panics print here
docker compose down -v
```

## 6) SD-Core (`docker-sdcore/`)

omec **SMF v3.0.1 ⟷ N4/PFCP ⟷ UPF (upf-epc pfcpiface) v2.1.2**. The SMF has no static UPF list — it polls the webconsole for the slice and then initiates the N4 association — so the minimal live-N4 set is `mongo + webconsole + smf + upf`. Mongo runs as a single-node replica set (the webconsole requires one). The SMF is pinned at `10.100.1.5` and the UPF at `10.100.1.4`. See `docker-sdcore/README.md` for the full walkthrough.

```bash
cd docker-sdcore

docker compose up -d        # pulls images, starts all 5 containers
./provision.sh              # push the slice -> SMF learns the UPF
docker compose logs -f smf | grep -i -E 'assoc|pfcp|upf'
```

Verify / stop:
```bash
docker compose ps           # mongo-init shows Exited (0); the rest stay up
docker compose down -v
```

> EA fuzzing does **not** need `./provision.sh` — the SMF/UPF parse incoming PFCP regardless of whether an association exists.

## 7) Open5GS LTE (`docker-open5gs-lte/`)

The **4G/LTE EPC** sibling of `docker-open5gs/` — *the same Open5GS v2.7.5 source build*. It is the **GTP-C** (S11/S5/S8, `2123/udp`) testbed for the scope `scope/gtpc/scope_open5gs_275_gtpc.json`. Every 4G daemon already lives in the `base-open5gs:v2.7.5` image, so the NFs (MME / SGW-C / SGW-U / SMF=PGW-C / UPF / HSS / PCRF, + a minimal NRF the converged SMF must register with) run from it with mounted configs — no new image to build. The inter-NF links (S6a / S11 / Sxa / S5 / Sxb / Gx) come up at idle; the GTP-C NFs are pinned (`mme`=10.100.2.10, `sgwc`=10.100.2.11, `smf`=10.100.2.13). See `docker-open5gs-lte/README.md` for the full walkthrough.

```bash
# one-time: build the base image (shared with docker-open5gs/)
(cd docker-open5gs && make base-open5gs)

cd docker-open5gs-lte
docker compose up -d        # starts all 9 containers
# GTP-C (S11/S5) listeners + Diameter/PFCP associations:
docker compose logs mme sgwc smf | grep -E 'gtp_server\(\).*2123'
docker compose logs mme smf      | grep -i 'CONNECTED TO'
```

Verify / stop:
```bash
docker compose ps           # all NFs Up; smf logs "NF registered"
docker compose down -v
```

> EA fuzzing needs no eNB/UE/subscriber — the MME/SGW-C/SMF GTP-C listeners parse incoming GTPv2-C regardless of any session.
