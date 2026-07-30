#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# PID-1 entrypoint for the upf-bess container (privileged) in the SD-Core
# docker-compose testbed. Brings up hugepages + the af_packet datapath
# interfaces, starts bessd, and loads the UP4 pipeline.
set -u
log(){ echo "[upf-bess] $*"; }

###############################################################################
# 1. Hugepages. BESS/DPDK needs them even in af_packet mode. Self-provision so
#    you don't have to touch the host (needs privileged: true). If this fails,
#    set 'sudo sysctl -w vm.nr_hugepages=1024' on the host and restart.
###############################################################################
if ! mountpoint -q /dev/hugepages 2>/dev/null; then
  mkdir -p /dev/hugepages
  if mount -t hugetlbfs none /dev/hugepages 2>/dev/null; then
    log "mounted hugetlbfs at /dev/hugepages"
  else
    log "WARN: could not mount hugetlbfs (continuing)"
  fi
fi
# BESS/DPDK's default packet pool needs ~1 GiB of 2 MiB hugepages. On a busy
# host the kernel often can't allocate them until reclaimable page cache is
# freed, so we request, and if short, drop caches (best-effort) and retry.
want=1100   # ~2.1 GiB requested; bessd uses ~1 GiB, the rest is headroom
ensure_hp(){ echo "$want" > /proc/sys/vm/nr_hugepages 2>/dev/null || true; cat /proc/sys/vm/nr_hugepages 2>/dev/null || echo 0; }
got=$(ensure_hp)
if [ "${got:-0}" -lt 600 ]; then
  log "only ${got} hugepages allocated; freeing page cache and retrying ..."
  sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
  got=$(ensure_hp)
fi
free_hp=$(awk '/HugePages_Free/{print $2}' /proc/meminfo 2>/dev/null || echo 0)
log "hugepages: total=${got}, free=${free_hp} (bessd needs ~512 free 2MB pages)"
if [ "${free_hp:-0}" -lt 512 ]; then
  log "WARN: <512 free hugepages; bessd may fail. Free host RAM or run 'sudo sysctl -w vm.nr_hugepages=1100' on the host."
fi

###############################################################################
# 2. Datapath interfaces. af_packet binds to real, UP interfaces that carry an
#    IPv4 address. We create veth pairs 'access' (N3) and 'core' (N6/N9). There
#    is no real peer behind them - that is the deliberately-simplified data
#    plane; it is enough for the N4/PFCP control plane this testbed targets.
###############################################################################
setup_if(){
  name="$1"; cidr="$2"; peer="${1}-pd"
  if ! ip link show "$name" >/dev/null 2>&1; then
    ip link add "$name" type veth peer name "$peer" || { log "ERROR creating veth $name"; return 1; }
  fi
  ip addr replace "$cidr" dev "$name"
  ip link set "$name" up
  ip link set "$peer" up
}
setup_if access 198.18.0.1/30 || true
setup_if core   198.19.0.1/30 || true
log "datapath interfaces:"
ip -br addr show access core 2>/dev/null || true

###############################################################################
# 3. bessd + pipeline. Start the daemon (gRPC on :10514), wait for it, then load
#    the UP4 af_packet pipeline (reads conf/upf.jsonc). bessd is PID-tracked so
#    this script lives exactly as long as the daemon.
###############################################################################
cd /opt/bess/bessctl || exit 1
log "starting bessd (default 1GB hugepage budget) ..."
bessd -f -grpc-url=0.0.0.0:10514 &
bess_pid=$!

for _ in $(seq 1 30); do
  if bessctl show version >/dev/null 2>&1; then break; fi
  if ! kill -0 "$bess_pid" 2>/dev/null; then
    log "ERROR: bessd exited early (most likely hugepages). See logs above."
    wait "$bess_pid"; exit 1
  fi
  sleep 1
done

log "loading UP4 af_packet pipeline (conf/upf.jsonc) ..."
if bessctl run up4; then
  log "UP4 pipeline loaded"
  # route_control resolves L2 next-hops for the (simplified) data plane. With no
  # real peers it will just log unresolved ARP - harmless for the control plane.
  python3 /opt/bess/bessctl/conf/route_control.py -i access core >/tmp/route_control.log 2>&1 &
  log "route_control started (best-effort, log: /tmp/route_control.log)"
else
  log "WARN: UP4 pipeline load failed; N4/PFCP still works via bessd gRPC (data plane disabled)"
fi

log "UPF ready - pfcpiface serves N4/PFCP on :8805 (shares this netns)"
wait "$bess_pid"
