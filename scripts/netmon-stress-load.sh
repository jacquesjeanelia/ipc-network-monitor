#!/usr/bin/env bash
#
# netmon-stress-load.sh — drive heavy, heterogeneous traffic through the default
# route so ipc-network-monitor / kernel-spy dashboards (flows, protocols, pps,
# conntrack, etc.) have something to show.
#
# Usage:
#   ./scripts/netmon-stress-load.sh
#   NETMON_STRESS_SECONDS=300 NETMON_TCP_WORKERS=16 ./scripts/netmon-stress-load.sh
#
# Requirements: bash 4+, curl, coreutils. Optional: dig/bind9-dnsutils, ping,
# ping6, openssl, nc (netcat-openbsd), wget.
#
# WARNING: Generates real Internet traffic (TCP, TLS, DNS, ICMP). Use only on
# networks you own or are authorized to load-test. Stop with Ctrl+C.

set -uo pipefail

NETMON_STRESS_SECONDS="${NETMON_STRESS_SECONDS:-180}"
NETMON_TCP_WORKERS="${NETMON_TCP_WORKERS:-12}"
NETMON_DNS_WORKERS="${NETMON_DNS_WORKERS:-6}"
NETMON_HTTPS_BURST="${NETMON_HTTPS_BURST:-8}"

PIDS=()
cleanup() {
  echo ""
  echo "[netmon-stress] stopping workers…"
  for p in "${PIDS[@]+"${PIDS[@]}"}"; do
    kill "$p" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

have() { command -v "$1" >/dev/null 2>&1; }

tcp_syn_and_tls_worker() {
  local id="$1"
  local end=$((SECONDS + NETMON_STRESS_SECONDS))
  local hosts=(1.1.1.1 8.8.8.8 9.9.9.9 149.112.112.112 208.67.220.220)
  while (( SECONDS < end )); do
    for h in "${hosts[@]}"; do
      # Raw TCP open (conntrack + SYN path) — short timeout
      timeout 1.5 bash -c "exec 3<>/dev/tcp/${h}/443" 2>/dev/null || true
      timeout 1.5 bash -c "exec 3<>/dev/tcp/${h}/80" 2>/dev/null || true
      if have curl; then
        curl -fsS --connect-timeout 2 --max-time 4 -o /dev/null \
          "https://${h}/cdn-cgi/trace" 2>/dev/null || true
        curl -fsS --connect-timeout 2 --max-time 4 -o /dev/null \
          "http://${h}/" 2>/dev/null || true
      fi
      if have openssl; then
        echo | timeout 2 openssl s_client -connect "${h}:443" -servername "example.com" >/dev/null 2>&1 || true
      fi
    done
    sleep "0.0$(( id % 5 + 1 ))"
  done
}

dns_udp_worker() {
  local end=$((SECONDS + NETMON_STRESS_SECONDS))
  local resolvers=(1.1.1.1 8.8.8.8 9.9.9.9)
  local names=(cloudflare.com google.com amazon.com microsoft.com openbsd.org kernel.org)
  if ! have dig; then
    while (( SECONDS < end )); do sleep 2; done
    return 0
  fi
  while (( SECONDS < end )); do
    for r in "${resolvers[@]}"; do
      for n in "${names[@]}"; do
        dig +time=1 +tries=1 "@${r}" "${n}" A +short >/dev/null 2>&1 || true
        dig +time=1 +tries=1 "@${r}" "${n}" AAAA +short >/dev/null 2>&1 || true
      done
    done
    sleep 0.15
  done
}

https_parallel_burst() {
  local end=$((SECONDS + NETMON_STRESS_SECONDS))
  while (( SECONDS < end )); do
    for _ in $(seq 1 "${NETMON_HTTPS_BURST}"); do
      if have curl; then
        ( curl -fsS --connect-timeout 2 --max-time 5 -o /dev/null "https://1.1.1.1/cdn-cgi/trace" || true ) &
        PIDS+=($!)
      fi
    done
    wait || true
    sleep 0.4
  done
}

icmp_worker() {
  local end=$((SECONDS + NETMON_STRESS_SECONDS))
  while (( SECONDS < end )); do
    if have ping; then
      ping -n -c 8 -i 0.2 1.1.1.1 >/dev/null 2>&1 || true
    fi
    if have ping6; then
      ping6 -n -c 4 -i 0.3 2606:4700:4700::1111 >/dev/null 2>&1 || true
    fi
    sleep 0.5
  done
}

udp_fireforget_worker() {
  local end=$((SECONDS + NETMON_STRESS_SECONDS))
  while (( SECONDS < end )); do
    if have nc; then
      for p in 53 123 443; do
        echo "x" | nc -u -w1 1.1.1.1 "${p}" 2>/dev/null || true
      done
    fi
    sleep 0.3
  done
}

wget_worker() {
  local end=$((SECONDS + NETMON_STRESS_SECONDS))
  if ! have wget; then
    while (( SECONDS < end )); do sleep 3; done
    return 0
  fi
  while (( SECONDS < end )); do
    wget -q -T 3 -O /dev/null "https://www.example.com/" 2>/dev/null || true
    sleep 1
  done
}

echo "[netmon-stress] duration=${NETMON_STRESS_SECONDS}s  tcp_workers=${NETMON_TCP_WORKERS}  dns_workers=${NETMON_DNS_WORKERS}"
echo "[netmon-stress] ensure kernel-spy is bound to the iface that carries this default-route traffic."

for i in $(seq 1 "${NETMON_TCP_WORKERS}"); do
  tcp_syn_and_tls_worker "$i" &
  PIDS+=($!)
done

for _ in $(seq 1 "${NETMON_DNS_WORKERS}"); do
  dns_udp_worker &
  PIDS+=($!)
done

https_parallel_burst &
PIDS+=($!)

icmp_worker &
PIDS+=($!)

udp_fireforget_worker &
PIDS+=($!)

wget_worker &
PIDS+=($!)

echo "[netmon-stress] all workers running. Ctrl+C to stop."
wait
