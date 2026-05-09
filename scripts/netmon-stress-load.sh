#!/usr/bin/env bash
#
# netmon-stress-load.sh — drive heavy, heterogeneous traffic through the default
# route so ipc-network-monitor / kernel-spy dashboards (flows, protocols, pps,
# conntrack, etc.) have something to show.
#
# Usage:
#   ./scripts/netmon-stress-load.sh
#   NETMON_STRESS_SECONDS=300 NETMON_TCP_WORKERS=16 ./scripts/netmon-stress-load.sh
#   NETMON_HTTPS_URL=https://internal.example/health  NETMON_TCP_HOSTS="10.0.0.1 10.0.0.2" ./scripts/netmon-stress-load.sh
#   NETMON_CURL_QUIET=0  # show curl errors while debugging
#
# Optional real apps (better for PID/comm + inode correlation in kernel-spy):
#   NETMON_APPS=1 (default) — start git / python3 / iperf3 / aria2c / socat / hey|ab when installed
#   NETMON_APPS=0 — only the lightweight bash/curl/dig workers above
#   NETMON_IPERF_HOSTS="bouygues.iperf.fr ping.online.net"  NETMON_IPERF_PORT=5201
#   NETMON_GIT_URL="https://github.com/octocat/Hello-World.git"
#
# Requirements: bash 4+, curl, coreutils. Optional: dig/bind9-dnsutils, ping,
# ping6, openssl, nc (netcat-openbsd), wget, git, python3, iperf3, aria2c, hey, apache2-utils (ab).
#
# WARNING: Generates real Internet traffic (TCP, TLS, DNS, ICMP). Use only on
# networks you own or are authorized to load-test. Stop with Ctrl+C.

set -uo pipefail

NETMON_STRESS_SECONDS="${NETMON_STRESS_SECONDS:-180}"
NETMON_TCP_WORKERS="${NETMON_TCP_WORKERS:-12}"
NETMON_DNS_WORKERS="${NETMON_DNS_WORKERS:-6}"
NETMON_HTTPS_BURST="${NETMON_HTTPS_BURST:-8}"
# Override if 1.1.1.1 is blocked (corporate firewall, lab without WAN). Example: https://your-proxy/health
NETMON_HTTPS_URL="${NETMON_HTTPS_URL:-https://1.1.1.1/cdn-cgi/trace}"
# Space-separated IPs for TCP opens + curl loop (first host used for burst URL host parsing is awkward — keep 1.1.1.1 in URL only)
NETMON_TCP_HOSTS="${NETMON_TCP_HOSTS:-1.1.1.1 8.8.8.8 9.9.9.9 149.112.112.112 208.67.220.220}"
NETMON_CURL_QUIET="${NETMON_CURL_QUIET:-1}"
NETMON_APPS="${NETMON_APPS:-1}"
NETMON_IPERF_PORT="${NETMON_IPERF_PORT:-5201}"
NETMON_IPERF_HOSTS="${NETMON_IPERF_HOSTS:-bouygues.iperf.fr ping.online.net}"
NETMON_GIT_URL="${NETMON_GIT_URL:-https://github.com/octocat/Hello-World.git}"

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

curl_quiet() {
  if [[ "${NETMON_CURL_QUIET}" == "1" ]]; then
    curl -fsS "$@" 2>/dev/null || true
  else
    curl -fsS "$@" || true
  fi
}

tcp_syn_and_tls_worker() {
  local id="$1"
  local end=$((SECONDS + NETMON_STRESS_SECONDS))
  local -a hosts
  IFS=' ' read -r -a hosts <<< "${NETMON_TCP_HOSTS}"
  while (( SECONDS < end )); do
    for h in "${hosts[@]}"; do
      # Raw TCP open (conntrack + SYN path) — short timeout
      timeout 1.5 bash -c "exec 3<>/dev/tcp/${h}/443" 2>/dev/null || true
      timeout 1.5 bash -c "exec 3<>/dev/tcp/${h}/80" 2>/dev/null || true
      if have curl; then
        curl_quiet --connect-timeout 2 --max-time 4 -o /dev/null "https://${h}/cdn-cgi/trace"
        curl_quiet --connect-timeout 2 --max-time 4 -o /dev/null "http://${h}/"
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
        if [[ "${NETMON_CURL_QUIET}" == "1" ]]; then
          ( curl -fsS --connect-timeout 2 --max-time 5 -o /dev/null "${NETMON_HTTPS_URL}" 2>/dev/null || true ) &
        else
          ( curl -fsS --connect-timeout 2 --max-time 5 -o /dev/null "${NETMON_HTTPS_URL}" || true ) &
        fi
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

# --- Real applications (distinct comm= lines, TLS stacks, bulk TCP) ----------

app_git_loop() {
  have git || return 0
  local end=$((SECONDS + NETMON_STRESS_SECONDS))
  local base
  base="$(mktemp -d /tmp/netmon-git.XXXXXX)"
  (
    while (( SECONDS < end )); do
      rm -rf "${base}/repo" 2>/dev/null || true
      GIT_TERMINAL_PROMPT=0 GIT_SSH_COMMAND="ssh -o BatchMode=yes -o ConnectTimeout=5" \
        git clone --depth 1 "${NETMON_GIT_URL}" "${base}/repo" 2>/dev/null || true
      GIT_TERMINAL_PROMPT=0 git -C "${base}/repo" ls-remote origin HEAD 2>/dev/null || true
      sleep 4
    done
    rm -rf "${base}" 2>/dev/null || true
  ) &
  PIDS+=($!)
}

app_python_loop() {
  have python3 || return 0
  (
    export NETMON_PY_DURATION="${NETMON_STRESS_SECONDS}"
    python3 - <<'PY'
import os, time, urllib.request
deadline = time.time() + float(os.environ["NETMON_PY_DURATION"])
urls = [
    "https://www.example.com/",
    "https://1.1.1.1/cdn-cgi/trace",
    "http://detectportal.firefox.com/success.txt",
    "https://www.cloudflare.com/cdn-cgi/trace",
]
while int(time.time()) < deadline:
    for u in urls:
        try:
            with urllib.request.urlopen(u, timeout=5) as r:
                r.read(8192)
        except Exception:
            pass
    time.sleep(0.35)
PY
  ) &
  PIDS+=($!)
}

app_python_loop_alt() {
  have python3 || return 0
  (
    export NETMON_PY_DURATION="${NETMON_STRESS_SECONDS}"
    python3 - <<'PY'
import os, time, urllib.request
deadline = time.time() + float(os.environ["NETMON_PY_DURATION"])
urls = [
    "https://www.wikipedia.org/wiki/Special:Random",
    "https://example.com/",
]
while int(time.time()) < deadline:
    for u in urls:
        try:
            with urllib.request.urlopen(u, timeout=6) as r:
                r.read(16384)
        except Exception:
            pass
    time.sleep(0.5)
PY
  ) &
  PIDS+=($!)
}

app_iperf3_loop() {
  have iperf3 || return 0
  local -a hosts
  IFS=' ' read -r -a hosts <<< "${NETMON_IPERF_HOSTS}"
  local h
  for h in "${hosts[@]}"; do
    (
      local end=$((SECONDS + NETMON_STRESS_SECONDS))
      while (( SECONDS < end )); do
        iperf3 -c "${h}" -p "${NETMON_IPERF_PORT}" -t 18 -P 3 --connect-timeout 5000 2>/dev/null || true
        sleep 3
      done
    ) &
    PIDS+=($!)
  done
}

app_aria2_loop() {
  have aria2c || return 0
  local end=$((SECONDS + NETMON_STRESS_SECONDS))
  (
    while (( SECONDS < end )); do
      aria2c -d /tmp -o netmon-stress.bin --allow-overwrite=true --auto-file-renaming=false \
        -x 8 -s 8 --max-tries=2 --timeout=5 --connect-timeout=5 \
        "https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf" 2>/dev/null || true
      rm -f /tmp/netmon-stress.bin 2>/dev/null || true
      sleep 6
    done
  ) &
  PIDS+=($!)
}

app_openssl_bulk_loop() {
  have openssl || return 0
  local end=$((SECONDS + NETMON_STRESS_SECONDS))
  (
    while (( SECONDS < end )); do
      for h in 1.1.1.1 8.8.8.8; do
        # Full TLS handshake + read application data (distinct from tiny s_client probes elsewhere)
        timeout 10 bash -c "openssl s_client -connect ${h}:443 -servername www.google.com -brief </dev/null 2>/dev/null | head -c 65536 >/dev/null" || true
      done
      sleep 2
    done
  ) &
  PIDS+=($!)
}

app_http_bench_loop() {
  local end=$((SECONDS + NETMON_STRESS_SECONDS))
  if have hey; then
    (
      while (( SECONDS < end )); do
        hey -n 80 -c 6 -t 4 "${NETMON_HTTPS_URL}" 2>/dev/null || true
        sleep 3
      done
    ) &
    PIDS+=($!)
  elif have ab; then
    (
      while (( SECONDS < end )); do
        # ab is happiest with plain HTTP; keeps load without TLS quirks
        ab -n 200 -c 10 -s 5 "http://example.com/" 2>/dev/null || true
        sleep 3
      done
    ) &
    PIDS+=($!)
  fi
}

start_app_generators() {
  echo "[netmon-stress] starting app suite (git / python3 / iperf3 / …) — set NETMON_APPS=0 to skip"
  app_git_loop
  app_python_loop
  app_python_loop_alt
  app_iperf3_loop
  app_aria2_loop
  app_openssl_bulk_loop
  app_http_bench_loop
}

echo "[netmon-stress] duration=${NETMON_STRESS_SECONDS}s  tcp_workers=${NETMON_TCP_WORKERS}  dns_workers=${NETMON_DNS_WORKERS}"
echo "[netmon-stress] HTTPS URL: ${NETMON_HTTPS_URL}"
echo "[netmon-stress] ensure kernel-spy is bound to the iface that carries this default-route traffic."
echo "[netmon-stress] tip: curl timeouts to 1.1.1.1 usually mean outbound HTTPS is blocked or there is no working default route — try NETMON_HTTPS_URL=https://<reachable-host>/path or reduce NETMON_TCP_WORKERS / NETMON_HTTPS_BURST."

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

if [[ "${NETMON_APPS}" == "1" ]]; then
  start_app_generators
fi

echo "[netmon-stress] all workers running. Ctrl+C to stop."
wait
