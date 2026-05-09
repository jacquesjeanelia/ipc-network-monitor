#!/bin/bash

# Best-effort: expose nf_conntrack sysctls so monitors can read conntrack count/max (optional).
if [[ ! -r /proc/sys/net/netfilter/nf_conntrack_max ]]; then
  if [[ "${EUID:-0}" -eq 0 ]]; then
    modprobe nf_conntrack 2>/dev/null || true
  elif command -v sudo >/dev/null 2>&1; then
    sudo modprobe nf_conntrack 2>/dev/null || true
  fi
fi

echo "Starting long-lived multi-protocol traffic..."

# ICMP
ping 8.8.8.8 > /dev/null 2>&1 &
echo "Ping started"

# DNS
while true; do dig google.com > /dev/null 2>&1; sleep 1; done &
echo "DNS started"

# HTTP
while true; do curl -s http://example.com > /dev/null; done &
echo "HTTP started"

# HTTPS
while true; do curl -s https://example.com > /dev/null; done &
echo "HTTPS started"

# TCP
while true; do
    echo -e "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" | nc example.com 80 > /dev/null 2>&1
done &
echo "TCP started"

# UDP
while true; do echo "hello" | nc -u 8.8.8.8 53; sleep 1; done &
echo "UDP started"

echo "All traffic generators started. Press CTRL+C to stop."

while true; do sleep 60; done
