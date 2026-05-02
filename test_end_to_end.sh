#!/bin/bash
# Test end-to-end UDP correlation with the actual daemon

set -e

cd ~/ipc-network-monitor

echo "=== Starting kernel-spy daemon ==="
# Start daemon in background, capture output
timeout 30 cargo run --release -p kernel-spy -- \
    --iface lo \
    --xdp-mode skb \
    --max-flow-rows 50 \
    --export-socket /tmp/test-netmon.sock 2>&1 &
DAEMON_PID=$!

sleep 2  # Let daemon start

echo ""
echo "=== Generating UDP traffic ==="
# Send DNS query (UDP 53)
echo "test" | nc -u -w1 127.0.0.1 53 > /dev/null 2>&1 &
sleep 0.5

# Send to arbitrary port
echo "hello" | nc -u -w1 127.0.0.1 12345 > /dev/null 2>&1 &
sleep 0.5

echo ""
echo "=== Checking export socket for results ==="
if [ -S /tmp/test-netmon.sock ]; then
    echo "✓ Export socket exists"
    
    # Try to read from the export socket (will get the latest snapshot)
    timeout 2 nc -U /tmp/test-netmon.sock < /dev/null 2>/dev/null | \
        python3 -m json.tool 2>/dev/null | grep -A 5 -B 5 '"protocol": "UDP"' || echo "No UDP flows in export yet"
else
    echo "✗ Export socket not found"
fi

echo ""
echo "=== Daemon output ==="
wait $DAEMON_PID 2>/dev/null || true

rm -f /tmp/test-netmon.sock 2>/dev/null || true
