#!/bin/bash
# Simpler UDP binding test

echo "=== Testing UDP socket visibility in /proc/net/udp ==="
echo ""

# Create a simple background process that binds to UDP port and waits
# Using bash instead of python for simplicity
echo "Starting UDP listener on port 9999..."
{
    exec 3<>/dev/udp/127.0.0.1/9999 || true
    sleep 10
} &
PID=$!

sleep 0.5

echo "Listener PID: $PID"
echo ""
echo "Checking if listener appears in /proc/net/udp:"
cat /proc/net/udp | head -2
echo "..."
cat /proc/net/udp | tail -3

echo ""
echo "Searching for port 9999 (hex 270f):"
grep 270f /proc/net/udp || echo "Port 9999 NOT found in /proc/net/udp"

# Kill listener
kill $PID 2>/dev/null || true
wait $PID 2>/dev/null || true

echo ""
echo "After killing listener:"
echo "Searching for port 9999 (hex 270f):"
grep 270f /proc/net/udp || echo "Port 9999 NOT found (expected)"
