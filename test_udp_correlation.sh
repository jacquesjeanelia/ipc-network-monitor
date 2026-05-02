#!/bin/bash
# Comprehensive end-to-end UDP correlation test

set -e

echo "=== UDP Correlation End-to-End Test ==="
echo ""

# Start a simple UDP listener that will appear in /proc/net/udp with non-zero inode
LISTENER_SCRIPT=$(mktemp)
cat > "$LISTENER_SCRIPT" << 'EOF'
import socket
import threading

def listen():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', 9999))
    print("Listener PID:", os.getpid(), flush=True)
    # Keep listening
    sock.recvfrom(1024)
    sock.close()

import os
listen()
EOF

# Start listener in background
python3 "$LISTENER_SCRIPT" > /tmp/listener_pid.txt 2>&1 &
LISTENER_PID=$!
sleep 0.5

# Get the actual listener PID
LISTENER_ACTUAL_PID=$(cat /tmp/listener_pid.txt | grep 'Listener PID' | awk '{print $NF}')
echo "Started listener on PID: $LISTENER_ACTUAL_PID"

# Send data to the listener
echo ""
echo "=== Sending UDP packets ==="
echo "test" | nc -u -w1 127.0.0.1 9999 > /dev/null 2>&1 &
NC_PID=$!
sleep 0.5

# Now check what's in /proc/net/udp
echo ""
echo "=== Checking /proc/net/udp for port 9999 ==="
PORT_HEX=$(printf '%04x' 9999)
echo "Port 9999 in hex: $PORT_HEX"

cat /proc/net/udp | grep ":$PORT_HEX " | while read line; do
    echo "Found: $line"
    INODE=$(echo "$line" | awk '{print $10}')
    echo "  Inode: $INODE"
    
    if [ "$INODE" != "0" ]; then
        echo "  ✓ Non-zero inode, can correlate"
        
        # Check if this inode maps to the listener PID
        FD_ENTRY=$(find /proc/*/fd -lname "socket:[$INODE]" 2>/dev/null | head -1)
        if [ -n "$FD_ENTRY" ]; then
            CORRELATED_PID=$(echo "$FD_ENTRY" | cut -d/ -f3)
            echo "  ✓ Found in /proc/*/fd: PID $CORRELATED_PID"
            if [ "$CORRELATED_PID" = "$LISTENER_ACTUAL_PID" ]; then
                echo "  ✓✓ MATCH! Correlated to correct PID!"
            else
                echo "  ⚠ PID mismatch: expected $LISTENER_ACTUAL_PID, got $CORRELATED_PID"
            fi
        else
            echo "  ✗ Inode not found in /proc/*/fd"
        fi
    else
        echo "  ✗ Inode is 0 (kernel socket, cannot correlate)"
    fi
done

echo ""
echo "=== Summary ==="
echo "If all checks pass, UDP correlation via /proc should work!"

# Cleanup
kill $LISTENER_PID 2>/dev/null || true
kill $NC_PID 2>/dev/null || true
rm -f "$LISTENER_SCRIPT" /tmp/listener_pid.txt
