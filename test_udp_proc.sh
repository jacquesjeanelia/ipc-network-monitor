#!/bin/bash
# Test UDP /proc correlation infrastructure

set -e

echo "=== Testing UDP /proc correlation infrastructure ==="
echo ""

# Start UDP listener on port 8888
timeout 60 socat UDP-LISTEN:8888,reuseaddr - > /dev/null 2>&1 &
LISTENER_PID=$!
sleep 0.3

# Send a UDP packet
echo "test" | nc -u -w1 127.0.0.1 8888 > /dev/null 2>&1 &
sleep 0.3

# Check if port 8888 appears in /proc/net/udp
echo "1. Checking if UDP port 8888 appears in /proc/net/udp:"
if grep -q '8888' /proc/net/udp; then
    echo "   ✓ Port 8888 found in /proc/net/udp"
    echo "   Entries:"
    cat /proc/net/udp | grep '8888' | head -3 | sed 's/^/     /'
else
    echo "   ✗ Port 8888 NOT found in /proc/net/udp"
    exit 1
fi

echo ""
echo "2. Extracting socket inode from /proc/net/udp:"
# Extract inode from /proc/net/udp entry (second-to-last column)
INODE=$(cat /proc/net/udp | grep '8888' | head -1 | awk '{print $(NF-1)}')
echo "   Found inode: $INODE"

if [ -z "$INODE" ] || [ "$INODE" = "0" ]; then
    echo "   ✗ Failed to extract valid inode"
    exit 1
fi

echo ""
echo "3. Verifying inode maps to PID via /proc/*/fd:"
# Check if this inode exists in any /proc/*/fd symlinks
FOUND_PID=$(grep -r "socket:\[$INODE\]" /proc/*/fd 2>/dev/null | head -1 | cut -d/ -f3 || echo "")

if [ -n "$FOUND_PID" ]; then
    echo "   ✓ Inode $INODE found in PID $FOUND_PID"
    echo "   Link details:"
    grep -r "socket:\[$INODE\]" /proc/*/fd 2>/dev/null | head -1 | sed 's/^/     /'
else
    echo "   ✗ Inode $INODE NOT found in any /proc/*/fd"
    echo "   This suggests /proc-based correlation won't work for this flow"
    exit 1
fi

echo ""
echo "4. Checking /proc/net/udp format:"
echo "   Header line:"
head -1 /proc/net/udp | sed 's/^/     /'
echo ""
echo "   Sample data line:"
cat /proc/net/udp | grep '8888' | head -1 | sed 's/^/     /'

echo ""
echo "✓ All /proc-based UDP correlation tests PASSED"
echo "  /proc-based correlation should work for UDP flows"

wait
