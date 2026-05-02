#!/bin/bash
# Simple verification that /proc infrastructure works

echo "=== /proc socket infrastructure verification ==="
echo ""

echo "1. Finding socket FD entries:"
find /proc/*/fd -lname 'socket:*' 2>/dev/null | head -5 | while read path; do
    inode=$(readlink "$path" | grep -oE '[0-9]+')
    pid=$(echo "$path" | cut -d/ -f3)
    echo "   PID $pid: inode $inode (path: $path)"
done

echo ""
echo "2. Checking /proc/net/udp structure:"
head -2 /proc/net/udp | tail -1 | awk '{
    print "   sl | local_address | rem_address | st | tx_queue | rx_queue | tr | tm->when | retrnsmt | uid | timeout | inode"
    print "   Columns: 1  | 2            | 3           | 4  | 5        | 6        | 7  | 8        | 9        | 10  | 11      | 12"
}'

echo ""
echo "3. Sample /proc/net/udp entry:"
tail -1 /proc/net/udp | awk '{print "   Column 12 (inode): " $12}'

echo ""
echo "4. Test forward mapping (local_address:port → inode):"
# Extract a UDP entry and its inode
UDP_ENTRY=$(tail -1 /proc/net/udp)
UDP_INODE=$(echo "$UDP_ENTRY" | awk '{print $12}')
LOCAL_ADDR=$(echo "$UDP_ENTRY" | awk '{print $2}')
echo "   UDP entry local_address: $LOCAL_ADDR, inode: $UDP_INODE"

echo ""
echo "5. Test reverse mapping (inode → PID):"
echo "   Looking for processes with inode $UDP_INODE..."
FOUND=$(find /proc/*/fd -lname "socket:[$UDP_INODE]" 2>/dev/null | head -1)
if [ -n "$FOUND" ]; then
    FOUND_PID=$(echo "$FOUND" | cut -d/ -f3)
    echo "   ✓ Found! PID $FOUND_PID has socket with inode $UDP_INODE"
    echo "   Path: $FOUND"
else
    echo "   ✗ Inode not found in /proc/*/fd"
    echo "   This is expected if the UDP socket was not accessed by any tracked process"
fi

echo ""
echo "6. Summary:"
SOCKET_COUNT=$(find /proc/*/fd -lname 'socket:*' 2>/dev/null | wc -l)
UDP_COUNT=$(tail -n +2 /proc/net/udp | wc -l)
echo "   Total socket FD entries found: $SOCKET_COUNT"
echo "   Total UDP entries in /proc/net/udp: $UDP_COUNT"

if [ "$SOCKET_COUNT" -gt 0 ] && [ "$UDP_COUNT" -gt 0 ]; then
    echo ""
    echo "✓ /proc infrastructure is functional for UDP correlation"
else
    echo ""
    echo "✗ /proc infrastructure appears incomplete"
    exit 1
fi
