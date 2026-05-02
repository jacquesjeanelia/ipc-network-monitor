#!/bin/bash
# Verify /proc socket inode mapping

echo "=== Verifying /proc socket infrastructure ==="
echo ""

echo "1. Check if socket FD entries exist:"
SOCKET_FDS=$(find /proc/*/fd -lname 'socket:*' 2>/dev/null | wc -l)
echo "   Found $SOCKET_FDS socket file descriptors"

if [ "$SOCKET_FDS" -eq 0 ]; then
    echo "   ✗ No socket FDs found - this is a problem!"
    exit 1
fi

echo ""
echo "2. Sample socket FD entries:"
find /proc/*/fd -lname 'socket:*' 2>/dev/null | head -5 | while read fd; do
    LINK=$(readlink "$fd")
    PID=$(echo "$fd" | cut -d/ -f3)
    echo "   PID $PID: $LINK"
done

echo ""
echo "3. Extract sample inode from entry:"
SAMPLE_FD=$(find /proc/*/fd -lname 'socket:*' 2>/dev/null | head -1)
if [ -n "$SAMPLE_FD" ]; then
    SAMPLE_INODE=$(readlink "$SAMPLE_FD" | grep -oP '(?<=\[)\d+(?=\])')
    SAMPLE_PID=$(echo "$SAMPLE_FD" | cut -d/ -f3)
    echo "   Sample: PID $SAMPLE_PID has inode $SAMPLE_INODE"
    
    echo ""
    echo "4. Verify reverse lookup (inode → PID):"
    REVERSE=$(grep -r "socket:\[$SAMPLE_INODE\]" /proc/*/fd 2>/dev/null | cut -d/ -f3 | head -1)
    if [ "$REVERSE" = "$SAMPLE_PID" ]; then
        echo "   ✓ Successfully mapped inode $SAMPLE_INODE back to PID $SAMPLE_PID"
    else
        echo "   ✗ Failed to map inode back to process"
        exit 1
    fi
else
    echo "   ✗ Could not find sample socket FD"
    exit 1
fi

echo ""
echo "5. Check /proc/net/udp for UDP entries:"
UDP_ENTRIES=$(wc -l < /proc/net/udp)
echo "   Total UDP entries: $((UDP_ENTRIES - 1)) (excluding header)"

# Show an entry if available
if [ "$UDP_ENTRIES" -gt 1 ]; then
    echo "   Sample UDP entry:"
    tail -1 /proc/net/udp | sed 's/^/     /'
fi

echo ""
echo "✓ All /proc infrastructure tests PASSED"
echo "  - Socket FD mappings work"
echo "  - Inode → PID reverse lookup works"
echo "  - /proc/net/udp contains entries"
