#!/bin/bash
# Analyze /proc/net/udp column structure

echo "=== Analyzing /proc/net/udp column structure ==="
echo ""

echo "Header with whitespace-split (using tr):"
head -1 /proc/net/udp | tr ' ' '\n' | grep -v '^$' | nl -v 0 -s ': '

echo ""
echo "Sample data with whitespace-split:"
tail -1 /proc/net/udp | tr ' ' '\n' | grep -v '^$' | nl -v 0 -s ': '

echo ""
echo "Sample data line (raw):"
tail -1 /proc/net/udp

echo ""
echo "Extracting inode from sample (using awk column 12):"
tail -1 /proc/net/udp | awk '{print "Column 12 (awk): " $12}'

echo ""
echo "Extracting inode from sample (using awk column 11):"
tail -1 /proc/net/udp | awk '{print "Column 11 (awk): " $11}'

echo ""
echo "Using the proc_corr parsing logic (split_whitespace simulation):"
tail -1 /proc/net/udp | awk '
{
    for (i = 1; i <= NF; i++) {
        parts[i-1] = $i
    }
    printf("parts[9] = %s (uid according to header)\n", parts[9])
    printf("parts[11] = %s (likely inode)\n", parts[11])
    printf("parts[10] = %s (likely timeout)\n", parts[10])
}
'

echo ""
echo "Finding the inode column by matching known pattern (the big hex number):"
LINE=$(tail -1 /proc/net/udp)
for i in $(seq 1 20); do
    VAL=$(echo "$LINE" | awk "{print \$$i}")
    # Inode is typically a decimal number that's been created recently
    if [[ "$VAL" =~ ^[0-9]+$ ]] && [ "$VAL" -gt 1000 ] && [ "$VAL" -lt 999999 ]; then
        echo "Field $i (awk) / index $((i-1)) (Rust parts[]) = $VAL (likely inode)"
    fi
done
