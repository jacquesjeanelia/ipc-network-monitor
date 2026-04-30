# Capability Requirements & Scoping

**Reference:** NFR-S4 (Capability scoping), SC-A3 (Linux kernel 5.15 LTS minimum)

---

## Overview

Instead of running kernel-spy as root, use **Linux kernel capabilities** to grant only the minimum privileges required. This reduces attack surface and enables better auditing.

---

## Required Capabilities

| Capability         | Purpose                                                        | Required   | Kernel |
| ------------------ | -------------------------------------------------------------- | ---------- | ------ |
| `CAP_NET_ADMIN`    | Load XDP/TC programs, manage nftables, attach tracepoints      | ✓ Yes      | 5.8+   |
| `CAP_BPF`          | eBPF operations (replaced `CAP_SYS_ADMIN` for BPF in 5.8+)     | ✓ Yes      | 5.8+   |
| `CAP_PERFMON`      | Tracepoint attachment, performance monitoring (new in 5.8+)    | ✓ Yes      | 5.8+   |
| `CAP_SYS_RESOURCE` | Override resource limits, pin eBPF maps                        | ~ Optional | 5.8+   |
| `CAP_NET_RAW`      | Raw socket operations (used by tracepoints)                    | ~ Optional | 5.8+   |
| `CAP_DAC_OVERRIDE` | Override file permissions (for audit log if in restricted dir) | ~ Optional | 5.8+   |

**Legend:**

- ✓ = required for core monitoring
- ~ = optional, may be needed in restricted environments

---

## Kernel Version Constraints

### Minimum: Linux 5.15 LTS

**Why 5.15?**

- Oldest LTS kernel with mature eBPF support
- `CAP_BPF` and `CAP_PERFMON` available (split from `CAP_SYS_ADMIN` in 5.8)
- eBPF subprogram support stable
- BPF-to-BPF calls working correctly

### Not Recommended: Older Kernels

- **< 5.8:** No `CAP_BPF`/`CAP_PERFMON`; must use `CAP_SYS_ADMIN` (coarse-grained)
- **< 4.15:** No unprivileged eBPF; requires full root or custom LSM rules
- **< 4.9:** XDP not available; cannot use XDP programs at all

### Testing: Windows Subsystem for Linux (WSL)

- **WSL1:** eBPF not supported (Linux kernel not involved)
- **WSL2:** eBPF available but **limited kernel version** (currently ~5.10, may vary)
  - XDP in SKB mode works
  - XDP in driver mode may not work
  - Some tracepoints unavailable
  - **Recommendation:** Use native Linux for full feature support; WSL2 for testing only

---

## How to Grant Capabilities

### Option 1: Runtime Capability Grant (Recommended for Development)

Use `setcap` to grant capabilities to the binary:

```bash
# Build the binary
cargo build --release -p kernel-spy

# Grant capabilities (setcap can only be run as root)
sudo setcap cap_net_admin,cap_bpf,cap_perfmon,cap_sys_resource,cap_net_raw=ep \
  ./target/release/kernel-spy

# Verify
getcap ./target/release/kernel-spy
# Output: ./target/release/kernel-spy = cap_net_admin,cap_bpf,cap_perfmon,cap_sys_resource,cap_net_raw=ep

# Now run as unprivileged user (no sudo needed)
./target/release/kernel-spy -i eth0
```

**Advantages:**

- Binary runs as unprivileged user (UID != 0)
- Capabilities checked by kernel, not UID
- Behavior is auditable (can trace capability checks)
- If binary is replaced, capabilities are not inherited (security boundary)

**Limitations:**

- `setcap` is a privileged operation (requires sudo)
- Capabilities are tied to the binary inode; if binary is moved, capabilities may be lost

### Option 2: Capability Inheritance via Systemd Service (Production)

Create a systemd service that drops all privilege except required capabilities:

**File: `/etc/systemd/system/ipc-netmon.service`**

```ini
[Unit]
Description=IPC Network Monitor & Controller
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=netmon
Group=netmon

# Drop all privileges
CapabilityBoundingSet=CAP_NET_ADMIN CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE CAP_NET_RAW

# Deny privilege escalation
NoNewPrivileges=true

# Restrict filesystem access
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes

# Allow writing to state directory
ReadWritePaths=/tmp/ipc-netmon-state /run/ipc-netmon

ExecStart=/usr/local/bin/kernel-spy -i eth0

StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

**Usage:**

```bash
# Enable and start service
sudo systemctl enable ipc-netmon.service
sudo systemctl start ipc-netmon.service

# Check status
sudo systemctl status ipc-netmon.service
```

### Option 3: Docker Container (Development)

If running in Docker:

```dockerfile
FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
  build-essential rustup clang bpf-linker \
  nftables iproute2

# Create unprivileged user
RUN useradd -m netmon

# Copy binary (pre-built or built in container)
COPY ./kernel-spy /usr/local/bin/kernel-spy

# Grant capabilities (inside container, as root)
RUN setcap cap_net_admin,cap_bpf,cap_perfmon,cap_sys_resource,cap_net_raw=ep \
  /usr/local/bin/kernel-spy

# Switch to unprivileged user
USER netmon

# Run
ENTRYPOINT ["/usr/local/bin/kernel-spy"]
CMD ["-i", "eth0"]
```

**Run Container:**

```bash
docker run --cap-drop=ALL \
  --cap-add=NET_ADMIN \
  --cap-add=BPF \
  --cap-add=PERFMON \
  --cap-add=SYS_RESOURCE \
  --cap-add=NET_RAW \
  --network host \
  ipc-netmon:latest
```

---

## Capability Reference

### CAP_NET_ADMIN

**What it allows:**

- Load XDP programs (`bpf(BPF_PROG_LOAD, ...)`)
- Attach XDP to interfaces (`bpf(BPF_LINK_CREATE, ...)`)
- Attach TC/netfilter programs
- Modify nftables rules (`nft` tool)
- Change interface MTU/state
- Add tc qdisc and class

**Used in kernel-spy for:**

- XDP attachment: [kernel-spy/src/main.rs](../kernel-spy/kernel-spy/src/main.rs) lines ~280+
- TC attachment: [kernel-spy/src/main.rs](../kernel-spy/kernel-spy/src/main.rs) lines ~300+
- nftables: [kernel-spy/src/nft.rs](../kernel-spy/kernel-spy/src/nft.rs)
- tc control: [kernel-spy/src/tc_control.rs](../kernel-spy/kernel-spy/src/tc_control.rs)

---

### CAP_BPF

**What it allows (kernel 5.8+):**

- Load eBPF programs (`bpf(BPF_PROG_LOAD, ...)`)
- Create BPF maps (`bpf(BPF_MAP_CREATE, ...)`)
- Attach to events (previously required `CAP_SYS_ADMIN`)

**Pre-5.8 workaround:**
If kernel < 5.8, use `CAP_SYS_ADMIN` instead:

```bash
setcap cap_sys_admin,cap_net_admin=ep kernel-spy
```

**Used in kernel-spy for:**

- eBPF program compilation and loading
- BPF map creation and pinning

---

### CAP_PERFMON

**What it allows (kernel 5.8+):**

- Attach to tracepoints (`perf_event_open(...)`)
- Read kernel event streams
- Enable performance monitoring

**Used in kernel-spy for:**

- `tcp:tcp_retransmit_skb` tracepoint attachment
- Enable/disable via `--skip-tcp-retransmit-trace` flag

---

### CAP_SYS_RESOURCE

**What it allows:**

- Override resource limits (RLIMIT\_\*)
- Lock memory pages
- Bypass filesystem quotas

**Used in kernel-spy for:**

- Pin eBPF maps to virtual filesystem (if using BPF filesystem)
- Override stack size limits for eBPF verification

---

### CAP_NET_RAW

**What it allows:**

- Bind to raw sockets
- Craft raw packets
- Bypass input/output filters

**Used in kernel-spy for:**

- Potentially by eBPF programs for raw packet introspection (less common)

---

## Verification: List Current Capabilities

```bash
# Show capabilities of running process
grep Cap /proc/<pid>/status
# Output example:
# CapInh:    0000000000000000
# CapPrm:    00000000000c3400  (bitmask of CAP_NET_ADMIN, CAP_BPF, CAP_PERFMON)
# CapEff:    00000000000c3400
# CapBnd:    00000000000fffff
# CapAmb:    0000000000000000

# Decode bitmask:
# 0x0c3400 in binary = 1100 0011 0100 0000 0000
# Bits: [CAP_NET_ADMIN=12, CAP_BPF=39, CAP_PERFMON=38]
# Use: cat /usr/include/linux/capability.h to map

# Easier: use `capsh` (if available)
capsh --decode=0x00000000000c3400
```

---

## Fallback Strategy: Old Kernels (< 5.8)

If running on kernel < 5.8, use `CAP_SYS_ADMIN` instead of split capabilities:

```bash
setcap cap_sys_admin,cap_net_admin=ep kernel-spy
```

**Trade-off:** Less fine-grained security (CAP_SYS_ADMIN is very powerful), but works on older kernels.

---

## Troubleshooting

### Error: "Operation not permitted" or "EPERM"

**Likely cause:** Required capability is missing

**Fix:**

```bash
# Verify capabilities are set
getcap ./kernel-spy

# If empty, grant capabilities again
sudo setcap cap_net_admin,cap_bpf,cap_perfmon,cap_sys_resource,cap_net_raw=ep ./kernel-spy

# If still failing, check kernel version
uname -r

# If kernel < 5.8, use CAP_SYS_ADMIN instead
sudo setcap cap_sys_admin,cap_net_admin=ep ./kernel-spy
```

### Error: "Invalid argument" for XDP or TC

**Likely cause:** Wrong interface or driver doesn't support XDP

**Fix:**

```bash
# List interfaces
ip link show

# Try different XDP mode
./kernel-spy -i eth0 --xdp-mode skb  # Fallback mode
```

### Error: "Function not implemented" for BPF operations

**Likely cause:** Kernel doesn't support eBPF or BPF subsystem not compiled in

**Fix:**

```bash
# Check if BPF is available
grep BPF /boot/config-$(uname -r)
# Should see: CONFIG_BPF=y, CONFIG_BPF_SYSCALL=y, CONFIG_XDP_SOCKETS=y

# If not, recompile kernel with BPF support
```

---

## Performance Notes

**Capability checking overhead:** Negligible (kernel inline optimization).

**No performance difference between:**

- Running as root
- Running with capabilities via setcap
- Running with capabilities via systemd

All are equally fast.

---

## Code References

- **Capability initialization:** Check build.rs for constants
- **eBPF program loading:** [kernel-spy/src/main.rs](../kernel-spy/kernel-spy/src/main.rs) line ~270
- **Tracepoint attachment:** [kernel-spy/src/main.rs](../kernel-spy/kernel-spy/src/main.rs) line ~310
- **nftables operations:** [kernel-spy/src/nft.rs](../kernel-spy/kernel-spy/src/nft.rs)
