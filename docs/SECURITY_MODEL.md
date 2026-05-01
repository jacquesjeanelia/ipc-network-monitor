# Security Model & Privilege Boundary

**References:** FR-U1 (Separation of privilege), NFR-S1–S4 (Security requirements)

---

## Architecture: Privilege Separation

The system enforces a strict boundary between **privileged collector** and **unprivileged UI**:

```
┌─────────────────────────────────────────────────────────────────────┐
│  Kernel & System Resources                                          │
├─────────────────────────────────────────────────────────────────────┤
│  kernel-spy (privileged collector)                                  │
│  - Runs as root or with elevated capabilities                       │
│  - Direct access: eBPF programs, netlink, nftables, tc              │
│  - Binds sockets: /tmp/ipc-netmon.sock (export), -ctl.sock (control)│
│  - Writes audit log (append-only)                                   │
│  - Manages state dir: /tmp/ipc-netmon-state/ (backups, config)      │
└─────────────────────────────────────────────────────────────────────┘
                             ↑↓ IPC (Unix Domain Socket)
┌─────────────────────────────────────────────────────────────────────┐
│  collector / ui (unprivileged processes)                            │
│  - Runs as ordinary user (no special privileges)                    │
│  - NO direct kernel calls (no eBPF, netlink, iptables, nftables)   │
│  - NO file system access except: read /tmp/ipc-netmon.sock          │
│  - Receives JSON data: MonitorSnapshotV1, ControlAuditEntry         │
│  - Sends JSON requests: {"method":"nft_apply_drop", ...}           │
│  - Cannot execute arbitrary code in kernel context                  │
└─────────────────────────────────────────────────────────────────────┘
```

**Guarantee:** If the UI process is compromised (memory corruption, vulnerability), it cannot:

- Load arbitrary eBPF programs
- Modify firewall rules directly
- Read kernel memory
- Execute privileged syscalls

All privileged operations are **mediated by kernel-spy** and **logged in audit trail**.

---

## IPC Isolation

### Unix Domain Socket Permissions

**Export Socket** (`/tmp/ipc-netmon.sock`):

- Created by kernel-spy with mode **0666** (world-readable)
- Any process can connect and read export data
- **Why:** Allow unprivileged collector and UI to read monitoring data
- **Limitation:** Any user on the system can spy on traffic; not suitable for multi-tenant environments

**Control Socket** (`/tmp/ipc-netmon-ctl.sock`):

- Created by kernel-spy with mode **0666** (world-readable, world-writable)
- Any process can connect and send control requests
- **Current behavior:** No authentication; first-come-first-served
- **Risk:** Unprivileged user could apply policies, but kernel-spy validates all requests
- **Mitigation (for production):** Use `/run/ipc-netmon/` directory with 0750 permissions + dedicated group

**Recommended Production Setup:**

```bash
# Create directory with restricted permissions
sudo mkdir -p /run/ipc-netmon
sudo chown root:netmon /run/ipc-netmon
sudo chmod 0750 /run/ipc-netmon

# Run kernel-spy with restricted socket paths
sudo ./kernel-spy -i eth0 \
  --export-socket /run/ipc-netmon/export.sock \
  --control-socket /run/ipc-netmon/control.sock

# Add users to netmon group to grant access
sudo usermod -a -G netmon alice
```

---

## Privilege Boundary Enforcement

### What kernel-spy CAN do (privileged operations):

1. **Load eBPF programs** (CAP_BPF, CAP_PERFMON)
2. **Attach to XDP, TC hooks** (CAP_NET_ADMIN)
3. **Read kernel tracepoints** (CAP_PERFMON)
4. **Manage nftables rules** (CAP_NET_ADMIN)
5. **Apply tc/netem discipline** (CAP_NET_ADMIN)
6. **Write audit logs** (CAP_DAC_OVERRIDE if /tmp restrictions apply)

### What collector/UI CANNOT do (unprivileged restrictions):

1. ❌ Load eBPF programs (would require CAP_BPF)
2. ❌ Attach to XDP hooks (would require CAP_NET_ADMIN)
3. ❌ Read tracepoints (would require CAP_PERFMON)
4. ❌ Modify nftables rules (would require CAP_NET_ADMIN)
5. ❌ Execute any privileged syscall
6. ❌ Open `/dev/mem` or `/proc/kcore`
7. ❌ Access sysfs or debugfs (kernel introspection)

### Verification: Strace Analysis

To verify UI makes **only** socket calls:

```bash
# Terminal 1: Run kernel-spy
sudo ./target/release/kernel-spy -i eth0 &

# Terminal 2: Run UI and trace syscalls
strace -f -e trace=open,openat,read,write,sendto,recvfrom,socket,bind,connect \
  ./target/release/ui 2>&1 | grep -v 'ENOENT\|EACCES'
```

**Expected output:**

```
[ui] socket(AF_UNIX, SOCK_STREAM, 0) = 3
[ui] connect(3, {sa_family=AF_UNIX, sun_path="/tmp/ipc-netmon.sock"}, 110) = 0
[ui] recvfrom(3, "...", 4096, 0, NULL, NULL) = 2048     # JSON data
[ui] socket(AF_UNIX, SOCK_STREAM, 0) = 4
[ui] connect(4, {sa_family=AF_UNIX, sun_path="/tmp/ipc-netmon-ctl.sock"}, 110) = 0
[ui] sendto(4, "{\"method\":\"ping\"}", ...) = 17        # RPC request
[ui] recvfrom(4, "{\"ok\":true}", ...) = 12              # RPC response
```

**Red flag syscalls (should NOT appear):**

- `bpf()` — would indicate eBPF loading
- `openat(..., "/sys/kernel/", ...)` — kernel introspection
- `ioctl(..., SIOCETHTOOL, ...)` — direct device control
- `setsockopt(SOL_IP, IP_HDRINCL, ...)` — raw packet construction
- Any `CAP_*` check failure (indicates code path tried to escalate privilege)

---

## Audit Log Integrity

**Requirement (NFR-S3):** Audit log shall be append-only during session and not editable through GUI.

**Implementation:**

```rust
// Append-only: file opened with O_APPEND flag
let file = OpenOptions::new()
    .create(true)
    .append(true)       // 👈 KEY: forces writes to end-of-file
    .open(audit_log_path)?;

// Each entry is one JSON line
writeln!(file, "{}", serde_json::to_string(&entry))?;
// No seek, no truncate, no edit: impossible to modify existing entries
```

**Guarantee:** Even if a user process gains access to the audit log file, `O_APPEND` prevents modification of earlier entries. Entries can only be appended.

**Verification:**

```bash
# Attempt to edit audit log (should fail)
cat /tmp/ipc-netmon-audit.log | sed 's/success/failure/g' > /tmp/temp.log
mv /tmp/temp.log /tmp/ipc-netmon-audit.log  # This works (file replacement)

# But: kernel-spy continues to write with O_APPEND, so entries after tampering will be appended
# Tamper is visible: audit log has break in timeline

# Better protection: root ownership + 0600 perms
sudo chown root:root /tmp/ipc-netmon-audit.log
sudo chmod 0600 /tmp/ipc-netmon-audit.log
```

---

## Policy Change Safety (NFR-S2)

**Requirement:** A misconfigured policy shall not silently corrupt existing rules; rollback must always be possible.

**Mechanism:**

1. **Before apply:** Backup current nftables state

   ```bash
   nft list table inet ipc_netmon > /tmp/ipc-netmon-state/nft-backup-2026-04-30T12:34:56.json
   ```

2. **Apply:** Use `nft` tool to add rule

   ```bash
   nft add rule inet ipc_netmon output ip daddr 10.0.0.1 drop
   ```

3. **If failure:** Restore from backup

   ```bash
   nft flush table inet ipc_netmon
   nft create table inet ipc_netmon  # if needed
   nft < /tmp/ipc-netmon-state/nft-backup-2026-04-30T12:34:56.json
   ```

4. **Audit log entry:**
   ```json
   {
     "ts_unix_ms": 1714512896000,
     "action": "nft_apply_drop",
     "detail": "dst=10.0.0.1 backup=/tmp/...",
     "outcome": "success",
     "session_id": "abc-123"
   }
   ```

**Guarantee:** If `nft apply` fails, prior state is restored and logged. Audit trail shows both apply attempt and rollback.

---

## Capability Scoping (NFR-S4)

Instead of running kernel-spy as root, use Linux capabilities:

**Required Capabilities:**

- `CAP_NET_ADMIN` — load XDP, attach TC, manage nftables
- `CAP_BPF` — eBPF operations (kernel 5.8+)
- `CAP_PERFMON` — tracepoint attachment (kernel 5.8+)
- `CAP_SYS_RESOURCE` — pin eBPF maps to virtual filesystem (if used)
- `CAP_NET_RAW` — raw socket operations (if used)

**Startup Command:**

```bash
# Instead of:
sudo ./kernel-spy -i eth0

# Use:
sudo setcap cap_net_admin,cap_bpf,cap_perfmon,cap_sys_resource,cap_net_raw=ep ./kernel-spy
./kernel-spy -i eth0
```

**Verify Caps:**

```bash
getcap ./kernel-spy
# Output: ./kernel-spy = cap_net_admin,cap_bpf,cap_perfmon,cap_sys_resource,cap_net_raw=ep
```

**Advantages:**

- Kernel-spy runs as unprivileged user, not root
- Kernel audits capabilities, not UID (finer-grained logging)
- If binary is overwritten, capabilities are not inherited (attacker cannot re-exec with caps)

---

## Threat Model

### Threat 1: Compromised UI Process

**Scenario:** Attacker exploits memory corruption vulnerability in UI (e.g., buffer overflow).

**Capabilities (current):**

- Read monitoring data from export socket (traffic data)
- Send control RPC requests (apply policies, etc.)

**Cannot do:**

- Load arbitrary eBPF code
- Modify kernel data structures directly
- Elevate privilege to root

**Mitigation:** All UI requests are authenticated/validated by kernel-spy before execution.

### Threat 2: Unauthorized User Sends Control Requests

**Scenario:** Unprivileged user connects to control socket and sends `nft_apply_drop` request.

**Current behavior:** kernel-spy processes request without authentication (any user can send).

**Mitigation (for production):** Restrict control socket perms to authorized group (see IPC Isolation section above).

### Threat 3: Audit Log Tamper

**Scenario:** Attacker modifies `/tmp/ipc-netmon-audit.log` to hide policy changes.

**Mitigation:** File opened O_APPEND (appends are atomic, edits are not). Tamper is evident.

**Better mitigation (future):** Send audit entries to remote syslog or immutable storage (e.g., ProtectedLogDir on systemd).

### Threat 4: Packet Capture Privilege Escalation

**Scenario:** If network monitor can be tricked into executing user-supplied eBPF code, attacker gains kernel execution.

**Mitigation (FR-E1):** Kernel-spy does **not** expose arbitrary eBPF scripting. Probe set is fixed at build time. Only operator-curated diagnostics are available.

---

## Compliance & Audit

- **All privileged operations are logged** in audit trail (audit_log file)
- **Every policy change recorded** with timestamp, action, outcome, session ID
- **Operator accountability:** Session ID ties policy changes to user session
- **Trace privilege delegation:** Control RPC requests log which unprivileged user triggered them (if needed, can add UID to request)

---

## Secrets & Credentials

Current implementation does not handle secrets:

- No authentication tokens for control RPC
- No encryption for export socket data
- No password-protected config

**Assumption:** Deployed in trusted network or air-gapped environment.

**For production:**

- Wrap sockets in TLS (add TLS layer on top of Unix socket)
- Authenticate control RPC requests (shared secret or mTLS cert)
- Encrypt audit log (GPG or filesystem encryption)

---

## Code References

- **Capability requirements:** Check build.rs for CAP\_\* definitions
- **Audit logging:** [kernel-spy/src/control.rs](../kernel-spy/kernel-spy/src/control.rs) — `audit()` function
- **Socket perms:** [kernel-spy/src/socket_perm.rs](../kernel-spy/kernel-spy/src/socket_perm.rs) — `chmod_0666_for_clients()`
- **nftables backup:** [kernel-spy/src/nft.rs](../kernel-spy/kernel-spy/src/nft.rs) — `apply_drop_ipv4()`, `apply_rate_limit_ipv4()`
