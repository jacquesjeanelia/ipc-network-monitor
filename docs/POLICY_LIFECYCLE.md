# Policy Lifecycle: Apply, Preview, Rollback & Audit

**References:** FR-P1–P6 (Policy requirements), NFR-S2 (Policy safety), NFR-S3 (Audit integrity), NFR-R3 (Policy atomicity)

---

## Overview

The policy lifecycle ensures that traffic control rules can be safely applied, previewed before commitment, and rolled back if something goes wrong. All operations are logged in an append-only audit trail.

```
┌─────────────────────┐
│   Operator Form     │
│  [Action] [Dest]    │
│  [Preview] [Apply]  │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│     Preview         │ (nft_preview_drop / nft_preview_rate_limit)
│  Show nftables rule │ ← No state changes, read-only
│  Ask: confirm?      │
└──────────┬──────────┘
           │ User clicks "Apply"
           ▼
┌─────────────────────────────────────────┐
│  1. Backup current state                │
│     $ nft list table inet ipc_netmon > backup.json
│  2. Apply new rule                      │
│     $ nft add rule inet ipc_netmon ... drop
│  3. Verify success                      │
│  4. Log audit entry: "nft_apply_drop"   │
│     outcome: "success", backup: "..."   │
└─────────────────────────────────────────┘
           │ Success
           ▼
┌─────────────────────┐
│  Policy Active      │
│  Show in UI list    │
│  [Disable] [Rollback]
└─────────────────────┘
           │ If user clicks "Rollback"
           ▼
┌─────────────────────────────────────────┐
│  1. Restore from backup                 │
│     $ nft flush table inet ipc_netmon
│     $ nft < backup.json
│  2. Verify success                      │
│  3. Log audit entry: "nft_rollback"     │
│     outcome: "success"                  │
└─────────────────────────────────────────┘
           │ Success
           ▼
┌─────────────────────┐
│  Policy Inactive    │
│  Removed from UI    │
└─────────────────────┘
```

---

## Policy Actions

Supported actions on traffic matching criteria:

### 1. Drop (Deny)

**Effect:** Matched packets are silently discarded.

**Use case:** Block traffic from/to untrusted host.

**Example:**

```
Action: Drop
Destination: 10.0.0.100
→ nftables rule: ip daddr 10.0.0.100 drop
```

**Implementation:** [kernel-spy/src/nft.rs](../kernel-spy/kernel-spy/src/nft.rs) — `apply_drop_ipv4()`

### 2. Rate-Limit

**Effect:** Matched packets are shaped (rate-limited) to specified rate.

**Use case:** Throttle traffic to prevent DoS or control bandwidth.

**Example:**

```
Action: Rate-limit
Destination: 203.0.113.1
Rate: 10 mbytes/second
→ nftables rule: ip daddr 203.0.113.1 limit rate 10 mbytes/second accept
```

**Implementation:** [kernel-spy/src/nft.rs](../kernel-spy/kernel-spy/src/nft.rs) — `apply_rate_limit_ipv4()`

---

## Policy Scope

Policies are expressible with scope along:

- **Destination IP** (current implementation)
- **Source IP** (can be added)
- **Protocol** (TCP/UDP; can be added)
- **Port** (source/dest port; can be added)
- **Interface** (scope to specific interface; can be added)
- **UID/GID** (optional; partially implemented via `meta skuid`)

**Current scope:**

```
ip daddr 10.0.0.1 drop
ip daddr 203.0.113.0/24 limit rate 100 mbytes/second accept
```

**Future scope (if implemented):**

```
ip daddr 10.0.0.1 udp dport 53 drop  # Block DNS to 10.0.0.1
ip saddr 192.168.0.0/16 tcp dport 22 drop  # Block SSH from subnet
meta skuid 1000 drop  # Drop all packets from UID 1000
```

---

## Preview Before Apply (FR-P4)

**Purpose:** Show operator what rule will be created before committing it.

**Process:**

1. **User fills form:**

   ```
   Action: [Drop]
   Destination: [10.0.0.1]
   ```

2. **User clicks "Preview" button**

3. **Control RPC:** `{"method":"nft_preview_drop","params":{"dst":"10.0.0.1"}}`

4. **kernel-spy response:**

   ```json
   {
     "ok": true,
     "data": {
       "preview": "table inet ipc_netmon {\n  chain output {\n    ip daddr 10.0.0.1 drop\n  }\n}"
     }
   }
   ```

5. **UI displays:**

   ```
   Preview: Policy will apply the following nftables rule:

   table inet ipc_netmon {
     chain output {
       ip daddr 10.0.0.1 drop
     }
   }

   This will DROP all traffic to 10.0.0.1

   ⚠️  WARNING: This affects LIVE traffic

   [Cancel]  [Apply]
   ```

**Implementation:** [kernel-spy/src/nft.rs](../kernel-spy/kernel-spy/src/nft.rs) — `preview_drop_ipv4()`, `preview_rate_limit_ipv4()`

**Guarantee:** Preview shows **exactly** what will be applied (not just a guess). If apply changes behavior, it's a bug.

---

## Apply: Backup & Atomicity (NFR-R3, NFR-S2)

**Requirement:** Apply and rollback must be atomic. Partial application is not acceptable.

**Process:**

```
User clicks "Apply"
  ↓
Check prerequisites:
  - nft binary available?
  - ipc_netmon table exists?
  - Sufficient permissions?
  ↓
Backup current state:
  $ nft list table inet ipc_netmon > /tmp/ipc-netmon-state/nft-backup-<TIMESTAMP>.json
  ↓
Apply new rule:
  $ nft add rule inet ipc_netmon output ip daddr 10.0.0.1 drop
  ↓
Verify success:
  - Re-read table to confirm rule is present
  - On failure, restore from backup
  ↓
Log audit entry:
  {"ts_unix_ms":1714512896000,"action":"nft_apply_drop","detail":"dst=10.0.0.1 backup=/tmp/ipc-netmon-state/nft-backup-2026-04-30T12:34:56.json","outcome":"success","session_id":"abc-123"}
  ↓
Return to UI:
  {"ok": true, "data": {"backup": "/tmp/ipc-netmon-state/nft-backup-2026-04-30T12:34:56.json"}}
  ↓
UI displays:
  ✓ Policy applied successfully
  Backup: /tmp/ipc-netmon-state/nft-backup-2026-04-30T12:34:56.json
```

**Backup File Format:**

```json
{
  "timestamp_ms": 1714512896000,
  "table_name": "ipc_netmon",
  "table_json": {
    "nftables": [
      {
        "metainfo": {...}
      },
      {
        "table": {
          "family": "inet",
          "name": "ipc_netmon",
          "handle": 1,
          "chains": [...]
        }
      }
    ]
  }
}
```

**Atomicity Guarantee:**

1. **Backup is created first:** If apply fails, backup is available for rollback
2. **Apply is single `nft add rule`:** Either succeeds or fails, no partial state
3. **Verification**: Re-read table to confirm rule was added
4. **Audit log entry is appended:** Even if apply fails, failure is logged

**If apply fails:**

```
Attempt to apply: FAILS
  ↓
Restore from backup:
  $ nft flush table inet ipc_netmon
  $ nft < /tmp/ipc-netmon-state/nft-backup-2026-04-30T12:34:56.json
  ↓
Log audit entry:
  {"ts_unix_ms":1714512896000,"action":"nft_apply_drop","detail":"dst=10.0.0.1","outcome":"failure","error":"Invalid IP address"}
  ↓
Return to UI:
  {"ok": false, "error": "Invalid IP address"}
  ↓
UI displays:
  ✗ Policy apply failed: Invalid IP address
```

---

## Disable & Enable (FR-P5)

**Purpose:** Temporarily disable a policy without deleting it.

**Implementation:**

- Disabled policies are removed from nftables (but backup is kept)
- If re-enabled, policy is reapplied from backup

**Example:**

```
Active policies:
[✓] ID:1  Drop 10.0.0.1      [Disable] [Rollback]
[✓] ID:2  Drop 10.0.0.2      [Disable] [Rollback]

User clicks "Disable" on ID:1
  ↓
kernel-spy removes rule from nftables
Audit entry: {"action":"nft_disable","detail":"id=1","outcome":"success"}

Active policies:
[ ] ID:1  Drop 10.0.0.1      [Enable] [Delete]
[✓] ID:2  Drop 10.0.0.2      [Disable] [Rollback]

User clicks "Enable" on ID:1
  ↓
kernel-spy re-adds rule from backup
Audit entry: {"action":"nft_enable","detail":"id=1","outcome":"success"}

Active policies:
[✓] ID:1  Drop 10.0.0.1      [Disable] [Rollback]
[✓] ID:2  Drop 10.0.0.2      [Disable] [Rollback]
```

---

## Rollback to Previous Safe State (FR-P5)

**Purpose:** Undo a policy change and restore to the previous state.

**Scope:**

1. **Rollback single policy:** Revert a specific policy to its backed-up state
2. **Reset to safe state:** Remove all user-applied policies, restore pre-session baseline (future enhancement)

**Implementation:**

```
User clicks "Rollback" on policy ID:1
  ↓
Retrieve backup file for ID:1:
  /tmp/ipc-netmon-state/nft-backup-2026-04-30T12:34:56.json
  ↓
Compare current state vs. backup state:
  - Rules in current but not in backup? (NEW rules added since this policy)
  - Rules in backup but not in current? (Rules deleted by other policies)
  ↓
If conflict detected:
  - Show warning to user: "Other policies have been applied since this backup"
  - Ask: "Rollback anyway? This will remove policies [ID:2, ID:3]"
  ↓
If user confirms:
  - Restore table from backup:
    $ nft flush table inet ipc_netmon
    $ nft < /tmp/ipc-netmon-state/nft-backup-2026-04-30T12:34:56.json
  - Reapply any other active policies (that came after this backup)
  ↓
Audit entry:
  {"action":"nft_rollback","detail":"policy_id=1 backup=/tmp/ipc-netmon-state/nft-backup-2026-04-30T12:34:56.json","outcome":"success"}
  ↓
UI displays:
  ✓ Policy rolled back
  Note: Policies [ID:2, ID:3] were also reverted (re-apply if needed)
```

**Ordering:** Policies are applied in order. Rollback is complex if multiple policies are active because backups are per-policy, not per-table-state.

**Better approach (future):** Maintain a "policy stack" where each policy update records its backup, allowing selective rollback.

---

## Policy Change Audit Log (FR-P6)

**Purpose:** Record all policy operations for accountability and debugging.

**Audit Entry Format:**

```json
{
  "ts_unix_ms": 1714512896000,
  "action": "nft_apply_drop",
  "detail": "dst=10.0.0.1",
  "outcome": "success",
  "session_id": "abc-123"
}
```

**Logged Actions:**

- `nft_preview_drop` — Preview a drop rule
- `nft_preview_rate_limit` — Preview a rate-limit rule
- `nft_apply_drop` — Apply a drop rule
- `nft_apply_rate_limit` — Apply a rate-limit rule
- `nft_disable` — Disable an active policy
- `nft_enable` — Re-enable a disabled policy
- `nft_rollback` — Rollback a policy
- `tc_netem` — Apply traffic shaping

**Immutability (NFR-S3):**

- File opened with `O_APPEND` flag (kernel enforces append-only writes)
- Even if attacker gains file access, they cannot edit previous entries
- Tamper is evident (timeline break)

**Storage:**

- Default: `--audit-log /tmp/ipc-netmon-audit.log` (world-readable)
- Production: `/var/log/ipc-netmon-audit.log` with restricted permissions (root:root, 0640)

**Searchability:**

- Searchable by action, outcome, session_id in UI (Audit view)
- Exportable as JSON or CSV

---

## Control RPC Methods

### nft_preview_drop

Request:

```json
{ "method": "nft_preview_drop", "params": { "dst": "10.0.0.1" } }
```

Response:

```json
{ "ok": true, "data": { "preview": "table inet ipc_netmon {...}" } }
```

### nft_apply_drop

Request:

```json
{ "method": "nft_apply_drop", "params": { "dst": "10.0.0.1" } }
```

Response (success):

```json
{
  "ok": true,
  "data": {
    "backup": "/tmp/ipc-netmon-state/nft-backup-2026-04-30T12:34:56.json"
  }
}
```

Response (failure):

```json
{ "ok": false, "error": "Invalid IP address" }
```

### nft_preview_rate_limit / nft_apply_rate_limit

Similar to drop, but with additional `rate` parameter:

```json
{
  "method": "nft_apply_rate_limit",
  "params": { "dst": "203.0.113.1", "rate": "10 mbytes/second" }
}
```

### nft_apply_drop_uid / nft_apply_drop_gid

Apply policies based on UID/GID (process ownership):

```json
{ "method": "nft_apply_drop_uid", "params": { "uid": 1000 } }
```

Generates rule:

```
meta skuid 1000 drop
```

---

## Error Handling

**Policy apply failures:**

1. **Invalid IP:** `"error":"Invalid IP address"`
2. **nftables not available:** `"error":"nft binary not found"`
3. **Permission denied:** `"error":"Operation not permitted (missing CAP_NET_ADMIN?)"`
4. **Syntax error in rule:** `"error":"nftables parse error: ..."`
5. **Backup restore failed:** `"error":"Failed to restore from backup"`

**UI displays:** Error message with suggestion for next step.

---

## State Directory

All policy-related state is stored in `--state-dir` (default: `/tmp/ipc-netmon-state`):

```
/tmp/ipc-netmon-state/
├── nft-backup-2026-04-30T12:34:56.json    # Policy #1 backup
├── nft-backup-2026-04-30T12:35:00.json    # Policy #2 backup
└── ... (more backups)
```

**Permissions:** World-writable (or restricted group if in /run/)

**Cleanup:** Backups are kept indefinitely. Manual cleanup recommended via cron or systemd timer.

---

## Code References

- **nftables operations:** [kernel-spy/src/nft.rs](../kernel-spy/kernel-spy/src/nft.rs)
- **Control RPC dispatch:** [kernel-spy/src/control_rpc.rs](../kernel-spy/kernel-spy/src/control_rpc.rs)
- **Audit logging:** [kernel-spy/src/control.rs](../kernel-spy/kernel-spy/src/control.rs)
- **Data model:** [common/src/lib.rs](../common/src/lib.rs) — `ControlAuditEntry`
