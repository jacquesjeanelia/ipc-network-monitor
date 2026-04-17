//! placeholder for host-only checks (ebpf attach, dual-stack maps, nft uid/gid rules).
//! run with: `cargo test -p kernel-spy -- --ignored --nocapture`

#[test]
#[ignore = "needs CAP_NET_ADMIN / root; run by hand on a lab box"]
fn privileged_smoke_placeholder() {
    // empty on purpose — `--ignored` hooks are for manual validation
}
