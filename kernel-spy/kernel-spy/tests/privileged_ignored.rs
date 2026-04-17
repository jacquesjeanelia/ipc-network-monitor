//! Placeholder for host-only checks (eBPF attach, `nft` apply). Run with:
//! `cargo test -p kernel-spy -- --ignored --nocapture`

#[test]
#[ignore = "requires CAP_NET_ADMIN / root; run manually on a lab host"]
fn privileged_smoke_placeholder() {
    // Intentionally empty: document that `--ignored` tests are for manual validation.
}
