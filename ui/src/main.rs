//! IPC Network Monitor — Professional egui UI (v2)

use std::collections::{BTreeSet, VecDeque};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use eframe::egui::{
    self, Align, Color32, FontId, Layout, Margin, Rounding, RichText, Stroke, Ui, Vec2,
};
use egui_plot::{Legend, Line, Plot, PlotPoints};

use common::{AlertEvent, FlowRow, MonitorSnapshotV1, ProcessTrafficRow, UserTrafficRow, parse_export_line};

const HISTORY_CAP: usize = 120;
const PROTO_HISTORY_CAP: usize = 60;
const RECENT_SIGHTINGS_CAP: usize = 64;
const EXPORT_SOCK: &str = "/tmp/ipc-netmon.sock";
const CONTROL_SOCK: &str = "/tmp/ipc-netmon-ctl.sock";
const MAX_ALERT_LOG: usize = 500;
/// Show all flows present in the snapshot (server caps with `--max-flow-rows`).
const FLOW_TABLE_MAX_ROWS: usize = 512;

// ── palette (VS Code–style dark: near-white text, blue accents, gray chrome) ─

const CLR_BG: Color32         = Color32::from_rgb(0x1e, 0x1e, 0x1e);
const CLR_PANEL: Color32      = Color32::from_rgb(0x25, 0x25, 0x26);
const CLR_CARD: Color32       = Color32::from_rgb(0x2d, 0x2d, 0x30);
const CLR_BORDER: Color32     = Color32::from_rgb(0x3e, 0x3e, 0x42);
const CLR_TEXT: Color32       = Color32::from_rgb(0xcc, 0xcc, 0xcc);
const CLR_TEXT_BRIGHT: Color32 = Color32::from_rgb(0xf3, 0xf3, 0xf3);
const CLR_MUTED: Color32      = Color32::from_rgb(0x85, 0x85, 0x85);
const CLR_ACCENT: Color32     = Color32::from_rgb(0x37, 0x94, 0xff);
const CLR_GREEN: Color32      = Color32::from_rgb(0x4e, 0xc9, 0xb0);
const CLR_YELLOW: Color32     = Color32::from_rgb(0xd7, 0xba, 0x0d);
const CLR_RED: Color32        = Color32::from_rgb(0xf4, 0x87, 0x71);
const CLR_ORANGE: Color32     = Color32::from_rgb(0xce, 0x91, 0x78);
const CLR_BLUE_LIGHT: Color32 = Color32::from_rgb(0x75, 0xbe, 0xff);
const CLR_BLUE_MID: Color32   = Color32::from_rgb(0x56, 0x9c, 0xd6);
const CLR_BLUE_DIM: Color32   = Color32::from_rgb(0x3c, 0x6e, 0x9c);
const CLR_PURPLE: Color32     = Color32::from_rgb(0x6a, 0x8c, 0xc8);
const SIDEBAR_W: f32 = 184.0;

// ── formatting ───────────────────────────────────────────────────────────────

fn fmt_bytes(b: u64) -> String {
    const GIB: u64 = 1 << 30;
    const MIB: u64 = 1 << 20;
    const KIB: u64 = 1 << 10;
    if b >= GIB      { format!("{:.2} GiB", b as f64 / GIB as f64) }
    else if b >= MIB { format!("{:.2} MiB", b as f64 / MIB as f64) }
    else if b >= KIB { format!("{:.1} KiB", b as f64 / KIB as f64) }
    else             { format!("{b} B") }
}

fn fmt_rate(bps: f64) -> String { format!("{}/s", fmt_bytes(bps as u64)) }

fn fmt_ts_ms(ts_ms: u64) -> String {
    let secs = ts_ms / 1000;
    let h = (secs / 3600) % 24;
    let m = (secs / 60)   % 60;
    let s =  secs          % 60;
    format!("{h:02}:{m:02}:{s:02} UTC")
}

fn flow_row_has_attribution(row: &FlowRow) -> bool {
    row.local_pid.is_some()
        || row.local_uid.is_some()
        || row.local_gid.is_some()
        || row.local_username.as_deref().is_some_and(|s| !s.is_empty())
        || row.local_comm.as_deref().is_some_and(|s| !s.is_empty())
}

/// Task name (`local_comm`), login (`local_username`), pid, uid — omit missing pieces.
fn fmt_flow_attribution(row: &FlowRow) -> String {
    if !flow_row_has_attribution(row) {
        return "—".to_string();
    }
    let mut parts: Vec<&str> = Vec::new();
    if let Some(c) = row.local_comm.as_deref().filter(|s| !s.is_empty()) {
        parts.push(c);
    }
    if let Some(u) = row.local_username.as_deref().filter(|s| !s.is_empty()) {
        parts.push(u);
    }
    let mut s = parts.join(" · ");
    if let Some(p) = row.local_pid {
        if !s.is_empty() {
            s.push_str(" · ");
        }
        s.push_str(&format!("pid={p}"));
    }
    if let Some(u) = row.local_uid {
        if !s.is_empty() {
            s.push_str(" · ");
        }
        s.push_str(&format!("uid={u}"));
    }
    if let Some(g) = row.local_gid {
        if !s.is_empty() {
            s.push_str(" · ");
        }
        s.push_str(&format!("gid={g}"));
    }
    s
}

fn flow_attribution_rich_text(row: &FlowRow) -> RichText {
    if flow_row_has_attribution(row) {
        return RichText::new(fmt_flow_attribution(row))
        .small()
        .color(CLR_MUTED);
    }
    match row.protocol.as_str() {
        "ICMP" | "ICMPv6" | "IGMP" => RichText::new("L3 · no socket")
            .small()
            .italics()
            .color(CLR_YELLOW),
        "TCP" | "UDP" => RichText::new("—").small().color(CLR_MUTED),
        _ => RichText::new("—").small().color(CLR_MUTED),
    }
}

fn flow_attribution_hover(row: &FlowRow) -> Option<&'static str> {
    if flow_row_has_attribution(row) {
        return None;
    }
    Some(match row.protocol.as_str() {
        "ICMP" | "ICMPv6" | "IGMP" => {
            "ICMP/IGMP are not in /proc/net/tcp or UDP. There is no per-flow PID in the standard Linux APIs for these protocols."
        }
        "TCP" | "UDP" => {
            "No match from the Linux /proc pipeline: 5-tuple in /proc/net/tcp|tcp6|udp|udp6 → socket inode → owning PID via /proc/*/fd → optional ss(8); user comes from /proc/PID/status (Uid:) when PID is known. Also tries the eBPF sport map. If traffic is in another netns, run kernel-spy with --ss-netns <name>. Use privileges if ss -p is denied."
        }
        _ => "No standard socket-based attribution for this protocol.",
    })
}

fn alert_color(severity: &str) -> Color32 {
    match severity {
        "critical" => CLR_RED,
        "warn" | "warning" => CLR_YELLOW,
        _ => CLR_BLUE_LIGHT,
    }
}

fn proto_color(proto: &str) -> Color32 {
    match proto {
        "TCP" => CLR_ACCENT,
        "UDP" => CLR_BLUE_MID,
        "ICMP" | "ICMPv6" => CLR_BLUE_DIM,
        "IGMP" | "GRE" | "SCTP" | "ESP" | "AH" => CLR_PURPLE,
        _ => CLR_MUTED,
    }
}

// ── protocol snapshot ────────────────────────────────────────────────────────

#[derive(Clone, Default)]
struct ProtoSnapshot {
    elapsed:       f64,
    tcp_bytes:     u64,
    udp_bytes:     u64,
    icmp_bytes:    u64,
    icmpv6_bytes:  u64,
    igmp_bytes:    u64,
    gre_bytes:     u64,
    sctp_bytes:    u64,
    esp_bytes:     u64,
    ah_bytes:      u64,
    other_bytes:   u64,
}

fn classify_flow_bytes(flows: &[FlowRow]) -> ProtoSnapshot {
    let mut s = ProtoSnapshot::default();
    for f in flows {
        match f.protocol.as_str() {
            "TCP"     => s.tcp_bytes    += f.bytes,
            "UDP"     => s.udp_bytes    += f.bytes,
            "ICMP"    => s.icmp_bytes   += f.bytes,
            "ICMPv6"  => s.icmpv6_bytes += f.bytes,
            "IGMP"    => s.igmp_bytes   += f.bytes,
            "GRE"     => s.gre_bytes    += f.bytes,
            "SCTP"    => s.sctp_bytes   += f.bytes,
            "ESP"     => s.esp_bytes    += f.bytes,
            "AH"      => s.ah_bytes     += f.bytes,
            _         => s.other_bytes  += f.bytes,
        }
    }
    s
}

fn proto_snapshot_elapsed(mut s: ProtoSnapshot, elapsed: f64) -> ProtoSnapshot {
    s.elapsed = elapsed;
    s
}

// ── shared state ─────────────────────────────────────────────────────────────

struct SharedState {
    snapshot: Option<MonitorSnapshotV1>,
    recent_process_sightings: VecDeque<ProcessTrafficRow>,
    recent_user_sightings: VecDeque<UserTrafficRow>,
    rx_rate_history: VecDeque<[f64; 2]>,
    tx_rate_history: VecDeque<[f64; 2]>,
    port_rate_history: VecDeque<[f64; 2]>,
    conntrack_util_history: VecDeque<[f64; 2]>,
    conntrack_insert_failed_history: VecDeque<[f64; 2]>,
    nic_rx_dropped_history: VecDeque<[f64; 2]>,
    proto_history: VecDeque<ProtoSnapshot>,
    prev_rx_bytes: Option<u64>,
    prev_tx_bytes: Option<u64>,
    prev_ts_ms: Option<u64>,
    prev_port_matched_bytes: Option<u64>,
    /// Sum of flow bytes (RX+TX) where `src_port` or `dst_port` matches; drives port rate chart.
    selected_port: Option<u16>,
    start: Instant,
    connected: bool,
    alert_log: Vec<AlertEvent>,
    rpc_result: String,
}

impl SharedState {
    fn new() -> Self {
        Self {
            snapshot: None,
            recent_process_sightings: VecDeque::new(),
            recent_user_sightings: VecDeque::new(),
            rx_rate_history: VecDeque::new(),
            tx_rate_history: VecDeque::new(),
            port_rate_history: VecDeque::new(),
            conntrack_util_history: VecDeque::new(),
            conntrack_insert_failed_history: VecDeque::new(),
            nic_rx_dropped_history: VecDeque::new(),
            proto_history: VecDeque::new(),
            prev_rx_bytes: None,
            prev_tx_bytes: None,
            prev_ts_ms: None,
            prev_port_matched_bytes: None,
            selected_port: None,
            start: Instant::now(),
            connected: false,
            alert_log: Vec::new(),
            rpc_result: String::new(),
        }
    }

    fn remember_process_sighting(&mut self, row: &ProcessTrafficRow) {
        if let Some(pos) = self.recent_process_sightings.iter().position(|e| e.pid == row.pid) {
            self.recent_process_sightings.remove(pos);
        }
        self.recent_process_sightings.push_front(row.clone());
        while self.recent_process_sightings.len() > RECENT_SIGHTINGS_CAP {
            self.recent_process_sightings.pop_back();
        }
    }

    fn remember_user_sighting(&mut self, row: &UserTrafficRow) {
        if let Some(pos) = self.recent_user_sightings.iter().position(|e| e.uid == row.uid) {
            self.recent_user_sightings.remove(pos);
        }
        self.recent_user_sightings.push_front(row.clone());
        while self.recent_user_sightings.len() > RECENT_SIGHTINGS_CAP {
            self.recent_user_sightings.pop_back();
        }
    }

    fn ingest(&mut self, snap: MonitorSnapshotV1) {
        // Any parsed snapshot means the export socket delivered data (same idea as web `netmon-link`
        // vs first `read_line` race).
        self.connected = true;
        let elapsed = self.start.elapsed().as_secs_f64();

        let mut port_bytes_cur: Option<u64> = None;
        if let Some(port) = self.selected_port {
            let mut b = 0u64;
            for f in snap.flows_rx.iter().chain(snap.flows_tx.iter()) {
                if f.src_port == port || f.dst_port == port {
                    b = b.saturating_add(f.bytes);
                }
            }
            port_bytes_cur = Some(b);
        }

        if let (Some(prx), Some(ptx), Some(pts)) =
            (self.prev_rx_bytes, self.prev_tx_bytes, self.prev_ts_ms)
        {
            let dt = snap.ts_unix_ms.saturating_sub(pts) as f64 / 1000.0;
            if dt > 0.0 {
                let rx_rate = snap.rx.bytes.saturating_sub(prx) as f64 / dt;
                let tx_rate = snap.tx.bytes.saturating_sub(ptx) as f64 / dt;
                if self.rx_rate_history.len() >= HISTORY_CAP { self.rx_rate_history.pop_front(); }
                self.rx_rate_history.push_back([elapsed, rx_rate]);
                if self.tx_rate_history.len() >= HISTORY_CAP { self.tx_rate_history.pop_front(); }
                self.tx_rate_history.push_back([elapsed, tx_rate]);

                if let (Some(pb), Some(ppb)) = (port_bytes_cur, self.prev_port_matched_bytes) {
                    let prate = pb.saturating_sub(ppb) as f64 / dt;
                    if self.port_rate_history.len() >= HISTORY_CAP {
                        self.port_rate_history.pop_front();
                    }
                    self.port_rate_history.push_back([elapsed, prate]);
                }
            }
        }
        self.prev_rx_bytes = Some(snap.rx.bytes);
        self.prev_tx_bytes = Some(snap.tx.bytes);
        self.prev_ts_ms    = Some(snap.ts_unix_ms);

        if let Some(pb) = port_bytes_cur {
            self.prev_port_matched_bytes = Some(pb);
        } else {
            self.prev_port_matched_bytes = None;
            self.port_rate_history.clear();
        }

        // Protocol breakdown snapshot
        let mut all_flows: Vec<FlowRow> = snap.flows_rx.clone();
        all_flows.extend_from_slice(&snap.flows_tx);
        let nic_rx_dropped_delta: u64 = snap.nic_stats_delta.iter().map(|r| r.rx_dropped).sum();
        if self.conntrack_util_history.len() >= HISTORY_CAP {
            self.conntrack_util_history.pop_front();
        }
        self.conntrack_util_history
            .push_back([elapsed, snap.conntrack.utilization_percent]);
        if self.conntrack_insert_failed_history.len() >= HISTORY_CAP {
            self.conntrack_insert_failed_history.pop_front();
        }
        self.conntrack_insert_failed_history
            .push_back([elapsed, snap.conntrack_delta.insert_failed as f64]);
        if self.nic_rx_dropped_history.len() >= HISTORY_CAP {
            self.nic_rx_dropped_history.pop_front();
        }
        self.nic_rx_dropped_history
            .push_back([elapsed, nic_rx_dropped_delta as f64]);
        let proto = classify_flow_bytes(&all_flows);
        if self.proto_history.len() >= PROTO_HISTORY_CAP { self.proto_history.pop_front(); }
        self.proto_history.push_back(proto_snapshot_elapsed(proto, elapsed));

        for row in &snap.aggregates_by_pid  { self.remember_process_sighting(row); }
        for row in &snap.aggregates_by_user { self.remember_user_sighting(row); }
        for alert in &snap.alerts {
            if self.alert_log.len() >= MAX_ALERT_LOG { self.alert_log.remove(0); }
            self.alert_log.push(alert.clone());
        }
        self.snapshot = Some(snap);
    }
}

// ── app ──────────────────────────────────────────────────────────────────────

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Dashboard,
    Flows,
    Processes,
    Audit,
    Control,
    Settings,
}

/// Sub-pages under Dashboard (everything available; use toggles + pages to reduce noise).
#[derive(PartialEq, Clone, Copy, Debug)]
enum DashboardPage {
    Overview,
    Traffic,
    Attribution,
    KernelHealth,
}

struct App {
    state: Arc<Mutex<SharedState>>,
    active_tab: Tab,
    flow_filter: String,
    ip_input: String,
    rate_input: String,
    uid_input: String,
    gid_input: String,
    simulate_lookback_mins: String,
    sim_medium_bytes_input: String,
    sim_high_bytes_input: String,
    sim_medium_ratio_input: String,
    sim_high_ratio_input: String,
    alert_softnet_warn_input: String,
    alert_softnet_crit_input: String,
    alert_listen_warn_input: String,
    alert_listen_crit_input: String,
    alert_conntrack_util_warn_input: String,
    alert_conntrack_util_crit_input: String,
    alert_conntrack_insert_failed_warn_input: String,
    alert_conntrack_insert_failed_crit_input: String,
    alert_nic_rx_dropped_warn_input: String,
    alert_nic_rx_dropped_crit_input: String,
    dashboard_page: DashboardPage,
    /// Show zero-byte protocols in Traffic protocol bars.
    dash_show_proto_zeros: bool,
    /// Extra diagnostic row on Overview (TCP softnet overflows, etc.).
    dash_show_overview_extended: bool,
}

impl App {
    fn new(state: Arc<Mutex<SharedState>>, cc: &eframe::CreationContext<'_>) -> Self {
        setup_visuals(&cc.egui_ctx);
        Self {
            state,
            active_tab: Tab::Dashboard,
            flow_filter: String::new(),
            ip_input: String::new(),
            rate_input: "1 mbytes/second".to_string(),
            uid_input: String::new(),
            gid_input: String::new(),
            simulate_lookback_mins: "10".to_string(),
            sim_medium_bytes_input: (5_u64 << 20).to_string(),
            sim_high_bytes_input: (50_u64 << 20).to_string(),
            sim_medium_ratio_input: "0.25".to_string(),
            sim_high_ratio_input: "0.55".to_string(),
            alert_softnet_warn_input: "1".to_string(),
            alert_softnet_crit_input: "10".to_string(),
            alert_listen_warn_input: "1".to_string(),
            alert_listen_crit_input: "5".to_string(),
            alert_conntrack_util_warn_input: "70".to_string(),
            alert_conntrack_util_crit_input: "90".to_string(),
            alert_conntrack_insert_failed_warn_input: "1".to_string(),
            alert_conntrack_insert_failed_crit_input: "10".to_string(),
            alert_nic_rx_dropped_warn_input: "1".to_string(),
            alert_nic_rx_dropped_crit_input: "50".to_string(),
            dashboard_page: DashboardPage::Overview,
            dash_show_proto_zeros: false,
            dash_show_overview_extended: false,
        }
    }

    fn rpc(&self, method: &str, params: serde_json::Value) -> String {
        let req = serde_json::json!({"method": method, "params": params}).to_string() + "\n";
        match UnixStream::connect(CONTROL_SOCK) {
            Err(e) => format!("connect error: {e}"),
            Ok(mut s) => {
                s.set_read_timeout(Some(Duration::from_secs(3))).ok();
                if s.write_all(req.as_bytes()).is_err() { return "write error".to_string(); }
                let mut resp = String::new();
                BufReader::new(s).read_line(&mut resp).ok();
                resp.trim().to_string()
            }
        }
    }

    fn set_rpc_result(&self, result: String) {
        if let Ok(mut s) = self.state.lock() { s.rpc_result = result; }
    }
}

fn setup_visuals(ctx: &egui::Context) {
    let mut v = egui::Visuals::dark();
    v.panel_fill           = CLR_PANEL;
    v.window_fill          = CLR_CARD;
    v.extreme_bg_color     = CLR_BG;
    v.faint_bg_color       = CLR_CARD;
    v.code_bg_color        = Color32::from_rgb(0x1e, 0x1e, 0x1e);
    v.window_stroke        = Stroke::new(1.0, CLR_BORDER);
    v.widgets.noninteractive.bg_fill   = CLR_CARD;
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0, CLR_TEXT);
    v.widgets.inactive.bg_fill         = Color32::from_rgb(0x3c, 0x3c, 0x3c);
    v.widgets.inactive.fg_stroke       = Stroke::new(1.0, CLR_TEXT_BRIGHT);
    v.widgets.hovered.bg_fill          = Color32::from_rgb(0x2a, 0x2d, 0x2e);
    v.widgets.active.bg_fill           = Color32::from_rgb(0x09, 0x47, 0x71);
    v.selection.bg_fill                = Color32::from_rgba_premultiplied(0x26, 0x88, 0xf2, 0x55);
    v.hyperlink_color                    = CLR_ACCENT;
    v.widgets.noninteractive.rounding  = Rounding::same(4.0);
    v.widgets.inactive.rounding        = Rounding::same(4.0);
    v.widgets.hovered.rounding         = Rounding::same(4.0);
    v.widgets.active.rounding          = Rounding::same(4.0);
    ctx.set_visuals(v);

    use egui::FontFamily::{Monospace, Proportional};
    let mut style = (*ctx.style()).clone();
    style.text_styles.insert(egui::TextStyle::Body,      FontId::new(14.5, Proportional));
    style.text_styles.insert(egui::TextStyle::Heading,   FontId::new(19.0, Proportional));
    style.text_styles.insert(egui::TextStyle::Monospace, FontId::new(13.0, Monospace));
    style.text_styles.insert(egui::TextStyle::Small,     FontId::new(11.5, Proportional));
    style.text_styles.insert(egui::TextStyle::Button,    FontId::new(13.5, Proportional));
    style.spacing.item_spacing   = Vec2::new(10.0, 7.0);
    style.spacing.button_padding = Vec2::new(12.0, 6.0);
    ctx.set_style(style);
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.request_repaint_after(Duration::from_millis(500));

        let (connected, snap, rx_hist, tx_hist, port_hist, ct_util_hist, ct_insert_failed_hist, nic_rx_drop_hist, proto_hist, alert_log, rpc_result, recent_procs, recent_users) = {
            let s = self.state.lock().unwrap();
            (
                s.connected,
                s.snapshot.clone(),
                s.rx_rate_history.iter().cloned().collect::<Vec<_>>(),
                s.tx_rate_history.iter().cloned().collect::<Vec<_>>(),
                s.port_rate_history.iter().cloned().collect::<Vec<_>>(),
                s.conntrack_util_history.iter().cloned().collect::<Vec<_>>(),
                s.conntrack_insert_failed_history.iter().cloned().collect::<Vec<_>>(),
                s.nic_rx_dropped_history.iter().cloned().collect::<Vec<_>>(),
                s.proto_history.iter().cloned().collect::<Vec<_>>(),
                s.alert_log.clone(),
                s.rpc_result.clone(),
                s.recent_process_sightings.iter().cloned().collect::<Vec<_>>(),
                s.recent_user_sightings.iter().cloned().collect::<Vec<_>>(),
            )
        };

        // ── sidebar ──────────────────────────────────────────────────────
        egui::SidePanel::left("sidebar")
            .exact_width(SIDEBAR_W)
            .resizable(false)
            .frame(egui::Frame::none().fill(CLR_BG).inner_margin(Margin::symmetric(0.0, 0.0)))
            .show(ctx, |ui| {
                ui.set_min_height(ui.available_height());
                ui.add_space(18.0);

                ui.vertical_centered(|ui| {
                    ui.label(RichText::new("⬡").size(30.0).color(CLR_ACCENT));
                    ui.label(RichText::new("NetMon").size(15.5).strong().color(CLR_TEXT_BRIGHT));
                    ui.add_space(2.0);
                    ui.horizontal(|ui| {
                        ui.add_space(20.0);
                        if connected {
                            ui.colored_label(CLR_ACCENT, "●");
                            ui.label(RichText::new("LIVE").size(11.0).color(CLR_ACCENT).strong());
                        } else if snap.is_some() {
                            ui.colored_label(Color32::from_rgb(0xe7, 0xa2, 0x3d), "●");
                            ui.label(
                                RichText::new("STALE")
                                    .size(11.0)
                                    .color(Color32::from_rgb(0xe7, 0xa2, 0x3d))
                                    .strong(),
                            );
                        } else {
                            ui.colored_label(CLR_RED, "●");
                            ui.label(RichText::new("No feed").size(11.0).color(CLR_RED));
                        }
                    });
                });

                ui.add_space(16.0);
                ui.add(egui::Separator::default().spacing(0.0));
                ui.add_space(6.0);

                let entries: &[(Tab, &str, &str)] = &[
                    (Tab::Dashboard,  "⊞", "Dashboard"),
                    (Tab::Flows,      "⇄", "Flows"),
                    (Tab::Processes,  "◈", "Processes"),
                    (Tab::Audit,      "◎", "Audit"),
                    (Tab::Control,    "⚙", "Control"),
                    (Tab::Settings,   "◇", "Settings"),
                ];

                for &(tab, icon, label) in entries {
                    let selected = self.active_tab == tab;
                    let bg = if selected {
                        Color32::from_rgb(0x37, 0x37, 0x3d)
                    } else {
                        Color32::TRANSPARENT
                    };
                    let text_color = if selected { CLR_ACCENT } else { CLR_MUTED };

                    let full_label = format!("  {icon}  {label}");
                    let response = egui::Frame::none()
                        .fill(bg)
                        .inner_margin(Margin::symmetric(0.0, 7.0))
                        .show(ui, |ui| {
                            ui.set_min_width(SIDEBAR_W);
                            if selected {
                                let rect = ui.available_rect_before_wrap();
                                ui.painter().rect_filled(
                                    egui::Rect::from_min_size(rect.min, Vec2::new(3.0, 30.0)),
                                    Rounding::ZERO,
                                    CLR_ACCENT,
                                );
                            }
                            ui.add_space(2.0);
                            ui.label(RichText::new(full_label).size(13.5).color(text_color));
                        })
                        .response;

                    if response.interact(egui::Sense::click()).clicked() {
                        self.active_tab = tab;
                    }
                }

                // alert badge at bottom
                let remaining = ui.available_height() - 64.0;
                if remaining > 0.0 { ui.add_space(remaining); }

                ui.add(egui::Separator::default().spacing(0.0));
                ui.add_space(6.0);

                if !alert_log.is_empty() {
                    let resp = egui::Frame::none()
                        .fill(Color32::from_rgba_premultiplied(0xf0, 0x4f, 0x4f, 0x28))
                        .stroke(Stroke::new(1.0, Color32::from_rgba_premultiplied(0xf0, 0x4f, 0x4f, 0x60)))
                        .rounding(Rounding::same(6.0))
                        .inner_margin(Margin::symmetric(8.0, 6.0))
                        .show(ui, |ui| {
                            ui.set_min_width(SIDEBAR_W - 16.0);
                            ui.horizontal(|ui| {
                                ui.colored_label(CLR_RED, "⚠");
                                ui.label(RichText::new(format!("{} alert(s)", alert_log.len()))
                                    .size(11.5).color(CLR_RED));
                            });
                        })
                        .response;
                    if resp.interact(egui::Sense::click()).clicked() {
                        self.active_tab = Tab::Audit;
                    }
                } else {
                    ui.horizontal(|ui| {
                        ui.add_space(12.0);
                        ui.colored_label(CLR_GREEN, "✓");
                        ui.label(RichText::new("No alerts").size(11.0).color(CLR_MUTED));
                    });
                }
                ui.add_space(8.0);
            });

        // ── topbar ───────────────────────────────────────────────────────
        egui::TopBottomPanel::top("topbar")
            .frame(egui::Frame::none()
                .fill(CLR_PANEL)
                .stroke(Stroke::new(1.0, CLR_BORDER))
                .inner_margin(Margin::symmetric(16.0, 8.0)))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let tab_name = match self.active_tab {
                        Tab::Dashboard  => "Dashboard",
                        Tab::Flows      => "Flows",
                        Tab::Processes  => "Process & User Correlation",
                        Tab::Audit      => "Audit & Alerts",
                        Tab::Control    => "Policy Control",
                        Tab::Settings   => "Settings",
                    };
                    ui.label(RichText::new(tab_name).size(16.0).strong().color(CLR_TEXT_BRIGHT));

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if let Some(ref s) = snap {
                            ui.colored_label(CLR_MUTED, fmt_ts_ms(s.ts_unix_ms));
                            ui.separator();
                            let sid = &s.session.session_id;
                            let short = &sid[..8.min(sid.len())];
                            ui.colored_label(CLR_MUTED, format!("session: {short}"));
                            ui.separator();
                            ui.colored_label(CLR_MUTED, format!("iface: {}", s.iface));
                        } else if snap.is_none() {
                            ui.colored_label(CLR_RED,
                                RichText::new("Waiting for kernel-spy export socket…").size(12.0));
                        }
                    });
                });
            });

        // ── main content ─────────────────────────────────────────────────
        egui::CentralPanel::default()
            .frame(egui::Frame::none()
                .fill(CLR_BG)
                .inner_margin(Margin::same(20.0)))
            .show(ctx, |ui| {
                match self.active_tab {
                    Tab::Dashboard  => self.show_dashboard(ui, snap.as_ref(), &rx_hist, &tx_hist, &port_hist, &ct_util_hist, &ct_insert_failed_hist, &nic_rx_drop_hist, &proto_hist),
                    Tab::Flows      => self.show_flows(ui, snap.as_ref()),
                    Tab::Processes  => self.show_processes(ui, snap.as_ref(), &recent_procs, &recent_users),
                    Tab::Audit      => self.show_audit(ui, snap.as_ref(), &alert_log),
                    Tab::Control    => self.show_control(ui, &rpc_result),
                    Tab::Settings   => self.show_settings(ui, snap.as_ref()),
                }
            });
    }
}

// ── Dashboard helpers ────────────────────────────────────────────────────────

fn cache_age_label(now_ms: u64, marker_ms: u64) -> String {
    if marker_ms == 0 {
        return "—".to_string();
    }
    let d = now_ms.saturating_sub(marker_ms);
    if d < 1500 {
        "fresh".to_string()
    } else if d < 60_000 {
        format!("{}s", d / 1000)
    } else if d < 3_600_000 {
        format!("{}m", d / 60_000)
    } else {
        format!("{}h", d / 3_600_000)
    }
}

fn glance_strip(ui: &mut Ui, snap: &MonitorSnapshotV1) {
    let nic_rx_drop: u64 = snap.nic_stats_delta.iter().map(|r| r.rx_dropped).sum();
    let nft_age = if snap.probe_status.nftables_ready {
        cache_age_label(snap.ts_unix_ms, snap.collector_cache.nft_rules_last_ok_unix_ms)
    } else {
        "off".to_string()
    };
    let proc_age = cache_age_label(snap.ts_unix_ms, snap.collector_cache.proc_inode_cache_unix_ms);
    egui::Frame::none()
        .fill(CLR_PANEL)
        .stroke(Stroke::new(1.0, CLR_BORDER))
        .rounding(Rounding::same(8.0))
        .inner_margin(Margin::same(14.0))
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                glance_item(ui, "IFACE", &snap.iface, CLR_BLUE_LIGHT);
                glance_item(
                    ui,
                    "coverage",
                    &format!("{:.1}% attrib", snap.attribution_coverage_percent),
                    if snap.attribution_coverage_percent >= 80.0 {
                        CLR_GREEN
                    } else {
                        CLR_YELLOW
                    },
                );
                glance_item(
                    ui,
                    "alerts/tick",
                    &snap.alerts.len().to_string(),
                    if snap.alerts.is_empty() {
                        CLR_GREEN
                    } else {
                        CLR_YELLOW
                    },
                );
                glance_item(
                    ui,
                    "conntrack",
                    &format!("{:.1}% util", snap.conntrack.utilization_percent),
                    if snap.conntrack.utilization_percent < 70.0 {
                        CLR_GREEN
                    } else {
                        CLR_YELLOW
                    },
                );
                glance_item(ui, "softnet_drop/tick", &snap.softnet_delta.dropped.to_string(), CLR_MUTED);
                glance_item(ui, "nic rx_drop Δ", &nic_rx_drop.to_string(), CLR_MUTED);
                glance_item(
                    ui,
                    "tick",
                    &format!("{} ms", snap.collector_tick.tick_wall_ms),
                    CLR_MUTED,
                );
                glance_item(ui, "nft Δ", &nft_age, CLR_MUTED);
                glance_item(ui, "proc Δ", &proc_age, CLR_MUTED);
            });
        });
}

fn glance_item(ui: &mut Ui, k: &str, v: &str, vc: Color32) {
    ui.vertical(|ui| {
        ui.label(RichText::new(k).small().color(CLR_MUTED));
        ui.label(RichText::new(v).size(13.5).strong().color(vc));
    });
    ui.add_space(14.0);
}

fn proto_bars_filtered(
    ui: &mut Ui,
    cl: &ProtoSnapshot,
    proto_total: u64,
    show_zeros: bool,
) {
    let rows: &[(&str, u64, Color32)] = &[
        ("TCP", cl.tcp_bytes, CLR_BLUE_LIGHT),
        ("UDP", cl.udp_bytes, CLR_BLUE_MID),
        ("ICMP", cl.icmp_bytes, CLR_BLUE_DIM),
        ("ICMPv6", cl.icmpv6_bytes, CLR_BLUE_DIM),
        ("IGMP", cl.igmp_bytes, CLR_PURPLE),
        ("GRE", cl.gre_bytes, CLR_PURPLE),
        ("SCTP", cl.sctp_bytes, CLR_PURPLE),
        ("ESP", cl.esp_bytes, CLR_ORANGE),
        ("AH", cl.ah_bytes, CLR_MUTED),
        ("Other", cl.other_bytes, CLR_MUTED),
    ];
    egui::Frame::none()
        .fill(CLR_CARD)
        .stroke(Stroke::new(1.0, CLR_BORDER))
        .rounding(Rounding::same(8.0))
        .inner_margin(Margin::same(10.0))
        .show(ui, |ui| {
            for &(name, bytes, col) in rows {
                if !show_zeros && bytes == 0 && name != "Other" && name != "TCP" && name != "UDP"
                {
                    continue;
                }
                if !show_zeros && bytes == 0 && (name == "Other") {
                    continue;
                }
                proto_bar(ui, name, bytes, proto_total, col);
                ui.add_space(4.0);
            }
        });
}

fn kernel_metrics_grid(ui: &mut Ui, snap: &MonitorSnapshotV1) {
    let nic_rx_delta: u64 = snap.nic_stats_delta.iter().map(|r| r.rx_dropped).sum();
    let nic_tx_delta: u64 = snap.nic_stats_delta.iter().map(|r| r.tx_dropped).sum();
    egui::Frame::none()
        .fill(CLR_CARD)
        .stroke(Stroke::new(1.0, CLR_BORDER))
        .rounding(Rounding::same(8.0))
        .inner_margin(Margin::same(12.0))
        .show(ui, |ui| {
            egui::ScrollArea::horizontal().show(ui, |ui| {
                egui::Grid::new("kernel_snap_grid")
                    .striped(true)
                    .spacing([20.0, 6.0])
                    .show(ui, |ui| {
                        ui.label(RichText::new("Metric").small().strong());
                        ui.label(RichText::new("Absolute / counters").small().strong());
                        ui.label(RichText::new("Δ / tick").small().strong());
                        ui.end_row();

                        ui.label("Conntrack entries");
                        ui.label(format!("{} / {}", snap.conntrack.count, snap.conntrack.max.max(1)));
                        ui.label("—");
                        ui.end_row();
                        ui.label("Conntrack util");
                        ui.label(format!("{:.1}%", snap.conntrack.utilization_percent));
                        ui.label(format!(
                            "+{} insert_fail  +{} drops",
                            snap.conntrack_delta.insert_failed,
                            snap.conntrack_delta.drop
                        ));
                        ui.end_row();
                        ui.label("Softnet");
                        ui.monospace(format!(
                            "dropped {}",
                            snap.softnet.dropped
                        ));
                        ui.monospace(format!("Δ {}", snap.softnet_delta.dropped));
                        ui.end_row();
                        ui.label("TCP stack (TcpExt)");
                        ui.monospace(format!(
                            "timeouts {}",
                            snap.tcp_kernel.tcp_timeouts
                        ));
                        ui.monospace(format!(
                            "overflows {} LIST drop {} backlog {}",
                            snap.tcp_kernel_delta.listen_overflows,
                            snap.tcp_kernel_delta.listen_drops,
                            snap.tcp_kernel_delta.tcp_backlog_drop
                        ));
                        ui.end_row();
                        ui.label("Handshake");
                        ui.monospace(format!(
                            "syn_retrans {}",
                            snap.tcp_handshake.syn_retrans
                        ));
                        ui.monospace(format!(
                            "syncookies {}Δ  failed {}Δ",
                            snap.tcp_handshake_delta.syncookies_sent,
                            snap.tcp_handshake_delta.syncookies_failed,
                        ));
                        ui.end_row();
                        ui.label("NIC drops (Δ)");
                        ui.label(format!(
                            "cumulative netdev rx:{} tx:?",
                            snap.health.netdev_rx_dropped.unwrap_or(0),
                        ));
                        ui.monospace(format!("rxΔ {nic_rx_delta}  txΔ {nic_tx_delta}"));
                        ui.end_row();
                        ui.label("IP frag/reasm");
                        ui.monospace(format!(
                            "reasmFails {}",
                            snap.ip_frag.reasm_fails,
                        ));
                        ui.monospace(format!(
                            "reasmFails {}Δ fragFails {}Δ",
                            snap.ip_frag_delta.reasm_fails,
                            snap.ip_frag_delta.frag_fails,
                        ));
                        ui.end_row();
                        ui.label("Socket pressure");
                        ui.monospace(format!(
                            "tcp_mem {} orphans {}",
                            snap.socket_pressure.tcp_mem,
                            snap.socket_pressure.tcp_orphan
                        ));
                        ui.label(format!("TW {}", snap.socket_pressure.tcp_tw));
                        ui.end_row();
                    });
            });
        });
}

fn dashboard_trend_plot(
    ui: &mut Ui,
    id: &str,
    title_line: &str,
    points: &[[f64; 2]],
    line_color: Color32,
    warn: Option<f64>,
    crit: Option<f64>,
    _y_hint: &str,
) {
    if points.is_empty() {
        ui.label(RichText::new(format!("{title_line} — waiting for samples…")).small().color(CLR_MUTED));
        return;
    }
    let min_x = points.first().map(|p| p[0]).unwrap_or(0.0);
    let max_x = points.last().map(|p| p[0]).unwrap_or(min_x + 1.0);
    egui::Frame::none()
        .fill(CLR_CARD)
        .stroke(Stroke::new(1.0, CLR_BORDER))
        .rounding(Rounding::same(8.0))
        .inner_margin(Margin::same(8.0))
        .show(ui, |ui| {
            ui.label(RichText::new(title_line).size(11.5).color(CLR_MUTED));
            Plot::new(id)
                .height(150.0)
                .allow_boxed_zoom(false)
                .allow_drag(false)
                .allow_scroll(false)
                .allow_zoom(false)
                .include_y(0.0)
                .show_axes([true, true])
                .legend(Legend::default())
                .show(ui, |pui| {
                    if let Some(y) = warn {
                        pui.line(
                            Line::new(PlotPoints::new(vec![[min_x, y], [max_x, y]]))
                                .color(CLR_YELLOW.gamma_multiply(0.7))
                                .name("Warn")
                                .width(1.0),
                        );
                    }
                    if let Some(y) = crit {
                        pui.line(
                            Line::new(PlotPoints::new(vec![[min_x, y], [max_x, y]]))
                                .color(CLR_RED.gamma_multiply(0.85))
                                .name("Critical")
                                .width(1.0),
                        );
                    }
                    pui.line(
                        Line::new(PlotPoints::new(points.to_vec()))
                            .color(line_color)
                            .name("value")
                            .width(2.0),
                    );
                });
        });
}

// ── Dashboard ────────────────────────────────────────────────────────────────

impl App {
    fn show_dashboard(
        &mut self,
        ui: &mut Ui,
        snap: Option<&MonitorSnapshotV1>,
        rx_hist: &[[f64; 2]],
        tx_hist: &[[f64; 2]],
        port_hist: &[[f64; 2]],
        ct_util_hist: &[[f64; 2]],
        _ct_insert_failed_hist: &[[f64; 2]],
        nic_rx_drop_hist: &[[f64; 2]],
        proto_hist: &[ProtoSnapshot],
    ) {
        let Some(snap) = snap else {
            ui.centered_and_justified(|ui| {
                ui.label(
                    RichText::new("No data — is kernel-spy running without --no-export-socket?")
                        .size(16.0).color(CLR_MUTED),
                );
            });
            return;
        };

        let mut sel_port = self.state.lock().unwrap().selected_port;

        egui::ScrollArea::vertical().show(ui, |ui| {
        // compute protocol totals for current tick
        let mut all_flows: Vec<FlowRow> = snap.flows_rx.clone();
        all_flows.extend_from_slice(&snap.flows_tx);
        let cl = classify_flow_bytes(&all_flows);
        let proto_total = cl.tcp_bytes
            .saturating_add(cl.udp_bytes)
            .saturating_add(cl.icmp_bytes)
            .saturating_add(cl.icmpv6_bytes)
            .saturating_add(cl.igmp_bytes)
            .saturating_add(cl.gre_bytes)
            .saturating_add(cl.sctp_bytes)
            .saturating_add(cl.esp_bytes)
            .saturating_add(cl.ah_bytes)
            .saturating_add(cl.other_bytes);

        let mut ports_seen: BTreeSet<u16> = BTreeSet::new();
        for f in all_flows.iter() {
            if f.src_port != 0 {
                ports_seen.insert(f.src_port);
            }
            if f.dst_port != 0 {
                ports_seen.insert(f.dst_port);
            }
        }
        let port_list: Vec<u16> = ports_seen.into_iter().take(48).collect();


            ui.spacing_mut().item_spacing = Vec2::new(14.0, 12.0);

            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("View").small().color(CLR_MUTED));
                let pages = [
                    (DashboardPage::Overview, "Overview"),
                    (DashboardPage::Traffic, "Traffic"),
                    (DashboardPage::Attribution, "Attribution"),
                    (DashboardPage::KernelHealth, "Kernel health"),
                ];
                for (page, lab) in pages {
                    let sel = self.dashboard_page == page;
                    let r = ui.selectable_label(sel, RichText::new(lab).strong().size(13.5));
                    if r.clicked() {
                        self.dashboard_page = page;
                    }
                }
            });

            egui::CollapsingHeader::new(RichText::new("Display options").strong().size(12.5))
                .default_open(false)
                .show(ui, |ui| {
                    ui.checkbox(&mut self.dash_show_proto_zeros, "Show zero-byte protocols (Traffic)");
                    ui.checkbox(&mut self.dash_show_overview_extended, "Show extended diagnostics (Overview)");
                });

            ui.add_space(4.0);
            glance_strip(ui, snap);

            match self.dashboard_page {
                DashboardPage::Overview => {
                    section_header(ui, "Throughput & coverage");
                    ui.add_space(8.0);
                    ui.horizontal_wrapped(|ui| {
                        big_stat(ui, "↓ RX Pkts", &snap.rx.packets.to_string(), CLR_BLUE_LIGHT);
                        big_stat(ui, "↓ RX Bytes", &fmt_bytes(snap.rx.bytes), CLR_ACCENT);
                        big_stat(ui, "↑ TX Pkts", &snap.tx.packets.to_string(), CLR_BLUE_MID);
                        big_stat(ui, "↑ TX Bytes", &fmt_bytes(snap.tx.bytes), CLR_BLUE_LIGHT);
                        big_stat(
                            ui,
                            "Attribution",
                            &format!("{:.1}%", snap.attribution_coverage_percent),
                            if snap.attribution_coverage_percent >= 80.0 {
                                CLR_GREEN
                            } else {
                                CLR_YELLOW
                            },
                        );
                    });

                    ui.add_space(14.0);
                    section_header(ui, "Probe status");
                    ui.add_space(6.0);
                    ui.horizontal_wrapped(|ui| {
                        let ps = &snap.probe_status;
                        probe_pill(ui, "XDP", ps.xdp_attached);
                        probe_pill(ui, "TC egress", ps.tc_egress_attached);
                        probe_pill(ui, "tcp_retransmit", ps.tcp_retransmit_trace_attached);
                        probe_pill(ui, "nftables", ps.nftables_ready);
                    });
                    for err in &snap.probe_status.errors {
                        ui.colored_label(CLR_YELLOW, format!("⚠ {err}"));
                    }

                    if self.dash_show_overview_extended {
                        ui.add_space(14.0);
                        section_header(ui, "Diagnostics (tick deltas)");
                        ui.add_space(6.0);
                        ui.horizontal_wrapped(|ui| {
                            health_pill(ui, "TCP retr", snap.health.tcp_retransmit_skb);
                            health_pill(ui, "Policy drops", snap.health.policy_drops);
                            health_pill(ui, "TCP timeoutsΔ", snap.tcp_kernel_delta.tcp_timeouts);
                            health_pill(ui, "Listen overflowΔ", snap.tcp_kernel_delta.listen_overflows);
                            health_pill(ui, "Softnet droppedΔ", snap.softnet_delta.dropped);
                            if let Some(v) = snap.health.netdev_rx_dropped {
                                health_pill(ui, "NIC rx dropΣ", v);
                            }
                        });
                    }

                    if !snap.alerts.is_empty() {
                        ui.add_space(14.0);
                        section_header(ui, "Alerts (this snapshot)");
                        ui.add_space(6.0);
                        for a in &snap.alerts {
                            alert_row(ui, a);
                        }
                    }
                }
                DashboardPage::Traffic => {
                    section_header(ui, "Live throughput");
                    ui.add_space(6.0);
                    let rx_rate = rx_hist.last().map(|p| p[1]).unwrap_or(0.0);
                    let tx_rate = tx_hist.last().map(|p| p[1]).unwrap_or(0.0);
                    let port_rate = port_hist.last().map(|p| p[1]).unwrap_or(0.0);
                    ui.horizontal(|ui| {
                        rate_badge(ui, "↓ RX", rx_rate, CLR_BLUE_LIGHT);
                        ui.add_space(12.0);
                        rate_badge(ui, "↑ TX", tx_rate, CLR_ACCENT);
                        if sel_port.is_some() {
                            ui.add_space(12.0);
                            rate_badge(ui, "Port Σ", port_rate, CLR_BLUE_LIGHT);
                        }
                    });
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("Highlight port flow sum (flows matching src/dst)")
                                .size(11.5)
                                .color(CLR_MUTED),
                        );
                        egui::ComboBox::from_id_salt("dash_mon_port")
                            .width(112.0)
                            .selected_text(match sel_port {
                                None => "None".into(),
                                Some(p) => p.to_string(),
                            })
                            .show_ui(ui, |ui| {
                                if ui.selectable_label(sel_port.is_none(), "None").clicked() {
                                    sel_port = None;
                                }
                                for &pp in &port_list {
                                    if ui
                                        .selectable_label(sel_port == Some(pp), pp.to_string())
                                        .clicked()
                                    {
                                        sel_port = Some(pp);
                                    }
                                }
                            });
                    });
                    egui::Frame::none()
                        .fill(CLR_CARD)
                        .stroke(Stroke::new(1.0, CLR_BORDER))
                        .rounding(Rounding::same(8.0))
                        .inner_margin(Margin::same(10.0))
                        .show(ui, |ui| {
                            Plot::new("dash_throughput")
                                .height(280.0)
                                .include_y(0.0)
                                .legend(Legend::default())
                                .x_axis_label("Elapsed (s)")
                                .y_axis_label("Bytes/s")
                                .show(ui, |pui| {
                                    if !rx_hist.is_empty() {
                                        pui.line(
                                            Line::new(PlotPoints::new(rx_hist.to_vec()))
                                                .color(CLR_BLUE_LIGHT)
                                                .name("RX (B/s)")
                                                .width(2.0),
                                        );
                                    }
                                    if !tx_hist.is_empty() {
                                        pui.line(
                                            Line::new(PlotPoints::new(tx_hist.to_vec()))
                                                .color(CLR_ACCENT)
                                                .name("TX (B/s)")
                                                .width(2.0),
                                        );
                                    }
                                    if sel_port.is_some() && !port_hist.is_empty() {
                                        let nm = format!("Flows port {} (B/s)", sel_port.unwrap());
                                        pui.line(
                                            Line::new(PlotPoints::new(port_hist.to_vec()))
                                                .color(CLR_BLUE_LIGHT)
                                                .name(nm)
                                                .width(1.8),
                                        );
                                    }
                                });
                        });

                    ui.add_space(16.0);
                    section_header(ui, "Protocol shares (this tick)");
                    ui.add_space(6.0);
                    proto_bars_filtered(ui, &cl, proto_total, self.dash_show_proto_zeros);

                    ui.add_space(16.0);
                    section_header(ui, "Protocols over elapsed time");
                    ui.add_space(6.0);
                    egui::Frame::none()
                        .fill(CLR_CARD)
                        .stroke(Stroke::new(1.0, CLR_BORDER))
                        .rounding(Rounding::same(8.0))
                        .inner_margin(Margin::same(10.0))
                        .show(ui, |ui| {
                            Plot::new("dash_proto_hist")
                                .height(210.0)
                                .include_y(0.0)
                                .legend(Legend::default())
                                .x_axis_label("Elapsed (s)")
                                .y_axis_label("Bytes")
                                .show(ui, |pui| {
                                    if proto_hist.is_empty() {
                                        return;
                                    }
                                    let tcp_pts: Vec<[f64; 2]> =
                                        proto_hist.iter().map(|p| [p.elapsed, p.tcp_bytes as f64]).collect();
                                    let udp_pts: Vec<[f64; 2]> =
                                        proto_hist.iter().map(|p| [p.elapsed, p.udp_bytes as f64]).collect();
                                    let icmp_pts: Vec<[f64; 2]> =
                                        proto_hist.iter().map(|p| [p.elapsed, p.icmp_bytes as f64]).collect();
                                    let icmpv6_pts: Vec<[f64; 2]> =
                                        proto_hist.iter().map(|p| [p.elapsed, p.icmpv6_bytes as f64]).collect();
                                    let rest_pts: Vec<[f64; 2]> = proto_hist
                                        .iter()
                                        .map(|p| {
                                            let r = p.igmp_bytes
                                                .saturating_add(p.gre_bytes)
                                                .saturating_add(p.sctp_bytes)
                                                .saturating_add(p.esp_bytes)
                                                .saturating_add(p.ah_bytes)
                                                .saturating_add(p.other_bytes);
                                            [p.elapsed, r as f64]
                                        })
                                        .collect();
                                    pui.line(Line::new(PlotPoints::new(tcp_pts))
                                        .color(CLR_BLUE_LIGHT)
                                        .name("TCP")
                                        .width(1.5));
                                    pui.line(Line::new(PlotPoints::new(udp_pts))
                                        .color(CLR_BLUE_MID)
                                        .name("UDP")
                                        .width(1.5));
                                    pui.line(Line::new(PlotPoints::new(icmp_pts))
                                        .color(CLR_BLUE_DIM)
                                        .name("ICMP")
                                        .width(1.5));
                                    pui.line(Line::new(PlotPoints::new(icmpv6_pts))
                                        .color(CLR_PURPLE)
                                        .name("ICMPv6")
                                        .width(1.5));
                                    pui.line(Line::new(PlotPoints::new(rest_pts))
                                        .color(CLR_MUTED)
                                        .name("Other L4+")
                                        .width(1.2));
                                });
                        });

                    ui.add_space(16.0);
                    section_header(ui, "Top processes (this snapshot)");
                    ui.add_space(6.0);
                    egui::Frame::none()
                        .fill(CLR_CARD)
                        .stroke(Stroke::new(1.0, CLR_BORDER))
                        .rounding(Rounding::same(8.0))
                        .inner_margin(Margin::same(12.0))
                        .show(ui, |ui| {
                            if snap.aggregates_by_pid.is_empty() {
                                ui.colored_label(CLR_MUTED, "No PID attribution rows yet.");
                            } else {
                                for row in snap.aggregates_by_pid.iter().take(8) {
                                    let comm = row.comm.as_deref().unwrap_or("?");
                                    ui.horizontal(|ui| {
                                        ui.monospace(format!("{}", row.pid));
                                        ui.label(RichText::new(comm).strong().color(CLR_ACCENT));
                                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                            ui.label(
                                                RichText::new(fmt_bytes(row.bytes_total))
                                                    .color(CLR_TEXT),
                                            );
                                            ui.label(
                                                RichText::new(format!("{:.0}% ", row.share_percent))
                                                    .color(CLR_MUTED),
                                            );
                                        });
                                    });
                                    ui.add(egui::ProgressBar::new(
                                        (row.share_percent as f32 / 100.0).clamp(0.0, 1.0),
                                    )
                                    .fill(CLR_ACCENT));
                                    ui.add_space(8.0);
                                }
                            }
                        });
                }
                DashboardPage::Attribution => {
                    section_header(ui, "Attribution overview");
                    ui.add_space(8.0);
                    egui::Frame::none()
                        .fill(CLR_PANEL)
                        .rounding(Rounding::same(10.0))
                        .inner_margin(Margin::same(16.0))
                        .stroke(Stroke::new(1.0, CLR_BORDER))
                        .show(ui, |ui| {
                            ui.label(
                                RichText::new(format!(
                                    "{:.1}% of sampled flows mapped to UID/PID/context",
                                    snap.attribution_coverage_percent
                                ))
                                .size(15.0)
                                .strong()
                                .color(CLR_TEXT_BRIGHT),
                            );
                        });

                    ui.add_space(16.0);
                    section_header(ui, "Unresolved attribution buckets");
                    ui.add_space(6.0);
                    egui::Frame::none()
                        .fill(CLR_CARD)
                        .stroke(Stroke::new(1.0, CLR_BORDER))
                        .rounding(Rounding::same(8.0))
                        .inner_margin(Margin::same(12.0))
                        .show(ui, |ui| {
                            if snap.unknown_attribution_buckets.is_empty() {
                                ui.colored_label(CLR_GREEN, "All sampled flows accounted for ✓");
                            } else {
                                egui::Grid::new("unk_attr")
                                    .striped(true)
                                    .spacing([18.0, 8.0])
                                    .show(ui, |ui| {
                                        ui.label(RichText::new("Signal").weak());
                                        ui.label(RichText::new("Flows").weak());
                                        ui.end_row();
                                        for bucket in &snap.unknown_attribution_buckets {
                                            ui.monospace(&bucket.kind);
                                            ui.label(bucket.count.to_string());
                                            ui.end_row();
                                        }
                                    });
                            }
                        });

                    ui.add_space(16.0);
                    section_header(ui, "Workload pressure — cgroup aggregates");
                    ui.add_space(6.0);
                    egui::Frame::none()
                        .fill(CLR_CARD)
                        .stroke(Stroke::new(1.0, CLR_BORDER))
                        .rounding(Rounding::same(8.0))
                        .inner_margin(Margin::same(12.0))
                        .show(ui, |ui| {
                            if snap.cgroup_pressure.is_empty() {
                                ui.colored_label(CLR_MUTED, "No cgroup hints on sampled flows.");
                            } else {
                                for row in snap.cgroup_pressure.iter().take(12) {
                                    ui.horizontal(|ui| {
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(&row.cgroup).small().weak(),
                                            )
                                            .truncate(),
                                        );
                                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                            ui.label(
                                                RichText::new(fmt_bytes(row.bytes_total))
                                                    .strong(),
                                            );
                                        });
                                    });
                                }
                            }
                        });
                }
                DashboardPage::KernelHealth => {
                    ui.label(
                        RichText::new(
                            "Snapshot + per-tick deltas from /proc counters. Charts use your Settings thresholds.",
                        )
                        .small()
                        .color(CLR_MUTED),
                    );
                    ui.add_space(8.0);
                    kernel_metrics_grid(ui, snap);

                    ui.add_space(16.0);
                    let ct_w = self
                        .alert_conntrack_util_warn_input
                        .trim()
                        .parse::<f64>()
                        .ok();
                    let ct_c = self
                        .alert_conntrack_util_crit_input
                        .trim()
                        .parse::<f64>()
                        .ok();
                    let nic_w = self
                        .alert_nic_rx_dropped_warn_input
                        .trim()
                        .parse::<f64>()
                        .ok();
                    let nic_c = self
                        .alert_nic_rx_dropped_crit_input
                        .trim()
                        .parse::<f64>()
                        .ok();

                    dashboard_trend_plot(
                        ui,
                        "kern_ct_util_wide",
                        "Conntrack utilization % vs warn/critical (elapsed s)",
                        ct_util_hist,
                        CLR_BLUE_LIGHT,
                        ct_w,
                        ct_c,
                        "",
                    );
                    dashboard_trend_plot(
                        ui,
                        "kern_nic_drop_wide",
                        "NIC Σ rx_dropped Δ/tick vs warn/critical (elapsed s)",
                        nic_rx_drop_hist,
                        CLR_ORANGE,
                        nic_w,
                        nic_c,
                        "",
                    );

                    egui::CollapsingHeader::new(
                        RichText::new("More: drop attribution & taxonomy").small().strong(),
                    )
                    .default_open(false)
                    .show(ui, |ui| {
                        egui::Grid::new("drop_tax")
                            .striped(true)
                            .spacing([18.0, 6.0])
                            .show(ui, |ui| {
                                if snap.drop_reasons.is_empty() {
                                    ui.colored_label(CLR_MUTED, "No drop signals this tick.");
                                } else {
                                    for row in &snap.drop_reasons {
                                        ui.monospace(&row.reason);
                                        ui.label(format!(
                                            "{}   ({:.0}%)",
                                            row.count_delta, row.percent
                                        ));
                                        ui.end_row();
                                    }
                                }
                            });
                    });
                }
            }
        });
        if let Ok(mut s) = self.state.lock() {
            s.selected_port = sel_port;
        }
    }

    fn show_flows(&mut self, ui: &mut Ui, snap: Option<&MonitorSnapshotV1>) {
        let flow_scroll_h = (ui.ctx().screen_rect().height() * 0.50).clamp(420.0, 820.0);
        let Some(snap) = snap else {
            ui.centered_and_justified(|ui| {
                ui.label(RichText::new("No data yet.").size(16.0).color(CLR_MUTED));
            });
            return;
        };

        egui::ScrollArea::vertical().show(ui, |ui| {
            // filter bar
            ui.horizontal(|ui| {
                ui.label(RichText::new("🔍").size(14.0));
                ui.add(egui::TextEdit::singleline(&mut self.flow_filter)
                    .hint_text("Filter: IP, port, protocol, user, gid — or pid:1234 …")
                    .desired_width(520.0));
                if !self.flow_filter.is_empty() {
                    if styled_btn(ui, "✕ Clear").clicked() {
                        self.flow_filter.clear();
                    }
                }
            });
            ui.add_space(8.0);
            egui::CollapsingHeader::new(
                RichText::new("Attribution: /proc vs L3-only protocols").strong().size(12.0),
            )
            .default_open(false)
            .show(ui, |ui| {
                ui.label(RichText::new(
                    "• TCP/UDP (kernel-spy): match the flow to a line in /proc/net/tcp, tcp6, udp, or udp6 → read socket inode → resolve owning PID by scanning /proc/<pid>/fd for socket:[inode]; then /proc/<pid>/status (Uid:) plus passwd maps the user on each FlowRow.\n\
                     • Fallbacks: eBPF local-TCP-sport map, then merged ss -p output (see --ss-netns).\n\
                     • ICMP / similar: not in those /proc tables — label shows L3 · no socket.\n\
                     • Settings has iface / netns copy-paste hints.",
                ).size(11.0).color(CLR_MUTED));
            });
            ui.add_space(10.0);

            let filter_lc = self.flow_filter.trim().to_lowercase();

            fn filter_flows<'a>(rows: &'a [FlowRow], filter_lc: &str) -> (Vec<&'a FlowRow>, usize) {
                if let Some(rest) = filter_lc.strip_prefix("pid:") {
                    if let Ok(want) = rest.trim().parse::<u32>() {
                        let filtered: Vec<&'a FlowRow> = rows
                            .iter()
                            .filter(|r| r.local_pid == Some(want))
                            .collect();
                        let hidden = rows.len().saturating_sub(filtered.len());
                        return (filtered, hidden);
                    }
                }
                if filter_lc.is_empty() {
                    return (rows.iter().collect(), 0);
                }
                let filtered: Vec<&'a FlowRow> = rows
                    .iter()
                    .filter(|r| {
                        r.src_ip.to_lowercase().contains(filter_lc)
                            || r.dst_ip.to_lowercase().contains(filter_lc)
                            || r.src_port.to_string().contains(filter_lc)
                            || r.dst_port.to_string().contains(filter_lc)
                            || r.protocol.to_lowercase().contains(filter_lc)
                            || r.local_username.as_deref().unwrap_or("").to_lowercase().contains(filter_lc)
                            || r.local_comm.as_deref().unwrap_or("").to_lowercase().contains(filter_lc)
                            || r.local_gid
                                .map(|g| filter_lc.contains(&g.to_string()))
                                .unwrap_or(false)
                            || r.local_pid
                                .map(|p| filter_lc.contains(&p.to_string()))
                                .unwrap_or(false)
                    })
                    .collect();
                let hidden = rows.len().saturating_sub(filtered.len());
                (filtered, hidden)
            }

            let (rx_filtered, rx_hidden) = filter_flows(&snap.flows_rx, &filter_lc);
            let (tx_filtered, tx_hidden) = filter_flows(&snap.flows_tx, &filter_lc);

            ui.columns(2, |cols| {
                cols[0].vertical(|ui| {
                    ui.horizontal(|ui| {
                        section_header(ui, "RX Flows");
                        ui.add_space(6.0);
                        count_badge(ui, rx_filtered.len());
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if export_btn(ui, "Export CSV →").clicked() {
                                let r = self.rpc("export_flows_csv", serde_json::json!({
                                    "path": "/tmp/netmon-flows-export.csv"
                                }));
                                self.set_rpc_result(r);
                            }
                        });
                    });
                    ui.add_space(4.0);
                    if rx_hidden > 0 {
                        ui.colored_label(CLR_MUTED, format!("→ {rx_hidden} RX rows hidden by filter"));
                    }
                    egui::ScrollArea::vertical()
                        .id_salt("flows_rx_scroll")
                        .max_height(flow_scroll_h)
                        .show(ui, |ui| {
                            flow_table_filtered(ui, &rx_filtered, "rx_tbl");
                        });
                });

                cols[1].vertical(|ui| {
                    ui.horizontal(|ui| {
                        section_header(ui, "TX Flows");
                        ui.add_space(6.0);
                        count_badge(ui, tx_filtered.len());
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if export_btn(ui, "Export CSV →").clicked() {
                                let r = self.rpc("export_flows_csv", serde_json::json!({
                                    "path": "/tmp/netmon-flows-tx-export.csv"
                                }));
                                self.set_rpc_result(r);
                            }
                        });
                    });
                    ui.add_space(4.0);
                    if tx_hidden > 0 {
                        ui.colored_label(CLR_MUTED, format!("→ {tx_hidden} TX rows hidden by filter"));
                    }
                    egui::ScrollArea::vertical()
                        .id_salt("flows_tx_scroll")
                        .max_height(flow_scroll_h)
                        .show(ui, |ui| {
                            flow_table_filtered(ui, &tx_filtered, "tx_tbl");
                        });
                });
            });
        });
    }

    fn show_processes(
        &mut self,
        ui: &mut Ui,
        snap: Option<&MonitorSnapshotV1>,
        recent_procs: &[ProcessTrafficRow],
        recent_users: &[UserTrafficRow],
    ) {
        let Some(snap) = snap else {
            ui.centered_and_justified(|ui| {
                ui.label(RichText::new("No data yet.").size(16.0).color(CLR_MUTED));
            });
            return;
        };

        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.colored_label(
                CLR_MUTED,
                "Aggregates sum every flow in the snapshot (up to kernel-spy --max-flow-rows per direction). \
                 The Flows table can list the same rows (capped for UI scroll). \
                 Recent sightings below are a rolling history across ticks, so a PID may appear there without a visible row in the latest flow list.",
            );
            ui.add_space(8.0);
            egui::CollapsingHeader::new(
                RichText::new("How TCP/UDP maps to process and user (Linux /proc)").strong().size(12.0),
            )
            .default_open(true)
            .show(ui, |ui| {
                ui.label(RichText::new(
                    "1. /proc/net/tcp and /proc/net/tcp6 list local and remote endpoints plus a socket inode for each ESTABLISHED (and related) row; UDP uses /proc/net/udp and udp6.\n\
                     2. kernel-spy walks /proc/<pid>/fd and resolves socket:[<inode>] symlinks to learn which PID owns that inode.\n\
                     3. With a PID, it reads /proc/<pid>/status (Uid: line) and resolves the username from the system user database — that populates per-flow user fields and the user aggregates here.",
                ).size(11.0).color(CLR_MUTED));
            });
            ui.add_space(10.0);

        // top two-column
        ui.columns(2, |cols| {
            let ui = &mut cols[0];
            section_header(ui, "Processes (this tick)");
            ui.add_space(6.0);
            if snap.aggregates_by_pid.is_empty() {
                ui.colored_label(CLR_MUTED, "No process attribution yet.");
            } else {
                proc_table_bars(ui, &snap.aggregates_by_pid, "proc_top", |pid| {
                    self.flow_filter = format!("pid:{pid}");
                    self.active_tab = Tab::Flows;
                });
            }

            let ui = &mut cols[1];
            section_header(ui, "Users (this tick)");
            ui.add_space(6.0);
            if snap.aggregates_by_user.is_empty() {
                ui.colored_label(CLR_MUTED, "No user attribution yet.");
            } else {
                user_table_bars(ui, &snap.aggregates_by_user, "user_top");
            }
        });

        ui.add_space(18.0);

        // recent sightings
        ui.columns(2, |cols| {
            let ui = &mut cols[0];
            section_header(ui, "Recent Process Sightings");
            ui.add_space(6.0);
            egui::Frame::none()
                .fill(CLR_CARD)
                .stroke(Stroke::new(1.0, CLR_BORDER))
                .rounding(Rounding::same(8.0))
                .inner_margin(Margin::same(8.0))
                .show(ui, |ui| {
                    if recent_procs.is_empty() {
                        ui.colored_label(CLR_MUTED, "None yet.");
                    } else {
                        for row in recent_procs.iter().take(14) {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(fmt_ts_ms(row.ts_unix_ms))
                                    .monospace().size(10.5).color(CLR_MUTED));
                                ui.add_space(4.0);
                                ui.label(RichText::new(format!("pid {}", row.pid))
                                    .size(11.5).color(CLR_TEXT));
                                ui.colored_label(CLR_ACCENT,
                                    RichText::new(row.comm.as_deref().unwrap_or("—")).size(12.0));
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    ui.label(RichText::new(fmt_bytes(row.bytes_total))
                                        .size(11.5).color(CLR_BLUE_LIGHT));
                                });
                            });
                        }
                    }
                });

            let ui = &mut cols[1];
            section_header(ui, "Recent User Sightings");
            ui.add_space(6.0);
            egui::Frame::none()
                .fill(CLR_CARD)
                .stroke(Stroke::new(1.0, CLR_BORDER))
                .rounding(Rounding::same(8.0))
                .inner_margin(Margin::same(8.0))
                .show(ui, |ui| {
                    if recent_users.is_empty() {
                        ui.colored_label(CLR_MUTED, "None yet.");
                    } else {
                        for row in recent_users.iter().take(14) {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(fmt_ts_ms(row.ts_unix_ms))
                                    .monospace().size(10.5).color(CLR_MUTED));
                                ui.add_space(4.0);
                                ui.label(RichText::new(format!("uid {}", row.uid))
                                    .size(11.5).color(CLR_TEXT));
                                ui.colored_label(CLR_ACCENT,
                                    RichText::new(row.username.as_deref().unwrap_or("—")).size(12.0));
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    ui.label(RichText::new(fmt_bytes(row.bytes_total))
                                        .size(11.5).color(CLR_BLUE_LIGHT));
                                });
                            });
                        }
                    }
                });
        });

        // historical aggregates
        if !snap.aggregate_history_by_pid.is_empty() || !snap.aggregate_history_by_user.is_empty() {
            ui.add_space(18.0);
            section_header(ui, "Historical Aggregates");
            ui.add_space(6.0);
            ui.columns(2, |cols| {
                let ui = &mut cols[0];
                ui.label(RichText::new("Process History").strong().color(CLR_TEXT));
                ui.add_space(4.0);
                egui::Frame::none()
                    .fill(CLR_CARD).stroke(Stroke::new(1.0, CLR_BORDER))
                    .rounding(Rounding::same(6.0)).inner_margin(Margin::same(8.0))
                    .show(ui, |ui| {
                        for row in snap.aggregate_history_by_pid.iter().take(10) {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(fmt_ts_ms(row.ts_unix_ms))
                                    .monospace().size(10.5).color(CLR_MUTED));
                                ui.colored_label(CLR_ACCENT,
                                    RichText::new(row.comm.as_deref().unwrap_or("—")).size(11.5));
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    ui.colored_label(CLR_BLUE_LIGHT,
                                        RichText::new(fmt_bytes(row.bytes_total)).size(11.5));
                                });
                            });
                        }
                    });

                let ui = &mut cols[1];
                ui.label(RichText::new("User History").strong().color(CLR_TEXT));
                ui.add_space(4.0);
                egui::Frame::none()
                    .fill(CLR_CARD).stroke(Stroke::new(1.0, CLR_BORDER))
                    .rounding(Rounding::same(6.0)).inner_margin(Margin::same(8.0))
                    .show(ui, |ui| {
                        for row in snap.aggregate_history_by_user.iter().take(10) {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(fmt_ts_ms(row.ts_unix_ms))
                                    .monospace().size(10.5).color(CLR_MUTED));
                                ui.colored_label(CLR_ACCENT,
                                    RichText::new(row.username.as_deref().unwrap_or("—")).size(11.5));
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    ui.colored_label(CLR_BLUE_LIGHT,
                                        RichText::new(fmt_bytes(row.bytes_total)).size(11.5));
                                });
                            });
                        }
                    });
            });
        }
    });
    }

    fn show_settings(&mut self, ui: &mut Ui, snap: Option<&MonitorSnapshotV1>) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            section_header(ui, "Interface (kernel-spy)");
            ui.add_space(8.0);
            ui.colored_label(
                CLR_MUTED,
                "The monitored interface is chosen when kernel-spy starts (CLI -i/--iface or config file). \
                 Changing it requires restarting kernel-spy on the desired interface.",
            );
            ui.add_space(12.0);
            if let Some(s) = snap {
                kv_pair(ui, "Active iface", &s.iface);
                ui.add_space(10.0);
                section_header(ui, "Process & user attribution (TCP/UDP via /proc)");
                ui.add_space(4.0);
                ui.label(RichText::new(
                    "By default, kernel-spy correlates sockets using /proc/net/tcp|tcp6|udp|udp6, inode → /proc/*/fd, then \
                     /proc/<pid>/status for Uid. If the Flows tab shows “—” while traffic is in another network namespace, run kernel-spy with \
                     --ss-netns <name> so ss merges `ip netns exec <name> ss …` with the host. Check `ip netns list` or your runtime docs for names.",
                ).size(11.0).color(CLR_MUTED));
                ui.add_space(10.0);
                let suggested = format!(
                    "kernel-spy -i {} --export-socket /tmp/ipc-netmon.sock --control-socket /tmp/ipc-netmon-ctl.sock",
                    s.iface
                );
                let suggested_netns = format!("{suggested} --ss-netns <your-netns>");
                ui.horizontal(|ui| {
                    if ui.button(RichText::new("Copy start command").color(CLR_ACCENT)).clicked() {
                        ui.output_mut(|o| o.copied_text = suggested.clone());
                    }
                    if ui.button(RichText::new("Copy + --ss-netns template").color(CLR_ACCENT)).clicked() {
                        ui.output_mut(|o| o.copied_text = suggested_netns.clone());
                    }
                });
                ui.add_space(6.0);
                egui::Frame::none()
                    .fill(CLR_CARD)
                    .stroke(Stroke::new(1.0, CLR_BORDER))
                    .rounding(Rounding::same(6.0))
                    .inner_margin(Margin::same(10.0))
                    .show(ui, |ui| {
                        ui.label(RichText::new(&suggested).monospace().small().color(CLR_TEXT));
                        ui.add_space(4.0);
                        ui.label(RichText::new(&suggested_netns).monospace().small().color(CLR_MUTED));
                    });
            } else {
                ui.colored_label(CLR_MUTED, "No snapshot yet — start kernel-spy to see iface.");
            }
            ui.add_space(14.0);
            section_header(ui, "Live Alert Thresholds");
            ui.add_space(6.0);
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("softnet warn").color(CLR_MUTED));
                ui.add(egui::TextEdit::singleline(&mut self.alert_softnet_warn_input).desired_width(90.0));
                ui.label(RichText::new("softnet critical").color(CLR_MUTED));
                ui.add(egui::TextEdit::singleline(&mut self.alert_softnet_crit_input).desired_width(90.0));
            });
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("listen warn").color(CLR_MUTED));
                ui.add(egui::TextEdit::singleline(&mut self.alert_listen_warn_input).desired_width(90.0));
                ui.label(RichText::new("listen critical").color(CLR_MUTED));
                ui.add(egui::TextEdit::singleline(&mut self.alert_listen_crit_input).desired_width(90.0));
            });
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("conntrack util warn %").color(CLR_MUTED));
                ui.add(egui::TextEdit::singleline(&mut self.alert_conntrack_util_warn_input).desired_width(90.0));
                ui.label(RichText::new("conntrack util critical %").color(CLR_MUTED));
                ui.add(egui::TextEdit::singleline(&mut self.alert_conntrack_util_crit_input).desired_width(90.0));
            });
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("conntrack insert_failed warn").color(CLR_MUTED));
                ui.add(egui::TextEdit::singleline(&mut self.alert_conntrack_insert_failed_warn_input).desired_width(90.0));
                ui.label(RichText::new("conntrack insert_failed critical").color(CLR_MUTED));
                ui.add(egui::TextEdit::singleline(&mut self.alert_conntrack_insert_failed_crit_input).desired_width(90.0));
            });
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("NIC rx_dropped warn").color(CLR_MUTED));
                ui.add(egui::TextEdit::singleline(&mut self.alert_nic_rx_dropped_warn_input).desired_width(90.0));
                ui.label(RichText::new("NIC rx_dropped critical").color(CLR_MUTED));
                ui.add(egui::TextEdit::singleline(&mut self.alert_nic_rx_dropped_crit_input).desired_width(90.0));
            });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if styled_btn(ui, "Load current").clicked() {
                    let r = self.rpc("alert_thresholds_get", serde_json::Value::Null);
                    self.set_rpc_result(r.clone());
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&r) {
                        if let Some(d) = v.get("data") {
                            if let Some(x) = d.get("softnet_warn_per_tick").and_then(|x| x.as_u64()) {
                                self.alert_softnet_warn_input = x.to_string();
                            }
                            if let Some(x) = d.get("softnet_crit_per_tick").and_then(|x| x.as_u64()) {
                                self.alert_softnet_crit_input = x.to_string();
                            }
                            if let Some(x) = d.get("listen_warn_per_tick").and_then(|x| x.as_u64()) {
                                self.alert_listen_warn_input = x.to_string();
                            }
                            if let Some(x) = d.get("listen_crit_per_tick").and_then(|x| x.as_u64()) {
                                self.alert_listen_crit_input = x.to_string();
                            }
                            if let Some(x) = d.get("conntrack_util_warn_percent").and_then(|x| x.as_u64()) {
                                self.alert_conntrack_util_warn_input = x.to_string();
                            }
                            if let Some(x) = d.get("conntrack_util_crit_percent").and_then(|x| x.as_u64()) {
                                self.alert_conntrack_util_crit_input = x.to_string();
                            }
                            if let Some(x) = d.get("conntrack_insert_failed_warn_per_tick").and_then(|x| x.as_u64()) {
                                self.alert_conntrack_insert_failed_warn_input = x.to_string();
                            }
                            if let Some(x) = d.get("conntrack_insert_failed_crit_per_tick").and_then(|x| x.as_u64()) {
                                self.alert_conntrack_insert_failed_crit_input = x.to_string();
                            }
                            if let Some(x) = d.get("nic_rx_dropped_warn_per_tick").and_then(|x| x.as_u64()) {
                                self.alert_nic_rx_dropped_warn_input = x.to_string();
                            }
                            if let Some(x) = d.get("nic_rx_dropped_crit_per_tick").and_then(|x| x.as_u64()) {
                                self.alert_nic_rx_dropped_crit_input = x.to_string();
                            }
                        }
                    }
                }
                if styled_btn(ui, "Apply live").clicked() {
                    let r = self.rpc(
                        "alert_thresholds_set",
                        serde_json::json!({
                            "softnet_warn_per_tick": self.alert_softnet_warn_input.trim().parse::<u64>().ok(),
                            "softnet_crit_per_tick": self.alert_softnet_crit_input.trim().parse::<u64>().ok(),
                            "listen_warn_per_tick": self.alert_listen_warn_input.trim().parse::<u64>().ok(),
                            "listen_crit_per_tick": self.alert_listen_crit_input.trim().parse::<u64>().ok(),
                            "conntrack_util_warn_percent": self.alert_conntrack_util_warn_input.trim().parse::<u64>().ok(),
                            "conntrack_util_crit_percent": self.alert_conntrack_util_crit_input.trim().parse::<u64>().ok(),
                            "conntrack_insert_failed_warn_per_tick": self.alert_conntrack_insert_failed_warn_input.trim().parse::<u64>().ok(),
                            "conntrack_insert_failed_crit_per_tick": self.alert_conntrack_insert_failed_crit_input.trim().parse::<u64>().ok(),
                            "nic_rx_dropped_warn_per_tick": self.alert_nic_rx_dropped_warn_input.trim().parse::<u64>().ok(),
                            "nic_rx_dropped_crit_per_tick": self.alert_nic_rx_dropped_crit_input.trim().parse::<u64>().ok()
                        }),
                    );
                    self.set_rpc_result(r);
                }
            });
        });
    }

    fn show_audit(&mut self, ui: &mut Ui, snap: Option<&MonitorSnapshotV1>, alert_log: &[AlertEvent]) {
        let Some(snap) = snap else {
            ui.centered_and_justified(|ui| {
                ui.label(RichText::new("No data yet.").size(16.0).color(CLR_MUTED));
            });
            return;
        };

        egui::ScrollArea::vertical().show(ui, |ui| {
            // session info card
            egui::Frame::none()
                .fill(CLR_CARD)
                .stroke(Stroke::new(1.0, CLR_BORDER))
                .rounding(Rounding::same(8.0))
                .inner_margin(Margin::same(14.0))
                .show(ui, |ui| {
                    ui.label(RichText::new("Session").strong().size(13.5).color(CLR_MUTED));
                    ui.add_space(6.0);
                    ui.horizontal_wrapped(|ui| {
                        kv_pair(ui, "Session ID",   &snap.session.session_id);
                        ui.add_space(8.0);
                        ui.separator();
                        ui.add_space(8.0);
                        kv_pair(ui, "Snapshot",     &fmt_ts_ms(snap.ts_unix_ms));
                        ui.add_space(8.0);
                        ui.separator();
                        ui.add_space(8.0);
                        kv_pair(ui, "Probe errors", &snap.probe_status.errors.len().to_string());
                        ui.add_space(8.0);
                        ui.separator();
                        ui.add_space(8.0);
                        kv_pair(ui, "Alert count",  &alert_log.len().to_string());
                    });
                });

            ui.add_space(16.0);

            // alerts section header with export button
            ui.horizontal(|ui| {
                section_header(ui, "Alerts");
                ui.add_space(6.0);
                if !alert_log.is_empty() {
                    count_badge(ui, alert_log.len());
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if export_btn(ui, "Export Alerts CSV →").clicked() {
                        let r = self.rpc("export_alerts_csv", serde_json::json!({
                            "path": "/tmp/netmon-alerts-export.csv"
                        }));
                        self.set_rpc_result(r);
                    }
                });
            });
            ui.add_space(6.0);

            if alert_log.is_empty() {
                egui::Frame::none()
                    .fill(CLR_CARD).stroke(Stroke::new(1.0, CLR_BORDER))
                    .rounding(Rounding::same(8.0)).inner_margin(Margin::same(14.0))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.colored_label(CLR_GREEN, "✓");
                            ui.colored_label(CLR_GREEN, "No alerts recorded this session.");
                        });
                    });
            } else {
                egui::Frame::none()
                    .fill(CLR_CARD)
                    .stroke(Stroke::new(1.0, CLR_BORDER))
                    .rounding(Rounding::same(8.0))
                    .inner_margin(Margin::same(8.0))
                    .show(ui, |ui| {
                        egui::ScrollArea::vertical()
                            .max_height((ui.ctx().screen_rect().height() * 0.38).clamp(280.0, 560.0))
                            .show(ui, |ui| {
                            egui::Grid::new("audit_grid")
                                .num_columns(4)
                                .striped(true)
                                .spacing([12.0, 4.0])
                                .show(ui, |ui| {
                                    for hdr in ["Time", "Severity", "Kind", "Message"] {
                                        ui.label(RichText::new(hdr).small().strong().color(CLR_MUTED));
                                    }
                                    ui.end_row();
                                    for a in alert_log.iter().rev().take(200) {
                                        ui.label(RichText::new(fmt_ts_ms(a.ts_unix_ms)).monospace().small().color(CLR_MUTED));
                                        // severity badge
                                        let sev_color = alert_color(&a.severity);
                                        egui::Frame::none()
                                            .fill(Color32::from_rgba_premultiplied(
                                                sev_color.r(), sev_color.g(), sev_color.b(), 0x28))
                                            .rounding(Rounding::same(4.0))
                                            .inner_margin(Margin::symmetric(5.0, 2.0))
                                            .show(ui, |ui| {
                                                ui.label(RichText::new(a.severity.to_uppercase())
                                                    .small().strong().color(sev_color));
                                            });
                                        ui.label(RichText::new(&a.kind).small().color(CLR_TEXT));
                                        ui.label(RichText::new(&a.message).small().color(CLR_MUTED));
                                        ui.end_row();
                                    }
                                });
                        });
                    });
            }

            if !snap.probe_status.errors.is_empty() {
                ui.add_space(16.0);
                section_header(ui, "Probe Errors");
                ui.add_space(6.0);
                egui::Frame::none()
                    .fill(CLR_CARD).stroke(Stroke::new(1.0, CLR_BORDER))
                    .rounding(Rounding::same(8.0)).inner_margin(Margin::same(10.0))
                    .show(ui, |ui| {
                        for err in &snap.probe_status.errors {
                            ui.horizontal(|ui| {
                                ui.colored_label(CLR_YELLOW, "⚠");
                                ui.colored_label(CLR_YELLOW, err);
                            });
                        }
                    });
            }
        });
    }
}

// ── Control tab ───────────────────────────────────────────────────────────────

impl App {
    fn show_policy_simulation_card(&self, ui: &mut Ui, rpc_result: &str) {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(rpc_result) else {
            return;
        };
        let Some(data) = v.get("data") else {
            return;
        };
        if data.get("matched_flows").is_none() || data.get("matched_bytes").is_none() {
            return;
        }

        let matched_flows = data.get("matched_flows").and_then(|x| x.as_u64()).unwrap_or(0);
        let matched_bytes = data.get("matched_bytes").and_then(|x| x.as_u64()).unwrap_or(0);
        let lookback = data
            .get("lookback_minutes")
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        let confidence = data
            .get("confidence_mix")
            .and_then(|x| x.as_object())
            .cloned()
            .unwrap_or_default();
        let high_conf = confidence.get("high").and_then(|x| x.as_u64()).unwrap_or(0);
        let medium_conf = confidence
            .get("medium")
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        let low_conf = confidence.get("low").and_then(|x| x.as_u64()).unwrap_or(0);
        let none_conf = confidence.get("none").and_then(|x| x.as_u64()).unwrap_or(0);
        let uncertain_ratio = data
            .get("uncertain_ratio")
            .and_then(|x| x.as_f64())
            .unwrap_or_else(|| {
                let total_conf = high_conf + medium_conf + low_conf + none_conf;
                if total_conf == 0 {
                    1.0
                } else {
                    (low_conf + none_conf) as f64 / total_conf as f64
                }
            });
        let risk_level = data
            .get("risk_level")
            .and_then(|x| x.as_str())
            .unwrap_or("unknown");
        let recommendation = data
            .get("recommendation")
            .and_then(|x| x.as_str())
            .unwrap_or("No recommendation available.");
        let (risk_label, risk_color) = match risk_level {
            "high" => ("High risk", CLR_RED),
            "medium" => ("Medium risk", CLR_YELLOW),
            "low" => ("Low risk", CLR_GREEN),
            _ => ("Unknown", CLR_MUTED),
        };

        ui.add_space(16.0);
        section_header(ui, "Policy Simulation Summary");
        ui.add_space(6.0);
        egui::Frame::none()
            .fill(CLR_CARD)
            .stroke(Stroke::new(1.0, CLR_BORDER))
            .rounding(Rounding::same(8.0))
            .inner_margin(Margin::same(12.0))
            .show(ui, |ui| {
                let ring_n = data.get("ring_snapshot_count").and_then(|x| x.as_u64()).unwrap_or(0);
                let win_n = data
                    .get("lookback_snapshot_count")
                    .and_then(|x| x.as_u64())
                    .unwrap_or(0);
                ui.horizontal_wrapped(|ui| {
                    kv_pair(ui, "Lookback", &format!("{lookback} min"));
                    ui.separator();
                    kv_pair(ui, "Ring snaps", &ring_n.to_string());
                    ui.separator();
                    kv_pair(ui, "In window", &win_n.to_string());
                    ui.separator();
                    kv_pair(ui, "Matched flows", &matched_flows.to_string());
                    ui.separator();
                    kv_pair(ui, "Matched bytes", &fmt_bytes(matched_bytes));
                    ui.separator();
                    ui.label(RichText::new("Risk").small().color(CLR_MUTED));
                    ui.label(
                        RichText::new(risk_label)
                            .small()
                            .strong()
                            .color(risk_color),
                    );
                });
                ui.add_space(8.0);
                ui.label(RichText::new("Attribution confidence mix").small().color(CLR_MUTED));
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new(format!("high {high_conf}")).small().color(CLR_GREEN));
                    ui.label(
                        RichText::new(format!("medium {medium_conf}"))
                            .small()
                            .color(CLR_YELLOW),
                    );
                    ui.label(RichText::new(format!("low {low_conf}")).small().color(CLR_ORANGE));
                    ui.label(RichText::new(format!("none {none_conf}")).small().color(CLR_RED));
                });
                ui.label(
                    RichText::new(format!(
                        "Uncertain attribution ratio: {:.1}% — {}",
                        uncertain_ratio * 100.0,
                        recommendation
                    ))
                    .small()
                    .color(if risk_label == "High risk" { CLR_RED } else { CLR_MUTED }),
                );
                if let Some(th) = data.get("risk_thresholds").and_then(|x| x.as_object()) {
                    ui.label(
                        RichText::new(format!(
                            "Thresholds: medium_bytes={} high_bytes={} medium_ratio={:.2} high_ratio={:.2}",
                            th.get("medium_bytes").and_then(|x| x.as_u64()).unwrap_or(0),
                            th.get("high_bytes").and_then(|x| x.as_u64()).unwrap_or(0),
                            th.get("medium_uncertain_ratio").and_then(|x| x.as_f64()).unwrap_or(0.0),
                            th.get("high_uncertain_ratio").and_then(|x| x.as_f64()).unwrap_or(0.0),
                        ))
                        .small()
                        .color(CLR_MUTED),
                    );
                }

                if let Some(top_pids) = data.get("top_pids").and_then(|x| x.as_array()) {
                    if !top_pids.is_empty() {
                        ui.add_space(8.0);
                        ui.label(RichText::new("Top impacted processes").small().color(CLR_MUTED));
                        for row in top_pids.iter().take(5) {
                            let pid = row.get("pid").and_then(|x| x.as_u64()).unwrap_or(0);
                            let bytes = row.get("bytes").and_then(|x| x.as_u64()).unwrap_or(0);
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(format!("pid {pid}")).small().monospace().color(CLR_TEXT));
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    ui.label(RichText::new(fmt_bytes(bytes)).small().color(CLR_BLUE_LIGHT));
                                });
                            });
                        }
                    }
                }
                if let Some(top_uids) = data.get("top_uids").and_then(|x| x.as_array()) {
                    if !top_uids.is_empty() {
                        ui.add_space(8.0);
                        ui.label(RichText::new("Top impacted UIDs").small().color(CLR_MUTED));
                        for row in top_uids.iter().take(5) {
                            let uid = row.get("uid").and_then(|x| x.as_u64()).unwrap_or(0);
                            let bytes = row.get("bytes").and_then(|x| x.as_u64()).unwrap_or(0);
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(format!("uid {uid}")).small().monospace().color(CLR_TEXT));
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    ui.label(RichText::new(fmt_bytes(bytes)).small().color(CLR_BLUE_LIGHT));
                                });
                            });
                        }
                    }
                }
                if let Some(top_gids) = data.get("top_gids").and_then(|x| x.as_array()) {
                    if !top_gids.is_empty() {
                        ui.add_space(8.0);
                        ui.label(RichText::new("Top impacted GIDs").small().color(CLR_MUTED));
                        for row in top_gids.iter().take(5) {
                            let gid = row.get("gid").and_then(|x| x.as_u64()).unwrap_or(0);
                            let bytes = row.get("bytes").and_then(|x| x.as_u64()).unwrap_or(0);
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(format!("gid {gid}")).small().monospace().color(CLR_TEXT));
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    ui.label(RichText::new(fmt_bytes(bytes)).small().color(CLR_BLUE_LIGHT));
                                });
                            });
                        }
                    }
                }
            });
    }

    fn show_control(&mut self, ui: &mut Ui, rpc_result: &str) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.colored_label(CLR_MUTED,
                "Send control commands to kernel-spy via its JSON-RPC unix socket.");
            ui.add_space(14.0);

            control_section(ui, "Connectivity", |ui| {
                ui.horizontal(|ui| {
                    if styled_btn(ui, "Ping daemon").clicked() {
                        let r = self.rpc("ping", serde_json::Value::Null);
                        self.set_rpc_result(r);
                    }
                    if styled_btn(ui, "Session dump").clicked() {
                        let r = self.rpc("session_dump", serde_json::Value::Null);
                        self.set_rpc_result(r);
                    }
                });
            });

            ui.add_space(10.0);
            control_section(ui, "Drop / Rate-Limit by Destination IP", |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("IPv4:").color(CLR_MUTED));
                    ui.text_edit_singleline(&mut self.ip_input);
                });
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Rate:").color(CLR_MUTED));
                    ui.text_edit_singleline(&mut self.rate_input);
                });
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if styled_btn(ui, "Preview Drop").clicked() {
                        let r = self.rpc("nft_preview_drop", serde_json::json!({ "dst": self.ip_input }));
                        self.set_rpc_result(r);
                    }
                    if danger_btn(ui, "⚠ Apply Drop").clicked() {
                        let r = self.rpc("nft_apply_drop", serde_json::json!({ "dst": self.ip_input }));
                        self.set_rpc_result(r);
                    }
                    ui.add_space(8.0);
                    if styled_btn(ui, "Preview Rate Limit").clicked() {
                        let r = self.rpc("nft_preview_rate_limit",
                            serde_json::json!({ "dst": self.ip_input, "rate": self.rate_input }));
                        self.set_rpc_result(r);
                    }
                    if danger_btn(ui, "⚠ Apply Rate Limit").clicked() {
                        let r = self.rpc("nft_apply_rate_limit",
                            serde_json::json!({ "dst": self.ip_input, "rate": self.rate_input }));
                        self.set_rpc_result(r);
                    }
                });
            });

            ui.add_space(10.0);
            control_section(ui, "Policy Simulation (Blast Radius)", |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Lookback mins:").color(CLR_MUTED));
                    ui.add(egui::TextEdit::singleline(&mut self.simulate_lookback_mins).desired_width(90.0));
                });
                ui.add_space(6.0);
                if styled_btn(ui, "Simulate policy impact").clicked() {
                    let uid = self.uid_input.trim().parse::<u64>().ok();
                    let gid = self.gid_input.trim().parse::<u64>().ok();
                    let lookback_minutes = self
                        .simulate_lookback_mins
                        .trim()
                        .parse::<u64>()
                        .unwrap_or(10)
                        .max(1);
                    let r = self.rpc(
                        "policy_simulate",
                        serde_json::json!({
                            "dst": self.ip_input.trim(),
                            "uid": uid,
                            "gid": gid,
                            "lookback_minutes": lookback_minutes
                        }),
                    );
                    self.set_rpc_result(r);
                }
            });

            ui.add_space(10.0);
            control_section(ui, "Simulation Risk Thresholds", |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("medium_bytes").color(CLR_MUTED));
                    ui.add(egui::TextEdit::singleline(&mut self.sim_medium_bytes_input).desired_width(120.0));
                    ui.label(RichText::new("high_bytes").color(CLR_MUTED));
                    ui.add(egui::TextEdit::singleline(&mut self.sim_high_bytes_input).desired_width(120.0));
                });
                ui.add_space(4.0);
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("medium_ratio").color(CLR_MUTED));
                    ui.add(egui::TextEdit::singleline(&mut self.sim_medium_ratio_input).desired_width(90.0));
                    ui.label(RichText::new("high_ratio").color(CLR_MUTED));
                    ui.add(egui::TextEdit::singleline(&mut self.sim_high_ratio_input).desired_width(90.0));
                });
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if styled_btn(ui, "Load current").clicked() {
                        let r = self.rpc("policy_sim_get_thresholds", serde_json::Value::Null);
                        self.set_rpc_result(r.clone());
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&r) {
                            if let Some(d) = v.get("data") {
                                if let Some(x) = d.get("medium_bytes").and_then(|x| x.as_u64()) {
                                    self.sim_medium_bytes_input = x.to_string();
                                }
                                if let Some(x) = d.get("high_bytes").and_then(|x| x.as_u64()) {
                                    self.sim_high_bytes_input = x.to_string();
                                }
                                if let Some(x) = d.get("medium_uncertain_ratio").and_then(|x| x.as_f64()) {
                                    self.sim_medium_ratio_input = format!("{x:.2}");
                                }
                                if let Some(x) = d.get("high_uncertain_ratio").and_then(|x| x.as_f64()) {
                                    self.sim_high_ratio_input = format!("{x:.2}");
                                }
                            }
                        }
                    }
                    if styled_btn(ui, "Apply thresholds").clicked() {
                        let medium_bytes = self.sim_medium_bytes_input.trim().parse::<u64>().ok();
                        let high_bytes = self.sim_high_bytes_input.trim().parse::<u64>().ok();
                        let medium_ratio = self.sim_medium_ratio_input.trim().parse::<f64>().ok();
                        let high_ratio = self.sim_high_ratio_input.trim().parse::<f64>().ok();
                        let r = self.rpc(
                            "policy_sim_set_thresholds",
                            serde_json::json!({
                                "medium_bytes": medium_bytes,
                                "high_bytes": high_bytes,
                                "medium_uncertain_ratio": medium_ratio,
                                "high_uncertain_ratio": high_ratio
                            }),
                        );
                        self.set_rpc_result(r);
                    }
                });
            });

            ui.add_space(10.0);
            control_section(ui, "Drop by UID / GID", |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("UID:").color(CLR_MUTED));
                    ui.add(egui::TextEdit::singleline(&mut self.uid_input).desired_width(120.0));
                    if styled_btn(ui, "Preview").clicked() {
                        if let Ok(uid) = self.uid_input.trim().parse::<u64>() {
                            let r = self.rpc("nft_preview_drop_uid", serde_json::json!({ "uid": uid }));
                            self.set_rpc_result(r);
                        }
                    }
                    if danger_btn(ui, "⚠ Apply").clicked() {
                        if let Ok(uid) = self.uid_input.trim().parse::<u64>() {
                            let r = self.rpc("nft_apply_drop_uid", serde_json::json!({ "uid": uid }));
                            self.set_rpc_result(r);
                        }
                    }
                });
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label(RichText::new("GID:").color(CLR_MUTED));
                    ui.add(egui::TextEdit::singleline(&mut self.gid_input).desired_width(120.0));
                    if styled_btn(ui, "Preview").clicked() {
                        if let Ok(gid) = self.gid_input.trim().parse::<u64>() {
                            let r = self.rpc("nft_preview_drop_gid", serde_json::json!({ "gid": gid }));
                            self.set_rpc_result(r);
                        }
                    }
                    if danger_btn(ui, "⚠ Apply").clicked() {
                        if let Ok(gid) = self.gid_input.trim().parse::<u64>() {
                            let r = self.rpc("nft_apply_drop_gid", serde_json::json!({ "gid": gid }));
                            self.set_rpc_result(r);
                        }
                    }
                });
            });

            ui.add_space(10.0);
            control_section(ui, "Ruleset Rollback", |ui| {
                ui.colored_label(CLR_MUTED,
                    "Restore nftables from the backup taken before the last apply.");
                ui.add_space(6.0);
                if danger_btn(ui, "⚠ Rollback nftables").clicked() {
                    let r = self.rpc("nft_rollback", serde_json::Value::Null);
                    self.set_rpc_result(r);
                }
            });

            self.show_policy_simulation_card(ui, rpc_result);

            if !rpc_result.is_empty() {
                ui.add_space(16.0);
                section_header(ui, "Last RPC Response");
                ui.add_space(6.0);
                let pretty = serde_json::from_str::<serde_json::Value>(rpc_result)
                    .ok()
                    .and_then(|v| serde_json::to_string_pretty(&v).ok())
                    .unwrap_or_else(|| rpc_result.to_string());
                let ok = rpc_result.contains("\"ok\":true") || rpc_result.contains("\"ok\": true");
                let (status_label, status_color) = if ok {
                    ("✓  OK", CLR_GREEN)
                } else {
                    ("✗  Error / Pending", CLR_YELLOW)
                };
                ui.colored_label(status_color, RichText::new(status_label).strong());
                ui.add_space(4.0);
                egui::Frame::none()
                    .fill(Color32::from_rgb(0x1e, 0x1e, 0x1e))
                    .stroke(Stroke::new(1.0, CLR_BORDER))
                    .rounding(Rounding::same(6.0))
                    .inner_margin(Margin::same(10.0))
                    .show(ui, |ui| {
                        egui::ScrollArea::vertical()
                            .id_salt("rpc_resp_scroll")
                            .max_height(220.0)
                            .show(ui, |ui| {
                                ui.code(pretty);
                            });
                    });
            }
        });
    }
}

// ── widget helpers ────────────────────────────────────────────────────────────

fn section_header(ui: &mut Ui, text: &str) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(text).size(14.5).strong().color(CLR_TEXT_BRIGHT));
        let rect = ui.available_rect_before_wrap();
        let y = rect.min.y + 9.0;
        ui.painter().line_segment(
            [egui::pos2(rect.min.x + 4.0, y), egui::pos2(rect.max.x, y)],
            Stroke::new(1.0, CLR_BORDER),
        );
    });
}

fn big_stat(ui: &mut Ui, label: &str, value: &str, value_color: Color32) {
    egui::Frame::none()
        .fill(CLR_CARD)
        .stroke(Stroke::new(1.0, CLR_BORDER))
        .rounding(Rounding::same(10.0))
        .inner_margin(Margin::same(12.0))
        .show(ui, |ui| {
            ui.set_min_width(168.0);
            ui.vertical(|ui| {
                ui.label(RichText::new(label).size(11.5).color(CLR_MUTED));
                ui.add_space(4.0);
                ui.label(RichText::new(value).size(24.0).strong().color(value_color));
            });
        });
}

fn health_pill(ui: &mut Ui, label: &str, value: u64) {
    let (color, icon) = if value == 0 { (CLR_GREEN, "●") } else { (CLR_YELLOW, "▲") };
    egui::Frame::none()
        .fill(CLR_CARD)
        .stroke(Stroke::new(1.0, CLR_BORDER))
        .rounding(Rounding::same(20.0))
        .inner_margin(Margin::symmetric(10.0, 4.0))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.colored_label(color, icon);
                ui.label(RichText::new(format!("{label}: {value}")).size(12.0).color(CLR_TEXT));
            });
        });
}

fn probe_pill(ui: &mut Ui, label: &str, attached: bool) {
    let (color, icon) = if attached { (CLR_GREEN, "✓") } else { (CLR_RED, "✗") };
    egui::Frame::none()
        .fill(CLR_CARD)
        .stroke(Stroke::new(1.0, CLR_BORDER))
        .rounding(Rounding::same(20.0))
        .inner_margin(Margin::symmetric(10.0, 4.0))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.colored_label(color, icon);
                ui.label(RichText::new(label).size(12.0).color(CLR_TEXT));
            });
        });
}

fn rate_badge(ui: &mut Ui, label: &str, bps: f64, color: Color32) {
    egui::Frame::none()
        .fill(CLR_CARD)
        .stroke(Stroke::new(1.0, CLR_BORDER))
        .rounding(Rounding::same(6.0))
        .inner_margin(Margin::symmetric(12.0, 6.0))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(label).size(12.0).color(CLR_MUTED));
                ui.label(RichText::new(fmt_rate(bps)).size(15.0).strong().color(color));
            });
        });
}

fn sparkline(
    ui: &mut Ui,
    id: &str,
    points: &[[f64; 2]],
    color: Color32,
    warn: Option<f64>,
    crit: Option<f64>,
) {
    if points.is_empty() {
        ui.label(RichText::new("no trend yet").small().color(CLR_MUTED));
        return;
    }
    let min_x = points.first().map(|p| p[0]).unwrap_or(0.0);
    let max_x = points.last().map(|p| p[0]).unwrap_or(min_x + 1.0);
    Plot::new(id)
        .height(46.0)
        .allow_boxed_zoom(false)
        .allow_drag(false)
        .allow_scroll(false)
        .allow_zoom(false)
        .show_axes([false, false])
        .show_grid([false, false])
        .show(ui, |pui| {
            if let Some(y) = warn {
                pui.line(
                    Line::new(PlotPoints::new(vec![[min_x, y], [max_x, y]]))
                        .color(CLR_YELLOW.gamma_multiply(0.75))
                        .width(1.0),
                );
            }
            if let Some(y) = crit {
                pui.line(
                    Line::new(PlotPoints::new(vec![[min_x, y], [max_x, y]]))
                        .color(CLR_RED.gamma_multiply(0.85))
                        .width(1.0),
                );
            }
            pui.line(
                Line::new(PlotPoints::new(points.to_vec()))
                    .color(color)
                    .width(1.8),
            );
        });
}

fn count_badge(ui: &mut Ui, count: usize) {
    egui::Frame::none()
        .fill(Color32::from_rgb(0x4e, 0x9f, 0xff).gamma_multiply(0.15))
        .stroke(Stroke::new(1.0, CLR_ACCENT))
        .rounding(Rounding::same(10.0))
        .inner_margin(Margin::symmetric(7.0, 2.0))
        .show(ui, |ui| {
            ui.label(RichText::new(count.to_string()).size(11.0).color(CLR_ACCENT).strong());
        });
}

fn export_btn(ui: &mut Ui, label: &str) -> egui::Response {
    ui.add(egui::Button::new(RichText::new(label).size(12.0).color(CLR_ACCENT))
        .fill(Color32::from_rgba_premultiplied(0x4e, 0x9f, 0xff, 0x18))
        .stroke(Stroke::new(1.0, Color32::from_rgba_premultiplied(0x4e, 0x9f, 0xff, 0x80)))
        .rounding(Rounding::same(6.0)))
}

fn proto_bar(ui: &mut Ui, label: &str, bytes: u64, total: u64, color: Color32) {
    let frac = if total > 0 { bytes as f32 / total as f32 } else { 0.0 };
    ui.horizontal(|ui| {
        ui.set_min_width(ui.available_width());
        // label
        ui.add(egui::Label::new(
            RichText::new(label).size(11.5).color(CLR_MUTED)
        ));
        ui.add_space(4.0);
        // bar
        let bar_w = (ui.available_width() - 100.0).max(10.0);
        let fill_w = bar_w * frac;
        let (rect, _) = ui.allocate_exact_size(Vec2::new(bar_w, 14.0), egui::Sense::hover());
        ui.painter().rect_filled(rect, Rounding::same(3.0), CLR_BG);
        if fill_w > 0.0 {
            ui.painter().rect_filled(
                egui::Rect::from_min_size(rect.min, Vec2::new(fill_w, 14.0)),
                Rounding::same(3.0),
                color,
            );
        }
        ui.add_space(6.0);
        ui.label(RichText::new(fmt_bytes(bytes)).size(11.5).color(CLR_TEXT));
        ui.add_space(4.0);
        ui.label(RichText::new(format!("{:.1}%", frac * 100.0)).size(10.5).color(CLR_MUTED));
    });
}

fn alert_row(ui: &mut Ui, a: &AlertEvent) {
    let sev_color = alert_color(&a.severity);
    egui::Frame::none()
        .fill(Color32::from_rgba_premultiplied(
            sev_color.r(), sev_color.g(), sev_color.b(), 0x18))
        .stroke(Stroke::new(1.0, Color32::from_rgba_premultiplied(
            sev_color.r(), sev_color.g(), sev_color.b(), 0x60)))
        .rounding(Rounding::same(6.0))
        .inner_margin(Margin::symmetric(10.0, 5.0))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.colored_label(sev_color, RichText::new(a.severity.to_uppercase()).strong().size(11.0));
                ui.label(RichText::new(&a.kind).size(12.0).color(CLR_TEXT));
                ui.label(RichText::new(&a.message).size(12.0).color(CLR_MUTED));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(RichText::new(fmt_ts_ms(a.ts_unix_ms)).monospace().small().color(CLR_MUTED));
                });
            });
        });
}

fn kv_pair(ui: &mut Ui, key: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(key).size(11.5).color(CLR_MUTED));
        ui.label(RichText::new(value).size(11.5).monospace().color(CLR_TEXT));
    });
}

fn flow_table_filtered(ui: &mut Ui, rows: &[&FlowRow], id: &str) {
    if rows.is_empty() {
        ui.colored_label(CLR_MUTED, "No flows match.");
        return;
    }
    let n_total = rows.len();
    let n_show = n_total.min(FLOW_TABLE_MAX_ROWS);
    ui.colored_label(
        CLR_MUTED,
        format!("Showing {n_show} of {n_total} matching flows (cap {FLOW_TABLE_MAX_ROWS} per table)."),
    );
    ui.add_space(4.0);
    egui::Frame::none()
        .fill(CLR_CARD)
        .stroke(Stroke::new(1.0, CLR_BORDER))
        .rounding(Rounding::same(8.0))
        .inner_margin(Margin::same(8.0))
        .show(ui, |ui| {
            egui::Grid::new(id)
                .num_columns(5)
                .striped(true)
                .spacing([10.0, 3.0])
                .show(ui, |ui| {
                    for hdr in ["Protocol", "Src IP:Port", "Dst IP:Port", "Bytes"] {
                        ui.label(RichText::new(hdr).small().strong().color(CLR_MUTED));
                    }
                    let pr = ui.label(RichText::new("Process / User").small().strong().color(CLR_MUTED));
                    pr.on_hover_text(
                        "Shows task name (/proc/…/comm), login, pid, uid when kernel-spy resolves them. Hover unattributed cells for hints.",
                    );
                    ui.end_row();
                    for row in rows.iter().take(FLOW_TABLE_MAX_ROWS) {
                        // protocol badge
                        let pc = proto_color(&row.protocol);
                        egui::Frame::none()
                            .fill(Color32::from_rgba_premultiplied(pc.r(), pc.g(), pc.b(), 0x28))
                            .rounding(Rounding::same(4.0))
                            .inner_margin(Margin::symmetric(5.0, 2.0))
                            .show(ui, |ui| {
                                ui.label(RichText::new(&row.protocol).small().strong().color(pc));
                            });
                        ui.label(RichText::new(
                            format!("{}:{}", row.src_ip, row.src_port)
                        ).monospace().small().color(CLR_TEXT));
                        ui.label(RichText::new(
                            format!("{}:{}", row.dst_ip, row.dst_port)
                        ).monospace().small().color(CLR_TEXT));
                        ui.label(RichText::new(fmt_bytes(row.bytes)).small().color(CLR_BLUE_LIGHT));
                        let ar = flow_attribution_rich_text(row);
                        let resp = ui.add(egui::Label::new(ar));
                        if let Some(tip) = flow_attribution_hover(row) {
                            resp.on_hover_text(tip);
                        }
                        ui.end_row();
                    }
                });
        });
}

fn proc_table_bars<F: FnMut(u32)>(ui: &mut Ui, rows: &[ProcessTrafficRow], id_prefix: &str, mut on_flows: F) {
    egui::Frame::none()
        .fill(CLR_CARD)
        .stroke(Stroke::new(1.0, CLR_BORDER))
        .rounding(Rounding::same(8.0))
        .inner_margin(Margin::same(10.0))
        .show(ui, |ui| {
            for (i, row) in rows.iter().take(10).enumerate() {
                let comm = row.comm.as_deref().unwrap_or("unknown");
                let frac = (row.share_percent as f32 / 100.0).clamp(0.0, 1.0);
                let pid = row.pid;
                ui.push_id(format!("{id_prefix}_{i}"), |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("pid {}", row.pid))
                            .size(11.0).color(CLR_MUTED).monospace());
                        ui.label(RichText::new(comm).color(CLR_ACCENT).size(12.0));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui.small_button(RichText::new("Flows").color(CLR_ACCENT)).clicked() {
                                on_flows(pid);
                            }
                            ui.label(RichText::new(fmt_bytes(row.bytes_total))
                                .size(11.5).color(CLR_BLUE_LIGHT));
                        });
                    });
                    ui.add(egui::ProgressBar::new(frac)
                        .desired_width(ui.available_width())
                        .fill(CLR_ACCENT));
                    if i < rows.len().saturating_sub(1) { ui.add_space(6.0); }
                });
            }
        });
}

fn user_table_bars(ui: &mut Ui, rows: &[UserTrafficRow], id_prefix: &str) {
    egui::Frame::none()
        .fill(CLR_CARD)
        .stroke(Stroke::new(1.0, CLR_BORDER))
        .rounding(Rounding::same(8.0))
        .inner_margin(Margin::same(10.0))
        .show(ui, |ui| {
            for (i, row) in rows.iter().take(10).enumerate() {
                let uname = row.username.as_deref().unwrap_or("unknown");
                let frac = (row.share_percent as f32 / 100.0).clamp(0.0, 1.0);
                ui.push_id(format!("{id_prefix}_{i}"), |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("uid {}", row.uid))
                            .size(11.0).color(CLR_MUTED).monospace());
                        ui.label(RichText::new(uname).color(CLR_ACCENT).size(12.0));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(RichText::new(fmt_bytes(row.bytes_total))
                                .size(11.5).color(CLR_BLUE_LIGHT));
                        });
                    });
                    ui.add(egui::ProgressBar::new(frac)
                        .desired_width(ui.available_width())
                        .fill(CLR_ACCENT));
                    if i < rows.len().saturating_sub(1) { ui.add_space(6.0); }
                });
            }
        });
}

fn control_section(ui: &mut Ui, title: &str, content: impl FnOnce(&mut Ui)) {
    egui::Frame::none()
        .fill(CLR_CARD)
        .stroke(Stroke::new(1.0, CLR_BORDER))
        .rounding(Rounding::same(8.0))
        .inner_margin(Margin::same(14.0))
        .show(ui, |ui| {
            ui.label(RichText::new(title).strong().size(13.5).color(CLR_TEXT));
            ui.add(egui::Separator::default().spacing(6.0));
            content(ui);
        });
}

fn styled_btn(ui: &mut Ui, label: &str) -> egui::Response {
    ui.add(egui::Button::new(RichText::new(label).color(CLR_TEXT_BRIGHT))
        .fill(Color32::from_rgb(0x3c, 0x3c, 0x3c))
        .stroke(Stroke::new(1.0, CLR_BORDER))
        .rounding(Rounding::same(4.0)))
}

fn danger_btn(ui: &mut Ui, label: &str) -> egui::Response {
    ui.add(egui::Button::new(RichText::new(label).color(CLR_RED))
        .fill(Color32::from_rgba_premultiplied(0xf0, 0x4f, 0x4f, 0x20))
        .stroke(Stroke::new(1.0, Color32::from_rgba_premultiplied(0xf0, 0x4f, 0x4f, 0x80)))
        .rounding(Rounding::same(6.0)))
}

// ── background reader ─────────────────────────────────────────────────────────

fn reader_loop(state: Arc<Mutex<SharedState>>) {
    loop {
        match UnixStream::connect(EXPORT_SOCK) {
            Err(_) => {
                if let Ok(mut s) = state.lock() { s.connected = false; }
                thread::sleep(Duration::from_secs(2));
            }
            Ok(stream) => {
                { state.lock().unwrap().connected = true; }
                let reader = BufReader::new(stream);
                for line in reader.lines() {
                    let Ok(line) = line else { break };
                    if let Ok(snap) = parse_export_line(&line) {
                        if let Ok(mut s) = state.lock() { s.ingest(snap); }
                    }
                }
                if let Ok(mut s) = state.lock() { s.connected = false; }
                thread::sleep(Duration::from_secs(2));
            }
        }
    }
}

// ── entry point ───────────────────────────────────────────────────────────────

fn main() -> eframe::Result<()> {
    let state = Arc::new(Mutex::new(SharedState::new()));
    {
        let state = Arc::clone(&state);
        thread::spawn(move || reader_loop(state));
    }

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1680.0, 1050.0])
            .with_min_inner_size([1180.0, 720.0])
            .with_title("IPC Network Monitor"),
        ..Default::default()
    };

    eframe::run_native(
        "IPC Network Monitor",
        native_options,
        Box::new(|cc| Ok(Box::new(App::new(Arc::clone(&state), cc)))),
    )
}
