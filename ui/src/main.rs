//! IPC Network Monitor — Professional egui UI (v2)

use std::collections::VecDeque;
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

// ── palette ─────────────────────────────────────────────────────────────────

const CLR_BG: Color32         = Color32::from_rgb(0x0f, 0x11, 0x17);
const CLR_PANEL: Color32      = Color32::from_rgb(0x16, 0x1a, 0x26);
const CLR_CARD: Color32       = Color32::from_rgb(0x1e, 0x23, 0x33);
const CLR_BORDER: Color32     = Color32::from_rgb(0x2a, 0x31, 0x44);
const CLR_TEXT: Color32       = Color32::from_rgb(0xe0, 0xe4, 0xf0);
const CLR_MUTED: Color32      = Color32::from_rgb(0x70, 0x7a, 0x99);
const CLR_ACCENT: Color32     = Color32::from_rgb(0x4e, 0x9f, 0xff);
const CLR_GREEN: Color32      = Color32::from_rgb(0x3d, 0xd6, 0x8c);
const CLR_YELLOW: Color32     = Color32::from_rgb(0xf5, 0xc5, 0x18);
const CLR_RED: Color32        = Color32::from_rgb(0xf0, 0x4f, 0x4f);
const CLR_ORANGE: Color32     = Color32::from_rgb(0xff, 0x8c, 0x30);
const CLR_BLUE_LIGHT: Color32 = Color32::from_rgb(0x60, 0xb8, 0xff);
const CLR_PURPLE: Color32     = Color32::from_rgb(0xb0, 0x7e, 0xff);
const SIDEBAR_W: f32 = 160.0;

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

fn fmt_pid_user(pid: Option<u32>, uid: Option<u32>, username: Option<&str>) -> String {
    match (pid, uid, username) {
        (Some(p), Some(u), Some(n)) => format!("{n}  pid={p} uid={u}"),
        (Some(p), Some(u), None)    => format!("pid={p} uid={u}"),
        (Some(p), None, Some(n))    => format!("{n}  pid={p}"),
        (Some(p), None, None)       => format!("pid={p}"),
        _                           => "—".to_string(),
    }
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
        "TCP"  => CLR_BLUE_LIGHT,
        "UDP"  => CLR_YELLOW,
        "ICMP" => CLR_PURPLE,
        _      => CLR_MUTED,
    }
}

// ── protocol snapshot ────────────────────────────────────────────────────────

#[derive(Clone, Default)]
struct ProtoSnapshot {
    elapsed:     f64,
    tcp_bytes:   u64,
    udp_bytes:   u64,
    icmp_bytes:  u64,
    other_bytes: u64,
}

fn classify_flow_bytes(flows: &[FlowRow]) -> (u64, u64, u64, u64) {
    let (mut tcp, mut udp, mut icmp, mut other) = (0u64, 0u64, 0u64, 0u64);
    for f in flows {
        match f.protocol.as_str() {
            "TCP"  => tcp   += f.bytes,
            "UDP"  => udp   += f.bytes,
            "ICMP" => icmp  += f.bytes,
            _      => other += f.bytes,
        }
    }
    (tcp, udp, icmp, other)
}

// ── shared state ─────────────────────────────────────────────────────────────

struct SharedState {
    snapshot: Option<MonitorSnapshotV1>,
    recent_process_sightings: VecDeque<ProcessTrafficRow>,
    recent_user_sightings: VecDeque<UserTrafficRow>,
    rx_rate_history: VecDeque<[f64; 2]>,
    tx_rate_history: VecDeque<[f64; 2]>,
    proto_history: VecDeque<ProtoSnapshot>,
    prev_rx_bytes: Option<u64>,
    prev_tx_bytes: Option<u64>,
    prev_ts_ms: Option<u64>,
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
            proto_history: VecDeque::new(),
            prev_rx_bytes: None,
            prev_tx_bytes: None,
            prev_ts_ms: None,
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
        let elapsed = self.start.elapsed().as_secs_f64();

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
            }
        }
        self.prev_rx_bytes = Some(snap.rx.bytes);
        self.prev_tx_bytes = Some(snap.tx.bytes);
        self.prev_ts_ms    = Some(snap.ts_unix_ms);

        // Protocol breakdown snapshot
        let mut all_flows: Vec<FlowRow> = snap.flows_rx.clone();
        all_flows.extend_from_slice(&snap.flows_tx);
        let (tcp, udp, icmp, other) = classify_flow_bytes(&all_flows);
        if self.proto_history.len() >= PROTO_HISTORY_CAP { self.proto_history.pop_front(); }
        self.proto_history.push_back(ProtoSnapshot { elapsed, tcp_bytes: tcp, udp_bytes: udp, icmp_bytes: icmp, other_bytes: other });

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
enum Tab { Dashboard, Flows, Processes, Audit, Control }

struct App {
    state: Arc<Mutex<SharedState>>,
    active_tab: Tab,
    flow_filter: String,
    ip_input: String,
    rate_input: String,
    uid_input: String,
    gid_input: String,
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
    v.code_bg_color        = Color32::from_rgb(0x12, 0x16, 0x20);
    v.window_stroke        = Stroke::new(1.0, CLR_BORDER);
    v.widgets.noninteractive.bg_fill   = CLR_CARD;
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0, CLR_TEXT);
    v.widgets.inactive.bg_fill         = Color32::from_rgb(0x25, 0x2c, 0x40);
    v.widgets.inactive.fg_stroke       = Stroke::new(1.0, CLR_TEXT);
    v.widgets.hovered.bg_fill          = Color32::from_rgb(0x2e, 0x37, 0x50);
    v.widgets.active.bg_fill           = Color32::from_rgb(0x1a, 0x7a, 0x99);
    v.selection.bg_fill                = Color32::from_rgba_premultiplied(0x4e, 0x9f, 0xdd, 0x60);
    v.widgets.noninteractive.rounding  = Rounding::same(6.0);
    v.widgets.inactive.rounding        = Rounding::same(6.0);
    v.widgets.hovered.rounding         = Rounding::same(6.0);
    v.widgets.active.rounding          = Rounding::same(6.0);
    ctx.set_visuals(v);

    use egui::FontFamily::{Monospace, Proportional};
    let mut style = (*ctx.style()).clone();
    style.text_styles.insert(egui::TextStyle::Body,      FontId::new(13.5, Proportional));
    style.text_styles.insert(egui::TextStyle::Heading,   FontId::new(17.0, Proportional));
    style.text_styles.insert(egui::TextStyle::Monospace, FontId::new(12.5, Monospace));
    style.text_styles.insert(egui::TextStyle::Small,     FontId::new(11.0, Proportional));
    style.text_styles.insert(egui::TextStyle::Button,    FontId::new(13.0, Proportional));
    style.spacing.item_spacing   = Vec2::new(8.0, 6.0);
    style.spacing.button_padding = Vec2::new(10.0, 5.0);
    ctx.set_style(style);
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.request_repaint_after(Duration::from_millis(500));

        let (connected, snap, rx_hist, tx_hist, proto_hist, alert_log, rpc_result, recent_procs, recent_users) = {
            let s = self.state.lock().unwrap();
            (
                s.connected,
                s.snapshot.clone(),
                s.rx_rate_history.iter().cloned().collect::<Vec<_>>(),
                s.tx_rate_history.iter().cloned().collect::<Vec<_>>(),
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
                    ui.label(RichText::new("NetMon").size(15.5).strong().color(CLR_TEXT));
                    ui.add_space(2.0);
                    ui.horizontal(|ui| {
                        ui.add_space(20.0);
                        if connected {
                            ui.colored_label(CLR_GREEN, "●");
                            ui.label(RichText::new("LIVE").size(11.0).color(CLR_GREEN).strong());
                        } else {
                            ui.colored_label(CLR_RED, "●");
                            ui.label(RichText::new("Offline").size(11.0).color(CLR_RED));
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
                ];

                for &(tab, icon, label) in entries {
                    let selected = self.active_tab == tab;
                    let bg = if selected { Color32::from_rgb(0x1a, 0x20, 0x35) } else { Color32::TRANSPARENT };
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
                    };
                    ui.label(RichText::new(tab_name).size(15.0).strong().color(CLR_TEXT));

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if let Some(ref s) = snap {
                            ui.colored_label(CLR_MUTED, fmt_ts_ms(s.ts_unix_ms));
                            ui.separator();
                            let sid = &s.session.session_id;
                            let short = &sid[..8.min(sid.len())];
                            ui.colored_label(CLR_MUTED, format!("session: {short}"));
                            ui.separator();
                            ui.colored_label(CLR_MUTED, format!("iface: {}", s.iface));
                        } else if !connected {
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
                .inner_margin(Margin::same(16.0)))
            .show(ctx, |ui| {
                match self.active_tab {
                    Tab::Dashboard  => show_dashboard(ui, snap.as_ref(), &rx_hist, &tx_hist, &proto_hist),
                    Tab::Flows      => self.show_flows(ui, snap.as_ref()),
                    Tab::Processes  => show_processes(ui, snap.as_ref(), &recent_procs, &recent_users),
                    Tab::Audit      => self.show_audit(ui, snap.as_ref(), &alert_log),
                    Tab::Control    => self.show_control(ui, &rpc_result),
                }
            });
    }
}

// ── Dashboard ────────────────────────────────────────────────────────────────

fn show_dashboard(
    ui: &mut Ui,
    snap: Option<&MonitorSnapshotV1>,
    rx_hist: &[[f64; 2]],
    tx_hist: &[[f64; 2]],
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

    egui::ScrollArea::vertical().show(ui, |ui| {
        // compute protocol totals for current tick
        let mut all_flows: Vec<FlowRow> = snap.flows_rx.clone();
        all_flows.extend_from_slice(&snap.flows_tx);
        let (tcp_b, udp_b, icmp_b, other_b) = classify_flow_bytes(&all_flows);
        let proto_total = tcp_b + udp_b + icmp_b + other_b;

        // ── two-column layout ─────────────────────────────────────────
        let avail = ui.available_width();
        let left_w  = avail * 0.44;
        let right_w = avail * 0.54;

        ui.horizontal_top(|ui| {
            // ── LEFT COLUMN ──────────────────────────────────────────
            ui.allocate_ui(Vec2::new(left_w, ui.available_height()), |ui| {
                ui.vertical(|ui| {
                    // ── stat cards row ────────────────────────────────
                    section_header(ui, "Overview");
                    ui.add_space(6.0);
                    ui.horizontal_wrapped(|ui| {
                        big_stat(ui, "↓ RX Pkts",   &snap.rx.packets.to_string(), CLR_BLUE_LIGHT);
                        big_stat(ui, "↓ RX Bytes",  &fmt_bytes(snap.rx.bytes),    CLR_GREEN);
                        big_stat(ui, "↑ TX Pkts",   &snap.tx.packets.to_string(), CLR_ORANGE);
                        big_stat(ui, "↑ TX Bytes",  &fmt_bytes(snap.tx.bytes),    CLR_RED);
                    });

                    ui.add_space(14.0);

                    // ── health pills ──────────────────────────────────
                    section_header(ui, "Health");
                    ui.add_space(6.0);
                    ui.horizontal_wrapped(|ui| {
                        health_pill(ui, "TCP Retransmits", snap.health.tcp_retransmit_skb);
                        health_pill(ui, "Policy Drops",    snap.health.policy_drops);
                        if let Some(v) = snap.health.netdev_rx_dropped { health_pill(ui, "NIC RX Drop", v); }
                        if let Some(v) = snap.health.netdev_tx_dropped { health_pill(ui, "NIC TX Drop", v); }
                    });

                    ui.add_space(10.0);

                    // ── probe status pills ────────────────────────────
                    section_header(ui, "Probe Status");
                    ui.add_space(6.0);
                    ui.horizontal_wrapped(|ui| {
                        let ps = &snap.probe_status;
                        probe_pill(ui, "XDP",           ps.xdp_attached);
                        probe_pill(ui, "TC egress",     ps.tc_egress_attached);
                        probe_pill(ui, "tcp_retransmit",ps.tcp_retransmit_trace_attached);
                        probe_pill(ui, "nftables",      ps.nftables_ready);
                    });
                    for err in &snap.probe_status.errors {
                        ui.colored_label(CLR_YELLOW, format!("⚠ {err}"));
                    }

                    ui.add_space(14.0);

                    // ── protocol distribution ─────────────────────────
                    section_header(ui, "Protocol Distribution  (this tick)");
                    ui.add_space(6.0);
                    egui::Frame::none()
                        .fill(CLR_CARD)
                        .stroke(Stroke::new(1.0, CLR_BORDER))
                        .rounding(Rounding::same(8.0))
                        .inner_margin(Margin::same(10.0))
                        .show(ui, |ui| {
                            proto_bar(ui, "TCP",   tcp_b,   proto_total, CLR_BLUE_LIGHT);
                            ui.add_space(4.0);
                            proto_bar(ui, "UDP",   udp_b,   proto_total, CLR_YELLOW);
                            ui.add_space(4.0);
                            proto_bar(ui, "ICMP",  icmp_b,  proto_total, CLR_PURPLE);
                            ui.add_space(4.0);
                            proto_bar(ui, "Other", other_b, proto_total, CLR_MUTED);
                        });

                    // ── current-tick alerts ───────────────────────────
                    if !snap.alerts.is_empty() {
                        ui.add_space(14.0);
                        section_header(ui, "Active Alerts");
                        ui.add_space(4.0);
                        for a in &snap.alerts {
                            alert_row(ui, a);
                        }
                    }
                });
            });

            ui.add_space(12.0);

            // ── RIGHT COLUMN ─────────────────────────────────────────
            ui.allocate_ui(Vec2::new(right_w, ui.available_height()), |ui| {
                ui.vertical(|ui| {
                    // ── live throughput chart ─────────────────────────
                    section_header(ui, "Live Throughput");
                    ui.add_space(4.0);
                    let rx_rate = rx_hist.last().map(|p| p[1]).unwrap_or(0.0);
                    let tx_rate = tx_hist.last().map(|p| p[1]).unwrap_or(0.0);
                    ui.horizontal(|ui| {
                        rate_badge(ui, "↓ RX", rx_rate, CLR_GREEN);
                        ui.add_space(8.0);
                        rate_badge(ui, "↑ TX", tx_rate, CLR_ORANGE);
                    });
                    ui.add_space(6.0);
                    egui::Frame::none()
                        .fill(CLR_CARD)
                        .stroke(Stroke::new(1.0, CLR_BORDER))
                        .rounding(Rounding::same(8.0))
                        .inner_margin(Margin::same(8.0))
                        .show(ui, |ui| {
                            Plot::new("throughput")
                                .height(220.0)
                                .include_y(0.0)
                                .legend(Legend::default())
                                .x_axis_label("Elapsed (s)")
                                .y_axis_label("Bytes/s")
                                .show(ui, |pui| {
                                    if !rx_hist.is_empty() {
                                        pui.line(Line::new(PlotPoints::new(rx_hist.to_vec()))
                                            .color(CLR_GREEN).name("RX (B/s)").width(2.0));
                                    }
                                    if !tx_hist.is_empty() {
                                        pui.line(Line::new(PlotPoints::new(tx_hist.to_vec()))
                                            .color(CLR_ORANGE).name("TX (B/s)").width(2.0));
                                    }
                                });
                        });

                    ui.add_space(14.0);

                    // ── protocol breakdown over time chart ────────────
                    section_header(ui, "Protocol Breakdown over Time");
                    ui.add_space(4.0);
                    egui::Frame::none()
                        .fill(CLR_CARD)
                        .stroke(Stroke::new(1.0, CLR_BORDER))
                        .rounding(Rounding::same(8.0))
                        .inner_margin(Margin::same(8.0))
                        .show(ui, |ui| {
                            Plot::new("proto_breakdown")
                                .height(160.0)
                                .include_y(0.0)
                                .legend(Legend::default())
                                .x_axis_label("Elapsed (s)")
                                .y_axis_label("Bytes")
                                .show(ui, |pui| {
                                    if !proto_hist.is_empty() {
                                        let tcp_pts: Vec<[f64; 2]> = proto_hist.iter()
                                            .map(|p| [p.elapsed, p.tcp_bytes as f64]).collect();
                                        let udp_pts: Vec<[f64; 2]> = proto_hist.iter()
                                            .map(|p| [p.elapsed, p.udp_bytes as f64]).collect();
                                        let icmp_pts: Vec<[f64; 2]> = proto_hist.iter()
                                            .map(|p| [p.elapsed, p.icmp_bytes as f64]).collect();
                                        pui.line(Line::new(PlotPoints::new(tcp_pts))
                                            .color(CLR_BLUE_LIGHT).name("TCP").width(1.5));
                                        pui.line(Line::new(PlotPoints::new(udp_pts))
                                            .color(CLR_YELLOW).name("UDP").width(1.5));
                                        pui.line(Line::new(PlotPoints::new(icmp_pts))
                                            .color(CLR_PURPLE).name("ICMP").width(1.5));
                                    }
                                });
                        });

                    ui.add_space(14.0);

                    // ── top 5 processes ───────────────────────────────
                    section_header(ui, "Top 5 Processes");
                    ui.add_space(6.0);
                    egui::Frame::none()
                        .fill(CLR_CARD)
                        .stroke(Stroke::new(1.0, CLR_BORDER))
                        .rounding(Rounding::same(8.0))
                        .inner_margin(Margin::same(10.0))
                        .show(ui, |ui| {
                            if snap.aggregates_by_pid.is_empty() {
                                ui.colored_label(CLR_MUTED, "No process attribution yet.");
                            } else {
                                for row in snap.aggregates_by_pid.iter().take(5) {
                                    let comm = row.comm.as_deref().unwrap_or("unknown");
                                    ui.horizontal(|ui| {
                                        ui.label(RichText::new(format!("pid {}", row.pid))
                                            .size(11.0).color(CLR_MUTED).monospace());
                                        ui.add_space(4.0);
                                        ui.label(RichText::new(comm).color(CLR_ACCENT).size(12.0));
                                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                            ui.label(RichText::new(
                                                format!("{:.1}%", row.share_percent)
                                            ).size(11.0).color(CLR_MUTED));
                                            ui.add_space(4.0);
                                            ui.label(RichText::new(fmt_bytes(row.bytes_total))
                                                .size(11.5).color(CLR_GREEN));
                                        });
                                    });
                                    let frac = (row.share_percent as f32 / 100.0).clamp(0.0, 1.0);
                                    ui.add(egui::ProgressBar::new(frac)
                                        .desired_width(ui.available_width())
                                        .fill(CLR_ACCENT));
                                    ui.add_space(4.0);
                                }
                            }
                        });
                });
            });
        });
    });
}

// ── Flows tab ────────────────────────────────────────────────────────────────

impl App {
    fn show_flows(&mut self, ui: &mut Ui, snap: Option<&MonitorSnapshotV1>) {
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
                    .hint_text("Filter flows (IP, port, protocol)…")
                    .desired_width(340.0));
                if !self.flow_filter.is_empty() {
                    if styled_btn(ui, "✕ Clear").clicked() {
                        self.flow_filter.clear();
                    }
                }
            });
            ui.add_space(10.0);

            let filter = self.flow_filter.to_lowercase();

            fn filter_flows<'a>(rows: &'a [FlowRow], filter: &str) -> (Vec<&'a FlowRow>, usize) {
                if filter.is_empty() {
                    return (rows.iter().collect(), 0);
                }
                let filtered: Vec<&'a FlowRow> = rows.iter().filter(|r| {
                    r.src_ip.to_lowercase().contains(filter)
                    || r.dst_ip.to_lowercase().contains(filter)
                    || r.src_port.to_string().contains(filter)
                    || r.dst_port.to_string().contains(filter)
                    || r.protocol.to_lowercase().contains(filter)
                    || r.local_username.as_deref().unwrap_or("").to_lowercase().contains(filter)
                }).collect();
                let hidden = rows.len().saturating_sub(filtered.len());
                (filtered, hidden)
            }

            let (rx_filtered, rx_hidden) = filter_flows(&snap.flows_rx, &filter);
            let (tx_filtered, tx_hidden) = filter_flows(&snap.flows_tx, &filter);

            // RX section
            ui.horizontal(|ui| {
                section_header(ui, &format!("RX Flows"));
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
            flow_table_filtered(ui, &rx_filtered, "rx_tbl");
            if rx_hidden > 0 {
                ui.colored_label(CLR_MUTED, format!("  → {rx_hidden} more rows filtered"));
            }

            ui.add_space(16.0);

            // TX section
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
            flow_table_filtered(ui, &tx_filtered, "tx_tbl");
            if tx_hidden > 0 {
                ui.colored_label(CLR_MUTED, format!("  → {tx_hidden} more rows filtered"));
            }
        });
    }
}

// ── Processes tab ─────────────────────────────────────────────────────────────

fn show_processes(
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
        // top two-column
        ui.columns(2, |cols| {
            let ui = &mut cols[0];
            section_header(ui, "Processes (this tick)");
            ui.add_space(6.0);
            if snap.aggregates_by_pid.is_empty() {
                ui.colored_label(CLR_MUTED, "No process attribution yet.");
            } else {
                proc_table_bars(ui, &snap.aggregates_by_pid, "proc_top");
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
                                        .size(11.5).color(CLR_GREEN));
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
                                        .size(11.5).color(CLR_GREEN));
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
                                    ui.colored_label(CLR_GREEN,
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
                                    ui.colored_label(CLR_GREEN,
                                        RichText::new(fmt_bytes(row.bytes_total)).size(11.5));
                                });
                            });
                        }
                    });
            });
        }
    });
}

// ── Audit tab ─────────────────────────────────────────────────────────────────

impl App {
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
                        egui::ScrollArea::vertical().max_height(340.0).show(ui, |ui| {
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
                    .fill(Color32::from_rgb(0x12, 0x16, 0x20))
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
        ui.label(RichText::new(text).size(14.0).strong().color(CLR_TEXT));
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
            ui.set_min_width(140.0);
            ui.vertical(|ui| {
                ui.label(RichText::new(label).size(11.0).color(CLR_MUTED));
                ui.add_space(4.0);
                ui.label(RichText::new(value).size(22.0).strong().color(value_color));
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
                    for hdr in ["Protocol", "Src IP:Port", "Dst IP:Port", "Bytes", "Process / User"] {
                        ui.label(RichText::new(hdr).small().strong().color(CLR_MUTED));
                    }
                    ui.end_row();
                    for row in rows.iter().take(100) {
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
                        ui.label(RichText::new(fmt_bytes(row.bytes)).small().color(CLR_GREEN));
                        ui.label(RichText::new(
                            fmt_pid_user(row.local_pid, row.local_uid, row.local_username.as_deref())
                        ).small().color(CLR_MUTED));
                        ui.end_row();
                    }
                });
        });
}

fn proc_table_bars(ui: &mut Ui, rows: &[ProcessTrafficRow], id_prefix: &str) {
    egui::Frame::none()
        .fill(CLR_CARD)
        .stroke(Stroke::new(1.0, CLR_BORDER))
        .rounding(Rounding::same(8.0))
        .inner_margin(Margin::same(10.0))
        .show(ui, |ui| {
            for (i, row) in rows.iter().take(10).enumerate() {
                let comm = row.comm.as_deref().unwrap_or("unknown");
                let frac = (row.share_percent as f32 / 100.0).clamp(0.0, 1.0);
                ui.push_id(format!("{id_prefix}_{i}"), |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("pid {}", row.pid))
                            .size(11.0).color(CLR_MUTED).monospace());
                        ui.label(RichText::new(comm).color(CLR_ACCENT).size(12.0));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(RichText::new(fmt_bytes(row.bytes_total))
                                .size(11.5).color(CLR_GREEN));
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
                                .size(11.5).color(CLR_GREEN));
                        });
                    });
                    ui.add(egui::ProgressBar::new(frac)
                        .desired_width(ui.available_width())
                        .fill(CLR_GREEN));
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
    ui.add(egui::Button::new(RichText::new(label).color(CLR_TEXT))
        .fill(Color32::from_rgb(0x25, 0x2c, 0x44))
        .stroke(Stroke::new(1.0, CLR_BORDER))
        .rounding(Rounding::same(6.0)))
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
            .with_inner_size([1440.0, 900.0])
            .with_title("IPC Network Monitor"),
        ..Default::default()
    };

    eframe::run_native(
        "IPC Network Monitor",
        native_options,
        Box::new(|cc| Ok(Box::new(App::new(Arc::clone(&state), cc)))),
    )
}
