//! IPC network monitor

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, RichText, Ui};
use egui_plot::{Legend, Line, Plot, PlotPoints};

use common::{AlertEvent, FlowRow, MonitorSnapshotV1, parse_export_line};

const HISTORY_CAP: usize = 120;
const EXPORT_SOCK: &str = "/tmp/ipc-netmon.sock";
const CONTROL_SOCK: &str = "/tmp/ipc-netmon-ctl.sock";
const MAX_ALERT_LOG: usize = 500;

// formatting helpers

fn fmt_bytes(b: u64) -> String {
    const GIB: u64 = 1 << 30;
    const MIB: u64 = 1 << 20;
    const KIB: u64 = 1 << 10;
    if b >= GIB {
        format!("{:.2} GiB", b as f64 / GIB as f64)
    } else if b >= MIB {
        format!("{:.2} MiB", b as f64 / MIB as f64)
    } else if b >= KIB {
        format!("{:.1} KiB", b as f64 / KIB as f64)
    } else {
        format!("{b} B")
    }
}

fn fmt_rate(bytes_per_sec: f64) -> String {
    format!("{}/s", fmt_bytes(bytes_per_sec as u64))
}

fn fmt_ts_ms(ts_ms: u64) -> String {
    let secs = ts_ms / 1000;
    let h = (secs / 3600) % 24;
    let m = (secs / 60) % 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02} UTC")
}

//shared state (background thread -> GUI) 

struct SharedState {
    snapshot: Option<MonitorSnapshotV1>,
    rx_rate_history: VecDeque<[f64; 2]>, // [elapsed_secs, bytes/s]
    tx_rate_history: VecDeque<[f64; 2]>,
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
            rx_rate_history: VecDeque::new(),
            tx_rate_history: VecDeque::new(),
            prev_rx_bytes: None,
            prev_tx_bytes: None,
            prev_ts_ms: None,
            start: Instant::now(),
            connected: false,
            alert_log: Vec::new(),
            rpc_result: String::new(),
        }
    }

    fn ingest(&mut self, snap: MonitorSnapshotV1) {
        let elapsed = self.start.elapsed().as_secs_f64();

        if let (Some(prev_rx), Some(prev_tx), Some(prev_ts)) =
            (self.prev_rx_bytes, self.prev_tx_bytes, self.prev_ts_ms)
        {
            let dt = snap.ts_unix_ms.saturating_sub(prev_ts) as f64 / 1000.0;
            if dt > 0.0 {
                let rx_rate = snap.rx.bytes.saturating_sub(prev_rx) as f64 / dt;
                let tx_rate = snap.tx.bytes.saturating_sub(prev_tx) as f64 / dt;
                if self.rx_rate_history.len() >= HISTORY_CAP {
                    self.rx_rate_history.pop_front();
                }
                self.rx_rate_history.push_back([elapsed, rx_rate]);
                if self.tx_rate_history.len() >= HISTORY_CAP {
                    self.tx_rate_history.pop_front();
                }
                self.tx_rate_history.push_back([elapsed, tx_rate]);
            }
        }

        self.prev_rx_bytes = Some(snap.rx.bytes);
        self.prev_tx_bytes = Some(snap.tx.bytes);
        self.prev_ts_ms = Some(snap.ts_unix_ms);

        for alert in &snap.alerts {
            if self.alert_log.len() >= MAX_ALERT_LOG {
                self.alert_log.remove(0);
            }
            self.alert_log.push(alert.clone());
        }
        self.snapshot = Some(snap);
    }
}

//app

#[derive(PartialEq)]
enum Tab {
    Dashboard,
    Correlation,
    Control,
    Audit,
}

struct App {
    state: Arc<Mutex<SharedState>>,
    active_tab: Tab,
    ip_input: String,
    rate_input: String,
    uid_input: String,
    gid_input: String,
}

impl App {
    fn new(state: Arc<Mutex<SharedState>>) -> Self {
        Self {
            state,
            active_tab: Tab::Dashboard,
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
                if s.write_all(req.as_bytes()).is_err() {
                    return "write error".to_string();
                }
                let mut resp = String::new();
                BufReader::new(s).read_line(&mut resp).ok();
                resp.trim().to_string()
            }
        }
    }

    fn set_rpc_result(&self, result: String) {
        if let Ok(mut s) = self.state.lock() {
            s.rpc_result = result;
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.request_repaint_after(Duration::from_millis(500));

        // Pull a snapshot of all state we need for rendering
        let (connected, snap, rx_hist, tx_hist, alert_log, rpc_result) = {
            let s = self.state.lock().unwrap();
            (
                s.connected,
                s.snapshot.clone(),
                s.rx_rate_history.iter().cloned().collect::<Vec<_>>(),
                s.tx_rate_history.iter().cloned().collect::<Vec<_>>(),
                s.alert_log.clone(),
                s.rpc_result.clone(),
            )
        };

        // header bar
        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading(RichText::new("IPC Network Monitor").size(18.0).strong());
                ui.add_space(12.0);
                let (color, label) = if connected {
                    (Color32::GREEN, "● Connected")
                } else {
                    (Color32::RED, "● Disconnected")
                };
                ui.colored_label(color, label);

                if let Some(ref s) = snap {
                    ui.add_space(12.0);
                    ui.label(format!("iface: {}", s.iface));
                    ui.separator();
                    ui.label(format!("session: {}", s.session.session_id));
                    ui.separator();
                    ui.label(fmt_ts_ms(s.ts_unix_ms));
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    tab_btn(ui, "Control", &mut self.active_tab, Tab::Control);
                    tab_btn(ui, "Audit", &mut self.active_tab, Tab::Audit);
                    tab_btn(ui, "Correlation", &mut self.active_tab, Tab::Correlation);
                    tab_btn(ui, "Dashboard", &mut self.active_tab, Tab::Dashboard);
                });
            });
        });

        // alert count badge in status bar
        if !alert_log.is_empty() {
            egui::TopBottomPanel::bottom("alert_bar").show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.colored_label(
                        Color32::YELLOW,
                        format!("⚠ {} alert(s) fired this session", alert_log.len()),
                    );
                    if ui.small_button("View all").clicked() {
                        self.active_tab = Tab::Audit;
                    }
                });
            });
        }

        // main content
        egui::CentralPanel::default().show(ctx, |ui| match self.active_tab {
            Tab::Dashboard => Self::show_dashboard(ui, snap.as_ref(), &rx_hist, &tx_hist),
            Tab::Correlation => Self::show_correlation(ui, snap.as_ref()),
            Tab::Audit => Self::show_audit(ui, snap.as_ref(), &alert_log),
            Tab::Control => self.show_control(ui, &rpc_result),
        });
    }
}

// Dashboard tab

impl App {
    fn show_dashboard(
        ui: &mut Ui,
        snap: Option<&MonitorSnapshotV1>,
        rx_hist: &[[f64; 2]],
        tx_hist: &[[f64; 2]],
    ) {
        let Some(snap) = snap else {
            ui.centered_and_justified(|ui| {
                ui.label(
                    RichText::new("Waiting for data from kernel-spy…")
                        .size(18.0)
                        .color(Color32::GRAY),
                );
            });
            return;
        };

        egui::ScrollArea::vertical().show(ui, |ui| {
            // stat cards
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                stat_card(ui, "RX Packets", &snap.rx.packets.to_string(), Color32::from_rgb(0x4a, 0xaa, 0xff));
                stat_card(ui, "RX Total",   &fmt_bytes(snap.rx.bytes),    Color32::from_rgb(0x44, 0xcc, 0x88));
                stat_card(ui, "TX Packets", &snap.tx.packets.to_string(), Color32::from_rgb(0xff, 0xaa, 0x44));
                stat_card(ui, "TX Total",   &fmt_bytes(snap.tx.bytes),    Color32::from_rgb(0xff, 0x66, 0x66));
            });

            ui.add_space(10.0);
            ui.separator();

            // health panel
            ui.heading("Health");
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let h = &snap.health;
                health_badge(ui, "TCP Retransmits", h.tcp_retransmit_skb);
                health_badge(ui, "Policy Drops",    h.policy_drops);
                if let Some(v) = h.netdev_rx_dropped {
                    health_badge(ui, "NIC RX Dropped", v);
                }
                if let Some(v) = h.netdev_tx_dropped {
                    health_badge(ui, "NIC TX Dropped", v);
                }
            });

            ui.add_space(8.0);

            // probe status 
            ui.heading("Probe Status");
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let ps = &snap.probe_status;
                probe_badge(ui, "XDP ingress",          ps.xdp_attached);
                probe_badge(ui, "TC egress",             ps.tc_egress_attached);
                probe_badge(ui, "tcp_retransmit trace",  ps.tcp_retransmit_trace_attached);
                probe_badge(ui, "nftables",              ps.nftables_ready);
            });
            for err in &snap.probe_status.errors {
                ui.colored_label(Color32::YELLOW, format!("  ⚠ {err}"));
            }

            ui.add_space(10.0);
            ui.separator();

            //throughput chart 
            ui.heading("Live Throughput");
            let rx_rate = rx_hist.last().map(|p| p[1]).unwrap_or(0.0);
            let tx_rate = tx_hist.last().map(|p| p[1]).unwrap_or(0.0);
            ui.horizontal(|ui| {
                ui.colored_label(Color32::GREEN, format!("↓ RX  {}", fmt_rate(rx_rate)));
                ui.add_space(24.0);
                ui.colored_label(Color32::from_rgb(0xff, 0x88, 0x22), format!("↑ TX  {}", fmt_rate(tx_rate)));
            });
            ui.add_space(4.0);

            Plot::new("throughput")
                .height(200.0)
                .include_y(0.0)
                .legend(Legend::default())
                .x_axis_label("Elapsed (s)")
                .y_axis_label("Bytes / s")
                .show(ui, |pui| {
                    if !rx_hist.is_empty() {
                        pui.line(
                            Line::new(PlotPoints::new(rx_hist.to_vec()))
                                .color(Color32::GREEN)
                                .name("RX (B/s)"),
                        );
                    }
                    if !tx_hist.is_empty() {
                        pui.line(
                            Line::new(PlotPoints::new(tx_hist.to_vec()))
                                .color(Color32::from_rgb(0xff, 0x88, 0x22))
                                .name("TX (B/s)"),
                        );
                    }
                });

            //  current-tick alerts 
            if !snap.alerts.is_empty() {
                ui.add_space(8.0);
                ui.separator();
                ui.heading("Alerts (this tick)");
                for a in &snap.alerts {
                    let color = alert_color(&a.severity);
                    ui.colored_label(color, format!("[{}] {}  —  {}", a.severity.to_uppercase(), a.kind, a.message));
                }
            }

            // flow summary
            ui.add_space(8.0);
            ui.separator();
            ui.heading(format!(
                "Top Flows  (RX: {} entries  •  TX: {} entries)",
                snap.flows_rx.len(),
                snap.flows_tx.len()
            ));
            ui.horizontal(|ui| {
                ui.label(RichText::new("Switch to Flows tab for the full table").color(Color32::GRAY));
                if ui.small_button("Go to Flows →").clicked() {
                    // Can't mutate self.active_tab here without borrow; user clicks tab button instead.
                }
            });
            if let Some(top_rx) = snap.flows_rx.first() {
                ui.label(format!(
                    "  Top RX: {}:{} → {}:{}  {}  {}",
                    top_rx.src_ip, top_rx.src_port, top_rx.dst_ip, top_rx.dst_port,
                    top_rx.protocol, fmt_bytes(top_rx.bytes)
                ));
            }
            if let Some(top_tx) = snap.flows_tx.first() {
                ui.label(format!(
                    "  Top TX: {}:{} → {}:{}  {}  {}",
                    top_tx.src_ip, top_tx.src_port, top_tx.dst_ip, top_tx.dst_port,
                    top_tx.protocol, fmt_bytes(top_tx.bytes)
                ));
            }
        });
    }
}

// Correlation tab

impl App {
    fn show_correlation(ui: &mut Ui, snap: Option<&MonitorSnapshotV1>) {
        let Some(snap) = snap else {
            ui.label("No data yet.");
            return;
        };
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.heading("Correlation View");
            ui.colored_label(
                Color32::GRAY,
                "This view will drill from flows to processes, users, and socket attribution.",
            );
            ui.add_space(8.0);

            ui.group(|ui| {
                ui.label(RichText::new("Focus").strong());
                ui.label(format!("Interface: {}", snap.iface));
                ui.label(format!("Session: {}", snap.session.session_id));
                ui.label(format!("Latest snapshot: {}", fmt_ts_ms(snap.ts_unix_ms)));
            });

            ui.add_space(12.0);
            ui.heading(format!("RX Flows — {} entries", snap.flows_rx.len()));
            flow_table(ui, &snap.flows_rx, "rx_tbl");
            ui.add_space(16.0);
            ui.heading(format!("TX Flows — {} entries", snap.flows_tx.len()));
            flow_table(ui, &snap.flows_tx, "tx_tbl");

            ui.add_space(16.0);
            ui.separator();
            ui.heading("Process and User Correlation");
            ui.label("This is the skeleton area for process/user drill-downs and inode attribution.");
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(RichText::new("Top Processes").strong());
                    if snap.aggregates_by_pid.is_empty() {
                        ui.colored_label(Color32::GRAY, "No process attribution yet.");
                    } else {
                        for row in snap.aggregates_by_pid.iter().take(5) {
                            ui.label(format!("pid={} {} ({})", row.pid, row.comm.as_deref().unwrap_or("—"), fmt_bytes(row.bytes_total)));
                        }
                    }
                });
                ui.add_space(24.0);
                ui.vertical(|ui| {
                    ui.label(RichText::new("Top Users").strong());
                    if snap.aggregates_by_user.is_empty() {
                        ui.colored_label(Color32::GRAY, "No user attribution yet.");
                    } else {
                        for row in snap.aggregates_by_user.iter().take(5) {
                            ui.label(format!("uid={} {} ({})", row.uid, row.username.as_deref().unwrap_or("—"), fmt_bytes(row.bytes_total)));
                        }
                    }
                });
            });
        });
    }
}

fn flow_table(ui: &mut Ui, rows: &[FlowRow], id: &str) {
    egui::Grid::new(id)
        .num_columns(7)
        .striped(true)
        .min_col_width(90.0)
        .show(ui, |ui| {
            ui.label(RichText::new("Src IP").strong());
            ui.label(RichText::new("Src Port").strong());
            ui.label(RichText::new("Dst IP").strong());
            ui.label(RichText::new("Dst Port").strong());
            ui.label(RichText::new("Proto").strong());
            ui.label(RichText::new("Bytes").strong());
            ui.label(RichText::new("PID / User").strong());
            ui.end_row();
            for row in rows.iter().take(100) {
                ui.label(&row.src_ip);
                ui.label(row.src_port.to_string());
                ui.label(&row.dst_ip);
                ui.label(row.dst_port.to_string());
                // highlight protocol with colour
                let proto_color = match row.protocol.as_str() {
                    "TCP"  => Color32::from_rgb(0x66, 0xbb, 0xff),
                    "UDP"  => Color32::from_rgb(0xff, 0xcc, 0x66),
                    "ICMP" => Color32::from_rgb(0xcc, 0x88, 0xff),
                    _      => Color32::GRAY,
                };
                ui.colored_label(proto_color, &row.protocol);
                ui.label(fmt_bytes(row.bytes));
                let pid_user = match (row.local_pid, row.local_username.as_deref()) {
                    (Some(p), Some(u)) => format!("{p} ({u})"),
                    (Some(p), None)    => p.to_string(),
                    _                  => "—".to_string(),
                };
                ui.label(pid_user);
                ui.end_row();
            }
        });
    if rows.len() > 100 {
        ui.colored_label(Color32::GRAY, format!("  … {} more rows not shown", rows.len() - 100));
    }
}

// Audit tab

impl App {
    fn show_audit(ui: &mut Ui, snap: Option<&MonitorSnapshotV1>, alert_log: &[AlertEvent]) {
        let Some(snap) = snap else {
            ui.label("No data yet.");
            return;
        };
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.heading("Audit View");
            ui.colored_label(
                Color32::GRAY,
                "This view will eventually merge control RPC audit logs with alert history and probe errors.",
            );
            ui.add_space(8.0);

            ui.group(|ui| {
                ui.label(RichText::new("Current Session").strong());
                ui.label(format!("Session ID: {}", snap.session.session_id));
                ui.label(format!("Snapshot time: {}", fmt_ts_ms(snap.ts_unix_ms)));
                ui.label(format!("Probe errors: {}", snap.probe_status.errors.len()));
            });

            ui.add_space(12.0);

            ui.heading("Alerts from current session");
            if alert_log.is_empty() {
                ui.colored_label(Color32::GRAY, "No alerts recorded yet.");
            } else {
                egui::Grid::new("audit_alert_grid")
                    .num_columns(4)
                    .striped(true)
                    .show(ui, |ui| {
                        ui.label(RichText::new("Time").strong());
                        ui.label(RichText::new("Severity").strong());
                        ui.label(RichText::new("Kind").strong());
                        ui.label(RichText::new("Message").strong());
                        ui.end_row();
                        for a in alert_log.iter().rev().take(50) {
                            ui.label(fmt_ts_ms(a.ts_unix_ms));
                            ui.colored_label(alert_color(&a.severity), &a.severity);
                            ui.label(&a.kind);
                            ui.label(&a.message);
                            ui.end_row();
                        }
                    });
            }

            ui.add_space(12.0);
            ui.heading("Probe errors");
            if snap.probe_status.errors.is_empty() {
                ui.colored_label(Color32::GREEN, "No probe errors reported.");
            } else {
                for err in &snap.probe_status.errors {
                    ui.colored_label(Color32::YELLOW, format!("⚠ {err}"));
                }
            }
        });
    }
}

fn alert_color(severity: &str) -> Color32 {
    match severity {
        "critical" => Color32::RED,
        "warn" | "warning" => Color32::YELLOW,
        _ => Color32::LIGHT_BLUE,
    }
}

//  Control tab 

impl App {
    fn show_control(&mut self, ui: &mut Ui, rpc_result: &str) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.heading("Control Panel");
            ui.label(RichText::new(
                "Send control commands to the kernel-spy daemon via its JSON-RPC unix socket.",
            ).color(Color32::GRAY));
            ui.add_space(8.0);

            //  connectivity 
            ui.group(|ui| {
                ui.label(RichText::new("Connectivity").strong());
                ui.horizontal(|ui| {
                    if ui.button("Ping daemon").clicked() {
                        let r = self.rpc("ping", serde_json::Value::Null);
                        self.set_rpc_result(r);
                    }
                    if ui.button("Session dump (in response)").clicked() {
                        let r = self.rpc("session_dump", serde_json::Value::Null);
                        self.set_rpc_result(r);
                    }
                });
            });

            ui.add_space(8.0);

            //  IP drop rule 
            ui.group(|ui| {
                ui.label(RichText::new("Drop by Destination IP (nftables)").strong());
                ui.horizontal(|ui| {
                    ui.label("Target IPv4:");
                    ui.text_edit_singleline(&mut self.ip_input);
                });
                ui.horizontal(|ui| {
                    if ui.button("Preview Drop Rule").clicked() {
                        let r = self.rpc(
                            "nft_preview_drop",
                            serde_json::json!({ "dst": self.ip_input }),
                        );
                        self.set_rpc_result(r);
                    }
                    if ui.button("⚠ Apply Drop Rule").clicked() {
                        let r = self.rpc(
                            "nft_apply_drop",
                            serde_json::json!({ "dst": self.ip_input }),
                        );
                        self.set_rpc_result(r);
                    }
                });
            });

            ui.add_space(8.0);

            //  rate limit rule 
            ui.group(|ui| {
                ui.label(RichText::new("Rate Limit by Destination IP (nftables)").strong());
                ui.horizontal(|ui| {
                    ui.label("Target IPv4:");
                    ui.text_edit_singleline(&mut self.ip_input);
                });
                ui.horizontal(|ui| {
                    ui.label("Rate (e.g. 1 mbytes/second):");
                    ui.text_edit_singleline(&mut self.rate_input);
                });
                ui.horizontal(|ui| {
                    if ui.button("Preview Rate Limit").clicked() {
                        let r = self.rpc(
                            "nft_preview_rate_limit",
                            serde_json::json!({ "dst": self.ip_input, "rate": self.rate_input }),
                        );
                        self.set_rpc_result(r);
                    }
                    if ui.button("⚠ Apply Rate Limit").clicked() {
                        let r = self.rpc(
                            "nft_apply_rate_limit",
                            serde_json::json!({ "dst": self.ip_input, "rate": self.rate_input }),
                        );
                        self.set_rpc_result(r);
                    }
                });
            });

            ui.add_space(8.0);

            //  UID / GID drop 
            ui.group(|ui| {
                ui.label(RichText::new("Drop by UID / GID (nftables)").strong());
                ui.horizontal(|ui| {
                    ui.label("UID:");
                    ui.text_edit_singleline(&mut self.uid_input);
                    if ui.button("Preview UID Drop").clicked() {
                        if let Ok(uid) = self.uid_input.trim().parse::<u64>() {
                            let r = self.rpc("nft_preview_drop_uid", serde_json::json!({ "uid": uid }));
                            self.set_rpc_result(r);
                        }
                    }
                    if ui.button("⚠ Apply UID Drop").clicked() {
                        if let Ok(uid) = self.uid_input.trim().parse::<u64>() {
                            let r = self.rpc("nft_apply_drop_uid", serde_json::json!({ "uid": uid }));
                            self.set_rpc_result(r);
                        }
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("GID:");
                    ui.text_edit_singleline(&mut self.gid_input);
                    if ui.button("Preview GID Drop").clicked() {
                        if let Ok(gid) = self.gid_input.trim().parse::<u64>() {
                            let r = self.rpc("nft_preview_drop_gid", serde_json::json!({ "gid": gid }));
                            self.set_rpc_result(r);
                        }
                    }
                    if ui.button("⚠ Apply GID Drop").clicked() {
                        if let Ok(gid) = self.gid_input.trim().parse::<u64>() {
                            let r = self.rpc("nft_apply_drop_gid", serde_json::json!({ "gid": gid }));
                            self.set_rpc_result(r);
                        }
                    }
                });
            });

            ui.add_space(8.0);

            //  rollback 
            ui.group(|ui| {
                ui.label(RichText::new("Ruleset Rollback").strong());
                ui.label(RichText::new(
                    "Restore the nftables table from the backup taken before the last apply.",
                ).color(Color32::GRAY));
                if ui.button("⚠ Rollback nftables").clicked() {
                    let r = self.rpc("nft_rollback", serde_json::Value::Null);
                    self.set_rpc_result(r);
                }
            });

            //  RPC response 
            if !rpc_result.is_empty() {
                ui.add_space(8.0);
                ui.separator();
                ui.label(RichText::new("Last RPC Response").strong());
                let pretty = serde_json::from_str::<serde_json::Value>(rpc_result)
                    .ok()
                    .and_then(|v| serde_json::to_string_pretty(&v).ok())
                    .unwrap_or_else(|| rpc_result.to_string());
                let ok = rpc_result.contains("\"ok\":true") || rpc_result.contains("\"ok\": true");
                let resp_color = if ok { Color32::GREEN } else { Color32::RED };
                ui.colored_label(resp_color, if ok { "✓ ok" } else { "✗ error" });
                egui::ScrollArea::vertical()
                    .id_salt("rpc_resp_scroll")
                    .max_height(200.0)
                    .show(ui, |ui| {
                        ui.code(pretty);
                    });
            }
        });
    }
}

//  widget helpers 

fn tab_btn(ui: &mut Ui, label: &str, active: &mut Tab, tab: Tab) {
    let selected = *active == tab;
    let text = if selected {
        RichText::new(label).strong()
    } else {
        RichText::new(label)
    };
    if ui.selectable_label(selected, text).clicked() {
        *active = tab;
    }
}

fn stat_card(ui: &mut Ui, label: &str, value: &str, value_color: Color32) {
    ui.group(|ui| {
        ui.set_min_width(170.0);
        ui.vertical(|ui| {
            ui.label(RichText::new(label).color(Color32::GRAY).size(11.0));
            ui.add_space(2.0);
            ui.label(RichText::new(value).color(value_color).size(22.0).strong());
        });
    });
}

fn health_badge(ui: &mut Ui, label: &str, value: u64) {
    let color = if value == 0 { Color32::GREEN } else { Color32::YELLOW };
    ui.group(|ui| {
        ui.horizontal(|ui| {
            ui.colored_label(color, "●");
            ui.label(format!("{label}: {value}"));
        });
    });
}

fn probe_badge(ui: &mut Ui, label: &str, attached: bool) {
    let (sym, color) = if attached {
        ("✓", Color32::GREEN)
    } else {
        ("✗", Color32::RED)
    };
    ui.group(|ui| {
        ui.colored_label(color, format!("{sym} {label}"));
    });
}

//  background reader thread 

fn reader_loop(state: Arc<Mutex<SharedState>>) {
    loop {
        match UnixStream::connect(EXPORT_SOCK) {
            Err(_) => {
                if let Ok(mut s) = state.lock() {
                    s.connected = false;
                }
                thread::sleep(Duration::from_secs(2));
            }
            Ok(stream) => {
                {
                    let mut s = state.lock().unwrap();
                    s.connected = true;
                }
                let reader = BufReader::new(stream);
                for line in reader.lines() {
                    let Ok(line) = line else { break };
                    if let Ok(snap) = parse_export_line(&line) {
                        if let Ok(mut s) = state.lock() {
                            s.ingest(snap);
                        }
                    }
                }
                if let Ok(mut s) = state.lock() {
                    s.connected = false;
                }
                thread::sleep(Duration::from_secs(2));
            }
        }
    }
}

//  entry point 

fn main() -> eframe::Result<()> {
    let state = Arc::new(Mutex::new(SharedState::new()));

    {
        let state = Arc::clone(&state);
        thread::spawn(move || reader_loop(state));
    }

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 820.0])
            .with_title("IPC Network Monitor"),
        ..Default::default()
    };

    eframe::run_native(
        "IPC Network Monitor",
        native_options,
        Box::new(|_cc| Ok(Box::new(App::new(Arc::clone(&state))))),
    )
}
