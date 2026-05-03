use anyhow::Context;
use csv::Writer;

use crate::{AlertEvent, FlowRow, MonitorSnapshotV1, ProcessTrafficRow, UserTrafficRow};

fn writer_to_string(writer: Writer<Vec<u8>>) -> anyhow::Result<String> {
    let bytes = writer
        .into_inner()
        .map_err(|err| err.into_error())
        .context("finalize csv writer")?;
    String::from_utf8(bytes).context("csv output is not valid utf-8")
}

fn write_header(writer: &mut Writer<Vec<u8>>, header: &[&str]) -> anyhow::Result<()> {
    writer.write_record(header).context("write csv header")
}

fn opt_str(value: Option<&str>) -> &str {
    value.unwrap_or("")
}

fn opt_u32(value: Option<u32>) -> String {
    value.map(|v| v.to_string()).unwrap_or_default()
}

pub fn snapshot_flows_to_csv(snapshot: &MonitorSnapshotV1) -> anyhow::Result<String> {
    let mut writer = Writer::from_writer(Vec::new());
    write_header(
        &mut writer,
        &[
            "timestamp_ms",
            "interface",
            "direction",
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "protocol",
            "bytes",
            "local_pid",
            "local_uid",
            "local_username",
            "local_comm",
        ],
    )?;

    for flow in &snapshot.flows_rx {
        write_flow_row(&mut writer, snapshot.ts_unix_ms, &snapshot.iface, "rx", flow)?;
    }
    for flow in &snapshot.flows_tx {
        write_flow_row(&mut writer, snapshot.ts_unix_ms, &snapshot.iface, "tx", flow)?;
    }

    writer.flush().context("flush csv writer")?;
    writer_to_string(writer)
}

pub fn session_flows_to_csv(snaps: &[MonitorSnapshotV1]) -> anyhow::Result<String> {
    let mut writer = Writer::from_writer(Vec::new());
    write_header(
        &mut writer,
        &[
            "timestamp_ms",
            "interface",
            "direction",
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "protocol",
            "bytes",
            "local_pid",
            "local_uid",
            "local_username",
            "local_comm",
        ],
    )?;

    for snapshot in snaps {
        for flow in &snapshot.flows_rx {
            write_flow_row(&mut writer, snapshot.ts_unix_ms, &snapshot.iface, "rx", flow)?;
        }
        for flow in &snapshot.flows_tx {
            write_flow_row(&mut writer, snapshot.ts_unix_ms, &snapshot.iface, "tx", flow)?;
        }
    }

    writer.flush().context("flush csv writer")?;
    writer_to_string(writer)
}

fn write_flow_row(
    writer: &mut Writer<Vec<u8>>,
    ts_unix_ms: u64,
    iface: &str,
    direction: &str,
    flow: &FlowRow,
) -> anyhow::Result<()> {
    writer
        .write_record([
            ts_unix_ms.to_string(),
            iface.to_string(),
            direction.to_string(),
            flow.src_ip.clone(),
            flow.src_port.to_string(),
            flow.dst_ip.clone(),
            flow.dst_port.to_string(),
            flow.protocol.clone(),
            flow.bytes.to_string(),
            opt_u32(flow.local_pid),
            opt_u32(flow.local_uid),
            opt_str(flow.local_username.as_deref()).to_string(),
            opt_str(flow.local_comm.as_deref()).to_string(),
        ])
        .context("write flow csv row")
}

pub fn snapshot_processes_to_csv(snapshot: &MonitorSnapshotV1) -> anyhow::Result<String> {
    let mut writer = Writer::from_writer(Vec::new());
    write_header(
        &mut writer,
        &["timestamp_ms", "pid", "comm", "bytes_total"],
    )?;

    for row in &snapshot.aggregates_by_pid {
        write_process_row(&mut writer, snapshot.ts_unix_ms, row)?;
    }

    writer.flush().context("flush csv writer")?;
    writer_to_string(writer)
}

pub fn session_processes_to_csv(snaps: &[MonitorSnapshotV1]) -> anyhow::Result<String> {
    let mut writer = Writer::from_writer(Vec::new());
    write_header(
        &mut writer,
        &["timestamp_ms", "pid", "comm", "bytes_total"],
    )?;

    for snapshot in snaps {
        for row in &snapshot.aggregates_by_pid {
            write_process_row(&mut writer, snapshot.ts_unix_ms, row)?;
        }
    }

    writer.flush().context("flush csv writer")?;
    writer_to_string(writer)
}

fn write_process_row(
    writer: &mut Writer<Vec<u8>>,
    ts_unix_ms: u64,
    row: &ProcessTrafficRow,
) -> anyhow::Result<()> {
    writer
        .write_record([
            ts_unix_ms.to_string(),
            row.pid.to_string(),
            opt_str(row.comm.as_deref()).to_string(),
            row.bytes_total.to_string(),
        ])
        .context("write process csv row")
}

pub fn snapshot_users_to_csv(snapshot: &MonitorSnapshotV1) -> anyhow::Result<String> {
    let mut writer = Writer::from_writer(Vec::new());
    write_header(
        &mut writer,
        &["timestamp_ms", "uid", "username", "bytes_total"],
    )?;

    for row in &snapshot.aggregates_by_user {
        write_user_row(&mut writer, snapshot.ts_unix_ms, row)?;
    }

    writer.flush().context("flush csv writer")?;
    writer_to_string(writer)
}

pub fn session_users_to_csv(snaps: &[MonitorSnapshotV1]) -> anyhow::Result<String> {
    let mut writer = Writer::from_writer(Vec::new());
    write_header(
        &mut writer,
        &["timestamp_ms", "uid", "username", "bytes_total"],
    )?;

    for snapshot in snaps {
        for row in &snapshot.aggregates_by_user {
            write_user_row(&mut writer, snapshot.ts_unix_ms, row)?;
        }
    }

    writer.flush().context("flush csv writer")?;
    writer_to_string(writer)
}

fn write_user_row(
    writer: &mut Writer<Vec<u8>>,
    ts_unix_ms: u64,
    row: &UserTrafficRow,
) -> anyhow::Result<()> {
    writer
        .write_record([
            ts_unix_ms.to_string(),
            row.uid.to_string(),
            opt_str(row.username.as_deref()).to_string(),
            row.bytes_total.to_string(),
        ])
        .context("write user csv row")
}

pub fn snapshot_alerts_to_csv(snapshot: &MonitorSnapshotV1) -> anyhow::Result<String> {
    let mut writer = Writer::from_writer(Vec::new());
    write_header(
        &mut writer,
        &["timestamp_ms", "kind", "message", "severity"],
    )?;

    for row in &snapshot.alerts {
        write_alert_row(&mut writer, row)?;
    }

    writer.flush().context("flush csv writer")?;
    writer_to_string(writer)
}

pub fn session_alerts_to_csv(snaps: &[MonitorSnapshotV1]) -> anyhow::Result<String> {
    let mut writer = Writer::from_writer(Vec::new());
    write_header(
        &mut writer,
        &["timestamp_ms", "kind", "message", "severity"],
    )?;

    for snapshot in snaps {
        for row in &snapshot.alerts {
            write_alert_row(&mut writer, row)?;
        }
    }

    writer.flush().context("flush csv writer")?;
    writer_to_string(writer)
}

fn write_alert_row(writer: &mut Writer<Vec<u8>>, row: &AlertEvent) -> anyhow::Result<()> {
    writer
        .write_record([
            row.ts_unix_ms.to_string(),
            row.kind.clone(),
            row.message.clone(),
            opt_str(Some(row.severity.as_str())).to_string(),
        ])
        .context("write alert csv row")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DirectionTotals, HealthSnapshot, MonitorSnapshotV1};

    fn snapshot() -> MonitorSnapshotV1 {
        MonitorSnapshotV1 {
            schema_version: 2,
            ts_unix_ms: 42,
            iface: "eth0".into(),
            rx: DirectionTotals { packets: 0, bytes: 0 },
            tx: DirectionTotals { packets: 0, bytes: 0 },
            health: HealthSnapshot::default(),
            flows_rx: vec![FlowRow {
                src_ip: "10.0.0.1".into(),
                dst_ip: "8.8.8.8".into(),
                src_port: 1234,
                dst_port: 53,
                protocol: "UDP".into(),
                bytes: 99,
                local_pid: Some(1),
                local_uid: Some(1000),
                local_username: Some("alice".into()),
                local_comm: Some("curl".into()),
            }],
            flows_tx: vec![],
            probe_status: Default::default(),
            session: Default::default(),
            aggregates_by_pid: vec![ProcessTrafficRow {
                pid: 1,
                comm: Some("curl".into()),
                bytes_total: 99,
                ts_unix_ms: 42,
                share_percent: 100.0,
            }],
            aggregates_by_user: vec![UserTrafficRow {
                uid: 1000,
                username: Some("alice".into()),
                bytes_total: 99,
                ts_unix_ms: 42,
                share_percent: 100.0,
            }],
            aggregate_history_by_pid: vec![],
            aggregate_history_by_user: vec![],
            alerts: vec![AlertEvent {
                ts_unix_ms: 42,
                kind: "spike".into(),
                message: "traffic spike".into(),
                severity: "warn".into(),
            }],
        }
    }

    fn second_snapshot() -> MonitorSnapshotV1 {
        let mut snap = snapshot();
        snap.ts_unix_ms = 99;
        snap.iface = "wlan0".into();
        snap.flows_rx[0].src_ip = "10.0.0.2".into();
        snap.aggregates_by_pid[0].pid = 2;
        snap.aggregates_by_pid[0].comm = Some("wget".into());
        snap.aggregates_by_user[0].uid = 2000;
        snap.aggregates_by_user[0].username = Some("bob".into());
        snap.alerts[0].kind = "burst".into();
        snap
    }

    #[test]
    fn flows_csv_has_header_and_rows() {
        let csv = snapshot_flows_to_csv(&snapshot()).expect("csv");
        assert!(csv.contains("timestamp_ms,interface,direction,src_ip"));
        assert!(csv.contains("42,eth0,rx,10.0.0.1,1234,8.8.8.8,53,UDP,99,1,1000,alice,curl"));
    }

    #[test]
    fn process_csv_has_expected_columns() {
        let csv = snapshot_processes_to_csv(&snapshot()).expect("csv");
        assert!(csv.contains("timestamp_ms,pid,comm,bytes_total"));
        assert!(csv.contains("42,1,curl,99"));
    }

    #[test]
    fn users_csv_has_expected_columns() {
        let csv = snapshot_users_to_csv(&snapshot()).expect("csv");
        assert!(csv.contains("timestamp_ms,uid,username,bytes_total"));
        assert!(csv.contains("42,1000,alice,99"));
    }

    #[test]
    fn alerts_csv_has_expected_columns() {
        let csv = snapshot_alerts_to_csv(&snapshot()).expect("csv");
        assert!(csv.contains("timestamp_ms,kind,message,severity"));
        assert!(csv.contains("42,spike,traffic spike,warn"));
    }

    #[test]
    fn session_csv_helpers_aggregate_multiple_snapshots() {
        let snaps = vec![snapshot(), second_snapshot()];

        let flows = session_flows_to_csv(&snaps).expect("csv");
        assert!(flows.contains("42,eth0,rx,10.0.0.1,1234,8.8.8.8,53,UDP,99,1,1000,alice,curl"));
        assert!(flows.contains("99,wlan0,rx,10.0.0.2,1234,8.8.8.8,53,UDP,99,1,1000,alice,curl"));

        let processes = session_processes_to_csv(&snaps).expect("csv");
        assert!(processes.contains("42,1,curl,99"));
        assert!(processes.contains("99,2,wget,99"));

        let users = session_users_to_csv(&snaps).expect("csv");
        assert!(users.contains("42,1000,alice,99"));
        assert!(users.contains("99,2000,bob,99"));

        let alerts = session_alerts_to_csv(&snaps).expect("csv");
        assert!(alerts.contains("42,spike,traffic spike,warn"));
        assert!(alerts.contains("burst"));
        assert!(alerts.contains("traffic spike"));
    }
}
