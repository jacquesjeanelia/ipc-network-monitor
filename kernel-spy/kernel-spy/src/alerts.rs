//! simple thresholds and ema-smoothed rx deltas for alerting

use common::{AlertEvent, DirectionTotals, ProcessTrafficRow};

/// tweak thresholds; set a field to 0 to turn that alert off
pub struct AlertConfig {
    /// raw rx byte delta per tick (0 = off)
    pub rx_bytes_per_tick_threshold: u64,
    /// ema alpha for rx deltas (0..=1); only used when `rx_ema_delta_threshold` > 0
    pub rx_ema_alpha: f64,
    /// fire when smoothed rx byte delta passes this (0 = ema path off)
    pub rx_ema_delta_threshold: u64,
    /// fire when top pid `bytes_total` passes this (0 = off)
    pub top_pid_bytes_threshold: u64,
}

pub struct AlertEngine {
    cfg: AlertConfig,
    prev_rx_bytes: Option<u64>,
    ema_rx_delta: Option<f64>,
}

impl AlertEngine {
    pub fn new(cfg: AlertConfig) -> Self {
        Self {
            cfg,
            prev_rx_bytes: None,
            ema_rx_delta: None,
        }
    }

    pub fn evaluate(
        &mut self,
        ts_ms: u64,
        rx: &DirectionTotals,
        aggregates_by_pid: &[ProcessTrafficRow],
    ) -> Vec<AlertEvent> {
        let mut out = Vec::new();

        if self.cfg.rx_bytes_per_tick_threshold > 0 {
            if let Some(prev) = self.prev_rx_bytes {
                let delta = rx.bytes.saturating_sub(prev);
                if delta >= self.cfg.rx_bytes_per_tick_threshold {
                    out.push(AlertEvent {
                        ts_unix_ms: ts_ms,
                        kind: "rx_bytes_spike".into(),
                        message: format!(
                            "RX delta {} bytes in interval >= threshold {}",
                            delta, self.cfg.rx_bytes_per_tick_threshold
                        ),
                        severity: "warn".into(),
                    });
                }
            }
        }

        if self.cfg.rx_ema_delta_threshold > 0 && self.cfg.rx_ema_alpha > 0.0 {
            if let Some(prev) = self.prev_rx_bytes {
                let delta = rx.bytes.saturating_sub(prev) as f64;
                let alpha = self.cfg.rx_ema_alpha.clamp(0.0, 1.0);
                let ema = match self.ema_rx_delta {
                    None => delta,
                    Some(e) => alpha * delta + (1.0 - alpha) * e,
                };
                self.ema_rx_delta = Some(ema);
                if ema >= self.cfg.rx_ema_delta_threshold as f64 {
                    out.push(AlertEvent {
                        ts_unix_ms: ts_ms,
                        kind: "rx_bytes_ema".into(),
                        message: format!(
                            "smoothed RX delta EMA {:.0} >= threshold {}",
                            ema, self.cfg.rx_ema_delta_threshold
                        ),
                        severity: "warn".into(),
                    });
                }
            }
        }

        if self.cfg.top_pid_bytes_threshold > 0 {
            if let Some(top) = aggregates_by_pid.first() {
                if top.bytes_total >= self.cfg.top_pid_bytes_threshold {
                    out.push(AlertEvent {
                        ts_unix_ms: ts_ms,
                        kind: "top_pid_bytes".into(),
                        message: format!(
                            "top PID {} bytes_total {} >= threshold {}",
                            top.pid, top.bytes_total, self.cfg.top_pid_bytes_threshold
                        ),
                        severity: "warn".into(),
                    });
                }
            }
        }

        self.prev_rx_bytes = Some(rx.bytes);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(pid: u32, bytes: u64) -> ProcessTrafficRow {
        ProcessTrafficRow {
            pid,
            comm: None,
            bytes_total: bytes,
            ts_unix_ms: 0,
            share_percent: 0.0,
        }
    }

    #[test]
    fn spike_threshold_fires() {
        let mut e = AlertEngine::new(AlertConfig {
            rx_bytes_per_tick_threshold: 100,
            rx_ema_alpha: 0.25,
            rx_ema_delta_threshold: 0,
            top_pid_bytes_threshold: 0,
        });
        let _ = e.evaluate(1, &DirectionTotals { packets: 0, bytes: 50 }, &[]);
        let a = e.evaluate(
            2,
            &DirectionTotals {
                packets: 0,
                bytes: 200,
            },
            &[],
        );
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].kind, "rx_bytes_spike");
    }

    #[test]
    fn top_pid_fires() {
        let mut e = AlertEngine::new(AlertConfig {
            rx_bytes_per_tick_threshold: 0,
            rx_ema_alpha: 0.25,
            rx_ema_delta_threshold: 0,
            top_pid_bytes_threshold: 500,
        });
        let a = e.evaluate(
            1,
            &DirectionTotals { packets: 0, bytes: 0 },
            &[row(1, 1000)],
        );
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].kind, "top_pid_bytes");
    }
}
