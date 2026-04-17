//! small in-memory ring of recent snapshots for session export

use std::collections::VecDeque;

use common::MonitorSnapshotV1;

pub struct SessionRing {
    cap: usize,
    inner: VecDeque<MonitorSnapshotV1>,
}

impl SessionRing {
    pub fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            inner: VecDeque::new(),
        }
    }

    pub fn push(&mut self, snap: MonitorSnapshotV1) {
        if self.inner.len() >= self.cap {
            self.inner.pop_front();
        }
        self.inner.push_back(snap);
    }

    pub fn dump(&self) -> Vec<MonitorSnapshotV1> {
        self.inner.iter().cloned().collect()
    }
}
