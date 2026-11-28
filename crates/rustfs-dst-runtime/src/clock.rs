// Copyright 2026 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Deterministic and production clock abstractions for RustFS.
//!
//! All wall-clock reads (`SystemTime`), monotonic timestamps (`Instant`),
//! lease expiration checks, retry backoffs, and sleep timers in RustFS should
//! flow through [`Clock`] rather than calling `std::time` or `tokio::time`
//! directly.

use async_trait::async_trait;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Notify;

/// Monotonic virtual or real timestamp expressed as nanoseconds since an
/// arbitrary epoch (process start in production, zero in simulation).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SimInstant(pub u64);

impl SimInstant {
    pub const ZERO: Self = Self(0);

    pub fn from_millis(ms: u64) -> Self {
        Self(ms.saturating_mul(1_000_000))
    }

    pub fn as_millis(self) -> u64 {
        self.0 / 1_000_000
    }

    pub fn checked_add(self, dur: Duration) -> Option<Self> {
        let nanos = u64::try_from(dur.as_nanos()).ok()?;
        self.0.checked_add(nanos).map(Self)
    }

    pub fn saturating_add(self, dur: Duration) -> Self {
        let nanos = u64::try_from(dur.as_nanos()).unwrap_or(u64::MAX);
        Self(self.0.saturating_add(nanos))
    }

    pub fn saturating_duration_since(self, earlier: Self) -> Duration {
        Duration::from_nanos(self.0.saturating_sub(earlier.0))
    }
}

/// Unified time abstraction replacing direct `std::time` and `tokio::time`
/// usage inside RustFS.
#[async_trait]
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// Current wall-clock time (may jump forward or backward under clock skew).
    fn now_system(&self) -> SystemTime;

    /// Current monotonic instant (never moves backward on a single node).
    fn now_instant(&self) -> SimInstant;

    /// Wall-clock milliseconds since UNIX epoch.
    fn now_unix_ms(&self) -> i64 {
        match self.now_system().duration_since(UNIX_EPOCH) {
            Ok(d) => i64::try_from(d.as_millis()).unwrap_or(i64::MAX),
            Err(e) => -(i64::try_from(e.duration().as_millis()).unwrap_or(i64::MAX)),
        }
    }

    /// Suspend the caller for `duration` according to this clock.
    async fn sleep(&self, duration: Duration);
}

/// Production [`Clock`] backed by `std::time` and `tokio::time`.
#[derive(Debug)]
pub struct RealClock {
    origin: std::time::Instant,
}

impl Default for RealClock {
    fn default() -> Self {
        Self::new()
    }
}

impl RealClock {
    pub fn new() -> Self {
        Self {
            origin: std::time::Instant::now(),
        }
    }
}

#[async_trait]
impl Clock for RealClock {
    fn now_system(&self) -> SystemTime {
        SystemTime::now()
    }

    fn now_instant(&self) -> SimInstant {
        let nanos = u64::try_from(self.origin.elapsed().as_nanos()).unwrap_or(u64::MAX);
        SimInstant(nanos)
    }

    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}

#[derive(Debug)]
struct SimClockInner {
    /// Base simulated wall-clock epoch in milliseconds since UNIX_EPOCH.
    base_unix_ms: i64,
    /// Global simulated monotonic time in nanoseconds.
    now_ns: u64,
    /// Optional per-node wall-clock skew in milliseconds (can be negative).
    node_skew_ms: HashMap<String, i64>,
    /// Optional per-node monotonic drift multiplier in parts-per-million
    /// relative to 1_000_000 (e.g., +50_000 = 5% fast, -50_000 = 5% slow).
    node_drift_ppm: HashMap<String, i64>,
    /// Incrementally accumulated per-node monotonic nanoseconds so changing or
    /// clearing `node_drift_ppm` never causes a monotonic clock to jump backward.
    node_accumulated_ns: HashMap<String, u64>,
    /// Wake-up waiters indexed by deadline instant.
    waiters: BTreeMap<u64, Vec<Arc<Notify>>>,
}

/// Deterministic virtual clock with per-node clock skew, step jumps, and
/// monotonic drift injection.
///
/// Time only advances when [`SimClock::advance`] or [`SimClock::advance_to`]
/// is called by the simulator driver (or when `auto_advance` is enabled for
/// lightweight unit tests).
#[derive(Clone, Debug)]
pub struct SimClock {
    inner: Arc<Mutex<SimClockInner>>,
    node_id: Option<String>,
    auto_advance: bool,
}

impl SimClock {
    /// Fixed default simulation epoch: `2026-01-01T00:00:00Z` in milliseconds.
    pub const DEFAULT_EPOCH_MS: i64 = 1_767_225_600_000;

    /// Create a new deterministic simulation clock starting at `DEFAULT_EPOCH_MS`.
    pub fn new() -> Self {
        Self::with_epoch_ms(Self::DEFAULT_EPOCH_MS)
    }

    /// Create a new simulation clock starting at an explicit UNIX millisecond epoch.
    pub fn with_epoch_ms(base_unix_ms: i64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(SimClockInner {
                base_unix_ms,
                now_ns: 0,
                node_skew_ms: HashMap::new(),
                node_drift_ppm: HashMap::new(),
                node_accumulated_ns: HashMap::new(),
                waiters: BTreeMap::new(),
            })),
            node_id: None,
            auto_advance: false,
        }
    }

    /// Enable automatic instant advancement on [`Clock::sleep`], useful for
    /// single-threaded sequential simulation drivers without a separate ticker task.
    pub fn with_auto_advance(mut self, enabled: bool) -> Self {
        self.auto_advance = enabled;
        self
    }

    /// Derive a node-scoped clock view sharing the same global timeline while
    /// applying that node's injected wall-clock skew and monotonic drift.
    pub fn for_node(&self, node_id: impl Into<String>) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            node_id: Some(node_id.into()),
            auto_advance: self.auto_advance,
        }
    }

    /// Inject a wall-clock skew (in milliseconds; positive = ahead, negative = behind)
    /// for a specific node.
    pub fn set_node_skew_ms(&self, node_id: impl Into<String>, skew_ms: i64) {
        let mut inner = self.inner.lock().expect("SimClock lock poisoned");
        inner.node_skew_ms.insert(node_id.into(), skew_ms);
    }

    /// Inject a monotonic clock drift in parts-per-million for a node
    /// (clamped to `[-500_000, +500_000]`).
    pub fn set_node_drift_ppm(&self, node_id: impl Into<String>, drift_ppm: i64) {
        let mut inner = self.inner.lock().expect("SimClock lock poisoned");
        let id = node_id.into();
        let cur_ns = inner.now_ns;
        inner
            .node_accumulated_ns
            .entry(id.clone())
            .or_insert(cur_ns);
        inner
            .node_drift_ppm
            .insert(id, drift_ppm.clamp(-500_000, 500_000));
    }

    /// Reset all injected skews and drifts across all nodes without moving any
    /// node's accumulated monotonic instant backward.
    pub fn clear_faults(&self) {
        let mut inner = self.inner.lock().expect("SimClock lock poisoned");
        inner.node_skew_ms.clear();
        inner.node_drift_ppm.clear();
    }

    /// Advance simulated time by `delta` and wake any timers whose deadline has passed.
    pub fn advance(&self, delta: Duration) {
        let delta_ns = u64::try_from(delta.as_nanos()).unwrap_or(u64::MAX);
        let to_wake = {
            let mut inner = self.inner.lock().expect("SimClock lock poisoned");
            inner.now_ns = inner.now_ns.saturating_add(delta_ns);
            let drifts = inner.node_drift_ppm.clone();
            for (id, acc_ns) in &mut inner.node_accumulated_ns {
                let ppm = drifts.get(id).copied().unwrap_or(0);
                let scaled = (delta_ns as i128) * (1_000_000 + i128::from(ppm)) / 1_000_000;
                let step = u64::try_from(scaled.max(0)).unwrap_or(u64::MAX);
                *acc_ns = acc_ns.saturating_add(step);
            }
            let now = inner.now_ns;
            let ready_keys: Vec<u64> = inner.waiters.range(..=now).map(|(&k, _)| k).collect();
            let mut wakes = Vec::new();
            for key in ready_keys {
                if let Some(list) = inner.waiters.remove(&key) {
                    wakes.extend(list);
                }
            }
            wakes
        };
        for notify in to_wake {
            notify.notify_waiters();
        }
    }

    /// Advance simulated time directly to `target` if `target` is in the future.
    pub fn advance_to(&self, target: SimInstant) {
        let current = self.global_instant();
        if target > current {
            self.advance(target.saturating_duration_since(current));
        }
    }

    /// Read the unskewed global monotonic instant.
    pub fn global_instant(&self) -> SimInstant {
        let inner = self.inner.lock().expect("SimClock lock poisoned");
        SimInstant(inner.now_ns)
    }

    fn effective_instant(&self, inner: &SimClockInner) -> SimInstant {
        let ns = self
            .node_id
            .as_ref()
            .and_then(|id| inner.node_accumulated_ns.get(id).copied())
            .unwrap_or(inner.now_ns);
        SimInstant(ns)
    }
}

impl Default for SimClock {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Clock for SimClock {
    fn now_system(&self) -> SystemTime {
        let inner = self.inner.lock().expect("SimClock lock poisoned");
        let elapsed_ms = i64::try_from(self.effective_instant(&inner).as_millis()).unwrap_or(0);
        let skew_ms = self
            .node_id
            .as_ref()
            .and_then(|id| inner.node_skew_ms.get(id).copied())
            .unwrap_or(0);
        let total_ms = inner
            .base_unix_ms
            .saturating_add(elapsed_ms)
            .saturating_add(skew_ms);
        if total_ms >= 0 {
            UNIX_EPOCH + Duration::from_millis(total_ms as u64)
        } else {
            UNIX_EPOCH
                .checked_sub(Duration::from_millis(total_ms.unsigned_abs()))
                .unwrap_or(UNIX_EPOCH)
        }
    }

    fn now_instant(&self) -> SimInstant {
        let inner = self.inner.lock().expect("SimClock lock poisoned");
        self.effective_instant(&inner)
    }

    async fn sleep(&self, duration: Duration) {
        if duration.is_zero() {
            return;
        }
        if self.auto_advance {
            self.advance(duration);
            return;
        }
        let delta_ns = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
        let deadline = {
            let inner = self.inner.lock().expect("SimClock lock poisoned");
            inner.now_ns.saturating_add(delta_ns)
        };
        // Register interest before checking the deadline. `Notify::notified`
        // drops a `notify_waiters` that arrives before the future is polled,
        // which previously hung the sleeper if `advance` won that race.
        let notify = Arc::new(Notify::new());
        let notified = notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        {
            let mut inner = self.inner.lock().expect("SimClock lock poisoned");
            if inner.now_ns >= deadline {
                return;
            }
            inner
                .waiters
                .entry(deadline)
                .or_default()
                .push(Arc::clone(&notify));
        }
        notified.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sim_clock_skew_and_drift_are_deterministic() {
        let clock = SimClock::new();
        let n1 = clock.for_node("n1");
        let n2 = clock.for_node("n2");

        clock.set_node_skew_ms("n2", 5_000);
        clock.set_node_drift_ppm("n1", 100_000); // +10% fast

        clock.advance(Duration::from_secs(10));
        assert_eq!(n1.now_instant().as_millis(), 11_000);
        assert_eq!(n2.now_instant().as_millis(), 10_000);
        assert_eq!(n2.now_unix_ms() - n1.now_unix_ms(), 4_000);
    }

    #[tokio::test]
    async fn sim_clock_wakes_sleepers_on_advance() {
        let clock = SimClock::new();
        let c2 = clock.clone();
        let handle = tokio::spawn(async move {
            c2.sleep(Duration::from_secs(3)).await;
            c2.now_instant().as_millis()
        });
        tokio::task::yield_now().await;
        clock.advance(Duration::from_secs(2));
        tokio::task::yield_now().await;
        assert!(!handle.is_finished());
        clock.advance(Duration::from_secs(1));
        let finished_ms = handle.await.unwrap();
        assert_eq!(finished_ms, 3_000);
    }

    #[test]
    fn clearing_drift_never_moves_monotonic_clock_backward() {
        let clock = SimClock::new();
        let n1 = clock.for_node("n1");
        clock.set_node_drift_ppm("n1", 100_000);
        clock.advance(Duration::from_secs(10));
        let before_clear = n1.now_instant();
        assert_eq!(before_clear.as_millis(), 11_000);

        clock.clear_faults();
        let after_clear = n1.now_instant();
        assert_eq!(after_clear, before_clear);

        clock.advance(Duration::from_secs(5));
        assert_eq!(n1.now_instant().as_millis(), 16_000);
    }
}
