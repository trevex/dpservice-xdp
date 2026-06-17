//! Userspace conntrack aging: periodically evict entries idle longer than their timeout. Mirrors
//! dpservice (30 s default, 1-day established-TCP). Times are kernel-monotonic ns (bpf_ktime).
use std::time::Duration;

use xdp_dp_common::{CtEntry, TCP_ESTABLISHED};

use crate::maps::Conntrack;

const DEFAULT_TIMEOUT_NS: u64 = 30 * 1_000_000_000;
const TCP_ESTABLISHED_TIMEOUT_NS: u64 = 24 * 60 * 60 * 1_000_000_000;

fn timeout_ns(e: &CtEntry) -> u64 {
    if e.tcp_state == TCP_ESTABLISHED {
        TCP_ESTABLISHED_TIMEOUT_NS
    } else {
        DEFAULT_TIMEOUT_NS
    }
}

/// Kernel-monotonic time (ns) — the same clock `bpf_ktime_get_ns` stamps `last_seen` with.
fn ktime_now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u64) * 1_000_000_000 + ts.tv_nsec as u64
}

/// Sweep loop: every `interval`, remove entries whose idle age exceeds their timeout.
pub async fn run(mut ct: Conntrack, interval: Duration) {
    loop {
        tokio::time::sleep(interval).await;
        let now = ktime_now_ns();
        let stale: Vec<_> = ct
            .entries()
            .into_iter()
            .filter(|(_, e)| now.saturating_sub(e.last_seen) > timeout_ns(e))
            .map(|(k, _)| k)
            .collect();
        for k in stale {
            let _ = ct.remove(&k);
        }
    }
}
