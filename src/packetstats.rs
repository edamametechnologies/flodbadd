use chrono::{DateTime, Utc};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::info;

lazy_static! {
    pub static ref PACKET_STATS: PacketStatsInternal = PacketStatsInternal::new();
}

pub struct PacketStatsInternal {
    // Windowed counters (reset every 30s for logging)
    pub total_processed: AtomicU64,
    pub tcp_processed: AtomicU64,
    pub udp_processed: AtomicU64,
    pub ipv4_processed: AtomicU64,
    pub ipv6_processed: AtomicU64,
    pub new_sessions: AtomicU64,
    pub updated_sessions: AtomicU64,
    pub last_log_time: AtomicU64,

    // Cumulative counters (never reset)
    pub total_processed_cumulative: AtomicU64,
    pub tcp_processed_cumulative: AtomicU64,
    pub udp_processed_cumulative: AtomicU64,
    pub ipv4_processed_cumulative: AtomicU64,
    pub ipv6_processed_cumulative: AtomicU64,
    pub new_sessions_cumulative: AtomicU64,
    pub updated_sessions_cumulative: AtomicU64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketStats {
    // Windowed stats (last 30s activity)
    pub total_processed: u64,
    pub tcp_processed: u64,
    pub udp_processed: u64,
    pub ipv4_processed: u64,
    pub ipv6_processed: u64,
    pub new_sessions: u64,
    pub updated_sessions: u64,
    pub last_log_time: DateTime<Utc>,

    // Cumulative stats (since process start)
    pub total_processed_cumulative: u64,
    pub tcp_processed_cumulative: u64,
    pub udp_processed_cumulative: u64,
    pub ipv4_processed_cumulative: u64,
    pub ipv6_processed_cumulative: u64,
    pub new_sessions_cumulative: u64,
    pub updated_sessions_cumulative: u64,
}

impl Default for PacketStats {
    fn default() -> Self {
        Self {
            total_processed: 0,
            tcp_processed: 0,
            udp_processed: 0,
            ipv4_processed: 0,
            ipv6_processed: 0,
            new_sessions: 0,
            updated_sessions: 0,
            last_log_time: Utc::now(),
            total_processed_cumulative: 0,
            tcp_processed_cumulative: 0,
            udp_processed_cumulative: 0,
            ipv4_processed_cumulative: 0,
            ipv6_processed_cumulative: 0,
            new_sessions_cumulative: 0,
            updated_sessions_cumulative: 0,
        }
    }
}

impl PacketStatsInternal {
    pub fn new() -> Self {
        Self {
            total_processed: AtomicU64::new(0),
            tcp_processed: AtomicU64::new(0),
            udp_processed: AtomicU64::new(0),
            ipv4_processed: AtomicU64::new(0),
            ipv6_processed: AtomicU64::new(0),
            new_sessions: AtomicU64::new(0),
            updated_sessions: AtomicU64::new(0),
            last_log_time: AtomicU64::new(0),
            total_processed_cumulative: AtomicU64::new(0),
            tcp_processed_cumulative: AtomicU64::new(0),
            udp_processed_cumulative: AtomicU64::new(0),
            ipv4_processed_cumulative: AtomicU64::new(0),
            ipv6_processed_cumulative: AtomicU64::new(0),
            new_sessions_cumulative: AtomicU64::new(0),
            updated_sessions_cumulative: AtomicU64::new(0),
        }
    }

    pub fn log_and_reset(&self) {
        if self.last_log_time.load(Ordering::Relaxed) == 0
            || (Utc::now().timestamp_millis() as u64)
                .saturating_sub(self.last_log_time.load(Ordering::Relaxed))
                > 30000
        {
            self.last_log_time
                .store(Utc::now().timestamp_millis() as u64, Ordering::Relaxed);
        } else {
            return;
        }

        let total = self.total_processed.swap(0, Ordering::Relaxed);
        let tcp = self.tcp_processed.swap(0, Ordering::Relaxed);
        let udp = self.udp_processed.swap(0, Ordering::Relaxed);
        let ipv4 = self.ipv4_processed.swap(0, Ordering::Relaxed);
        let ipv6 = self.ipv6_processed.swap(0, Ordering::Relaxed);
        let new = self.new_sessions.swap(0, Ordering::Relaxed);
        let updated = self.updated_sessions.swap(0, Ordering::Relaxed);

        // Only log if there was activity in the interval
        if total > 0 {
            info!(
                "Packet Stats (last 30s): Total={}, TCP={}, UDP={}, IPv4={}, IPv6={}, NewSessions={}, UpdatedSessions={}",
                total, tcp, udp, ipv4, ipv6, new, updated
            );
        }
    }
}

pub fn get_packet_stats() -> PacketStats {
    let last_log_time = PACKET_STATS.last_log_time.load(Ordering::Relaxed);
    let last_log_time =
        DateTime::<Utc>::from_timestamp_millis(last_log_time as i64).unwrap_or_else(Utc::now);

    PacketStats {
        // Windowed stats (last 30s)
        total_processed: PACKET_STATS.total_processed.load(Ordering::Relaxed),
        tcp_processed: PACKET_STATS.tcp_processed.load(Ordering::Relaxed),
        udp_processed: PACKET_STATS.udp_processed.load(Ordering::Relaxed),
        ipv4_processed: PACKET_STATS.ipv4_processed.load(Ordering::Relaxed),
        ipv6_processed: PACKET_STATS.ipv6_processed.load(Ordering::Relaxed),
        new_sessions: PACKET_STATS.new_sessions.load(Ordering::Relaxed),
        updated_sessions: PACKET_STATS.updated_sessions.load(Ordering::Relaxed),
        last_log_time,

        // Cumulative stats (since process start)
        total_processed_cumulative: PACKET_STATS
            .total_processed_cumulative
            .load(Ordering::Relaxed),
        tcp_processed_cumulative: PACKET_STATS
            .tcp_processed_cumulative
            .load(Ordering::Relaxed),
        udp_processed_cumulative: PACKET_STATS
            .udp_processed_cumulative
            .load(Ordering::Relaxed),
        ipv4_processed_cumulative: PACKET_STATS
            .ipv4_processed_cumulative
            .load(Ordering::Relaxed),
        ipv6_processed_cumulative: PACKET_STATS
            .ipv6_processed_cumulative
            .load(Ordering::Relaxed),
        new_sessions_cumulative: PACKET_STATS.new_sessions_cumulative.load(Ordering::Relaxed),
        updated_sessions_cumulative: PACKET_STATS
            .updated_sessions_cumulative
            .load(Ordering::Relaxed),
    }
}
