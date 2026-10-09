use crate::asn::*;
use crate::ip::is_lan_ip;
use crate::l7::FlodbaddL7;
use crate::packetstats::PACKET_STATS;
use crate::port_vulns::get_name_from_port;
use crate::sessions::session_macros::*;
use crate::sessions::*;
use crate::sni;
use chrono::{DateTime, Utc};
use dashmap::mapref::entry::Entry;
use lazy_static::lazy_static;
use pnet_packet::ethernet::{EtherTypes, EthernetPacket};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::tcp::{TcpFlags, TcpPacket};
use pnet_packet::udp::UdpPacket;
use pnet_packet::Packet as PnetPacket;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio;
use tracing::{trace, warn};
use undeadlock::*;
use uuid::Uuid;

const TCP_PSH: u8 = 0x08; // PSH (push) flag in TCP

// Maximum history string length - prevents unbounded memory growth for long-lived connections
// 1000 chars is enough for TCP flag analysis while keeping memory usage reasonable
// A high-traffic connection (60k packets/10s) would fill this in ~0.17 seconds
const MAX_HISTORY_LENGTH: usize = 1000;

/// Ports below this are IANA system ports: the side holding one is the
/// service.
const SYSTEM_PORT_CEILING: u16 = 1024;

/// IANA dynamic (ephemeral) range: a port here belongs to a client.
const DYNAMIC_PORT_FLOOR: u16 = 49_152;

/// Lowest port this host's OS picks for an outgoing connection by default
/// (Linux `ip_local_port_range` 32768-60999; macOS and Windows use the IANA
/// dynamic range). A local port below it was not picked for a connection
/// this host opened, so this host is listening on it.
#[cfg(target_os = "linux")]
const LOCAL_EPHEMERAL_PORT_FLOOR: u16 = 32_768;
#[cfg(not(target_os = "linux"))]
const LOCAL_EPHEMERAL_PORT_FLOOR: u16 = DYNAMIC_PORT_FLOOR;

/// The same flow keyed the other way round.
fn mirrored(session: &Session) -> Session {
    Session {
        protocol: session.protocol.clone(),
        src_ip: session.dst_ip,
        src_port: session.dst_port,
        dst_ip: session.src_ip,
        dst_port: session.src_port,
    }
}

/// TLS record content type for application data. A port-443 egress segment
/// that begins one is past the handshake, so it is never part of a
/// ClientHello and its payload is not carried for SNI reassembly.
const TLS_APPLICATION_DATA: u8 = 0x17;

/// A ClientHello lives in one TLS record, whose body is at most 2^14 bytes
/// (`5` is the record header). A node / Chromium ClientHello that carries a
/// post-quantum key share is ~1.6 KB and spans two TCP segments but stays
/// well under this; a would-be record larger than this is not reassembled.
const MAX_CLIENT_HELLO_BYTES: usize = 5 + (1 << 14);

/// A split ClientHello completes within the client's first couple of egress
/// segments. Give up after this many continuations so a flow that merely
/// looks like a truncated handshake cannot pin a buffer.
const MAX_CLIENT_HELLO_SEGMENTS: u8 = 4;

/// Reassembly buffers age out defensively; a real ClientHello finishes in
/// far less than this.
const CLIENT_HELLO_REASSEMBLY_TTL: Duration = Duration::from_secs(5);

/// Upper bound on concurrently reassembling flows. Over it (after aging),
/// partials are dropped wholesale -- a dropped partial just falls back to
/// DNS-based naming, never to a wrong name.
const MAX_CLIENT_HELLO_REASSEMBLIES: usize = 1024;

/// Partial ClientHello bytes for one flow whose client split the record
/// across TCP segments.
struct ClientHelloReassembly {
    /// Bytes gathered so far, starting at the TLS record header.
    buf: Vec<u8>,
    /// Total bytes the complete record occupies (`5` + record length).
    needed: usize,
    /// Continuation segments appended after the first.
    segments: u8,
    /// When the first fragment arrived, for age-based eviction.
    inserted: Instant,
}

lazy_static! {
    /// Per-flow partial ClientHello bytes, keyed by the oriented session.
    /// A client that splits its ClientHello across TCP segments -- common
    /// once the record carries a post-quantum key share, which pushes it
    /// past one segment -- would otherwise lose its SNI, because any single
    /// segment holds only a truncated TLS record. Entries are short lived:
    /// dropped on SNI extraction, when the peer replies, on a segment/byte
    /// cap, or by age.
    static ref CLIENT_HELLO_REASSEMBLY: CustomDashMap<Session, ClientHelloReassembly> =
        CustomDashMap::new("client_hello_reassembly");
}

/// Carry an egress port-443 TCP payload so the SNI can be recovered even when
/// the ClientHello spans several TCP segments. The first segment starts a
/// handshake record (`0x16`); later segments carry the record's tail with no
/// header of their own, so a continuation is kept too, bounded to a
/// ClientHello's worth of bytes. Application-data records (`0x17`) are past
/// the handshake and are never carried, which keeps the steady-state upload
/// path from copying payloads.
fn carry_tls_egress_payload(dst_port: u16, payload: &[u8]) -> Option<Vec<u8>> {
    if dst_port != 443 {
        return None;
    }
    match payload.first() {
        None | Some(&TLS_APPLICATION_DATA) => None,
        Some(_) => Some(payload[..payload.len().min(MAX_CLIENT_HELLO_BYTES)].to_vec()),
    }
}

/// Feed one carried egress port-443 payload (see [`carry_tls_egress_payload`])
/// into the per-flow ClientHello reassembler and return the SNI hostname once
/// the whole record is in hand. A ClientHello that fits in one segment is
/// handled inline with no buffering, matching the previous behavior.
fn reassemble_client_hello_sni(key: &Session, payload: &[u8]) -> Option<String> {
    // Continuation of a ClientHello already started for this flow.
    if let Some(mut state) = CLIENT_HELLO_REASSEMBLY.get_mut(key) {
        state.segments = state.segments.saturating_add(1);
        let room = state.needed.min(MAX_CLIENT_HELLO_BYTES);
        if state.buf.len() < room {
            let take = (room - state.buf.len()).min(payload.len());
            state.buf.extend_from_slice(&payload[..take]);
        }
        let have = state.buf.len();
        let done = have >= state.needed || state.segments >= MAX_CLIENT_HELLO_SEGMENTS;
        drop(state);
        if done {
            if let Some((_, state)) = CLIENT_HELLO_REASSEMBLY.remove(key) {
                return sni::extract_sni(&state.buf).map(|info| info.hostname);
            }
        }
        return None;
    }

    // Not tracking this flow yet: only the start of a handshake record opens
    // one. Anything else (app data, a continuation we never saw begin) is
    // ignored cheaply.
    let needed = sni::client_hello_record_len(payload)?;
    if payload.len() >= needed {
        // Whole ClientHello in a single segment -- no state needed.
        return sni::extract_sni(payload).map(|info| info.hostname);
    }
    if needed <= MAX_CLIENT_HELLO_BYTES {
        prune_client_hello_reassembly();
        CLIENT_HELLO_REASSEMBLY.insert(
            key.clone(),
            ClientHelloReassembly {
                buf: payload.to_vec(),
                needed,
                segments: 0,
                inserted: Instant::now(),
            },
        );
    }
    None
}

/// Drop a flow's partial ClientHello: the handshake is done being sent (the
/// peer replied) or the connection closed. Called while holding no reassembly
/// guard.
fn forget_client_hello_reassembly(key: &Session) {
    if !CLIENT_HELLO_REASSEMBLY.is_empty() {
        CLIENT_HELLO_REASSEMBLY.remove(key);
    }
}

/// Evict aged partials, and if still at the cap, drop them all. Called only
/// when about to insert a new partial, so the common path never scans.
fn prune_client_hello_reassembly() {
    let now = Instant::now();
    CLIENT_HELLO_REASSEMBLY
        .retain(|_, state| now.duration_since(state.inserted) < CLIENT_HELLO_REASSEMBLY_TTL);
    if CLIENT_HELLO_REASSEMBLY.len() >= MAX_CLIENT_HELLO_REASSEMBLIES {
        CLIENT_HELLO_REASSEMBLY.clear();
    }
}

/// Whether the source of a packet is the server of its flow, for a packet
/// that does not say so itself (no SYN) between two ports that both carry a
/// service name. In order:
/// 1. a system port (< 1024) against a higher one: the system port serves;
/// 2. a dynamic port (>= 49152) against a lower one: the dynamic port is the
///    client's;
/// 3. exactly one end is this host: it serves when its port is below the
///    range its OS picks outgoing ports from (an inbound connection from a
///    client that uses a low source port, `remote:2142 -> host:3389`, is
///    keyed as inbound);
/// 4. otherwise the lower port serves.
///
/// Equal ports (NTP 123 to 123, mDNS 5353 to 5353) say nothing: the packet
/// keeps its direction, so the first packet of the flow decides.
fn packet_source_serves(session: &Session, own_ips: &HashSet<IpAddr>) -> bool {
    let (src_port, dst_port) = (session.src_port, session.dst_port);
    if src_port == dst_port {
        return false;
    }
    if (src_port < SYSTEM_PORT_CEILING) != (dst_port < SYSTEM_PORT_CEILING) {
        return src_port < SYSTEM_PORT_CEILING;
    }
    if (src_port >= DYNAMIC_PORT_FLOOR) != (dst_port >= DYNAMIC_PORT_FLOOR) {
        return dst_port >= DYNAMIC_PORT_FLOOR;
    }
    let src_is_own = own_ips.contains(&session.src_ip);
    let dst_is_own = own_ips.contains(&session.dst_ip);
    if src_is_own != dst_is_own {
        let own_port = if src_is_own { src_port } else { dst_port };
        let own_side_listens = own_port < LOCAL_EPHEMERAL_PORT_FLOOR;
        return if src_is_own {
            own_side_listens
        } else {
            !own_side_listens
        };
    }
    src_port < dst_port
}

/// The key (client as source, server as destination) of a flow first seen
/// through this packet.
fn orient_new_flow(
    session: &Session,
    flags: Option<u8>,
    src_is_service_port: bool,
    dst_is_service_port: bool,
    own_ips: &HashSet<IpAddr>,
) -> Session {
    if src_is_service_port && !dst_is_service_port {
        // Source is likely a server, swap to make the client (initiator) the source
        return mirrored(session);
    }
    if !(src_is_service_port && dst_is_service_port) {
        // Destination is the service, or neither port says: keep the packet's direction
        return session.clone();
    }
    // Both are service ports: the handshake flags decide when present.
    if let Some(flags) = flags {
        if session.protocol == Protocol::TCP && flags & TcpFlags::SYN != 0 {
            return if flags & TcpFlags::ACK == 0 {
                // SYN without ACK: the source opens the connection
                session.clone()
            } else {
                // SYN+ACK: the source answers
                mirrored(session)
            };
        }
    }
    if packet_source_serves(session, own_ips) {
        mirrored(session)
    } else {
        session.clone()
    }
}

#[derive(Debug, PartialEq)]
pub enum ParsedPacket {
    SessionPacket(SessionPacketData),
    DnsPacket(DnsPacketData),
    /// DNS traffic that is tracked both as a session (for anomaly/vulnerability
    /// detection) and as a DNS payload (for passive domain resolution).
    DnsSessionPacket(SessionPacketData, DnsPacketData),
}

#[derive(Debug, PartialEq, Clone)]
pub struct SessionPacketData {
    pub session: Session,
    pub packet_length: usize,
    pub ip_packet_length: usize,
    pub flags: Option<u8>,
    pub timestamp: DateTime<Utc>,
    /// TCP payload for potential SNI extraction (only for port 443 first packets)
    pub tls_client_hello: Option<Vec<u8>>,
}

#[derive(Debug, PartialEq)]
pub struct DnsPacketData {
    pub dns_payload: Vec<u8>,
}

// Helper: fast, in-place stats update for existing sessions
fn update_session_stats(
    stats: &mut SessionStats,
    parsed_packet: &SessionPacketData,
    now: chrono::DateTime<chrono::Utc>,
    is_originator: bool,
) {
    // Direction-aware byte/packet counters --------------------------------
    if is_originator {
        stats.outbound_bytes += parsed_packet.packet_length as u64;
        stats.orig_pkts += 1;
        stats.orig_ip_bytes += parsed_packet.ip_packet_length as u64;
    } else {
        stats.inbound_bytes += parsed_packet.packet_length as u64;
        stats.resp_pkts += 1;
        stats.resp_ip_bytes += parsed_packet.ip_packet_length as u64;
    }

    // Average pkt size + inbound/outbound ratio ---------------------------
    let total_packets = stats.orig_pkts + stats.resp_pkts;
    let total_bytes = stats.inbound_bytes + stats.outbound_bytes;
    stats.average_packet_size = if total_packets > 0 {
        total_bytes as f64 / total_packets as f64
    } else {
        0.0
    };

    stats.inbound_outbound_ratio = if stats.outbound_bytes > 0 {
        stats.inbound_bytes as f64 / stats.outbound_bytes as f64
    } else {
        0.0
    };

    // Segment detection ---------------------------------------------------
    let time_since_last_activity = (now - stats.last_activity).num_milliseconds() as f64 / 1000.0; // seconds

    let is_segment_end = if parsed_packet.session.protocol == Protocol::TCP {
        if let Some(flags) = parsed_packet.flags {
            (flags & TCP_PSH) != 0
        } else {
            false
        }
    } else {
        false
    } || (stats.in_segment
        && time_since_last_activity >= stats.segment_timeout);

    if !stats.in_segment {
        stats.in_segment = true;
        stats.current_segment_start = now;
    }

    if is_segment_end && stats.in_segment {
        let previous_end = stats.last_segment_end;
        stats.segment_count += 1;
        stats.in_segment = false;
        stats.last_segment_end = Some(now);

        if let Some(prev_end) = previous_end {
            let seg_ia =
                (stats.current_segment_start - prev_end).num_milliseconds() as f64 / 1000.0;
            if seg_ia >= 0.0 {
                stats.total_segment_interarrival += seg_ia;
                stats.segment_interarrival = if stats.segment_count > 1 {
                    stats.total_segment_interarrival / (stats.segment_count - 1) as f64
                } else {
                    0.0
                };
            } else {
                warn!(
                    "Negative segment interarrival calculated ({}ms). Current start: {:?}, Previous end: {:?}. Skipping.",
                    (stats.current_segment_start - prev_end).num_milliseconds(),
                    stats.current_segment_start,
                    prev_end
                );
            }
        }

        if time_since_last_activity >= stats.segment_timeout {
            stats.in_segment = true;
            stats.current_segment_start = now;
        }
    }

    // Update last activity -----------------------------------------------
    stats.last_activity = now;

    // History & connection state -----------------------------------------
    if let Some(flags) = parsed_packet.flags {
        let c = map_tcp_flags(flags, parsed_packet.packet_length, is_originator);
        // Cap history length to prevent unbounded memory growth for long-lived connections
        if stats.history.len() < MAX_HISTORY_LENGTH {
            stats.history.push(c);
        }
        if (flags & (TcpFlags::FIN | TcpFlags::RST)) != 0 && stats.end_time.is_none() {
            stats.end_time = Some(now);
            stats.conn_state = Some(determine_conn_state(&stats.history));
        }
    }
}

pub async fn process_parsed_packet(
    parsed_packet: SessionPacketData,
    sessions: &Arc<CustomDashMap<Session, SessionInfo>>,
    current_sessions: &Arc<CustomRwLock<Vec<Session>>>,
    own_ips: &HashSet<IpAddr>,
    filter: &Arc<CustomRwLock<SessionFilter>>,
    l7: Option<&Arc<FlodbaddL7>>,
) {
    // --- Increment Counters (both windowed and cumulative) ---
    PACKET_STATS.total_processed.fetch_add(1, Ordering::Relaxed);
    PACKET_STATS
        .total_processed_cumulative
        .fetch_add(1, Ordering::Relaxed);

    match parsed_packet.session.protocol {
        Protocol::TCP => {
            PACKET_STATS.tcp_processed.fetch_add(1, Ordering::Relaxed);
            PACKET_STATS
                .tcp_processed_cumulative
                .fetch_add(1, Ordering::Relaxed);
        }
        Protocol::UDP => {
            PACKET_STATS.udp_processed.fetch_add(1, Ordering::Relaxed);
            PACKET_STATS
                .udp_processed_cumulative
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    match parsed_packet.session.src_ip {
        IpAddr::V4(_) => {
            PACKET_STATS.ipv4_processed.fetch_add(1, Ordering::Relaxed);
            PACKET_STATS
                .ipv4_processed_cumulative
                .fetch_add(1, Ordering::Relaxed);
        }
        IpAddr::V6(_) => {
            PACKET_STATS.ipv6_processed.fetch_add(1, Ordering::Relaxed);
            PACKET_STATS
                .ipv6_processed_cumulative
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    // --- End Increment Counters ---

    let now = parsed_packet.timestamp;

    // Check if the ports are known service ports
    let src_service_name = get_name_from_port(parsed_packet.session.src_port).await;
    let dst_service_name = get_name_from_port(parsed_packet.session.dst_port).await;

    let src_is_service_port = !src_service_name.is_empty();
    let dst_is_service_port = !dst_service_name.is_empty();

    // Key the flow client -> server. A flow keeps the orientation its first
    // packet (usually the SYN) gave it: a later packet whose ports alone would
    // orient it the other way updates that session instead of opening a
    // mirror session keyed the other way round.
    let oriented = orient_new_flow(
        &parsed_packet.session,
        parsed_packet.flags,
        src_is_service_port,
        dst_is_service_port,
        own_ips,
    );
    // A pure SYN opens a new connection and says who opened it: it is never
    // folded into an earlier flow keyed the other way.
    let opens_connection = parsed_packet.session.protocol == Protocol::TCP
        && parsed_packet.flags.map_or(false, |flags| {
            flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK == 0
        });
    let key = if !opens_connection
        && !sessions.contains_key(&oriented)
        && sessions.contains_key(&mirrored(&oriented))
    {
        mirrored(&oriented)
    } else {
        oriented
    };

    // Determine if this packet is from originator to responder or vice versa
    // A packet is from the originator if it matches the flow direction of the session key
    // Otherwise it's a response packet from responder to originator
    let is_originator = parsed_packet.session.src_ip == key.src_ip
        && parsed_packet.session.src_port == key.src_port
        && parsed_packet.session.dst_ip == key.dst_ip
        && parsed_packet.session.dst_port == key.dst_port;

    // Apply filter before processing
    let filter = filter.read().await.clone();
    if filter == SessionFilter::LocalOnly && is_global_session!(parsed_packet) {
        return;
    } else if filter == SessionFilter::GlobalOnly && is_local_session!(parsed_packet) {
        return;
    }

    // Fast path: update existing session with minimal lock time
    if let Some(mut entry) = sessions.get_mut(&key) {
        PACKET_STATS
            .updated_sessions
            .fetch_add(1, Ordering::Relaxed);
        PACKET_STATS
            .updated_sessions_cumulative
            .fetch_add(1, Ordering::Relaxed);
        update_session_stats(&mut entry.stats, &parsed_packet, now, is_originator);
        // The ClientHello follows the handshake, so for a connection seen from
        // its SYN it reaches this path, not the new-session one: take the SNI
        // here too. The name the client asked for is this session's own; the
        // resolver's names are per address, which CDN tenants share. A client
        // that split the ClientHello across TCP segments is reassembled across
        // these updates (`reassemble_client_hello_sni`).
        if entry.dst_domain_type != DomainResolutionType::SNI {
            if is_originator {
                if let Some(hostname) = parsed_packet
                    .tls_client_hello
                    .as_ref()
                    .and_then(|payload| reassemble_client_hello_sni(&key, payload))
                {
                    trace!(
                        "Extracted SNI hostname '{}' for session {:?}",
                        hostname,
                        key
                    );
                    entry.dst_domain = Some(hostname);
                    entry.dst_domain_type = DomainResolutionType::SNI;
                }
            } else if parsed_packet.packet_length > 0 {
                // The peer sent data, so it already has the full ClientHello
                // (a server cannot answer before then): drop any partial still
                // held for this flow. A bare ACK carries no such signal and
                // must not discard a ClientHello still in flight.
                forget_client_hello_reassembly(&key);
            }
        }
        entry.last_modified = now;
        return;
    }

    // --- New session: perform all async lookups BEFORE touching the DashMap ---
    // Another packet might create this session while we do lookups; we handle
    // that race in the Entry::Occupied arm at the end.

    PACKET_STATS.new_sessions.fetch_add(1, Ordering::Relaxed);
    PACKET_STATS
        .new_sessions_cumulative
        .fetch_add(1, Ordering::Relaxed);

    let uid = Uuid::new_v4().to_string();

    let mut stats = SessionStats {
        start_time: now,
        end_time: None,
        last_activity: now,
        inbound_bytes: 0,
        outbound_bytes: 0,
        orig_pkts: 0,
        resp_pkts: 0,
        orig_ip_bytes: 0,
        resp_ip_bytes: 0,
        history: String::new(),
        conn_state: None,
        missed_bytes: 0,
        average_packet_size: 0.0,
        inbound_outbound_ratio: 0.0,
        segment_count: 0,
        current_segment_start: now,
        last_segment_end: None,
        segment_interarrival: 0.0,
        total_segment_interarrival: 0.0,
        in_segment: true,
        segment_timeout: 5.0,
    };

    if is_originator {
        stats.outbound_bytes += parsed_packet.packet_length as u64;
        stats.orig_pkts += 1;
        stats.orig_ip_bytes += parsed_packet.ip_packet_length as u64;
    } else {
        stats.inbound_bytes += parsed_packet.packet_length as u64;
        stats.resp_pkts += 1;
        stats.resp_ip_bytes += parsed_packet.ip_packet_length as u64;
    }

    let total_packets = stats.orig_pkts + stats.resp_pkts;
    let total_bytes = stats.inbound_bytes + stats.outbound_bytes;
    stats.average_packet_size = if total_packets > 0 {
        total_bytes as f64 / total_packets as f64
    } else {
        0.0
    };

    stats.inbound_outbound_ratio = if stats.outbound_bytes > 0 {
        stats.inbound_bytes as f64 / stats.outbound_bytes as f64
    } else {
        0.0
    };

    if let Some(flags) = parsed_packet.flags {
        let c = map_tcp_flags(flags, parsed_packet.packet_length, is_originator);
        stats.history.push(c);

        if parsed_packet.session.protocol == Protocol::TCP && (flags & TCP_PSH) != 0 {
            stats.segment_count = 1;
            stats.in_segment = false;
            stats.last_segment_end = Some(now);
        }

        if (flags & (TcpFlags::FIN | TcpFlags::RST)) != 0 {
            stats.end_time = Some(now);
            stats.conn_state = Some(determine_conn_state(&stats.history));
        }
    }

    let is_local_src = is_lan_ip(&key.src_ip);
    let is_local_dst = is_lan_ip(&key.dst_ip);
    let is_self_src = own_ips.contains(&key.src_ip);
    let is_self_dst = own_ips.contains(&key.dst_ip);

    trace!("New session: {:?}. Performing lookups concurrently.", key);

    let src_ip_lookup = key.src_ip;
    let dst_ip_lookup = key.dst_ip;

    let dst_service = if key.dst_port == parsed_packet.session.dst_port {
        if !dst_service_name.is_empty() {
            Some(dst_service_name)
        } else {
            None
        }
    } else if key.dst_port == parsed_packet.session.src_port {
        if !src_service_name.is_empty() {
            Some(src_service_name)
        } else {
            None
        }
    } else {
        warn!("Unexpected port mismatch in session key. Will look up service name.");
        let name = get_name_from_port(key.dst_port).await;
        if !name.is_empty() {
            Some(name)
        } else {
            None
        }
    };

    let (src_asn_opt, dst_asn_opt) = tokio::join!(
        async {
            if !is_local_src {
                get_asn(src_ip_lookup).await
            } else {
                None
            }
        },
        async {
            if !is_local_dst {
                get_asn(dst_ip_lookup).await
            } else {
                None
            }
        },
    );

    trace!("Lookups completed for session: {:?}", key);

    if let Some(l7) = l7 {
        l7.add_connection_to_resolver(&key).await;
        trace!("Added session {:?} to L7 resolver queue", key);
    }

    let status = SessionStatus {
        active: true,
        added: true,
        activated: true,
        deactivated: false,
    };

    let (dst_domain, dst_domain_type) = if let Some(hostname) = parsed_packet
        .tls_client_hello
        .as_ref()
        .filter(|_| is_originator)
        .and_then(|payload| reassemble_client_hello_sni(&key, payload))
    {
        trace!(
            "Extracted SNI hostname '{}' for session {:?}",
            hostname,
            key
        );
        (Some(hostname), DomainResolutionType::SNI)
    } else {
        (None, DomainResolutionType::None)
    };

    let session_info = SessionInfo {
        session: key.clone(),
        stats,
        status,
        is_local_src,
        is_local_dst,
        is_self_src,
        is_self_dst,
        src_domain: None,
        dst_domain,
        dst_service,
        l7: None,
        src_asn: src_asn_opt,
        dst_asn: dst_asn_opt,
        is_whitelisted: WhitelistState::Unknown,
        criticality: "".to_string(),
        dismissed: false,
        whitelist_reason: None,
        src_domain_type: DomainResolutionType::None,
        dst_domain_type,
        uid,
        last_modified: Utc::now(),
    };

    // All async work is done -- now do a quick atomic insert.
    // Use entry() so we handle the race where another packet created
    // this session while we were doing lookups.
    let mirror_key = mirrored(&key);
    if let Some(mut mirror) = sessions.get_mut(&mirror_key).filter(|_| !opens_connection) {
        // Another packet of this flow created it the other way round while we
        // did the lookups: keep that orientation.
        update_session_stats(&mut mirror.stats, &parsed_packet, now, !is_originator);
        mirror.last_modified = now;
        return;
    }
    match sessions.entry(key.clone()) {
        Entry::Occupied(mut occ) => {
            let info = occ.get_mut();
            update_session_stats(&mut info.stats, &parsed_packet, now, is_originator);
            info.last_modified = now;
        }
        Entry::Vacant(vacant) => {
            vacant.insert(session_info);
            trace!("Inserted session info for {:?} into main map", key);
        }
    }

    current_sessions.write().await.push(key.clone());
    trace!("Added session key {:?} to current sessions vector", key);
    PACKET_STATS.log_and_reset();
}

fn determine_conn_state(history: &str) -> String {
    if history.contains('S')
        && history.contains('H')
        && history.contains('F')
        && history.contains('f')
    {
        "SF".to_string()
    } else if history.contains('S') && !history.contains('h') && !history.contains('r') {
        "S0".to_string()
    } else if history.contains('R') || history.contains('r') {
        "REJ".to_string()
    } else if history.contains('S')
        && history.contains('H')
        && !history.contains('F')
        && !history.contains('f')
    {
        "S1".to_string()
    } else {
        "-".to_string()
    }
}

fn map_tcp_flags(flags: u8, packet_length: usize, is_originator: bool) -> char {
    if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK == 0 {
        if is_originator {
            'S'
        } else {
            's'
        }
    } else if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 {
        if is_originator {
            'H'
        } else {
            'h'
        }
    } else if flags & TcpFlags::FIN != 0 {
        if is_originator {
            'F'
        } else {
            'f'
        }
    } else if flags & TcpFlags::RST != 0 {
        if is_originator {
            'R'
        } else {
            'r'
        }
    } else if packet_length > 0 {
        if is_originator {
            '>'
        } else {
            '<'
        }
    } else if flags & TcpFlags::ACK != 0 {
        if is_originator {
            'A'
        } else {
            'a'
        }
    } else {
        '-'
    }
}

pub fn parse_packet_pcap(packet_data: &[u8], timestamp: DateTime<Utc>) -> Option<ParsedPacket> {
    let ethernet = match EthernetPacket::new(packet_data) {
        Some(packet) => packet,
        None => {
            warn!("Failed to parse Ethernet packet");
            return None;
        }
    };
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            let ipv4 = match Ipv4Packet::new(ethernet.payload()) {
                Some(packet) => packet,
                None => {
                    warn!("Failed to parse IPv4 packet");
                    return None;
                }
            };
            let ip_packet_length = ipv4.get_total_length() as usize;
            let next_protocol = ipv4.get_next_level_protocol();
            match next_protocol {
                IpNextHeaderProtocols::Tcp => {
                    let tcp = match TcpPacket::new(ipv4.payload()) {
                        Some(packet) => packet,
                        None => {
                            warn!("Failed to parse TCP packet");
                            return None;
                        }
                    };
                    let src_ip = IpAddr::V4(ipv4.get_source());
                    let dst_ip = IpAddr::V4(ipv4.get_destination());
                    let src_port = tcp.get_source();
                    let dst_port = tcp.get_destination();
                    let flags = tcp.get_flags(); // flags is u8
                    let packet_length = tcp.payload().len();

                    if src_port == 53 || dst_port == 53 {
                        let mut dns_payload = tcp.payload().to_vec();
                        if dns_payload.len() < 2 {
                            // Sub-2-byte port-53 TCP segments are normal control
                            // frames (SYN/ACK/FIN with no DNS length prefix), not an
                            // error. Demoted from warn! to avoid ~1.5k log lines/day.
                            trace!("DNS-over-TCP payload too short: {:?}", dns_payload);
                            return None;
                        }
                        dns_payload.drain(0..2);
                        trace!("Found DNS over TCP for IPv4: {:?}", dns_payload);
                        let session = Session {
                            protocol: Protocol::TCP,
                            src_ip,
                            src_port,
                            dst_ip,
                            dst_port,
                        };
                        return Some(ParsedPacket::DnsSessionPacket(
                            SessionPacketData {
                                session,
                                packet_length,
                                ip_packet_length,
                                flags: Some(flags),
                                timestamp,
                                tls_client_hello: None,
                            },
                            DnsPacketData { dns_payload },
                        ));
                    }

                    let session = Session {
                        protocol: Protocol::TCP,
                        src_ip,
                        src_port,
                        dst_ip,
                        dst_port,
                    };

                    let tls_client_hello = carry_tls_egress_payload(dst_port, tcp.payload());

                    Some(ParsedPacket::SessionPacket(SessionPacketData {
                        session,
                        packet_length,
                        ip_packet_length,
                        flags: Some(flags),
                        timestamp,
                        tls_client_hello,
                    }))
                }
                IpNextHeaderProtocols::Udp => {
                    let udp = match UdpPacket::new(ipv4.payload()) {
                        Some(packet) => packet,
                        None => {
                            warn!("Failed to parse UDP packet");
                            return None;
                        }
                    };
                    let src_ip = IpAddr::V4(ipv4.get_source());
                    let dst_ip = IpAddr::V4(ipv4.get_destination());
                    let src_port = udp.get_source();
                    let dst_port = udp.get_destination();
                    let packet_length = udp.payload().len();

                    if src_port == 53 || dst_port == 53 {
                        let dns_payload = udp.payload().to_vec();
                        trace!("Found DNS over UDP for IPv4: {:?}", dns_payload);
                        let session = Session {
                            protocol: Protocol::UDP,
                            src_ip,
                            src_port,
                            dst_ip,
                            dst_port,
                        };
                        return Some(ParsedPacket::DnsSessionPacket(
                            SessionPacketData {
                                session,
                                packet_length,
                                ip_packet_length,
                                flags: None,
                                timestamp,
                                tls_client_hello: None,
                            },
                            DnsPacketData { dns_payload },
                        ));
                    }

                    let session = Session {
                        protocol: Protocol::UDP,
                        src_ip,
                        src_port,
                        dst_ip,
                        dst_port,
                    };

                    Some(ParsedPacket::SessionPacket(SessionPacketData {
                        session,
                        packet_length,
                        ip_packet_length,
                        flags: None,
                        timestamp,
                        tls_client_hello: None,
                    }))
                }
                _ => None,
            }
        }
        EtherTypes::Ipv6 => {
            let ipv6 = match Ipv6Packet::new(ethernet.payload()) {
                Some(packet) => packet,
                None => {
                    warn!("Failed to parse IPv6 packet");
                    return None;
                }
            };
            let ip_packet_length = ipv6.get_payload_length() as usize + 40; // IPv6 header is 40 bytes
            let next_protocol = ipv6.get_next_header();
            match next_protocol {
                IpNextHeaderProtocols::Tcp => {
                    let tcp = match TcpPacket::new(ipv6.payload()) {
                        Some(packet) => packet,
                        None => {
                            warn!("Failed to parse TCP packet");
                            return None;
                        }
                    };
                    let src_ip = IpAddr::V6(ipv6.get_source());
                    let dst_ip = IpAddr::V6(ipv6.get_destination());
                    let src_port = tcp.get_source();
                    let dst_port = tcp.get_destination();
                    let flags = tcp.get_flags(); // flags is u8
                    let packet_length = tcp.payload().len();

                    if src_port == 53 || dst_port == 53 {
                        let mut dns_payload = tcp.payload().to_vec();
                        if dns_payload.len() < 2 {
                            // Sub-2-byte port-53 TCP segments are normal control
                            // frames (SYN/ACK/FIN with no DNS length prefix), not an
                            // error. Demoted from warn! to avoid ~1.5k log lines/day.
                            trace!("DNS-over-TCP payload too short: {:?}", dns_payload);
                            return None;
                        }
                        dns_payload.drain(0..2);
                        trace!("Found DNS over TCP for IPv6: {:?}", dns_payload);
                        let session = Session {
                            protocol: Protocol::TCP,
                            src_ip,
                            src_port,
                            dst_ip,
                            dst_port,
                        };
                        return Some(ParsedPacket::DnsSessionPacket(
                            SessionPacketData {
                                session,
                                packet_length,
                                ip_packet_length,
                                flags: Some(flags),
                                timestamp,
                                tls_client_hello: None,
                            },
                            DnsPacketData { dns_payload },
                        ));
                    }

                    let session = Session {
                        protocol: Protocol::TCP,
                        src_ip,
                        src_port,
                        dst_ip,
                        dst_port,
                    };

                    let tls_client_hello = carry_tls_egress_payload(dst_port, tcp.payload());

                    Some(ParsedPacket::SessionPacket(SessionPacketData {
                        session,
                        packet_length,
                        ip_packet_length,
                        flags: Some(flags),
                        timestamp,
                        tls_client_hello,
                    }))
                }
                IpNextHeaderProtocols::Udp => {
                    let udp = match UdpPacket::new(ipv6.payload()) {
                        Some(packet) => packet,
                        None => {
                            warn!("Failed to parse UDP packet");
                            return None;
                        }
                    };
                    let src_ip = IpAddr::V6(ipv6.get_source());
                    let dst_ip = IpAddr::V6(ipv6.get_destination());
                    let src_port = udp.get_source();
                    let dst_port = udp.get_destination();
                    let packet_length = udp.payload().len();

                    if src_port == 53 || dst_port == 53 {
                        let dns_payload = udp.payload().to_vec();
                        trace!("Found DNS over UDP for IPv6: {:?}", dns_payload);
                        let session = Session {
                            protocol: Protocol::UDP,
                            src_ip,
                            src_port,
                            dst_ip,
                            dst_port,
                        };
                        return Some(ParsedPacket::DnsSessionPacket(
                            SessionPacketData {
                                session,
                                packet_length,
                                ip_packet_length,
                                flags: None,
                                timestamp,
                                tls_client_hello: None,
                            },
                            DnsPacketData { dns_payload },
                        ));
                    }

                    let session = Session {
                        protocol: Protocol::UDP,
                        src_ip,
                        src_port,
                        dst_ip,
                        dst_port,
                    };

                    Some(ParsedPacket::SessionPacket(SessionPacketData {
                        session,
                        packet_length,
                        ip_packet_length,
                        flags: None,
                        timestamp,
                        tls_client_hello: None,
                    }))
                }
                _ => None,
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use pnet_packet::tcp::TcpFlags;
    use serial_test::serial;
    use std::net::{IpAddr, Ipv4Addr};
    use std::{collections::HashSet, sync::Arc};
    use undeadlock::CustomRwLock;

    fn tcp_packet(
        src: (Ipv4Addr, u16),
        dst: (Ipv4Addr, u16),
        flags: u8,
        payload: usize,
        client_hello: Option<Vec<u8>>,
    ) -> SessionPacketData {
        SessionPacketData {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(src.0),
                src_port: src.1,
                dst_ip: IpAddr::V4(dst.0),
                dst_port: dst.1,
            },
            packet_length: payload,
            ip_packet_length: payload + 40,
            flags: Some(flags),
            timestamp: Utc::now(),
            tls_client_hello: client_hello,
        }
    }

    /// A named port below 3389, used as a client's source port.
    async fn named_low_client_port() -> u16 {
        for port in [1433u16, 3306, 1723, 2049, 1521, 2083] {
            if !get_name_from_port(port).await.is_empty() {
                return port;
            }
        }
        panic!("no named port below 3389 in the port database");
    }

    /// An inbound connection to the host's port 3389 from a client whose
    /// source port is named and lower: the whole flow, handshake and data in
    /// both directions, is one inbound session (never egress).
    #[tokio::test]
    #[serial]
    async fn test_inbound_connection_from_low_named_port_stays_inbound() {
        let client_port = named_low_client_port().await;
        assert!(
            !get_name_from_port(3389).await.is_empty(),
            "3389 must be a named service port for this case"
        );
        let host = Ipv4Addr::new(192, 0, 2, 10);
        let client = Ipv4Addr::new(203, 0, 113, 7);
        let own: HashSet<IpAddr> = [IpAddr::V4(host)].into_iter().collect();
        let sessions = Arc::new(CustomDashMap::new("sessions"));
        let current = Arc::new(CustomRwLock::new(Vec::new()));
        let filter = Arc::new(CustomRwLock::new(SessionFilter::All));

        let packets = vec![
            tcp_packet((client, client_port), (host, 3389), TcpFlags::SYN, 0, None),
            tcp_packet(
                (host, 3389),
                (client, client_port),
                TcpFlags::SYN | TcpFlags::ACK,
                0,
                None,
            ),
            tcp_packet((client, client_port), (host, 3389), TcpFlags::ACK, 0, None),
            tcp_packet(
                (client, client_port),
                (host, 3389),
                TcpFlags::ACK | TcpFlags::PSH,
                19,
                None,
            ),
            tcp_packet(
                (host, 3389),
                (client, client_port),
                TcpFlags::ACK | TcpFlags::PSH,
                19,
                None,
            ),
            tcp_packet((client, client_port), (host, 3389), TcpFlags::RST, 0, None),
        ];
        for packet in packets {
            process_parsed_packet(packet, &sessions, &current, &own, &filter, None).await;
        }

        assert_eq!(sessions.len(), 1, "one flow, one session");
        let inbound = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::V4(client),
            src_port: client_port,
            dst_ip: IpAddr::V4(host),
            dst_port: 3389,
        };
        let info = sessions.get(&inbound).expect("keyed client -> host:3389");
        assert!(info.is_self_dst && !info.is_self_src, "inbound, not egress");
        assert!(!crate::whitelists::is_egress_session(&info));
        assert_eq!(
            info.stats.orig_pkts, 4,
            "the client's packets count as the originator's"
        );
        assert_eq!(info.stats.resp_pkts, 2);
    }

    /// The same flow first seen mid-stream (the handshake before the capture,
    /// or dropped): the host's side holds a port its OS would not pick for an
    /// outgoing connection, so the host is the server.
    #[tokio::test]
    #[serial]
    async fn test_midstream_inbound_flow_keyed_to_the_listening_host() {
        let client_port = named_low_client_port().await;
        let host = Ipv4Addr::new(192, 0, 2, 11);
        let client = Ipv4Addr::new(198, 51, 100, 23);
        let own: HashSet<IpAddr> = [IpAddr::V4(host)].into_iter().collect();
        let sessions = Arc::new(CustomDashMap::new("sessions"));
        let current = Arc::new(CustomRwLock::new(Vec::new()));
        let filter = Arc::new(CustomRwLock::new(SessionFilter::All));

        // Either packet may come first.
        for packet in [
            tcp_packet(
                (host, 3389),
                (client, client_port),
                TcpFlags::ACK | TcpFlags::PSH,
                40,
                None,
            ),
            tcp_packet(
                (client, client_port),
                (host, 3389),
                TcpFlags::ACK | TcpFlags::PSH,
                40,
                None,
            ),
        ] {
            process_parsed_packet(packet, &sessions, &current, &own, &filter, None).await;
        }
        assert_eq!(sessions.len(), 1);
        let entry = sessions.iter().next().unwrap();
        assert_eq!(entry.key().dst_ip, IpAddr::V4(host));
        assert_eq!(entry.key().dst_port, 3389);
        assert!(!crate::whitelists::is_egress_session(entry.value()));
    }

    /// Egress keeps its direction: the host's own ephemeral port against a
    /// named remote port, first seen mid-stream from the remote side.
    #[tokio::test]
    #[serial]
    async fn test_midstream_egress_flow_stays_egress() {
        let host = Ipv4Addr::new(10, 1, 0, 4);
        let remote = Ipv4Addr::new(140, 82, 112, 5);
        let own: HashSet<IpAddr> = [IpAddr::V4(host)].into_iter().collect();
        let sessions = Arc::new(CustomDashMap::new("sessions"));
        let current = Arc::new(CustomRwLock::new(Vec::new()));
        let filter = Arc::new(CustomRwLock::new(SessionFilter::All));
        for packet in [
            tcp_packet(
                (remote, 443),
                (host, 50123),
                TcpFlags::ACK | TcpFlags::PSH,
                1200,
                None,
            ),
            tcp_packet((host, 50123), (remote, 443), TcpFlags::ACK, 0, None),
        ] {
            process_parsed_packet(packet, &sessions, &current, &own, &filter, None).await;
        }
        assert_eq!(sessions.len(), 1);
        let entry = sessions.iter().next().unwrap();
        assert_eq!(entry.key().src_ip, IpAddr::V4(host));
        assert_eq!(entry.key().dst_port, 443);
        assert!(crate::whitelists::is_egress_session(entry.value()));
    }

    #[test]
    fn test_packet_source_serves_rules() {
        let own: HashSet<IpAddr> = [IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]
            .into_iter()
            .collect();
        let s = |src: ([u8; 4], u16), dst: ([u8; 4], u16)| Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::V4(Ipv4Addr::from(src.0)),
            src_port: src.1,
            dst_ip: IpAddr::V4(Ipv4Addr::from(dst.0)),
            dst_port: dst.1,
        };
        // System port serves.
        assert!(packet_source_serves(
            &s(([1, 1, 1, 1], 443), ([10, 0, 0, 1], 3306)),
            &own
        ));
        assert!(!packet_source_serves(
            &s(([10, 0, 0, 1], 3306), ([1, 1, 1, 1], 443)),
            &own
        ));
        // Dynamic port is the client's.
        assert!(!packet_source_serves(
            &s(([1, 1, 1, 1], 50000), ([2, 2, 2, 2], 3389)),
            &own
        ));
        // The host listens below its OS's ephemeral floor.
        assert!(packet_source_serves(
            &s(([10, 0, 0, 1], 3389), ([1, 1, 1, 1], 1433)),
            &own
        ));
        assert!(!packet_source_serves(
            &s(([1, 1, 1, 1], 1433), ([10, 0, 0, 1], 3389)),
            &own
        ));
        // Equal ports: the packet keeps its direction.
        assert!(!packet_source_serves(
            &s(([10, 0, 0, 1], 123), ([1, 1, 1, 1], 123)),
            &own
        ));
        // Neither end is this host: the lower port serves.
        assert!(packet_source_serves(
            &s(([1, 1, 1, 1], 1433), ([2, 2, 2, 2], 3389)),
            &own
        ));
    }

    fn client_hello(hostname: &str) -> Vec<u8> {
        let name = hostname.as_bytes();
        let mut sni = vec![0x00, 0x00];
        sni.extend_from_slice(&((name.len() + 5) as u16).to_be_bytes());
        sni.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        sni.push(0x00);
        sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni.extend_from_slice(name);
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]);
        body.push(0x00);
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f, 0x01, 0x00]);
        body.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        body.extend_from_slice(&sni);
        let mut handshake = vec![
            0x01,
            (body.len() >> 16) as u8,
            (body.len() >> 8) as u8,
            body.len() as u8,
        ];
        handshake.extend_from_slice(&body);
        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    /// The ClientHello comes after the handshake, so it reaches the session
    /// the SYN created: its SNI names the session.
    #[tokio::test]
    #[serial]
    async fn test_sni_after_handshake_names_the_session() {
        let host = Ipv4Addr::new(10, 1, 0, 4);
        let fastly = Ipv4Addr::new(185, 199, 110, 133);
        let own: HashSet<IpAddr> = [IpAddr::V4(host)].into_iter().collect();
        let sessions = Arc::new(CustomDashMap::new("sessions"));
        let current = Arc::new(CustomRwLock::new(Vec::new()));
        let filter = Arc::new(CustomRwLock::new(SessionFilter::All));
        let hello = client_hello("gist.githubusercontent.com");
        for packet in [
            tcp_packet((host, 50124), (fastly, 443), TcpFlags::SYN, 0, None),
            tcp_packet(
                (fastly, 443),
                (host, 50124),
                TcpFlags::SYN | TcpFlags::ACK,
                0,
                None,
            ),
            tcp_packet((host, 50124), (fastly, 443), TcpFlags::ACK, 0, None),
            tcp_packet(
                (host, 50124),
                (fastly, 443),
                TcpFlags::ACK | TcpFlags::PSH,
                hello.len(),
                Some(hello.clone()),
            ),
        ] {
            process_parsed_packet(packet, &sessions, &current, &own, &filter, None).await;
        }
        assert_eq!(sessions.len(), 1);
        let info = sessions.iter().next().unwrap();
        assert_eq!(
            info.dst_domain.as_deref(),
            Some("gist.githubusercontent.com")
        );
        assert_eq!(info.dst_domain_type, DomainResolutionType::SNI);
    }

    /// A padded ClientHello that does not fit in one TCP segment -- the shape
    /// a modern client produces once the record carries a post-quantum key
    /// share -- is reassembled across its segments and still names the
    /// session. Without reassembly each segment holds only a truncated TLS
    /// record and the SNI is lost (the in-process-key-theft blind spot).
    #[tokio::test]
    #[serial]
    async fn test_split_client_hello_reassembles_sni() {
        let host = Ipv4Addr::new(10, 2, 0, 7);
        let server = Ipv4Addr::new(104, 21, 48, 1);
        let own: HashSet<IpAddr> = [IpAddr::V4(host)].into_iter().collect();
        let sessions = Arc::new(CustomDashMap::new("sessions"));
        let current = Arc::new(CustomRwLock::new(Vec::new()));
        let filter = Arc::new(CustomRwLock::new(SessionFilter::All));

        // ~1.7 KB record: larger than one Ethernet segment, so a real client
        // would split it. Split past the first MSS, so the first segment
        // carries a truncated record and the second carries the tail with no
        // header of its own.
        let hello = padded_client_hello("api.mainnet-beta.solana.com", 1400);
        assert!(hello.len() > 1460, "hello must exceed one segment");
        let split = 1460;
        let seg1 = hello[..split].to_vec();
        let seg2 = hello[split..].to_vec();
        assert_eq!(seg1.first(), Some(&0x16), "first segment starts the record");

        for packet in [
            tcp_packet((host, 51000), (server, 443), TcpFlags::SYN, 0, None),
            tcp_packet(
                (server, 443),
                (host, 51000),
                TcpFlags::SYN | TcpFlags::ACK,
                0,
                None,
            ),
            tcp_packet((host, 51000), (server, 443), TcpFlags::ACK, 0, None),
            tcp_packet(
                (host, 51000),
                (server, 443),
                TcpFlags::ACK | TcpFlags::PSH,
                seg1.len(),
                Some(seg1),
            ),
            // The server bare-ACKs the first segment before the second
            // arrives: this must not discard the partial ClientHello.
            tcp_packet((server, 443), (host, 51000), TcpFlags::ACK, 0, None),
            tcp_packet(
                (host, 51000),
                (server, 443),
                TcpFlags::ACK | TcpFlags::PSH,
                seg2.len(),
                Some(seg2),
            ),
        ] {
            process_parsed_packet(packet, &sessions, &current, &own, &filter, None).await;
        }

        assert_eq!(sessions.len(), 1);
        let info = sessions.iter().next().unwrap();
        assert_eq!(
            info.dst_domain.as_deref(),
            Some("api.mainnet-beta.solana.com")
        );
        assert_eq!(info.dst_domain_type, DomainResolutionType::SNI);
    }

    /// The parser carries egress port-443 payloads for reassembly, but not
    /// application-data records (past the handshake) or non-443 traffic, and
    /// it bounds the copy to a ClientHello's worth of bytes.
    #[test]
    fn test_carry_tls_egress_payload_gate() {
        // Handshake record start on 443: carried.
        assert_eq!(
            carry_tls_egress_payload(443, &[0x16, 0x03, 0x01, 0x00, 0x05]),
            Some(vec![0x16, 0x03, 0x01, 0x00, 0x05])
        );
        // Continuation (no header): carried, so reassembly can append it.
        assert_eq!(
            carry_tls_egress_payload(443, &[0xAB, 0xCD]),
            Some(vec![0xAB, 0xCD])
        );
        // Application data record: never carried.
        assert_eq!(carry_tls_egress_payload(443, &[0x17, 0x03, 0x03]), None);
        // Empty payload (bare ACK): nothing to carry.
        assert_eq!(carry_tls_egress_payload(443, &[]), None);
        // Not egress 443: not carried.
        assert_eq!(carry_tls_egress_payload(80, &[0x16, 0x03, 0x01]), None);
        // Copy is bounded.
        let big = vec![0x16u8; MAX_CLIENT_HELLO_BYTES + 4096];
        assert_eq!(
            carry_tls_egress_payload(443, &big).map(|v| v.len()),
            Some(MAX_CLIENT_HELLO_BYTES)
        );
    }

    /// A ClientHello that fits in one segment is extracted inline, with no
    /// lingering reassembly state for the flow.
    #[test]
    fn test_single_segment_client_hello_needs_no_state() {
        let key = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 3, 0, 1)),
            src_port: 52000,
            dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
            dst_port: 443,
        };
        let hello = client_hello("single.example.com");
        assert_eq!(
            reassemble_client_hello_sni(&key, &hello).as_deref(),
            Some("single.example.com")
        );
        assert!(CLIENT_HELLO_REASSEMBLY.get(&key).is_none());
    }

    /// A padded ClientHello with a dummy extension so the record exceeds one
    /// TCP segment, as a modern (post-quantum) client's does.
    fn padded_client_hello(hostname: &str, pad_len: usize) -> Vec<u8> {
        let name = hostname.as_bytes();
        let mut sni = vec![0x00, 0x00];
        sni.extend_from_slice(&((name.len() + 5) as u16).to_be_bytes());
        sni.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        sni.push(0x00);
        sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni.extend_from_slice(name);

        // Padding extension (type 0x0015), skipped by the extension parser.
        let mut padding = vec![0x00, 0x15];
        padding.extend_from_slice(&(pad_len as u16).to_be_bytes());
        padding.extend(std::iter::repeat(0u8).take(pad_len));

        let mut extensions = sni;
        extensions.extend_from_slice(&padding);

        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]);
        body.push(0x00);
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f, 0x01, 0x00]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = vec![
            0x01,
            (body.len() >> 16) as u8,
            (body.len() >> 8) as u8,
            body.len() as u8,
        ];
        handshake.extend_from_slice(&body);

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[tokio::test]
    #[serial]
    async fn test_service_port_based_direction() {
        // Create a test packet with a well-known service port as the source
        // This simulates a server sending a packet to a client
        let session_data = SessionPacketData {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), // Server IP
                src_port: 80,                                  // HTTP server port
                dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), // Client IP
                dst_port: 12345,                               // Client random high port
            },
            packet_length: 100,
            ip_packet_length: 120,
            flags: Some(TcpFlags::SYN | TcpFlags::ACK), // Server response
            timestamp: Utc::now(),
            tls_client_hello: None,
        };

        // Create necessary objects for the test
        let sessions = Arc::new(CustomDashMap::new("sessions"));
        let current_sessions = Arc::new(CustomRwLock::new(Vec::new()));
        let own_ips = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))];
        let own_ips_set: HashSet<IpAddr> = own_ips.into_iter().collect();
        let filter = Arc::new(CustomRwLock::new(SessionFilter::All));

        // Process the packet
        process_parsed_packet(
            session_data,
            &sessions,
            &current_sessions,
            &own_ips_set,
            &filter,
            None,
        )
        .await;

        // Verify that the session was added with the client as source and server as destination
        // (swapped from the original packet)
        assert_eq!(sessions.len(), 1);
        let session_key = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), // Now client is source
            src_port: 12345,                                   // Client port
            dst_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),     // Server is destination
            dst_port: 80,                                      // Server port
        };

        // Verify the session was stored with the swapped key
        assert!(sessions.contains_key(&session_key),
            "Session key should have been swapped to put client as source and server as destination");

        // Verify service name was assigned from the server port
        let session_info = sessions.get(&session_key).unwrap();
        assert!(
            session_info.dst_service.is_some(),
            "Destination service name should have been set"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_regular_client_server_direction() {
        // Regular client-to-server packet with client using high port and server using well-known port
        let session_data = SessionPacketData {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), // Client IP
                src_port: 54321,                                   // Random high port
                dst_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),     // Server IP
                dst_port: 443,                                     // HTTPS port
            },
            packet_length: 100,
            ip_packet_length: 120,
            flags: Some(TcpFlags::SYN), // Client initiating
            timestamp: Utc::now(),
            tls_client_hello: None,
        };

        // Create necessary objects for the test
        let sessions = Arc::new(CustomDashMap::new("sessions"));
        let current_sessions = Arc::new(CustomRwLock::new(Vec::new()));
        let own_ips = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))];
        let own_ips_set: HashSet<IpAddr> = own_ips.into_iter().collect();
        let filter = Arc::new(CustomRwLock::new(SessionFilter::All));

        // Process the packet
        process_parsed_packet(
            session_data,
            &sessions,
            &current_sessions,
            &own_ips_set,
            &filter,
            None,
        )
        .await;

        // The original direction should be preserved (client to server)
        assert_eq!(sessions.len(), 1);
        let session_key = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), // Client as source
            src_port: 54321,                                   // Client port
            dst_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),     // Server as destination
            dst_port: 443,                                     // Server port
        };

        // Verify the session was stored with the original key
        assert!(
            sessions.contains_key(&session_key),
            "Session key should remain as original client-to-server direction"
        );

        // Verify service name was assigned for the destination port
        let session_info = sessions.get(&session_key).unwrap();
        assert!(
            session_info.dst_service.is_some(),
            "Destination service name should have been set"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_both_ports_are_service_ports() {
        // Create a test packet with both source and destination being service ports
        // This simulates a connection between two servers
        let session_data = SessionPacketData {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), // Server 1 IP
                src_port: 80,                                   // HTTP server port
                dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), // Server 2 IP
                dst_port: 443,                                  // HTTPS server port
            },
            packet_length: 100,
            ip_packet_length: 120,
            flags: Some(TcpFlags::SYN), // Client initiating with SYN
            timestamp: Utc::now(),
            tls_client_hello: None,
        };

        // Create necessary objects for the test
        let sessions = Arc::new(CustomDashMap::new("sessions"));
        let current_sessions = Arc::new(CustomRwLock::new(Vec::new()));
        let own_ips = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))]; // Neither IP is ours
        let own_ips_set: HashSet<IpAddr> = own_ips.into_iter().collect();
        let filter = Arc::new(CustomRwLock::new(SessionFilter::All));

        // Process the packet
        process_parsed_packet(
            session_data.clone(),
            &sessions,
            &current_sessions,
            &own_ips_set,
            &filter,
            None,
        )
        .await;

        // Verify that the session was added with the same source/dest as the original packet
        // Since SYN without ACK indicates initiation, and both are service ports
        assert_eq!(sessions.len(), 1);
        let session_key = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), // Original source (initiator)
            src_port: 80,                                   // Original source port
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), // Original destination
            dst_port: 443,                                  // Original destination port
        };

        // Verify the session was stored with the original key (not swapped)
        assert!(sessions.contains_key(&session_key),
            "Session key should maintain original direction when both are service ports and SYN flag is set");

        // Verify service name was assigned for the destination port
        let session_info = sessions.get(&session_key).unwrap();
        assert!(
            session_info.dst_service.is_some(),
            "Destination service name should have been set"
        );

        // Now test with a SYN+ACK packet - should swap direction
        let sessions2 = Arc::new(CustomDashMap::new("sessions"));
        let current_sessions2 = Arc::new(CustomRwLock::new(Vec::new()));

        let session_data2 = SessionPacketData {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), // Server 2 IP
                src_port: 443,                                  // HTTPS server port
                dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), // Server 1 IP
                dst_port: 80,                                   // HTTP server port
            },
            packet_length: 100,
            ip_packet_length: 120,
            flags: Some(TcpFlags::SYN | TcpFlags::ACK), // Response with SYN+ACK
            timestamp: Utc::now(),
            tls_client_hello: None,
        };

        // Process the packet
        process_parsed_packet(
            session_data2,
            &sessions2,
            &current_sessions2,
            &own_ips_set,
            &filter,
            None,
        )
        .await;

        // SYN+ACK indicates this is a response, so we should swap to make the initiator the source
        assert_eq!(sessions2.len(), 1);
        let session_key2 = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), // Initiator as source
            src_port: 80,                                   // Initiator port
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), // Responder as destination
            dst_port: 443,                                  // Responder port
        };

        // Verify the session was stored with the swapped key
        assert!(
            sessions2.contains_key(&session_key2),
            "Session key should be swapped when both are service ports and SYN+ACK flags are set"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_packet_statistics() {
        // Create test data
        let src_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let own_ips = vec![src_ip];
        let own_ips_set: HashSet<IpAddr> = own_ips.into_iter().collect();

        // Set up session storage
        let sessions = Arc::new(CustomDashMap::new("sessions"));
        let current_sessions = Arc::new(CustomRwLock::new(Vec::new()));
        let filter = Arc::new(CustomRwLock::new(SessionFilter::All));

        // Create session key
        let session_key = Session {
            protocol: Protocol::TCP,
            src_ip,
            src_port: 12345,
            dst_ip,
            dst_port: 80,
        };

        // 1. Create and process the first packet (100 bytes, outbound)
        let packet1 = SessionPacketData {
            session: session_key.clone(),
            packet_length: 100,
            ip_packet_length: 120,
            flags: Some(TcpFlags::SYN),
            timestamp: Utc::now(),
            tls_client_hello: None,
        };
        process_parsed_packet(
            packet1,
            &sessions,
            &current_sessions,
            &own_ips_set,
            &filter,
            None,
        )
        .await;

        // Check initial statistics
        {
            let session_info = sessions.get(&session_key).unwrap();
            assert_eq!(
                session_info.stats.average_packet_size, 100.0,
                "Initial average packet size should be 100.0"
            );
            assert_eq!(
                session_info.stats.inbound_outbound_ratio, 0.0,
                "Initial inbound/outbound ratio should be 0.0"
            );
            assert_eq!(
                session_info.stats.segment_count, 0,
                "Initial segment count should be 0"
            );
            assert!(
                session_info.stats.in_segment,
                "Initial packet should start a segment"
            );
        }

        // 2. Process a second packet (200 bytes, inbound)
        let packet2 = SessionPacketData {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: dst_ip,
                src_port: 80,
                dst_ip: src_ip,
                dst_port: 12345,
            },
            packet_length: 200,
            ip_packet_length: 220,
            flags: Some(TcpFlags::ACK),
            timestamp: Utc::now(),
            tls_client_hello: None,
        };

        // Debug check direction swapping logic
        let src_service_name = get_name_from_port(packet2.session.src_port).await;
        let dst_service_name = get_name_from_port(packet2.session.dst_port).await;

        // Process the packet (using clone)
        process_parsed_packet(
            packet2.clone(),
            &sessions,
            &current_sessions,
            &own_ips_set,
            &filter,
            None,
        )
        .await;

        println!(
            "DEBUG: Inbound packet - src port {} service: '{}', dst port {} service: '{}'",
            packet2.session.src_port, src_service_name, packet2.session.dst_port, dst_service_name
        );

        let src_is_service_port = !src_service_name.is_empty();
        let dst_is_service_port = !dst_service_name.is_empty();
        println!(
            "DEBUG: src_is_service_port: {}, dst_is_service_port: {}",
            src_is_service_port, dst_is_service_port
        );

        // Debug session map contents
        println!("DEBUG: After packet 2, sessions in map: {}", sessions.len());
        for entry in sessions.iter() {
            let key = entry.key();
            let value = entry.value();
            println!(
                "DEBUG: Session key: {}:{} -> {}:{}, bytes: inbound={}, outbound={}, avg_size={}",
                key.src_ip,
                key.src_port,
                key.dst_ip,
                key.dst_port,
                value.stats.inbound_bytes,
                value.stats.outbound_bytes,
                value.stats.average_packet_size
            );
        }

        // Check updated statistics after packet 2
        {
            let session_info = sessions.get(&session_key).unwrap();
            assert_eq!(
                session_info.stats.orig_pkts, 1,
                "Originator packets should be 1"
            );
            assert_eq!(
                session_info.stats.resp_pkts, 1,
                "Responder packets should be 1"
            );
            assert_eq!(
                session_info.stats.outbound_bytes, 100,
                "Outbound bytes should be 100"
            );
            assert_eq!(
                session_info.stats.inbound_bytes, 200,
                "Inbound bytes should be 200"
            );
            let total_packets = session_info.stats.orig_pkts + session_info.stats.resp_pkts;
            let total_bytes = session_info.stats.inbound_bytes + session_info.stats.outbound_bytes;
            assert_eq!(total_packets, 2, "Total packets should be 2");
            assert_eq!(total_bytes, 300, "Total bytes should be 300");
            // Check average with a tolerance for floating point comparisons
            let expected_avg = 150.0;
            assert!(
                (session_info.stats.average_packet_size - expected_avg).abs() < 0.001,
                "Average packet size should be close to {}, got {}",
                expected_avg,
                session_info.stats.average_packet_size
            );

            assert_eq!(
                session_info.stats.segment_count, 0,
                "No segments completed yet"
            );
        }

        // 3. Process a third packet with PSH flag to end the first segment
        let packet3 = SessionPacketData {
            session: session_key.clone(),
            packet_length: 300,
            ip_packet_length: 320,
            flags: Some(TcpFlags::ACK | TCP_PSH),
            timestamp: Utc::now(),
            tls_client_hello: None,
        };
        process_parsed_packet(
            packet3,
            &sessions,
            &current_sessions,
            &own_ips_set,
            &filter,
            None,
        )
        .await;

        // Check statistics after segment completion
        {
            let session_info = sessions.get(&session_key).unwrap();
            assert_eq!(
                session_info.stats.average_packet_size, 200.0,
                "Average packet size should be 200.0 after Pkt 3"
            );
            assert_eq!(
                session_info.stats.segment_count, 1,
                "One segment should be completed after Pkt 3"
            );
            assert!(
                !session_info.stats.in_segment,
                "Should not be in a segment after PSH"
            );
            assert!(
                session_info.stats.last_segment_end.is_some(),
                "Last segment end should be set"
            );
        }

        // Introduce a small delay to ensure Packet 4's timestamp is distinct and later
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // 4. Process packet to start a new segment
        let packet4 = SessionPacketData {
            session: session_key.clone(),
            packet_length: 150,
            ip_packet_length: 170,
            flags: Some(TcpFlags::ACK),
            timestamp: Utc::now(),
            tls_client_hello: None,
        };
        process_parsed_packet(
            packet4,
            &sessions,
            &current_sessions,
            &own_ips_set,
            &filter,
            None,
        )
        .await;

        // Check that we're in a segment again
        {
            let session_info = sessions.get(&session_key).unwrap();
            assert!(
                session_info.stats.in_segment,
                "Should be in a segment after Packet 4"
            );
        }

        // Introduce a delay LONGER than the segment timeout
        let segment_timeout_duration = {
            let info = sessions.get(&session_key).unwrap();
            std::time::Duration::from_secs_f64(info.stats.segment_timeout)
        };
        tokio::time::sleep(segment_timeout_duration + std::time::Duration::from_secs(1)).await;

        // 5. Process another packet - this should trigger a timeout detection for segment 2
        let packet5 = SessionPacketData {
            session: session_key.clone(),
            packet_length: 250,
            ip_packet_length: 270,
            flags: Some(TcpFlags::ACK),
            timestamp: Utc::now(),
            tls_client_hello: None,
        };
        process_parsed_packet(
            packet5,
            &sessions,
            &current_sessions,
            &own_ips_set,
            &filter,
            None,
        )
        .await;

        // Check statistics after timeout-based segment completion
        {
            let session_info = sessions.get(&session_key).unwrap();
            assert_eq!(
                session_info.stats.segment_count, 2,
                "A second segment should be completed due to timeout"
            );
            assert!(
                session_info.stats.segment_interarrival > 0.0,
                "Segment interarrival time should be positive"
            );
            // Note: The average interarrival is just the first calculated one here.
        }

        // 6. Test UDP segment detection (only timeout-based)
        let udp_session_key = Session {
            protocol: Protocol::UDP,
            src_ip,
            src_port: 54321,
            dst_ip,
            dst_port: 53, // Using DNS port for service detection consistency if needed
        };

        let udp_packet1 = SessionPacketData {
            session: udp_session_key.clone(),
            packet_length: 100,
            ip_packet_length: 120,
            flags: None, // UDP has no flags
            timestamp: Utc::now(),
            tls_client_hello: None,
        };
        process_parsed_packet(
            udp_packet1,
            &sessions,
            &current_sessions,
            &own_ips_set,
            &filter,
            None,
        )
        .await;

        // Check that UDP session is created and in a segment
        {
            let session_info = sessions.get(&udp_session_key).unwrap();
            assert!(
                session_info.stats.in_segment,
                "UDP session should start in a segment"
            );
            assert_eq!(
                session_info.stats.segment_count, 0,
                "No segments completed yet in UDP session"
            );
        }

        // Final check on packet statistics
        {
            let session_info = sessions.get(&session_key).unwrap();

            // Calculated values based on our test packets (100 + 200 + 300 + 150 + 250 = 1000 bytes, 5 packets)
            let expected_avg = 200.0; // 1000 / 5 = 200
            assert!(
                (session_info.stats.average_packet_size - expected_avg).abs() < 0.001,
                "Final average packet size should be approximately {}, got {}",
                expected_avg,
                session_info.stats.average_packet_size
            );

            // 3 outbound packets (100 + 300 + 150 + 250 = 800), 1 inbound packet (200)
            assert_eq!(
                session_info.stats.inbound_outbound_ratio, 0.25,
                "Final inbound/outbound ratio should be 0.25, got {}",
                session_info.stats.inbound_outbound_ratio
            );
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_session_direction_with_standard_and_ephemeral_ports() {
        // Test case: client with high port connects to server with standard port
        // Expected: session maintained as-is (standard client->server with well-known port)

        let session_packet = SessionPacketData {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                src_port: 54321, // Random high port (client)
                dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                dst_port: 443, // HTTPS port (server)
            },
            packet_length: 100,
            ip_packet_length: 120,
            flags: Some(TcpFlags::SYN),
            timestamp: Utc::now(),
            tls_client_hello: None,
        };

        // Create necessary objects for the test
        let sessions = Arc::new(CustomDashMap::new("sessions"));
        let current_sessions = Arc::new(CustomRwLock::new(Vec::new()));
        let own_ips = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))];
        let own_ips_set: HashSet<IpAddr> = own_ips.into_iter().collect();
        let filter = Arc::new(CustomRwLock::new(SessionFilter::All));

        // Process the packet
        process_parsed_packet(
            session_packet.clone(),
            &sessions,
            &current_sessions,
            &own_ips_set,
            &filter,
            None,
        )
        .await;

        // Verify that the session direction is maintained as-is
        assert_eq!(sessions.len(), 1);
        for item in sessions.iter() {
            let session = item.key();
            let info = item.value();

            // Session key should match original packet
            assert_eq!(session.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
            assert_eq!(session.src_port, 54321);
            assert_eq!(session.dst_ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)));
            assert_eq!(session.dst_port, 443);

            // Verify it's classified as outbound
            assert_eq!(info.stats.outbound_bytes, 100);
            assert_eq!(info.stats.inbound_bytes, 0);
            assert_eq!(info.stats.history, "S"); // 'S' for originator SYN
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_session_direction_server_to_client() {
        // Test case: server with standard port connects to client with high port
        // Expected: direction flipped (non-standard but possible scenario)

        let session_packet = SessionPacketData {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                src_port: 80, // HTTP port (server)
                dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                dst_port: 54321, // Random high port (client)
            },
            packet_length: 100,
            ip_packet_length: 120,
            flags: Some(TcpFlags::SYN),
            timestamp: Utc::now(),
            tls_client_hello: None,
        };

        // Create necessary objects for the test
        let sessions = Arc::new(CustomDashMap::new("sessions"));
        let current_sessions = Arc::new(CustomRwLock::new(Vec::new()));
        let own_ips = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))];
        let own_ips_set: HashSet<IpAddr> = own_ips.into_iter().collect();
        let filter = Arc::new(CustomRwLock::new(SessionFilter::All));

        // Process the packet
        process_parsed_packet(
            session_packet.clone(),
            &sessions,
            &current_sessions,
            &own_ips_set,
            &filter,
            None,
        )
        .await;

        // Verify that the session direction is flipped
        assert_eq!(sessions.len(), 1);
        for item in sessions.iter() {
            let session = item.key();
            let info = item.value();

            // Session key should be flipped due to service port detection
            assert_eq!(session.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
            assert_eq!(session.src_port, 54321);
            assert_eq!(session.dst_ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)));
            assert_eq!(session.dst_port, 80);

            // Because the packet was from the responder in this flipped session,
            // it should be counted as inbound
            assert_eq!(info.stats.outbound_bytes, 0);
            assert_eq!(info.stats.inbound_bytes, 100);
            assert_eq!(info.stats.history, "s"); // lowercase 's' for responder SYN
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_session_direction_both_standard_ports() {
        // Test case: communication between two well-known service ports
        // Expected: direction determined by TCP flags - SYN identifies client

        let session_packet_syn = SessionPacketData {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                src_port: 443, // HTTPS
                dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                dst_port: 80, // HTTP
            },
            packet_length: 100,
            ip_packet_length: 120,
            flags: Some(TcpFlags::SYN), // Client initiating with SYN
            timestamp: Utc::now(),
            tls_client_hello: None,
        };

        // Create necessary objects for the test
        let sessions = Arc::new(CustomDashMap::new("sessions"));
        let current_sessions = Arc::new(CustomRwLock::new(Vec::new()));
        let own_ips = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))];
        let own_ips_set: HashSet<IpAddr> = own_ips.into_iter().collect();
        let filter = Arc::new(CustomRwLock::new(SessionFilter::All));

        // Process the packet
        process_parsed_packet(
            session_packet_syn.clone(),
            &sessions,
            &current_sessions,
            &own_ips_set,
            &filter,
            None,
        )
        .await;

        // Verify that the session direction is maintained due to SYN flag
        assert_eq!(sessions.len(), 1);
        for item in sessions.iter() {
            let session = item.key();
            let info = item.value();

            // Session key should match original packet
            assert_eq!(session.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
            assert_eq!(session.src_port, 443);
            assert_eq!(session.dst_ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)));
            assert_eq!(session.dst_port, 80);

            // Verify it's classified as outbound since this was a SYN packet
            assert_eq!(info.stats.outbound_bytes, 100);
            assert_eq!(info.stats.inbound_bytes, 0);
            assert_eq!(info.stats.history, "S"); // 'S' for originator SYN
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_session_direction_with_synack() {
        // Test case: Response with SYN+ACK between two well-known service ports
        // Expected: direction flipped to make the originator the source

        // Create the first session
        let sessions = Arc::new(CustomDashMap::new("sessions"));
        let current_sessions = Arc::new(CustomRwLock::new(Vec::new()));
        let own_ips = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))];
        let own_ips_set: HashSet<IpAddr> = own_ips.into_iter().collect();
        let filter = Arc::new(CustomRwLock::new(SessionFilter::All));

        // Server responding with SYN+ACK
        let session_packet_synack = SessionPacketData {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                src_port: 80, // HTTP
                dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                dst_port: 443, // HTTPS
            },
            packet_length: 100,
            ip_packet_length: 120,
            flags: Some(TcpFlags::SYN | TcpFlags::ACK), // Server responding with SYN+ACK
            timestamp: Utc::now(),
            tls_client_hello: None,
        };

        // Process the SYN+ACK packet
        process_parsed_packet(
            session_packet_synack.clone(),
            &sessions,
            &current_sessions,
            &own_ips_set,
            &filter,
            None,
        )
        .await;

        // Verify that the session direction was flipped (client as source)
        assert_eq!(sessions.len(), 1);
        for item in sessions.iter() {
            let session = item.key();
            let info = item.value();

            // Session key should be flipped due to SYN+ACK indicating the responder
            assert_eq!(session.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
            assert_eq!(session.src_port, 443);
            assert_eq!(session.dst_ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)));
            assert_eq!(session.dst_port, 80);

            // The SYN+ACK packet came from the responder in this flipped session
            assert_eq!(info.stats.outbound_bytes, 0);
            assert_eq!(info.stats.inbound_bytes, 100);
            assert_eq!(info.stats.history, "h"); // lowercase 'h' for responder SYN+ACK
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_segment_interarrival_edge_cases() {
        // Create test data
        let src_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let own_ips = vec![src_ip];
        let own_ips_set: HashSet<IpAddr> = own_ips.into_iter().collect();

        // Set up session storage
        let sessions = Arc::new(CustomDashMap::new("sessions"));
        let current_sessions = Arc::new(CustomRwLock::new(Vec::new()));
        let filter = Arc::new(CustomRwLock::new(SessionFilter::All));

        // Create session key
        let session_key = Session {
            protocol: Protocol::TCP,
            src_ip,
            src_port: 12345,
            dst_ip,
            dst_port: 80,
        };

        // 1. Create and process the first packet
        let packet1 = SessionPacketData {
            session: session_key.clone(),
            packet_length: 100,
            ip_packet_length: 120,
            flags: Some(TcpFlags::SYN),
            timestamp: Utc::now(),
            tls_client_hello: None,
        };
        process_parsed_packet(
            packet1,
            &sessions,
            &current_sessions,
            &own_ips_set,
            &filter,
            None,
        )
        .await;

        // Sleep to ensure time difference
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        // 2. Process a PSH packet to end the first segment
        let packet2 = SessionPacketData {
            session: session_key.clone(),
            packet_length: 200,
            ip_packet_length: 220,
            flags: Some(TcpFlags::ACK | TCP_PSH),
            timestamp: Utc::now(),
            tls_client_hello: None,
        };
        process_parsed_packet(
            packet2,
            &sessions,
            &current_sessions,
            &own_ips_set,
            &filter,
            None,
        )
        .await;

        // Verify first segment ended
        {
            let session_info = sessions.get(&session_key).unwrap();
            assert_eq!(
                session_info.stats.segment_count, 1,
                "First segment should be completed"
            );
            assert!(
                !session_info.stats.in_segment,
                "Should not be in a segment after PSH"
            );
        }

        // 3. Very quickly send a packet to start a new segment and another to end it
        // Start segment 2
        let packet3 = SessionPacketData {
            session: session_key.clone(),
            packet_length: 150,
            ip_packet_length: 170,
            flags: Some(TcpFlags::ACK),
            timestamp: Utc::now(),
            tls_client_hello: None,
        };
        process_parsed_packet(
            packet3,
            &sessions,
            &current_sessions,
            &own_ips_set,
            &filter,
            None,
        )
        .await;

        // Immediately end segment 2 without sleeping
        let packet4 = SessionPacketData {
            session: session_key.clone(),
            packet_length: 250,
            ip_packet_length: 270,
            flags: Some(TcpFlags::ACK | TCP_PSH),
            timestamp: Utc::now(),
            tls_client_hello: None,
        };
        process_parsed_packet(
            packet4,
            &sessions,
            &current_sessions,
            &own_ips_set,
            &filter,
            None,
        )
        .await;

        // Check that segment interarrival time exists but is very small
        {
            let session_info = sessions.get(&session_key).unwrap();
            assert_eq!(
                session_info.stats.segment_count, 2,
                "Second segment should be completed"
            );
            assert!(
                session_info.stats.segment_interarrival >= 0.0,
                "Segment interarrival time should be positive"
            );
            // We can't be too specific about the exact value since it depends on execution speed
        }

        // 4. Start another segment but with clock time manipulation scenario
        // Sleep to ensure third segment has a clear start time
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Start segment 3
        let packet5 = SessionPacketData {
            session: session_key.clone(),
            packet_length: 300,
            ip_packet_length: 320,
            flags: Some(TcpFlags::ACK),
            timestamp: Utc::now(),
            tls_client_hello: None,
        };
        process_parsed_packet(
            packet5,
            &sessions,
            &current_sessions,
            &own_ips_set,
            &filter,
            None,
        )
        .await;

        // Manually manipulate the last segment end time to be in the future relative to current time
        // This is to simulate clock adjustments or cross-device time discrepancies
        {
            let mut info = sessions.get_mut(&session_key).unwrap();
            // Set last_segment_end to 100ms in the future
            info.stats.last_segment_end = Some(Utc::now() + chrono::Duration::milliseconds(100));
        }

        // End segment 3 with another PSH packet
        let packet6 = SessionPacketData {
            session: session_key.clone(),
            packet_length: 350,
            ip_packet_length: 370,
            flags: Some(TcpFlags::ACK | TCP_PSH),
            timestamp: Utc::now(),
            tls_client_hello: None,
        };
        process_parsed_packet(
            packet6,
            &sessions,
            &current_sessions,
            &own_ips_set,
            &filter,
            None,
        )
        .await;

        // Check that negative interarrival was handled gracefully
        {
            let session_info = sessions.get(&session_key).unwrap();
            assert_eq!(
                session_info.stats.segment_count, 3,
                "Third segment should be completed"
            );

            // The interarrival calculation should either skip the negative value or handle it
            // We're primarily checking that the code didn't crash and the stats are still reasonable
            assert!(
                session_info.stats.segment_interarrival >= 0.0,
                "Segment interarrival should remain non-negative despite time anomaly"
            );
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_udp_segment_timeout() {
        // Create test data for UDP
        let src_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let own_ips = vec![src_ip];
        let own_ips_set: HashSet<IpAddr> = own_ips.into_iter().collect();

        // Set up session storage
        let sessions = Arc::new(CustomDashMap::new("sessions"));
        let current_sessions = Arc::new(CustomRwLock::new(Vec::new()));
        let filter = Arc::new(CustomRwLock::new(SessionFilter::All));

        // Create UDP session key
        let udp_session_key = Session {
            protocol: Protocol::UDP,
            src_ip,
            src_port: 12345,
            dst_ip,
            dst_port: 53, // DNS port
        };

        // 1. Create and process the first UDP packet
        let udp_packet1 = SessionPacketData {
            session: udp_session_key.clone(),
            packet_length: 100,
            ip_packet_length: 120,
            flags: None, // UDP has no flags
            timestamp: Utc::now(),
            tls_client_hello: None,
        };
        process_parsed_packet(
            udp_packet1,
            &sessions,
            &current_sessions,
            &own_ips_set,
            &filter,
            None,
        )
        .await;

        // Verify UDP session creation
        {
            let session_info = sessions.get(&udp_session_key).unwrap();
            assert!(
                session_info.stats.in_segment,
                "UDP session should start in a segment"
            );
            assert_eq!(
                session_info.stats.segment_count, 0,
                "No segments completed yet"
            );
        }

        // Get the session timeout value
        let segment_timeout_duration = {
            let info = sessions.get(&udp_session_key).unwrap();
            std::time::Duration::from_secs_f64(info.stats.segment_timeout)
        };

        // Wait longer than the timeout to trigger segment end
        tokio::time::sleep(segment_timeout_duration + std::time::Duration::from_secs(1)).await;

        // 2. Send another UDP packet - should trigger timeout for first segment
        let udp_packet2 = SessionPacketData {
            session: udp_session_key.clone(),
            packet_length: 200,
            ip_packet_length: 220,
            flags: None,
            timestamp: Utc::now(),
            tls_client_hello: None,
        };
        process_parsed_packet(
            udp_packet2,
            &sessions,
            &current_sessions,
            &own_ips_set,
            &filter,
            None,
        )
        .await;

        // Verify segment completion due to timeout
        {
            let session_info = sessions.get(&udp_session_key).unwrap();
            assert_eq!(
                session_info.stats.segment_count, 1,
                "First segment should be completed due to timeout"
            );
            assert!(
                session_info.stats.in_segment,
                "Should be in a new segment after packet 2"
            );
            assert!(
                session_info.stats.last_segment_end.is_some(),
                "Last segment end time should be set"
            );
        }

        // 3. Send multiple rapid UDP packets that don't exceed timeout
        for i in 0..5 {
            let udp_packet_n = SessionPacketData {
                session: udp_session_key.clone(),
                packet_length: 100 + i * 20,
                ip_packet_length: 120 + i * 20,
                flags: None,
                timestamp: Utc::now(),
                tls_client_hello: None,
            };
            process_parsed_packet(
                udp_packet_n,
                &sessions,
                &current_sessions,
                &own_ips_set,
                &filter,
                None,
            )
            .await;
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        // Verify no new segments were created
        {
            let session_info = sessions.get(&udp_session_key).unwrap();
            assert_eq!(
                session_info.stats.segment_count, 1,
                "Still only one segment should be completed"
            );
            assert!(
                session_info.stats.in_segment,
                "Should still be in the same segment after rapid packets"
            );
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_packet_ordering_and_statistics() {
        // Create test data
        let src_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let own_ips = vec![src_ip];
        let own_ips_set: HashSet<IpAddr> = own_ips.into_iter().collect();

        // Set up session storage
        let sessions = Arc::new(CustomDashMap::new("sessions"));
        let current_sessions = Arc::new(CustomRwLock::new(Vec::new()));
        let filter = Arc::new(CustomRwLock::new(SessionFilter::All));

        // Create session key
        let session_key = Session {
            protocol: Protocol::TCP,
            src_ip,
            src_port: 12345,
            dst_ip,
            dst_port: 80,
        };

        // 1. Process packets out of order - FIN before SYN
        // First process a FIN packet (which would normally come later in the session)
        let packet_fin = SessionPacketData {
            session: session_key.clone(),
            packet_length: 100,
            ip_packet_length: 120,
            flags: Some(TcpFlags::FIN | TcpFlags::ACK),
            timestamp: Utc::now(),
            tls_client_hello: None,
        };
        process_parsed_packet(
            packet_fin,
            &sessions,
            &current_sessions,
            &own_ips_set,
            &filter,
            None,
        )
        .await;

        // Now process a SYN packet (which would normally start the session)
        let packet_syn = SessionPacketData {
            session: session_key.clone(),
            packet_length: 150,
            ip_packet_length: 170,
            flags: Some(TcpFlags::SYN),
            timestamp: Utc::now(),
            tls_client_hello: None,
        };
        process_parsed_packet(
            packet_syn,
            &sessions,
            &current_sessions,
            &own_ips_set,
            &filter,
            None,
        )
        .await;

        // Check that statistics are still updated correctly despite out-of-order packets
        {
            let session_info = sessions.get(&session_key).unwrap();
            // Both packets should be counted
            assert_eq!(
                session_info.stats.orig_pkts, 2,
                "Both packets should be counted as originator packets"
            );
            // Total bytes should be the sum of both packets
            assert_eq!(
                session_info.stats.outbound_bytes, 250,
                "Total outbound bytes should be 250 (100+150)"
            );

            // Average packet size should account for both
            let expected_avg = 125.0; // (100 + 150) / 2
            assert!(
                (session_info.stats.average_packet_size - expected_avg).abs() < 0.001,
                "Average packet size should be approximately 125 bytes"
            );

            // Check that history contains both flags in the order they were processed
            assert!(
                session_info.stats.history.contains('F'),
                "History should contain FIN flag"
            );
            assert!(
                session_info.stats.history.contains('S'),
                "History should contain SYN flag"
            );
            // The history should have F before S since that's the order we processed them
            let f_pos = session_info.stats.history.find('F').unwrap();
            let s_pos = session_info.stats.history.find('S').unwrap();
            assert!(
                f_pos < s_pos,
                "FIN flag should appear before SYN flag in history"
            );

            // Should have an end time since we saw a FIN
            assert!(
                session_info.stats.end_time.is_some(),
                "End time should be set because of FIN flag"
            );

            // Should have a connection state since we saw a FIN
            assert!(
                session_info.stats.conn_state.is_some(),
                "Connection state should be set"
            );
        }

        // 2. Process out-of-order packets with segment boundaries
        // Create a new session key to avoid interference
        let session_key2 = Session {
            protocol: Protocol::TCP,
            src_ip,
            src_port: 12346, // Different source port
            dst_ip,
            dst_port: 80,
        };

        // Send a PSH packet first (would normally end a segment)
        let packet_psh = SessionPacketData {
            session: session_key2.clone(),
            packet_length: 200,
            ip_packet_length: 220,
            flags: Some(TcpFlags::ACK | TCP_PSH),
            timestamp: Utc::now(),
            tls_client_hello: None,
        };
        process_parsed_packet(
            packet_psh,
            &sessions,
            &current_sessions,
            &own_ips_set,
            &filter,
            None,
        )
        .await;

        // Then send a regular ACK packet (would normally be in the middle of a segment)
        let packet_ack = SessionPacketData {
            session: session_key2.clone(),
            packet_length: 300,
            ip_packet_length: 320,
            flags: Some(TcpFlags::ACK),
            timestamp: Utc::now(),
            tls_client_hello: None,
        };
        process_parsed_packet(
            packet_ack,
            &sessions,
            &current_sessions,
            &own_ips_set,
            &filter,
            None,
        )
        .await;

        // Check segment handling with out-of-order packets
        {
            let session_info = sessions.get(&session_key2).unwrap();

            // Since the first packet had PSH, it should have started and immediately ended a segment
            assert_eq!(
                session_info.stats.segment_count, 1,
                "Should have completed one segment with PSH"
            );

            // The second packet should have started a new segment
            assert!(
                session_info.stats.in_segment,
                "Should be in a new segment after second packet"
            );

            // Packets and bytes should be counted correctly
            assert_eq!(session_info.stats.orig_pkts, 2, "Should count both packets");
            assert_eq!(
                session_info.stats.outbound_bytes, 500,
                "Total outbound bytes should be 500 (200+300)"
            );
        }
    }

    fn build_udp_dns_ipv4_frame(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        dns_payload: &[u8],
    ) -> Vec<u8> {
        use pnet_packet::ethernet::MutableEthernetPacket;
        use pnet_packet::ipv4::MutableIpv4Packet;
        use pnet_packet::udp::MutableUdpPacket;
        use pnet_packet::MutablePacket;

        let udp_len = 8 + dns_payload.len();
        let ip_total_len = 20 + udp_len;
        let frame_len = 14 + ip_total_len;

        let mut buf = vec![0u8; frame_len];

        // Ethernet header (14 bytes)
        {
            let mut eth = MutableEthernetPacket::new(&mut buf[..14]).unwrap();
            eth.set_ethertype(EtherTypes::Ipv4);
        }

        // IPv4 header (20 bytes)
        {
            let mut ip = MutableIpv4Packet::new(&mut buf[14..14 + 20]).unwrap();
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length(ip_total_len as u16);
            ip.set_ttl(64);
            ip.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            ip.set_source(Ipv4Addr::from(src_ip));
            ip.set_destination(Ipv4Addr::from(dst_ip));
        }

        // UDP header (8 bytes) + payload
        {
            let udp_start = 14 + 20;
            let mut udp = MutableUdpPacket::new(&mut buf[udp_start..udp_start + udp_len]).unwrap();
            udp.set_source(src_port);
            udp.set_destination(dst_port);
            udp.set_length(udp_len as u16);
            udp.payload_mut()[..dns_payload.len()].copy_from_slice(dns_payload);
        }

        buf
    }

    fn build_tcp_dns_ipv4_frame(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        dns_payload: &[u8],
    ) -> Vec<u8> {
        use pnet_packet::ethernet::MutableEthernetPacket;
        use pnet_packet::ipv4::MutableIpv4Packet;
        use pnet_packet::tcp::MutableTcpPacket;
        use pnet_packet::MutablePacket;

        let tcp_header_len = 20;
        // DNS-over-TCP has a 2-byte length prefix
        let tcp_payload_len = 2 + dns_payload.len();
        let tcp_total = tcp_header_len + tcp_payload_len;
        let ip_total_len = 20 + tcp_total;
        let frame_len = 14 + ip_total_len;

        let mut buf = vec![0u8; frame_len];

        {
            let mut eth = MutableEthernetPacket::new(&mut buf[..14]).unwrap();
            eth.set_ethertype(EtherTypes::Ipv4);
        }

        {
            let mut ip = MutableIpv4Packet::new(&mut buf[14..14 + 20]).unwrap();
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length(ip_total_len as u16);
            ip.set_ttl(64);
            ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
            ip.set_source(Ipv4Addr::from(src_ip));
            ip.set_destination(Ipv4Addr::from(dst_ip));
        }

        {
            let tcp_start = 14 + 20;
            let mut tcp =
                MutableTcpPacket::new(&mut buf[tcp_start..tcp_start + tcp_total]).unwrap();
            tcp.set_source(src_port);
            tcp.set_destination(dst_port);
            tcp.set_data_offset(5); // 20-byte header = 5 * 4
            tcp.set_flags(TcpFlags::ACK);
            // TCP payload: 2-byte length prefix + DNS payload
            let payload = tcp.payload_mut();
            let dns_len = dns_payload.len() as u16;
            payload[0] = (dns_len >> 8) as u8;
            payload[1] = (dns_len & 0xff) as u8;
            payload[2..2 + dns_payload.len()].copy_from_slice(dns_payload);
        }

        buf
    }

    #[test]
    fn test_udp_dns_ipv4_produces_dns_session_packet() {
        let dns_query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
        let frame =
            build_udp_dns_ipv4_frame([192, 168, 1, 100], [8, 8, 8, 8], 54321, 53, dns_query);

        let result = parse_packet_pcap(&frame, Utc::now());
        match result {
            Some(ParsedPacket::DnsSessionPacket(sp, dp)) => {
                assert_eq!(sp.session.protocol, Protocol::UDP);
                assert_eq!(sp.session.src_port, 54321);
                assert_eq!(sp.session.dst_port, 53);
                assert_eq!(sp.session.dst_ip, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
                assert_eq!(dp.dns_payload, dns_query);
            }
            other => panic!("Expected DnsSessionPacket for UDP DNS, got {:?}", other),
        }
    }

    #[test]
    fn test_tcp_dns_ipv4_produces_dns_session_packet() {
        let dns_query =
            b"\xAB\xCD\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04test\x03org\x00\x00\x01\x00\x01";
        let frame = build_tcp_dns_ipv4_frame([10, 0, 0, 5], [1, 1, 1, 1], 45678, 53, dns_query);

        let result = parse_packet_pcap(&frame, Utc::now());
        match result {
            Some(ParsedPacket::DnsSessionPacket(sp, dp)) => {
                assert_eq!(sp.session.protocol, Protocol::TCP);
                assert_eq!(sp.session.src_port, 45678);
                assert_eq!(sp.session.dst_port, 53);
                assert_eq!(sp.session.dst_ip, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
                assert_eq!(dp.dns_payload, dns_query);
            }
            other => panic!("Expected DnsSessionPacket for TCP DNS, got {:?}", other),
        }
    }

    #[test]
    fn test_dns_response_from_port_53_produces_dns_session_packet() {
        let dns_response = b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
        let frame =
            build_udp_dns_ipv4_frame([8, 8, 8, 8], [192, 168, 1, 100], 53, 12345, dns_response);

        let result = parse_packet_pcap(&frame, Utc::now());
        match result {
            Some(ParsedPacket::DnsSessionPacket(sp, dp)) => {
                assert_eq!(sp.session.src_port, 53);
                assert_eq!(sp.session.dst_port, 12345);
                assert_eq!(dp.dns_payload, dns_response);
            }
            other => panic!(
                "Expected DnsSessionPacket for DNS response, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_non_dns_udp_still_produces_session_packet() {
        let payload = b"not dns traffic";
        let frame =
            build_udp_dns_ipv4_frame([192, 168, 1, 100], [10, 0, 0, 1], 54321, 8080, payload);

        let result = parse_packet_pcap(&frame, Utc::now());
        match result {
            Some(ParsedPacket::SessionPacket(sp)) => {
                assert_eq!(sp.session.protocol, Protocol::UDP);
                assert_eq!(sp.session.dst_port, 8080);
            }
            other => panic!("Expected SessionPacket for non-DNS UDP, got {:?}", other),
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_dns_session_packet_creates_session_entry() {
        let dns_query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
        let frame =
            build_udp_dns_ipv4_frame([192, 168, 1, 100], [8, 8, 8, 8], 54321, 53, dns_query);

        let parsed = parse_packet_pcap(&frame, Utc::now()).unwrap();
        let sp = match parsed {
            ParsedPacket::DnsSessionPacket(sp, _dp) => sp,
            other => panic!("Expected DnsSessionPacket, got {:?}", other),
        };

        let sessions = Arc::new(CustomDashMap::new("dns_sessions"));
        let current_sessions = Arc::new(CustomRwLock::new(Vec::new()));
        let own_ips: HashSet<IpAddr> = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))]
            .into_iter()
            .collect();
        let filter = Arc::new(CustomRwLock::new(SessionFilter::All));

        process_parsed_packet(sp, &sessions, &current_sessions, &own_ips, &filter, None).await;

        assert_eq!(
            sessions.len(),
            1,
            "DNS packet should create a session entry"
        );
        let expected_key = Session {
            protocol: Protocol::UDP,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            src_port: 54321,
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            dst_port: 53,
        };
        assert!(
            sessions.contains_key(&expected_key),
            "DNS session should be stored with correct key"
        );
    }
}
