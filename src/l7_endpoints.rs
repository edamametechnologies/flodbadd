// Endpoint consistency for L7 process attribution.
//
// Every fallback that attributes a session from a socket or from a cached
// resolution holds evidence about ONE local endpoint: an address and port and,
// when the OS reports it, the peer that socket talks to. `evidence_end` is the
// single test those fallbacks share. The evidence attributes a session only
// when:
// - its local address AND port are one end of the session, taken together (a
//   port on one end and an address on the other is not a match), a wildcard
//   address standing only for an address this host receives traffic at;
// - its peer, when known, is the session's other end.
//
// A port number alone proves nothing. The remote end's service port (80, 53)
// is the local port of every listener for that service, and Linux hands the
// same ephemeral port to concurrent connections towards different
// destinations, so "same local port" does not mean "same socket".
//
// Live evidence (test-mint, Linux, 2026-10): WALinuxAgent's HTTP to the Azure
// WireServer 168.63.129.16:80 and avahi-daemon's DNS to 168.63.129.16:53 were
// attributed to /usr/bin/edamame_posture and raised a `cloud_metadata_egress`
// finding naming EDAMAME's own daemon. Once those short-lived sockets had
// closed, every fallback left could only match on port numbers: the port
// cache answered by either session port, and also stored a LAN session under
// its remote port (a probe of a LAN host's :80 then answered for any later
// session to a :80); the socket fallbacks and the macOS UDP scan accepted a
// socket on either session port whatever its peer.
//
// The cost of the rule is that a session whose only evidence is inconsistent
// stays unattributed. That is the intended direction: no process is better
// than a wrong one.

use crate::sessions::Session;
use arc_swap::ArcSwapOption;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// One end of a [`Session`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SessionEnd {
    Src,
    Dst,
}

impl SessionEnd {
    pub fn endpoint(self, session: &Session) -> (IpAddr, u16) {
        match self {
            SessionEnd::Src => (session.src_ip, session.src_port),
            SessionEnd::Dst => (session.dst_ip, session.dst_port),
        }
    }

    pub fn other(self) -> SessionEnd {
        match self {
            SessionEnd::Src => SessionEnd::Dst,
            SessionEnd::Dst => SessionEnd::Src,
        }
    }
}

/// A local socket, or a resolution remembered from one, offered as evidence
/// for a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketEndpoints {
    pub local_ip: IpAddr,
    pub local_port: u16,
    /// The peer when the evidence is one conversation (a connected TCP
    /// socket, a connected UDP socket where the OS reports it, a cached
    /// resolution). `None` for a listener and for a UDP socket whose peer is
    /// not reported: such a socket serves any peer, but only at an endpoint
    /// this host owns.
    pub remote: Option<(IpAddr, u16)>,
}

/// The addresses this host receives traffic at. Only evidence bound to a
/// wildcard address (`0.0.0.0`, `::`) needs them: such a socket owns its port
/// at every local address, and at no remote one.
#[derive(Clone, Debug, Default)]
pub struct HostAddresses {
    unicast: HashSet<IpAddr>,
    broadcast: HashSet<IpAddr>,
}

struct HostAddressesSnapshot {
    taken_at: Instant,
    addresses: Arc<HostAddresses>,
}

static HOST_ADDRESSES: ArcSwapOption<HostAddressesSnapshot> = ArcSwapOption::const_empty();

/// How long one interface listing answers. Resolver rounds run up to four
/// times a second; listing the interfaces is a syscall walk on Unix and a
/// `GetAdaptersAddresses` call on Windows, cheap once, not per round. An
/// address added since the listing only leaves wildcard-bound evidence
/// unused for that long (unattributed, never misattributed).
const HOST_ADDRESSES_TTL: Duration = Duration::from_secs(10);

impl HostAddresses {
    pub fn new(
        unicast: impl IntoIterator<Item = IpAddr>,
        broadcast: impl IntoIterator<Item = IpAddr>,
    ) -> Self {
        Self {
            unicast: unicast.into_iter().map(|ip| ip.to_canonical()).collect(),
            broadcast: broadcast.into_iter().map(|ip| ip.to_canonical()).collect(),
        }
    }

    /// This host's addresses, listed at most once per `HOST_ADDRESSES_TTL`.
    pub fn current() -> Arc<HostAddresses> {
        if let Some(snapshot) = HOST_ADDRESSES.load_full() {
            if snapshot.taken_at.elapsed() < HOST_ADDRESSES_TTL {
                return snapshot.addresses.clone();
            }
        }
        let addresses = Arc::new(Self::collect());
        HOST_ADDRESSES.store(Some(Arc::new(HostAddressesSnapshot {
            taken_at: Instant::now(),
            addresses: addresses.clone(),
        })));
        addresses
    }

    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    fn collect() -> Self {
        use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};
        match NetworkInterface::show() {
            Ok(interfaces) => {
                let mut unicast = Vec::new();
                let mut broadcast = Vec::new();
                for addr in interfaces.iter().flat_map(|iface| iface.addr.iter()) {
                    match addr {
                        Addr::V4(v4) => {
                            unicast.push(IpAddr::V4(v4.ip));
                            if let Some(bcast) = v4.broadcast {
                                broadcast.push(IpAddr::V4(bcast));
                            }
                        }
                        Addr::V6(v6) => unicast.push(IpAddr::V6(v6.ip)),
                    }
                }
                Self::new(unicast, broadcast)
            }
            Err(e) => {
                // An empty set leaves wildcard-bound evidence to loopback
                // sessions: unattributed rather than attributed to a socket
                // that may not own the session's address.
                tracing::warn!(
                    "L7: cannot list host addresses ({}); wildcard-bound sockets attribute loopback sessions only",
                    e
                );
                Self::default()
            }
        }
    }

    // No interface listing on this target: wildcard-bound evidence then
    // attributes loopback sessions only (fails closed).
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    fn collect() -> Self {
        Self::default()
    }

    /// Whether `ip` is an address of this host (loopback and the unspecified
    /// address included: a DHCP client speaks from `0.0.0.0`).
    pub fn owns(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        ip.is_loopback() || ip.is_unspecified() || self.unicast.contains(&ip)
    }

    /// Group-addressed: multicast, the limited broadcast, or the broadcast
    /// address of one of this host's subnets. Every local socket bound to the
    /// wildcard on that port receives it.
    fn is_group(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        ip.is_multicast() || ip == IpAddr::V4(Ipv4Addr::BROADCAST) || self.broadcast.contains(&ip)
    }

    /// The session end this host owns, for evidence that names a connection
    /// without saying which of its ends is local (a lookup table keyed both
    /// ways round). The source when neither or both ends are local.
    pub fn local_end_of(&self, session: &Session) -> SessionEnd {
        if !self.owns(session.src_ip) && self.owns(session.dst_ip) {
            SessionEnd::Dst
        } else {
            SessionEnd::Src
        }
    }
}

fn same_ip(a: IpAddr, b: IpAddr) -> bool {
    // A dual-stack socket reports an IPv4 peer as `::ffff:a.b.c.d`; the
    // captured session carries the plain IPv4 address.
    a.to_canonical() == b.to_canonical()
}

/// Whether `evidence` is a socket at `end` of `session`.
pub fn evidence_fits_end(
    session: &Session,
    end: SessionEnd,
    evidence: &SocketEndpoints,
    host: &HostAddresses,
) -> bool {
    let (ip, port) = end.endpoint(session);
    if evidence.local_port != port {
        return false;
    }
    let (peer_ip, peer_port) = end.other().endpoint(session);
    let local_ip = evidence.local_ip.to_canonical();
    let wildcard = local_ip.is_unspecified();
    match evidence.remote {
        // One conversation: the session must be that conversation.
        Some((remote_ip, remote_port)) => {
            remote_port == peer_port
                && same_ip(remote_ip, peer_ip)
                && (same_ip(local_ip, ip) || (wildcard && host.owns(ip)))
        }
        None if host.is_group(ip) => {
            // A local receiver of group traffic stands for the session only
            // when another host sent it; this host's own send to a group
            // belongs to the sender's socket, not to every local listener.
            !host.owns(peer_ip) && (wildcard || same_ip(local_ip, ip))
        }
        // Any peer, but only at an endpoint this host owns: a wildcard
        // listener on port 80 owns no part of a connection to a remote :80.
        None if wildcard => host.owns(ip),
        None => same_ip(local_ip, ip),
    }
}

/// The session end `evidence` is a socket at, if any (source first).
pub fn evidence_end(
    session: &Session,
    evidence: &SocketEndpoints,
    host: &HostAddresses,
) -> Option<SessionEnd> {
    [SessionEnd::Src, SessionEnd::Dst]
        .into_iter()
        .find(|end| evidence_fits_end(session, *end, evidence, host))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sessions::Protocol;
    use std::str::FromStr;

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).unwrap()
    }

    fn session(proto: Protocol, src: (&str, u16), dst: (&str, u16)) -> Session {
        Session {
            protocol: proto,
            src_ip: ip(src.0),
            src_port: src.1,
            dst_ip: ip(dst.0),
            dst_port: dst.1,
        }
    }

    fn host() -> HostAddresses {
        HostAddresses::new([ip("10.0.0.4"), ip("fe80::4")], [ip("10.0.0.255")])
    }

    fn listener(local: &str, port: u16) -> SocketEndpoints {
        SocketEndpoints {
            local_ip: ip(local),
            local_port: port,
            remote: None,
        }
    }

    fn connected(local: (&str, u16), remote: (&str, u16)) -> SocketEndpoints {
        SocketEndpoints {
            local_ip: ip(local.0),
            local_port: local.1,
            remote: Some((ip(remote.0), remote.1)),
        }
    }

    // test-mint 2026-10: WALinuxAgent -> WireServer.
    fn wireserver_http() -> Session {
        session(Protocol::TCP, ("10.0.0.4", 41000), ("168.63.129.16", 80))
    }

    #[test]
    fn connection_on_the_same_local_port_to_another_peer_is_not_evidence() {
        // Linux reused 41000 for the daemon's own connection elsewhere.
        let other = connected(("10.0.0.4", 41000), ("52.1.2.3", 443));
        assert_eq!(evidence_end(&wireserver_http(), &other, &host()), None);
    }

    #[test]
    fn the_same_conversation_is_evidence_either_way_round() {
        let same = connected(("10.0.0.4", 41000), ("168.63.129.16", 80));
        assert_eq!(
            evidence_end(&wireserver_http(), &same, &host()),
            Some(SessionEnd::Src)
        );
        let mirrored = session(Protocol::TCP, ("168.63.129.16", 80), ("10.0.0.4", 41000));
        assert_eq!(
            evidence_end(&mirrored, &same, &host()),
            Some(SessionEnd::Dst)
        );
    }

    #[test]
    fn dual_stack_socket_matches_the_ipv4_session() {
        let mapped = connected(("::ffff:10.0.0.4", 41000), ("::ffff:168.63.129.16", 80));
        assert_eq!(
            evidence_end(&wireserver_http(), &mapped, &host()),
            Some(SessionEnd::Src)
        );
    }

    #[test]
    fn wildcard_listener_does_not_own_the_remote_service_port() {
        // A local web server on *:80 is not the client of a remote :80.
        assert_eq!(
            evidence_end(&wireserver_http(), &listener("0.0.0.0", 80), &host()),
            None
        );
        assert_eq!(
            evidence_end(&wireserver_http(), &listener("::", 80), &host()),
            None
        );
    }

    #[test]
    fn address_and_port_must_name_the_same_end() {
        // Bound on the session's local address, but on the remote's port.
        let crossed = listener("10.0.0.4", 53);
        let dns = session(Protocol::UDP, ("10.0.0.4", 50000), ("168.63.129.16", 53));
        assert_eq!(evidence_end(&dns, &crossed, &host()), None);
    }

    #[test]
    fn wildcard_listener_owns_inbound_sessions_to_this_host() {
        let rdp = session(Protocol::TCP, ("203.0.113.9", 51000), ("10.0.0.4", 3389));
        assert_eq!(
            evidence_end(&rdp, &listener("0.0.0.0", 3389), &host()),
            Some(SessionEnd::Dst)
        );
        assert_eq!(
            evidence_end(&rdp, &listener("::", 3389), &host()),
            Some(SessionEnd::Dst)
        );
        // A listener on a specific address owns that address only.
        assert_eq!(
            evidence_end(&rdp, &listener("10.0.0.4", 3389), &host()),
            Some(SessionEnd::Dst)
        );
        assert_eq!(
            evidence_end(&rdp, &listener("127.0.0.1", 3389), &host()),
            None
        );
    }

    #[test]
    fn wildcard_listener_does_not_own_a_lan_peer() {
        // Outbound to another LAN host's :80 while a local server listens on
        // *:80: private is not local.
        let lan = session(Protocol::TCP, ("10.0.0.4", 41001), ("10.0.0.1", 80));
        assert_eq!(evidence_end(&lan, &listener("0.0.0.0", 80), &host()), None);
    }

    #[test]
    fn unconnected_udp_socket_owns_its_local_end() {
        let dns = session(Protocol::UDP, ("10.0.0.4", 50000), ("168.63.129.16", 53));
        assert_eq!(
            evidence_end(&dns, &listener("0.0.0.0", 50000), &host()),
            Some(SessionEnd::Src)
        );
        // A local DNS server on *:53 is not the client of a remote :53.
        assert_eq!(evidence_end(&dns, &listener("0.0.0.0", 53), &host()), None);
    }

    #[test]
    fn loopback_and_unspecified_are_local_without_a_listing() {
        let empty = HostAddresses::default();
        let lo = session(Protocol::TCP, ("127.0.0.1", 50001), ("127.0.0.1", 8080));
        assert_eq!(
            evidence_end(&lo, &listener("0.0.0.0", 8080), &empty),
            Some(SessionEnd::Dst)
        );
        let dhcp = session(Protocol::UDP, ("0.0.0.0", 68), ("255.255.255.255", 67));
        assert_eq!(
            evidence_end(&dhcp, &listener("0.0.0.0", 68), &empty),
            Some(SessionEnd::Src)
        );
        // Without a listing, a wildcard socket owns no routable address.
        let rdp = session(Protocol::TCP, ("203.0.113.9", 51000), ("10.0.0.4", 3389));
        assert_eq!(evidence_end(&rdp, &listener("0.0.0.0", 3389), &empty), None);
    }

    #[test]
    fn group_traffic_from_a_peer_reaches_local_receivers_only() {
        let mdns_in = session(Protocol::UDP, ("10.0.0.7", 5353), ("224.0.0.251", 5353));
        assert_eq!(
            evidence_end(&mdns_in, &listener("0.0.0.0", 5353), &host()),
            Some(SessionEnd::Dst)
        );
        let netbios_in = session(Protocol::UDP, ("10.0.0.7", 137), ("10.0.0.255", 137));
        assert_eq!(
            evidence_end(&netbios_in, &listener("0.0.0.0", 137), &host()),
            Some(SessionEnd::Dst)
        );
        // This host's own SSDP search belongs to the sender, not to the
        // local SSDP listener on *:1900.
        let ssdp_out = session(
            Protocol::UDP,
            ("10.0.0.4", 50002),
            ("239.255.255.250", 1900),
        );
        assert_eq!(
            evidence_end(&ssdp_out, &listener("0.0.0.0", 1900), &host()),
            None
        );
        // Its own mDNS is the local responder's, by the source end.
        let mdns_out = session(Protocol::UDP, ("10.0.0.4", 5353), ("224.0.0.251", 5353));
        assert_eq!(
            evidence_end(&mdns_out, &listener("0.0.0.0", 5353), &host()),
            Some(SessionEnd::Src)
        );
    }

    #[test]
    fn local_end_of_a_connection() {
        let h = host();
        assert_eq!(h.local_end_of(&wireserver_http()), SessionEnd::Src);
        let inbound = session(Protocol::TCP, ("203.0.113.9", 51000), ("10.0.0.4", 22));
        assert_eq!(h.local_end_of(&inbound), SessionEnd::Dst);
        let transit = session(Protocol::TCP, ("192.0.2.1", 1), ("192.0.2.2", 2));
        assert_eq!(h.local_end_of(&transit), SessionEnd::Src);
    }
}
