use crate::task::TaskHandle;
use hickory_resolver::config::{
    NameServerConfig, ResolverConfig, ResolverOpts, ServerGroup, CLOUDFLARE, GOOGLE, QUAD9,
};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::NetError;
use hickory_resolver::proto::rr::RData;
use hickory_resolver::TokioResolver;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::watch;
use tokio::time::{sleep, Duration};
use tracing::{debug, info, trace, warn};
use undeadlock::*;

// Resolution retry parameters
const MAX_RESOLUTION_ATTEMPTS: usize = 3;
const RESOLUTION_RETRY_DELAY_MS: u64 = 500;

// Cache size limits
const REVERSE_DNS_CACHE_MAX_ENTRIES: usize = 50_000;
const REVERSE_DNS_CACHE_EVICT_COUNT: usize = 5_000;
const RESOLVER_QUEUE_MAX_SIZE: usize = 10_000;

// hickory resolver options. These are the hickory-resolver 0.25 values the
// resolvers ran with; they are pinned so a hickory default cannot move them.
/// Per-query timeout.
const RESOLVER_TIMEOUT: Duration = Duration::from_secs(5);
/// Retries of a failed query inside hickory (on top of MAX_RESOLUTION_ATTEMPTS).
const RESOLVER_ATTEMPTS: usize = 2;
/// Responses hickory caches per resolver. 0.26 raised its default from 32 to
/// 8,192; FlodbaddResolver keeps its own reverse DNS cache, so this stays small.
const RESOLVER_CACHE_SIZE: u64 = 32;

/// Reverse DNS cache entry with timestamp for LRU eviction
#[derive(Debug, Clone)]
struct ReverseDnsEntry {
    domain: String,
    inserted_at: Instant,
}

/// The resolver options every public resolver uses.
fn resolver_options() -> ResolverOpts {
    let mut options = ResolverOpts::default();
    options.timeout = RESOLVER_TIMEOUT;
    options.attempts = RESOLVER_ATTEMPTS;
    options.cache_size = RESOLVER_CACHE_SIZE;
    // hickory 0.26 sends EDNS0 by default; 0.25 did not.
    options.edns0 = false;
    // Only hickory 0.25 reads this; ProviderResolver does the fallback for 0.26.
    options.try_tcp_on_error = true;
    options
}

/// UDP errors after which hickory 0.25 (`try_tcp_on_error`) retried the query
/// over TCP. A timeout or a DNS answer (NXDOMAIN, no records) is not one.
fn retries_over_tcp(error: &NetError) -> bool {
    matches!(error, NetError::Io(_) | NetError::NoConnections)
}

/// One public DNS provider (Google, Cloudflare or Quad9).
///
/// hickory 0.26 still has `ResolverOpts::try_tcp_on_error`, but its name
/// server pool no longer reads it: a query moves from UDP to TCP only on a
/// truncated answer. `tcp` restores the 0.25 behaviour: the same servers over
/// TCP only, asked when the UDP query fails with an I/O error.
#[derive(Clone, Debug)]
struct ProviderResolver {
    name: &'static str,
    /// UDP first, TCP on a truncated answer.
    udp: TokioResolver,
    /// TCP only.
    tcp: TokioResolver,
}

impl ProviderResolver {
    fn new(name: &'static str, servers: &ServerGroup<'_>) -> Result<Self, NetError> {
        Self::from_name_servers(
            name,
            servers.udp_and_tcp().collect(),
            servers.tcp().collect(),
        )
    }

    fn from_name_servers(
        name: &'static str,
        udp_and_tcp: Vec<NameServerConfig>,
        tcp_only: Vec<NameServerConfig>,
    ) -> Result<Self, NetError> {
        Ok(Self {
            name,
            udp: Self::build(udp_and_tcp)?,
            tcp: Self::build(tcp_only)?,
        })
    }

    fn build(name_servers: Vec<NameServerConfig>) -> Result<TokioResolver, NetError> {
        let mut builder = TokioResolver::builder_with_config(
            ResolverConfig::from_name_servers(name_servers),
            TokioRuntimeProvider::default(),
        );
        *builder.options_mut() = resolver_options();
        builder.build()
    }

    /// The first PTR name for `ip_addr`, without its trailing dot. `Ok(None)`
    /// when the answer carries no PTR record.
    async fn reverse_lookup(&self, ip_addr: IpAddr) -> Result<Option<String>, NetError> {
        match Self::ptr_name(&self.udp, ip_addr).await {
            Err(e) if retries_over_tcp(&e) => {
                trace!(
                    "UDP lookup of {} via {} failed ({}), retrying over TCP",
                    ip_addr,
                    self.name,
                    e
                );
                Self::ptr_name(&self.tcp, ip_addr).await
            }
            result => result,
        }
    }

    async fn ptr_name(
        resolver: &TokioResolver,
        ip_addr: IpAddr,
    ) -> Result<Option<String>, NetError> {
        let lookup = resolver.reverse_lookup(ip_addr).await?;
        Ok(lookup
            .answers()
            .iter()
            .find_map(|record| match &record.data {
                RData::PTR(ptr) => Some(ptr.to_string().trim_end_matches('.').to_string()),
                _ => None,
            }))
    }
}

#[derive(Debug)]
pub struct FlodbaddResolver {
    resolvers: Arc<CustomRwLock<Vec<ProviderResolver>>>,
    reverse_dns: Arc<CustomDashMap<IpAddr, ReverseDnsEntry>>,
    resolver_queue: Arc<CustomRwLock<VecDeque<IpAddr>>>,
    resolver_handle: Arc<CustomRwLock<Option<TaskHandle>>>,
}

impl FlodbaddResolver {
    pub fn new() -> Self {
        Self {
            resolvers: Arc::new(CustomRwLock::new(Vec::new())),
            reverse_dns: Arc::new(CustomDashMap::new("reverse_dns")),
            resolver_queue: Arc::new(CustomRwLock::new(VecDeque::new())),
            resolver_handle: Arc::new(CustomRwLock::new(None)),
        }
    }

    // Create resolvers for public DNS servers, asked in this order
    fn create_resolvers() -> Vec<ProviderResolver> {
        [
            ("Google", &GOOGLE),
            ("Cloudflare", &CLOUDFLARE),
            ("Quad9", &QUAD9),
        ]
        .into_iter()
        .filter_map(
            |(name, servers)| match ProviderResolver::new(name, servers) {
                Ok(resolver) => Some(resolver),
                Err(e) => {
                    warn!("Unable to create the {} resolver: {}", name, e);
                    None
                }
            },
        )
        .collect()
    }

    async fn perform_reverse_dns_lookup(
        ip_addr: IpAddr,
        reverse_dns: Arc<CustomDashMap<IpAddr, ReverseDnsEntry>>,
        resolvers: Vec<ProviderResolver>,
    ) {
        // Skip if already resolved
        if let Some(entry) = reverse_dns.get(&ip_addr) {
            if entry.value().domain != "Resolving" {
                return;
            }
        }

        // Try each resolver with retries
        for resolver in resolvers.iter() {
            for attempt in 1..=MAX_RESOLUTION_ATTEMPTS {
                match resolver.reverse_lookup(ip_addr).await {
                    Ok(Some(domain)) => {
                        trace!(
                            "DNS resolution succeeded using {}: {} -> {}",
                            resolver.name,
                            ip_addr,
                            domain
                        );
                        reverse_dns.insert(
                            ip_addr,
                            ReverseDnsEntry {
                                domain,
                                inserted_at: Instant::now(),
                            },
                        );
                        return;
                    }
                    // An answer without a PTR record: next attempt, no delay
                    Ok(None) => {}
                    Err(e) => {
                        if attempt < MAX_RESOLUTION_ATTEMPTS {
                            trace!(
                                "Retry #{} for {} with {}: {}",
                                attempt,
                                ip_addr,
                                resolver.name,
                                e
                            );
                            sleep(Duration::from_millis(RESOLUTION_RETRY_DELAY_MS)).await;
                        } else {
                            debug!("Error with {} for {}: {}", resolver.name, ip_addr, e);
                        }
                    }
                }
            }
        }

        // All resolvers failed
        debug!("All resolvers failed for {}. Marking as Unknown.", ip_addr);
        reverse_dns.insert(
            ip_addr,
            ReverseDnsEntry {
                domain: "Unknown".to_string(),
                inserted_at: Instant::now(),
            },
        );
    }

    pub async fn start(&self) {
        if self.resolver_handle.read().await.is_some() {
            warn!("Resolver task is already running");
            return;
        }

        // Create resolvers
        let resolvers = Self::create_resolvers();
        *self.resolvers.write().await = resolvers.clone();

        // Spawn resolver task
        if !resolvers.is_empty() {
            let resolver_queue = self.resolver_queue.clone();
            let reverse_dns = self.reverse_dns.clone();
            let (stop_tx, stop_rx) = watch::channel(false);
            let stop_tx = Arc::new(stop_tx);
            let resolvers_clone = resolvers.clone();

            let resolver_handle = tokio::spawn(async move {
                info!("Starting resolver task");
                let mut cleanup_counter = 0u32;

                while !*stop_rx.borrow() || !resolver_queue.read().await.is_empty() {
                    // Get the IPs to resolve from the queue
                    let to_resolve: Vec<IpAddr> = resolver_queue.write().await.drain(..).collect();
                    let to_resolve_len = to_resolve.len();
                    if to_resolve_len > 0 {
                        trace!("Resolving {} IPs", to_resolve_len);

                        // Resolve the IPs in parallel
                        let _ = futures::future::join_all(to_resolve.into_iter().map(|ip| {
                            let resolvers = resolvers_clone.clone();
                            let reverse_dns = reverse_dns.clone();
                            async move {
                                Self::perform_reverse_dns_lookup(ip, reverse_dns, resolvers).await
                            }
                        }))
                        .await;

                        info!("Resolved {} IPs", to_resolve_len);
                    }

                    // Periodic cache cleanup (every ~30 iterations = ~60 seconds)
                    cleanup_counter += 1;
                    if cleanup_counter >= 30 {
                        cleanup_counter = 0;
                        let cache_len = reverse_dns.len();
                        if cache_len > REVERSE_DNS_CACHE_MAX_ENTRIES {
                            info!(
                                "Reverse DNS cache at {} entries, evicting {} oldest",
                                cache_len, REVERSE_DNS_CACHE_EVICT_COUNT
                            );

                            // Collect entries with timestamps
                            let mut entries: Vec<(IpAddr, Instant)> = reverse_dns
                                .iter()
                                .map(|e| (*e.key(), e.value().inserted_at))
                                .collect();

                            // Sort by timestamp (oldest first)
                            entries.sort_by_key(|(_, ts)| *ts);

                            // Remove the oldest entries
                            for (ip, _) in entries.into_iter().take(REVERSE_DNS_CACHE_EVICT_COUNT) {
                                reverse_dns.remove(&ip);
                            }
                        }
                    }

                    // Sleep briefly before checking queue again
                    sleep(Duration::from_secs(2)).await;
                }

                info!("Resolver task completed");
            });

            *self.resolver_handle.write().await = Some(TaskHandle {
                handle: resolver_handle,
                stop_tx,
            });
        }
    }

    pub async fn stop(&self) {
        if let Some(task_handle) = self.resolver_handle.write().await.take() {
            let _ = task_handle.stop_tx.send(true);
            let _ = task_handle.handle.await;
            info!("Stopped resolver task");
        } else {
            warn!("Resolver task not running");
        }
    }

    pub async fn add_ip_to_resolver(&self, ip_addr: &IpAddr) {
        // Check if the IP has already been resolved
        if self.reverse_dns.get(ip_addr).is_some() {
            return;
        }

        // Check queue size limit
        {
            let queue = self.resolver_queue.read().await;
            if queue.len() >= RESOLVER_QUEUE_MAX_SIZE {
                debug!(
                    "Resolver queue full ({} entries), dropping IP: {}",
                    queue.len(),
                    ip_addr
                );
                return;
            }
        }

        // Add the IP to the resolver queue
        self.resolver_queue.write().await.push_back(*ip_addr);
        debug!("Added IP to resolver queue: {}", ip_addr);
        // Mark the IP as resolving
        self.reverse_dns.insert(
            *ip_addr,
            ReverseDnsEntry {
                domain: "Resolving".to_string(),
                inserted_at: Instant::now(),
            },
        );
    }

    pub async fn get_resolved_ip(&self, ip_addr: &IpAddr) -> Option<String> {
        // Check if the IP is already resolved
        match self
            .reverse_dns
            .get(ip_addr)
            .map(|e| e.value().domain.clone())
        {
            Some(domain) => match domain.as_str() {
                "Resolving" => None,
                _ => Some(domain),
            },
            None => None,
        }
    }

    // Add a new method to integrate DNS resolutions from packet capture
    pub fn add_dns_resolutions(&self, dns_resolutions: &CustomDashMap<IpAddr, String>) -> usize {
        let mut added_count = 0;
        let now = Instant::now();

        for entry in dns_resolutions.iter() {
            let ip = *entry.key();
            let domain = entry.value().clone();

            // Only use captured DNS if it looks like a proper domain
            // Skip .local and .arpa domains which are typically not useful for user display
            if domain.contains('.') && !domain.ends_with(".local") && !domain.ends_with(".arpa") {
                let should_update = match self.reverse_dns.get(&ip) {
                    Some(existing) => {
                        let existing_domain = &existing.value().domain;
                        // Always update if current value is "Unknown" or "Resolving"
                        if existing_domain == "Unknown" || existing_domain == "Resolving" {
                            true
                        } else {
                            if domain != existing_domain.as_str() {
                                // For other values (likely from reverse DNS), prefer forward DNS
                                // but log that we're replacing the value
                                debug!(
                                    "Replacing reverse DNS {} with forward DNS {} for IP {}",
                                    existing_domain, domain, ip
                                );
                                true
                            } else {
                                false
                            }
                        }
                    }
                    None => true, // No existing entry, so add it
                };

                if should_update {
                    debug!(
                        "Adding forward DNS resolution to resolver cache: {} -> {}",
                        ip, domain
                    );
                    self.reverse_dns.insert(
                        ip,
                        ReverseDnsEntry {
                            domain,
                            inserted_at: now,
                        },
                    );
                    added_count += 1;
                }
            }
        }

        if added_count > 0 {
            info!(
                "Integrated {} DNS resolutions from packet capture",
                added_count
            );
        }

        added_count
    }

    // Add a specialized method for CustomDashMap
    pub fn add_dns_resolutions_custom(
        &self,
        dns_resolutions: &Arc<CustomDashMap<IpAddr, String>>,
    ) -> usize {
        let mut added_count = 0;
        let now = Instant::now();

        for entry in dns_resolutions.iter() {
            let ip = *entry.key();
            let domain = entry.value().clone();

            // Only use captured DNS if it looks like a proper domain
            // Skip .local and .arpa domains which are typically not useful for user display
            if domain.contains('.') && !domain.ends_with(".local") && !domain.ends_with(".arpa") {
                let should_update = match self.reverse_dns.get(&ip) {
                    Some(existing) => {
                        let existing_domain = &existing.value().domain;
                        // Always update if current value is "Unknown" or "Resolving"
                        if existing_domain == "Unknown" || existing_domain == "Resolving" {
                            true
                        } else {
                            if domain != existing_domain.as_str() {
                                // For other values (likely from reverse DNS), prefer forward DNS
                                // but log that we're replacing the value
                                debug!(
                                    "Replacing reverse DNS {} with forward DNS {} for IP {}",
                                    existing_domain, domain, ip
                                );
                                true
                            } else {
                                false
                            }
                        }
                    }
                    None => true, // No existing entry, so add it
                };

                if should_update {
                    debug!(
                        "Adding forward DNS resolution to resolver cache: {} -> {}",
                        ip, domain
                    );
                    self.reverse_dns.insert(
                        ip,
                        ReverseDnsEntry {
                            domain,
                            inserted_at: now,
                        },
                    );
                    added_count += 1;
                }
            }
        }

        if added_count > 0 {
            info!(
                "Integrated {} DNS resolutions from packet capture",
                added_count
            );
        }

        added_count
    }

    // Add a method to prioritize DNS resolution for important services
    pub async fn prioritize_resolution(&self, ip: &IpAddr, is_important: bool) {
        // If this IP is already being resolved or has been resolved, we're done
        if self.reverse_dns.contains_key(ip) {
            return;
        }

        // Add to resolver queue
        self.add_ip_to_resolver(ip).await;

        // For important IPs (e.g., connected servers), try to resolve immediately
        // instead of waiting for the background task
        if is_important {
            if let Some(resolver) = self.resolvers.read().await.first().cloned() {
                // Try immediate resolution in a separate task
                let ip_copy = *ip;
                let reverse_dns = self.reverse_dns.clone();
                let resolvers_vec = vec![resolver];

                tokio::spawn(async move {
                    Self::perform_reverse_dns_lookup(ip_copy, reverse_dns, resolvers_vec).await;
                });
            }
        }
    }

    /// Get the number of cached reverse DNS entries
    pub fn reverse_dns_cache_size(&self) -> usize {
        self.reverse_dns.len()
    }

    /// Get the current resolver queue size
    pub async fn resolver_queue_size(&self) -> usize {
        self.resolver_queue.read().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::config::{ConnectionConfig, ProtocolConfig};
    use hickory_resolver::net::{DnsError, NoRecords};
    use hickory_resolver::proto::op::{Message, OpCode, Query, ResponseCode};
    use hickory_resolver::proto::rr::rdata::PTR;
    use hickory_resolver::proto::rr::{Name, Record, RecordType};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};
    use tokio::time::sleep;

    // ---- Local DNS servers: resolver behaviour without the network ----------

    const LOCAL_PTR: &str = "host.example.";
    // TEST-NET-1: never assigned to this host, so binding it fails with an
    // I/O error before any packet leaves.
    const UNBINDABLE: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    const LOOKED_UP: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));

    /// The answer to `query`: one PTR record naming LOCAL_PTR.
    fn ptr_answer(query: &[u8]) -> Vec<u8> {
        let query = Message::from_vec(query).expect("a DNS query");
        let mut answer = Message::response(query.metadata.id, OpCode::Query);
        answer.metadata.recursion_desired = query.metadata.recursion_desired;
        answer.metadata.recursion_available = true;
        for question in &query.queries {
            answer.add_query(question.clone());
            answer.add_answer(Record::from_rdata(
                question.name().clone(),
                60,
                RData::PTR(PTR(Name::from_ascii(LOCAL_PTR).unwrap())),
            ));
        }
        answer.to_vec().expect("an encodable DNS answer")
    }

    /// A UDP DNS server on 127.0.0.1; returns its port.
    async fn udp_dns_server(queries: Arc<AtomicUsize>) -> u16 {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = socket.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
                queries.fetch_add(1, Ordering::SeqCst);
                let _ = socket.send_to(&ptr_answer(&buf[..len]), peer).await;
            }
        });
        port
    }

    /// A TCP DNS server (two-byte length prefix) on 127.0.0.1; returns its port.
    async fn tcp_dns_server(queries: Arc<AtomicUsize>) -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let queries = queries.clone();
                tokio::spawn(async move {
                    loop {
                        let mut len = [0u8; 2];
                        if stream.read_exact(&mut len).await.is_err() {
                            return;
                        }
                        let mut query = vec![0u8; u16::from_be_bytes(len) as usize];
                        if stream.read_exact(&mut query).await.is_err() {
                            return;
                        }
                        queries.fetch_add(1, Ordering::SeqCst);
                        let answer = ptr_answer(&query);
                        let mut framed = (answer.len() as u16).to_be_bytes().to_vec();
                        framed.extend_from_slice(&answer);
                        if stream.write_all(&framed).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        port
    }

    fn localhost(connections: Vec<ConnectionConfig>) -> NameServerConfig {
        NameServerConfig::new(IpAddr::V4(Ipv4Addr::LOCALHOST), true, connections)
    }

    fn udp_on(port: u16) -> ConnectionConfig {
        let mut connection = ConnectionConfig::udp();
        connection.port = port;
        connection
    }

    fn tcp_on(port: u16) -> ConnectionConfig {
        let mut connection = ConnectionConfig::tcp();
        connection.port = port;
        connection
    }

    #[test]
    fn resolver_options_are_the_hickory_025_ones() {
        let options = resolver_options();
        assert_eq!(options.timeout, Duration::from_secs(5));
        assert_eq!(options.attempts, 2);
        assert_eq!(options.cache_size, 32);
        assert_eq!(options.num_concurrent_reqs, 2);
        assert!(!options.edns0);
        assert!(options.try_tcp_on_error);
    }

    #[test]
    fn providers_ask_udp_first_and_keep_a_tcp_only_fallback() {
        for servers in [&GOOGLE, &CLOUDFLARE, &QUAD9] {
            let udp_and_tcp: Vec<NameServerConfig> = servers.udp_and_tcp().collect();
            let tcp_only: Vec<NameServerConfig> = servers.tcp().collect();
            assert_eq!(udp_and_tcp.len(), 4, "{}", servers.server_name);
            assert_eq!(tcp_only.len(), 4, "{}", servers.server_name);
            for (both, tcp) in udp_and_tcp.iter().zip(&tcp_only) {
                assert_eq!(both.ip, tcp.ip);
                assert!(both.trust_negative_responses);
                assert!(matches!(
                    both.connections.as_slice(),
                    [udp, tcp] if matches!(udp.protocol, ProtocolConfig::Udp)
                        && matches!(tcp.protocol, ProtocolConfig::Tcp)
                        && udp.port == 53
                        && tcp.port == 53
                ));
                assert!(matches!(
                    tcp.connections.as_slice(),
                    [tcp] if matches!(tcp.protocol, ProtocolConfig::Tcp) && tcp.port == 53
                ));
            }
        }
    }

    #[tokio::test]
    async fn resolvers_are_google_then_cloudflare_then_quad9() {
        let names: Vec<&str> = FlodbaddResolver::create_resolvers()
            .iter()
            .map(|resolver| resolver.name)
            .collect();
        assert_eq!(names, ["Google", "Cloudflare", "Quad9"]);
    }

    #[test]
    fn only_io_failures_retry_over_tcp() {
        let refused = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
        assert!(retries_over_tcp(&NetError::Io(Arc::new(refused))));
        assert!(retries_over_tcp(&NetError::NoConnections));

        assert!(!retries_over_tcp(&NetError::Timeout));
        assert!(!retries_over_tcp(&NetError::Busy));
        let query = Query::query(Name::from(LOOKED_UP), RecordType::PTR);
        let nxdomain = NoRecords::new(query, ResponseCode::NXDomain);
        assert!(!retries_over_tcp(&NetError::Dns(DnsError::NoRecordsFound(
            nxdomain
        ))));
    }

    #[tokio::test]
    async fn reverse_lookup_reads_the_ptr_answer_over_udp() {
        let udp_queries = Arc::new(AtomicUsize::new(0));
        let tcp_queries = Arc::new(AtomicUsize::new(0));
        let udp_port = udp_dns_server(udp_queries.clone()).await;
        let tcp_port = tcp_dns_server(tcp_queries.clone()).await;
        let resolver = ProviderResolver::from_name_servers(
            "local",
            vec![localhost(vec![udp_on(udp_port), tcp_on(tcp_port)])],
            vec![localhost(vec![tcp_on(tcp_port)])],
        )
        .unwrap();

        let name = resolver.reverse_lookup(LOOKED_UP).await.unwrap();

        assert_eq!(name.as_deref(), Some("host.example"));
        assert!(udp_queries.load(Ordering::SeqCst) >= 1);
        assert_eq!(tcp_queries.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn an_io_failure_over_udp_retries_over_tcp() {
        let tcp_queries = Arc::new(AtomicUsize::new(0));
        let tcp_port = tcp_dns_server(tcp_queries.clone()).await;
        let mut broken_udp = udp_on(53);
        broken_udp.bind_addr = Some(SocketAddr::new(UNBINDABLE, 0));
        let resolver = ProviderResolver::from_name_servers(
            "local",
            vec![localhost(vec![broken_udp])],
            vec![localhost(vec![tcp_on(tcp_port)])],
        )
        .unwrap();

        let name = resolver.reverse_lookup(LOOKED_UP).await.unwrap();

        assert_eq!(name.as_deref(), Some("host.example"));
        assert!(tcp_queries.load(Ordering::SeqCst) >= 1);
    }

    // ---- Public resolvers (network) ------------------------------------------

    #[tokio::test]
    async fn test_reverse_dns_lookup_success() {
        let resolver = Arc::new(FlodbaddResolver::new());
        resolver.start().await;

        // Use a real IP address for testing (Google's DNS)
        let ip_addr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        resolver.add_ip_to_resolver(&ip_addr).await;

        // Wait for the resolver to complete
        while resolver.get_resolved_ip(&ip_addr).await.is_none() {
            sleep(Duration::from_millis(100)).await;
        }
        let domain = resolver.get_resolved_ip(&ip_addr).await.unwrap();
        assert_eq!(domain, "dns.google");
    }

    #[tokio::test]
    async fn test_reverse_dns_lookup_unknown() {
        let resolver = Arc::new(FlodbaddResolver::new());
        resolver.start().await;

        // Use a non-existent IP address for testing
        let ip_addr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)); // Reserved IP for documentation
        resolver.add_ip_to_resolver(&ip_addr).await;

        // Wait for the resolver to complete
        while resolver.get_resolved_ip(&ip_addr).await.is_none() {
            sleep(Duration::from_millis(100)).await;
        }
        let domain = resolver.get_resolved_ip(&ip_addr).await.unwrap();
        assert_eq!(domain, "Unknown");
    }

    #[tokio::test]
    async fn test_add_same_ip_multiple_times() {
        let resolver = Arc::new(FlodbaddResolver::new());
        resolver.start().await;

        let ip_addr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        resolver.add_ip_to_resolver(&ip_addr).await;
        resolver.add_ip_to_resolver(&ip_addr).await; // Adding the same IP again

        // Wait for the resolver to complete
        while resolver.get_resolved_ip(&ip_addr).await.is_none() {
            sleep(Duration::from_millis(100)).await;
        }
        let domain = resolver.get_resolved_ip(&ip_addr).await.unwrap();
        assert_eq!(domain, "dns.google");
    }

    #[tokio::test]
    async fn test_concurrent_ip_additions() {
        let resolver = Arc::new(FlodbaddResolver::new());
        resolver.start().await;

        let ip_addr1 = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)); // Google DNS
        let ip_addr2 = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)); // Cloudflare DNS

        // Add IPs concurrently
        let resolver_clone = Arc::clone(&resolver);
        let handle1 = tokio::spawn(async move {
            resolver_clone.add_ip_to_resolver(&ip_addr1).await;
        });
        let resolver_clone = Arc::clone(&resolver);
        let handle2 = tokio::spawn(async move {
            resolver_clone.add_ip_to_resolver(&ip_addr2).await;
        });

        let _ = tokio::join!(handle1, handle2);

        // Wait for both to resolve
        while resolver.get_resolved_ip(&ip_addr1).await.is_none() {
            sleep(Duration::from_millis(100)).await;
        }
        while resolver.get_resolved_ip(&ip_addr2).await.is_none() {
            sleep(Duration::from_millis(100)).await;
        }

        let domain1 = resolver.get_resolved_ip(&ip_addr1).await.unwrap();
        let domain2 = resolver.get_resolved_ip(&ip_addr2).await.unwrap();

        assert_eq!(domain1, "dns.google");
        assert_eq!(domain2, "one.one.one.one");
    }

    #[tokio::test]
    async fn test_stop_resolver() {
        let resolver = Arc::new(FlodbaddResolver::new());
        resolver.start().await;

        // Ensure the resolver is running
        assert!(resolver.resolver_handle.read().await.is_some());

        // Stop the resolver
        resolver.stop().await;

        // Ensure the resolver handle is None after stopping
        assert!(resolver.resolver_handle.read().await.is_none());
    }

    #[tokio::test]
    async fn test_forward_dns_priority_over_reverse() {
        let resolver = Arc::new(FlodbaddResolver::new());
        resolver.start().await;

        // Use a well-known IP address for testing
        let ip_addr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        // First, let's do reverse DNS resolution
        resolver.add_ip_to_resolver(&ip_addr).await;

        // Wait for the resolver to complete
        while resolver.get_resolved_ip(&ip_addr).await.is_none() {
            sleep(Duration::from_millis(100)).await;
        }

        // Verify we got a reverse DNS result (should be something like dns.google)
        let reverse_domain = resolver.get_resolved_ip(&ip_addr).await.unwrap();
        assert!(reverse_domain.contains("dns"));

        // Now simulate a forward DNS resolution from captured DNS packets
        let dns_resolutions = CustomDashMap::new("dns_resolutions");
        let forward_domain = "forward-dns-resolution.example.com";
        dns_resolutions.insert(ip_addr, forward_domain.to_string());

        // Add the forward DNS resolution
        let added = resolver.add_dns_resolutions(&dns_resolutions);
        assert_eq!(added, 1);

        // The forward resolution should override the reverse resolution
        let final_domain = resolver.get_resolved_ip(&ip_addr).await.unwrap();
        assert_eq!(final_domain, forward_domain);
    }
}
