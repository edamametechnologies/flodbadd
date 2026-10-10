use macaddr::MacAddr6;
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
/// We'll just expose a type alias for a boxed error to keep it flexible.
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Re-export the single cross-platform async function that calls the correct platform impl.
pub use platform_impl::scan_neighbors;

/// A consolidated neighbor entry: multiple IPv4 addresses, multiple IPv6 addresses for a given MAC.
pub type ConsolidatedNeighbor = (MacAddr6, Vec<Ipv4Addr>, Vec<Ipv6Addr>);

/// Helper to unify multiple (IpAddr, MacAddr6) pairs per MAC into a single
/// (Vec<Ipv4Addr>, Vec<Ipv6Addr>, MacAddr6) entry.
fn unify_neighbors(neighbors: Vec<(IpAddr, MacAddr6)>) -> Vec<ConsolidatedNeighbor> {
    // Filter out entries with nil MacAddr6
    let neighbors: Vec<(IpAddr, MacAddr6)> = neighbors
        .into_iter()
        .filter(|(_, mac)| !mac.is_nil())
        .collect();

    // Filter out link-local, broadcast, or multicast addresses, etc.
    let neighbors: Vec<(IpAddr, MacAddr6)> = neighbors
        .into_iter()
        .filter(|(ip, _)| match ip {
            IpAddr::V4(v4) => {
                !(v4.is_link_local()
                // is_broadcast() is true only for 255.255.255.255
                // || v4.is_broadcast()
                || v4.octets()[3] == 255 // Check if last octet is 255
                || v4.is_multicast()
                || v4.is_unspecified()
                || v4.is_loopback())
            }
            IpAddr::V6(v6) => !(v6.is_multicast() || v6.is_unspecified() || v6.is_loopback()),
        })
        .collect();

    let mut map: HashMap<MacAddr6, (HashSet<Ipv4Addr>, HashSet<Ipv6Addr>)> = HashMap::new();
    for (ip, mac) in neighbors {
        let (v4set, v6set) = map
            .entry(mac)
            .or_insert_with(|| (HashSet::new(), HashSet::new()));
        match ip {
            IpAddr::V4(v4) => {
                v4set.insert(v4);
            }
            IpAddr::V6(v6) => {
                v6set.insert(v6);
            }
        }
    }
    // Flatten our collected sets into final results:
    map.into_iter()
        .map(|(mac, (v4s, v6s))| (mac, v4s.into_iter().collect(), v6s.into_iter().collect()))
        .collect()
}

/// Parse one row of `/proc/net/arp`, the Linux kernel's IPv4 neighbor table,
/// optionally keeping only `interface_name`:
///
/// ```text
/// IP address       HW type     Flags       HW address            Mask     Device
/// 192.168.1.5      0x1         0x2         00:11:22:33:44:55     *        eth0
/// ```
///
/// An incomplete entry carries a zero MAC, which `unify_neighbors` drops.
/// Compiled for tests on every platform so the parser is checked anywhere.
#[cfg(any(target_os = "linux", test))]
fn parse_proc_net_arp_row(line: &str, interface_name: Option<&str>) -> Option<(IpAddr, MacAddr6)> {
    let cols: Vec<&str> = line.split_whitespace().collect();
    if cols.len() < 6 {
        return None;
    }
    if interface_name.is_some_and(|iface| cols[5] != iface) {
        return None;
    }
    let ip: Ipv4Addr = cols[0].parse().ok()?;
    let mac: MacAddr6 = cols[3].parse().ok()?;
    Some((IpAddr::V4(ip), mac))
}

#[cfg(target_os = "windows")]
mod platform_impl {
    use super::*;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetIpNetTable2, MIB_IPNET_ROW2,
    };
    use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC};

    /// Parse Windows MIB_IPNET_ROW2 into an IP + MAC (+ LUID) tuple (if valid).
    fn parse_address(row: &MIB_IPNET_ROW2) -> Option<(IpAddr, MacAddr6, u64)> {
        if row.PhysicalAddressLength != 6 {
            return None;
        }
        let mac = MacAddr6::new(
            row.PhysicalAddress[0],
            row.PhysicalAddress[1],
            row.PhysicalAddress[2],
            row.PhysicalAddress[3],
            row.PhysicalAddress[4],
            row.PhysicalAddress[5],
        );
        // SAFETY: we trust that row.Address is valid because it is coming from the OS.
        let family = unsafe { row.Address.si_family };
        let ip = match family {
            AF_INET => {
                // interpret the address as SOCKADDR_IN
                let sock_in = unsafe { row.Address.Ipv4 };
                let octets = unsafe { sock_in.sin_addr.S_un.S_addr.to_ne_bytes() };
                IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
            }
            AF_INET6 => {
                // interpret the address as SOCKADDR_IN6
                let sock_in6 = unsafe { row.Address.Ipv6 };
                let octets = unsafe { sock_in6.sin6_addr.u.Byte };
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => return None,
        };

        // SAFETY: InterfaceLuid is a union field but we trust the OS to provide valid data
        unsafe { Some((ip, mac, row.InterfaceLuid.Value)) }
    }

    /// Collect neighbor table using the Windows crate, optionally filtering by interface alias.
    pub async fn scan_neighbors(
        interface_name: Option<&str>,
    ) -> Result<Vec<super::ConsolidatedNeighbor>> {
        let mut pairs = vec![];

        unsafe {
            let mut filter_luid = None;
            if let Some(iface_name) = interface_name {
                let wide: Vec<u16> = OsStr::new(iface_name)
                    .encode_wide()
                    .chain(std::iter::once(0))
                    .collect();
                let mut luid = NET_LUID_LH::default();
                let ret = windows::Win32::NetworkManagement::IpHelper::ConvertInterfaceAliasToLuid(
                    PCWSTR::from_raw(wide.as_ptr()),
                    &mut luid,
                );
                if ret != windows::Win32::Foundation::ERROR_SUCCESS {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("ConvertInterfaceAliasToLuid failed with code {ret:?}"),
                    )
                    .into());
                }
                filter_luid = Some(luid.Value);
            }

            let mut table_ptr = std::ptr::null_mut();
            let res = GetIpNetTable2(AF_UNSPEC, &mut table_ptr);
            if res != ERROR_SUCCESS {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("GetIpNetTable2 failed with code {res:?}"),
                )
                .into());
            }
            if table_ptr.is_null() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "GetIpNetTable2 returned a null pointer",
                )
                .into());
            }

            let table = &*table_ptr;
            let row_slice =
                std::slice::from_raw_parts(table.Table.as_ptr(), table.NumEntries as usize);

            for row in row_slice {
                if let Some((ip, mac, luid_val)) = parse_address(row) {
                    if let Some(filter_luid) = filter_luid {
                        if luid_val != filter_luid {
                            continue;
                        }
                    }
                    pairs.push((ip, mac));
                }
            }

            FreeMibTable(table_ptr.cast());
        }

        // Consolidate multiple IPs per MAC:
        Ok(super::unify_neighbors(pairs))
    }
}

#[cfg(target_os = "linux")]
mod platform_impl {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::process::Command;
    use tracing::warn;

    /// `ip` is absent on minimal images (containers, some appliances): said
    /// once per process, not on every LAN scan.
    static IP_BINARY_MISSING_REPORTED: AtomicBool = AtomicBool::new(false);

    /// The IPv4 neighbors from `/proc/net/arp`, the fallback when `ip` is not
    /// installed. IPv6 neighbors are only reachable through netlink (`ip`), so
    /// they are missing on that path.
    fn read_proc_net_arp(interface_name: Option<&str>) -> io::Result<Vec<(IpAddr, MacAddr6)>> {
        let table = std::fs::read_to_string("/proc/net/arp")?;
        Ok(table
            .lines()
            .skip(1)
            .filter_map(|line| super::parse_proc_net_arp_row(line, interface_name))
            .collect())
    }

    /// Parse a single line of `ip neigh` (Linux).
    fn parse(line: &str) -> Option<(IpAddr, MacAddr6)> {
        // Example line: "192.168.1.5 dev eth0 lladdr 00:11:22:33:44:55 STALE"
        let mut parts = line.split_whitespace();
        let ip = parts.next()?.parse().ok()?;
        // Skip 'dev', device name, 'lladdr'
        let mac = parts.skip(3).next()?.parse().ok()?;
        Some((ip, mac))
    }

    /// Get neighbors from `ip neigh`, optionally filtered by interface name, in an async manner.
    /// Returns consolidated neighbors so that the same MAC can have multiple IPs.
    pub async fn scan_neighbors(
        interface_name: Option<&str>,
    ) -> Result<Vec<super::ConsolidatedNeighbor>> {
        let mut cmd = Command::new("ip");
        cmd.arg("neigh");

        if let Some(iface_name) = interface_name {
            cmd.arg("show").arg("dev").arg(iface_name);
        }

        // Bound the subprocess so a wedged `ip neigh` can't freeze neighbor
        // discovery (and therefore the whole lanscan) indefinitely. kill_on_drop
        // reaps the child when the timeout fires.
        cmd.kill_on_drop(true);
        let output = match tokio::time::timeout(std::time::Duration::from_secs(10), cmd.output())
            .await
        {
            Ok(Ok(output)) => output,
            Ok(Err(e)) if e.kind() == io::ErrorKind::NotFound => {
                if !IP_BINARY_MISSING_REPORTED.swap(true, Ordering::Relaxed) {
                    warn!(
                        "'ip' is not installed: reading IPv4 neighbors from /proc/net/arp (no IPv6 neighbors)"
                    );
                }
                return match read_proc_net_arp(interface_name) {
                    Ok(raw_neighbors) => Ok(super::unify_neighbors(raw_neighbors)),
                    // The kind stays NotFound so the caller can tell a
                    // host without the tools from a failed scan.
                    Err(arp_error) => Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!(
                            "'ip' is not installed and /proc/net/arp is unreadable: {arp_error}"
                        ),
                    )
                    .into()),
                };
            }
            // Keep the kind (permission denied, ...) for the caller.
            Ok(Err(e)) => {
                return Err(
                    io::Error::new(e.kind(), format!("Failed to execute 'ip neigh': {e}")).into(),
                )
            }
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "'ip neigh' timed out after 10s",
                )
                .into())
            }
        };

        let stdout_str = String::from_utf8_lossy(&output.stdout);
        let raw_neighbors = stdout_str.lines().filter_map(parse).collect();

        Ok(super::unify_neighbors(raw_neighbors))
    }
}

#[cfg(target_os = "macos")]
mod platform_impl {
    use super::*;
    use tokio::process::Command;

    /// A neighbor-table dump (`ndp`/`arp`) completes in milliseconds normally;
    /// bound it so a wedged subprocess can never freeze neighbor discovery (and
    /// therefore the whole lanscan) indefinitely. This was the root of the
    /// observed dogfood "scan stuck at 0%" hang.
    const NEIGHBOR_CMD_TIMEOUT_SECS: u64 = 10;

    /// Run a command with args, returning stdout as String.
    async fn run(cmd: &str, args: &[&str]) -> Result<String> {
        let mut c = Command::new(cmd);
        c.args(args);
        // Reap the child if the timeout below fires before it exits.
        c.kill_on_drop(true);

        let output = match tokio::time::timeout(
            std::time::Duration::from_secs(NEIGHBOR_CMD_TIMEOUT_SECS),
            c.output(),
        )
        .await
        {
            Ok(result) => result.map_err(|e| {
                // Keep the kind (NotFound, permission denied, ...) for the
                // caller.
                io::Error::new(e.kind(), format!("Failed to execute {cmd}: {e}"))
            })?,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("{cmd} timed out after {NEIGHBOR_CMD_TIMEOUT_SECS}s"),
                )
                .into())
            }
        };

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    fn sanitize_mac(s: &str) -> Option<MacAddr6> {
        let mut bytes_iter = s.split(':').flat_map(|x| u8::from_str_radix(x, 16).ok());
        Some(MacAddr6::from([
            bytes_iter.next()?,
            bytes_iter.next()?,
            bytes_iter.next()?,
            bytes_iter.next()?,
            bytes_iter.next()?,
            bytes_iter.next()?,
        ]))
    }

    /// Parse a line from "ndp -anr" when it looks like:
    ///   2a01:e0a:17f:a660:b7:18b5:3dd8:7fd2     a2:e0:22:d3:49:93    en0  9h48m19s  S
    fn v6_parse(row: &str, interface_name: Option<&str>) -> Option<(IpAddr, MacAddr6)> {
        let cols: Vec<&str> = row.split_whitespace().collect();
        // We need at least [IP, MAC, NetIf] columns
        if cols.len() < 3 {
            return None;
        }
        let raw_ip = cols[0]; // e.g. "2a01:e0a:17f:..."
        let raw_mac = cols[1]; // e.g. "a2:e0:22:d3:49:93" or "(incomplete)"
        let netif = cols[2]; // e.g. "en0"

        // Skip lines where MAC is "(incomplete)"
        if raw_mac == "(incomplete)" {
            return None;
        }

        // If the user specified an interface, skip lines where netif doesn't match
        if let Some(iface) = interface_name {
            if netif != iface {
                return None;
            }
        }

        // Some addresses may have a %en0 suffix (e.g. fe80::XXXX%en0), so strip that
        let ip_str = raw_ip.split('%').next().unwrap_or(raw_ip);
        let ipv6: Ipv6Addr = ip_str.parse().ok()?; // parse IP

        // Convert the MAC string to MacAddr6
        let mac = sanitize_mac(raw_mac)?;

        Some((IpAddr::V6(ipv6), mac))
    }

    /// Parse lines from "arp -an" (IPv4).
    /// Each line yields (IpAddr::V4(...), MacAddr6) if valid.
    fn v4_parse(row: &str) -> Option<(IpAddr, MacAddr6)> {
        // e.g. "? (192.168.1.5) at 00:11:22:33:44:55 on en0 ...
        let mut parts = row.split_whitespace().skip(1); // skip "?"
        let ip_str = parts.next()?; // "(192.168.1.5)"
        let ip_str = ip_str.trim_start_matches('(').trim_end_matches(')');
        let ip_addr = IpAddr::V4(ip_str.parse().ok()?);

        let at_word = parts.next()?; // "at"
        if at_word != "at" {
            return None;
        }
        let mac_str = parts.next()?; // e.g. "00:11:22:33:44:55"
        let mac = sanitize_mac(mac_str)?;
        Some((ip_addr, mac))
    }

    /// Get neighbors on macOS, optionally filtered by interface, consolidating multiple
    /// addresses per MAC in a single Vec<(Vec<Ipv4Addr>, Vec<Ipv6Addr>, MacAddr6)>.
    pub async fn scan_neighbors(
        interface_name: Option<&str>,
    ) -> Result<Vec<super::ConsolidatedNeighbor>> {
        // Gather raw IPv6 neighbors:
        let ndp_lines = run("ndp", &["-anr"]).await?;
        let ndp_lines: Vec<_> = ndp_lines.lines().skip(1).collect(); // skip heading

        let mut raw_neighbors = vec![];
        for line in ndp_lines {
            if let Some(x) = v6_parse(line, interface_name) {
                // x is (IpAddr::V6(...), MacAddr6)
                raw_neighbors.push(x);
            }
        }

        // Gather raw IPv4 neighbors:
        let mut arp_args = vec!["-an"];
        if let Some(iface) = interface_name {
            arp_args.push("-i");
            arp_args.push(iface);
        }
        let arp_lines = run("arp", &arp_args).await?;
        for line in arp_lines.lines() {
            if let Some(x) = v4_parse(line) {
                // x is (IpAddr::V4(...), MacAddr6)
                raw_neighbors.push(x);
            }
        }

        // Consolidate by MAC
        Ok(super::unify_neighbors(raw_neighbors))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interface::get_default_interface;

    #[test]
    fn proc_net_arp_rows_parse_and_filter_by_interface() {
        let table = "IP address       HW type     Flags       HW address            Mask     Device
192.168.1.5      0x1         0x2         00:11:22:33:44:55     *        eth0
192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        eth0
10.0.0.7         0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0";
        let rows: Vec<_> = table
            .lines()
            .skip(1)
            .filter_map(|line| parse_proc_net_arp_row(line, Some("eth0")))
            .collect();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)));
        assert_eq!(rows[0].1, "00:11:22:33:44:55".parse::<MacAddr6>().unwrap());

        // The incomplete entry's zero MAC is dropped when unified.
        let unified = unify_neighbors(rows);
        assert_eq!(unified.len(), 1);
        assert_eq!(unified[0].1, vec![Ipv4Addr::new(192, 168, 1, 5)]);

        let all: Vec<_> = table
            .lines()
            .skip(1)
            .filter_map(|line| parse_proc_net_arp_row(line, None))
            .collect();
        assert_eq!(all.len(), 3);
        assert!(parse_proc_net_arp_row("garbage", None).is_none());
    }

    // Converted test to async. Requires you to run with a test runtime (e.g. cargo test -- --test-threads=1 under tokio).
    #[tokio::test]
    async fn test_neighbors_default_interface() {
        // Attempt to fetch a default interface (non-loopback, with IP).
        let Some(interface) = get_default_interface() else {
            println!("No suitable default interface found for neighbor test.");
            return;
        };

        println!(
            "Detected default interface for neighbor test: {}",
            interface.name
        );

        // Attempt to get neighbors for that interface (async).
        match scan_neighbors(Some(&interface.name)).await {
            Ok(neighbors) => {
                println!(
                    "Found {} neighbor groupings on '{}':",
                    neighbors.len(),
                    interface.name
                );
                for (mac, v4_addrs, v6_addrs) in neighbors {
                    println!(" -> MAC {mac}, v4 = {v4_addrs:?}, v6 = {v6_addrs:?}");
                }
            }
            Err(e) => {
                println!(
                    "Failed to retrieve neighbors on '{}': {}",
                    interface.name, e
                );
            }
        }
    }
}
