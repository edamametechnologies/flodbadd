fn main() {
    let s1: &str = &flodbadd::sensitive_paths_db::SENSITIVE_PATHS_DB;
    let s2: &str = &flodbadd::profiles_db::DEVICE_PROFILES;
    let s3: &str = &flodbadd::port_vulns_db::PORT_VULNS;
    let s4: &str = &flodbadd::vendor_vulns_db::VENDOR_VULNS;
    let s5: &str = &flodbadd::whitelists_db::WHITELISTS;
    let s6: &str = &flodbadd::blacklists_db::BLACKLISTS;
    println!("len={} {} {} {} {} {}", s1.len(), s2.len(), s3.len(), s4.len(), s5.len(), s6.len());
}
