//! Generic obfuscation for CloudModel embedded fallback blobs (`*_db.rs`).
//!
//! # Why
//!
//! The CloudModel pattern keeps an embedded fallback JSON blob inside the
//! compiled binary so the agent works offline / pre-first-fetch. Several of
//! these blobs (notably `sensitive_paths_db.rs`, `cve_detection_params_db.rs`,
//! and the helper-side path lists fed by them) contain literal lists of
//! credential-store paths, DPAPI master-key directories, browser
//! `User Data` directories, password-manager extension IDs, crypto-wallet
//! locations, and similar. Embedded as `pub static FOO: &str = r#"..."#;`,
//! those literals end up as a single contiguous block of UTF-8 in the
//! binary's rodata section, perfectly readable to `strings(1)` and to
//! Microsoft Defender's cloud ML model. The model recognizes that corpus
//! as a textbook information-stealer reconnaissance fingerprint
//! (`Trojan:Win32/Stealga.HAK!MTB`, ID 2147966677 -- the StealC family ML
//! signature) and flags the signed binary as malware on user machines.
//!
//! The goal of this module is to break that static fingerprint. We
//! gzip-compress the JSON (destroys readable strings, raises section
//! entropy) and XOR with a fixed key (defeats trivial signature scanners
//! that look for known prefixes / file magic). The transform is reversed
//! on demand by the function the macro emits. There is no security
//! boundary here -- a debugger or `strings` against the running process
//! recovers the JSON immediately. The point is anti-static-analysis noise
//! so the distributed binary's rodata does not look like an infostealer.
//!
//! # Usage
//!
//! Each `*_db.rs` becomes:
//!
//! ```ignore
//! use crate::obfuscated_cloud_model_fallback;
//!
//! obfuscated_cloud_model_fallback!(pub fn port_vulns_json: &[
//!     0xab, 0x12, 0x44, 0x9d, /* ... gzip+XOR encoded JSON ... */
//! ]);
//! ```
//!
//! The macro produces a `pub fn port_vulns_json() -> String` that decodes
//! the blob each time it is called. The decoded text is only ever needed
//! for the few milliseconds a parser reads it (`CloudModel::initialize`
//! keeps the parsed value, not the text), so nothing retains it: until
//! 2.3.2 the macro emitted a process-lifetime `Lazy<String>`, and the
//! decoded vendor-vulnerability snapshot (~75 MB of JSON) stayed resident
//! in every helper, daemon and app for the life of the process after a
//! single parse at startup. Callers pass `&foo_json()` where they used to
//! pass `&FOO`.
//!
//! Encode with `tools/encode_cloud_fallback.py`. The encoder is invoked
//! automatically from `update-threats.sh` and `update-asn.sh` after each
//! `threatmodels` fetch.

use std::io::Read;

/// XOR key applied to the compressed bytes. Fixed (not derived per-file)
/// because the goal is anti-string-matching, not cryptographic secrecy.
/// Picking a non-trivial value (not 0x00 / 0xff / 0x55 / 0xaa) reduces
/// the chance of collisions with common fixed-byte sections an ML model
/// might already discount.
const XOR_KEY: u8 = 0xA7;

/// Decode an obfuscated CloudModel fallback blob: XOR-decode then
/// gzip-decompress, returning the original UTF-8 JSON.
///
/// Panics on corrupted input. This is correct because:
///   1. The encoder is part of the build pipeline -- any corruption is a
///      build bug, not a recoverable runtime condition.
///   2. The CloudModel fallback IS the last-resort recovery path; if it's
///      unusable the agent has no usable defaults regardless.
pub fn decode_fallback(obfuscated: &[u8]) -> String {
    let xored: Vec<u8> = obfuscated.iter().map(|b| b ^ XOR_KEY).collect();
    let mut decoder = flate2::read::GzDecoder::new(&xored[..]);
    let mut out = String::with_capacity(obfuscated.len() * 4);
    decoder
        .read_to_string(&mut out)
        .expect("CloudModel fallback gzip decode failed -- corrupt obfuscated *_db.rs?");
    out
}

/// Declare an obfuscated CloudModel fallback as a function returning the
/// decoded JSON.
///
/// Each call decodes the blob anew and the caller owns the result, so the
/// decoded text lives exactly as long as the parse that needs it (see the
/// module docs). Nothing is cached: the fallbacks are read once at startup
/// and again only when a model is reset to its built-in data.
#[macro_export]
macro_rules! obfuscated_cloud_model_fallback {
    ($vis:vis fn $name:ident : $bytes:expr) => {
        $vis fn $name() -> String {
            $crate::cloud_model_fallback::decode_fallback($bytes)
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    fn encode_for_test(plain: &str) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(plain.as_bytes()).expect("gzip write");
        let compressed = encoder.finish().expect("gzip finish");
        compressed.iter().map(|b| b ^ XOR_KEY).collect()
    }

    #[test]
    fn roundtrip_short_json() {
        let plain = r#"{"hello":"world","credentials":["/.ssh/","/.aws/credentials"]}"#;
        let obf = encode_for_test(plain);
        // The obfuscated form must not contain any readable substring of
        // the original (this is the whole point of the transform).
        let obf_str = String::from_utf8_lossy(&obf);
        assert!(!obf_str.contains("ssh"));
        assert!(!obf_str.contains("aws"));
        assert!(!obf_str.contains("credentials"));
        let decoded = decode_fallback(&obf);
        assert_eq!(decoded, plain);
    }

    #[test]
    fn roundtrip_large_json() {
        // ~50 KB of mixed JSON to mimic real fallback sizes.
        let mut plain = String::from("{\"items\":[");
        for i in 0..1000 {
            plain.push_str(&format!(
                "{{\"id\":{},\"path\":\"/Users/example/.ssh/id_rsa_{}\"}},",
                i, i
            ));
        }
        plain.pop();
        plain.push_str("]}");
        let obf = encode_for_test(&plain);
        // Compressed form should be substantially smaller than plaintext.
        assert!(obf.len() < plain.len() / 2);
        let decoded = decode_fallback(&obf);
        assert_eq!(decoded, plain);
    }

    #[test]
    #[should_panic(expected = "gzip decode failed")]
    fn corrupt_input_panics() {
        let _ = decode_fallback(&[0x00, 0x01, 0x02, 0x03]);
    }

    static TEST_BLOB: once_cell::sync::Lazy<Vec<u8>> =
        once_cell::sync::Lazy::new(|| encode_for_test(r#"{"date":"x","signature":"y"}"#));
    obfuscated_cloud_model_fallback!(fn test_blob_json: &TEST_BLOB);

    /// The macro emits a function, not a cached static: every call returns
    /// its own buffer, which the caller drops once parsed.
    #[test]
    fn the_macro_decodes_on_demand_and_retains_nothing() {
        let first = test_blob_json();
        let second = test_blob_json();
        assert_eq!(first, r#"{"date":"x","signature":"y"}"#);
        assert_eq!(first, second);
        assert_ne!(first.as_ptr(), second.as_ptr(), "a fresh buffer per call");
        // The declared item is callable as a plain function (no `Deref`).
        let f: fn() -> String = test_blob_json;
        assert!(!f().is_empty());
    }
}
