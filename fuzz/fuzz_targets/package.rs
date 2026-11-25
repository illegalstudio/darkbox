//! Arbitrary bytes as a complete package: container parsing, manifest, schema,
//! inventory, canonical comparison and SQLite checks must never panic or hang.
#![no_main]
use darkbox::{DiagnosticPackage, Limits, VerificationOptions};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = Limits::default()
        .with_max_archive_bytes(4 * 1024 * 1024)
        .with_max_entry_bytes(4 * 1024 * 1024)
        .with_max_total_bytes(16 * 1024 * 1024)
        .with_max_entries(256)
        .with_max_metadata_bytes(1024 * 1024)
        .with_timeout_seconds(10);
    let _ = DiagnosticPackage::from_reader(data, limits, &VerificationOptions::default());
});
