//! Streaming creation and replacement editions, using only public test keys.
use darkbox::protection::{
    self, BlockContext, BlockLocation, DecryptionKeys, ManifestSigner, NAMESPACE, NonceSequence,
    SIGNATURE_PATH,
};
use darkbox::{Limits, PackageWriter, VerificationOptions};
use ed25519_dalek::{Signer, SigningKey};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const KEY: [u8; 32] = [42; 32];
const PACKAGE: &str = "00112233445566778899aabbccddeeff";

struct TestKeys;
impl DecryptionKeys for TestKeys {
    fn key(&self, id: &str) -> Option<Zeroizing<[u8; 32]>> {
        (id == "test-key").then(|| Zeroizing::new(KEY))
    }
}
struct TestSigner(SigningKey);
impl ManifestSigner for TestSigner {
    fn signer_id(&self) -> &str {
        "test-signer"
    }
    fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
    fn sign(&self, bytes: &[u8]) -> Result<[u8; 64], darkbox::Error> {
        Ok(self.0.sign(bytes).to_bytes())
    }
}
struct TestNonces(u32);
impl NonceSequence for TestNonces {
    fn next_nonce(&mut self, _: &str) -> Result<[u8; 12], darkbox::Error> {
        // Deterministic test data only. Production applications reserve durable nonces.
        self.0 += 1;
        let mut nonce = [0; 12];
        nonce[8..].copy_from_slice(&self.0.to_be_bytes());
        Ok(nonce)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let output = args
        .next()
        .map(PathBuf::from)
        .ok_or("Usage: cargo run --example streaming -- OUTPUT.project [replacement]")?;
    let replacement = match args.next() {
        None => false,
        Some(value) if value == "replacement" => true,
        _ => return Err("Expected replacement or no second argument".into()),
    };
    if args.next().is_some() {
        return Err("Too many arguments".into());
    }
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let prepared = tempfile::Builder::new()
        .prefix(".darkbox-streaming-example-")
        .tempdir_in(parent)?;
    let database = prepared.path().join("snapshot.sqlite");
    let db = Connection::open(&database)?;
    db.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA user_version=1; CREATE TABLE notes(id TEXT PRIMARY KEY NOT NULL,label TEXT,secret BLOB);")?;
    let context = |location| BlockContext {
        package_id: PACKAGE.into(),
        key_id: "test-key".into(),
        location,
    };
    let mut nonces = TestNonces(0);
    for id in ["r1", "r2"] {
        let block = protection::encrypt_block(
            b"Private text",
            &KEY,
            &context(BlockLocation::Sqlite {
                database: "data/project.sqlite".into(),
                table: "notes".into(),
                column: "secret".into(),
                record_id: id.into(),
            }),
            &mut nonces,
        )?;
        db.execute(
            "INSERT INTO notes VALUES (?1,'Public label',?2)",
            params![id, block],
        )?;
    }
    // Caller preparation ends with a closed coherent SQLite snapshot.
    drop(db);
    let path = if replacement {
        "assets/new.bin"
    } else {
        "assets/private.bin"
    };
    let encrypted = prepared.path().join("attachment.bin");
    fs::write(
        &encrypted,
        protection::encrypt_block(
            b"An already encrypted attachment",
            &KEY,
            &context(BlockLocation::File { path: path.into() }),
            &mut TestNonces(if replacement { 200 } else { 100 }),
        )?,
    )?;
    let mut manifest: Value = serde_json::from_slice(include_bytes!("notebook.manifest.json"))?;
    manifest["application"] = json!({"id":"org.example.streaming-notes","formatVersion":"1","profilePath":"docs/profile.md"});
    manifest["databases"][0]["userVersion"] = json!(1);
    manifest["databases"][0]["tables"] =
        json!([{"name":"notes","description":"Public labels and protected text"}]);
    manifest["folders"].as_array_mut().unwrap().extend([
        json!({"path":"assets","description":"Large public and protected resources"}),
        json!({"path":"extensions","description":"Extensions"}),
        json!({"path":format!("extensions/{NAMESPACE}"),"description":"Detached signature"}),
    ]);
    manifest["extensions"][NAMESPACE] = json!({"version":"1.0.0","required":true,"data":{"packageId":PACKAGE,"signature":{"algorithm":"Ed25519","signerId":"test-signer","path":SIGNATURE_PATH},"inventory":[],"files":[{"path":path,"keyId":"test-key"}],"sqlite":[{"database":"data/project.sqlite","table":"notes","column":"secret","recordIdColumn":"id","keyId":"test-key"}]}});
    let signer = TestSigner(SigningKey::from_bytes(&[7; 32]));
    let options = VerificationOptions {
        decryption_keys: Some(&TestKeys),
        trusted_signers: BTreeMap::from([("test-signer".into(), signer.public_key())]),
        require_protection: true,
        ..Default::default()
    };
    let mut writer = PackageWriter::new(
        &output,
        manifest,
        Limits::default(),
        &options,
        Some(&signer),
    )?;
    writer.add_path("data/project.sqlite", &database)?;
    writer.add_path(
        "docs/profile.md",
        Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/profiles/streaming-notes.md"),
    )?;
    writer.add_path(path, &encrypted)?;
    // This resource never exists as one in-memory allocation or input file.
    let resource =
        writer.add_reader("assets/public.bin", io::repeat(b'p').take(16 * 1024 * 1024))?;
    let report = writer.finish()?;
    println!(
        "Published {}: {:?}, streamed {} bytes; encrypted resource {}",
        output.display(),
        report.status,
        resource.size,
        path
    );
    Ok(())
}
