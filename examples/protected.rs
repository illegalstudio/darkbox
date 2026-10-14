//! Complete fictional protected package. All cryptographic keys are public test values.
use darkbox::protection::{
    self, BlockContext, BlockLocation, DecryptionKeys, ManifestSigner, NAMESPACE, NonceSequence,
    SIGNATURE_PATH,
};
use darkbox::{Limits, Mode, VerificationOptions};
use ed25519_dalek::{Signer, SigningKey};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;
use zip::{ZipWriter, write::SimpleFileOptions};

const PACKAGE: &str = "00112233445566778899aabbccddeeff";
const TEST_KEY: [u8; 32] = [42; 32];

struct DemoKeys;
impl DecryptionKeys for DemoKeys {
    fn key(&self, id: &str) -> Option<Zeroizing<[u8; 32]>> {
        (id == "test-key").then(|| Zeroizing::new(TEST_KEY))
    }
}
struct DemoNonces(u32);
impl NonceSequence for DemoNonces {
    fn next_nonce(&mut self, _: &str) -> Result<[u8; 12], darkbox::Error> {
        // Deterministic demonstration only. Real applications reserve durable nonces.
        self.0 += 1;
        let mut nonce = [0; 12];
        nonce[8..].copy_from_slice(&self.0.to_be_bytes());
        Ok(nonce)
    }
}
struct DemoSigner(SigningKey);
impl ManifestSigner for DemoSigner {
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

fn collect(base: &Path, path: &Path, files: &mut BTreeMap<String, Vec<u8>>) -> std::io::Result<()> {
    for entry in fs::read_dir(path)? {
        let path = entry?.path();
        if path.is_dir() {
            collect(base, &path, files)?;
        } else {
            files.insert(
                path.strip_prefix(base)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .replace('\\', "/"),
                fs::read(path)?,
            );
        }
    }
    Ok(())
}

struct Published {
    paths: Vec<PathBuf>,
    done: bool,
}
impl Drop for Published {
    fn drop(&mut self) {
        if !self.done {
            for path in &self.paths {
                let _ = fs::remove_file(path);
            }
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("Usage: cargo run --example protected -- OUTPUT.project")?;
    let trust = output.with_extension("trust.json");
    let keys = output.with_extension("keys.json");
    if [&output, &trust, &keys].iter().any(|path| path.exists()) {
        return Err("Example output paths must not already exist".into());
    }
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let staging = tempfile::Builder::new()
        .prefix(".darkbox-example-")
        .tempdir_in(parent)?;
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let base = root.join("archive/1.1.0");
    let mut files = BTreeMap::new();
    collect(&base, &base, &mut files)?;
    files.insert(
        "docs/profile.md".into(),
        fs::read(root.join("examples/profiles/protected-notes.md"))?,
    );
    files.insert(
        "assets/public.txt".into(),
        b"A public attachment\n".to_vec(),
    );
    let mut nonces = DemoNonces(0);
    let context = |location| BlockContext {
        package_id: PACKAGE.into(),
        key_id: "test-key".into(),
        location,
    };
    files.insert(
        "assets/private.bin".into(),
        protection::encrypt_block(
            b"A private attachment\0\xff",
            &TEST_KEY,
            &context(BlockLocation::File {
                path: "assets/private.bin".into(),
            }),
            &mut nonces,
        )?,
    );
    let path = staging.path().join("project.sqlite");
    let db = Connection::open(&path)?;
    db.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA user_version=1; CREATE TABLE notes(id TEXT PRIMARY KEY NOT NULL,label TEXT NOT NULL,secret BLOB);")?;
    for id in ["r1", "r2"] {
        let plaintext = Zeroizing::new(serde_json::to_vec(
            &json!({"text":format!("Private {id}"),"count":3}),
        )?);
        let block = protection::encrypt_block(
            &plaintext,
            &TEST_KEY,
            &context(BlockLocation::Sqlite {
                database: "data/project.sqlite".into(),
                table: "notes".into(),
                column: "secret".into(),
                record_id: id.into(),
            }),
            &mut nonces,
        )?;
        // Encryption completes before SQLite sees any private value.
        db.execute(
            "INSERT INTO notes VALUES (?1,?2,?3)",
            params![id, format!("Public {id}"), block],
        )?;
    }
    drop(db);
    files.insert("data/project.sqlite".into(), fs::read(path)?);
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(root.join("examples/notebook.manifest.json"))?)?;
    manifest["application"] = json!({"id":"org.example.protected-notes","formatVersion":"1","profilePath":"docs/profile.md"});
    manifest["databases"][0]["description"] = json!("Public labels and protected notes");
    manifest["databases"][0]["userVersion"] = json!(1);
    manifest["databases"][0]["tables"] =
        json!([{"name":"notes","description":"Public id/label and protected secret BLOB"}]);
    manifest["folders"].as_array_mut().unwrap().extend([
        json!({"path":"assets","description":"Public and protected attachments"}),
        json!({"path":"extensions","description":"Extension resources"}),
        json!({"path":format!("extensions/{NAMESPACE}"),"description":"Detached signature"}),
    ]);
    let inventory:Vec<_>=files.iter().map(|(path,bytes)| json!({"path":path,"size":bytes.len(),"sha256":format!("{:x}",Sha256::digest(bytes))})).collect();
    manifest["extensions"][NAMESPACE] = json!({"version":"1.0.0","required":true,"data":{"packageId":PACKAGE,
        "signature":{"algorithm":"Ed25519","signerId":"test-signer","path":SIGNATURE_PATH},"inventory":inventory,
        "files":[{"path":"assets/private.bin","keyId":"test-key"}],
        "sqlite":[{"database":"data/project.sqlite","table":"notes","column":"secret","recordIdColumn":"id","keyId":"test-key"}]
    }});
    let signer = DemoSigner(SigningKey::from_bytes(&[7; 32]));
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    files.insert(
        SIGNATURE_PATH.into(),
        signer.sign(&manifest_bytes)?.to_vec(),
    );
    files.insert("manifest.json".into(), manifest_bytes);
    let mut candidate = tempfile::NamedTempFile::new_in(parent)?;
    {
        let mut zip = ZipWriter::new(candidate.as_file_mut());
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for folder in manifest["folders"].as_array().unwrap() {
            zip.add_directory(format!("{}/", folder["path"].as_str().unwrap()), options)?;
        }
        for (path, bytes) in &files {
            zip.start_file(path, options)?;
            zip.write_all(bytes)?;
        }
        zip.finish()?;
    }
    let options = VerificationOptions {
        decryption_keys: Some(&DemoKeys),
        trusted_signers: BTreeMap::from([("test-signer".into(), signer.public_key())]),
        require_protection: true,
        ..Default::default()
    };
    let report = darkbox::analyze_with(candidate.path(), Mode::Verify, Limits::default(), &options);
    if report.status != darkbox::Status::Passed {
        return Err(format!(
            "Example failed validation: {}",
            serde_json::to_string(&report)?
        )
        .into());
    }
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let mut published = Published {
        paths: Vec::new(),
        done: false,
    };
    for (path, bytes) in [
        (
            &trust,
            serde_json::to_vec_pretty(&json!({"test-signer":hex(&signer.public_key())}))?,
        ),
        (
            &keys,
            serde_json::to_vec_pretty(&json!({"test-key":hex(&TEST_KEY)}))?,
        ),
    ] {
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        temporary.write_all(&bytes)?;
        temporary.persist_noclobber(path)?;
        published.paths.push(path.clone());
    }
    candidate.persist_noclobber(&output)?;
    published.paths.push(output.clone());
    published.done = true;
    println!(
        "Created {} with public test keys at {} and {}",
        output.display(),
        trust.display(),
        keys.display()
    );
    Ok(())
}
