//! Complete SDK lifecycle. All encryption and signing keys here are public test data.
use darkbox::{
    ApplicationProfile, Error, Limits, ManifestBuilder, Package, PackageEditor, ProfileContext,
    ValueAddress, VerificationOptions,
    manifest::{DatabaseDeclaration, TableDeclaration},
    protection::{
        self, Ed25519Signer, KeyRing, ManifestSigner, NonceSequence, ProtectionData,
        SignatureDeclaration, SqliteProtection,
    },
    rusqlite::Connection,
    zeroize::Zeroizing,
};
use std::{
    io::{self, Cursor, Read},
    path::PathBuf,
};

const DATABASE: &str = "data/notes.sqlite";
fn sql(error: darkbox::rusqlite::Error) -> Error {
    Error::invalid("example.sql", error.to_string())
}
fn database() -> DatabaseDeclaration {
    DatabaseDeclaration {
        path: DATABASE.into(),
        description: "Note records".into(),
        user_version: Some(1),
        tables: vec![TableDeclaration {
            name: "notes".into(),
            description: "Stable TEXT id, public TEXT label, NULL or encrypted UTF-8 secret".into(),
        }],
    }
}
struct NotesProfile;
impl ApplicationProfile for NotesProfile {
    fn id(&self) -> &str {
        "org.example.sdk-notes"
    }
    fn supports(&self, version: &str) -> bool {
        version == "1"
    }
    fn validate(&self, context: &ProfileContext<'_>) -> Result<(), Error> {
        context.with_database(DATABASE, |db| {
            let label: String = db
                .query_row("SELECT label FROM notes WHERE id='note-1'", [], |row| {
                    row.get(0)
                })
                .map_err(sql)?;
            if label.trim().is_empty() {
                return Err(Error::invalid(
                    "profile.label",
                    "Note labels must be nonempty",
                ));
            }
            Ok(())
        })?;
        if context.manifest["extensions"]
            .get(protection::NAMESPACE)
            .is_some()
        {
            let secret = context
                .decrypt_value(ValueAddress::new(DATABASE, "notes", "secret", "note-1"))?
                .ok_or_else(|| {
                    Error::invalid(
                        "profile.secret",
                        "This example requires a private note value",
                    )
                })?;
            if std::str::from_utf8(&secret).is_err() {
                return Err(Error::invalid(
                    "profile.secret",
                    "Private note value must be UTF-8",
                ));
            }
        }
        Ok(())
    }
}
struct TestNonces(u32);
impl NonceSequence for TestNonces {
    fn next_nonce(&mut self, _: &str) -> Result<[u8; 12], Error> {
        // Public test keys only. Production allocators reserve durable unique nonces.
        self.0 += 1;
        let mut nonce = [0; 12];
        nonce[8..].copy_from_slice(&self.0.to_be_bytes());
        Ok(nonce)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let path = PathBuf::from(
        args.next()
            .ok_or("Usage: cargo run --example lifecycle -- OUTPUT.project [protected]")?,
    );
    let protected = match args.next() {
        None => false,
        Some(value) if value == "protected" => true,
        _ => return Err("Expected protected or no second argument".into()),
    };
    if args.next().is_some() {
        return Err("Too many arguments".into());
    }
    let mut keys = KeyRing::default();
    keys.insert("test-key", Zeroizing::new([42; 32]));
    let signer = Ed25519Signer::from_seed("test-signer", Zeroizing::new([7; 32]));
    let mut options = VerificationOptions {
        require_protection: protected,
        require_profile: true,
        decryption_keys: Some(&keys),
        ..Default::default()
    };
    options
        .trusted_signers
        .insert("test-signer".into(), signer.public_key());
    options.profiles.register(NotesProfile);
    let mut builder = ManifestBuilder::new("1.1.0", "org.example.sdk-notes", "1")?
        .folder("data", "Coherent SQLite snapshots")
        .folder("assets", "Public and private attachments")
        .database(database());
    if protected {
        builder = builder.protection(ProtectionData {
            package_id: "00112233445566778899aabbccddeeff".into(),
            signature: SignatureDeclaration {
                algorithm: "Ed25519".into(),
                signer_id: "test-signer".into(),
                path: protection::SIGNATURE_PATH.into(),
            },
            inventory: vec![],
            files: vec![],
            sqlite: vec![SqliteProtection {
                database: DATABASE.into(),
                table: "notes".into(),
                column: "secret".into(),
                record_id_column: "id".into(),
                key_id: "test-key".into(),
            }],
        });
    }
    let mut editor = PackageEditor::new(builder.build()?, Limits::default())?;
    let db = Connection::open_in_memory()?;
    db.execute_batch("PRAGMA user_version=1; CREATE TABLE notes(id TEXT PRIMARY KEY NOT NULL,label TEXT NOT NULL,secret BLOB); INSERT INTO notes VALUES('note-1','First label',NULL);")?;
    editor.put_database(database(), &db)?;
    editor.put_reader(
        "docs/profile.md",
        Cursor::new(include_bytes!("profiles/sdk-notes.md")),
    )?;
    editor.put_reader(
        "assets/generated.bin",
        io::repeat(b'p').take(8 * 1024 * 1024),
    )?;
    let mut nonces = TestNonces(0);
    if protected {
        editor.put_encrypted(
            "assets/private.bin",
            b"Private attachment",
            "test-key",
            &keys,
            &mut nonces,
        )?;
        editor.put_encrypted_value(
            ValueAddress::new(DATABASE, "notes", "secret", "note-1"),
            b"Private note",
            &keys,
            &mut nonces,
        )?;
    }
    let signing = protected.then_some(&signer as &dyn ManifestSigner);
    editor.save_as(&path, &options, signing)?;

    let opened = Package::open(&path, Limits::default(), &options)?;
    let mut editor = opened.edit();
    editor.edit_database(DATABASE, |tx| {
        tx.execute(
            "UPDATE notes SET label=?1 WHERE id='note-1'",
            ["Edited label"],
        )
        .map_err(sql)?;
        Ok(())
    })?;
    editor.rename_resource("assets/generated.bin", "assets/public.bin")?;
    editor.put_reader("assets/temporary.txt", Cursor::new(b"Temporary resource"))?;
    editor.remove_resource("assets/temporary.txt")?;
    if protected {
        editor.rename_encrypted("assets/private.bin", "assets/moved.bin", &keys, &mut nonces)?;
    }
    let saved = editor.save(&options, signing)?;
    let reader = saved.database(DATABASE)?;
    let label = reader.with_connection(|db| {
        db.query_row("SELECT label FROM notes WHERE id='note-1'", [], |row| {
            row.get::<_, String>(0)
        })
        .map_err(sql)
    })?;
    println!(
        "Saved {}: {}, {} resources, profile {}",
        path.display(),
        label,
        saved.resources().count(),
        saved.report().application_validation
    );
    if protected {
        let attachment = saved.decrypt_resource("assets/moved.bin", &keys)?;
        println!(
            "Authenticated {} private attachment bytes",
            attachment.len()
        );
    }
    let compressed = saved.copy_to(io::sink())?;
    let imported = Package::from_reader(std::fs::File::open(&path)?, Limits::default(), &options)?;
    assert_eq!(imported.manifest(), saved.manifest());
    println!("Verified {compressed} archive bytes through the library API");
    Ok(())
}
