//! Arbitrary bytes as an encrypted block: header parsing and authenticated
//! decryption must reject them without panicking.
#![no_main]
use darkbox::protection::{BlockContext, BlockLocation, block_header, decrypt_block};
use darkbox::zeroize::Zeroizing;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = block_header(data);
    let context = BlockContext {
        package_id: "00112233445566778899aabbccddeeff".into(),
        key_id: "fuzz-key".into(),
        location: BlockLocation::File {
            path: "assets/private.bin".into(),
        },
    };
    let key = Zeroizing::new([7u8; 32]);
    let _ = decrypt_block(data, &key, &context);
});
