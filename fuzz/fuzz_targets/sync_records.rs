//! Arbitrary bytes as each canonical sync record. Decoding accepts only exact
//! canonical encodings, so anything accepted must re-encode to the same bytes.
#![no_main]
use darkbox::sync::{
    Baseline, Checkpoint, DomainRoot, Generation, LogicalState, Receipt, ReplicaDescriptor,
    RepositoryRoot, Segment, SnapshotDescriptor, SyncMapping, SyncTransaction, canonical, decode,
};
use libfuzzer_sys::fuzz_target;

macro_rules! round_trip {
    ($data:expr, $($record:ty),+ $(,)?) => {
        $(
            if let Ok(record) = decode::<$record>($data, $data.len()) {
                assert_eq!(canonical(&record).unwrap(), $data);
            }
        )+
    };
}

fuzz_target!(|data: &[u8]| {
    round_trip!(
        data,
        SyncTransaction,
        Segment,
        Receipt,
        ReplicaDescriptor,
        DomainRoot,
        SyncMapping,
        LogicalState,
        Baseline,
        Checkpoint,
        SnapshotDescriptor,
        RepositoryRoot,
        Generation,
    );
});
