//! The checkpoint entries parser and `verify_checkpoint` on arbitrary input:
//! never a panic, a parsed list writes back to the same bytes, and a
//! checkpoint that verifies really is consistent with the rows it was checked
//! against (plan section 9.2).
#![no_main]

use ferret_core::integrity::{ENTRY_LEN, encode_entries, parse_entries};
use ferret_core::{
    AccountId, ItemId, RowState, ServerRow, UnlockedVault, VaultContext, VaultId, VaultKey,
    make_checkpoint, verify_checkpoint,
};
use libfuzzer_sys::fuzz_target;

/// One row of the server's state in the input: `item_id (16) ‖ rev (8) ‖
/// state (1) ‖ hash (32)`.
const ROW_LEN: usize = 16 + 8 + 1 + 32;

fn vault() -> UnlockedVault {
    UnlockedVault::from_vault_key(
        VaultContext {
            account_id: AccountId::from_bytes([1; 16]),
            vault_id: VaultId::from_bytes([2; 16]),
            vk_epoch: 1,
        },
        VaultKey::from_test_bytes([3; 32]),
    )
    .expect("the keys derive")
}

fuzz_target!(|data: &[u8]| {
    // The parser alone.
    if let Ok(list) = parse_entries(data) {
        assert_eq!(data.len(), list.len() * ENTRY_LEN);
        assert_eq!(encode_entries(&list).expect("a parsed list encodes"), data);
    }

    // Layout: seq (8) ‖ top_seq (8) ‖ n_entries (1) ‖ entries ‖ rows.
    let Some((head, rest)) = data.split_first_chunk::<17>() else {
        return;
    };
    let seq = u64::from_be_bytes(head[..8].try_into().expect("8 bytes"));
    let top = u64::from_be_bytes(head[8..16].try_into().expect("8 bytes"));
    let n = usize::from(head[16]).min(rest.len() / ENTRY_LEN);
    let (entry_bytes, row_bytes) = rest.split_at(n * ENTRY_LEN);
    let Ok(entries) = parse_entries(entry_bytes) else {
        return;
    };
    let vault = vault();
    let cp =
        make_checkpoint(&vault, seq, entries.clone()).expect("a parsed list makes a checkpoint");
    assert_eq!(cp.entries, entry_bytes);

    let rows: Vec<ServerRow> = row_bytes
        .chunks_exact(ROW_LEN)
        .map(|c| ServerRow {
            item_id: ItemId::from_bytes(c[..16].try_into().expect("16 bytes")),
            rev: u64::from_be_bytes(c[16..24].try_into().expect("8 bytes")),
            state: if c[24] & 1 == 0 {
                RowState::Deleted
            } else {
                RowState::Live {
                    blob_sha256: c[25..57].try_into().expect("32 bytes"),
                }
            },
        })
        .collect();

    if verify_checkpoint(&vault, &cp, &rows, top).is_ok() {
        assert!(seq <= top);
        // Every live entry is shown by the server, at the same or a higher
        // revision, with the same blob if the revision is the same.
        for e in &entries {
            let Some(hash) = e.live_hash else { continue };
            let row = rows
                .iter()
                .find(|r| r.item_id == e.item_id)
                .expect("a live entry has a row");
            assert!(row.rev >= e.rev);
            if row.rev == e.rev {
                assert_eq!(row.state, RowState::Live { blob_sha256: hash });
            }
        }
    }

    // A flipped MAC never verifies.
    let mut bad = cp.clone();
    bad.mac[0] ^= 1;
    assert!(verify_checkpoint(&vault, &bad, &rows, top).is_err());
});
