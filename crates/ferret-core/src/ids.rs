//! Public identifiers. They are not secret, so `Clone`, `Copy` and `Debug`
//! are allowed. All of them are 16 raw bytes (a UUID, never a string).

macro_rules! id_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
        pub struct $name([u8; 16]);

        impl $name {
            /// Length in bytes.
            pub const LEN: usize = 16;

            /// Wraps 16 raw bytes.
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            /// The raw bytes.
            pub const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
        }
    };
}

id_type!(
    /// Identifies an account.
    AccountId
);
id_type!(
    /// Identifies a vault.
    VaultId
);
id_type!(
    /// Identifies an item. [`ItemId::MANIFEST`] is reserved for the manifest.
    ItemId
);
id_type!(
    /// Identifies an unlock method.
    MethodId
);

impl ItemId {
    /// The reserved `item_id` of the manifest: 16 zero bytes.
    pub const MANIFEST: ItemId = ItemId([0; 16]);
}
