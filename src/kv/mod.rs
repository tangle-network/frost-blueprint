use std::sync::Arc;

/// In-memory storage for the key-value store.
#[cfg(feature = "kv-mem")]
mod mem;
/// Storage using [`sled`](https://docs.rs/sled) as the backend.
#[cfg(feature = "kv-sled")]
mod sled;

#[cfg(feature = "kv-mem")]
pub use mem::MemKVStore;
#[cfg(feature = "kv-sled")]
pub use sled::SledKVStore;

pub trait KVStore {
    type Key: AsRef<[u8]>;
    type Value: AsRef<[u8]>;

    /// Get the value of a key.
    type Error;

    fn get(&self, key: &Self::Key) -> Result<Option<Self::Value>, Self::Error>;
    fn set(&self, key: Self::Key, value: Self::Value) -> Result<(), Self::Error>;
    fn del(&self, key: &Self::Key) -> Result<(), Self::Error>;
    fn ex(&self, key: &Self::Key) -> Result<bool, Self::Error>;
}

/// A shared, thread-safe, dynamic key-value store independent of the underlying storage.
pub type SharedDynKVStore<K, V> =
    Arc<dyn KVStore<Key = K, Value = V, Error = std::io::Error> + Send + Sync + 'static>;
