use std::collections::HashMap;

use gadget_sdk::parking_lot;

/// Shared In-memory key-value store.
#[derive(Debug)]
pub struct MemKVStore<K, V, E> {
    store: parking_lot::Mutex<HashMap<K, V>>,
    error: core::marker::PhantomData<E>,
}

impl<K, V, E> MemKVStore<K, V, E>
where
    K: Eq + std::hash::Hash,
    V: Clone,
{
    /// Create a new `MemKVStore`.
    pub fn new() -> Self {
        MemKVStore {
            store: parking_lot::Mutex::new(HashMap::new()),
            error: core::marker::PhantomData,
        }
    }

    /// Insert a key-value pair into the store.
    pub fn insert(&self, key: K, value: V) {
        self.store.lock().insert(key, value);
    }

    /// Get the value associated with a key.
    pub fn get(&self, key: &K) -> Option<V> {
        self.store.lock().get(key).cloned()
    }

    /// Remove a key-value pair from the store.
    pub fn remove(&self, key: &K) -> Option<V> {
        self.store.lock().remove(key)
    }

    /// Check if the store contains a key.
    pub fn contains_key(&self, key: &K) -> bool {
        self.store.lock().contains_key(key)
    }
}

impl<K, V, E> Default for MemKVStore<K, V, E>
where
    K: Eq + std::hash::Hash,
    V: Clone,
{
    fn default() -> Self {
        MemKVStore::new()
    }
}

impl<K, V, E> super::KVStore for MemKVStore<K, V, E>
where
    K: Eq + std::hash::Hash + Clone + AsRef<[u8]>,
    V: Clone + AsRef<[u8]>,
{
    type Key = K;

    type Value = V;

    type Error = E;

    fn get(&self, key: &Self::Key) -> Result<Option<Self::Value>, Self::Error> {
        Ok(MemKVStore::get(self, key))
    }

    fn set(&self, key: Self::Key, value: Self::Value) -> Result<(), Self::Error> {
        self.insert(key, value);
        Ok(())
    }

    fn del(&self, key: &Self::Key) -> Result<(), Self::Error> {
        self.remove(key);
        Ok(())
    }

    fn ex(&self, key: &Self::Key) -> Result<bool, Self::Error> {
        Ok(self.contains_key(key))
    }
}
