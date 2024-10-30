use std::collections::HashMap;

/// In-memory key-value store.
#[derive(Debug, Clone)]
pub struct MemKVStore<K, V> {
    store: HashMap<K, V>,
}

impl<K, V> MemKVStore<K, V>
where
    K: Eq + std::hash::Hash,
{
    /// Create a new `MemKVStore`.
    pub fn new() -> Self {
        MemKVStore {
            store: HashMap::new(),
        }
    }

    /// Insert a key-value pair into the store.
    pub fn insert(&mut self, key: K, value: V) {
        self.store.insert(key, value);
    }

    /// Get the value associated with a key.
    pub fn get(&self, key: &K) -> Option<&V> {
        self.store.get(key)
    }

    /// Remove a key-value pair from the store.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.store.remove(key)
    }

    /// Check if the store contains a key.
    pub fn contains_key(&self, key: &K) -> bool {
        self.store.contains_key(key)
    }

    /// Get the number of key-value pairs in the store.
    pub fn len(&self) -> usize {
        self.store.len()
    }

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }
}

impl<K, V> Default for MemKVStore<K, V>
where
    K: Eq + std::hash::Hash,
{
    fn default() -> Self {
        MemKVStore::new()
    }
}

impl<K, V> super::KVStore for MemKVStore<K, V>
where
    K: Eq + std::hash::Hash + Clone + AsRef<[u8]>,
    V: Clone + AsRef<[u8]>,
{
    type Key = K;

    type Value = V;

    fn get(&self, key: &Self::Key) -> Option<&Self::Value> {
        MemKVStore::get(self, key)
    }

    fn set(&mut self, key: Self::Key, value: Self::Value) {
        self.insert(key, value);
    }

    fn del(&mut self, key: &Self::Key) {
        self.remove(key);
    }

    fn ex(&self, key: &Self::Key) -> bool {
        self.contains_key(key)
    }
}
