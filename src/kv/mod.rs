/// In-memory storage for the key-value store.
mod mem;

pub trait KVStore {
    type Key: AsRef<[u8]>;
    type Value: AsRef<[u8]>;

    /// Get the value of a key.
    fn get(&self, key: &Self::Key) -> Option<&Self::Value>;
    /// Set the value of a key.
    fn set(&mut self, key: Self::Key, value: Self::Value);
    /// Remove a key, if it exists.
    fn del(&mut self, key: &Self::Key);
    /// Check if the key exists in the store.
    fn ex(&self, key: &Self::Key) -> bool;
}
