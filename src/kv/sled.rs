use sled::Db;

/// A key-value store backed by Sled.
#[derive(Debug)]
pub struct SledKVStore<K, V> {
    db: Db,
    _phantom: core::marker::PhantomData<(K, V)>,
}

impl<K, V> SledKVStore<K, V> {
    /// Create a new `SledKVStore` with the given `Db`.
    pub fn new(db: Db) -> Self {
        SledKVStore {
            db,
            _phantom: core::marker::PhantomData,
        }
    }

    /// Open a `SledKVStore` from the given path.
    pub fn from_path<P: AsRef<std::path::Path>>(path: P) -> Result<Self, std::io::Error> {
        sled::open(path).map(Self::new).map_err(Into::into)
    }

    /// Open a `SledKVStore` in-memory.
    pub fn in_memory() -> Result<Self, std::io::Error> {
        sled::Config::new()
            .temporary(true)
            .open()
            .map(Self::new)
            .map_err(Into::into)
    }
}

impl<K, V> super::KVStore for SledKVStore<K, V>
where
    K: AsRef<[u8]>,
    V: AsRef<[u8]> + From<Vec<u8>>,
{
    type Key = K;
    type Value = V;
    type Error = std::io::Error;

    fn get(&self, key: &Self::Key) -> Result<Option<Self::Value>, Self::Error> {
        self.db
            .get(key)
            .map(|opt| opt.map(|ivec| ivec.to_vec().into()))
            .map_err(Into::into)
    }

    fn set(&self, key: Self::Key, value: Self::Value) -> Result<(), Self::Error> {
        self.db
            .insert(key, value.as_ref())
            .map(|_| ())
            .map_err(Into::into)
    }

    fn del(&self, key: &Self::Key) -> Result<(), Self::Error> {
        self.db.remove(key).map(|_| ()).map_err(Into::into)
    }

    fn ex(&self, key: &Self::Key) -> Result<bool, Self::Error> {
        self.db.contains_key(key).map_err(Into::into)
    }
}
