use epic_wallet_libwallet::TxLogEntry;
use epic_wallet_util::epic_core::ser::ProtocolVersion;
use sqlite::{self, Connection, Cursor, Row};
use std::fs::create_dir_all;

use crate::Error;

static DB_DEFAULT_PATH: &str = "~/.epic/user/wallet_data/da/lmdb";
static DB_FILENAME: &str = "epic.db";
pub struct Store {
	db: Connection,
	name: String,
	version: ProtocolVersion,
}

impl Store {
	/// Create a new LMDB env under the provided directory.
	/// By default creates an environment named "lmdb".
	/// Be aware of transactional semantics in lmdb
	/// (transactions are per environment, not per database).
	pub fn new(
		root_path: &str,
		db_name: Option<&str>,
		max_readers: Option<u32>,
	) -> Result<Store, Error> {
		let db_name = match db_name {
			Some(n) => n.to_owned(),
			None => "lmdb".to_owned(),
		};
		let full_path = [root_path.to_owned(), name].join("/");
		fs::create_dir_all(&full_path)
			.expect("Unable to create directory 'db_root' to store chain_data");

		let res = Store {
			db: sqlite::Connection("foobar"),
			name: db_name,
			version: DEFAULT_DB_VERSION,
		};

		{
			// let mut w = res.db.write();
			// *w = Some(Arc::new(lmdb::Database::open(
			// 	res.env.clone(),
			// 	Some(&res.name),
			// 	&lmdb::DatabaseOptions::new(lmdb::db::CREATE),
			// )?));
		}
		Ok(res)
	}

	/// Construct a new store using a specific protocol version.
	/// Permits access to the db with legacy protocol versions for db migrations.
	pub fn with_version(&self, version: ProtocolVersion) -> Store {
		Store {
			db: self.db.clone(),
			name: self.name.clone(),
			version: version,
		}
	}

	/// Opens the database environment
	// some of these calls won't make sense on a relational db but the signatures might still be necessary
	pub fn open(&self) -> Result<(), Error> {
		// let mut w = self.db.write();
		// *w = Some(Arc::new(lmdb::Database::open(
		// 	self.env.clone(),
		// 	Some(&self.name),
		// 	&lmdb::DatabaseOptions::new(lmdb::db::CREATE),
		// )?));
		Ok(())
	}

	/// Gets a value from the db, provided its key
	pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
		let db = self.db.read();
		let txn = lmdb::ReadTransaction::new(self.env.clone())?;
		let access = txn.access();
		let res = access.get(&db.as_ref().unwrap(), key);
		res.map(|res: &[u8]| res.to_vec())
			.to_opt()
			.map_err(From::from)
	}

	/// Gets a `Readable` value from the db, provided its key. Encapsulates
	/// serialization.
	pub fn get_ser<T: ser::Readable>(&self, key: &[u8]) -> Result<Option<T>, Error> {
		let db = self.db.read();
		let txn = lmdb::ReadTransaction::new(self.env.clone())?;
		let access = txn.access();
		self.get_ser_access(key, &access, db)
	}

	fn get_ser_access<T: ser::Readable>(
		&self,
		key: &[u8],
		access: &lmdb::ConstAccessor<'_>,
		db: RwLockReadGuard<'_, Option<Arc<lmdb::Database<'static>>>>,
	) -> Result<Option<T>, Error> {
		let res: lmdb::error::Result<&[u8]> = access.get(&db.as_ref().unwrap(), key);
		match res.to_opt() {
			Ok(Some(mut res)) => match ser::deserialize(&mut res, self.version) {
				Ok(res) => Ok(Some(res)),
				Err(e) => Err(Error::SerErr(format!("{}", e))),
			},
			Ok(None) => Ok(None),
			Err(e) => Err(From::from(e)),
		}
	}

	/// Whether the provided key exists
	pub fn exists(&self, key: &[u8]) -> Result<bool, Error> {
		let db = self.db.read();
		let txn = lmdb::ReadTransaction::new(self.env.clone())?;
		let access = txn.access();
		let res: lmdb::error::Result<&lmdb::Ignore> = access.get(&db.as_ref().unwrap(), key);
		res.to_opt().map(|r| r.is_some()).map_err(From::from)
	}

	/// Produces an iterator of (key, value) pairs, where values are `Readable` types
	/// moving forward from the provided key.
	pub fn iter<T: ser::Readable>(&self, from: &[u8]) -> Result<SerIterator<T>, Error> {
		let db = self.db.read();
		let tx = Arc::new(lmdb::ReadTransaction::new(self.env.clone())?);
		let cursor = Arc::new(tx.cursor(db.as_ref().unwrap().clone()).unwrap());
		Ok(SerIterator {
			tx,
			cursor,
			seek: false,
			prefix: from.to_vec(),
			version: self.version,
			_marker: marker::PhantomData,
		})
	}

	/// Builds a new batch to be used with this store.
	pub fn batch(&self) -> Result<Batch<'_>, Error> {
		// check if the db needs resizing before returning the batch
		if self.needs_resize()? {
			self.do_resize()?;
		}
		let tx = lmdb::WriteTransaction::new(self.env.clone())?;
		Ok(Batch { store: self, tx })
	}
}

/// Batch to write multiple Writeables to db in an atomic manner.
pub struct Batch<'a> {
	store: &'a Store,
	tx: lmdb::WriteTransaction<'a>,
}

impl<'a> Batch<'a> {
	/// Writes a single key/value pair to the db
	pub fn put(&self, key: &[u8], value: &[u8]) -> Result<(), Error> {
		let db = self.store.db.read();
		self.tx
			.access()
			.put(&db.as_ref().unwrap(), key, value, lmdb::put::Flags::empty())?;
		Ok(())
	}

	/// Writes a single key and its `Writeable` value to the db.
	/// Encapsulates serialization using the (default) version configured on the store instance.
	pub fn put_ser<W: ser::Writeable>(&self, key: &[u8], value: &W) -> Result<(), Error> {
		self.put_ser_with_version(key, value, self.store.version)
	}

	/// Writes a single key and its `Writeable` value to the db.
	/// Encapsulates serialization using the specified protocol version.
	pub fn put_ser_with_version<W: ser::Writeable>(
		&self,
		key: &[u8],
		value: &W,
		version: ProtocolVersion,
	) -> Result<(), Error> {
		let ser_value = ser::ser_vec(value, version);
		match ser_value {
			Ok(data) => self.put(key, &data),
			Err(err) => Err(Error::SerErr(format!("{}", err))),
		}
	}

	/// gets a value from the db, provided its key
	pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
		self.store.get(key)
	}

	/// Whether the provided key exists
	pub fn exists(&self, key: &[u8]) -> Result<bool, Error> {
		self.store.exists(key)
	}

	/// Produces an iterator of `Readable` types moving forward from the
	/// provided key.
	pub fn iter<T: ser::Readable>(&self, from: &[u8]) -> Result<SerIterator<T>, Error> {
		self.store.iter(from)
	}

	/// Gets a `Readable` value from the db, provided its key, taking the
	/// content of the current batch into account.
	pub fn get_ser<T: ser::Readable>(&self, key: &[u8]) -> Result<Option<T>, Error> {
		let access = self.tx.access();
		let db = self.store.db.read();
		self.store.get_ser_access(key, &access, db)
	}

	/// Deletes a key/value pair from the db
	pub fn delete(&self, key: &[u8]) -> Result<(), Error> {
		let db = self.store.db.read();
		self.tx.access().del_key(&db.as_ref().unwrap(), key)?;
		Ok(())
	}

	/// Writes the batch to db
	pub fn commit(self) -> Result<(), Error> {
		self.tx.commit()?;
		Ok(())
	}

	/// Creates a child of this batch. It will be merged with its parent on
	/// commit, abandoned otherwise.
	pub fn child(&mut self) -> Result<Batch<'_>, Error> {
		Ok(Batch {
			store: self.store,
			tx: self.tx.child_tx()?,
		})
	}
}

/// An iterator that produces Readable instances back. Wraps the lower level
/// DBIterator and deserializes the returned values.
pub struct SerIterator<T>
where
	T: ser::Readable,
{
	tx: Arc<lmdb::ReadTransaction<'static>>,
	cursor: Arc<lmdb::Cursor<'static, 'static>>,
	seek: bool,
	prefix: Vec<u8>,
	version: ProtocolVersion,
	_marker: marker::PhantomData<T>,
}

impl<T> Iterator for SerIterator<T>
where
	T: ser::Readable,
{
	type Item = (Vec<u8>, T);

	fn next(&mut self) -> Option<(Vec<u8>, T)> {
		let access = self.tx.access();
		let kv = if self.seek {
			Arc::get_mut(&mut self.cursor).unwrap().next(&access)
		} else {
			self.seek = true;
			Arc::get_mut(&mut self.cursor)
				.unwrap()
				.seek_range_k(&access, &self.prefix[..])
		};
		match kv {
			Ok((k, v)) => self.deser_if_prefix_match(k, v),
			Err(_) => None,
		}
	}
}

impl<T> SerIterator<T>
where
	T: ser::Readable,
{
	fn deser_if_prefix_match(&self, key: &[u8], value: &[u8]) -> Option<(Vec<u8>, T)> {
		let plen = self.prefix.len();
		if plen == 0 || (key.len() >= plen && key[0..plen] == self.prefix[..]) {
			if let Ok(value) = ser::deserialize(&mut &value[..], self.version) {
				Some((key.to_vec(), value))
			} else {
				None
			}
		} else {
			None
		}
	}
}
