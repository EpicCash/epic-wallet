use crate::core::ser;
use epic_wallet_libwallet::TxLogEntry;
use epic_wallet_util::epic_core::ser::ProtocolVersion;
use sqlite::{self, Connection, Cursor, Row};
use std::{fs, result};

use crate::Error;

static DB_DEFAULT_PATH: &str = "~/.epic/user/wallet_data/da/lmdb";
static DB_FILENAME: &str = "epic.db";
const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion(1);

pub struct Store {
	db: Connection,
	name: String,
	version: ProtocolVersion,
}

//TODO update (almost) all comments

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
		let name = String::from("foo/bar");
		let full_path = [root_path.to_owned(), name].join("/");
		fs::create_dir_all(&full_path)
			.expect("Unable to create directory 'db_root' to store chain_data");

		let res = Store {
			db: sqlite::open(full_path).unwrap(),
			name: db_name,
			version: PROTOCOL_VERSION,
		};

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
	pub fn open(&self) -> Result<(), Error> {
		Ok(())
	}

	/// Gets a value from the db, provided its key
	pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
		let statement = self
			.db
			.prepare("SELECT * FROM data WHERE key = ? LIMIT 1")
			.unwrap()
			.bind(1, key)
			.unwrap();

		Ok(Some(statement.read::<Vec<u8>>(1).unwrap()))
	}

	/// Gets a `Readable` value from the db, provided its key. Encapsulates
	/// serialization.
	pub fn get_ser<T: ser::Readable>(&self, key: &[u8]) -> Result<Option<T>, Error> {
		let mut value = match self.get(key).unwrap() {
			Some(n) => n,
			None => {
				panic!("deu ruim")
			}
		};
		let foobar = ser::deserialize(&mut value.as_slice(), ser::ProtocolVersion(1));
		foobar
	}

	/// Whether the provided key exists
	pub fn exists(&self, key: &[u8]) -> Result<bool, Error> {
		let statement = self
			.db
			.prepare("SELECT * FROM data WHERE key = ? LIMIT 1")
			.unwrap()
			.bind(1, key)
			.unwrap();
		return Ok(statement.next().is_ok());
	}

	/// Produces an iterator of (key, value) pairs, where values are `Readable` types
	/// moving forward from the provided key.
	pub fn iter<T: ser::Readable>(&self, from: &[u8]) -> result::IntoIter<TxLogEntry> {
		let query = "SELECT * FROM data;";
		return self
			.db
			.iterate(query, |pairs| {
				for &(key, value) in pairs.iter() {
					ser::deserialize(value.unwrap(), ProtocolVersion(1));
				}
			})
			.into_iter();
	}

	/// Builds a new batch to be used with this store.
	pub fn batch(&self) -> Result<Batch, Error> {
		Ok(Batch { store: self.db })
	}
}

/// Batch to write multiple Writeables to db in an atomic manner.
pub struct Batch {
	store: Connection,
}

impl<'a> Batch {
	/// Writes a single key/value pair to the db
	pub fn put(&self, key: &[u8], mut value: u8, prefix: char) -> Result<(), Error> {
		let statement = self
			.store
			.prepare("INSERT INTO data VALUES (?, ?, ?);")
			.unwrap()
			.bind(1, key)
			.unwrap()
			.bind(2, value.to_owned() as i64)
			.unwrap()
			.bind(3, prefix as i64)
			.unwrap();
		let result = match statement {
			Ok(n) => n,
			_ => panic!("Error"),
		};
		//result()
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
	// pub fn iter<T: ser::Readable>(
	// 	&self,
	// 	from: &[u8],
	// ) -> Result<dyn Iterator<Item = TxLogEntry>, Error> {
	// 	self.store.iter(from)
	// }

	/// Gets a `Readable` value from the db, provided its key, taking the
	/// content of the current batch into account.
	pub fn get_ser<T: ser::Readable>(&self, key: &[u8]) -> Result<Option<T>, Error> {
		let access = self.tx.access();
		let db = self.store.db.read();
		// self.store.get_ser_access(key, &access, db)
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
}

unsafe impl Sync for Store {}
unsafe impl Send for Store {}
