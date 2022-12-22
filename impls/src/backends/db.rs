use epic_wallet_util::epic_core::ser::ProtocolVersion;
use serde::Serialize;
use sqlite::{self, Connection};
use std::fs;

use crate::serialization as ser;
use crate::serialization::Serializable;
use crate::Error;

static DB_DEFAULT_PATH: &str = "~/.epic/user/wallet_data/db/sqlite/";
static DB_FILENAME: &str = "epic.db";
const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion(1);

pub struct Store {
	db: Connection,
}

impl Store {
	pub fn new() -> Store {
		let full_path: String = DB_DEFAULT_PATH.to_owned() + DB_FILENAME;
		fs::create_dir_all(DB_DEFAULT_PATH);
		let db: Connection = sqlite::open(full_path).unwrap();
		Store::check_or_create(db, &full_path);
		return Store { db };
	}

	pub fn check_or_create(db: Connection, path: &str) -> Result<(), sqlite::Error> {
		// SELECT * FROM data LIMIT 1; to check if table exists
		let creation = "CREATE TABLE IF NOT EXISTS data (id INTEGER PRIMARY KEY, key TEXT NOT NULL, data TEXT NOT NULL, prefix TEXT);"; //create database if file not found
		return db.execute(creation);
	}

	/// Gets a value from the db, provided its key
	pub fn get(&self, key: &[u8]) -> Result<Option<Serializable>, Error> {
		let statement = self
			.db
			.prepare("SELECT * FROM data WHERE key = ? LIMIT 1")
			.unwrap()
			.bind(1, key)
			.unwrap();

		let data = statement.read::<String>(1).unwrap();
		let deser = ser::deserialize(&data).unwrap();
		Ok(Some(deser))
	}

	/// Gets a `Readable` value from the db, provided its key. Encapsulates
	/// serialization.
	pub fn get_ser(&self, key: &[u8]) -> Result<Option<Serializable>, Error> {
		self.get(key)
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
	pub fn iter(&self, from: &[u8]) -> Vec<Serializable> {
		let query = "SELECT * FROM data;";
		self.db
			.prepare(query)
			.into_iter()
			.map(|row| {
				let row_data = row.read::<String>(1).unwrap();
				ser::deserialize(&row_data).unwrap()
			})
			.collect()
	}

	/// Builds a new batch to be used with this store.
	pub fn batch(&self) -> Result<Batch, Error> {
		Ok(Batch { store: self })
	}

	pub fn execute(&self, statement: String) -> Result<(), sqlite::Error> {
		self.db.execute(statement)
	}
}

/// Batch to write multiple Writeables to db in an atomic manner.
pub struct Batch<'a> {
	store: &'a Store,
}

impl<'a> Batch<'_> {
	/// Writes a single key/value pair to the db
	pub fn put<T>(&self, key: &[u8], mut value: &T, prefix: char) -> Result<(), Error> {
		// serialize value to json
		let statement = format!(
			"INSERT INTO data VALUES ({}, {}, {});",
			String::from_utf8(key.to_vec()).unwrap(),
			value,
			prefix
		);
		return Ok(self.store.execute(statement).unwrap());
	}

	/// Writes a single key and its `Writeable` value to the db.
	/// Encapsulates serialization using the (default) version configured on the store instance.
	pub fn put_ser<T>(&self, key: &[u8], value: &T) -> Result<(), Error> {
		self.put(key, value, 'a')
	}

	/// gets a value from the db, provided its key
	pub fn get(&self, key: &[u8]) -> Result<Option<Serializable>, Error> {
		self.store.get(key)
	}

	/// Whether the provided key exists
	pub fn exists(&self, key: &[u8]) -> Result<bool, Error> {
		self.exists(key)
	}

	// Produces an iterator of `Readable` types moving forward from the
	// provided key.
	pub fn iter<T: Serialize>(&self, from: &[u8]) -> Vec<impl Serialize> {
		self.store.iter(from)
	}

	/// Deletes a key/value pair from the db
	pub fn delete(&self, key: &[u8]) -> Result<(), Error> {
		let statement = format!(
			"DELETE FROM data WHERE key = {}",
			String::from_utf8(key.to_owned()).unwrap()
		);
		self.store.execute(statement);
		Ok(())
	}

	pub fn get_ser(&self, key: &[u8]) -> Result<Option<Serializable>, Error> {
		return self.store.get_ser(key);
	}
}

unsafe impl Sync for Store {}
unsafe impl Send for Store {}
