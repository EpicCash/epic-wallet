use sqlite::{self, Connection};
use std::fs;

use crate::serialization as ser;
use crate::serialization::Serializable;
use crate::Error;

static DB_DEFAULT_PATH: &str = "~/.epic/user/wallet_data/db/sqlite/";
static DB_FILENAME: &str = "epic.db";

pub struct Store {
	db: Connection,
}

impl Store {
	pub fn new() -> Store {
		let full_path: String = DB_DEFAULT_PATH.to_owned() + DB_FILENAME;
		fs::create_dir_all(DB_DEFAULT_PATH);
		let db: Connection = sqlite::open(&full_path).unwrap();
		Store::check_or_create(&db, &full_path);
		return Store { db };
	}

	pub fn check_or_create(db: &Connection, path: &str) -> Result<(), sqlite::Error> {
		// SELECT * FROM data LIMIT 1; to check if table exists
		let creation = "CREATE TABLE IF NOT EXISTS data (id INTEGER PRIMARY KEY, key TEXT NOT NULL, data TEXT NOT NULL, prefix TEXT);"; //create database if file not found
		return db.execute(creation);
	}

	/// Gets a value from the db, provided its key
	pub fn get(&self, key: &[u8]) -> Option<Serializable> {
		let statement = self
			.db
			.prepare("SELECT data FROM data WHERE key = ? LIMIT 1")
			.unwrap()
			.into_iter()
			.next()
			.unwrap()
			.unwrap();

		let data = statement.read::<&str, _>("data");
		Some(ser::deserialize(&data).unwrap())
	}

	/// Gets a `Readable` value from the db, provided its key. Encapsulates
	/// serialization.
	pub fn get_ser(&self, key: &[u8]) -> Option<Serializable> {
		self.get(key)
	}

	/// Whether the provided key exists
	pub fn exists(&self, key: &[u8]) -> Result<bool, Error> {
		let mut statement = self
			.db
			.prepare("SELECT * FROM data WHERE key = ? LIMIT 1")
			.unwrap()
			.into_iter();
		return Ok(statement.next().is_some());
	}

	/// Produces an iterator of (key, value) pairs, where values are `Readable` types
	/// moving forward from the provided key.
	pub fn iter(&self, from: &[u8]) -> Vec<Serializable> {
		let query = format!(
			r#"SELECT data FROM data WHERE prefix = "{}";"#,
			String::from_utf8(from.to_vec()).unwrap()
		);
		self.db
			.prepare(query)
			.unwrap()
			.into_iter()
			.map(|row| {
				let row = row.unwrap();
				ser::deserialize(row.read::<&str, _>("data")).unwrap()
			})
			.collect()
	}

	/// Builds a new batch to be used with this store.
	pub fn batch(&self) -> Batch {
		Batch { store: self }
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
	pub fn put(&self, key: &[u8], mut value: Serializable) -> Result<(), Error> {
		// serialize value to json
		let value = ser::serialize(value).unwrap();
		let prefix = key[0] as char;
		let statement = format!(
			r#"INSERT INTO data (key, data, prefix) VALUES ("{}", '{}', "{}");"#,
			String::from_utf8(key.to_vec()).unwrap(),
			value,
			prefix
		);
		return Ok(self.store.execute(statement).unwrap());
	}

	pub fn put_ser(&self, key: &[u8], mut value: Serializable) -> Result<(), Error> {
		self.put(key, value)
	}

	/// gets a value from the db, provided its key
	pub fn get(&self, key: &[u8]) -> Option<Serializable> {
		self.store.get(key)
	}

	/// Whether the provided key exists
	pub fn exists(&self, key: &[u8]) -> Result<bool, Error> {
		self.exists(key)
	}

	// Produces an iterator of `Readable` types moving forward from the
	// provided key.
	pub fn iter(&self, from: &[u8]) -> Vec<Serializable> {
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

	pub fn get_ser(&self, key: &[u8]) -> Option<Serializable> {
		return self.store.get_ser(key);
	}
}

unsafe impl Sync for Store {}
unsafe impl Send for Store {}
