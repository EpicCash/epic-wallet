use sqlite::{self, Connection};
use std::fs;
use std::path::PathBuf;

use crate::serialization as ser;
use crate::serialization::Serializable;
use crate::Error;

static SQLITE_FILENAME: &str = "epic.db";

pub struct Store {
	db: Connection,
}

impl Store {
	pub fn new(db_path: PathBuf) -> Store {
		let db_path = db_path.join(SQLITE_FILENAME);
		let db: Connection = sqlite::open(db_path).unwrap();
		Store::check_or_create(&db);
		return Store { db };
	}

	pub fn check_or_create(db: &Connection) -> Result<(), sqlite::Error> {
		// SELECT * FROM data LIMIT 1; to check if table exists
		let creation = "CREATE TABLE IF NOT EXISTS data (id INTEGER PRIMARY KEY, key TEXT NOT NULL, data TEXT NOT NULL, prefix TEXT);"; //create database if file not found
		return db.execute(creation);
	}

	/// Gets a value from the db, provided its key
	pub fn get(&self, key: &[u8]) -> Option<Serializable> {
		let query = format!(
			r#"SELECT data FROM data WHERE key = "{}" LIMIT 1;"#,
			remove_non_display_as_string(key)
		);

		match self.db.prepare(query).unwrap().into_iter().next() {
			Some(s) => {
				let data = s.unwrap().read::<&str, _>("data").to_string();
				Some(ser::deserialize(&data).unwrap())
			}
			None => None,
		}
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
	pub fn put(&self, key: &[u8], value: Serializable) -> Result<(), Error> {
		// serialize value to json
		let value = ser::serialize(value).unwrap();
		let prefix = key[0] as char;

		let query = format!(
			r#"INSERT INTO data (key, data, prefix) VALUES ("{}", '{}', "{}");"#,
			remove_non_display_as_string(key),
			value,
			prefix
		);
		return Ok(self.store.execute(query).unwrap());
	}

	pub fn put_ser(&self, key: &[u8], value: Serializable) -> Result<(), Error> {
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

fn remove_non_display_as_string(s: &[u8]) -> String {
	String::from_utf8(s.to_vec())
		.unwrap()
		.chars()
		.filter(|x| x.is_ascii_graphic())
		.collect()
}

unsafe impl Sync for Store {}
unsafe impl Send for Store {}
