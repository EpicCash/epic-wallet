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
		Store { db }
	}

	pub fn check_or_create(db: &Connection) -> Result<(), sqlite::Error> {
		// SELECT * FROM data LIMIT 1; to check if table exists
		let creation = r#"CREATE TABLE IF NOT EXISTS data (
			id INTEGER PRIMARY KEY,
			key TEXT NOT NULL,
			prefix TEXT, 
			data TEXT NOT NULL,
			q_tx_id INTEGER,
			q_confirmed INTEGER,
			q_tx_status TEXT);
		"#; //create database if file not found
		db.execute(creation)
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
		let query = format!(
			r#"SELECT * FROM data WHERE key = "{}" LIMIT 1;"#,
			remove_non_display_as_string(key)
		);
		let mut statement = self.db.prepare(query).unwrap().into_iter();
		Ok(statement.next().is_some())
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
		let value_s = ser::serialize(&value).unwrap();
		let prefix = key[0] as char;

		// Insert on the database
		// TxLogEntry and OutputData make use of queriable columns
		let mut query = match &value {
			Serializable::TxLogEntry(t) => format!(
				r#"INSERT INTO data 
						(key, data, prefix, q_tx_id, q_confirmed, q_tx_status) 
					VALUES 
						("{}", '{}', "{}", {}, {}, "{}");
				"#,
				remove_non_display_as_string(key),
				value_s,
				prefix,
				t.id,
				t.confirmed,
				t.tx_type
			),
			Serializable::OutputData(o) => format!(
				r#"INSERT INTO data 
						(key, data, prefix, q_tx_id, q_tx_status) 
					VALUES 
						("{}", '{}', "{}", "{}", "{}")
				"#,
				remove_non_display_as_string(key),
				value_s,
				prefix,
				match o.tx_log_entry {
					Some(entry) => entry.to_string(),
					None => "".to_string(),
				},
				o.status
			),
			_ => format!(
				r#"INSERT INTO data 
						(key, data, prefix) 
					VALUES 
						("{}", '{}', "{}");
				"#,
				remove_non_display_as_string(key),
				value_s,
				prefix
			),
		};

		// Update if the current key exists on the database
		// TxLogEntry and OutputData make use of queriable columns
		if self.exists(&key).unwrap() {
			query = match &value {
				Serializable::TxLogEntry(t) => format!(
					r#"UPDATE data
						SET 
							data = '{}', 
							q_tx_id = {}, 
							q_confirmed = {}, 
							q_tx_status = "{}"
						WHERE 
							key = "{}";
					"#,
					value_s,
					t.id,
					t.confirmed,
					t.tx_type,
					remove_non_display_as_string(key)
				),
				Serializable::OutputData(o) => format!(
					r#"UPDATE data 
						SET 
							data = '{}',
							q_tx_id = {},
							q_tx_status = "{}"
						WHERE 
							key = "{}";
					"#,
					value_s,
					match o.tx_log_entry {
						Some(entry) => entry.to_string(),
						None => "".to_string(),
					},
					o.status,
					remove_non_display_as_string(key)
				),
				_ => format!(
					r#"UPDATE data 
						SET 
							data = '{}' 
						WHERE 
							key = "{}";
					"#,
					value_s,
					remove_non_display_as_string(key)
				),
			};
		}
		Ok(self.store.execute(query).unwrap())
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
		self.store.exists(key)
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
		self.store.get_ser(key)
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
