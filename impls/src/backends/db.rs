use sqlite::{self, Connection};
use std::path::PathBuf;

use crate::serialization as ser;
use crate::serialization::Serializable;
use crate::Error;
use std::thread;
use std::time::Duration;

const SQLITE_MAX_RETRIES: u8 = 3;
static SQLITE_FILENAME: &str = "epic.db";

pub struct Store {
	db: Connection,
}

impl Store {
	pub fn new(db_path: PathBuf) -> Result<Store, sqlite::Error> {
		let db_path = db_path.join(SQLITE_FILENAME);
		let db: Connection = sqlite::open(db_path)?;
		Store::check_or_create(&db)?;
		Ok(Store { db })
	}

	pub fn check_or_create(db: &Connection) -> Result<(), sqlite::Error> {
		// SELECT * FROM data LIMIT 1; to check if table exists
		let creation = r#"CREATE TABLE IF NOT EXISTS data (
			id INTEGER PRIMARY KEY,
			key BLOB NOT NULL UNIQUE,
			prefix TEXT, 
			data TEXT NOT NULL,
			q_tx_id INTEGER,
			q_confirmed INTEGER,
			q_tx_status TEXT);
			CREATE INDEX IF NOT EXISTS prefix_index ON data (prefix);
			CREATE INDEX IF NOT EXISTS q_tx_id_index ON data (q_tx_id);
			CREATE INDEX IF NOT EXISTS q_confirmed_index ON data (q_confirmed);
			CREATE INDEX IF NOT EXISTS q_tx_status_index ON data (q_tx_status);

			PRAGMA journal_mode=WAL; -- better write-concurrency
			PRAGMA synchronous=NORMAL; -- fsync only in critical moments
			PRAGMA wal_checkpoint(TRUNCATE); -- free some space by truncating possibly massive WAL files from the last run.
		"#;
		db.execute(creation)
	}

	/// Gets a value from the db, provided its key
	pub fn get(&self, key: &[u8]) -> Option<Serializable> {
		let query = format!(r#"SELECT data FROM data WHERE key = "{:?}" LIMIT 1;"#, key);
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
			r#"
			SELECT 
				* 
			FROM 
				data 
			WHERE 
				key = "{:?}" 
			LIMIT 1;"#,
			key
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
		let mut retries = 0;

		loop {
			match self.db.execute(statement.to_string()) {
				Ok(()) => break,
				Err(e) => {
					// Code follows SQLite errors
					// Full documentation for error types can be found on https://www.sqlite.org/rescode.html
					// The error 5 is SQLITE_BUSY
					if e.code.unwrap() != 5 {
						return Err(e);
					}
					retries = retries + 1;

					if retries > SQLITE_MAX_RETRIES {
						return Err(e);
					}
					thread::sleep(Duration::from_millis(100));
				}
			}
		}

		Ok(())
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
						("{:?}", '{}', "{}", {}, {}, "{}");
				"#,
				key, value_s, prefix, t.id, t.confirmed, t.tx_type
			),
			Serializable::OutputData(o) => format!(
				r#"INSERT INTO data 
						(key, data, prefix, q_tx_id, q_tx_status) 
					VALUES 
						("{:?}", '{}', "{}", "{}", "{}")
				"#,
				key,
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
						("{:?}", '{}', "{}");
				"#,
				key, value_s, prefix
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
							key = "{:?}";
					"#,
					value_s, t.id, t.confirmed, t.tx_type, key
				),
				Serializable::OutputData(o) => format!(
					r#"UPDATE data 
						SET 
							data = '{}',
							q_tx_id = "{}",
							q_tx_status = "{}"
						WHERE 
							key = "{:?}";
					"#,
					value_s,
					match o.tx_log_entry {
						Some(entry) => entry.to_string(),
						None => "".to_string(),
					},
					o.status,
					key
				),
				_ => format!(
					r#"UPDATE data 
						SET 
							data = '{}' 
						WHERE 
							key = "{:?}";
					"#,
					value_s, key
				),
			};
		}
		Ok(self.store.execute(query).unwrap())
	}

	pub fn put_ser(&self, key: &[u8], value: Serializable) -> Result<(), Error> {
		self.put(key, value)
	}

	/// gets a value from the db, provided its key
	// pub fn get(&self, key: &[u8]) -> Option<Serializable> {
	// 	self.store.get(key)
	// }

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
		let statement = format!(r#"DELETE FROM data WHERE key = "{:?}""#, key);
		self.store.execute(statement)?;
		Ok(())
	}

	pub fn get_ser(&self, key: &[u8]) -> Option<Serializable> {
		self.store.get_ser(key)
	}
}

unsafe impl Sync for Store {}
unsafe impl Send for Store {}
