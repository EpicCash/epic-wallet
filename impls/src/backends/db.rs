use epic_wallet_util::epic_core::ser::ProtocolVersion;
use serde::Serialize;
use sqlite::{self, Connection};
use std::fs;

use crate::serialization as ser;
use crate::serialization::Serializable;
use crate::Error;

use crate::keychain::Identifier;
use crate::store::{self, option_to_not_found, to_key, to_key_u64};
use uuid::Uuid;

use super::lmdb::{
	ACCOUNT_PATH_MAPPING_PREFIX, CONFIRMED_HEIGHT_PREFIX, DERIV_PREFIX, LAST_SCANNED_BLOCK,
	LAST_SCANNED_KEY, OUTPUT_HISTORY_ID_PREFIX, OUTPUT_HISTORY_PREFIX, OUTPUT_PREFIX,
	PRIVATE_TX_CONTEXT_PREFIX, TX_LOG_ENTRY_PREFIX, TX_LOG_ID_PREFIX, WALLET_INIT_STATUS,
	WALLET_INIT_STATUS_KEY,
};

static DB_DEFAULT_PATH: &str = "~/.epic/user/wallet_data/db/sqlite/";
static DB_FILENAME: &str = "epic.db";
static SQLITE_FILTER: &str = "AND key =";
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

	/// get an TxLogEntry by tx_id, tx_slate_id or parent_key_id
	pub fn get_txs(
		&self,
		key_tx_id: Option<Vec<u8>>,
		key_tx_slate_id: Option<Vec<u8>>,
		key_parent_key_id: Option<Vec<u8>>,
	) -> Vec<Serializable> {
		// TX_LOG_ENTRY_PREFIX: u8 = 't';
		let mut query = format!(
			"SELECT * FROM data WHERE prefix = '{}' ",
			TX_LOG_ENTRY_PREFIX
		);

		if key_tx_id.is_some() {
			query = format!(
				"{} {} {}",
				query,
				SQLITE_FILTER,
				String::from_utf8(key_tx_id.unwrap()).unwrap()
			);
		};
		if key_tx_slate_id.is_some() {
			query = format!(
				"{} {} {}",
				query,
				SQLITE_FILTER,
				String::from_utf8(key_tx_slate_id.unwrap()).unwrap()
			);
		};
		if key_parent_key_id.is_some() {
			query = format!(
				"{} {} {}",
				query,
				SQLITE_FILTER,
				String::from_utf8(key_parent_key_id.unwrap()).unwrap()
			);
		};

		self.db
			.prepare(query)
			.into_iter()
			.map(|row| {
				let row_data = row.read::<String>(2).unwrap(); // data is the 2 column
				ser::deserialize(&row_data).unwrap()
			})
			.collect()
	}

	/// get an TxLogEntry by tx_id, tx_slate_id or parent_key_id
	pub fn get_outputs(
		&self,
		key_tx_id: Option<Vec<u8>>,
		key_parent_key_id: Option<Vec<u8>>,
		show_full_history: bool,
	) -> Vec<Serializable> {
		let mut query = if show_full_history {
			// OUTPUT_HISTORY_PREFIX: u8 = 'h'
			format!(
				"SELECT * FROM data WHERE prefix IN ('{}', '{}') ",
				OUTPUT_PREFIX, OUTPUT_HISTORY_PREFIX,
			)
		} else {
			// OUTPUT_PREFIX: u8 = 'o'
			format!("SELECT * FROM data WHERE prefix = '{}' ", OUTPUT_PREFIX)
		};

		if key_tx_id.is_some() {
			query = format!(
				"{} {} {}",
				query,
				SQLITE_FILTER,
				String::from_utf8(key_tx_id.unwrap()).unwrap()
			);
		};
		if key_parent_key_id.is_some() {
			query = format!(
				"{} {} {}",
				query,
				SQLITE_FILTER,
				String::from_utf8(key_parent_key_id.unwrap()).unwrap()
			);
		};

		self.db
			.prepare(query)
			.into_iter()
			.map(|row| {
				let row_data = row.read::<String>(2).unwrap(); // data is the 2 column
				ser::deserialize(&row_data).unwrap()
			})
			.collect()
	}
}

/// Batch to write multiple Writeables to db in an atomic manner.
pub struct Batch<'a> {
	store: &'a Store,
}

impl<'a> Batch<'_> {
	/// Writes a single key/value pair to the db
	pub fn put(&self, key: &[u8], mut value: u8, prefix: char) -> Result<(), Error> {
		// serialize value to json
		let statement = format!(
			"INSERT INTO data VALUES ({}, {}, {});",
			String::from_utf8(key.to_vec()).unwrap(),
			value,
			prefix
		);
		return Ok(self.store.execute(statement).unwrap());
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
