use epic_wallet_util::epic_core::ser::ProtocolVersion;
use serde::Serialize;
use sqlite::{self, Connection};
use std::fs;

use crate::serialization as ser;
use crate::serialization::Serializable;
use crate::Error;

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
static ID_FILTER: &str = "AND tx_id =";
static SLATE_ID_FILTER: &str = "AND slate_id =";
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
			.prepare("SELECT data WHERE key = ? LIMIT 1")
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
			.prepare("SELECT data WHERE key = ? LIMIT 1")
			.unwrap()
			.bind(1, key)
			.unwrap();
		return Ok(statement.next().is_ok());
	}

	/// Produces an iterator of (key, value) pairs, where values are `Readable` types
	/// moving forward from the provided key.
	pub fn iter(&self, from: &[u8]) -> Vec<Serializable> {
		let query = "SELECT data;";
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

	/// get an TxLogEntry by parent_key_id (key column) and tx_id, tx_slate_id
	/// If no input is passed, returns all TxLogEntry transactions.
	/// If outstanding_only = true then return Received/Sent not confirmed transactions.
	pub fn get_txs(
		&self,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
		parent_key_id: Option<Vec<u8>>,
		outstanding_only: bool,
	) -> Vec<Serializable> {
		// initial query (get all TxLogEntry)
		let mut query = format!("SELECT data WHERE prefix = '{}' ", TX_LOG_ENTRY_PREFIX);

		// filter by parent_key_id (key)
		query = match parent_key_id {
			Some(key) => format!(
				"{} {} '{}'",
				query,
				SQLITE_FILTER,
				String::from_utf8(key).unwrap()
			),
			None => query,
		};

		// filter by tx_id
		query = match tx_id {
			Some(id) => format!("{} {} '{}'", query, ID_FILTER, id),
			None => query,
		};

		// filter by tx_slate_id
		query = match tx_slate_id {
			Some(slate_id) => format!("{} {} '{}'", query, SLATE_ID_FILTER, slate_id),
			None => query,
		};

		// get not confirmed AND Received,Sent transactions
		if outstanding_only {
			query = format!(
				"{} {} {}",
				query, "AND confirmed is null", "AND status IN ('TxReceived','TxSent')"
			)
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

	/// get all OutputData by parent_key_id and tx_id, tx_slate_id
	/// If no input is passed, returns all OutputData transactions.
	/// If show_full_history = true then it will return all usable transactions and those already used by other transactions.
	/// If show_spent = true then it will return all transactions that have already spent.
	pub fn get_outputs(
		&self,
		tx_id: Option<u32>,
		parent_key_id: Option<Vec<u8>>,
		show_full_history: bool,
		show_spent: bool,
	) -> Vec<Serializable> {
		// initial query, get all OutputData
		let mut query = if show_full_history {
			format!(
				"SELECT data WHERE prefix IN ('{}', '{}') ",
				OUTPUT_PREFIX, OUTPUT_HISTORY_PREFIX,
			)
		} else {
			format!("SELECT data WHERE prefix = '{}' ", OUTPUT_PREFIX)
		};

		// get transaction key column
		query = match parent_key_id {
			Some(key) => format!(
				"{} {} '{}'",
				query,
				SQLITE_FILTER,
				String::from_utf8(key).unwrap()
			),
			None => query,
		};

		// get transaction with tx_id
		query = match tx_id {
			Some(id) => format!("{} {} '{}'", query, ID_FILTER, id),
			None => query,
		};

		// get not spent transactions
		if !show_spent {
			query = format!("{} {}", query, "AND status != 'Spent'")
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

	/// Return a larger set of which the set of eligible transactions is in here.
	/// This function makes it easy to get the eligible transactions to create a new transaction.
	/// Some filters are missing, like (!OutputData.is_coinbase) and (OutputData.num_confirmations(current_height) >= minimum_confirmations)
	/// that is, what it returns is not necessarily eligible. But to be eligible it needs to be in the return of that function.
	pub fn get_outputs_eligible(&self) -> Vec<Serializable> {
		let mut query = format!(
			"SELECT data WHERE prefix = '{}' status IN ('Unspent', 'Unconfirmed')",
			OUTPUT_PREFIX
		);

		self.db
			.prepare(query)
			.into_iter()
			.map(|row| {
				let row_data = row.read::<String>(2).unwrap(); // data is the 2 column
				ser::deserialize(&row_data).unwrap()
			})
			.collect()
	}

	/// get a Context
	pub fn get_context(&self, ctx_key: Vec<u8>) -> Vec<Serializable> {
		let mut query = format!(
			"SELECT data WHERE prefix = '{}' ",
			PRIVATE_TX_CONTEXT_PREFIX
		);

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
