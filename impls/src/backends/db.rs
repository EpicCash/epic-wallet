// Copyright 2023 The Epic Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The main interface for SQLite
//! Has the main operations to handle the SQLite database
//! This was built to replace LMDB

use crate::serialization as ser;
use crate::serialization::Serializable;
use crate::Error;
use epic_wallet_libwallet::{OutputStatus, TxLogEntryType};
use epic_wallet_util::epic_keychain::Identifier;
use sqlite::{self, Connection};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;
use uuid::Uuid;

const SQLITE_MAX_RETRIES: u8 = 3;
use super::lmdb::{
	OUTPUT_HISTORY_PREFIX, OUTPUT_PREFIX, PRIVATE_TX_CONTEXT_PREFIX, TX_LOG_ENTRY_PREFIX,
};

static SQLITE_FILENAME: &str = "epic.db";

/// Basic struct holding the SQLite database connection
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

	/// Handle the creation of the database
	/// New resource create use the 'IF NOT EXISTS' to avoid recreation
	pub fn check_or_create(db: &Connection) -> Result<(), sqlite::Error> {
		let creation = r#"
		-- Create the database table
		CREATE TABLE IF NOT EXISTS data (
			id INTEGER PRIMARY KEY,
			key BLOB NOT NULL UNIQUE,
			prefix TEXT,
			data TEXT NOT NULL,
			q_tx_id INTEGER,
			q_confirmed INTEGER,
			q_tx_status TEXT);

		-- Create indexes for queriable columns
		CREATE INDEX IF NOT EXISTS prefix_index ON data (prefix);
		CREATE INDEX IF NOT EXISTS q_tx_id_index ON data (q_tx_id);
		CREATE INDEX IF NOT EXISTS q_confirmed_index ON data (q_confirmed);
		CREATE INDEX IF NOT EXISTS q_tx_status_index ON data (q_tx_status);

		-- Configure SQLite WAL level
		-- This is optimized for multithread usage
		PRAGMA journal_mode=WAL; -- better write-concurrency
		PRAGMA synchronous=NORMAL; -- fsync only in critical moments
		PRAGMA wal_checkpoint(TRUNCATE); -- free some space by truncating possibly massive WAL files from the last run.
		"#;
		db.execute(creation)
	}

	/// Returns a single value of the database
	/// This returns a Serializable enum
	pub fn get(&self, key: &[u8]) -> Option<Serializable> {
		let query = format!(
			r#"
			SELECT
				data
			FROM
				data
			WHERE
				key = "{:?}"
			LIMIT 1;
			"#,
			key
		);
		match self.db.prepare(query).unwrap().into_iter().next() {
			Some(s) => {
				let data = s.unwrap().read::<&str, _>("data").to_string();
				Some(ser::deserialize(&data).unwrap())
			}
			None => None,
		}
	}

	/// Encapsulation for get function
	/// Gets a `Readable` value from the db, provided its key
	pub fn get_ser(&self, key: &[u8]) -> Option<Serializable> {
		self.get(key)
	}

	/// Check if a key exists on the database
	pub fn exists(&self, key: &[u8]) -> Result<bool, Error> {
		let query = format!(
			r#"
			SELECT
				*
			FROM
				data
			WHERE
				key = "{:?}"
			LIMIT 1;
			"#,
			key
		);
		let mut statement = self.db.prepare(query).unwrap().into_iter();
		Ok(statement.next().is_some())
	}

	/// Provided a 'from' as prefix, returns a vector of Serializable enums
	pub fn iter(&self, from: &[u8]) -> Vec<Serializable> {
		let query = format!(
			r#"
			SELECT
				data
			FROM
				data
			WHERE
				prefix = "{}";
			"#,
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

	/// Builds a new batch to be used with this store
	pub fn batch(&self) -> Batch {
		Batch { store: self }
	}

	/// get an TxLogEntry by parent_key_id (key column) and tx_id, tx_slate_id
	/// If no input is passed, returns all TxLogEntry transactions.
	/// If outstanding_only = true then return Received/Sent not confirmed transactions.
	pub fn get_txs(
		&self,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
		parent_key_id: Option<&Identifier>,
		outstanding_only: bool,
	) -> Vec<Serializable> {
		// initial query (get all TxLogEntry)
		let mut query = format!(
			"SELECT * FROM data WHERE prefix = '{}'",
			TX_LOG_ENTRY_PREFIX as char
		);

		// filter by parent_key_id (key)
		query = match parent_key_id {
			Some(key) => format!(
				"{} AND json_extract(data, '$.parent_key_id') = {}",
				query,
				serde_json::to_string(key).unwrap()
			),
			None => query,
		};

		// filter by tx_id
		query = match tx_id {
			Some(id) => format!("{} AND q_tx_id = '{}'", query, id),
			None => query,
		};

		// filter by tx_slate_id
		query = match tx_slate_id {
			Some(slate_id) => format!(
				"{} AND json_extract(data, '$.tx_slate_id') = '{}'",
				query, slate_id
			),
			None => query,
		};

		// get not confirmed AND Received,Sent transactions
		if outstanding_only {
			query = format!(
				"{} AND q_confirmed = '0' AND q_tx_status IN ('{}','{}')",
				query,
				TxLogEntryType::TxReceived,
				TxLogEntryType::TxSent,
			)
		};

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

	/// get all OutputData by parent_key_id and tx_id, tx_slate_id
	/// If no input is passed, returns all OutputData transactions.
	/// If show_full_history = true then it will return all usable transactions and those already used by other transactions.
	/// If show_spent = true then it will return all transactions that have already spent.
	pub fn get_outputs(
		&self,
		tx_id: Option<u32>,
		parent_key_id: Option<&Identifier>,
		show_full_history: bool,
		show_spent: bool,
	) -> Vec<Serializable> {
		// initial query, get all OutputData
		let mut query = if show_full_history {
			format!(
				"SELECT data FROM data WHERE prefix IN ('{}', '{}') ",
				OUTPUT_PREFIX as char, OUTPUT_HISTORY_PREFIX as char,
			)
		} else {
			format!(
				"SELECT data FROM data WHERE prefix = '{}' ",
				OUTPUT_PREFIX as char
			)
		};

		// get transaction key column
		query = match parent_key_id {
			Some(key) => format!(
				"{} AND json_extract(data, '$.root_key_id')= {}",
				query,
				serde_json::to_string(key).unwrap()
			),
			None => query,
		};

		// get transaction with tx_id
		query = match tx_id {
			Some(id) => format!("{} AND q_tx_id = '{}'", query, id),
			None => query,
		};

		// get not spent transactions
		if !show_spent {
			query = format!("{} AND q_tx_status = != '{}'", query, OutputStatus::Spent)
		};

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

	/// Return a larger set of which the set of eligible transactions is in here.
	/// This function makes it easy to get the eligible transactions to create a new transaction.
	/// Some filters are missing, like (!OutputData.is_coinbase) and (OutputData.num_confirmations(current_height) >= minimum_confirmations)
	/// that is, what it returns is not necessarily eligible. But to be eligible it needs to be in the return of that function.
	pub fn eligible_outputs_preset(&self, key: Option<&Identifier>) -> Vec<Serializable> {
		let query = format!(
			"SELECT data FROM data WHERE prefix = '{}' AND q_tx_status IN ('{}', '{}') AND json_extract(data, '$.root_key_id') = '{}'",
			OUTPUT_PREFIX as char,
			OutputStatus::Unspent,
			OutputStatus::Unconfirmed,
			serde_json::to_string(&key).unwrap()
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

	/// Executes an SQLite statement
	/// If the database is locked due to another writing process,
	/// The code will retry the same statement after 100 milliseconds
	pub fn execute(&self, statement: String) -> Result<(), sqlite::Error> {
		let mut retries = 0;
		loop {
			match self.db.execute(statement.to_string()) {
				Ok(()) => break,
				Err(e) => {
					// e.code follows SQLite error types
					// Full documentation for error types can be found on https://www.sqlite.org/rescode.html
					// Error 5 is SQLITE_BUSY
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

/// Batch to write multiple Writeables to db in an atomic manner
pub struct Batch<'a> {
	store: &'a Store,
}

impl<'a> Batch<'_> {
	/// Writes a single value to the db, given a key and a Serializable enum
	/// Specialized queries are used for TxLogEntry and OutputData to make best use of queriable columns
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

	/// Writes a single value to the db, given a key and a Serializable enum
	/// Encapsulation for the store put function
	pub fn put_ser(&self, key: &[u8], value: Serializable) -> Result<(), Error> {
		self.put(key, value)
	}

	/// Check if a key exists on the database
	/// Encapsulation for the store exists function
	pub fn exists(&self, key: &[u8]) -> Result<bool, Error> {
		self.store.exists(key)
	}

	/// Provided a 'from' as prefix, returns a vector of Serializable enums
	/// Encapsulation for the store iter function
	pub fn iter(&self, from: &[u8]) -> Vec<Serializable> {
		self.store.iter(from)
	}

	/// Deletes a key from the db
	pub fn delete(&self, key: &[u8]) -> Result<(), Error> {
		let statement = format!(
			r#"
		DELETE
		FROM
			data
		WHERE
			key = "{:?}"
		"#,
			key
		);
		self.store.execute(statement)?;
		Ok(())
	}

	/// Returns a single value of the database
	/// Encapsulation for the store get_ser function
	pub fn get_ser(&self, key: &[u8]) -> Option<Serializable> {
		self.store.get_ser(key)
	}
	pub fn get_txs(
		&self,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
		parent_key_id: Option<&Identifier>,
		outstanding_only: bool,
	) -> Vec<Serializable> {
		self.store
			.get_txs(tx_id, tx_slate_id, parent_key_id, outstanding_only)
	}

	pub fn get_outputs(
		&self,
		tx_id: Option<u32>,
		parent_key_id: Option<&Identifier>,
		show_full_history: bool,
		show_spent: bool,
	) -> Vec<Serializable> {
		self.store
			.get_outputs(tx_id, parent_key_id, show_full_history, show_spent)
	}

	pub fn eligible_outputs_preset(&self, key: Option<&Identifier>) -> Vec<Serializable> {
		self.store.eligible_outputs_preset(key)
	}
}

unsafe impl Sync for Store {}
unsafe impl Send for Store {}
