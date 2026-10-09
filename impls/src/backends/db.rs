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
use sqlite::{self, Connection, State};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

const SQLITE_MAX_RETRIES: u8 = 3;
static SQLITE_FILENAME: &str = "epic.db";

fn retry_sqlite<T, F>(mut operation: F) -> Result<T, sqlite::Error>
where
    F: FnMut() -> Result<T, sqlite::Error>,
{
    let mut retries = 0;
    loop {
        match operation() {
            Ok(value) => return Ok(value),
            Err(error) if error.code == Some(5) && retries < SQLITE_MAX_RETRIES => {
                retries += 1;
                thread::sleep(Duration::from_millis(100));
            }
            Err(error) => return Err(error),
        }
    }
}

fn encoded_key(key: &[u8]) -> String {
    format!("{:?}", key)
}

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
    pub fn get(&self, key: &[u8]) -> Result<Option<Serializable>, Error> {
        let key = encoded_key(key);
        let data = retry_sqlite(|| {
            let mut statement = self.db.prepare(
                r#"
			SELECT data
			FROM data
			WHERE key = ?1
			LIMIT 1;
			"#,
            )?;
            statement.bind((1, key.as_str()))?;
            match statement.next()? {
                State::Row => Ok(Some(statement.read::<String, _>("data")?)),
                State::Done => Ok(None),
            }
        })?;
        data.map(|data| ser::deserialize(&data).map_err(Error::from))
            .transpose()
    }

    /// Encapsulation for get function
    /// Gets a `Readable` value from the db, provided its key
    pub fn get_ser(&self, key: &[u8]) -> Result<Option<Serializable>, Error> {
        self.get(key)
    }

    /// Provided a 'from' as prefix, returns a vector of Serializable enums
    pub fn iter(&self, from: &[u8]) -> Result<Vec<Serializable>, Error> {
        let prefix = String::from_utf8(from.to_vec())
            .map_err(|error| Error::GenericError(error.to_string()))?;
        let rows = retry_sqlite(|| {
            let mut statement = self.db.prepare(
                r#"
			SELECT data
			FROM data
			WHERE prefix = ?1;
			"#,
            )?;
            statement.bind((1, prefix.as_str()))?;
            let mut rows = Vec::new();
            while let State::Row = statement.next()? {
                rows.push(statement.read::<String, _>("data")?);
            }
            Ok(rows)
        })?;
        rows.into_iter()
            .map(|data| ser::deserialize(&data).map_err(Error::from))
            .collect()
    }

    /// Builds a new batch to be used with this store
    pub fn batch(&self) -> Batch<'_> {
        Batch { store: self }
    }

    /// Executes a prepared SQLite statement.
    /// If the database is locked due to another writing process,
    /// The code will retry the same statement after 100 milliseconds
    fn execute_prepared<F>(&self, sql: &str, mut bind: F) -> Result<(), sqlite::Error>
    where
        F: FnMut(&mut sqlite::Statement<'_>) -> Result<(), sqlite::Error>,
    {
        retry_sqlite(|| {
            let mut statement = self.db.prepare(sql)?;
            bind(&mut statement)?;
            statement.next().map(|_| ())
        })
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
        let value_s = ser::serialize(&value)?;
        let key_s = encoded_key(key);
        let prefix = (*key
            .first()
            .ok_or_else(|| Error::GenericError("database key cannot be empty".to_owned()))?
            as char)
            .to_string();

        match &value {
            Serializable::TxLogEntry(tx) => {
                let tx_type = tx.tx_type.to_string();
                self.store.execute_prepared(
                    r#"INSERT INTO data
						(key, data, prefix, q_tx_id, q_confirmed, q_tx_status)
					VALUES (?1, ?2, ?3, ?4, ?5, ?6)
					ON CONFLICT(key) DO UPDATE SET
						data = excluded.data,
						q_tx_id = excluded.q_tx_id,
						q_confirmed = excluded.q_confirmed,
						q_tx_status = excluded.q_tx_status;"#,
                    |statement| {
                        statement.bind((1, key_s.as_str()))?;
                        statement.bind((2, value_s.as_str()))?;
                        statement.bind((3, prefix.as_str()))?;
                        statement.bind((4, tx.id as i64))?;
                        statement.bind((5, i64::from(tx.confirmed)))?;
                        statement.bind((6, tx_type.as_str()))
                    },
                )?;
            }
            Serializable::OutputData(output) => {
                let status = output.status.to_string();
                self.store.execute_prepared(
                    r#"INSERT INTO data
						(key, data, prefix, q_tx_id, q_tx_status)
					VALUES (?1, ?2, ?3, ?4, ?5)
					ON CONFLICT(key) DO UPDATE SET
						data = excluded.data,
						q_tx_id = excluded.q_tx_id,
						q_tx_status = excluded.q_tx_status;"#,
                    |statement| {
                        statement.bind((1, key_s.as_str()))?;
                        statement.bind((2, value_s.as_str()))?;
                        statement.bind((3, prefix.as_str()))?;
                        match output.tx_log_entry {
                            Some(entry) => statement.bind((4, entry as i64))?,
                            None => statement.bind((4, ""))?,
                        }
                        statement.bind((5, status.as_str()))
                    },
                )?;
            }
            _ => {
                self.store.execute_prepared(
                    r#"INSERT INTO data (key, data, prefix)
					VALUES (?1, ?2, ?3)
					ON CONFLICT(key) DO UPDATE SET data = excluded.data;"#,
                    |statement| {
                        statement.bind((1, key_s.as_str()))?;
                        statement.bind((2, value_s.as_str()))?;
                        statement.bind((3, prefix.as_str()))
                    },
                )?;
            }
        }

        Ok(())
    }

    /// Writes a single value to the db, given a key and a Serializable enum
    /// Encapsulation for the store put function
    pub fn put_ser(&self, key: &[u8], value: Serializable) -> Result<(), Error> {
        self.put(key, value)
    }

    /// Provided a 'from' as prefix, returns a vector of Serializable enums
    /// Encapsulation for the store iter function
    pub fn iter(&self, from: &[u8]) -> Result<Vec<Serializable>, Error> {
        self.store.iter(from)
    }

    /// Deletes a key from the db
    pub fn delete(&self, key: &[u8]) -> Result<(), Error> {
        let key = encoded_key(key);
        self.store
            .execute_prepared("DELETE FROM data WHERE key = ?1;", |statement| {
                statement.bind((1, key.as_str()))
            })?;
        Ok(())
    }

    /// Returns a single value of the database
    /// Encapsulation for the store get_ser function
    pub fn get_ser(&self, key: &[u8]) -> Result<Option<Serializable>, Error> {
        self.store.get_ser(key)
    }
}

unsafe impl Sync for Store {}
unsafe impl Send for Store {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keychain::{ExtKeychain, Keychain, SwitchCommitmentType};
    use crate::util::secp::key::PublicKey;
    use epic_wallet_libwallet::slate::ParticipantMessages;
    use epic_wallet_libwallet::{
        AcctPathMapping, ParticipantMessageData, TxLogEntry, TxLogEntryType,
    };
    use std::fs;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn temp_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("epic_db_test_{}_{}", nanos, n));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn acct(label: &str) -> Serializable {
        Serializable::AcctPathMapping(AcctPathMapping {
            label: label.to_owned(),
            path: ExtKeychain::derive_key_id(2, 0, 0, 0, 0),
        })
    }

    #[test]
    fn bound_values_treat_sql_metacharacters_as_data() {
        let dir = temp_dir();
        let store = Store::new(dir.clone()).unwrap();
        store.batch().put(b"survivor", acct("safe")).unwrap();

        let payload = "x', 'a'); DELETE FROM data; --";
        let keychain = ExtKeychain::from_random_seed(true).unwrap();
        let secret = keychain
            .derive_key(
                0,
                &ExtKeychain::root_key_id(),
                &SwitchCommitmentType::Regular,
            )
            .unwrap();
        let mut tx = TxLogEntry::new(ExtKeychain::root_key_id(), TxLogEntryType::TxReceived, 1);
        tx.messages = Some(ParticipantMessages {
            messages: vec![ParticipantMessageData {
                id: 1,
                public_key: PublicKey::from_secret_key(keychain.secp(), &secret).unwrap(),
                message: Some(payload.to_owned()),
                message_sig: None,
            }],
        });
        store
            .batch()
            .put(b"attack", Serializable::TxLogEntry(tx))
            .unwrap();

        let survivor = format!("{:?}", store.get(b"survivor"));
        let attacker = format!("{:?}", store.get(b"attack"));
        assert!(survivor.contains("safe"));
        assert!(attacker.contains(payload));
        drop(store);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn concurrent_first_puts_are_atomic() {
        const WRITERS: usize = 2;

        let dir = temp_dir();
        let stores: Vec<_> = (0..WRITERS)
            .map(|_| Store::new(dir.clone()).unwrap())
            .collect();
        let barrier = Arc::new(Barrier::new(WRITERS));
        let mut writers = Vec::new();

        for (writer, store) in stores.into_iter().enumerate() {
            let barrier = barrier.clone();
            writers.push(std::thread::spawn(move || {
                barrier.wait();
                store
                    .batch()
                    .put(b"race", acct(&format!("writer_{writer}")))
                    .unwrap();
            }));
        }

        for writer in writers {
            writer.join().unwrap();
        }

        let db = sqlite::open(dir.join(SQLITE_FILENAME)).unwrap();
        let count = db
            .prepare("SELECT COUNT(*) AS count FROM data WHERE prefix = 'r';")
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
            .unwrap()
            .read::<i64, _>("count");
        assert_eq!(count, 1);
        drop(db);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn legacy_text_key_encoding_is_preserved() {
        let dir = temp_dir();
        let store = Store::new(dir.clone()).unwrap();
        let key = b"acct1";
        store.batch().put(key, acct("legacy compatible")).unwrap();

        let mut statement = store
            .db
            .prepare("SELECT typeof(key), key FROM data LIMIT 1;")
            .unwrap();
        assert_eq!(statement.next().unwrap(), sqlite::State::Row);
        assert_eq!(statement.read::<String, _>(0).unwrap(), "text");
        assert_eq!(
            statement.read::<String, _>(1).unwrap(),
            format!("{:?}", key)
        );
        drop(statement);
        drop(store);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn corrupt_rows_report_errors_instead_of_missing_values() {
        let dir = temp_dir();
        let store = Store::new(dir.clone()).unwrap();
        let key = b"broken";
        let query = format!(
            "INSERT INTO data (key, data, prefix) VALUES (\"{:?}\", 'not-json', 'b');",
            key
        );
        store.db.execute(query).unwrap();

        let get_result = catch_unwind(AssertUnwindSafe(|| format!("{:?}", store.get(key))));
        assert!(get_result.is_ok(), "database get panicked");
        assert!(get_result.unwrap().starts_with("Err("));

        let iter_result = catch_unwind(AssertUnwindSafe(|| format!("{:?}", store.iter(b"b"))));
        assert!(iter_result.is_ok(), "database iteration panicked");
        assert!(iter_result.unwrap().starts_with("Err("));
        drop(store);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn generic_upsert_preserves_query_metadata() {
        let dir = temp_dir();
        let store = Store::new(dir.clone()).unwrap();
        let key = b"acct1";
        let mut statement = store
            .db
            .prepare(
                "INSERT INTO data \
				 (key, data, prefix, q_tx_id, q_confirmed, q_tx_status) \
				 VALUES (?1, ?2, 'a', 42, 1, 'sent');",
            )
            .unwrap();
        statement.bind((1, encoded_key(key).as_str())).unwrap();
        statement
            .bind((2, ser::serialize(&acct("old")).unwrap().as_str()))
            .unwrap();
        statement.next().unwrap();
        drop(statement);

        store.batch().put(key, acct("new")).unwrap();
        let mut statement = store
            .db
            .prepare("SELECT q_tx_id, q_confirmed, q_tx_status FROM data WHERE key = ?1;")
            .unwrap();
        statement.bind((1, encoded_key(key).as_str())).unwrap();
        let row = statement.into_iter().next().unwrap().unwrap();
        assert_eq!(row.read::<i64, _>("q_tx_id"), 42);
        assert_eq!(row.read::<i64, _>("q_confirmed"), 1);
        assert_eq!(row.read::<&str, _>("q_tx_status"), "sent");
        drop(store);
        fs::remove_dir_all(dir).unwrap();
    }
}
