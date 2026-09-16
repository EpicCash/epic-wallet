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
use sqlite::{self, Connection, State, Value};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

const SQLITE_MAX_RETRIES: u8 = 3;
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
        Store::migrate_legacy_keys(&db)?;
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

    fn migrate_legacy_keys(db: &Connection) -> Result<(), sqlite::Error> {
        let mut rows_to_fix: Vec<(i64, Vec<u8>)> = Vec::new();
        let statement = db.prepare("SELECT id, key FROM data")?;
        for row in statement.into_iter() {
            let row = row?;
            if let Ok(key_str) = row.try_read::<&str, _>("key") {
                if key_str.starts_with('[') && key_str.ends_with(']') {
                    if let Ok(bytes) = serde_json::from_str::<Vec<u8>>(key_str) {
                        rows_to_fix.push((row.try_read::<i64, _>("id")?, bytes));
                    }
                }
            }
        }

        for (id, bytes) in rows_to_fix {
            let mut update = db.prepare("UPDATE data SET key = ?1 WHERE id = ?2")?;
            update.bind((1, Value::Binary(bytes)))?;
            update.bind((2, id))?;
            update.next()?;
        }

        Ok(())
    }

    /// Returns a single value of the database
    /// This returns a Serializable enum
    pub fn get(&self, key: &[u8]) -> Option<Serializable> {
        let mut statement = self
            .db
            .prepare(
                r#"
			SELECT
				data
			FROM
				data
			WHERE
				key = ?1
			LIMIT 1;
			"#,
            )
            .ok()?;
        statement.bind((1, key)).ok()?;
        match statement.next().ok()? {
            State::Row => {
                let data = statement.read::<String, _>("data").ok()?;
                match ser::deserialize(&data) {
                    Ok(deser) => Some(deser),
                    Err(e) => {
                        error!(
                            "Failed to deserialize value for key {}: {:?}",
                            String::from_utf8_lossy(key),
                            e
                        );
                        None
                    }
                }
            }
            State::Done => None,
        }
    }

    /// Encapsulation for get function
    /// Gets a `Readable` value from the db, provided its key
    pub fn get_ser(&self, key: &[u8]) -> Option<Serializable> {
        self.get(key)
    }

    /// Provided a 'from' as prefix, returns a vector of Serializable enums
    pub fn iter(&self, from: &[u8]) -> Vec<Serializable> {
        let prefix = String::from_utf8(from.to_vec()).unwrap();
        let mut results = Vec::new();
        let mut statement = match self.db.prepare(
            r#"
			SELECT
				data
			FROM
				data
			WHERE
				prefix = ?1;
			"#,
        ) {
            Ok(statement) => statement,
            Err(e) => {
                error!("Failed to prepare iter statement: {:?}", e);
                return results;
            }
        };
        if let Err(e) = statement.bind((1, prefix.as_str())) {
            error!("Failed to bind prefix {}: {:?}", prefix, e);
            return results;
        }
        while let Ok(State::Row) = statement.next() {
            let data = match statement.read::<String, _>("data") {
                Ok(data) => data,
                Err(e) => {
                    warn!("Failed to read row for prefix {}: {:?}", prefix, e);
                    continue;
                }
            };
            match ser::deserialize(&data) {
                Ok(deser) => results.push(deser),
                Err(e) => warn!("Failed to deserialize row for prefix {}: {:?}", prefix, e),
            }
        }
        results
    }

    /// Builds a new batch to be used with this store
    pub fn batch(&self) -> Batch<'_> {
        Batch { store: self }
    }

    /// Executes a single SQLite statement, binding parameters through `bind`
    /// If the database is locked due to another writing process,
    /// The code will retry the same statement after 100 milliseconds
    fn execute_prepared<F>(&self, sql: &str, mut bind: F) -> Result<(), sqlite::Error>
    where
        F: FnMut(&mut sqlite::Statement<'_>) -> Result<(), sqlite::Error>,
    {
        let mut retries = 0;
        loop {
            let result = self.db.prepare(sql).and_then(|mut statement| {
                bind(&mut statement)?;
                statement.next().map(|_| ())
            });
            match result {
                Ok(()) => break,
                Err(e) => {
                    // e.code follows SQLite error types
                    // Full documentation for error types can be found on https://www.sqlite.org/rescode.html
                    // Error 5 is SQLITE_BUSY
                    if e.code != Some(5) {
                        return Err(e);
                    }
                    retries += 1;

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
        let prefix = (key[0] as char).to_string();

        match &value {
            Serializable::TxLogEntry(t) => {
                let tx_type = t.tx_type.to_string();
                self.store.execute_prepared(
                    r#"INSERT INTO data
						(key, data, prefix, q_tx_id, q_confirmed, q_tx_status)
					VALUES
						(?1, ?2, ?3, ?4, ?5, ?6)
					ON CONFLICT(key) DO UPDATE SET
						data = excluded.data,
						prefix = excluded.prefix,
						q_tx_id = excluded.q_tx_id,
						q_confirmed = excluded.q_confirmed,
						q_tx_status = excluded.q_tx_status;
				"#,
                    |statement| {
                        statement.bind((1, key))?;
                        statement.bind((2, value_s.as_str()))?;
                        statement.bind((3, prefix.as_str()))?;
                        statement.bind((4, t.id as i64))?;
                        statement.bind((5, i64::from(t.confirmed)))?;
                        statement.bind((6, tx_type.as_str()))?;
                        Ok(())
                    },
                )?;
            }
            Serializable::OutputData(o) => {
                let tx_status = o.status.to_string();
                self.store.execute_prepared(
                    r#"INSERT INTO data
						(key, data, prefix, q_tx_id, q_tx_status)
					VALUES
						(?1, ?2, ?3, ?4, ?5)
					ON CONFLICT(key) DO UPDATE SET
						data = excluded.data,
						prefix = excluded.prefix,
						q_tx_id = excluded.q_tx_id,
						q_tx_status = excluded.q_tx_status;
				"#,
                    |statement| {
                        statement.bind((1, key))?;
                        statement.bind((2, value_s.as_str()))?;
                        statement.bind((3, prefix.as_str()))?;
                        match o.tx_log_entry {
                            Some(entry) => statement.bind((4, entry as i64))?,
                            None => statement.bind((4, Value::Null))?,
                        }
                        statement.bind((5, tx_status.as_str()))?;
                        Ok(())
                    },
                )?;
            }
            _ => {
                self.store.execute_prepared(
                    r#"INSERT INTO data
						(key, data, prefix)
					VALUES
						(?1, ?2, ?3)
					ON CONFLICT(key) DO UPDATE SET
						data = excluded.data,
						prefix = excluded.prefix;
				"#,
                    |statement| {
                        statement.bind((1, key))?;
                        statement.bind((2, value_s.as_str()))?;
                        statement.bind((3, prefix.as_str()))?;
                        Ok(())
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
    pub fn iter(&self, from: &[u8]) -> Vec<Serializable> {
        self.store.iter(from)
    }

    /// Deletes a key from the db
    pub fn delete(&self, key: &[u8]) -> Result<(), Error> {
        self.store.execute_prepared(
            r#"
		DELETE
		FROM
			data
		WHERE
			key = ?1
		"#,
            |statement| {
                statement.bind((1, key))?;
                Ok(())
            },
        )?;
        Ok(())
    }

    /// Returns a single value of the database
    /// Encapsulation for the store get_ser function
    pub fn get_ser(&self, key: &[u8]) -> Option<Serializable> {
        self.store.get_ser(key)
    }
}

unsafe impl Sync for Store {}
unsafe impl Send for Store {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keychain::{ExtKeychain, Keychain};
    use epic_wallet_libwallet::AcctPathMapping;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};
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
            label: label.to_string(),
            path: ExtKeychain::derive_key_id(2, 0, 0, 0, 0),
        })
    }

    fn label_of(value: Serializable) -> String {
        match value {
            Serializable::AcctPathMapping(a) => a.label,
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn put_then_get_roundtrip() {
        let dir = temp_dir();
        let store = Store::new(dir.clone()).unwrap();
        store.batch().put(b"acct1", acct("primary")).unwrap();
        assert_eq!(label_of(store.get(b"acct1").unwrap()), "primary");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn put_upserts_instead_of_duplicating() {
        let dir = temp_dir();
        let store = Store::new(dir.clone()).unwrap();
        store.batch().put(b"acct1", acct("first")).unwrap();
        store.batch().put(b"acct1", acct("second")).unwrap();
        assert_eq!(label_of(store.get(b"acct1").unwrap()), "second");
        assert_eq!(store.iter(b"a").len(), 1);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn values_containing_a_single_quote_roundtrip() {
        let dir = temp_dir();
        let store = Store::new(dir.clone()).unwrap();
        store.batch().put(b"acct1", acct("Dan's wallet")).unwrap();
        assert_eq!(label_of(store.get(b"acct1").unwrap()), "Dan's wallet");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn delete_removes_only_the_named_key() {
        let dir = temp_dir();
        let store = Store::new(dir.clone()).unwrap();
        store.batch().put(b"acct1", acct("one")).unwrap();
        store.batch().put(b"acct2", acct("two")).unwrap();
        store.batch().delete(b"acct1").unwrap();
        assert!(store.get(b"acct1").is_none());
        assert_eq!(label_of(store.get(b"acct2").unwrap()), "two");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn legacy_debug_formatted_keys_are_migrated() {
        let dir = temp_dir();
        let key: &[u8] = b"acct1";
        let data = ser::serialize(acct("legacy")).unwrap();
        {
            let db = sqlite::open(dir.join(SQLITE_FILENAME)).unwrap();
            Store::check_or_create(&db).unwrap();
            let mut statement = db
                .prepare("INSERT INTO data (key, data, prefix) VALUES (?1, ?2, ?3);")
                .unwrap();
            statement
                .bind((1, format!("{:?}", key).as_str()))
                .unwrap();
            statement.bind((2, data.as_str())).unwrap();
            statement.bind((3, "a")).unwrap();
            statement.next().unwrap();
        }

        let store = Store::new(dir.clone()).unwrap();
        assert_eq!(label_of(store.get(key).unwrap()), "legacy");
        fs::remove_dir_all(dir).unwrap();
    }
}
