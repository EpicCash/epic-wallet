// Copyright 2022 The Epic Developers
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

//use crate::internal::updater::retrieve_txs;
//use crate::{OutputData, TxLogEntry};
// let result = api_owner.retrieve_txs(None, update_from_node, tx_id, tx_slate_id);
use crate::epic_core::global::ChainTypes;
use crate::epic_keychain::{Identifier, Keychain};
use crate::types::{NodeClient, OutputData, TxLogEntry, WalletBackend};
use epic_wallet_config as config;
use std::cmp::PartialEq;
use std::path::{Path, PathBuf};
use std::{fs, io, num};

/// Copy all files and subfoldes into a dst folder
#[warn(dead_code)]
fn copy_dir_all(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> io::Result<()> {
	fs::create_dir_all(&dst)?;
	for entry in fs::read_dir(src)? {
		let entry = entry?;
		let ty = entry.file_type()?;
		if ty.is_dir() {
			copy_dir_all(entry.path(), dst.as_ref().join(entry.file_name()))?;
		} else {
			fs::copy(entry.path(), dst.as_ref().join(entry.file_name()))?;
		}
	}
	Ok(())
}

/// Use to compare 2 vectors of transactions
fn compare_vectors<T: PartialEq>(vec_lmdb: &Vec<T>, vec_sqlite: &Vec<T>) -> bool {
	// Getting number of transaction from LMDB in vector
	let size_vec = vec_lmdb.len();

	// Getting number of transaction from SQLite in vector
	let size_aux = vec_sqlite.len();

	// If the number of transactions obtained is different we get a error
	if size_aux != size_vec {
		error!(
			"Error in obtaining transactions between banks, transactions obtained,\n
			LMDB: {}\n
			SQLite: {}\n",
			size_vec, size_aux
		)
	}

	// Checking 1-1 if transactions are equal using PartialEq
	let matching = vec_lmdb
		.iter()
		.zip(vec_sqlite)
		.filter(|&(vec_lmdb, vec_sqlite)| vec_lmdb == vec_sqlite)
		.count();

	// If the number of LMDB transactions is equal to the number of transactions belonging to SQLite, then it means that the vectors are equal
	size_vec == matching
}

/// This function will get from the wallet the information regarding the transactions based on the structs `TxLogEntry` and `OutputData`
/// CHAGE THIS AFTER SQLITE DONE
pub fn get_vectors_from_sqlite<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	num_transactions: u8,
) -> (Vec<TxLogEntry>, Vec<OutputData>)
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// save OutputData
	let mut outputs_to_compare: Vec<OutputData> = vec![];
	let mut outputs = wallet.iter();

	// save TxLogEntry
	let mut txs_to_compare: Vec<TxLogEntry> = vec![];
	let mut txs = wallet.tx_log_iter();

	// for each transaction
	for _ in 0..num_transactions {
		let out = outputs.next();
		match out {
			Some(value) => outputs_to_compare.push(value),
			None => (),
		}

		let tx = txs.next();
		match tx {
			Some(value) => txs_to_compare.push(value),
			None => (),
		}
	}

	return (txs_to_compare, outputs_to_compare);
}

/// This function will get from the wallet the information regarding the transactions based on the structs `TxLogEntry` and `OutputData`
pub fn get_vectors_from_lmdb<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	num_transactions: u8,
) -> (Vec<TxLogEntry>, Vec<OutputData>)
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// save OutputData
	let mut outputs_to_compare: Vec<OutputData> = vec![];
	let mut outputs = wallet.iter();
	for _ in 0..num_transactions {
		let out = outputs.next();
		match out {
			Some(value) => outputs_to_compare.push(value),
			None => break,
		}
	}

	// save TxLogEntry
	let mut txs_to_compare: Vec<TxLogEntry> = vec![];
	let mut txs = wallet.tx_log_iter();
	for _ in 0..num_transactions {
		let tx = txs.next();
		match tx {
			Some(value) => txs_to_compare.push(value),
			None => break,
		}
	}

	return (txs_to_compare, outputs_to_compare);
}

/// Verifies `n` transactions between LMDB and SQLite databases, considering `OutputData` and `TxLogEntry` structs
pub fn check_migration<'a, T: ?Sized, C, K>(wallet: &mut T) -> bool
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Are we going to consider a default value or not?
	let num_transactions: u8 = 15;

	// Get the transactions
	let (txs_lmdb, outputs_lmdb) = get_vectors_from_lmdb(wallet, num_transactions);
	let (txs_sql, outputs_sql) = get_vectors_from_sqlite(wallet, num_transactions);

	// Let's assume that the wallets are equal
	let mut check = true;

	// If txs fails
	check = check && compare_vectors(&txs_lmdb, &txs_sql);

	// Error if the TxLogEntry are different
	if !check {
		error!(
			"TxLogEntry type transactions are different between banks,
			LMDB: {:?}
			SQLite: {:?}",
			txs_lmdb, txs_sql
		)
	}

	// If output fails
	check = check && compare_vectors(&outputs_lmdb, &outputs_sql);

	// Error if the OutputData are different
	if !check {
		error!(
			"OutputData type transactions are different between banks,
			LMDB: {:?}
			SQLite: {:?}",
			outputs_lmdb, outputs_sql
		)
	}

	check
}

/// This function checks if the database migration has already been done from LMDB to SQLite
fn need_migration(chain_type: &ChainTypes) -> bool {
	let mut home_dir = config::get_epic_path(&chain_type).unwrap();
	home_dir.push("wallet_data"); //wallet_data by default
	home_dir.push("db");
	home_dir.push("sqlite"); // Need to check if we are going to use this path for the new wallet

	home_dir.exists() // Need to check if we are going to use a flag to check if the flock migration has already been done or not
}

/// get all keys_id from vector of OutputData
fn get_output_keys(vec_outputs: Vec<OutputData>) -> Vec<Identifier> {
	let mut keys: Vec<Identifier> = vec![];
	for output in vec_outputs {
		keys.push(output.key_id);
	}
	keys
}

/// get all keys_id from vector of TxLogEntry
fn get_txlog_keys(vec_txs: Vec<TxLogEntry>) -> Vec<u32> {
	let mut keys: Vec<u32> = vec![];
	for tx in vec_txs {
		keys.push(tx.id);
	}
	keys
}

/// This function migrates the database from LMDB to SQLite and executes the SQLite check at the end
pub fn make_migration<'a, T: ?Sized, C, K>(wallet: &mut T, chain_type: &ChainTypes) -> bool
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Checks if the migration has already been done previously
	if need_migration(chain_type) {
		return true;
	}

	// SQLite migration blocked, we still don't have SQLite finalized to perform the migration between databases
	todo!();

	// Checking if the migration was successful
	if check_migration(wallet) {
		info!("Success in the migration between banks!. Migration verification between banks completed successfully!")
	}
	true
}

/// this function will make a copy of wallet_data before the migration between LMDB and SQLite
pub fn backup_wallet_data(chain_type: ChainTypes, dst_wallet_data: PathBuf) {
	let mut home_dir = config::get_epic_path(&chain_type).unwrap();
	home_dir.push("wallet_data"); //wallet_data by default
	home_dir.push("db");

	// if we want a deafult backup folder just use the following code
	// let mut dst_wallet_data = config::get_epic_path(&chain_type).unwrap();
	// dst_wallet_data.push("wallet_data_LMDB_backup");

	let res = copy_dir_all(home_dir, dst_wallet_data);

	match res {
		Ok(()) => println!("Backup finished!"),
		Err(_) => println!("Backup don't work!"),
	}
}
