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

use crate::epic_core::global::ChainTypes;
use crate::epic_keychain::{Identifier, Keychain};
use crate::types::{OutputData, TxLogEntry, WalletBackend};
//use crate::{address, IssueInvoiceTxArgs, NodeClient, WalletInst, WalletLCProvider};
use crate::NodeClient;
use epic_wallet_config as config;
//use epic_wallet_util::epic_util::{secp::key::SecretKey, to_hex, Mutex, ZeroingString};
use rand::Rng;
use std::cmp::PartialEq;
use std::path::{Path, PathBuf};
//use std::sync::Arc;
use std::{fs, io};

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
			"Error in obtaining transactions between databases, transactions obtained,\n
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
	num_transactions: u64,
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
	num_transactions: u64,
	check_random: bool,
) -> (Vec<TxLogEntry>, Vec<OutputData>)
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// save OutputData
	let mut outputs_to_compare: Vec<OutputData> = vec![];
	let mut outputs: Box<dyn Iterator<Item = OutputData>> = wallet.iter();

	// save TxLogEntry
	let mut txs_to_compare: Vec<TxLogEntry> = vec![];
	let mut txs: Box<dyn Iterator<Item = TxLogEntry>> = wallet.tx_log_iter();

	if check_random {
		let (low, high, step, num_elements) = generate_lim_rand(num_transactions, 10);

		let vec_ids = generate_rand_integer(low, high, step, num_elements);

		for k in 0..num_elements {
			let out = outputs.next();
			let tx = txs.next();

			if vec_ids.contains(&(k as u64)) {
				match out {
					Some(value) => outputs_to_compare.push(value),
					None => (),
				};

				match tx {
					Some(value) => txs_to_compare.push(value),
					None => (),
				};
			}
		}
	} else {
		for _ in 0..num_transactions {
			let out = outputs.next();
			let tx = txs.next();

			match out {
				Some(value) => outputs_to_compare.push(value),
				None => (),
			};

			match tx {
				Some(value) => txs_to_compare.push(value),
				None => (),
			};
		}
	}

	return (txs_to_compare, outputs_to_compare);
}

/// Verifies `n` transactions between LMDB and SQLite databases, considering `OutputData` and `TxLogEntry` structs
pub fn check_migration<'a, T: ?Sized, C, K>(wallet: &mut T, dir: &str) -> bool
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Are we going to consider a default value or not?
	let num_transactions = get_approximately_number_transactions(dir);

	// If we want to randomly check
	let check_random = true;

	// Get the transactions
	let (txs_lmdb, outputs_lmdb) = get_vectors_from_lmdb(wallet, num_transactions, check_random);
	let (txs_sql, outputs_sql) = get_vectors_from_sqlite(wallet, num_transactions);

	// Let's assume that the wallets are equal
	let mut check = true;

	// If txs fails
	check = check && compare_vectors(&txs_lmdb, &txs_sql);

	// Error if the TxLogEntry are different
	if !check {
		error!(
			"TxLogEntry type transactions are different between databases,
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
			"OutputData type transactions are different between databases,
			LMDB: {:?}
			SQLite: {:?}",
			outputs_lmdb, outputs_sql
		)
	}

	check
}

/// This function checks if the database migration has already been done from LMDB to SQLite
pub fn need_migration(chain_type: &ChainTypes) -> bool {
	let mut home_dir = config::get_epic_path(&chain_type).unwrap();
	home_dir.push("wallet_data"); //wallet_data by default
	home_dir.push("db");
	home_dir.push("sqlite"); // Need to check if we are going to use this path for the new wallet

	!home_dir.exists() // Need to check if we are going to use a flag to check if the flock migration has already been done or not
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

/// Get the size of lmdb wallet database in kB
fn get_wallet_size(dir: &str) -> u64 {
	// get .epic/chain_type/ PathBuf
	let mut path = PathBuf::from(dir);

	// get wallet_data/db/lmdb/data.mdb PathBuf
	path.push("db");
	path.push("lmdb");
	path.push("data.mdb");

	// get lmdb kB
	let lmdb_size = path
		.metadata()
		.expect("Can't get LMDB wallet database size")
		.len();
	lmdb_size
}

/// This function generates all the values for the function responsible for generating the vector of which transactions we are going to use to test the migration (statistical importance);
/// Function input should be:
/// num_transactions - Number of transactions obtained from the function `get_approximately_number_transactions()`
/// percentage - An integer number between 0 and 50 that corresponds to the percentage of transactions that we are going to test
/// So the function returns:
/// low - lower bound of the range to get the entire transaction amount
/// high - upper limit of the range to get the entire transaction amount
/// step - step the model takes to vary the intervals and get different random numbers
/// num_elements - the total number of random numbers retrieved based on `percentage` of the number of transactions
fn generate_lim_rand(num_transactions: u64, percentage: usize) -> (usize, usize, usize, usize) {
	let per = if percentage > 50 { 50 } else { percentage }; // We cannot take more than 50% for testing, otherwise the code that generates the random vector needs the `high` to be much larger than the `low`

	let num_elements = num_transactions * per as u64 / 100;

	// start with first transaction
	let low: usize = 0;

	// To calculate high we need:
	// num_transactions > num_elements*step
	// 0 = num_transactions - num_elements*step
	// Step is def by:
	// step = high - low + 1
	// So => 0 = num_transactions - num_elements*(high - low + 1)
	// num_elements(high - low + 1) = num_transactions
	// high - low + 1 =  num_transactions/num_elements
	// Finally,
	// high = num_transactions/num_elements + low - 1

	// But the initial conditions are complicated (low < high)
	// this would imply that (num_transactions/num_elements - 1 > low)
	// and even worse thinking that we will always start from
	// the beginning low = 0 and also that low and high are integers
	// so we need that (num_transactions/ num_elements - 1 > 2)

	// What makes the calculation difficult so we kept num_elements = `percentage` of num_transactions.
	// So low and high are always the same values regardless of the number of transactions the wallet has.
	let high: usize = (100 / percentage as usize) - 1; // num_transactions / num_elements - 1 = x/(x * percentage / 100) - 1 = (100 / percentage) - 1 = 9

	// number of elements between low and high including limits
	let step: usize = high - low + 1;

	(low, high, step, num_elements as usize)
}

/// This function is responsible for returning a vector with random integers with the transactions that must be caught inside the LMDB wallet
fn generate_rand_integer(
	min_range: usize,
	max_range: usize,
	step: usize,
	number_elements: usize,
) -> Vec<u64> {
	let mut rng = rand::thread_rng();

	let mut low_k = min_range.clone();
	let mut high_k = max_range.clone();

	//step = high_k - low_k + 1;

	let mut vec_random = vec![0 as u64; number_elements];
	for k in 1..number_elements {
		let num = rng.gen_range(low_k, high_k);
		vec_random[k] = num as u64;
		low_k = low_k + step;
		high_k = high_k + step;
	}
	vec_random
}

/// Returns approximately the number of transactions to consider for testing the migration
/// The bool means if we are going to get the transactions sequentially,
/// if it is `false` then we are going to get the transactions randomly
fn get_approximately_number_transactions(dir: &str) -> u64 {
	// LMDB empty wallet database kb
	let size_empty_database: u64 = 45056;

	// Get wallet_data/lmdb/db kb
	let size_wallet: u64 = get_wallet_size(dir);

	// If the wallet is empty returns an error
	if size_empty_database == size_wallet {
		error!(
			"The wallet is empty, can't approximate a number of transactions to database (LMDB -> SQLite) migration!"
		)
	}

	// 15*db_kb/empty_db_kb is only a approximating the number of transactions available
	let approx_transactions: u64 = 15 * size_wallet / size_empty_database;

	// If the wallet has almost no transactions then we will verify it using the default value of 15
	if approx_transactions < 30 {
		return 15;
	}

	return approx_transactions;
}

/// This function migrates the database from LMDB to SQLite and executes the SQLite check at the end
pub fn make_migration<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	chain_type: &ChainTypes,
	wallet_dir: &str,
) -> bool
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// SQLite migration blocked, we still don't have SQLite finalized to perform the migration between databases
	println!("TODO"); //todo!();

	// Checking if the migration was successful
	if check_migration(wallet, wallet_dir) {
		info!("Success in the migration between databases!. Migration verification between databases completed successfully!")
	};

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
