// Copyright 2019 The epic Developers
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

use crate::api;
use crate::chain;
use crate::chain::Chain;
use crate::core;
use crate::core::core::{BlockHeader,Output, OutputFeatures, OutputIdentifier, Transaction, TxKernel};
use crate::core::{consensus, global, pow};
use crate::core::core::block::feijoada::PoWType as FType;
use crate::core::core::block::feijoada::PoWType;
use crate::core::core::block::feijoada::{
	count_beans, get_bottles_default, next_block_bottles, Deterministic, Feijoada, Policy,
	PolicyConfig,
};
use crate::core::pow::{
new_cuckaroo_ctx, new_cuckatoo_ctx, new_md5_ctx, new_progpow_ctx, new_randomx_ctx,
	Difficulty,DifficultyNumber, EdgeType, Error, PoWContext};
use crate::keychain;
use crate::keychain::{ExtKeychain, Keychain};
use crate::keychain::ExtKeychainPath;
use chrono::prelude::{DateTime, NaiveDateTime, Utc};

use crate::libwallet;
use crate::libwallet::api_impl::{foreign, owner};
use crate::libwallet::{
	BlockFees, InitTxArgs, NodeClient, WalletInfo, WalletInst, WalletLCProvider,
};
use crate::util::secp::key::SecretKey;
use crate::util::secp::pedersen;
use crate::util::Mutex;
use chrono::Duration;
use std::sync::Arc;
use std::thread;

mod testclient;

pub use self::{testclient::LocalWalletClient, testclient::WalletProxy};

const MAX_SOLS: u32 = 10;

/// Get an output from the chain locally and present it back as an API output
fn get_output_local(chain: &chain::Chain, commit: &pedersen::Commitment) -> Option<api::Output> {
	let outputs = [
		OutputIdentifier::new(OutputFeatures::Plain, commit),
		OutputIdentifier::new(OutputFeatures::Coinbase, commit),
	];

	for x in outputs.iter() {
		if chain.is_unspent(&x).is_ok() {
			let block_height = chain.get_header_for_output(&x).unwrap().height;
			let output_pos = chain.get_output_pos(&x.commit).unwrap_or(0);
			return Some(api::Output::new(&commit, block_height, output_pos));
		}
	}
	None
}

/// Get a kernel from the chain locally
fn get_kernel_local(
	chain: Arc<chain::Chain>,
	excess: &pedersen::Commitment,
	min_height: Option<u64>,
	max_height: Option<u64>,
) -> Option<api::LocatedTxKernel> {
	chain
		.get_kernel_height(&excess, min_height, max_height)
		.unwrap()
		.map(|(tx_kernel, height, mmr_index)| api::LocatedTxKernel {
			tx_kernel,
			height,
			mmr_index,
		})
}

/// get output listing traversing pmmr from local
fn get_outputs_by_pmmr_index_local(
	chain: Arc<chain::Chain>,
	start_index: u64,
	end_index: Option<u64>,
	max: u64,
) -> api::OutputListing {
	let outputs = chain
		.unspent_outputs_by_pmmr_index(start_index, max, end_index)
		.unwrap();
	api::OutputListing {
		last_retrieved_index: outputs.0,
		highest_index: outputs.1,
		outputs: outputs
			.2
			.iter()
			.map(|x| {
				api::OutputPrintable::from_output(x, chain.clone(), None, true, false).unwrap()
			})
			.collect(),
	}
}

/// get output listing in a given block range
fn height_range_to_pmmr_indices_local(
	chain: Arc<chain::Chain>,
	start_index: u64,
	end_index: Option<u64>,
) -> api::OutputListing {
	let indices = chain
		.block_height_range_to_pmmr_indices(start_index, end_index)
		.unwrap();
	api::OutputListing {
		last_retrieved_index: indices.0,
		highest_index: indices.1,
		outputs: vec![],
	}
}




/// Adds a block with a given reward to the chain and mines it
pub fn add_block_with_reward(chain: &Chain, txs: Vec<&Transaction>, reward_output: Output,
	reward_kernel: TxKernel,) {

	let prev = chain.head_header().unwrap();
	let next_header_info = consensus::next_difficulty(
		1,
		(&prev.pow.proof).into(),
		chain.difficulty_iter().unwrap(),
	);


	let mut b = core::core::Block::new(
		&prev,
		txs.into_iter().cloned().collect(),
		next_header_info.clone().difficulty,
		(reward_output, reward_kernel)

	)
	.unwrap();


	b.header.timestamp = prev.timestamp + Duration::seconds(60);
	b.header.pow.secondary_scaling = next_header_info.secondary_scaling;
	b.header.bottles = next_block_bottles(
		FType::Cuckatoo,
		&prev.bottles,
	);


	let hash = chain
		.header_pmmr()
		.read()
		.get_header_hash_by_height(pow::randomx::rx_current_seed_height(prev.height + 1))
		.unwrap();
	let mut seed = [0u8; 32];
	seed.copy_from_slice(&hash.as_bytes()[0..32]);
	b.header.pow.seed = seed;
	chain.set_txhashset_roots(&mut b).unwrap();

	/*let edge_bits = global::min_edge_bits();
	match b.header.pow.proof {
		pow::Proof::CuckooProof {
			edge_bits: ref mut bits,
			..
		} => *bits = edge_bits,
		pow::Proof::MD5Proof {
			edge_bits: ref mut bits,
			..
		} => *bits = edge_bits,
		_ => {}
	};
	pow_size_custom(
		&mut b.header,
		next_header_info.difficulty,
		global::proofsize(),
		edge_bits,
		&FType::Cuckatoo,
	)
	.unwrap();*/


	/*pow::pow_size(
		&mut b.header,
		next_header_info.difficulty,
		global::proofsize(),
		global::min_edge_bits(),
	)
	.unwrap();*/
println!("block to add {:?}", b);
	chain.process_block(b, chain::Options::SKIP_POW).unwrap();
	chain.validate(false).unwrap();
}

fn pow_size_custom(
	bh: &mut BlockHeader,
	diff: Difficulty,
	proof_size: usize,
	sz: u8,
	pow_type: &PoWType,
) -> Result<(), Error> {
	let start_nonce = bh.pow.nonce;
	// set the nonce for faster solution finding in user testing
	if bh.height == 0 {
		bh.pow.nonce = global::get_genesis_nonce();
	}

	// try to find a cuckoo cycle on that header hash
	loop {
		// if we found a cycle (not guaranteed) and the proof hash is higher that the
		// diff, we're all good
		let mut ctx = create_pow_context_custom::<u32>(
			bh.height,
			sz,
			proof_size,
			MAX_SOLS,
			pow_type,
			bh.pow.seed,
		)?;

		if let pow::Proof::CuckooProof { .. } = bh.pow.proof {
			ctx.set_header_nonce(bh.pre_pow(), None, Some(bh.height), true)?;
		} else {
			ctx.set_header_nonce(bh.pre_pow(), Some(bh.pow.nonce), Some(bh.height), true)?;
		}

		if let Ok(proofs) = ctx.pow_solve() {
			bh.pow.proof = proofs[0].clone();
			if bh.pow.to_difficulty(&bh.pre_pow(), bh.height, bh.pow.nonce) >= diff {
				return Ok(());
			}
		}

		// otherwise increment the nonce
		let (res, _) = bh.pow.nonce.overflowing_add(1);
		bh.pow.nonce = res;

		// and if we're back where we started, update the time (changes the hash as
		// well)
		if bh.pow.nonce == start_nonce {
			bh.timestamp = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(0, 0), Utc);
		}
	}
}
fn create_pow_context_custom<T>(
	_height: u64,
	edge_bits: u8,
	proof_size: usize,
	max_sols: u32,
	pow_type: &PoWType,
	seed: [u8; 32],
) -> Result<Box<dyn PoWContext<T>>, pow::Error>
where
	T: EdgeType + 'static,
{
	match pow_type {
		// Mainnet has Cuckaroo29 for AR and Cuckatoo30+ for AF
		PoWType::Cuckaroo => new_cuckaroo_ctx(edge_bits, proof_size),
		PoWType::Cuckatoo => new_cuckatoo_ctx(edge_bits, proof_size, max_sols),
		PoWType::RandomX => new_randomx_ctx(seed),
		PoWType::ProgPow => new_progpow_ctx(),
	}
}
/// adds a reward output to a wallet, includes that reward in a block, mines
/// the block and adds it to the chain, with option transactions included.
/// Helpful for building up precise wallet balances for testing.
pub fn award_block_to_wallet<'a, L, C, K>(
	chain: &Chain,
	txs: Vec<&Transaction>,
	wallet: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K> + 'a>>>,
	keychain_mask: Option<&SecretKey>,
) -> Result<(), libwallet::Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: keychain::Keychain + 'a,
{
	// build block fees
	let prev = chain.head_header().unwrap();
	let fee_amt = txs.iter().map(|tx| tx.fee()).sum();
	let block_fees = BlockFees {
		fees: fee_amt,
		key_id: None,
		height: prev.height + 1,
	};
	// build coinbase (via api) and add block
	let coinbase_tx = {
		let mut w_lock = wallet.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		foreign::build_coinbase(&mut **w, keychain_mask, &block_fees, true)?
	};


	add_block_with_reward(chain, txs, coinbase_tx.output, coinbase_tx.kernel);
	Ok(())
}

/// Award a blocks to a wallet directly
pub fn award_blocks_to_wallet<'a, L, C, K>(
	chain: &Chain,
	wallet: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K> + 'a>>>,
	keychain_mask: Option<&SecretKey>,
	number: usize,
	pause_between: bool,
) -> Result<(), libwallet::Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: keychain::Keychain + 'a,
{
	for _ in 0..number {
		award_block_to_wallet(chain, vec![], wallet.clone(), keychain_mask)?;
		if pause_between {
			thread::sleep(std::time::Duration::from_millis(100));
		}
	}
	Ok(())
}

/// send an amount to a destination
pub fn send_to_dest<'a, L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	client: LocalWalletClient,
	dest: &str,
	amount: u64,
	test_mode: bool,
) -> Result<(), libwallet::Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: keychain::Keychain + 'a,
{
	let slate = {
		let mut w_lock = wallet.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		let args = InitTxArgs {
			src_acct_name: None,
			amount,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			..Default::default()
		};
		let slate_i = owner::init_send_tx(&mut **w, keychain_mask, args, test_mode)?;
		let slate = client.send_tx_slate_direct(dest, &slate_i)?;
		owner::tx_lock_outputs(&mut **w, keychain_mask, &slate, 0)?;
		owner::finalize_tx(&mut **w, keychain_mask, &slate)?
	};
	let client = {
		let mut w_lock = wallet.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		w.w2n_client().clone()
	};
	owner::post_tx(&client, &slate.tx, false)?; // mines a block
	Ok(())
}

/// get wallet info totals
pub fn wallet_info<'a, L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
) -> Result<WalletInfo, libwallet::Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: keychain::Keychain + 'a,
{
	let (wallet_refreshed, wallet_info) =
		owner::retrieve_summary_info(wallet, keychain_mask, &None, true, 1)?;
	assert!(wallet_refreshed);
	Ok(wallet_info)
}
