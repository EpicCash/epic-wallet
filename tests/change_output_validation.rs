// Copyright 2026 The Epic Developers
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

#[macro_use]
extern crate log;

use epic_wallet_impls::test_framework::{self, LocalWalletClient, WalletProxy};
use epic_wallet_impls::DefaultLCProvider;
use epic_wallet_libwallet::api_impl::owner;
use epic_wallet_libwallet::{Error, InitTxArgs};
use epic_wallet_util::epic_keychain::ExtKeychain;
use std::collections::HashSet;
use std::thread;

#[macro_use]
mod common;
use common::{clean_output_dir, execute_command, initial_setup_wallet, instantiate_wallet, setup};

#[test]
fn change_output_validation_and_conservation() -> Result<(), epic_wallet_controller::Error> {
	let test_dir = "target/test_output/change_output_validation_and_conservation";
	setup(test_dir);
	setup_proxy!(test_dir, chain, wallet1, client1, mask1, _wallet2, _client2, _mask2);

	test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 10, false)?;

	let result = {
		let mut wallet_lock = wallet1.lock();
		let wallet = wallet_lock.lc_provider()?.wallet_inst()?;
		owner::init_send_tx(
			&mut **wallet,
			mask1,
			InitTxArgs {
				amount: 1_000_000_000,
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 0,
				selection_strategy_is_use_all: true,
				..Default::default()
			},
			true,
		)
	};

	assert!(matches!(result, Err(Error::ArgumentError(_))));

	let (slate, context) = {
		let mut wallet_lock = wallet1.lock();
		let wallet = wallet_lock.lc_provider()?.wallet_inst()?;
		let slate = owner::init_send_tx(
			&mut **wallet,
			mask1,
			InitTxArgs {
				amount: 1_000_000_000,
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 3,
				selection_strategy_is_use_all: true,
				..Default::default()
			},
			true,
		)?;
		let context = wallet.get_private_context(mask1, slate.id.as_bytes(), 0)?;
		(slate, context)
	};

	let inputs = context.get_inputs();
	let outputs = context.get_outputs();
	let input_total = inputs.iter().map(|input| input.2).sum::<u64>();
	let output_total = outputs.iter().map(|output| output.2).sum::<u64>();
	let output_ids = outputs
		.iter()
		.map(|output| output.0.clone())
		.collect::<HashSet<_>>();

	assert_eq!(context.fee, slate.fee);
	assert_eq!(outputs.len(), 3);
	assert_eq!(slate.tx.outputs().len(), outputs.len());
	assert_eq!(output_ids.len(), outputs.len());
	assert!(outputs.iter().all(|output| output.1.is_none()));
	assert!(outputs.iter().all(|output| output.2 > 0));
	assert_eq!(output_total, input_total - slate.amount - slate.fee);

	clean_output_dir(test_dir);
	Ok(())
}
