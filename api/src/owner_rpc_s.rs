// Copyright 2019 The Epic Developers
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

//! JSON-RPC Stub generation for the Owner API
use uuid::Uuid;

use crate::config::{EpicboxConfig, TorConfig, WalletConfig};
use crate::core::core::Transaction;
use crate::core::global;
use crate::keychain::{Identifier, Keychain};
use crate::libwallet::slate_versions::v3::TransactionV3;
use crate::libwallet::{
	AcctPathMapping, EpicboxAddress, ErrorKind, InitTxArgs, IssueInvoiceTxArgs, NodeClient,
	NodeHeightResult, OutputCommitMapping, PaymentProof, Slate, SlateVersion, StatusMessage,
	TxLogEntry, VersionedSlate, WalletInfo, WalletLCProvider,
};
use crate::util::logger::LoggingConfig;
use crate::util::secp::key::{PublicKey, SecretKey};
use crate::util::{static_secp_instance, ZeroingString};
use crate::{ECDHPubkey, Owner, PubAddress, Token};
use easy_jsonrpc_mw;
use rand::thread_rng;
use std::time::Duration;

/// Public definition used to generate Owner jsonrpc api.
/// Secure version containing wallet lifecycle functions. All calls to this API must be encrypted.
/// See [`init_secure_api`](#tymethod.init_secure_api) for details of secret derivation
/// and encryption.

#[easy_jsonrpc_mw::rpc]
pub trait OwnerRpcS {
	/**
	Networked version of [Owner::accounts](struct.Owner.html#method.accounts).

	# Json rpc example

	```
	# epic_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "accounts",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"result": {
			"Ok": [
				{
					"label": "default",
					"path": "0200000000000000000000000000000000"
				}
			]
		},
		"id": 1
	}
	# "#
	# , true, 4, false, false, false, false);
	```
	*/
	fn accounts(&self, token: Token) -> Result<Vec<AcctPathMapping>, ErrorKind>;

	/**
	Networked version of [Owner::create_account_path](struct.Owner.html#method.create_account_path).

	# Json rpc example

	```
	# epic_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "create_account_path",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"label": "account1"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"result": {
			"Ok": "0200000001000000000000000000000000"
		},
		"id": 1
	}
	# "#
	# ,true, 4, false, false, false, false);
	```
	 */
	fn create_account_path(&self, token: Token, label: &String) -> Result<Identifier, ErrorKind>;

	/**
	Networked version of [Owner::set_active_account](struct.Owner.html#method.set_active_account).

	# Json rpc example

	```
	# epic_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "set_active_account",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"label": "default"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		},
		"id": 1
	}
	# "#
	# , true, 4, false, false, false, false);
	```
	 */
	fn set_active_account(&self, token: Token, label: &String) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::retrieve_outputs](struct.Owner.html#method.retrieve_outputs).

	# Json rpc example

	```
	# epic_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "retrieve_outputs",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"include_spent": false,
			"refresh_from_node": true,
			"tx_id": null
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": [
				true,
				[
					{
						"commit": "089be87c488db1e7c783b19272a83b23bce56a5263163554b345c6f7ffedac517e",
						"output": {
							"commit": "089be87c488db1e7c783b19272a83b23bce56a5263163554b345c6f7ffedac517e",
							"height": "1",
							"is_coinbase": true,
							"key_id": "0300000000000000000000000000000000",
							"lock_height": "4",
							"mmr_index": null,
							"n_child": 0,
							"root_key_id": "0200000000000000000000000000000000",
							"status": "Unspent",
							"tx_log_entry": 0,
							"value": "1457920000"
						}
					},
					{
						"commit": "09d8836ffd38ffca42567ef965fdcf1f35b05aeb357664d70cd482438ca0ca0c9e",
						"output": {
							"commit": "09d8836ffd38ffca42567ef965fdcf1f35b05aeb357664d70cd482438ca0ca0c9e",
							"height": "2",
							"is_coinbase": true,
							"key_id": "0300000000000000000000000100000000",
							"lock_height": "5",
							"mmr_index": null,
							"n_child": 1,
							"root_key_id": "0200000000000000000000000000000000",
							"status": "Unspent",
							"tx_log_entry": 1,
							"value": "1457920000"
						}
					}
				]
			]
		}
	}
	# "#
	# , true, 2, false, false, false, false);
	```
	*/
	fn retrieve_outputs(
		&self,
		token: Token,
		include_spent: bool,
		refresh_from_node: bool,
		tx_id: Option<u32>,
	) -> Result<(bool, Vec<OutputCommitMapping>), ErrorKind>;

	/**
	Networked version of [Owner::retrieve_txs](struct.Owner.html#method.retrieve_txs).

	# Json rpc example

	```
		# epic_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
		# r#"
		{
			"jsonrpc": "2.0",
			"method": "retrieve_txs",
			"params": {
				"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
				"refresh_from_node": true,
				"tx_id": null,
				"tx_slate_id": null
			},
			"id": 1
		}
		# "#
		# ,
		# r#"
		{
		"id": 1,
		"jsonrpc": "2.0",
	  "result": {
		"Ok": [
		  true,
		  [
			{
			  "amount_credited": "1457920000",
			  "amount_debited": "0",
			  "confirmation_ts": "2019-01-15T16:01:26Z",
			  "confirmed": true,
			  "creation_ts": "2019-01-15T16:01:26Z",
			  "fee": null,
			  "id": 0,
			  "kernel_excess": "09a89280fa8d888358ab730383f00a3d990b7f2c6b17fc960501f30aac8e014478",
			  "kernel_lookup_min_height": 1,
			  "messages": null,
			  "num_inputs": 0,
			  "num_outputs": 1,
			  "parent_key_id": "0200000000000000000000000000000000",
			  "stored_tx": null,
			  "ttl_cutoff_height": null,
			  "tx_slate_id": null,
			  "payment_proof": null,
			  "tx_type": "ConfirmedCoinbase"
			},
			{
			  "amount_credited": "1457920000",
			  "amount_debited": "0",
			  "confirmation_ts": "2019-01-15T16:01:26Z",
			  "confirmed": true,
			  "creation_ts": "2019-01-15T16:01:26Z",
			  "fee": null,
			  "id": 1,
			  "kernel_excess": "08bae42ff7d5fa5aca058fd0889dd1e40df16bf3ee2eea6e5db720c0a6d638a7f8",
			  "kernel_lookup_min_height": 2,
			  "messages": null,
			  "num_inputs": 0,
			  "num_outputs": 1,
			  "parent_key_id": "0200000000000000000000000000000000",
			  "stored_tx": null,
			  "ttl_cutoff_height": null,
			  "payment_proof": null,
			  "tx_slate_id": null,
			  "tx_type": "ConfirmedCoinbase"
			}
		  ]
		]
	  }
	}
	# "#
	# , true, 2, false, false, false, false);
	```
	*/

	fn retrieve_txs(
		&self,
		token: Token,
		refresh_from_node: bool,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(bool, Vec<TxLogEntry>), ErrorKind>;

	/**
	Networked version of [Owner::retrieve_summary_info](struct.Owner.html#method.retrieve_summary_info).

	# Json rpc example

	```
	# epic_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "retrieve_summary_info",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"refresh_from_node": true,
			"minimum_confirmations": 1
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
	"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": [
				true,
				{
					"amount_awaiting_confirmation": "0",
					"amount_awaiting_finalization": "0",
					"amount_currently_spendable": "1457920000",
					"amount_immature": "4373760000",
					"amount_locked": "0",
					"last_confirmed_height": "4",
					"minimum_confirmations": "1",
					"total": "5831680000"
				}

			]
		}
	}
	# "#
	# ,true, 4, false, false, false, false);
	```
	 */

	fn retrieve_summary_info(
		&self,
		token: Token,
		refresh_from_node: bool,
		minimum_confirmations: u64,
	) -> Result<(bool, WalletInfo), ErrorKind>;

	/**
	Networked version of [Owner::init_send_tx](struct.Owner.html#method.init_send_tx).

	# Json rpc example

	```
		# epic_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
		# r#"
		{
			"jsonrpc": "2.0",
			"method": "init_send_tx",
			"params": {
				"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
				"args": {
					"src_acct_name": null,
					"amount": "60000000",
					"minimum_confirmations": 2,
					"max_outputs": 500,
					"num_change_outputs": 1,
					"selection_strategy_is_use_all": true,
					"message": "my message",
					"target_slate_version": null,
					"payment_proof_recipient_address": "d03c09e9c19bb74aa9ea44e0fe5ae237a9bf40bddf0941064a80913a4459c8bb",
					"ttl_blocks": null,
					"send_args": null
				}
			},
			"id": 1
		}
		# "#
		# ,
		# r#"
		{
	  "id": 1,
	  "jsonrpc": "2.0",
	  "result": {
		"Ok": {
		  "amount": "60000000",
		  "fee": "800000",
		  "height": "4",
		  "id": "0436430c-2b02-624c-2032-570501212b00",
		  "lock_height": "0",
		  "num_participants": 2,

		  "participant_data": [
			{
			  "id": "0",
			  "message": "my message",
			  "message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bea065fb74c27c31d611427ac5fa1459d1db340d7475e2967f19e2fa95687d88c",
			  "part_sig": null,
			  "public_blind_excess": "039fbac4782fa1600aa704c38073eece85e3a085a90446ded19a9fec90e432b330",
			  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
			}
		  ],
		  "payment_proof": {
			  "receiver_address": "d03c09e9c19bb74aa9ea44e0fe5ae237a9bf40bddf0941064a80913a4459c8bb",
			  "receiver_signature": null,
			  "sender_address": "32cdd63928854f8b2628b1dce4626ddcdf35d56cb7cfdf7d64cca5822b78d4d3"
			},
			"ttl_cutoff_height": null,
		  "tx": {
			"body": {
			"inputs": [
			  {
				"commit": "089be87c488db1e7c783b19272a83b23bce56a5263163554b345c6f7ffedac517e",
				"features": "Coinbase"
			  }
			],
			"kernels": [
			  {
				"excess": "000000000000000000000000000000000000000000000000000000000000000000",
				"excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				"features": "Plain",
				"fee": "800000",
				"lock_height": "0"
			  }
			],
			"outputs": [
			  {
				"commit": "0832ca73c2049ee0c8f555c6297aa3658eb3f8ce711dfd63d6d5234cf3191c7756",
				"features": "Plain",
				"proof": "1393386202b2ba345e131efb1dfc3730c000ee6b6f3cb8d56e3d0680796b11940abeaed75e18458b544d28765b530a7ca2ed170b42c8bd5e07d4451b0cfa59c20fee43c9107091a328a9f745a255702ea17ac50f5e92b2daf51a7851e8ffde5e11a6837b5b6058aee5ab1e68bcd756646f36b38c6262aa20ff9c194d2e3e155b608216186fee66ef8ca269d31a015c63cca3cf5f0d40e4cccd13d390ed1aeed7a7c7d0709e9b509844462098d97e983ba6963ee3a68955d5317ecec47caeb8911784598be71d319ba8441c36388bf4a10ba2538f4f54f648b22a8f1e1f713dec36376936100b0fc5fb5ad4f51811ec96a76b564c3ee08305f5a2ad79a80152a03eb86d4dcd854a23818621d80771ceb169e45a692b45db77667beecd545e08b8afe8f8a3d049ae18e1cee5522769cd6b0131e036ee81d70df4cd679959fd82684bf9e1f4784325ef271eec2fb73ef4a9569fd76f7b1e55d8e2e87a5daa5ad5357cb401af13c2c695afc4b6a8a2004da1b0f5ebe7cb70cb2e15f0f3ca41eaca969abcb452f7a15fe9d004e66ff646e423366713632f1dedcb33bac1abbc47f1cf2b280f04cf85a7291bb4ecb2c1c252d65e933f5819ba4984b1018ec11ae36d2445af56900b9b6e746f84ddd6b06baab9d7c8f82f0b0bc7a61ade6eabe762ac0d3afe4b2102518361a9e54a4d9d51e4a25ccf1d40c36f6444d2271d03d91eb0f1f6895345c8758a7375926cf0ab75212ef7b4a0efa59a31decd995be2933e3da51efec22365521b8942f997789f9618cbbb422607c2414fc64bc558eca27df5fe7156954b98335a5cc63e6bfe7e076149c93e2314dd626f48bf6721b506b81962b6ca81bff28c7e216f49fcbf989045f97452f3b4ccdcaa7ca5a4ce0bd3f5e16440c6c0b73a42bfa6cfe8e31265b73b81b81c2d54e4f7aefb16ebfa1273adbfd57c08a6"
			  }
			]
			},
			"offset": "d202964900000000d302964900000000d402964900000000d502964900000000"
		  },
		  "version_info": {
				"orig_version": 3,
				"version": 3,
				"block_header_version": 6
		  }
		}
	  }
	}
		# "#
		# ,true, 4, false, false, false, false);
	```
	*/

	fn init_send_tx(&self, token: Token, args: InitTxArgs) -> Result<VersionedSlate, ErrorKind>;

	/**
	Networked version of [Owner::issue_invoice_tx](struct.Owner.html#method.issue_invoice_tx).

	# Json rpc example

	```
		# epic_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
		# r#"
		{
			"jsonrpc": "2.0",
			"method": "issue_invoice_tx",
			"params": {
				"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
				"args": {
					"amount": "60000000",
					"message": "Please give me your epics",
					"dest_acct_name": null,
					"target_slate_version": null
				}
			},
			"id": 1
		}
		# "#
		# ,
		# r#"
		{
			"id": 1,
			"jsonrpc": "2.0",
			"result": {
				"Ok": {
					"amount": "60000000",
					"fee": "0",
					"height": "4",
					"id": "0436430c-2b02-624c-2032-570501212b00",
					"lock_height": "0",
					"ttl_cutoff_height": null,
					"num_participants": 2,
					"payment_proof": null,
					"participant_data": [
						{
							"id": "1",
							"message": "Please give me your epics",
							"message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bb06e3894e0db51e6015d2181f101d06722094128dbc316f7186b57edd68731cb",
							"part_sig": null,
							"public_blind_excess": "035ca9d2d82e0e31bc2add7ef9200066b257d9f72cb16c0e57455277b90e2b3503",
							"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
						}
					],
					"tx": {
						"body": {
							"inputs": [],
							"kernels": [
								{
									"excess": "000000000000000000000000000000000000000000000000000000000000000000",
									"excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
									"features": "Plain",
									"fee": "0",
									"lock_height": "0"
								}
							],
							"outputs": [
								{
									"commit": "083fe68fb96a0941f70e9412b4483621326abee9eccf10e7a7efef2a9b4e97df25",
									"features": "Plain",
									"proof": "2df8ba188baa701a7c07e23de108e8318797ba029319b4557db3c1c8af917f6361d9871520e33423131d5771b06566aba2469f1e9fcc8eda8203a5c241759e45041af26939c57946372bf330d09670eb30a08cae27b3015dac2efb518fbe2325487d8417f4014cb854aec9e4e1770d2f5d7a6e32e2bc904245505ebd952eda10b5c401f315a8cb969da4cc2dc1e656f33d870ca07ffbc45f58cae9f28b836d4bf3c1786b805ba9d8789cc211998981a8b4115aa7383ddbd10e656fc0a590c3e2cf8dd07e414217d9a1d1af32bcbd933448d0a89033cb93ba2eb0d3b973136d61ee7f109d0476ed3475b7328eff5e9d3362b5db4621682a443a382f7ef09304f9bff422885d23f62f9d7d1a9bbf888e5ba5678e347182770cbbf41cfb3002269607f085881ce0f0df01f34f34433ef04dd6008f9a0c13e47e6e386d62151386dfd20bdf812ae2fb580edc38f38bfc9cc543d1023889ee646d4e75a7382caa3bb00b970062ffdc1fc643ce56d25e2e73b556162c8441d5a667b36b840cc244f69395b46900dd1edc562ed741c239804588e94c071b621766b55f738802c376012fa577e0d82bdf7bf2f229a867d91ed177bacde44faadb6901066f84e21a5fb0b73ed7ef9ef4a1e2c65e6a28a0ae834a99ed1694889d885fc8e90c8e7507078603a9705cc3c57b8b0125ad385cb5ec564f9ca69b530307d91ef2c6bb49a39e30d9e68f2f67d99915d87d1a7776f4c0b61913ea661ebe320b8e99919c69d9dbdc527e787d46e772da9ab9f9cc60e43b41fb0981b6b882ed7a535451158c711210fe25e68d12719192c3d332aea9e047a0f7a292b8e6f13fd76ed47afbadf070392cc3f4a4ebb8ec9853587e30ad9b9794717c87bf962e2ab99ec543f5a24efda0cfc2bf51f23c8132aee6058189925febe1d9d3a145f580ef9835db3c1f3b6e97bd36331e"
								}
							]
						},
						"offset": "d202964900000000d302964900000000d402964900000000d502964900000000"
					},
					"version_info": {
						"orig_version": 3,
						"version": 3,
						"block_header_version": 6
					}
				}
			}
		}
		# "#
		# ,true, 4, false, false, false, false);
	```
	*/

	fn issue_invoice_tx(
		&self,
		token: Token,
		args: IssueInvoiceTxArgs,
	) -> Result<VersionedSlate, ErrorKind>;

	/**
	Networked version of [Owner::process_invoice_tx](struct.Owner.html#method.process_invoice_tx).

	# Json rpc example

	```
		# epic_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
		# r#"
		{
			"jsonrpc": "2.0",
			"method": "process_invoice_tx",
			"params": {
				"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
				"slate": {
					"amount": "60000000",
					"fee": "0",
					"height": "4",
					"id": "0436430c-2b02-624c-2032-570501212b00",
					"lock_height": "0",
					"ttl_cutoff_height": null,
					"num_participants": 2,
					"payment_proof": null,
					"participant_data": [
						{
							"id": "1",
							"message": "Please give me your epics",
							"message_sig": "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078fd2599ab38942986602e943f684a85992893a6d34367dc7cc2b403a5dcfcdbcd9",
							"part_sig": null,
							"public_blind_excess": "028e95921cc0d5be5922362265d352c9bdabe51a9e1502a3f0d4a10387f1893f40",
							"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
						}
					],
					"tx": {
						"body": {
							"inputs": [],
							"kernels": [
								{
									"excess": "000000000000000000000000000000000000000000000000000000000000000000",
									"excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
									"features": "Plain",
									"fee": "0",
									"lock_height": "0"
								}
							],
							"outputs": [
								{
									"commit": "09cf47204446c326e361a1a92f34b174deff732daaedb80d7339fbe3db5ca2f6ba",
									"features": "Plain",
									"proof": "8f511614315626b5f39224482351d766f5a8ef136262befc050d839be8479b0a13470cd88f4436346d213d83847a4055c6e0ac63681556470349a1aab47034a3015eb64d8163955998e2dd4165dd24386b1e279974b05deb5d46ba2bc321f7000c0784f8f10690605ffe717119d045e02b141ed12d8fc6d20930483a8af889ef533495eb442fcff36d98ebc104f13fc645c28431b3296e4a11f7c991ff97f9abbc2f8886762d7f29fdacb31d52c6850e6ccf5386117d89e8ea4ca3071c56c218dd5d3bcd65f6c06ed9f51f848507ca1d594f41796d1cf99f68a5c3f0c5dd9873602284cff31269b102fcc6c68607565faaf0adb04ed4ff3ea5d41f3b5235ac6cb90e4046c808c9c48c27172c891b20085c56a99913ef47fd8b3dc4920cef50534b9319a7cefe0df10a0206a634ac837e11da92df83ff58b1a14de81313400988aa48b946fcbe1b81f0e79e13f7c6c639b1c10983b424bda08d0ce593a20f1f47e0aa01473e7144f116b76d9ebc60599053d8f1542d60747793d99064e51fce8f8866390325d48d6e8e3bbdbc1822c864303451525c6cb4c6902f105a70134186fb32110d8192fc2528a9483fc8a4001f4bdeab1dd7b3d1ccb9ae2e746a78013ef74043f0b2436f0ca49627af1768b7c791c669bd331fd18c16ef88ad0a29861db70f2f76f3e74fde5accb91b73573e31333333223693d6fbc786e740c085e4fc6e7bde0a3f54e9703f816c54f012d3b1f41ec4d253d9337af61e7f1f1383bd929421ac346e3d2771dfee0b60503b33938e7c83eb37af3b6bf66041a3519a2b4cb557b34e3b9afcf95524f9a011425a34d32e7b6e9f255291094930acae26e8f7a1e4e6bc405d0f88e919f354f3ba85356a34f1aba5f7da1fad88e2692f4129cc1fb80a2122b2d996c6ccf7f08d8248e511d92af9ce49039de728848a2dc74101f4e94a"
								}
							]
						},
						"offset": "d202964900000000d302964900000000d402964900000000d502964900000000"
					},
					"version_info": {
						"orig_version": 3,
						"version": 3,
						"block_header_version": 6
					}
				},
				"args": {
					"src_acct_name": null,
					"amount": "0",
					"minimum_confirmations": 2,
					"max_outputs": 500,
					"num_change_outputs": 1,
					"selection_strategy_is_use_all": true,
					"message": "Ok, here are your epics",
					"target_slate_version": null,
					"payment_proof_recipient_address": null,
					"ttl_blocks": null,
					"send_args": null
				}
			},
			"id": 1
		}
		# "#
		# ,
		# r#"
		{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": {
				"amount": "60000000",
				"fee": "800000",
				"height": "4",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"lock_height": "0",
				"ttl_cutoff_height": null,
				"num_participants": 2,
				"payment_proof": null,
				"participant_data": [
					{
						"id": "1",
						"message": "Please give me your epics",
						"message_sig": "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078fd2599ab38942986602e943f684a85992893a6d34367dc7cc2b403a5dcfcdbcd9",
						"part_sig": null,
						"public_blind_excess": "028e95921cc0d5be5922362265d352c9bdabe51a9e1502a3f0d4a10387f1893f40",
						"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
					},
					{
						"id": "0",
						"message": "Ok, here are your epics",
						"message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bec8c1cac6cb5770a3c62c9bb95063581cc08bfccd72dac72be8ec4ba5374a9f3",
						"part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bcec20532cbe7ce0a3152b61566785684fea3534b7f834f02f733fa524123ee54",
						"public_blind_excess": "02802124f21ba02769a3f05ecfe9662e8783fa0bd1a7b7d63cf3aea0ebc0d7af3a",
						"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
					}
				],
				"tx": {
					"body": {
						"inputs": [
							{
								"commit": "089be87c488db1e7c783b19272a83b23bce56a5263163554b345c6f7ffedac517e",
								"features": "Coinbase"
							}
						],
						"kernels": [
							{
								"excess": "000000000000000000000000000000000000000000000000000000000000000000",
								"excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
								"features": "Plain",
								"fee": "800000",
								"lock_height": "0"
							}
						],
						"outputs": [
							{
								"commit": "0832ca73c2049ee0c8f555c6297aa3658eb3f8ce711dfd63d6d5234cf3191c7756",
								"features": "Plain",
								"proof": "1393386202b2ba345e131efb1dfc3730c000ee6b6f3cb8d56e3d0680796b11940abeaed75e18458b544d28765b530a7ca2ed170b42c8bd5e07d4451b0cfa59c20fee43c9107091a328a9f745a255702ea17ac50f5e92b2daf51a7851e8ffde5e11a6837b5b6058aee5ab1e68bcd756646f36b38c6262aa20ff9c194d2e3e155b608216186fee66ef8ca269d31a015c63cca3cf5f0d40e4cccd13d390ed1aeed7a7c7d0709e9b509844462098d97e983ba6963ee3a68955d5317ecec47caeb8911784598be71d319ba8441c36388bf4a10ba2538f4f54f648b22a8f1e1f713dec36376936100b0fc5fb5ad4f51811ec96a76b564c3ee08305f5a2ad79a80152a03eb86d4dcd854a23818621d80771ceb169e45a692b45db77667beecd545e08b8afe8f8a3d049ae18e1cee5522769cd6b0131e036ee81d70df4cd679959fd82684bf9e1f4784325ef271eec2fb73ef4a9569fd76f7b1e55d8e2e87a5daa5ad5357cb401af13c2c695afc4b6a8a2004da1b0f5ebe7cb70cb2e15f0f3ca41eaca969abcb452f7a15fe9d004e66ff646e423366713632f1dedcb33bac1abbc47f1cf2b280f04cf85a7291bb4ecb2c1c252d65e933f5819ba4984b1018ec11ae36d2445af56900b9b6e746f84ddd6b06baab9d7c8f82f0b0bc7a61ade6eabe762ac0d3afe4b2102518361a9e54a4d9d51e4a25ccf1d40c36f6444d2271d03d91eb0f1f6895345c8758a7375926cf0ab75212ef7b4a0efa59a31decd995be2933e3da51efec22365521b8942f997789f9618cbbb422607c2414fc64bc558eca27df5fe7156954b98335a5cc63e6bfe7e076149c93e2314dd626f48bf6721b506b81962b6ca81bff28c7e216f49fcbf989045f97452f3b4ccdcaa7ca5a4ce0bd3f5e16440c6c0b73a42bfa6cfe8e31265b73b81b81c2d54e4f7aefb16ebfa1273adbfd57c08a6"
							},
							{
								"commit": "09cf47204446c326e361a1a92f34b174deff732daaedb80d7339fbe3db5ca2f6ba",
								"features": "Plain",
								"proof": "8f511614315626b5f39224482351d766f5a8ef136262befc050d839be8479b0a13470cd88f4436346d213d83847a4055c6e0ac63681556470349a1aab47034a3015eb64d8163955998e2dd4165dd24386b1e279974b05deb5d46ba2bc321f7000c0784f8f10690605ffe717119d045e02b141ed12d8fc6d20930483a8af889ef533495eb442fcff36d98ebc104f13fc645c28431b3296e4a11f7c991ff97f9abbc2f8886762d7f29fdacb31d52c6850e6ccf5386117d89e8ea4ca3071c56c218dd5d3bcd65f6c06ed9f51f848507ca1d594f41796d1cf99f68a5c3f0c5dd9873602284cff31269b102fcc6c68607565faaf0adb04ed4ff3ea5d41f3b5235ac6cb90e4046c808c9c48c27172c891b20085c56a99913ef47fd8b3dc4920cef50534b9319a7cefe0df10a0206a634ac837e11da92df83ff58b1a14de81313400988aa48b946fcbe1b81f0e79e13f7c6c639b1c10983b424bda08d0ce593a20f1f47e0aa01473e7144f116b76d9ebc60599053d8f1542d60747793d99064e51fce8f8866390325d48d6e8e3bbdbc1822c864303451525c6cb4c6902f105a70134186fb32110d8192fc2528a9483fc8a4001f4bdeab1dd7b3d1ccb9ae2e746a78013ef74043f0b2436f0ca49627af1768b7c791c669bd331fd18c16ef88ad0a29861db70f2f76f3e74fde5accb91b73573e31333333223693d6fbc786e740c085e4fc6e7bde0a3f54e9703f816c54f012d3b1f41ec4d253d9337af61e7f1f1383bd929421ac346e3d2771dfee0b60503b33938e7c83eb37af3b6bf66041a3519a2b4cb557b34e3b9afcf95524f9a011425a34d32e7b6e9f255291094930acae26e8f7a1e4e6bc405d0f88e919f354f3ba85356a34f1aba5f7da1fad88e2692f4129cc1fb80a2122b2d996c6ccf7f08d8248e511d92af9ce49039de728848a2dc74101f4e94a"
							}
						]
					},
					"offset": "d202964900000000d302964900000000d402964900000000d502964900000000"
				},
				"version_info": {
					"orig_version": 3,
					"version": 3,
					"block_header_version": 6
				}
			}
		}
	}
	# "#
	# ,true, 4, false, false, false, false);
	```
	*/

	fn process_invoice_tx(
		&self,
		token: Token,
		slate: VersionedSlate,
		args: InitTxArgs,
	) -> Result<VersionedSlate, ErrorKind>;

	/**
	Networked version of [Owner::tx_lock_outputs](struct.Owner.html#method.tx_lock_outputs).

	# Json rpc example

	```
	# epic_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "tx_lock_outputs",
		"id": 1,
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"slate": {
				"amount": "1457920000",
				"fee": "8000000",
				"height": "4",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"lock_height": "4",
				"ttl_cutoff_height": null,
				"num_participants": 2,
				"payment_proof": null,
				"participant_data": [
				{
					"id": "0",
					"message": "my message",
					"message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b1d4c1358be398f801eb90d933774b5218fa7e769b11c4c640402253353656f75",
					"part_sig": null,
					"public_blind_excess": "034b4df2f0558b73ea72a1ca5c4ab20217c66bbe0829056fca7abe76888e9349ee",
					"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
				}
				],
				"tx": {
					"body": {
						"inputs": [
						{
							"commit": "08e1da9e6dc4d6e808a718b2f110a991dd775d65ce5ae408a4e1f002a4961aa9e7",
							"features": "Coinbase"
						}
						],
						"kernels": [
						{
							"excess": "000000000000000000000000000000000000000000000000000000000000000000",
							"excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
							"features": "HeightLocked",
							"fee": "8000000",
							"lock_height": "4"
						}
						],
						"outputs": [
						{
							"commit": "094be57c91787fc2033d5d97fae099f1a6ddb37ea48370f1a138f09524c767fdd3",
							"features": "Plain",
							"proof": "2a42e9e902b70ce44e1fccb14de87ee0a97100bddf12c6bead1b9c5f4eb60300f29c13094fa12ffeee238fb4532b18f6b61cf51b23c1c7e1ad2e41560dc27edc0a2b9e647a0b3e4e806fced5b65e61d0f1f5197d3e2285c632d359e27b6b9206b2caffea4f67e0c7a2812e7a22c134b98cf89bd43d9f28b8bec25cce037a0ac5b1ae8f667e54e1250813a5263004486b4465ad4e641ab2b535736ea26535a11013564f08f483b7dab1c2bcc3ee38eadf2f7850eff7e3459a4bbabf9f0cf6c50d0c0a4120565cd4a2ce3e354c11721cd695760a24c70e0d5a0dfc3c5dcd51dfad6de2c237a682f36dc0b271f21bb3655e5333016aaa42c2efa1446e5f3c0a79ec417c4d30f77556951cb0f05dbfafb82d9f95951a9ea241fda2a6388f73ace036b98acce079f0e4feebccc96290a86dcc89118a901210b245f2d114cf94396e4dbb461e82aa26a0581389707957968c7cdc466213bb1cd417db207ef40c05842ab67a01a9b96eb1430ebc26e795bb491258d326d5174ad549401059e41782121e506744af8af9d8e493644a87d613600888541cbbe538c625883f3eb4aa3102c5cfcc25de8e97af8927619ce6a731b3b8462d51d993066b935b0648d2344ad72e4fd70f347fbd81041042e5ea31cc7b2e3156a920b80ecba487b950ca32ca95fae85b759c936246ecf441a9fdd95e8fee932d6782cdec686064018c857efc47fb4b2a122600d5fdd79af2486f44df7e629184e1c573bc0a9b3feb40b190ef2861a1ab45e2ac2201b9cd42e495deea247269820ed32389a2810ad6c0f9a296d2a2d9c54089fed50b7f5ecfcd33ab9954360e1d7f5598c32128cfcf2a1d8bf14616818da8a5343bfa88f0eedf392e9d4ab1ace1b60324129cd4852c2e27813a9cf71a6ae6229a4fcecc1a756b3e664c5f50af333082616815a3bec8fc0b75b8e4e767d719"
						}
						]
					},
					"offset": "d202964900000000d302964900000000d402964900000000d502964900000000"
				},
				"version_info": {
					"orig_version": 3,
					"version": 3,
					"block_header_version": 6
				}
			},
			"participant_id": 0
		}
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"id": 1,
		"result": {
			"Ok": null
		}
	}
	# "#
	# ,true, 5 ,true, false, false, false);

	```
	 */
	fn tx_lock_outputs(
		&self,
		token: Token,
		slate: VersionedSlate,
		participant_id: usize,
	) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::finalize_tx](struct.Owner.html#method.finalize_tx).

	# Json rpc example

	```
	# epic_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "finalize_tx",
		"id": 1,
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"slate": {
				"version_info": {
					"version": 3,
					"orig_version": 3,
					"block_header_version": 6
				},
				"num_participants": 2,
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"payment_proof": null,
				"tx": {
					"offset": "d202964900000000d302964900000000d402964900000000d502964900000000",
					"body": {
						"inputs": [
							{
								"features": "Coinbase",
								"commit": "09d8836ffd38ffca42567ef965fdcf1f35b05aeb357664d70cd482438ca0ca0c9e"
							},
							{
								"features": "Coinbase",
								"commit": "089be87c488db1e7c783b19272a83b23bce56a5263163554b345c6f7ffedac517e"
							}
						],
						"outputs": [
							{
								"features": "Plain",
								"commit": "091454e23b4dbc71f546a41035d69f4c87d0f6efb5ceb119cc0d2eef80ba1928d7",
								"proof": "1a32a93de1dad833b4ae66d042784c435f60ac452f769d2d778772b3e2f2ca9fb16191636222b35866f273935f657ff37e1d38b877e12b7bcce98b1aa71f47a701b9ed8c648e2d6ab18ac0f8f7cf4a7c0aebb2c15681a684ec6f4d385e5db20e7bf9e6f3d8554ada1b82ac2fa9b77cb0a4c4c6b6c740d938fc0c6031a1cc0c0839701e6dab439c4dcdb32ca87d510b582efbabe8f8b783a330bc2c4451d1c2949a6ad901d40f7abc6103fadebba22016a955eaec4a0215398afbc7d22a4ad5bf3103446f4fe5440ded3bd9db607a69b8ca7c005c09e82fa367febc532b8d5c573e2bcc65a972bf76cea98943d9baaf209c84b4b70d56444c22cd334c7299000122de110f957b7af1f4d7f3816e053c94731113fd098bd2c0ccbe4c19152dd07a8d137b453e5a9d19cca576b494f448c5673babf9122297e4d2f4bd4a5a768c4da040527816d6ff91edb57da4053df167a44d2d5cf194bf30a47bcdd4ff541638b3db02e8ac882fb00767bf50fe5bf1b6077c8ad4f163ce75f21c99f708a9bcc0676034351e5ca68894550fcca5ee868d3d9d87e164612f09c79f2676a4acd8a8266e0f794c49318f8a1595ee1ff4e55e9cf5f3361cc473a032bd3bbd36a085f0c03f9b451b472d6a6a7ea9d858fd42a49c2e68c25bf8f18dd8e691168fe6f10602c6ec04cbc2601afa479294da84ecb79bc9b225d8758f682a2df52882c586ead779711258a9443e43365df9d326ca9052615ce33efac4bd0452a18d5b294b9fcf86e860786a692bfbd84a8bf3a751adedd978b969177cd8897871c43cd28df40a4beefcc86b10e6822ba18673f396294c799e756c8a5f03c92499127ec567e9f5b794442c63be7119ce741e4e056f502ca4809f7c76dd6dad754a1b31201ca2e2540e125637e1da5d16c61e3bea90ded06892076268893c167e0faed26172f304900e"
							},
							{
								"features": "Plain",
								"commit": "09414416856d650cd42abad97943f8ea32ff19e7d5d10201ff790d1ca941f578ed",
								"proof": "bdd12075099d53912b42073fd9c2841f2e21dff01656e7f909e1bbd30ada9a18b2f645128676ecddaecbffdcce43e9ff0e850acbce0f9a1e3fc525a7424d09040da752a8db0c8173f31ec4696bf007bf76801f63cedeadc66f4198836494de20a3d48150776c819d2e0a8ef376622d8a1cef78cd6928b3aa38883f51594fa50c3a772c539071c1c05ac4fce08768076618e2d5c7b3d46e28f1459f84f143a943957a4294011b093caf0e077020caf0668b379525df35f626641be6e81d7b711f1b32a98596c1829b9671d574f793e7f9f08c9118bdda60577053456caace5071cc14b10a67205e1c263bb53990fcf4fbcaea9cae652bd9e7ad6c1573ff96cd9271ecf0fabb895cea13b80d59bf7093fa03907911f526cb60df2bf0d3e2d4b81be4bbae55c466d6b221fa70cb145e6550e37856d080304e104fb23be97ae1499b4d3a2f7a4550545a03c20d374c081ac4f592477e23a20f418bcc59d9b02f665b898400a74350b88d793d383a0dc57618d58711e85e221383abb170c4a7f1640f30f2fc8258074f882b56453befecf3a61ed194a8ad98d1f6ab38c565b7cde60a7bb258066d9c5363c6bd618a9b3473b70a516ad4a67c2571e62fec4970eb4df902143aa130d333825f0a4cde9f93d8249c32f26bfadb26be8a5ceb6b5b6cdd076baa1cbde1973d83e64a1b35075dba69682e51cedfb82484276d56cf9e0601a272c0148ce070c6019ab2882405900164871f6b59d2c2a9f5d92674fe58cd9e036752eae8fb58e0fc29e3d59330ac92c1f263988f67add07a22770c381f29a602785244dbd46e4416ca56f25fe0cdd21714bcdf58c28329e22124247416b8de61297b6bd1630b93692a3a81c3107689f35cf4be5a8472b31552973ef2bcee5a298a858a768eefd0e31a3936790dd1c6e1379fffa0235c188b2c0f8b8b41abb84c32c608"
							}
						],
						"kernels": [
							{
								"features": "Plain",
								"fee": "700000",
								"lock_height": "0",
								"excess": "000000000000000000000000000000000000000000000000000000000000000000",
								"excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
							}
						]
					}
				},
				"amount": "600000000",
				"fee": "700000",
				"height": "5",
				"lock_height": "0",
				"ttl_cutoff_height": null,
				"participant_data": [
					{
						"id": "0",
						"public_blind_excess": "028e1bbb43e6038efc42054778d0a1aa184b2cf4d51acb40a2a8dc049788d97bd2",
						"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
						"part_sig": null,
						"message": null,
						"message_sig": null
					},
					{
						"id": "1",
						"public_blind_excess": "03e14bacb4cfeda43edf6c1b0ffced9a358a119c7936bc68af724477eb91d9e4eb",
						"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
						"part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b129340313ed7db02f6fd9a16c23ae8d5801af4fdc2ea580e2dec26e3821d5c17",
						"message": null,
						"message_sig": null
					}
				]
			}
		}
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"id": 1,
		"result": {
		"Ok": {
				"amount": "600000000",
				"fee": "700000",
				"height": "5",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"lock_height": "0",
				"ttl_cutoff_height": null,
				"num_participants": 2,
				"payment_proof": null,
				"participant_data": [
					{
						"id": "0",
						"message": null,
						"message_sig": null,
						"part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b93f888685e13250c5cb6b830ff898264ce247c73d3ab47845c01bcc6455ecbe5",
						"public_blind_excess": "028e1bbb43e6038efc42054778d0a1aa184b2cf4d51acb40a2a8dc049788d97bd2",
						"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
					},
					{
						"id": "1",
						"message": null,
						"message_sig": null,
						"part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b129340313ed7db02f6fd9a16c23ae8d5801af4fdc2ea580e2dec26e3821d5c17",
						"public_blind_excess": "03e14bacb4cfeda43edf6c1b0ffced9a358a119c7936bc68af724477eb91d9e4eb",
						"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
					}
				],
				"tx": {
					"body": {
					"inputs": [
						{
							"commit": "09d8836ffd38ffca42567ef965fdcf1f35b05aeb357664d70cd482438ca0ca0c9e",
							"features": "Coinbase"
						},
						{
							"commit": "089be87c488db1e7c783b19272a83b23bce56a5263163554b345c6f7ffedac517e",
							"features": "Coinbase"
						}
					],
					"kernels": [
						{
							"excess": "08d09187cb93cf5d6b97b28e8ca529912bf35ec8773d3e9af9b3c174a270dc7f05",
							"excess_sig": "66074d25a751c4743342c90ad8ead9454daa00d9b9aed29bca321036d16c4b4da58bc9999cea000f52b45347c1c46a3a4f3f70719696a09289ede2a9c87b27fd",
							"features": "Plain",
							"fee": "700000",
							"lock_height": "0"
						}
					],
					"outputs": [
						{
							"commit": "091454e23b4dbc71f546a41035d69f4c87d0f6efb5ceb119cc0d2eef80ba1928d7",
							"features": "Plain",
							"proof": "1a32a93de1dad833b4ae66d042784c435f60ac452f769d2d778772b3e2f2ca9fb16191636222b35866f273935f657ff37e1d38b877e12b7bcce98b1aa71f47a701b9ed8c648e2d6ab18ac0f8f7cf4a7c0aebb2c15681a684ec6f4d385e5db20e7bf9e6f3d8554ada1b82ac2fa9b77cb0a4c4c6b6c740d938fc0c6031a1cc0c0839701e6dab439c4dcdb32ca87d510b582efbabe8f8b783a330bc2c4451d1c2949a6ad901d40f7abc6103fadebba22016a955eaec4a0215398afbc7d22a4ad5bf3103446f4fe5440ded3bd9db607a69b8ca7c005c09e82fa367febc532b8d5c573e2bcc65a972bf76cea98943d9baaf209c84b4b70d56444c22cd334c7299000122de110f957b7af1f4d7f3816e053c94731113fd098bd2c0ccbe4c19152dd07a8d137b453e5a9d19cca576b494f448c5673babf9122297e4d2f4bd4a5a768c4da040527816d6ff91edb57da4053df167a44d2d5cf194bf30a47bcdd4ff541638b3db02e8ac882fb00767bf50fe5bf1b6077c8ad4f163ce75f21c99f708a9bcc0676034351e5ca68894550fcca5ee868d3d9d87e164612f09c79f2676a4acd8a8266e0f794c49318f8a1595ee1ff4e55e9cf5f3361cc473a032bd3bbd36a085f0c03f9b451b472d6a6a7ea9d858fd42a49c2e68c25bf8f18dd8e691168fe6f10602c6ec04cbc2601afa479294da84ecb79bc9b225d8758f682a2df52882c586ead779711258a9443e43365df9d326ca9052615ce33efac4bd0452a18d5b294b9fcf86e860786a692bfbd84a8bf3a751adedd978b969177cd8897871c43cd28df40a4beefcc86b10e6822ba18673f396294c799e756c8a5f03c92499127ec567e9f5b794442c63be7119ce741e4e056f502ca4809f7c76dd6dad754a1b31201ca2e2540e125637e1da5d16c61e3bea90ded06892076268893c167e0faed26172f304900e"
						},
						{
							"commit": "09414416856d650cd42abad97943f8ea32ff19e7d5d10201ff790d1ca941f578ed",
							"features": "Plain",
							"proof": "bdd12075099d53912b42073fd9c2841f2e21dff01656e7f909e1bbd30ada9a18b2f645128676ecddaecbffdcce43e9ff0e850acbce0f9a1e3fc525a7424d09040da752a8db0c8173f31ec4696bf007bf76801f63cedeadc66f4198836494de20a3d48150776c819d2e0a8ef376622d8a1cef78cd6928b3aa38883f51594fa50c3a772c539071c1c05ac4fce08768076618e2d5c7b3d46e28f1459f84f143a943957a4294011b093caf0e077020caf0668b379525df35f626641be6e81d7b711f1b32a98596c1829b9671d574f793e7f9f08c9118bdda60577053456caace5071cc14b10a67205e1c263bb53990fcf4fbcaea9cae652bd9e7ad6c1573ff96cd9271ecf0fabb895cea13b80d59bf7093fa03907911f526cb60df2bf0d3e2d4b81be4bbae55c466d6b221fa70cb145e6550e37856d080304e104fb23be97ae1499b4d3a2f7a4550545a03c20d374c081ac4f592477e23a20f418bcc59d9b02f665b898400a74350b88d793d383a0dc57618d58711e85e221383abb170c4a7f1640f30f2fc8258074f882b56453befecf3a61ed194a8ad98d1f6ab38c565b7cde60a7bb258066d9c5363c6bd618a9b3473b70a516ad4a67c2571e62fec4970eb4df902143aa130d333825f0a4cde9f93d8249c32f26bfadb26be8a5ceb6b5b6cdd076baa1cbde1973d83e64a1b35075dba69682e51cedfb82484276d56cf9e0601a272c0148ce070c6019ab2882405900164871f6b59d2c2a9f5d92674fe58cd9e036752eae8fb58e0fc29e3d59330ac92c1f263988f67add07a22770c381f29a602785244dbd46e4416ca56f25fe0cdd21714bcdf58c28329e22124247416b8de61297b6bd1630b93692a3a81c3107689f35cf4be5a8472b31552973ef2bcee5a298a858a768eefd0e31a3936790dd1c6e1379fffa0235c188b2c0f8b8b41abb84c32c608"
						}
					]
					},
					"offset": "d202964900000000d302964900000000d402964900000000d502964900000000"
				},
				"version_info": {
					"orig_version": 3,
					"version": 3,
					"block_header_version": 6
				}
			}
		}
	}
	# "#
	# , true, 5, true, true, false, false);
	```
	 */
	fn finalize_tx(&self, token: Token, slate: VersionedSlate)
		-> Result<VersionedSlate, ErrorKind>;

	/**
	Networked version of [Owner::post_tx](struct.Owner.html#method.post_tx).

	# Json rpc example

	```
	# epic_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"id": 1,
		"method": "post_tx",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"tx": {
			"offset": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"body": {
				"inputs": [
					{
						"features": "Coinbase",
						"commit": "09d8836ffd38ffca42567ef965fdcf1f35b05aeb357664d70cd482438ca0ca0c9e"
					},
					{
						"features": "Coinbase",
						"commit": "089be87c488db1e7c783b19272a83b23bce56a5263163554b345c6f7ffedac517e"
					}
				],
				"kernels": [
					{
						"features": "Plain",
						"fee": "700000",
						"lock_height": "0",
						"excess": "08d09187cb93cf5d6b97b28e8ca529912bf35ec8773d3e9af9b3c174a270dc7f05",
						"excess_sig": "66074d25a751c4743342c90ad8ead9454daa00d9b9aed29bca321036d16c4b4da58bc9999cea000f52b45347c1c46a3a4f3f70719696a09289ede2a9c87b27fd"
					}
				],
				"outputs": [
					{
						"features": "Plain",
						"commit": "091454e23b4dbc71f546a41035d69f4c87d0f6efb5ceb119cc0d2eef80ba1928d7",
						"proof": "1a32a93de1dad833b4ae66d042784c435f60ac452f769d2d778772b3e2f2ca9fb16191636222b35866f273935f657ff37e1d38b877e12b7bcce98b1aa71f47a701b9ed8c648e2d6ab18ac0f8f7cf4a7c0aebb2c15681a684ec6f4d385e5db20e7bf9e6f3d8554ada1b82ac2fa9b77cb0a4c4c6b6c740d938fc0c6031a1cc0c0839701e6dab439c4dcdb32ca87d510b582efbabe8f8b783a330bc2c4451d1c2949a6ad901d40f7abc6103fadebba22016a955eaec4a0215398afbc7d22a4ad5bf3103446f4fe5440ded3bd9db607a69b8ca7c005c09e82fa367febc532b8d5c573e2bcc65a972bf76cea98943d9baaf209c84b4b70d56444c22cd334c7299000122de110f957b7af1f4d7f3816e053c94731113fd098bd2c0ccbe4c19152dd07a8d137b453e5a9d19cca576b494f448c5673babf9122297e4d2f4bd4a5a768c4da040527816d6ff91edb57da4053df167a44d2d5cf194bf30a47bcdd4ff541638b3db02e8ac882fb00767bf50fe5bf1b6077c8ad4f163ce75f21c99f708a9bcc0676034351e5ca68894550fcca5ee868d3d9d87e164612f09c79f2676a4acd8a8266e0f794c49318f8a1595ee1ff4e55e9cf5f3361cc473a032bd3bbd36a085f0c03f9b451b472d6a6a7ea9d858fd42a49c2e68c25bf8f18dd8e691168fe6f10602c6ec04cbc2601afa479294da84ecb79bc9b225d8758f682a2df52882c586ead779711258a9443e43365df9d326ca9052615ce33efac4bd0452a18d5b294b9fcf86e860786a692bfbd84a8bf3a751adedd978b969177cd8897871c43cd28df40a4beefcc86b10e6822ba18673f396294c799e756c8a5f03c92499127ec567e9f5b794442c63be7119ce741e4e056f502ca4809f7c76dd6dad754a1b31201ca2e2540e125637e1da5d16c61e3bea90ded06892076268893c167e0faed26172f304900e"
					},
					{
						"features": "Plain",
						"commit": "09414416856d650cd42abad97943f8ea32ff19e7d5d10201ff790d1ca941f578ed",
						"proof": "bdd12075099d53912b42073fd9c2841f2e21dff01656e7f909e1bbd30ada9a18b2f645128676ecddaecbffdcce43e9ff0e850acbce0f9a1e3fc525a7424d09040da752a8db0c8173f31ec4696bf007bf76801f63cedeadc66f4198836494de20a3d48150776c819d2e0a8ef376622d8a1cef78cd6928b3aa38883f51594fa50c3a772c539071c1c05ac4fce08768076618e2d5c7b3d46e28f1459f84f143a943957a4294011b093caf0e077020caf0668b379525df35f626641be6e81d7b711f1b32a98596c1829b9671d574f793e7f9f08c9118bdda60577053456caace5071cc14b10a67205e1c263bb53990fcf4fbcaea9cae652bd9e7ad6c1573ff96cd9271ecf0fabb895cea13b80d59bf7093fa03907911f526cb60df2bf0d3e2d4b81be4bbae55c466d6b221fa70cb145e6550e37856d080304e104fb23be97ae1499b4d3a2f7a4550545a03c20d374c081ac4f592477e23a20f418bcc59d9b02f665b898400a74350b88d793d383a0dc57618d58711e85e221383abb170c4a7f1640f30f2fc8258074f882b56453befecf3a61ed194a8ad98d1f6ab38c565b7cde60a7bb258066d9c5363c6bd618a9b3473b70a516ad4a67c2571e62fec4970eb4df902143aa130d333825f0a4cde9f93d8249c32f26bfadb26be8a5ceb6b5b6cdd076baa1cbde1973d83e64a1b35075dba69682e51cedfb82484276d56cf9e0601a272c0148ce070c6019ab2882405900164871f6b59d2c2a9f5d92674fe58cd9e036752eae8fb58e0fc29e3d59330ac92c1f263988f67add07a22770c381f29a602785244dbd46e4416ca56f25fe0cdd21714bcdf58c28329e22124247416b8de61297b6bd1630b93692a3a81c3107689f35cf4be5a8472b31552973ef2bcee5a298a858a768eefd0e31a3936790dd1c6e1379fffa0235c188b2c0f8b8b41abb84c32c608"
					}
				]

			}
		},
		"fluff": false
		}
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , true, 5, true, true, true, false);
	```
	 */

	fn post_tx(&self, token: Token, tx: TransactionV3, fluff: bool) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::cancel_tx](struct.Owner.html#method.cancel_tx).

	# Json rpc example

	```
	# epic_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "cancel_tx",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"tx_id": null,
			"tx_slate_id": "0436430c-2b02-624c-2032-570501212b00"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , true, 5, true, true, false, false);
	```
	 */
	fn cancel_tx(
		&self,
		token: Token,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::get_stored_tx](struct.Owner.html#method.get_stored_tx).

	# Json rpc example

	```
	# epic_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_stored_tx",
		"id": 1,
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"tx": {
				"amount_credited": "59993000000",
				"amount_debited": "120000000000",
				"confirmation_ts": "2019-01-15T16:01:26Z",
				"confirmed": false,
				"creation_ts": "2019-01-15T16:01:26Z",
				"fee": "7000000",
				"id": 5,
				"messages": {
					"messages": [
						{
							"id": "0",
							"message": null,
							"message_sig": null,
							"public_key": "033ac2158fa0077f087de60c19d8e431753baa5b63b6e1477f05a2a6e7190d4592"
						},
						{
							"id": "1",
							"message": null,
							"message_sig": null,
							"public_key": "024f9bc78c984c78d6e916d3a00746aa30fa1172124c8dbc0cbddcb7b486719bc7"
						}
					]
				},
				"num_inputs": 2,
				"num_outputs": 1,
				"parent_key_id": "0200000000000000000000000000000000",
				"stored_tx": "0436430c-2b02-624c-2032-570501212b00.epictx",
				"tx_slate_id": "0436430c-2b02-624c-2032-570501212b00",
				"tx_type": "TxSent",
				"kernel_excess": null,
				"kernel_lookup_min_height": null
			}
		}
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"id": 1,
		"result": {
			"Ok": {
				"body": {
				"inputs": [
					{
						"commit": "09d8836ffd38ffca42567ef965fdcf1f35b05aeb357664d70cd482438ca0ca0c9e",
						"features": "Coinbase"
					},
					{
						"commit": "089be87c488db1e7c783b19272a83b23bce56a5263163554b345c6f7ffedac517e",
						"features": "Coinbase"
					}
				],
				"kernels": [
					{
						"excess": "000000000000000000000000000000000000000000000000000000000000000000",
						"excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
						"features": "Plain",
						"fee": "700000",
						"lock_height": "0"
					}
				],
				"outputs": [
					{
						"commit": "091454e23b4dbc71f546a41035d69f4c87d0f6efb5ceb119cc0d2eef80ba1928d7",
						"features": "Plain",
						"proof": "1a32a93de1dad833b4ae66d042784c435f60ac452f769d2d778772b3e2f2ca9fb16191636222b35866f273935f657ff37e1d38b877e12b7bcce98b1aa71f47a701b9ed8c648e2d6ab18ac0f8f7cf4a7c0aebb2c15681a684ec6f4d385e5db20e7bf9e6f3d8554ada1b82ac2fa9b77cb0a4c4c6b6c740d938fc0c6031a1cc0c0839701e6dab439c4dcdb32ca87d510b582efbabe8f8b783a330bc2c4451d1c2949a6ad901d40f7abc6103fadebba22016a955eaec4a0215398afbc7d22a4ad5bf3103446f4fe5440ded3bd9db607a69b8ca7c005c09e82fa367febc532b8d5c573e2bcc65a972bf76cea98943d9baaf209c84b4b70d56444c22cd334c7299000122de110f957b7af1f4d7f3816e053c94731113fd098bd2c0ccbe4c19152dd07a8d137b453e5a9d19cca576b494f448c5673babf9122297e4d2f4bd4a5a768c4da040527816d6ff91edb57da4053df167a44d2d5cf194bf30a47bcdd4ff541638b3db02e8ac882fb00767bf50fe5bf1b6077c8ad4f163ce75f21c99f708a9bcc0676034351e5ca68894550fcca5ee868d3d9d87e164612f09c79f2676a4acd8a8266e0f794c49318f8a1595ee1ff4e55e9cf5f3361cc473a032bd3bbd36a085f0c03f9b451b472d6a6a7ea9d858fd42a49c2e68c25bf8f18dd8e691168fe6f10602c6ec04cbc2601afa479294da84ecb79bc9b225d8758f682a2df52882c586ead779711258a9443e43365df9d326ca9052615ce33efac4bd0452a18d5b294b9fcf86e860786a692bfbd84a8bf3a751adedd978b969177cd8897871c43cd28df40a4beefcc86b10e6822ba18673f396294c799e756c8a5f03c92499127ec567e9f5b794442c63be7119ce741e4e056f502ca4809f7c76dd6dad754a1b31201ca2e2540e125637e1da5d16c61e3bea90ded06892076268893c167e0faed26172f304900e"
					},
					{
						"commit": "09414416856d650cd42abad97943f8ea32ff19e7d5d10201ff790d1ca941f578ed",
						"features": "Plain",
						"proof": "bdd12075099d53912b42073fd9c2841f2e21dff01656e7f909e1bbd30ada9a18b2f645128676ecddaecbffdcce43e9ff0e850acbce0f9a1e3fc525a7424d09040da752a8db0c8173f31ec4696bf007bf76801f63cedeadc66f4198836494de20a3d48150776c819d2e0a8ef376622d8a1cef78cd6928b3aa38883f51594fa50c3a772c539071c1c05ac4fce08768076618e2d5c7b3d46e28f1459f84f143a943957a4294011b093caf0e077020caf0668b379525df35f626641be6e81d7b711f1b32a98596c1829b9671d574f793e7f9f08c9118bdda60577053456caace5071cc14b10a67205e1c263bb53990fcf4fbcaea9cae652bd9e7ad6c1573ff96cd9271ecf0fabb895cea13b80d59bf7093fa03907911f526cb60df2bf0d3e2d4b81be4bbae55c466d6b221fa70cb145e6550e37856d080304e104fb23be97ae1499b4d3a2f7a4550545a03c20d374c081ac4f592477e23a20f418bcc59d9b02f665b898400a74350b88d793d383a0dc57618d58711e85e221383abb170c4a7f1640f30f2fc8258074f882b56453befecf3a61ed194a8ad98d1f6ab38c565b7cde60a7bb258066d9c5363c6bd618a9b3473b70a516ad4a67c2571e62fec4970eb4df902143aa130d333825f0a4cde9f93d8249c32f26bfadb26be8a5ceb6b5b6cdd076baa1cbde1973d83e64a1b35075dba69682e51cedfb82484276d56cf9e0601a272c0148ce070c6019ab2882405900164871f6b59d2c2a9f5d92674fe58cd9e036752eae8fb58e0fc29e3d59330ac92c1f263988f67add07a22770c381f29a602785244dbd46e4416ca56f25fe0cdd21714bcdf58c28329e22124247416b8de61297b6bd1630b93692a3a81c3107689f35cf4be5a8472b31552973ef2bcee5a298a858a768eefd0e31a3936790dd1c6e1379fffa0235c188b2c0f8b8b41abb84c32c608"
					}
				]
				},
				"offset": "d202964900000000d302964900000000d402964900000000d502964900000000"
			}
		}
	}
	# "#
	# , true, 5, true, true, false, false);
	```
	 */
	fn get_stored_tx(
		&self,
		token: Token,
		tx: &TxLogEntry,
	) -> Result<Option<TransactionV3>, ErrorKind>;

	/**
	Networked version of [Owner::verify_slate_messages](struct.Owner.html#method.verify_slate_messages).

	# Json rpc example

	```
	# epic_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "verify_slate_messages",
		"id": 1,
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"slate": {
				"amount": "1457920000",
				"fee": "8000000",
				"height": "4",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"lock_height": "4",
				"ttl_cutoff_height": null,
				"num_participants": 2,
				"participant_data": [
				{
					"id": "0",
					"message": "my message",
					"message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b1d4c1358be398f801eb90d933774b5218fa7e769b11c4c640402253353656f75",
					"part_sig": null,
					"public_blind_excess": "034b4df2f0558b73ea72a1ca5c4ab20217c66bbe0829056fca7abe76888e9349ee",
					"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
				}
				],
				"tx": {
					"body": {
						"inputs": [
						{
							"commit": "08e1da9e6dc4d6e808a718b2f110a991dd775d65ce5ae408a4e1f002a4961aa9e7",
							"features": "Coinbase"
						}
						],
						"kernels": [
						{
							"excess": "000000000000000000000000000000000000000000000000000000000000000000",
							"excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
							"features": "HeightLocked",
							"fee": "8000000",
							"lock_height": "4"
						}
						],
						"outputs": [
						{
							"commit": "094be57c91787fc2033d5d97fae099f1a6ddb37ea48370f1a138f09524c767fdd3",
							"features": "Plain",
							"proof": "2a42e9e902b70ce44e1fccb14de87ee0a97100bddf12c6bead1b9c5f4eb60300f29c13094fa12ffeee238fb4532b18f6b61cf51b23c1c7e1ad2e41560dc27edc0a2b9e647a0b3e4e806fced5b65e61d0f1f5197d3e2285c632d359e27b6b9206b2caffea4f67e0c7a2812e7a22c134b98cf89bd43d9f28b8bec25cce037a0ac5b1ae8f667e54e1250813a5263004486b4465ad4e641ab2b535736ea26535a11013564f08f483b7dab1c2bcc3ee38eadf2f7850eff7e3459a4bbabf9f0cf6c50d0c0a4120565cd4a2ce3e354c11721cd695760a24c70e0d5a0dfc3c5dcd51dfad6de2c237a682f36dc0b271f21bb3655e5333016aaa42c2efa1446e5f3c0a79ec417c4d30f77556951cb0f05dbfafb82d9f95951a9ea241fda2a6388f73ace036b98acce079f0e4feebccc96290a86dcc89118a901210b245f2d114cf94396e4dbb461e82aa26a0581389707957968c7cdc466213bb1cd417db207ef40c05842ab67a01a9b96eb1430ebc26e795bb491258d326d5174ad549401059e41782121e506744af8af9d8e493644a87d613600888541cbbe538c625883f3eb4aa3102c5cfcc25de8e97af8927619ce6a731b3b8462d51d993066b935b0648d2344ad72e4fd70f347fbd81041042e5ea31cc7b2e3156a920b80ecba487b950ca32ca95fae85b759c936246ecf441a9fdd95e8fee932d6782cdec686064018c857efc47fb4b2a122600d5fdd79af2486f44df7e629184e1c573bc0a9b3feb40b190ef2861a1ab45e2ac2201b9cd42e495deea247269820ed32389a2810ad6c0f9a296d2a2d9c54089fed50b7f5ecfcd33ab9954360e1d7f5598c32128cfcf2a1d8bf14616818da8a5343bfa88f0eedf392e9d4ab1ace1b60324129cd4852c2e27813a9cf71a6ae6229a4fcecc1a756b3e664c5f50af333082616815a3bec8fc0b75b8e4e767d719"
						}
						]
					},
					"offset": "d202964900000000d302964900000000d402964900000000d502964900000000",
					"payment_proof": null
				},
				"version_info": {
					"orig_version": 3,
					"version": 3,
					"block_header_version": 6
				}
			}
		}
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"id": 1,
		"result": {
			"Ok": null
		}
	}
	# "#
	# ,true, 0 ,false, false, false, false);
	```
	*/
	fn verify_slate_messages(&self, token: Token, slate: VersionedSlate) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::scan](struct.Owner.html#method.scan).

	# Json rpc example

	```
	# epic_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "scan",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"start_height": 1,
			"delete_unconfirmed": false
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , true, 1, false, false, false, false);
	```
	 */
	fn scan(
		&self,
		token: Token,
		start_height: Option<u64>,
		delete_unconfirmed: bool,
	) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::node_height](struct.Owner.html#method.node_height).

	# Json rpc example

	```
	# epic_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "node_height",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": {
				"header_hash": "d4b3d3c40695afd8c7760f8fc423565f7d41310b7a4e1c4a4a7950a66f16240d",
				"height": "5",
				"updated_from_node": true
			}
		}
	}
	# "#
	# , true, 5, false, false, false, false);
	```
	 */
	fn node_height(&self, token: Token) -> Result<NodeHeightResult, ErrorKind>;

	/**
		Initializes the secure JSON-RPC API. This function must be called and a shared key
		established before any other OwnerAPI JSON-RPC function can be called.

		The shared key will be derived using ECDH with the provided public key on the secp256k1 curve. This
		function will return its public key used in the derivation, which the caller should multiply by its
		private key to derive the shared key.

		Once the key is established, all further requests and responses are encrypted and decrypted with the
		following parameters:
		* AES-256 in GCM mode with 128-bit tags and 96 bit nonces
		* 12 byte nonce which must be included in each request/response to use on the decrypting side
		* Empty vector for additional data
		* Suffix length = AES-256 GCM mode tag length = 16 bytes
		*

		Fully-formed JSON-RPC requests (as documented) should be encrypted using these parameters, encoded
		into base64 and included with the one-time nonce in a request for the `encrypted_request_v3` method
		as follows:

		```
		# let s = r#"
		{
			 "jsonrpc": "2.0",
			 "method": "encrypted_request_v3",
			 "id": "1",
			 "params": {
					"nonce": "ef32...",
					"body_enc": "e0bcd..."
			 }
		}
		# "#;
		```

		With a typical response being:

		```
		# let s = r#"{
		{
			 "jsonrpc": "2.0",
			 "method": "encrypted_response_v3",
			 "id": "1",
			 "Ok": {
					"nonce": "340b...",
					"body_enc": "3f09c..."
			 }
		}
		# }"#;
		```

	*/

	fn init_secure_api(&self, ecdh_pubkey: ECDHPubkey) -> Result<ECDHPubkey, ErrorKind>;

	/**
	Networked version of [Owner::get_top_level_directory](struct.Owner.html#method.get_top_level_directory).

	# Json rpc example

	```
	# epic_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_top_level_directory",
		"params": {
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": "/doctest/dir"
		}
	}
	# "#
	# , true, 5, false, false, false, false);
	```
	*/

	fn get_top_level_directory(&self) -> Result<String, ErrorKind>;

	/**
	Networked version of [Owner::set_top_level_directory](struct.Owner.html#method.set_top_level_directory).

	# Json rpc example

	```
	# epic_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "set_top_level_directory",
		"params": {
			"dir": "/home/wallet_user/my_wallet_dir"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , true, 5, false, false, false, false);
	```
	*/

	fn set_top_level_directory(&self, dir: String) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::create_config](struct.Owner.html#method.create_config).

	# Json rpc example

	Both the `wallet_config` and `logging_config` parameters can be `null`, the examples
	below are for illustration. Note that the values provided for `log_file_path` and `data_file_dir`
	will be ignored and replaced with the actual values based on the value of `get_top_level_directory`

	```
	# epic_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "create_config",
		"params": {
			"chain_type": "Mainnet",
			"wallet_config": {
				"epicbox_domain": "epicbox.io",
				"epicbox_address_index": 0,
				"chain_type": null,
				"api_listen_interface": "127.0.0.1",
				"api_listen_port": 3415,
				"owner_api_listen_port": 3420,
				"api_secret_path": null,
				"node_api_secret_path": null,
				"check_node_api_http_addr": "http://127.0.0.1:3413",
				"owner_api_include_foreign": false,
				"data_file_dir": "/path/to/data/file/dir",
				"no_commit_cache": null,
				"tls_certificate_file": null,
				"tls_certificate_key": null,
				"dark_background_color_scheme": null,
				"keybase_notify_ttl": null
			},
			"logging_config": {
				"log_to_stdout": false,
				"stdout_log_level": "Info",
				"log_to_file": true,
				"file_log_level": "Debug",
				"log_file_path": "/path/to/log/file",
				"log_file_append": true,
				"log_max_size": null,
				"log_max_files": null,
				"tui_running": null
			},
			"tor_config" : {
				"use_tor_listener": true,
				"socks_proxy_addr": "127.0.0.1:9050",
				"send_config_dir": "."
			},
			"epicbox_config" : {
				"epicbox_domain": "epicbox.io",
				"epicbox_port": 443,
				"epicbox_protocol_unsecure": false,
				"epicbox_address_index": 0
			}
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , true, 5, false, false, false, false);
	```
	*/
	fn create_config(
		&self,
		chain_type: global::ChainTypes,
		wallet_config: Option<WalletConfig>,
		logging_config: Option<LoggingConfig>,
		tor_config: Option<TorConfig>,
		epicbox_config: Option<EpicboxConfig>,
	) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::create_wallet](struct.Owner.html#method.create_wallet).

	# Json rpc example

	```
	# epic_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "create_wallet",
		"params": {
			"name": null,
			"mnemonic": null,
			"mnemonic_length": 0,
			"password": "my_secret_password"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , true, 0, false, false, false, false);
	```
	*/

	fn create_wallet(
		&self,
		name: Option<String>,
		mnemonic: Option<String>,
		mnemonic_length: u32,
		password: String,
	) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::open_wallet](struct.Owner.html#method.open_wallet).

	# Json rpc example

	```
	# epic_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "open_wallet",
		"params": {
			"name": null,
			"password": "my_secret_password"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": "d096b3cb75986b3b13f80b8f5243a9edf0af4c74ac37578c5a12cfb5b59b1868"
		}
	}
	# "#
	# , true, 0, false, false, false, false);
	```
	*/

	fn open_wallet(&self, name: Option<String>, password: String) -> Result<Token, ErrorKind>;

	/**
	Networked version of [Owner::close_wallet](struct.Owner.html#method.close_wallet).

	# Json rpc example

	```
	# epic_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "close_wallet",
		"params": {
			"name": null
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , true, 0, false, false, false, false);
	```
	*/

	fn close_wallet(&self, name: Option<String>) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::get_mnemonic](struct.Owner.html#method.get_mnemonic).

	# Json rpc example

	```
	# epic_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_mnemonic",
		"params": {
			"name": null,
			"password": ""
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": "fat twenty mean degree forget shell check candy immense awful flame next during february bulb bike sun wink theory day kiwi embrace peace lunch"
		}
	}
	# "#
	# , true, 0, false, false, false, false);
	```
	*/

	fn get_mnemonic(&self, name: Option<String>, password: String) -> Result<String, ErrorKind>;

	/**
	Networked version of [Owner::change_password](struct.Owner.html#method.change_password).

	# Json rpc example

	```
	# epic_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "change_password",
		"params": {
			"name": null,
			"old": "",
			"new": "new_password"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , true, 0, false, false, false, false);
	```
	*/
	fn change_password(
		&self,
		name: Option<String>,
		old: String,
		new: String,
	) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::delete_wallet](struct.Owner.html#method.delete_wallet).

	# Json rpc example

	```
	# epic_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "delete_wallet",
		"params": {
			"name": null
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , true, 0, false, false, false, false);
	```
	*/
	fn delete_wallet(&self, name: Option<String>) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::start_updated](struct.Owner.html#method.start_updater).

	# Json rpc example

	```
	# epic_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "start_updater",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"frequency": 30000
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , true, 0, false, false, false, false);
	```
	*/

	fn start_updater(&self, token: Token, frequency: u32) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::stop_updater](struct.Owner.html#method.stop_updater).

	# Json rpc example

	```
	# epic_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "stop_updater",
		"params": null,
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , true, 0, false, false, false, false);
	```
	*/
	fn stop_updater(&self) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::get_updater_messages](struct.Owner.html#method.get_updater_messages).

	# Json rpc example

	```
	# epic_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_updater_messages",
		"params": {
			"count": 1
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": []
		}
	}
	# "#
	# , true, 0, false, false, false, false);
	```
	*/

	fn get_updater_messages(&self, count: u32) -> Result<Vec<StatusMessage>, ErrorKind>;

	/**
	Networked version of [Owner::get_public_address](struct.Owner.html#method.get_public_address).

	# Json rpc example

	```
	# epic_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_public_address",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"derivation_index": 0
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok":  {
				"domain": "",
				"port": 0,
				"public_key": "esWVpwMwUyYoxta4EpGPQQEBYdm3wBqCcggVswNyquoLHaLjFdwq"
			}
		}
	}
	# "#
	# , true, 0, false, false, false, false);
	```
	*/

	fn get_public_address(
		&self,
		token: Token,
		derivation_index: u32,
	) -> Result<EpicboxAddress, ErrorKind>;

	/**
	Networked version of [Owner::get_public_proof_address](struct.Owner.html#method.get_public_proof_address).

	# Json rpc example

	```
	# epic_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_public_proof_address",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"derivation_index": 0
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": "32cdd63928854f8b2628b1dce4626ddcdf35d56cb7cfdf7d64cca5822b78d4d3"
		}
	}
	# "#
	# , true, 0, false, false, false, false);
	```
	*/

	fn get_public_proof_address(
		&self,
		token: Token,
		derivation_index: u32,
	) -> Result<PubAddress, ErrorKind>;

	/**
	Networked version of [Owner::proof_address_from_onion_v3](struct.Owner.html#method.proof_address_from_onion_v3).

	# Json rpc example

	```
	# epic_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "proof_address_from_onion_v3",
		"params": {
			"address_v3": "2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": "d03c09e9c19bb74aa9ea44e0fe5ae237a9bf40bddf0941064a80913a4459c8bb"
		}
	}
	# "#
	# , true, 0, false, false, false, false);
	```
	*/

	fn proof_address_from_onion_v3(&self, address_v3: String) -> Result<PubAddress, ErrorKind>;

	/**
	Networked version of [Owner::retrieve_payment_proof](struct.Owner.html#method.retrieve_payment_proof).
	```
	# epic_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "retrieve_payment_proof",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"refresh_from_node": true,
			"tx_id": null,
			"tx_slate_id": "0436430c-2b02-624c-2032-570501212b00"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": {
				"amount": "600000000",
				"excess": "08d09187cb93cf5d6b97b28e8ca529912bf35ec8773d3e9af9b3c174a270dc7f05",
				"recipient_address": "pa7wkkdgs5bkteha7lykl7ff2wztgdrxxo442xdcq2lnaphe5aidd4id",
				"recipient_sig": "b9ac5e18fd13ce72923cc47796bd5af09b5247c52da3634c9b934d4e111a43f53f1c55e3f3be36a79450e18f8989d81a0c21c4b2c16c208753a9971a5ffee406",
				"sender_address": "glg5mojiqvhywjriwhooiytn3tptlvlmw7h567lezssyek3y2tjzznad",
				"sender_sig": "d26fa48e9a32058b4dc9e9098edd3b98bf2e5286024adc5f7555aa4804acdb1c5506412dfae7d087c138d727da427e14c6c5b7dc2008fc7ed55ab95e8bac3e06"
			}
		}
	}
	# "#
	# , true, 5, true, true, true, true);
	```
	*/

	fn retrieve_payment_proof(
		&self,
		token: Token,
		refresh_from_node: bool,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<PaymentProof, ErrorKind>;

	/**
	Networked version of [Owner::verify_payment_proof](struct.Owner.html#method.verify_payment_proof).
	```
	# epic_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "verify_payment_proof",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"proof": {
				"amount": "600000000",
				"excess": "08d09187cb93cf5d6b97b28e8ca529912bf35ec8773d3e9af9b3c174a270dc7f05",
				"recipient_address": "pa7wkkdgs5bkteha7lykl7ff2wztgdrxxo442xdcq2lnaphe5aidd4id",
				"recipient_sig": "b9ac5e18fd13ce72923cc47796bd5af09b5247c52da3634c9b934d4e111a43f53f1c55e3f3be36a79450e18f8989d81a0c21c4b2c16c208753a9971a5ffee406",
				"sender_address": "glg5mojiqvhywjriwhooiytn3tptlvlmw7h567lezssyek3y2tjzznad",
				"sender_sig": "d26fa48e9a32058b4dc9e9098edd3b98bf2e5286024adc5f7555aa4804acdb1c5506412dfae7d087c138d727da427e14c6c5b7dc2008fc7ed55ab95e8bac3e06"
			}
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": [
				true,
				false
			]
		}
	}
	# "#
	# , true, 5, true, true, true, true);
	```
	*/

	fn verify_payment_proof(
		&self,
		token: Token,
		proof: PaymentProof,
	) -> Result<(bool, bool), ErrorKind>;

	/**
	Networked version of [Owner::set_tor_config](struct.Owner.html#method.set_tor_config).

	# Json rpc example

	```
	# epic_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "set_tor_config",
		"params": {
			"tor_config": {
				"use_tor_listener": true,
				"socks_proxy_addr": "127.0.0.1:59050",
				"send_config_dir": "."
			}
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , true, 0, false, false, false, false);
	```
	*/
	fn set_tor_config(&self, tor_config: Option<TorConfig>) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::set_epicbox_config](struct.Owner.html#method.set_epicbox_config).

	# Json rpc example

	```
	# epic_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "set_epicbox_config",
		"params": {
			"epicbox_config": {
				"epicbox_domain": "epicbox.io",
				"epicbox_port": 443,
				"epicbox_protocol_unsecure": false,
				"epicbox_address_index": 0
			}
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , true, 0, false, false, false, false);
	```
	*/
	fn set_epicbox_config(&self, epicbox_config: Option<EpicboxConfig>) -> Result<(), ErrorKind>;
}

impl<L, C, K> OwnerRpcS for Owner<L, C, K>
where
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	fn accounts(&self, token: Token) -> Result<Vec<AcctPathMapping>, ErrorKind> {
		Owner::accounts(self, (&token.keychain_mask).as_ref()).map_err(|e| e.kind())
	}

	fn create_account_path(&self, token: Token, label: &String) -> Result<Identifier, ErrorKind> {
		Owner::create_account_path(self, (&token.keychain_mask).as_ref(), label)
			.map_err(|e| e.kind())
	}

	fn set_active_account(&self, token: Token, label: &String) -> Result<(), ErrorKind> {
		Owner::set_active_account(self, (&token.keychain_mask).as_ref(), label)
			.map_err(|e| e.kind())
	}

	fn retrieve_outputs(
		&self,
		token: Token,
		include_spent: bool,
		refresh_from_node: bool,
		tx_id: Option<u32>,
	) -> Result<(bool, Vec<OutputCommitMapping>), ErrorKind> {
		Owner::retrieve_outputs(
			self,
			(&token.keychain_mask).as_ref(),
			include_spent,
			refresh_from_node,
			false,
			tx_id,
		)
		.map_err(|e| e.kind())
	}

	fn retrieve_txs(
		&self,
		token: Token,
		refresh_from_node: bool,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(bool, Vec<TxLogEntry>), ErrorKind> {
		Owner::retrieve_txs(
			self,
			(&token.keychain_mask).as_ref(),
			refresh_from_node,
			tx_id,
			tx_slate_id,
		)
		.map_err(|e| e.kind())
	}

	fn retrieve_summary_info(
		&self,
		token: Token,
		refresh_from_node: bool,
		minimum_confirmations: u64,
	) -> Result<(bool, WalletInfo), ErrorKind> {
		Owner::retrieve_summary_info(
			self,
			(&token.keychain_mask).as_ref(),
			refresh_from_node,
			minimum_confirmations,
		)
		.map_err(|e| e.kind())
	}

	fn init_send_tx(&self, token: Token, args: InitTxArgs) -> Result<VersionedSlate, ErrorKind> {
		let slate = Owner::init_send_tx(self, (&token.keychain_mask).as_ref(), args)
			.map_err(|e| e.kind())?;
		let version = SlateVersion::V3;
		Ok(VersionedSlate::into_version(slate, version))
	}

	fn issue_invoice_tx(
		&self,
		token: Token,
		args: IssueInvoiceTxArgs,
	) -> Result<VersionedSlate, ErrorKind> {
		let slate = Owner::issue_invoice_tx(self, (&token.keychain_mask).as_ref(), args)
			.map_err(|e| e.kind())?;
		let version = SlateVersion::V3;
		Ok(VersionedSlate::into_version(slate, version))
	}

	fn process_invoice_tx(
		&self,
		token: Token,
		in_slate: VersionedSlate,
		args: InitTxArgs,
	) -> Result<VersionedSlate, ErrorKind> {
		let out_slate = Owner::process_invoice_tx(
			self,
			(&token.keychain_mask).as_ref(),
			&Slate::from(in_slate),
			args,
		)
		.map_err(|e| e.kind())?;
		let version = SlateVersion::V3;
		Ok(VersionedSlate::into_version(out_slate, version))
	}

	fn finalize_tx(
		&self,
		token: Token,
		in_slate: VersionedSlate,
	) -> Result<VersionedSlate, ErrorKind> {
		let out_slate = Owner::finalize_tx(
			self,
			(&token.keychain_mask).as_ref(),
			&Slate::from(in_slate),
		)
		.map_err(|e| e.kind())?;
		let version = SlateVersion::V3;
		Ok(VersionedSlate::into_version(out_slate, version))
	}

	fn tx_lock_outputs(
		&self,
		token: Token,
		in_slate: VersionedSlate,
		participant_id: usize,
	) -> Result<(), ErrorKind> {
		Owner::tx_lock_outputs(
			self,
			(&token.keychain_mask).as_ref(),
			&Slate::from(in_slate),
			participant_id,
		)
		.map_err(|e| e.kind())
	}

	fn cancel_tx(
		&self,
		token: Token,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(), ErrorKind> {
		Owner::cancel_tx(self, (&token.keychain_mask).as_ref(), tx_id, tx_slate_id)
			.map_err(|e| e.kind())
	}

	fn get_stored_tx(
		&self,
		token: Token,
		tx: &TxLogEntry,
	) -> Result<Option<TransactionV3>, ErrorKind> {
		Owner::get_stored_tx(self, (&token.keychain_mask).as_ref(), tx)
			.map(|x| x.map(|y| TransactionV3::from(y)))
			.map_err(|e| e.kind())
	}

	fn post_tx(&self, token: Token, tx: TransactionV3, fluff: bool) -> Result<(), ErrorKind> {
		Owner::post_tx(
			self,
			(&token.keychain_mask).as_ref(),
			&Transaction::from(tx),
			fluff,
		)
		.map_err(|e| e.kind())
	}

	fn verify_slate_messages(&self, token: Token, slate: VersionedSlate) -> Result<(), ErrorKind> {
		Owner::verify_slate_messages(self, (&token.keychain_mask).as_ref(), &Slate::from(slate))
			.map_err(|e| e.kind())
	}

	fn scan(
		&self,
		token: Token,
		start_height: Option<u64>,
		delete_unconfirmed: bool,
	) -> Result<(), ErrorKind> {
		Owner::scan(
			self,
			(&token.keychain_mask).as_ref(),
			start_height,
			delete_unconfirmed,
		)
		.map_err(|e| e.kind())
	}

	fn node_height(&self, token: Token) -> Result<NodeHeightResult, ErrorKind> {
		Owner::node_height(self, (&token.keychain_mask).as_ref()).map_err(|e| e.kind())
	}

	fn init_secure_api(&self, ecdh_pubkey: ECDHPubkey) -> Result<ECDHPubkey, ErrorKind> {
		let secp_inst = static_secp_instance();
		let secp = secp_inst.lock();
		let sec_key = SecretKey::new(&secp, &mut thread_rng());

		let mut shared_pubkey = ecdh_pubkey.ecdh_pubkey.clone();
		shared_pubkey
			.mul_assign(&secp, &sec_key)
			.map_err(|e| ErrorKind::Secp(e))?;

		let x_coord = shared_pubkey.serialize_vec(&secp, true);
		let shared_key =
			SecretKey::from_slice(&secp, &x_coord[1..]).map_err(|e| ErrorKind::Secp(e))?;
		{
			let mut s = self.shared_key.lock();
			*s = Some(shared_key);
		}

		let pub_key =
			PublicKey::from_secret_key(&secp, &sec_key).map_err(|e| ErrorKind::Secp(e))?;

		Ok(ECDHPubkey {
			ecdh_pubkey: pub_key,
		})
	}

	fn get_top_level_directory(&self) -> Result<String, ErrorKind> {
		Owner::get_top_level_directory(self).map_err(|e| e.kind())
	}

	fn set_top_level_directory(&self, dir: String) -> Result<(), ErrorKind> {
		Owner::set_top_level_directory(self, &dir).map_err(|e| e.kind())
	}

	fn create_config(
		&self,
		chain_type: global::ChainTypes,
		wallet_config: Option<WalletConfig>,
		logging_config: Option<LoggingConfig>,
		tor_config: Option<TorConfig>,
		epicbox_config: Option<EpicboxConfig>,
	) -> Result<(), ErrorKind> {
		Owner::create_config(
			self,
			&chain_type,
			wallet_config,
			logging_config,
			tor_config,
			epicbox_config,
		)
		.map_err(|e| e.kind())
	}

	fn create_wallet(
		&self,
		name: Option<String>,
		mnemonic: Option<String>,
		mnemonic_length: u32,
		password: String,
	) -> Result<(), ErrorKind> {
		let n = name.as_ref().map(|s| s.as_str());
		let m = match mnemonic {
			Some(s) => Some(ZeroingString::from(s)),
			None => None,
		};
		Owner::create_wallet(self, n, m, mnemonic_length, ZeroingString::from(password))
			.map_err(|e| e.kind())
	}

	fn open_wallet(&self, name: Option<String>, password: String) -> Result<Token, ErrorKind> {
		let n = name.as_ref().map(|s| s.as_str());
		let sec_key = Owner::open_wallet(self, n, ZeroingString::from(password), true)
			.map_err(|e| e.kind())?;
		Ok(Token {
			keychain_mask: sec_key,
		})
	}

	fn close_wallet(&self, name: Option<String>) -> Result<(), ErrorKind> {
		let n = name.as_ref().map(|s| s.as_str());
		Owner::close_wallet(self, n).map_err(|e| e.kind())
	}

	fn get_mnemonic(&self, name: Option<String>, password: String) -> Result<String, ErrorKind> {
		let n = name.as_ref().map(|s| s.as_str());
		let res =
			Owner::get_mnemonic(self, n, ZeroingString::from(password)).map_err(|e| e.kind())?;
		Ok(format!("{}", &*res))
	}

	fn change_password(
		&self,
		name: Option<String>,
		old: String,
		new: String,
	) -> Result<(), ErrorKind> {
		let n = name.as_ref().map(|s| s.as_str());
		Owner::change_password(self, n, ZeroingString::from(old), ZeroingString::from(new))
			.map_err(|e| e.kind())
	}

	fn delete_wallet(&self, name: Option<String>) -> Result<(), ErrorKind> {
		let n = name.as_ref().map(|s| s.as_str());
		Owner::delete_wallet(self, n).map_err(|e| e.kind())
	}

	fn start_updater(&self, token: Token, frequency: u32) -> Result<(), ErrorKind> {
		Owner::start_updater(
			self,
			(&token.keychain_mask).as_ref(),
			Duration::from_millis(frequency as u64),
		)
		.map_err(|e| e.kind())
	}

	fn stop_updater(&self) -> Result<(), ErrorKind> {
		Owner::stop_updater(self).map_err(|e| e.kind())
	}

	fn get_updater_messages(&self, count: u32) -> Result<Vec<StatusMessage>, ErrorKind> {
		Owner::get_updater_messages(self, count as usize).map_err(|e| e.kind())
	}

	fn get_public_proof_address(
		&self,
		token: Token,
		derivation_index: u32,
	) -> Result<PubAddress, ErrorKind> {
		let address = Owner::get_public_proof_address(
			self,
			(&token.keychain_mask).as_ref(),
			derivation_index,
		)
		.map_err(|e| e.kind())?;
		Ok(PubAddress { address })
	}
	fn get_public_address(
		&self,
		token: Token,
		derivation_index: u32,
	) -> Result<EpicboxAddress, ErrorKind> {
		let address =
			Owner::get_public_address(self, (&token.keychain_mask).as_ref(), derivation_index)
				.map_err(|e| e.kind())?;
		Ok(address)
	}
	fn retrieve_payment_proof(
		&self,
		token: Token,
		refresh_from_node: bool,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<PaymentProof, ErrorKind> {
		Owner::retrieve_payment_proof(
			self,
			(&token.keychain_mask).as_ref(),
			refresh_from_node,
			tx_id,
			tx_slate_id,
		)
		.map_err(|e| e.kind())
	}

	fn verify_payment_proof(
		&self,
		token: Token,
		proof: PaymentProof,
	) -> Result<(bool, bool), ErrorKind> {
		Owner::verify_payment_proof(self, (&token.keychain_mask).as_ref(), &proof)
			.map_err(|e| e.kind())
	}
	fn proof_address_from_onion_v3(&self, address_v3: String) -> Result<PubAddress, ErrorKind> {
		let address =
			Owner::proof_address_from_onion_v3(self, &address_v3).map_err(|e| e.kind())?;
		Ok(PubAddress { address })
	}

	fn set_tor_config(&self, tor_config: Option<TorConfig>) -> Result<(), ErrorKind> {
		Owner::set_tor_config(self, tor_config);
		Ok(())
	}
	fn set_epicbox_config(&self, epicbox_config: Option<EpicboxConfig>) -> Result<(), ErrorKind> {
		Owner::set_epicbox_config(self, epicbox_config);
		Ok(())
	}
}
