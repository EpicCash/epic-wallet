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

use crate::api::TLSConfig;
use crate::config::EPIC_WALLET_DIR;
use crate::util::file::get_first_line;
use crate::util::{to_hex, Mutex, ZeroingString};
/// Argument parsing and error handling for wallet commands
use clap::ArgMatches;
use epic_wallet_config::{EpicboxConfig, TorConfig, WalletConfig};
use epic_wallet_controller::command;

use epic_wallet_impls::tor::config::is_tor_address;
use epic_wallet_impls::{DefaultLCProvider, DefaultWalletImpl};
use epic_wallet_impls::{PathToSlate, SlateGetter as _};
use epic_wallet_libwallet::{
	address, Error, IssueInvoiceTxArgs, NodeClient, Slate, WalletInst, WalletLCProvider,
};
use epic_wallet_util::epic_core as core;
use epic_wallet_util::epic_core::core::amount_to_hr_string;
use epic_wallet_util::epic_core::global;
use epic_wallet_util::epic_keychain as keychain;

use linefeed::terminal::Signal;
use linefeed::{Interface, ReadResult};
use rpassword;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustyline::error::ReadlineError;
use rustyline::history::DefaultHistory;
use rustyline::Editor;

use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crate::cmd::built_info;
use clap::{Arg, ArgAction, Command};

// define what to do on argument error
macro_rules! arg_parse {
	( $r:expr ) => {
		match $r {
			Ok(res) => res,
			Err(e) => {
				return Err(Error::ArgumentError(format!("{}", e)));
			}
		}
	};
}

pub fn build_cli() -> Command {
	Command::new("epic-wallet")
        .about("Reference Epic Wallet")
        .author("The Epic Team")
        .version(built_info::PKG_VERSION)
       
	    .arg(Arg::new("floonet").long("floonet")
		.help("Run epic against the Floonet (as opposed to mainnet)").action(clap::ArgAction::SetTrue))
        
		.arg(Arg::new("usernet").long("usernet")
		.help("Run epic as a local-only network. Doesn't block peer connections but will not connect to any peer or seed").action(clap::ArgAction::SetTrue))
        
		.arg(Arg::new("pass").short('p').long("pass")
		.help("Passphrase used to encrypt wallet seed").num_args(1))
        
		.arg(Arg::new("account").short('a').long("account")
		.help("Wallet account to use").num_args(1).default_value("default"))
        
		.arg(Arg::new("top_level_dir").short('t').long("top_level_dir")
		.help("Top directory in which wallet files are stored (location of 'epic-wallet.toml')").num_args(1))
        
		.arg(Arg::new("current_dir").short('c').long("current_dir")
		.help("Path to epic wallet_data dir (defaul: ~/.epic)").num_args(1))
        
		.arg(Arg::new("external").short('e').long("external")
		.help("Listen on 0.0.0.0 interface to allow external connections (default is 127.0.0.1)").action(clap::ArgAction::SetTrue))
        
		.arg(Arg::new("show_spent").short('s').long("show_spent")
		.help("Show spent outputs on wallet output commands").action(clap::ArgAction::SetTrue))
        
		.arg(Arg::new("api_server_address").short('r').long("api_server_address")
		.help("Api address of running node on which to check inputs and post transactions").num_args(1))
        
		.arg(Arg::new("offline_mode").long("offline_mode")
		.help("Run the wallet in offline mode, skipping node sync checks")
		.action(clap::ArgAction::SetTrue)
	
	)
       
		
		.subcommand(
            Command::new("account")
                .about("List wallet accounts or create a new account")
                
				.arg(Arg::new("create").short('c').long("create")
				.help("Create a new wallet account with provided name").num_args(1))
        )
        .subcommand(
            Command::new("listen")
                .about("Runs the wallet in listening mode waiting for transactions")
                
				.arg(Arg::new("port").short('l').long("port")
				.help("Port on which to run the wallet listener").num_args(1).value_parser(clap::value_parser!(u16)))
                
				.arg(Arg::new("method").short('m').long("method")
				.help("Which method to use for communication").value_parser(["http", "keybase", "epicbox"]).default_value("http").num_args(1))
                
				.arg(Arg::new("no_tor").short('n').long("no_tor")
				.help("Don't start TOR listener when starting HTTP listener").action(clap::ArgAction::SetTrue))
        )
        .subcommand(
            Command::new("owner_api")
                .about("Runs the wallet's local web API")
                
				.arg(Arg::new("port").short('l').long("port")
				.help("Port on which to run the wallet owner listener").num_args(1).value_parser(clap::value_parser!(u16)))
                
				.arg(Arg::new("run_foreign").long("run_foreign")
				.help("Also run the Foreign API").action(clap::ArgAction::SetTrue))
        )
        .subcommand(
            Command::new("send")
                .about("Builds a transaction to send coins and sends to the specified listener directly")
                
				.arg(Arg::new("amount")
				.help("Number of coins to send with optional fraction, e.g. 12.423").index(1))
                
				.arg(Arg::new("minimum_confirmations").short('c').long("min_conf")
				.help("Minimum number of confirmations required for an output to be spendable").default_value("10").num_args(1))
                
				.arg(Arg::new("selection_strategy").short('s').long("selection")
				.help("Coin/Output selection strategy.").value_parser(["all", "smallest"]).default_value("smallest").num_args(1))
                
				.arg(Arg::new("estimate_selection_strategies").short('e').long("estimate-selection")
				.help("Estimates all possible Coin/Output selection strategies.")
				.action(clap::ArgAction::SetTrue))
                
				.arg(Arg::new("change_outputs").short('o').long("change_outputs")
				.help("Number of change outputs to generate (mainly for testing)").default_value("1").num_args(1))
                
				.arg(Arg::new("method").short('m').long("method")
				.help("Method for sending this transaction").value_parser(["http", "file", "self", "keybase", "emoji", "epicbox"]).default_value("http").num_args(1))
                
				.arg(Arg::new("dest").short('d').long("dest")
				.help("Send the transaction to the provided server (start with http://) or save as file.").num_args(1))
                
				.arg(Arg::new("request_payment_proof").short('y').long("request_payment_proof")
				.help("Request a payment proof from the recipient. If sending to a tor address, the address will be filled automatically.")
				.action(clap::ArgAction::SetTrue))
                
				.arg(Arg::new("proof_address").short('z').long("proof_address")
				.help("Recipient proof address. If not using TOR, must be provided seprarately by the recipient").num_args(1))
                
				.arg(Arg::new("fluff").short('f').long("fluff")
				.help("Fluff the transaction (ignore Dandelion relay protocol)").action(clap::ArgAction::SetTrue))
                
				.arg(Arg::new("message").short('g').long("message")
				.help("Optional participant message to include").num_args(1))
                
				.arg(Arg::new("stored_tx").short('t').long("stored_tx")
				.help("If present, use the previously stored Unconfirmed transaction with given id").num_args(1))
                
				.arg(Arg::new("ttl_blocks").short('b').long("ttl_blocks")
				.help("If present, the number of blocks from the current after which wallets should refuse to process transactions further").num_args(1))
				
				.arg(Arg::new("slate_version").short('v').long("slate_version")
				.help("Target slate version to create/send").value_parser(clap::value_parser!(u16)).num_args(1))
		)
		.subcommand(
			Command::new("issue_invoice")
				.about("Issues an invoice transaction to be paid later")
				
				.arg(Arg::new("amount")
				.help("Number of coins to invoice with optional fraction, e.g. 12.423").index(1))
				
				.arg(Arg::new("message").short('g').long("message")
				.help("Optional participant message to include").num_args(1))
				
				.arg(Arg::new("dest").short('d').long("dest")
				.help("Name of destination slate output file").num_args(1))
				
				.arg(Arg::new("fluff").short('f').long("fluff")
				.help("Fluff the transaction (ignore Dandelion relay protocol)")
				.action(clap::ArgAction::SetTrue))
				
				.arg(Arg::new("ttl_blocks").short('b').long("ttl_blocks")
				.help("If present, the number of blocks from the current after which wallets should refuse to process transactions further").num_args(1))
				
				.arg(Arg::new("slate_version").short('v').long("slate_version")
				.help("Target slate version to create/send").value_parser(clap::value_parser!(u16)).num_args(1))
	
		)
        .subcommand(
            Command::new("receive")
                .about("Processes a transaction file to accept a transfer from a sender")
                
				.arg(Arg::new("message").short('g').long("message")
				.help("Optional participant message to include").num_args(1))
               
			    .arg(Arg::new("method").short('m').long("method")
				.help("Method of receiving this transaction").value_parser(["file", "emoji"]).default_value("file").num_args(1))
               
			    .arg(Arg::new("input").short('i').long("input")
				.help("Partial transaction to process, expects the sender's transaction file or emoji string.").num_args(1))
        )
        .subcommand(
            Command::new("finalize")
                .about("Processes a receiver's transaction file to finalize a transfer.")
                
				.arg(Arg::new("method").short('m').long("method")
				.help("Method for finalize this transaction").value_parser(["file", "emoji"]).default_value("file").num_args(1))
                
				.arg(Arg::new("input").short('i').long("input")
				.help("Partial transaction to process, expects the receiver's transaction file.").num_args(1))
                
				.arg(Arg::new("fluff").short('f').long("fluff")
				.help("Fluff the transaction (ignore Dandelion relay protocol)")
				.action(clap::ArgAction::SetTrue))
                
				.arg(Arg::new("nopost").short('n').long("nopost")
				.help("Do not post the transaction.")
				.action(clap::ArgAction::SetTrue))	
                
				.arg(Arg::new("dest").short('d').long("dest")
				.help("Specify file to save the finalized slate.").num_args(1))
        )
        .subcommand(
            Command::new("invoice")
                .about("Initialize an invoice transaction.")
                
				.arg(Arg::new("amount")
				.help("Number of coins to invoice  with optional fraction, e.g. 12.423").index(1))
                
				.arg(Arg::new("message").short('g').long("message")
				.help("Optional participant message to include").num_args(1))
                
				.arg(Arg::new("dest").short('d').long("dest")
				.help("Name of destination slate output file").num_args(1))
				
				.arg(Arg::new("slate_version").short('v').long("slate_version")
				.help("Target slate version to create/send").value_parser(clap::value_parser!(u16)).num_args(1))
	
		)		
        .subcommand(
            Command::new("pay")
                .about("Spend coins to pay the provided invoice transaction")
               
			    .arg(Arg::new("minimum_confirmations").short('c').long("min_conf")
				.help("Minimum number of confirmations required for an output to be spendable").default_value("10").num_args(1))
              
			    .arg(Arg::new("selection_strategy").short('s').long("selection")
				.help("Coin/Output selection strategy.").value_parser(["all", "smallest"]).default_value("all").num_args(1))
              
			    .arg(Arg::new("estimate_selection_strategies").short('e').long("estimate-selection")
				.help("Estimates all possible Coin/Output selection strategies.")
				.action(clap::ArgAction::SetTrue))
              
			    .arg(Arg::new("method").short('m').long("method")
				.help("Method for sending the processed invoice back to the invoice creator").value_parser(["file", "http", "self"]).default_value("file").num_args(1))
              
			    .arg(Arg::new("dest").short('d').long("dest")
				.help("Send the transaction to the provided server (start with http://) or save as file.").num_args(1))
               
			    .arg(Arg::new("message").short('g').long("message")
				.help("Optional participant message to include").num_args(1))
              
			    .arg(Arg::new("input").short('i').long("input")
				.help("Partial transaction to process, expects the invoicer's transaction file.").num_args(1))
               
			    .arg(Arg::new("ttl_blocks").short('b').long("ttl_blocks")
				.help("If present, the number of blocks from the current after which wallets should refuse to process transactions further").num_args(1))
        )
        .subcommand(
            Command::new("outputs")
                .about("Raw wallet output info (list of outputs)")
                
				.arg(Arg::new("show_full_history").short('f').long("show_full_history")
				.help("If specified, display full outputs history").action(clap::ArgAction::SetTrue))
                
				.arg(Arg::new("limit").short('l').long("limit")
				.help("Limit the number of transactions to display").num_args(1))
                
				.arg(Arg::new("offset").short('o').long("offset")
				.help("Skip the first N transactions").num_args(1))
                
				.arg(Arg::new("sort_order").short('s').long("sort_order")
				.help("Sort transactions by creation time, either 'asc' or 'desc' (default is 'desc')").value_parser(["asc", "desc"]).num_args(1))
        )
        .subcommand(
            Command::new("txs")
                .about("Display transaction information")
                
				.arg(Arg::new("id").short('i').long("id")
				.help("If specified, display transaction with given Id and all associated Inputs/Outputs").num_args(1))
                
				.arg(Arg::new("txid").short('t').long("txid")
				.help("If specified, display transaction with given TxID UUID and all associated Inputs/Outputs").num_args(1))
                
				.arg(Arg::new("limit").short('l').long("limit")
				.help("Limit the number of transactions to display").num_args(1))
                
				.arg(Arg::new("offset").short('o').long("offset")
				.help("Skip the first N transactions").num_args(1))
                
				.arg(Arg::new("sort_order").short('s').long("sort_order")
				.help("Sort transactions by creation time, either 'asc' or 'desc' (default is 'desc')").value_parser(["asc", "desc"]).num_args(1))
        )
        .subcommand(
            Command::new("post")
                .about("Posts a finalized transaction to the chain")
                
				.arg(Arg::new("input").short('i').long("input")
				.help("File name of the transaction to post").num_args(1))
                
				.arg(Arg::new("fluff").short('f').long("fluff")
				.help("Fluff the transaction (ignore Dandelion relay protocol)")
				.action(clap::ArgAction::SetTrue))
        )
        .subcommand(
            Command::new("repost")
                .about("Reposts a stored, completed but unconfirmed transaction to the chain, or dumps it to a file")
                
				.arg(Arg::new("id").short('i').long("id")
				.help("Transaction ID containing the stored completed transaction").num_args(1))
                
				.arg(Arg::new("dumpfile").short('m').long("dumpfile")
				.help("File name to duMp the transaction to instead of posting").num_args(1))
                
				.arg(Arg::new("fluff").short('f').long("fluff")
				.help("Fluff the transaction (ignore Dandelion relay protocol)")
				.action(clap::ArgAction::SetTrue))
        )
        .subcommand(
            Command::new("cancel")
                .about("Cancels a previously created transaction, freeing previously locked outputs for use again")
                
				.arg(Arg::new("id").short('i').long("id")
				.help("The ID of the transaction to cancel").num_args(1))
                
				.arg(Arg::new("txid").short('t').long("txid")
				.help("The TxID UUID of the transaction to cancel").num_args(1))
        )
        .subcommand(
            Command::new("info")
                .about("Basic wallet contents summary")
                .arg(Arg::new("minimum_confirmations").short('c').long("min_conf")
				.help("Minimum number of confirmations required for an output to be spendable")
				.default_value("10").num_args(1))
        )
        .subcommand(
            Command::new("init")
                .about("Initialize a new wallet seed file and database")
				
				.arg(Arg::new("cwd").short('w').long("cwd")
				.help("Create wallet files in the current directory instead of the default ~/.epic directory").action(clap::ArgAction::SetTrue))
                
				.arg(Arg::new("short_wordlist").short('s').long("short_wordlist")
				.help("Generate a 12-word recovery phrase/seed instead of default 24").action(clap::ArgAction::SetTrue))
                
				.arg(Arg::new("recover").short('r').long("recover")
				.help("Initialize new wallet using a recovery phrase").action(clap::ArgAction::SetTrue))
        )
        .subcommand(
            Command::new("recover")
                .about("Displays a recovery phrase for the wallet. (use `init -r` to perform recovery)")
        )
        .subcommand(
            Command::new("address")
                .about("Display the wallet's Epicbox public address, the payment proof address and the TOR address")
        )
        .subcommand(
            Command::new("scan")
                .about("Checks a wallet's outputs against a live node, repairing and restoring missing outputs if required")
                
				.arg(Arg::new("delete_unconfirmed").short('d').long("delete_unconfirmed")
				.help("!!! Warning !!! Delete any unconfirmed outputs unlock any locked outputs and delete all associated transactions (!!! this will delete all ongoing transactions !!!) while doing the check.").action(clap::ArgAction::SetTrue))
                
				.arg(Arg::new("start_height").short('s').long("start_height")
				.help("If given, the first block from which to start the scan (default 1)").default_value("1").num_args(1))
        )
        .subcommand(
            Command::new("export_proof")
                .about("Export a payment proof from a completed transaction")
               
			    .arg(Arg::new("output")
				.help("Output proof file").index(1))
              
			    .arg(Arg::new("id").short('i').long("id")
				.help("If specified, retrieve the proof for the given transaction ID").num_args(1))
               
			    .arg(Arg::new("txid").short('t').long("txid")
				.help("If specified, retrieve the proof for the given Slate ID").num_args(1))
        )
        .subcommand(
            Command::new("verify_proof")
            .about("Verify a payment proof")
            .arg(Arg::new("input").help("Filename of a proof file").index(1))
        )
		.subcommand(
		Command::new("change_password")
			.about("Change the wallet password")
			
			.arg(Arg::new("old_password")
			.help("Current password"))
			
			.arg(Arg::new("new_password")
			.help("New password"))
			
			.arg(Arg::new("remove_backup").long("remove-backup")
			.help("Remove the backup file after password change")
			.action(ArgAction::SetFalse),)
		)
}

fn prompt_password_stdout(prompt: &str) -> ZeroingString {
	ZeroingString::from(rpassword::prompt_password(prompt).unwrap_or("".to_string()))
}

pub fn prompt_password(password: &Option<ZeroingString>) -> ZeroingString {
	match password {
		None => prompt_password_stdout("Password: "),
		Some(p) => p.clone(),
	}
}

fn prompt_password_confirm() -> ZeroingString {
	let mut first = ZeroingString::from("first");
	let mut second = ZeroingString::from("second");
	while first != second {
		first = prompt_password_stdout("New Password: ");
		second = prompt_password_stdout("Confirm Password: ");
	}
	first
}

fn prompt_recovery_phrase<L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
) -> Result<ZeroingString, Error>
where
	DefaultWalletImpl<'static, C>: WalletInst<'static, L, C, K>,
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let mut rl = Editor::<(), DefaultHistory>::new().expect("Failed to create editor");
	println!("Please enter your recovery phrase:");
	loop {
		let readline = rl.readline("phrase> ");
		match readline {
			Ok(line) => {
				let mut w_lock = wallet.lock();
				let p = w_lock.lc_provider().unwrap();
				if p.validate_mnemonic(ZeroingString::from(line.clone()))
					.is_ok()
				{
					return Ok(ZeroingString::from(line));
				} else {
					println!();
					eprintln!("Recovery word phrase is invalid.");
					println!();
				}
			}
			Err(ReadlineError::Interrupted) => {
				return Err(Error::CancelledError);
			}
			Err(ReadlineError::Eof) => {
				return Err(Error::CancelledError);
			}
			Err(err) => {
				eprintln!("Error: {:?}", err);
				return Err(Error::CancelledError);
			}
		}
	}
}

fn prompt_pay_invoice(slate: &Slate, method: &str, dest: &str) -> Result<bool, Error> {
	let interface = Arc::new(Interface::new("pay")?);
	let amount = amount_to_hr_string(slate.amount, false);
	interface.set_report_signal(Signal::Interrupt, true);
	interface.set_prompt(
		"To proceed, type the exact amount of the invoice as displayed above (or Q/q to quit) > ",
	)?;
	println!();
	println!(
		"This command will pay the amount specified in the invoice using your wallet's funds."
	);
	println!("After you confirm, the following will occur: ");
	println!();
	println!(
		"* {} of your wallet funds will be added to the transaction to pay this invoice.",
		amount
	);
	if method == "http" {
		println!("* The resulting transaction will IMMEDIATELY be sent to the wallet listening at: '{}'.", dest);
	} else {
		println!("* The resulting transaction will be saved to the file '{}', which you can manually send back to the invoice creator.", dest);
	}
	println!();
	println!("The invoice slate's participant info is:");
	for m in slate.participant_messages().messages {
		println!("{}", m);
	}
	println!("Please review the above information carefully before proceeding");
	println!();
	loop {
		let res = interface.read_line().unwrap();
		match res {
			ReadResult::Eof => return Ok(false),
			ReadResult::Signal(sig) => {
				if sig == Signal::Interrupt {
					interface.cancel_read_line()?;
					return Err(Error::CancelledError);
				}
			}
			ReadResult::Input(line) => {
				match line.trim() {
					"Q" | "q" => return Err(Error::CancelledError),
					result => {
						if result == amount {
							return Ok(true);
						} else {
							println!("Please enter exact amount of the invoice as shown above or Q to quit");
							println!();
						}
					}
				}
			}
		}
	}
}

// instantiate wallet (needed by most functions)

pub fn inst_wallet<L, C, K>(
	config: WalletConfig,
	node_client: C,
) -> Result<Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>, Error>
where
	DefaultWalletImpl<'static, C>: WalletInst<'static, L, C, K>,
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let mut wallet = Box::new(DefaultWalletImpl::<'static, C>::new(node_client.clone()).unwrap())
		as Box<dyn WalletInst<'static, L, C, K>>;
	let lc = wallet.lc_provider().unwrap();
	let _ = lc.set_top_level_directory(&config.data_file_dir);
	Ok(Arc::new(Mutex::new(wallet)))
}

// parses a required value, or throws error with message otherwise
fn parse_required<'a>(args: &'a ArgMatches, name: &str) -> Result<&'a str, Error> {
	let arg = args.get_one::<String>(name).map(|s| s.as_str());
	match arg {
		Some(ar) => Ok(ar),
		None => {
			let msg = format!("Value for argument '{}' is required in this context", name,);
			Err(Error::ArgumentError(msg))
		}
	}
}

// parses a number, or throws error with message otherwise
fn parse_u64(arg: &str, name: &str) -> Result<u64, Error> {
	let val = arg.parse::<u64>();
	match val {
		Ok(v) => Ok(v),
		Err(e) => {
			let msg = format!("Could not parse {} as a whole number. e={}", name, e);
			Err(Error::ArgumentError(msg))
		}
	}
}

// As above, but optional
fn parse_u64_or_none(arg: Option<&str>) -> Option<u64> {
	let val = match arg {
		Some(a) => a.parse::<u64>(),
		None => return None,
	};
	match val {
		Ok(v) => Some(v),
		Err(_) => None,
	}
}

pub fn parse_global_args(
	config: &WalletConfig,
	args: &ArgMatches,
) -> Result<command::GlobalArgs, Error> {
	let account = args
		.get_one::<String>("account")
		.map(|s| s.as_str())
		.ok_or_else(|| {
			Error::ArgumentError(
				"Value for argument 'account' is required in this context".to_string(),
			)
		})?;

	let show_spent = args.get_flag("show_spent");

	let api_secret = get_first_line(config.api_secret_path.clone());
	let node_api_secret = get_first_line(config.node_api_secret_path.clone());
	let password = args
		.get_one::<String>("pass")
		.map(|p| ZeroingString::from(p.as_str()));

	let tls_conf = match config.tls_certificate_file.clone() {
		None => None,
		Some(file) => {
			let key = match config.tls_certificate_key.clone() {
				Some(k) => k,
				None => {
					let msg = format!("Private key for certificate is not set");
					return Err(Error::ArgumentError(msg));
				}
			};
			Some(TLSConfig::new(file, key))
		}
	};

	let chain_type = match config.chain_type.clone() {
		None => {
			let param_ref = global::CHAIN_TYPE.read();
			param_ref.clone()
		}
		Some(c) => c,
	};

	let offline_mode = args.get_flag("offline_mode");
	Ok(command::GlobalArgs {
		account: account.to_owned(),
		show_spent,
		chain_type,
		api_secret,
		node_api_secret,
		password,
		tls_conf,
		offline_mode,
	})
}

pub fn parse_init_args<L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
	config: &WalletConfig,
	g_args: &command::GlobalArgs,
	args: &ArgMatches,
) -> Result<command::InitArgs, Error>
where
	DefaultWalletImpl<'static, C>: WalletInst<'static, L, C, K>,
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let list_length = match args.get_flag("short_wordlist") {
		false => 32,
		true => 16,
	};

	let recovery_phrase = match args.subcommand() {
		Some(("init", sub_args)) if sub_args.get_flag("recover") => {
			Some(prompt_recovery_phrase(wallet)?)
		}
		_ => None,
	};

	if recovery_phrase.is_some() {
		println!("Please provide a new password for the recovered wallet");
	} else {
		println!("Please enter a password for your new wallet");
	}

	let password = match g_args.password.clone() {
		Some(p) => p,
		None => prompt_password_confirm(),
	};

	Ok(command::InitArgs {
		list_length,
		password,
		config: config.clone(),
		recovery_phrase,
		restore: false,
	})
}

pub fn parse_recover_args(g_args: &command::GlobalArgs) -> Result<command::RecoverArgs, Error>
where
{
	let passphrase = prompt_password(&g_args.password);
	Ok(command::RecoverArgs { passphrase })
}

pub fn parse_listen_args(
	config: &mut WalletConfig,
	tor_config: &mut TorConfig,
	args: &ArgMatches,
) -> Result<command::ListenArgs, Error> {
	if let Some(port) = args.get_one::<u16>("port") {
		config.api_listen_port = port.to_owned();
	}

	let method = parse_required(args, "method")?;

	if args.get_flag("no_tor") {
		tor_config.use_tor_listener = false;
	}
	Ok(command::ListenArgs {
		method: method.to_owned(),
	})
}

pub fn parse_owner_api_args(config: &mut WalletConfig, args: &ArgMatches) -> Result<(), Error> {
	if let Some(port) = args.get_one::<u16>("port") {
		config.owner_api_listen_port = Some(*port);
	}
	if args.get_flag("run_foreign") {
		config.owner_api_include_foreign = Some(true);
	}
	Ok(())
}

pub fn parse_account_args(account_args: &ArgMatches) -> Result<command::AccountArgs, Error> {
	let create = match account_args.get_one::<String>("create") {
		None => None,
		Some(s) => Some(s.to_owned()),
	};
	Ok(command::AccountArgs { create })
}

pub fn parse_send_args(args: &ArgMatches) -> Result<command::SendArgs, Error> {
	// amount
	let amount = parse_required(args, "amount")?;
	let amount = core::core::amount_from_hr_string(amount);
	let amount = match amount {
		Ok(a) => a,
		Err(e) => {
			let msg = format!(
				"Could not parse amount as a number with optional decimal point. e={:?}",
				e
			);
			return Err(Error::ArgumentError(msg));
		}
	};

	// message
	let message = args.get_one::<String>("message").map(|s| s.to_owned());

	// minimum_confirmations
	let min_c = parse_required(args, "minimum_confirmations")?;
	let min_c = parse_u64(min_c, "minimum_confirmations")?;

	// selection_strategy
	let selection_strategy = parse_required(args, "selection_strategy")?;

	// estimate_selection_strategies
	let estimate_selection_strategies = args.get_flag("estimate_selection_strategies");

	// method
	let method = parse_required(args, "method")?;

	// dest
	let dest = {
		if method == "self" {
			match args.get_one::<String>("dest").map(|s| s.as_str()) {
				Some(d) => d,
				None => "default",
			}
		} else if method == "emoji" {
			""
		} else {
			if !estimate_selection_strategies {
				parse_required(args, "dest")?
			} else {
				""
			}
		}
	};

	if !estimate_selection_strategies
		&& method == "http"
		&& !dest.starts_with("http://")
		&& !dest.starts_with("https://")
		&& is_tor_address(&dest).is_err()
	{
		let msg = format!(
			"HTTP Destination should start with http://: or https://: {}",
			dest,
		);
		return Err(Error::ArgumentError(msg));
	}

	// change_outputs
	let change_outputs = parse_required(args, "change_outputs")?;
	let change_outputs = parse_u64(change_outputs, "change_outputs")? as usize;

	// fluff
	let fluff = args.get_flag("fluff");

	// ttl_blocks
	let ttl_blocks = parse_u64_or_none(args.get_one::<String>("ttl_blocks").map(|s| s.as_str()));

	// max_outputs
	let max_outputs = 500;

	// target slate version to create/send
	let target_slate_version = args.get_one::<u16>("slate_version").map(|v| *v);

	let payment_proof_address = {
		match args.get_flag("request_payment_proof") {
			true => {
				// if the destination address is a TOR address, we don't need the address
				// separately
				match address::pubkey_from_onion_v3(&dest) {
					Ok(k) => Some(to_hex(k.to_bytes().to_vec())),
					Err(_) => Some(parse_required(args, "proof_address")?.to_owned()),
				}
			}
			false => None,
		}
	};

	Ok(command::SendArgs {
		amount,
		message,
		minimum_confirmations: min_c,
		selection_strategy: selection_strategy.to_owned(),
		estimate_selection_strategies,
		method: method.to_owned(),
		dest: dest.to_owned(),
		change_outputs,
		fluff,
		max_outputs,
		payment_proof_address,
		ttl_blocks,
		target_slate_version,
	})
}

pub fn parse_receive_args(receive_args: &ArgMatches) -> Result<command::ReceiveArgs, Error> {
	// message
	let message = receive_args
		.get_one::<String>("message")
		.map(|s| s.to_owned());

	// method
	let method = parse_required(receive_args, "method")?;

	// input
	let tx_file = parse_required(receive_args, "input")?;

	// validate input
	if method == "file" {
		if !Path::new(&tx_file).is_file() {
			let msg = format!("File {} not found.", &tx_file);
			return Err(Error::ArgumentError(msg));
		}
	}

	Ok(command::ReceiveArgs {
		input: tx_file.to_owned(),
		message,
		method: method.to_string(),
	})
}

pub fn parse_finalize_args(args: &ArgMatches) -> Result<command::FinalizeArgs, Error> {
	let fluff = args.get_flag("fluff");
	let nopost = args.get_flag("nopost");

	// method
	let method = parse_required(args, "method")?;

	// input
	let input = parse_required(args, "input")?;

	// validate input
	if method == "file" {
		if !Path::new(&input).is_file() {
			let msg = format!("File {} not found.", input);
			return Err(Error::ArgumentError(msg));
		}
	}

	let dest_file = args.get_one::<String>("dest").map(|s| s.to_owned());

	Ok(command::FinalizeArgs {
		method: method.to_string(),
		input: input.to_owned(),
		dest: dest_file.to_owned(),
		nopost,
		fluff,
	})
}

pub fn parse_issue_invoice_args(args: &ArgMatches) -> Result<command::IssueInvoiceArgs, Error> {
	let amount = parse_required(args, "amount")?;
	let amount = core::core::amount_from_hr_string(amount);
	let amount = match amount {
		Ok(a) => a,
		Err(e) => {
			let msg = format!(
				"Could not parse amount as a number with optional decimal point. e={:?}",
				e
			);
			return Err(Error::ArgumentError(msg));
		}
	};
	// message
	let message = args.get_one::<String>("message").map(|s| s.to_owned());

	// target slate version to create
	let target_slate_version = args.get_one::<u16>("slate_version").map(|v| *v);

	// dest (output file)
	let dest = parse_required(args, "dest")?;
	Ok(command::IssueInvoiceArgs {
		dest: dest.into(),
		issue_args: IssueInvoiceTxArgs {
			dest_acct_name: None,
			amount,
			message,
			target_slate_version,
		},
	})
}

pub fn parse_process_invoice_args(
	args: &ArgMatches,
	prompt: bool,
) -> Result<command::ProcessInvoiceArgs, Error> {
	// TODO: display and prompt for confirmation of what we're doing
	// message
	let message = args.get_one::<String>("message").map(|s| s.to_owned());

	// minimum_confirmations
	let min_c = parse_required(args, "minimum_confirmations")?;
	let min_c = parse_u64(min_c, "minimum_confirmations")?;

	// selection_strategy
	let selection_strategy = parse_required(args, "selection_strategy")?;

	// estimate_selection_strategies
	let estimate_selection_strategies = args.get_flag("estimate_selection_strategies");

	// method
	let method = parse_required(args, "method")?;

	// dest
	let dest = {
		if method == "self" {
			match args.get_one::<String>("dest").map(|s| s.as_str()) {
				Some(d) => d,
				None => "default",
			}
		} else {
			if !estimate_selection_strategies {
				parse_required(args, "dest")?
			} else {
				""
			}
		}
	};
	if !estimate_selection_strategies
		&& method == "http"
		&& !dest.starts_with("http://")
		&& !dest.starts_with("https://")
	{
		let msg = format!(
			"HTTP Destination should start with http://: or https://: {}",
			dest,
		);
		return Err(Error::ArgumentError(msg));
	}

	// ttl_blocks
	let ttl_blocks = parse_u64_or_none(args.get_one::<String>("ttl_blocks").map(|s| s.as_str()));

	// max_outputs
	let max_outputs = 500;

	// file input only
	let tx_file = parse_required(args, "input")?;

	if prompt {
		// Now we need to prompt the user whether they want to do this,
		// which requires reading the slate

		let slate = match PathToSlate((&tx_file).into()).get_tx() {
			Ok(s) => s,
			Err(e) => return Err(Error::ArgumentError(format!("{}", e))),
		};

		prompt_pay_invoice(&slate, method, dest)?;
	}

	Ok(command::ProcessInvoiceArgs {
		message,
		minimum_confirmations: min_c,
		selection_strategy: selection_strategy.to_owned(),
		estimate_selection_strategies,
		method: method.to_owned(),
		dest: dest.to_owned(),
		max_outputs,
		input: tx_file.to_owned(),
		ttl_blocks,
	})
}

pub fn parse_info_args(args: &ArgMatches) -> Result<command::InfoArgs, Error> {
	// minimum_confirmations
	let mc = parse_required(args, "minimum_confirmations")?;
	let mc = parse_u64(mc, "minimum_confirmations")?;
	Ok(command::InfoArgs {
		minimum_confirmations: mc,
	})
}

pub fn parse_outputs_args(args: &ArgMatches) -> Result<command::OutputsArgs, Error> {
	let show_full_history = args.get_flag("show_full_history");
	// Parse limit
	let limit = match args.get_one::<String>("limit") {
		None => None,
		Some(l) => Some(parse_u64(l, "limit")? as usize),
	};

	// Parse offset
	let offset = match args.get_one::<String>("offset") {
		None => None,
		Some(o) => Some(parse_u64(o, "offset")? as usize),
	};

	// Parse sort order
	let sort_order = match args.get_one::<String>("sort_order") {
		None => None,
		Some(so) => {
			let so_lower = so.to_lowercase();
			if so_lower != "asc" && so_lower != "desc" {
				let msg = format!("Invalid value for 'sort_order'. Must be 'asc' or 'desc'.");
				return Err(Error::ArgumentError(msg));
			}
			Some(so_lower)
		}
	};
	Ok(command::OutputsArgs {
		show_full_history,
		limit,
		offset,
		sort_order,
	})
}

pub fn parse_check_args(args: &ArgMatches) -> Result<command::CheckArgs, Error> {
	let delete_unconfirmed = args.get_flag("delete_unconfirmed");
	let start_height =
		parse_u64_or_none(args.get_one::<String>("start_height").map(|s| s.as_str()));
	Ok(command::CheckArgs {
		start_height,
		delete_unconfirmed,
	})
}

pub fn parse_txs_args(args: &ArgMatches) -> Result<command::TxsArgs, Error> {
	// Parse transaction ID
	let tx_id = match args.get_one::<String>("id") {
		None => None,
		Some(tx) => Some(parse_u64(tx, "id")? as u32),
	};

	// Parse transaction slate ID
	let tx_slate_id = match args.get_one::<String>("txid") {
		None => None,
		Some(tx) => match tx.parse() {
			Ok(t) => Some(t),
			Err(e) => {
				let msg = format!("Could not parse txid parameter. e={}", e);
				return Err(Error::ArgumentError(msg));
			}
		},
	};

	// Ensure only one of `id` or `txid` is provided
	if tx_id.is_some() && tx_slate_id.is_some() {
		let msg = format!("At most one of 'id' (-i) or 'txid' (-t) may be provided.");
		return Err(Error::ArgumentError(msg));
	}

	// Parse limit
	let limit = match args.get_one::<String>("limit") {
		None => None,
		Some(l) => Some(parse_u64(l, "limit")? as usize),
	};

	// Parse offset
	let offset = match args.get_one::<String>("offset") {
		None => None,
		Some(o) => Some(parse_u64(o, "offset")? as usize),
	};

	// Parse sort order
	let sort_order = match args.get_one::<String>("sort_order") {
		None => None,
		Some(so) => {
			let so_lower = so.to_lowercase();
			if so_lower != "asc" && so_lower != "desc" {
				let msg = format!("Invalid value for 'sort_order'. Must be 'asc' or 'desc'.");
				return Err(Error::ArgumentError(msg));
			}
			Some(so_lower)
		}
	};

	// Return the parsed arguments
	Ok(command::TxsArgs {
		id: tx_id,
		tx_slate_id,
		limit,
		offset,
		sort_order,
	})
}

pub fn parse_post_args(args: &ArgMatches) -> Result<command::PostArgs, Error> {
	let tx_file = parse_required(args, "input")?;
	let fluff = args.get_flag("fluff");

	Ok(command::PostArgs {
		input: tx_file.to_owned(),
		fluff,
	})
}

pub fn parse_repost_args(args: &ArgMatches) -> Result<command::RepostArgs, Error> {
	let tx_id = match args.get_one::<String>("id") {
		None => None,
		Some(tx) => Some(parse_u64(tx, "id")? as u32),
	};

	let fluff = args.get_flag("fluff");
	let dump_file = match args.get_one::<String>("dumpfile") {
		None => None,
		Some(d) => Some(d.to_owned()),
	};

	Ok(command::RepostArgs {
		id: tx_id.unwrap(),
		dump_file,
		fluff,
	})
}

pub fn parse_cancel_args(args: &ArgMatches) -> Result<command::CancelArgs, Error> {
	let mut tx_id_string = "";
	let tx_id = match args.get_one::<String>("id") {
		None => None,
		Some(tx) => Some(parse_u64(tx, "id")? as u32),
	};
	let tx_slate_id = match args.get_one::<String>("txid") {
		None => None,
		Some(tx) => match tx.parse() {
			Ok(t) => {
				tx_id_string = tx;
				Some(t)
			}
			Err(e) => {
				let msg = format!("Could not parse txid parameter. e={}", e);
				return Err(Error::ArgumentError(msg));
			}
		},
	};
	if (tx_id.is_none() && tx_slate_id.is_none()) || (tx_id.is_some() && tx_slate_id.is_some()) {
		let msg = format!("'id' (-i) or 'txid' (-t) argument is required.");
		return Err(Error::ArgumentError(msg));
	}
	Ok(command::CancelArgs {
		tx_id,
		tx_slate_id,
		tx_id_string: tx_id_string.to_owned(),
	})
}
pub fn parse_export_proof_args(args: &ArgMatches) -> Result<command::ProofExportArgs, Error> {
	let output_file = parse_required(args, "output")?;
	let tx_id = match args.get_one::<String>("id") {
		None => None,
		Some(tx) => Some(parse_u64(tx, "id")? as u32),
	};
	let tx_slate_id = match args.get_one::<String>("txid") {
		None => None,
		Some(tx) => match tx.parse() {
			Ok(t) => Some(t),
			Err(e) => {
				let msg = format!("Could not parse txid parameter. e={}", e);
				return Err(Error::ArgumentError(msg));
			}
		},
	};
	if tx_id.is_some() && tx_slate_id.is_some() {
		let msg = format!("At most one of 'id' (-i) or 'txid' (-t) may be provided.");
		return Err(Error::ArgumentError(msg));
	}
	if tx_id.is_none() && tx_slate_id.is_none() {
		let msg = format!("Either 'id' (-i) or 'txid' (-t) must be provided.");
		return Err(Error::ArgumentError(msg));
	}
	Ok(command::ProofExportArgs {
		output_file: output_file.to_owned(),
		id: tx_id,
		tx_slate_id,
	})
}

pub fn parse_verify_proof_args(args: &ArgMatches) -> Result<command::ProofVerifyArgs, Error> {
	let input_file = parse_required(args, "input")?;
	Ok(command::ProofVerifyArgs {
		input_file: input_file.to_owned(),
	})
}

pub fn wallet_command<C, F>(
	wallet_args: &ArgMatches,
	mut wallet_config: WalletConfig,
	tor_config: Option<TorConfig>,
	epicbox_config: Option<EpicboxConfig>,
	node_client: C,
	test_mode: bool,
	wallet_inst_cb: F,
) -> Result<String, Error>
where
	C: NodeClient + 'static + Clone,
	F: FnOnce(
		Arc<
			Mutex<
				Box<
					dyn WalletInst<
						'static,
						DefaultLCProvider<'static, C, keychain::ExtKeychain>,
						C,
						keychain::ExtKeychain,
					>,
				>,
			>,
		>,
	),
{
	if let Some(t) = wallet_config.chain_type.clone() {
		global::set_mining_mode(t);
	}

	if wallet_args.get_flag("external") {
		wallet_config.api_listen_interface = "0.0.0.0".to_string();
	}

	if let Some(dir) = wallet_args.get_one::<String>("top_level_dir") {
		wallet_config.data_file_dir = dir.to_string();
	}

	let global_wallet_args = arg_parse!(parse_global_args(&wallet_config, &wallet_args));

	// legacy hack to avoid the need for changes in existing epic-wallet.toml files
	// remove `wallet_data` from end of path as
	// new lifecycle provider assumes epic_wallet.toml is in root of data directory
	let mut top_level_wallet_dir = PathBuf::from(wallet_config.clone().data_file_dir);
	if top_level_wallet_dir.ends_with(EPIC_WALLET_DIR) {
		top_level_wallet_dir.pop();
		wallet_config.data_file_dir = top_level_wallet_dir.to_str().unwrap().into();
	}

	// for backwards compatibility: If tor config doesn't exist in the file, assume
	// the top level directory for data
	let tor_config = match tor_config {
		Some(tc) => tc,
		None => {
			let mut tc = TorConfig::default();
			tc.send_config_dir = wallet_config.data_file_dir.clone();
			tc
		}
	};

	// for backwards compatibility: If epicbox config doesn't exist in the file
	let epicbox_config = match epicbox_config {
		Some(epicbox_config) => epicbox_config,
		None => EpicboxConfig::default(),
	};

	// Instantiate wallet (doesn't open the wallet)
	let wallet =
		inst_wallet::<DefaultLCProvider<C, keychain::ExtKeychain>, C, keychain::ExtKeychain>(
			wallet_config.clone(),
			node_client.clone(),
		)
		.unwrap_or_else(|e| {
			eprintln!("{:?}", e);
			std::process::exit(1);
		});

	{
		let mut wallet_lock = wallet.lock();
		let lc = wallet_lock.lc_provider().unwrap();
		let _ = lc.set_top_level_directory(&wallet_config.data_file_dir);
	}

	// provide wallet instance back to the caller (handy for testing with local wallet proxy, etc)
	wallet_inst_cb(wallet.clone());

	// don't open wallet for certain lifecycle commands
	let mut open_wallet = true;
	match wallet_args.subcommand() {
		Some(("init", _)) => open_wallet = false,
		Some(("recover", _)) => open_wallet = false,
		Some(("owner_api", _)) => {
			// If wallet exists, open it. Otherwise, that's fine too.
			let mut wallet_lock = wallet.lock();
			let lc = wallet_lock.lc_provider().unwrap();
			open_wallet = lc.wallet_exists(None).unwrap();
		}
		_ => {}
	}

	let keychain_mask = match open_wallet {
		true => {
			let mut wallet_lock = wallet.lock();
			let lc = wallet_lock.lc_provider().unwrap();
			let mask = lc.open_wallet(
				None,
				prompt_password(&global_wallet_args.password),
				false,
				false,
			)?;
			if let Some(account) = wallet_args.get_one::<String>("account") {
				let wallet_inst = lc.wallet_inst()?;
				wallet_inst.set_parent_key_id_by_name(account)?;
			}
			mask
		}
		false => None,
	};

	let km = (&keychain_mask).as_ref();
	let node_client_clone = node_client.clone();
	let is_node_synced = if test_mode {
		Arc::new(AtomicBool::new(true))
	} else {
		Arc::new(AtomicBool::new(false))
	};

	if !test_mode {
		let is_node_synced_clone = is_node_synced.clone();

		// Spawn a thread to check node sync status every 10 seconds
		thread::spawn(move || {
			loop {
				let synced = match node_client_clone.get_node_status() {
					Ok(status) => status.sync_status == "no_sync",
					Err(_) => false,
				};
				is_node_synced_clone.store(synced, Ordering::SeqCst);
				thread::sleep(Duration::from_secs(10)); // adjust interval as needed
			}
		});
	}

	let res = match wallet_args.subcommand() {
		Some(("init", args)) => {
			let a = arg_parse!(parse_init_args(
				wallet.clone(),
				&wallet_config,
				&global_wallet_args,
				&args
			));
			command::init(wallet, &global_wallet_args, a)
		}
		Some(("recover", _)) => {
			let a = arg_parse!(parse_recover_args(&global_wallet_args,));
			command::recover(wallet, a)
		}
		Some(("listen", args)) => {
			let mut c = wallet_config.clone();
			let mut t = tor_config.clone();
			let e = epicbox_config.clone();
			let a = arg_parse!(parse_listen_args(&mut c, &mut t, &args));
			command::listen(
				wallet,
				Arc::new(Mutex::new(keychain_mask)),
				&c,
				&t,
				&e,
				&a,
				&global_wallet_args.clone(),
				is_node_synced.clone(),
			)
		}
		Some(("owner_api", args)) => {
			let mut c = wallet_config.clone();
			let mut g = global_wallet_args.clone();
			g.tls_conf = None;
			arg_parse!(parse_owner_api_args(&mut c, &args));
			command::owner_api(
				wallet,
				keychain_mask,
				&c,
				&tor_config,
				&epicbox_config,
				&g,
				is_node_synced.clone(),
			)
		}
		Some(("web", _)) => command::owner_api(
			wallet,
			keychain_mask,
			&wallet_config,
			&tor_config,
			&epicbox_config,
			&global_wallet_args,
			is_node_synced.clone(),
		),
		Some(("account", args)) => {
			let a = arg_parse!(parse_account_args(&args));
			command::account(wallet, km, a, is_node_synced.clone())
		}
		Some(("send", args)) => {
			let a = arg_parse!(parse_send_args(&args));
			command::send(
				wallet,
				km,
				Some(tor_config),
				Some(epicbox_config),
				a,
				wallet_config.dark_background_color_scheme.unwrap_or(true),
				is_node_synced.clone(),
			)
		}
		Some(("receive", args)) => {
			let a = arg_parse!(parse_receive_args(&args));
			command::receive(wallet, km, &global_wallet_args, a)
		}
		Some(("finalize", args)) => {
			let a = arg_parse!(parse_finalize_args(&args));
			command::finalize(wallet, km, a, is_node_synced.clone())
		}
		Some(("invoice", args)) => {
			let a = arg_parse!(parse_issue_invoice_args(&args));
			command::issue_invoice_tx(wallet, km, a, is_node_synced.clone())
		}
		Some(("pay", args)) => {
			let a = arg_parse!(parse_process_invoice_args(&args, !test_mode));
			command::process_invoice(
				wallet,
				km,
				Some(tor_config),
				a,
				wallet_config.dark_background_color_scheme.unwrap_or(true),
				is_node_synced.clone(),
			)
		}
		Some(("info", args)) => {
			let a = arg_parse!(parse_info_args(&args));
			command::info(
				wallet,
				km,
				&global_wallet_args,
				a,
				wallet_config.dark_background_color_scheme.unwrap_or(true),
				is_node_synced.clone(),
			)
		}
		Some(("outputs", args)) => {
			let a = arg_parse!(parse_outputs_args(&args));
			command::outputs(
				wallet,
				km,
				&global_wallet_args,
				a,
				wallet_config.dark_background_color_scheme.unwrap_or(true),
				is_node_synced.clone(),
			)
		}
		Some(("txs", args)) => {
			let a = arg_parse!(parse_txs_args(&args));
			command::txs(
				wallet,
				km,
				&global_wallet_args,
				a,
				wallet_config.dark_background_color_scheme.unwrap_or(true),
				is_node_synced.clone(),
			)
		}
		Some(("post", args)) => {
			let a = arg_parse!(parse_post_args(&args));
			command::post(wallet, km, a, is_node_synced.clone())
		}
		Some(("repost", args)) => {
			let a = arg_parse!(parse_repost_args(&args));
			command::repost(wallet, km, a, is_node_synced.clone())
		}
		Some(("cancel", args)) => {
			let a = arg_parse!(parse_cancel_args(&args));
			command::cancel(wallet, km, a, is_node_synced.clone())
		}
		Some(("export_proof", args)) => {
			let a = arg_parse!(parse_export_proof_args(&args));
			command::proof_export(wallet, km, a, is_node_synced.clone())
		}
		Some(("verify_proof", args)) => {
			let a = arg_parse!(parse_verify_proof_args(&args));
			command::proof_verify(wallet, km, a, is_node_synced.clone())
		}
		Some(("address", _)) => command::address(
			wallet,
			&global_wallet_args,
			km,
			epicbox_config,
			is_node_synced.clone(),
		),
		Some(("scan", args)) => {
			let a = arg_parse!(parse_check_args(&args));
			command::scan(wallet, km, a, is_node_synced.clone())
		}
		Some(("change_password", args)) => {
			// Prompt for current password if not provided
			let old_password = match args.get_one::<String>("old_password") {
				Some(p) => ZeroingString::from(p.clone()),
				None => prompt_password_stdout("Current password: "),
			};

			// Prompt for new password and confirmation
			let new_password = if let Some(p) = args.get_one::<String>("new_password") {
				ZeroingString::from(p.clone())
			} else {
				prompt_password_confirm()
			};

			// Get the remove_backup flag
			let remove_backup = args.get_flag("remove_backup");

			// Call the lifecycle provider's change_password method
			let mut wallet_lock = wallet.lock();
			let lc = wallet_lock.lc_provider().unwrap();
			lc.change_password(None, old_password, new_password, remove_backup)
		}

		_ => {
			let msg = format!("Unknown wallet command, use 'epic-wallet help' for details");
			return Err(Error::ArgumentError(msg));
		}
	};
	if let Err(e) = res {
		Err(e)
	} else {
		//info!("subcommand");
		Ok(wallet_args
			.subcommand()
			.map(|(name, _)| name.to_owned())
			.unwrap_or_default())
	}
}
