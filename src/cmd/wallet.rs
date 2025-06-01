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

use crate::cmd::wallet_args;
use crate::config::GlobalWalletConfig;
use clap::ArgMatches;
use epic_wallet_impls::HTTPNodeClient;
use epic_wallet_libwallet::NodeClient;
use log::{error, info, warn};
use semver::Version;
use std::fs;
use std::thread;
use std::time::Duration;

const MIN_COMPAT_NODE_VERSION: &str = "3.5.0";

pub fn wallet_command(wallet_args: &ArgMatches, config: GlobalWalletConfig) -> i32 {
	// Get defaults from the global config
	let wallet_config = config.members.clone().unwrap().wallet;
	let tor_config = config.members.clone().unwrap().tor;
	let epicbox_config = config.members.unwrap().epicbox;

	// Load the node API secret from the configuration or fallback to the default file
	let node_api_secret = wallet_config
		.node_api_secret_path
		.clone()
		.and_then(|path| fs::read_to_string(path).ok().map(|s| s.trim().to_string()));

	if node_api_secret.is_none() {
		warn!("Node API secret path is not configured. Proceeding without Node API secret.");
	}

	// Check if offline mode is enabled
	let offline_mode = wallet_args.get_flag("offline_mode");

	// Setup node client, check for provided node URL, else use default
	let mut node_client = match wallet_args
		.get_one::<String>("api_server_address")
		.map(|s| s.as_str())
	{
		Some(node_url) => HTTPNodeClient::new(node_url, node_api_secret.clone()).unwrap(),
		None => match HTTPNodeClient::new(
			wallet_config.check_node_api_http_addr.as_str(),
			node_api_secret.clone(),
		) {
			Ok(client) => client,
			Err(e) => {
				if offline_mode {
					warn!(
						"Failed to create HTTPNodeClient: {}. Proceeding without node sync.",
						e
					);
					return 0; // Allow offline mode to proceed
				} else {
					error!("Failed to create HTTPNodeClient: {}", e);
					return 1; // Exit with error code
				}
			}
		},
	};

	info!("Connecting to the node: {} ...", node_client.node_url);

	// Check the node sync status
	match node_client.get_node_status() {
		Ok(status) if status.sync_status == "no_sync" => {
			info!("Node is synced, proceeding...");
		}
		Ok(status) => {
			if offline_mode {
				warn!(
					"Node is not synced: {}. Proceeding without synced node.",
					status.sync_status
				);
			} else {
				error!(
					"Node is currently syncing. Sync status: {}. Please wait until the node is fully synced.",
					status.sync_status
				);
				return 1; // Exit with an error code to indicate the node is not ready
			}
		}
		Err(_) => {
			if offline_mode {
				warn!("Failed to check node sync status. Proceeding without a synced node.");
			} else {
				error!("Failed to check node sync status.");
				warn!("Set --offline_mode to proceed without a synced node, or check your node connection.");
				return 1; // Exit with error code
			}
		}
	}

	// Check the node version info, and exit with report if we're not compatible
	let global_wallet_args = wallet_args::parse_global_args(&wallet_config, &wallet_args)
		.expect("Can't read configuration file");

	node_client.set_node_api_secret(global_wallet_args.node_api_secret.clone());

	// This will also cache the node version info for calls to foreign API check middleware
	if !offline_mode {
		if let Some(v) = node_client.clone().get_version_info() {
			if Version::parse(&v.node_version).unwrap()
				< Version::parse(MIN_COMPAT_NODE_VERSION).unwrap()
			{
				let version = if v.node_version == "2.0.0" {
					"2.x.x series"
				} else {
					&v.node_version
				};
				error!("The Epic Node in use (version {}) is outdated and incompatible with this wallet version.", version);
				error!("Please update the node to version 3.5.0 or later and try again.");
				return 1;
			}
		}
	}

	// Proceed with wallet commands
	let res = wallet_args::wallet_command(
		wallet_args,
		wallet_config,
		tor_config,
		epicbox_config,
		node_client,
		false,
		|_| {},
	);

	// we need to give log output a chance to catch up before exiting
	thread::sleep(Duration::from_millis(100));

	if let Err(e) = res {
		error!("Wallet command failed: {}", e);
		1
	} else {
		info!(
			"Command '{}' completed successfully",
			wallet_args
				.subcommand()
				.map(|(name, _)| name)
				.unwrap_or("unknown")
		);
		0
	}
}
