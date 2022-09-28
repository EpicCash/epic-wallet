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

// Keybase Wallet Plugin
use crate::adapters::SlateReceiver;
use crate::config::WalletConfig;
use crate::keychain::Keychain;
use crate::libwallet::EpicboxAddress;
use crate::libwallet::{
	Controller, Error, NodeClient, Publisher, VersionedSlate, WalletInst, WalletLCProvider,
	DEFAULT_EPICBOX_PORT,
};
use crate::util::secp::key::SecretKey;
use crate::util::Mutex;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use ws::util::Token;
use ws::{
	connect, CloseCode, Error as WsError, ErrorKind as WsErrorKind, Handler, Handshake, Message,
	Result as WsResult, Sender,
};

const LISTEN_SLEEP_DURATION: Duration = Duration::from_millis(5000);

/// Receives slates on all channels with topic SLATE_NEW
pub struct EpicboxAllChannels {
	_priv: (), // makes EpicboxAllChannels unconstructable without checking for existence of keybase executable
}

impl EpicboxAllChannels {
	/// Create a EpicboxAllChannels,
	pub fn new() -> Result<EpicboxAllChannels, Error> {
		Ok(EpicboxAllChannels { _priv: () })
	}
}

impl SlateReceiver for EpicboxAllChannels {
	/// Start a listener, passing received messages to the wallet api directly

	fn listen<L, C, K>(
		&self,
		wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
		keychain_mask: Arc<Mutex<Option<SecretKey>>>,
		config: WalletConfig,
		address: &EpicboxAddress,
	) -> Result<(), Error>
	where
		L: WalletLCProvider<'static, C, K> + 'static,
		C: NodeClient + 'static,
		K: Keychain + 'static,
	{
		let mask = keychain_mask.lock();
		// eventually want to read a list of service config keys
		let mut w_lock = wallet.lock();
		let lc = w_lock.lc_provider()?;
		let w_inst = lc.wallet_inst()?;

		let url = {
			let cloned_address = address.clone();
			match config.epicbox_protocol_unsecure {
				Some(true) => format!(
					"ws://{}:{}",
					cloned_address.domain,
					cloned_address.port.unwrap_or(DEFAULT_EPICBOX_PORT)
				),
				Some(false) => format!(
					"wss://{}:{}",
					cloned_address.domain,
					cloned_address.port.unwrap_or(DEFAULT_EPICBOX_PORT)
				),
				None => format!(
					"wss://{}:{}",
					cloned_address.domain,
					cloned_address.port.unwrap_or(DEFAULT_EPICBOX_PORT)
				),
			}
		};

		info!(
			"Listening for transactions on epicbox ... on {:?}",
			url.clone()
		);

		let cloned_address = address.clone();
		let cloned_inner = self.inner.clone();
		let cloned_handler = handler.clone();

		loop {
			// listen for messages from all channels with topic SLATE_NEW

			sleep(LISTEN_SLEEP_DURATION);
		}
		Ok(())
	}
}
