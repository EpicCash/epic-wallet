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
use crate::epicbox::protocol::{ProtocolRequest, ProtocolResponse};
use crate::keychain::Keychain;
use crate::libwallet::crypto::{sign_challenge, Hex};
use crate::libwallet::EpicboxAddress;
use crate::libwallet::{Error, NodeClient, WalletInst, WalletLCProvider, DEFAULT_EPICBOX_PORT};
use crate::util::secp::key::SecretKey;
use crate::util::Mutex;
use std::sync::Arc;

use std::time::Duration;

use ws::util::Token;
use ws::{
	connect, CloseCode, Error as WsError, ErrorKind as WsErrorKind, Handler, Handshake, Message,
	Result as WsResult, Sender,
};

const KEEPALIVE_TOKEN: Token = Token(1);
const KEEPALIVE_INTERVAL_MS: u64 = 30_000;
const LISTEN_SLEEP_DURATION: Duration = Duration::from_millis(5000);

pub enum CloseReason {
	Normal,
	Abnormal(Error),
}

struct ConnectionMetadata {
	retries: u32,
	connected_at_least_once: bool,
}

impl ConnectionMetadata {
	pub fn new() -> Self {
		Self {
			retries: 0,
			connected_at_least_once: false,
		}
	}
}

/// Receives slates on all channels with topic SLATE_NEW
pub struct EpicboxAllChannels {
	_priv: (), // makes EpicboxAllChannels unconstructable without checking for existence of keybase executable
	inner: Arc<Mutex<Option<Sender>>>,
	protocol_unsecure: bool,
}

impl EpicboxAllChannels {
	/// Create a EpicboxAllChannels,
	pub fn new() -> Result<EpicboxAllChannels, Error> {
		Ok(EpicboxAllChannels {
			_priv: (),
			inner: Arc::new(Mutex::new(None)),
			protocol_unsecure: false,
		})
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
		secret_key: &SecretKey,
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
		let connection_meta_data = Arc::new(Mutex::new(ConnectionMetadata::new()));

		//let cloned_inner = self.inner.clone();
		//ålet cloned_handler = handler.clone();

		loop {
			// listen for messages from all channels with topic SLATE_NEW
			let cloned_address = cloned_address.clone();
			let cloned_connection_meta_data = connection_meta_data.clone();
			let cloned_cloned_inner = cloned_inner.clone();
			let result = connect(url.clone(), |sender| {
				{
					let mut guard = cloned_cloned_inner.lock();
					*guard = Some(sender.clone());
				}

				let client = EpicboxClient {
					sender,
					//handler: cloned_handler.clone(),
					challenge: None,
					address: cloned_address.clone(),
					secret_key: secret_key.clone(),
					connection_meta_data: cloned_connection_meta_data.clone(),
				};
				client
			});

			let is_stopped = cloned_inner.lock().is_none();

			if is_stopped {
				match result {
					Err(_) => {
						println!("error is stopped")
					} //handler.lock().on_close(CloseReason::Abnormal(ErrorKind::EpicboxWebsocketAbnormalTermination.into(),)),
					_ => {
						println!("handler on stop")
						//handler.lock().on_close(CloseReason::Normal)
					}
				}
				break;
			} else {
				let mut guard = connection_meta_data.lock();
				if guard.retries == 0 && guard.connected_at_least_once {
					//handler.lock().on_dropped();
				}
				let secs = std::cmp::min(32, 2u64.pow(guard.retries));
				let duration = std::time::Duration::from_secs(secs);
				std::thread::sleep(duration);
				guard.retries += 1;
			}
		}
		let mut guard = cloned_inner.lock();
		*guard = None;
		Ok(())
	}
}

struct EpicboxClient {
	sender: Sender,
	//handler: Arc<Mutex<Controller<W, C, K, P>>>,
	challenge: Option<String>,
	address: EpicboxAddress,
	secret_key: SecretKey,
	connection_meta_data: Arc<Mutex<ConnectionMetadata>>,
}

impl EpicboxClient {
	fn subscribe(&self, challenge: &str) -> Result<(), Error> {
		let signature = sign_challenge(&challenge, &self.secret_key)?.to_hex();
		let request = ProtocolRequest::Subscribe {
			address: self.address.public_key.to_string(),
			signature,
		};
		self.send(&request)
			.expect("could not send subscribe request!");
		Ok(())
	}

	fn send(&self, request: &ProtocolRequest) -> Result<(), Error> {
		let request = serde_json::to_string(&request).unwrap();

		//self.sender.send(request)?;
		Ok(())
	}
}

impl Handler for EpicboxClient {
	fn on_open(&mut self, _shake: Handshake) -> WsResult<()> {
		let mut guard = self.connection_meta_data.lock();

		if guard.connected_at_least_once {
			//self.handler.lock().on_reestablished();
		} else {
			//self.handler.lock().on_open();
			guard.connected_at_least_once = true;
		}

		guard.retries = 0;

		self.sender
			.timeout(KEEPALIVE_INTERVAL_MS, KEEPALIVE_TOKEN)?;
		Ok(())
	}

	fn on_timeout(&mut self, event: Token) -> WsResult<()> {
		match event {
			KEEPALIVE_TOKEN => {
				self.sender.ping(vec![])?;
				self.sender.timeout(KEEPALIVE_INTERVAL_MS, KEEPALIVE_TOKEN)
			}
			_ => Err(WsError::new(
				WsErrorKind::Internal,
				"Invalid timeout token encountered!",
			)),
		}
	}

	fn on_message(&mut self, msg: Message) -> WsResult<()> {
		let response = match serde_json::from_str::<ProtocolResponse>(&msg.to_string()) {
			Ok(x) => x,
			Err(_) => {
				println!("{} Could not parse response", "ERROR:");
				return Ok(());
			}
		};

		match response {
			ProtocolResponse::Challenge { str } => {
				self.challenge = Some(str.clone());
				self.subscribe(&str).map_err(|_| {
					WsError::new(WsErrorKind::Protocol, "error attempting to subscribe!")
				})?;
			}
			ProtocolResponse::Slate {
				from,
				str,
				challenge,
				signature,
			} => {
				/*let (slate, mut tx_proof) = match TxProof::from_response(
					from,
					str,
					challenge,
					signature,
					&self.secret_key,
					Some(&self.address),
				) {
					Ok(x) => x,
					Err(e) => {
						println!("{} {}", "ERROR:".bright_red(), e);
						return Ok(());
					}
				};

				let address = tx_proof.address.clone();
				self.handler
					.lock()
					.on_slate(&address, &slate, Some(&mut tx_proof));*/
			}
			ProtocolResponse::Error {
				kind: _,
				description: _,
			} => {
				println!("{} {}", "ERROR:", response);
			}
			_ => {}
		}
		Ok(())
	}

	fn on_error(&mut self, err: WsError) {
		// Ignore connection reset errors by default
		if let WsErrorKind::Io(ref err) = err.kind {
			if let Some(104) = err.raw_os_error() {
				return;
			}
		}

		error!("{:?}", err);
	}
}
