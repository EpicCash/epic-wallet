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
use crate::config::WalletConfig;
use crate::epicbox::protocol::{ProtocolRequest, ProtocolResponse};
use crate::keychain::Keychain;
use crate::libwallet::crypto::{sign_challenge, Hex};
use crate::libwallet::message::EncryptedMessage;

use crate::libwallet::wallet_lock;
use crate::libwallet::{Address, AddressType, EpicboxAddress, TxProof};
use crate::libwallet::{
	Error, ErrorKind, NodeClient, WalletInst, WalletLCProvider, DEFAULT_EPICBOX_PORT,
};
use crate::libwallet::{Slate, VersionedSlate};
use crate::util::secp::key::SecretKey;
use crate::util::Mutex;

use std::collections::HashMap;
use std::fmt::{self, Debug};

use std::sync::Arc;
use std::thread::JoinHandle;

use crate::libwallet::api_impl::foreign;
use crate::libwallet::api_impl::owner;

use ws::util::Token;
use ws::{
	connect, CloseCode, Error as WsError, ErrorKind as WsErrorKind, Handler, Handshake, Message,
	Result as WsResult, Sender,
};
// Copyright 2019 The vault713 Developers
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

/// Epicbox 'plugin' implementation

/// Encapsulate wallet to wallet communication functions
pub trait Adapter {
	/// Whether this adapter supports sync mode
	fn supports_sync(&self) -> bool;

	/// Send a transaction slate to another listening wallet and return result
	fn send_tx_sync(&self, addr: &str, slate: &VersionedSlate) -> Result<VersionedSlate, Error>;

	/// Send a transaction asynchronously (result will be returned via the listener)
	fn send_tx_async(&self, addr: &str, slate: &VersionedSlate) -> Result<(), Error>;
}
#[derive(Clone)]
pub struct EpicboxAdapter<'a> {
	container: &'a Arc<Mutex<Container>>,
}

impl<'a> EpicboxAdapter<'a> {
	/// Create
	pub fn new(container: &'a Arc<Mutex<Container>>) -> Box<Self> {
		Box::new(Self { container })
	}
}

impl<'a> Adapter for EpicboxAdapter<'a> {
	fn supports_sync(&self) -> bool {
		false
	}

	fn send_tx_sync(&self, _dest: &str, _slate: &VersionedSlate) -> Result<VersionedSlate, Error> {
		unimplemented!();
	}

	fn send_tx_async(&self, dest: &str, slate: &VersionedSlate) -> Result<(), Error> {
		println!("EpicboxAdapter send_tx_async");
		let c = self.container.lock();
		println!("EpicboxAdapter send_tx_async lock container");
		c.listener(ListenerInterface::Epicbox)?
			.publish(slate, &dest.to_owned())
	}
}

#[derive(Clone)]
pub struct EpicboxBroker {
	inner: Arc<Mutex<Option<Sender>>>,
	protocol_unsecure: bool,
}

const KEEPALIVE_TOKEN: Token = Token(1);
const KEEPALIVE_INTERVAL_MS: u64 = 30_000;

pub enum CloseReason {
	Normal,
	Abnormal(Error),
}

#[derive(Clone)]
pub struct EpicboxSubscriber {
	address: EpicboxAddress,
	broker: EpicboxBroker,
	secret_key: SecretKey,
}
#[derive(Clone)]
pub struct EpicboxPublisher {
	address: EpicboxAddress,
	broker: EpicboxBroker,
	secret_key: SecretKey,
}

pub struct EpicboxListener {
	pub address: EpicboxAddress,
	pub publisher: EpicboxPublisher,
	pub subscriber: EpicboxSubscriber,
	pub handle: JoinHandle<()>,
}

impl Listener for EpicboxListener {
	fn interface(&self) -> ListenerInterface {
		ListenerInterface::Epicbox
	}

	fn address(&self) -> String {
		self.address.stripped()
	}

	fn publish(&self, slate: &VersionedSlate, to: &String) -> Result<(), Error> {
		let address = EpicboxAddress::from_str(to)?;
		self.publisher.post_slate(slate, &address)
	}
	fn is_running(&self) -> bool {
		self.subscriber.is_running()
	}
	fn stop(self: Box<Self>) -> Result<(), Error> {
		let s = *self;
		s.subscriber.stop();
		let _ = s.handle.join();
		Ok(())
	}
}

impl EpicboxPublisher {
	pub fn new(
		address: EpicboxAddress,
		secret_key: SecretKey,
		protocol_unsecure: bool,
	) -> Result<Self, Error> {
		Ok(Self {
			address,
			broker: EpicboxBroker::new(protocol_unsecure)?,
			secret_key,
		})
	}
}

impl Publisher for EpicboxPublisher {
	fn post_slate(&self, slate: &VersionedSlate, to: &dyn Address) -> Result<(), Error> {
		let to = EpicboxAddress::from_str(&to.to_string())?;
		self.broker
			.post_slate(slate, &to, &self.address, &self.secret_key)?;
		Ok(())
	}
}
impl EpicboxSubscriber {
	pub fn new(publisher: &EpicboxPublisher) -> Result<Self, Error> {
		Ok(Self {
			address: publisher.address.clone(),
			broker: publisher.broker.clone(),
			secret_key: publisher.secret_key.clone(),
		})
	}
}

pub struct EpicboxController<P, L, C, K>
where
	P: Publisher,
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	name: String,
	publisher: P,
	/// Wallet instance
	pub wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
	/// Keychain mask
	pub keychain_mask: Arc<Mutex<Option<SecretKey>>>,
}
pub struct Container {
	pub config: WalletConfig,
	pub account: String,
	pub listeners: HashMap<ListenerInterface, Box<dyn Listener>>,
}
impl Container {
	pub fn new(config: WalletConfig) -> Arc<Mutex<Self>> {
		let container = Self {
			config,
			account: String::from("default"),
			listeners: HashMap::with_capacity(4),
		};
		Arc::new(Mutex::new(container))
	}

	pub fn listener(&self, interface: ListenerInterface) -> Result<&Box<dyn Listener>, ErrorKind> {
		self.listeners
			.get(&interface)
			.ok_or(ErrorKind::NoListener(format!("{}", interface)))
	}
}

pub trait Listener: Sync + Send + 'static {
	fn interface(&self) -> ListenerInterface;
	fn address(&self) -> String;
	fn publish(&self, slate: &VersionedSlate, to: &String) -> Result<(), Error>;
	fn stop(self: Box<Self>) -> Result<(), Error>;
	fn is_running(&self) -> bool;
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash)]
pub enum ListenerInterface {
	Epicbox,
	Keybase,
	ForeignHttp,
	OwnerHttp,
}
impl fmt::Display for ListenerInterface {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match *self {
			ListenerInterface::Epicbox => write!(f, "Epicbox"),
			ListenerInterface::Keybase => write!(f, "Keybase"),
			ListenerInterface::ForeignHttp => write!(f, "Foreign HTTP"),
			ListenerInterface::OwnerHttp => write!(f, "Owner HTTP"),
		}
	}
}

impl<P, L, C, K> EpicboxController<P, L, C, K>
where
	P: Publisher,
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	pub fn new(
		name: &str,
		// TODO: check if container is required
		_container: Arc<Mutex<Container>>,
		publisher: P,
		wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
		keychain_mask: Arc<Mutex<Option<SecretKey>>>,
	) -> Result<Self, Error> {
		Ok(Self {
			name: name.to_string(),
			publisher,
			wallet,
			keychain_mask,
		})
	}

	fn process_incoming_slate(
		&self,
		_address: Option<String>,
		slate: &mut Slate,
		_tx_proof: Option<&mut TxProof>,
	) -> Result<bool, Error> {
		/* build owner and foreign here */
		//let wallet = self.wallet.clone();
		let mask = self.keychain_mask.lock();
		wallet_lock!(self.wallet, w);

		if slate.num_participants > slate.participant_data.len() {
			if slate.tx.inputs().len() == 0 {
				// TODO: invoicing
			} else {
				println!("foreign::receive_tx");
				let ret_slate =
					foreign::receive_tx(&mut **w, (mask).as_ref(), &slate, None, None, false);
				*slate = ret_slate.unwrap();
			}

			Ok(false)
		} else {
			println!("owner::finalize_tx and post");
			let slate = owner::finalize_tx(&mut **w, (mask).as_ref(), slate)?;
			owner::post_tx(w.w2n_client(), &slate.tx, false)?;
			Ok(true)
		}
	}
}
pub trait SubscriptionHandler: Send {
	fn on_open(&self);
	fn on_slate(&self, from: &dyn Address, slate: &VersionedSlate, proof: Option<&mut TxProof>);
	fn on_close(&self, result: CloseReason);
	fn on_dropped(&self);
	fn on_reestablished(&self);
}

impl<P, L, C, K> SubscriptionHandler for EpicboxController<P, L, C, K>
where
	P: Publisher,
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	fn on_open(&self) {
		//        println!("Listener for {} started", self.name);
	}

	fn on_slate(&self, from: &dyn Address, slate: &VersionedSlate, tx_proof: Option<&mut TxProof>) {
		let version = slate.version();
		let mut slate: Slate = slate.clone().into();

		/*if slate.num_participants > slate.participant_data.len() {
			println!(
				"Slate [{}] received from [{}] for [{}] epics",
				slate.id.to_string(),
				display_from,
				amount_to_hr_string(slate.amount, false)
			);
		} else {
			println!(
				"Slate [{}] received back from [{}] for [{}] epics",
				slate.id.to_string(),
				display_from,
				amount_to_hr_string(slate.amount, false)
			);
		};*/

		if from.address_type() == AddressType::Epicbox {
			EpicboxAddress::from_str(&from.to_string()).expect("invalid epicbox address");
		}

		let result = self
			.process_incoming_slate(Some(from.to_string()), &mut slate, tx_proof)
			.and_then(|is_finalized| {
				if !is_finalized {
					let _id = slate.id.clone();
					let slate = VersionedSlate::into_version(slate, version);

					self.publisher
						.post_slate(&slate, from)
						.map_err(|e| {
							println!("{}: {}", "ERROR", e);
							e
						})
						.expect("failed posting slate!");
				} else {
					println!("Slate [{}] finalized successfully", slate.id.to_string());
				}
				Ok(())
			});

		match result {
			Ok(()) => {}
			Err(e) => println!("{}", e),
		}
	}

	fn on_close(&self, reason: CloseReason) {
		match reason {
			CloseReason::Normal => {
				//println!("Listener for {} stopped", self.name)
			}
			CloseReason::Abnormal(error) => {
				println!("Listener {} stopped unexpectedly {:?}", self.name, error)
			}
		}
	}

	fn on_dropped(&self) {
		println!("Listener {} lost connection. it will keep trying to restore connection in the background.", self.name)
	}

	fn on_reestablished(&self) {
		println!("Listener {} reestablished connection.", self.name)
	}
}
pub trait Subscriber {
	fn start<P, L, C, K>(&mut self, handler: EpicboxController<P, L, C, K>) -> Result<(), Error>
	where
		P: Publisher,
		L: WalletLCProvider<'static, C, K> + 'static,
		C: NodeClient + 'static,
		K: Keychain + 'static;
	fn stop(&self);
	fn is_running(&self) -> bool;
}
impl Subscriber for EpicboxSubscriber {
	fn start<P, L, C, K>(&mut self, handler: EpicboxController<P, L, C, K>) -> Result<(), Error>
	where
		P: Publisher,
		L: WalletLCProvider<'static, C, K> + 'static,
		C: NodeClient + 'static,
		K: Keychain + 'static,
	{
		self.broker
			.subscribe(&self.address, &self.secret_key, handler)?;
		Ok(())
	}

	fn stop(&self) {
		self.broker.stop();
	}

	fn is_running(&self) -> bool {
		self.broker.is_running()
	}
}

pub trait Publisher: Send {
	fn post_slate(&self, slate: &VersionedSlate, to: &dyn Address) -> Result<(), Error>;
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

impl EpicboxBroker {
	/// Create a EpicboxBroker,
	pub fn new(protocol_unsecure: bool) -> Result<Self, Error> {
		Ok(Self {
			inner: Arc::new(Mutex::new(None)),
			protocol_unsecure,
		})
	}
	/// Start a listener, passing received messages to the wallet api directly

	pub fn subscribe<P, L, C, K>(
		&self,
		address: &EpicboxAddress,
		secret_key: &SecretKey,
		handler: EpicboxController<P, L, C, K>,
	) -> Result<(), Error>
	where
		P: Publisher,
		L: WalletLCProvider<'static, C, K> + 'static,
		C: NodeClient + 'static,
		K: Keychain + 'static,
	{
		let handler = Arc::new(Mutex::new(handler));
		let url = {
			let cloned_address = address.clone();
			match self.protocol_unsecure {
				true => format!(
					"ws://{}:{}",
					cloned_address.domain,
					cloned_address.port.unwrap_or(DEFAULT_EPICBOX_PORT)
				),
				false => format!(
					"wss://{}:{}",
					cloned_address.domain,
					cloned_address.port.unwrap_or(DEFAULT_EPICBOX_PORT)
				),
			}
		};
		let cloned_address = address.clone();
		let cloned_inner = self.inner.clone();
		let cloned_handler = handler.clone();
		let connection_meta_data = Arc::new(Mutex::new(ConnectionMetadata::new()));
		loop {
			let cloned_address = cloned_address.clone();
			let cloned_handler = cloned_handler.clone();
			let cloned_cloned_inner = cloned_inner.clone();
			let cloned_connection_meta_data = connection_meta_data.clone();
			let result = connect(url.clone(), |sender| {
				{
					let mut guard = cloned_cloned_inner.lock();
					*guard = Some(sender.clone());
				}

				let client = EpicboxClient {
					sender,
					handler: cloned_handler.clone(),
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
					Err(_) => handler.lock().on_close(CloseReason::Abnormal(
						ErrorKind::EpicboxWebsocketAbnormalTermination.into(),
					)),
					_ => handler.lock().on_close(CloseReason::Normal),
				}
				break;
			} else {
				let mut guard = connection_meta_data.lock();
				if guard.retries == 0 && guard.connected_at_least_once {
					handler.lock().on_dropped();
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

	fn post_slate(
		&self,
		slate: &VersionedSlate,
		to: &EpicboxAddress,
		from: &EpicboxAddress,
		secret_key: &SecretKey,
	) -> Result<(), Error> {
		if !self.is_running() {
			return Err(ErrorKind::ClosedListener("epicbox".to_string()).into());
		}

		println!(
			"####################### post slate ###################### {}",
			serde_json::to_string(&slate).unwrap()
		);

		let pkey = to.public_key()?;
		let skey = secret_key.clone();
		let message =
			EncryptedMessage::new(serde_json::to_string(&slate).unwrap(), &to, &pkey, &skey)
				.map_err(|_| WsError::new(WsErrorKind::Protocol, "could not encrypt slate!"))
				.unwrap();
		let message_ser = serde_json::to_string(&message).unwrap();

		println!(
			"####################### post message_ser ###################### {}",
			serde_json::to_string(&message_ser).unwrap()
		);

		let mut challenge = String::new();
		challenge.push_str(&message_ser);

		let signature = sign_challenge(&challenge, secret_key)?.to_hex();
		let request = ProtocolRequest::PostSlate {
			from: from.stripped(),
			to: to.stripped(),
			str: message_ser,
			signature,
		};

		if let Some(ref sender) = *self.inner.lock() {
			sender
				.send(serde_json::to_string(&request).unwrap())
				.map_err(|_| ErrorKind::GenericError("failed posting slate!".to_string()).into())
		} else {
			Err(ErrorKind::GenericError("failed posting slate!".to_string()).into())
		}
	}
	fn stop(&self) {
		let mut guard = self.inner.lock();
		if let Some(ref sender) = *guard {
			let _ = sender.close(CloseCode::Normal);
		}
		*guard = None;
	}

	fn is_running(&self) -> bool {
		let guard = self.inner.lock();
		guard.is_some()
	}
}

struct EpicboxClient<P, L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
	P: Publisher,
{
	sender: Sender,
	handler: Arc<Mutex<EpicboxController<P, L, C, K>>>,
	challenge: Option<String>,
	address: EpicboxAddress,
	secret_key: SecretKey,
	connection_meta_data: Arc<Mutex<ConnectionMetadata>>,
}

impl<P, L, C, K> EpicboxClient<P, L, C, K>
where
	P: Publisher,
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
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

		self.sender.send(request).unwrap();
		Ok(())
	}
}

impl<P, L, C, K> Handler for EpicboxClient<P, L, C, K>
where
	P: Publisher,
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	fn on_open(&mut self, _shake: Handshake) -> WsResult<()> {
		let mut guard = self.connection_meta_data.lock();

		if guard.connected_at_least_once {
			self.handler.lock().on_reestablished();
		} else {
			self.handler.lock().on_open();
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
		println!("######## Handler on_message ######## {:?}", msg);

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
				let (slate, mut tx_proof) = match TxProof::from_response(
					from,
					str,
					challenge,
					signature,
					&self.secret_key,
					Some(&self.address),
				) {
					Ok(x) => x,
					Err(e) => {
						println!("{} {}", "ERROR:", e);
						return Ok(());
					}
				};

				let address = tx_proof.address.clone();
				self.handler
					.lock()
					.on_slate(&address, &slate, Some(&mut tx_proof));
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
		println!("######## Handler on_error ########");

		// Ignore connection reset errors by default
		if let WsErrorKind::Io(ref err) = err.kind {
			if let Some(104) = err.raw_os_error() {
				return;
			}
		}

		error!("{:?}", err);
	}
}
