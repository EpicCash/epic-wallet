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
use crate::libwallet::Slate;
use crate::libwallet::VersionedSlate;
use crate::libwallet::{Address, AddressType, EpicboxAddress, TxProof};
use crate::libwallet::{
	Error, ErrorKind, NodeClient, WalletBackend, WalletInst, WalletLCProvider, DEFAULT_EPICBOX_PORT,
};
use crate::util::secp::key::SecretKey;
use crate::util::Mutex;
use std::collections::HashMap;
use std::fmt::{self, Debug, Display};
use std::marker::PhantomData;
use std::sync::Arc;
use std::thread::JoinHandle;

use ws::util::Token;
use ws::{
	connect, CloseCode, Error as WsError, ErrorKind as WsErrorKind, Handler, Handshake, Message,
	Result as WsResult, Sender,
};
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

	fn stop(self: Box<Self>) -> Result<(), Error> {
		let s = *self;
		s.subscriber.stop();
		let _ = s.handle.join();
		Ok(())
	}
}

impl EpicboxPublisher {
	pub fn new(
		address: &EpicboxAddress,
		secret_key: &SecretKey,
		protocol_unsecure: bool,
	) -> Result<Self, Error> {
		Ok(Self {
			address: address.clone(),
			broker: EpicboxBroker::new(protocol_unsecure)?,
			secret_key: secret_key.clone(),
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

pub struct EpicboxController<P>
where
	P: Publisher,
{
	name: String,
	//owner: Owner<W, C, K>,
	//foreign: Foreign<W, C, K>,
	publisher: P,
}
pub struct Container {
	pub config: WalletConfig,

	pub account: String,
	pub listeners: HashMap<ListenerInterface, Box<dyn Listener>>,
}
pub trait Listener: Sync + Send + 'static {
	fn interface(&self) -> ListenerInterface;
	fn address(&self) -> String;
	fn publish(&self, slate: &VersionedSlate, to: &String) -> Result<(), Error>;
	fn stop(self: Box<Self>) -> Result<(), Error>;
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
impl<P> EpicboxController<P>
where
	P: Publisher,
{
	pub fn new(name: &str, container: Arc<Mutex<Container>>, publisher: P) -> Result<Self, Error> {
		Ok(Self {
			name: name.to_string(),
			//owner: Owner::new(container.clone()),
			//foreign: Foreign::new(container),
			publisher,
		})
	}

	fn process_incoming_slate(
		&self,
		address: Option<String>,
		slate: &mut Slate,
		tx_proof: Option<&mut TxProof>,
	) -> Result<bool, Error> {
		if slate.num_participants > slate.participant_data.len() {
			if slate.tx.inputs().len() == 0 {
				// TODO: invoicing
			} else {
				//*slate = self.foreign.receive_tx(slate, None, address, None)?;
			}
			Ok(false)
		} else {
			//self.owner.finalize_tx(slate)?;
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

impl<P> SubscriptionHandler for EpicboxController<P>
where
	P: Publisher,
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
					let id = slate.id.clone();
					let slate = VersionedSlate::into_version(slate, version);

					self.publisher
						.post_slate(&slate, from)
						.map_err(|e| {
							println!("{}: {}", "ERROR", e);
							e
						})
						.expect("failed posting slate!");
					println!(
						"Slate {} sent back to {} successfully",
						id.to_string(),
						from.stripped()
					);
				}
				/*else {
					println!(
						"Slate [{}] finalized successfully",
						slate.id.to_string()
					);
				}*/
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
	fn start<P>(&mut self, handler: EpicboxController<P>) -> Result<(), Error>
	where
		P: Publisher;
	fn stop(&self);
	fn is_running(&self) -> bool;
}
impl Subscriber for EpicboxSubscriber {
	fn start<P>(&mut self, handler: EpicboxController<P>) -> Result<(), Error>
	where
		P: Publisher,
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

	pub fn subscribe<P>(
		&self,
		address: &EpicboxAddress,
		secret_key: &SecretKey,
		handler: EpicboxController<P>,
	) -> Result<(), Error>
	where
		P: Publisher,
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

		let pkey = to.public_key()?;
		let skey = secret_key.clone();
		let message =
			EncryptedMessage::new(serde_json::to_string(&slate).unwrap(), &to, &pkey, &skey)
				.map_err(|_| WsError::new(WsErrorKind::Protocol, "could not encrypt slate!"))
				.unwrap();
		let message_ser = serde_json::to_string(&message).unwrap();

		let mut challenge = String::new();
		challenge.push_str(&message_ser);

		let signature = sign_challenge(&challenge, secret_key)?.to_hex();
		let request = ProtocolRequest::PostSlate {
			from: from.stripped(),
			to: to.stripped(),
			str: message_ser,
			signature,
		};

		println!(
			"####################### post slate ###################### {}",
			serde_json::to_string(&request).unwrap()
		);

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

struct EpicboxClient<P>
where
	P: Publisher,
{
	sender: Sender,
	handler: Arc<Mutex<EpicboxController<P>>>,
	challenge: Option<String>,
	address: EpicboxAddress,
	secret_key: SecretKey,
	connection_meta_data: Arc<Mutex<ConnectionMetadata>>,
}

impl<P> EpicboxClient<P>
where
	P: Publisher,
{
	fn subscribe(&self, challenge: &str) -> Result<(), Error> {
		println!("subscribe challenge {:?}", challenge);
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

impl<P> Handler for EpicboxClient<P>
where
	P: Publisher,
{
	fn on_open(&mut self, _shake: Handshake) -> WsResult<()> {
		println!("######## Handler on_open ########");

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
		println!("######## Handler on_timeout ########");

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
		println!("######## Handler on_message ########");

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
