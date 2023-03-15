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

use crate::config::EpicboxConfig;
use crate::epicbox::protocol::{ProtocolRequest, ProtocolResponse};
use crate::keychain::Keychain;
use crate::libwallet::crypto::{sign_challenge, Hex};
use crate::libwallet::message::EncryptedMessage;
use crate::util::secp::key::PublicKey;

use crate::libwallet::wallet_lock;
use crate::libwallet::{
	address, Address, AddressType, EpicboxAddress, TxProof, DEFAULT_EPICBOX_PORT_443,
	DEFAULT_EPICBOX_PORT_80,
};
use crate::libwallet::{NodeClient, WalletInst, WalletLCProvider};

use crate::Error;
use crate::ErrorKind;

use crate::libwallet::{Slate, SlateVersion, VersionedSlate};
use crate::util::secp::key::SecretKey;
use crate::util::Mutex;

use std::collections::HashMap;
use std::fmt::{self, Debug};

use crate::error::ErrorKind as ErrorKind2;
use std::sync::Arc;
use std::thread::JoinHandle;

use crate::libwallet::api_impl::foreign;
use crate::libwallet::api_impl::owner;
use epic_wallet_util::epic_core::core::amount_to_hr_string;
use std::net::TcpStream;
use std::string::ToString;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread::spawn;
use tungstenite::connect;
use tungstenite::Error as tungsteniteError;
use tungstenite::{protocol::WebSocket, stream::MaybeTlsStream};
use tungstenite::{Error as ErrorTungstenite, Message};

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

const CONNECTION_ERR_MSG: &str = "\nCan't connect to the epicbox server!\n\
	Check your epic-wallet.toml settings and make sure epicbox domain is correct.\n";
const DEFAULT_INTERVAL: u64 = 10;
const MIN_INTERVAL: u64 = 2;
const MAX_INTERVAL: u64 = 120;

const DEFAULT_CHALLENGE_RAW: &str = "7WUDtkSaKyGRUnQ22rE3QUXChV8DmA6NnunDYP4vheTpc";

/// Epicbox 'plugin' implementation
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

#[derive(Clone)]
pub struct EpicboxChannel {
	dest: String,
	epicbox_config: Option<EpicboxConfig>,
}

#[derive(Clone)]
pub struct EpicboxListenChannel {
	_priv: (),
}

impl EpicboxListenChannel {
	pub fn new() -> Result<EpicboxListenChannel, Error> {
		Ok(EpicboxListenChannel { _priv: () })
	}
	pub fn listen<L, C, K>(
		&self,
		wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
		keychain_mask: Arc<Mutex<Option<SecretKey>>>,
		epicbox_config: EpicboxConfig,
		interval_arg: Option<u64>,
	) -> Result<(), Error>
	where
		L: WalletLCProvider<'static, C, K> + 'static,
		C: NodeClient + 'static,
		K: Keychain + 'static,
	{
		let (address, sec_key, interval) = {
			let a_keychain = keychain_mask.clone();
			let a_wallet = wallet.clone();
			let mask = a_keychain.lock();
			let mut w_lock = a_wallet.lock();
			let lc = w_lock.lc_provider()?;
			let w_inst = lc.wallet_inst()?;
			let k = w_inst.keychain((&mask).as_ref())?;
			let parent_key_id = w_inst.parent_key_id();
			let sec_key = address::address_from_derivation_path(&k, &parent_key_id, 0)
				.map_err(|e| ErrorKind2::ArgumentError(format!("{:?}", e).into()))
				.unwrap();
			let pub_key = PublicKey::from_secret_key(k.secp(), &sec_key).unwrap();

			let address = EpicboxAddress::new(
				pub_key.clone(),
				Some(epicbox_config.epicbox_domain.clone()),
				epicbox_config.epicbox_port,
			);

			let mut interval = interval_arg;
			if interval.is_none() {
				interval = epicbox_config.epicbox_listener_interval
			}

			(address, sec_key, interval)
		};
		let url = {
			let cloned_address = address.clone();
			match epicbox_config.epicbox_protocol_unsecure.unwrap_or(false) {
				true => format!(
					"ws://{}:{}",
					cloned_address.domain,
					cloned_address.port.unwrap_or(DEFAULT_EPICBOX_PORT_80)
				),
				false => format!(
					"wss://{}:{}",
					cloned_address.domain,
					cloned_address.port.unwrap_or(DEFAULT_EPICBOX_PORT_443)
				),
			}
		};
		let (tx, _rx): (Sender<bool>, Receiver<bool>) = channel();

		debug!("Connecting to the epicbox server at {} ..", url.clone());
		let (socket, _response) = connect(url.clone()).map_err(|e| {
			warn!("{}", ErrorKind::EpicboxTungstenite(format!("{}", e).into()));
			ErrorKind::EpicboxTungstenite(format!("{}", e).into())
		})?;

		let publisher = EpicboxPublisher::new(address.clone(), sec_key, socket, tx)?;

		let mut subscriber = EpicboxSubscriber::new(&publisher)?;

		let container = Container::new(epicbox_config.clone());
		let cpublisher = publisher.clone();
		let mask = keychain_mask.lock();
		let km = mask.clone();
		let controller = EpicboxController::new(container, cpublisher, wallet, km)
			.expect("Could not init epicbox listener!");

		warn!("Starting epicbox listener for: {}", address);

		subscriber.start(controller, interval)
	}
}
impl EpicboxChannel {
	/// new epicbox.
	pub fn new(
		dest: &String,
		epicbox_config: Option<EpicboxConfig>,
	) -> Result<EpicboxChannel, Error> {
		Ok(EpicboxChannel {
			dest: dest.clone(),
			epicbox_config: epicbox_config.clone(),
		})
	}

	pub fn send<L, C, K>(
		&self,
		wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
		keychain_mask: Option<SecretKey>,
		slate: &Slate,
	) -> Result<Slate, Error>
	where
		L: WalletLCProvider<'static, C, K> + 'static,
		C: NodeClient + 'static,
		K: Keychain + 'static,
	{
		let config = match self.epicbox_config.clone() {
			None => EpicboxConfig::default(),
			Some(epicbox_config) => epicbox_config,
		};

		let container = Container::new(config.clone());

		let (tx, rx): (Sender<bool>, Receiver<bool>) = channel();
		let listener = start_epicbox(container.clone(), wallet, keychain_mask, config, tx).unwrap();

		container
			.lock()
			.listeners
			.insert(ListenerInterface::Epicbox, listener);

		loop {
			std::thread::sleep(std::time::Duration::from_secs(1));
			if rx.recv().unwrap() {
				break;
			}
		}

		let vslate = VersionedSlate::into_version(slate.clone(), SlateVersion::V2);

		let _ = container
			.lock()
			.listener(ListenerInterface::Epicbox)
			.unwrap()
			.publish(&vslate, &self.dest)
			.unwrap();

		let slate: Slate = VersionedSlate::into_version(slate.clone(), SlateVersion::V2).into();
		Ok(slate)
	}
}

pub fn start_epicbox<L, C, K>(
	container: Arc<Mutex<Container>>,
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
	keychain_mask: Option<SecretKey>,
	config: EpicboxConfig,
	tx: Sender<bool>,
) -> Result<Box<dyn Listener>, Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	let (address, sec_key, interval) = {
		let a_wallet = wallet.clone();
		let mut w_lock = a_wallet.lock();
		let lc = w_lock.lc_provider()?;
		let w_inst = lc.wallet_inst()?;
		let k = w_inst.keychain(keychain_mask.as_ref())?;
		let parent_key_id = w_inst.parent_key_id();
		let sec_key = address::address_from_derivation_path(&k, &parent_key_id, 0)
			.map_err(|e| ErrorKind2::ArgumentError(format!("{:?}", e).into()))
			.unwrap();
		let pub_key = PublicKey::from_secret_key(k.secp(), &sec_key).unwrap();

		let interval: Option<u64> = config.epicbox_listener_interval;

		let address = EpicboxAddress::new(
			pub_key.clone(),
			Some(config.epicbox_domain.clone()),
			config.epicbox_port,
		);
		(address, sec_key, interval)
	};
	let url = {
		let cloned_address = address.clone();
		match config.epicbox_protocol_unsecure.unwrap_or(false) {
			true => format!(
				"ws://{}:{}",
				cloned_address.domain,
				cloned_address.port.unwrap_or(DEFAULT_EPICBOX_PORT_80)
			),
			false => format!(
				"wss://{}:{}",
				cloned_address.domain,
				cloned_address.port.unwrap_or(DEFAULT_EPICBOX_PORT_443)
			),
		}
	};
	debug!("Connecting to the epicbox server at {} ..", url.clone());
	let (socket, _) = connect(url.clone()).expect(CONNECTION_ERR_MSG);

	let publisher = EpicboxPublisher::new(address.clone(), sec_key, socket, tx)?;
	let subscriber = EpicboxSubscriber::new(&publisher)?;

	let mut csubscriber = subscriber.clone();
	let cpublisher = publisher.clone();

	let handle = spawn(move || {
		let controller = EpicboxController::new(container, cpublisher, wallet, keychain_mask)
			.expect("Could not init epicbox controller!");

		csubscriber
			.start(controller, interval)
			.expect("Could not start epicbox controller!");
		()
	});

	Ok(Box::new(EpicboxListener {
		address,
		publisher,
		subscriber,
		handle,
	}))
}

impl Listener for EpicboxListener {
	/// keep :)
	fn interface(&self) -> ListenerInterface {
		ListenerInterface::Epicbox
	}

	fn address(&self) -> String {
		self.address.stripped()
	}
	/// post slate
	fn publish(&self, slate: &VersionedSlate, to: &String) -> Result<(), Error> {
		let address = EpicboxAddress::from_str(to)?;
		self.publisher.post_slate(slate, &address, true)
	}

	/// stops wss connection
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
		socket: WebSocket<MaybeTlsStream<TcpStream>>,
		tx: Sender<bool>,
	) -> Result<Self, Error> {
		Ok(Self {
			address,
			broker: EpicboxBroker::new(socket, tx)?,
			secret_key,
		})
	}
}

impl Publisher for EpicboxPublisher {
	fn post_slate(
		&self,
		slate: &VersionedSlate,
		to: &dyn Address,
		close_connection: bool,
	) -> Result<(), Error> {
		let to = EpicboxAddress::from_str(&to.to_string())?;
		self.broker
			.post_slate(slate, &to, &self.address, &self.secret_key)?;
		if close_connection {
			self.broker.stop().unwrap();
		}
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
	publisher: P,
	/// Wallet instance
	pub wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
	/// Keychain mask
	pub keychain_mask: Option<SecretKey>,
}
pub struct Container {
	pub config: EpicboxConfig,
	pub account: String,
	pub listeners: HashMap<ListenerInterface, Box<dyn Listener>>,
}
impl Container {
	pub fn new(config: EpicboxConfig) -> Arc<Mutex<Self>> {
		let container = Self {
			config,
			account: String::from("default"),
			///TODO: reduce listeners
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

pub trait Listener: Send + 'static {
	fn interface(&self) -> ListenerInterface;
	fn address(&self) -> String;
	fn publish(&self, slate: &VersionedSlate, to: &String) -> Result<(), Error>;
	fn stop(self: Box<Self>) -> Result<(), Error>;
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash)]
pub enum ListenerInterface {
	Epicbox,
}
impl fmt::Display for ListenerInterface {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match *self {
			ListenerInterface::Epicbox => write!(f, "Epicbox"),
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
		// TODO: check if container is required
		_container: Arc<Mutex<Container>>,
		publisher: P,
		wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
		keychain_mask: Option<SecretKey>,
	) -> Result<Self, Error> {
		Ok(Self {
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

		wallet_lock!(self.wallet, w);

		if slate.num_participants > slate.participant_data.len() {
			if slate.tx.inputs().len() == 0 {
				// TODO: invoicing
			} else {
				info!("Received new transaction (foreign::receive_tx)");
				let ret_slate = foreign::receive_tx(
					&mut **w,
					self.keychain_mask.as_ref(),
					&slate,
					None,
					None,
					false,
				);
				*slate = ret_slate.unwrap();
			}

			Ok(false)
		} else {
			info!("Finalize transaction (owner::finalize_tx)");
			let slate = owner::finalize_tx(&mut **w, self.keychain_mask.as_ref(), slate)?;

			info!("Post transaction to the network (owner::post_tx)");
			owner::post_tx(w.w2n_client(), &slate.tx, false)?;
			Ok(true)
		}
	}
}
pub trait SubscriptionHandler: Send {
	fn on_slate(&self, from: &dyn Address, slate: &VersionedSlate, proof: Option<&mut TxProof>);
	fn on_close(&self, result: CloseReason);
}

impl<P, L, C, K> SubscriptionHandler for EpicboxController<P, L, C, K>
where
	P: Publisher,
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	fn on_slate(&self, from: &dyn Address, slate: &VersionedSlate, tx_proof: Option<&mut TxProof>) {
		let version = slate.version();
		let mut slate: Slate = slate.clone().into();

		if slate.num_participants > slate.participant_data.len() {
			debug!(
				"Slate [{}] received from [{}] for [{}] epics",
				slate.id.to_string(),
				from.to_string(),
				amount_to_hr_string(slate.amount, false)
			);
		} else {
			debug!(
				"Slate [{}] received back from [{}] for [{}] epics",
				slate.id.to_string(),
				from.to_string(),
				amount_to_hr_string(slate.amount, false)
			);
		};

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
						.post_slate(&slate, from, false)
						.map_err(|e| {
							error!("{}: {}", "ERROR", e);
							e
						})
						.expect("failed posting slate!");
				} else {
					debug!("Slate [{}] finalized successfully", slate.id.to_string());
				}
				Ok(())
			});

		match result {
			Ok(()) => {}
			Err(e) => error!("{}", e),
		}
	}

	fn on_close(&self, reason: CloseReason) {
		match reason {
			CloseReason::Normal => {
				debug!("Listener for stopped, normal exit")
			}
			CloseReason::Abnormal(error) => {
				error!("{:?}", error.to_string())
			}
		}
	}
}
pub trait Subscriber {
	fn start<P, L, C, K>(
		&mut self,
		handler: EpicboxController<P, L, C, K>,
		interval: Option<u64>,
	) -> Result<(), Error>
	where
		P: Publisher,
		L: WalletLCProvider<'static, C, K> + 'static,
		C: NodeClient + 'static,
		K: Keychain + 'static;
	fn stop(&self);
}
impl Subscriber for EpicboxSubscriber {
	fn start<P, L, C, K>(
		&mut self,
		handler: EpicboxController<P, L, C, K>,
		interval: Option<u64>,
	) -> Result<(), Error>
	where
		P: Publisher,
		L: WalletLCProvider<'static, C, K> + 'static,
		C: NodeClient + 'static,
		K: Keychain + 'static,
	{
		self.broker
			.subscribe(&self.address, &self.secret_key, handler, interval)
	}

	fn stop(&self) {
		let _ = self.broker.stop();
	}
}

pub trait Publisher: Send {
	fn post_slate(
		&self,
		slate: &VersionedSlate,
		to: &dyn Address,
		close_connection: bool,
	) -> Result<(), Error>;
}

///TODO: reduce to broker
#[derive(Clone)]
pub struct EpicboxBroker {
	inner: Arc<Mutex<WebSocket<MaybeTlsStream<TcpStream>>>>,
	tx: Sender<bool>,
}
impl EpicboxBroker {
	/// Create a EpicboxBroker,
	pub fn new(
		inner: WebSocket<MaybeTlsStream<TcpStream>>,
		tx: Sender<bool>,
	) -> Result<Self, Error> {
		Ok(Self {
			inner: Arc::new(Mutex::new(inner)),
			tx,
		})
	}

	/// Start a listener, passing received messages to the wallet api directly
	pub fn subscribe<P, L, C, K>(
		&mut self,
		address: &EpicboxAddress,
		secret_key: &SecretKey,
		handler: EpicboxController<P, L, C, K>,
		interval: Option<u64>,
	) -> Result<(), Error>
	where
		P: Publisher,
		L: WalletLCProvider<'static, C, K> + 'static,
		C: NodeClient + 'static,
		K: Keychain + 'static,
	{
		let handler = Arc::new(Mutex::new(handler));
		let sender = self.inner.clone();
		let mut first_run = true;

		// Parse from epicbox config or use default value for the
		// time interval between new subscribe calls from the wallet
		let mut seconds = interval.unwrap_or(DEFAULT_INTERVAL);
		if seconds < MIN_INTERVAL {
			seconds = MIN_INTERVAL
		} else if seconds > MAX_INTERVAL {
			seconds = MAX_INTERVAL
		}
		let duration = std::time::Duration::from_secs(seconds);

		let mut client = EpicboxClient {
			sender,
			handler: handler.clone(),
			challenge: None,
			address: address.clone(),
			secret_key: secret_key.clone(),
			tx: self.tx.clone(),
		};

		let subscribe = DEFAULT_CHALLENGE_RAW;
		let signature = sign_challenge(&subscribe, &secret_key)?.to_hex();

		let request = ProtocolRequest::Subscribe {
			address: client.address.public_key.to_string(),
			signature,
		};
		client
			.send(&request)
			.expect("Could not send Subscribe request!");

		let res = loop {
			let err = client.sender.lock().read_message();
			let mut new_challenge = false;

			match err {
				Err(e) => {
					error!("Error reading message {:?}", e);
					handler.lock().on_close(CloseReason::Abnormal(
						ErrorKind::EpicboxWebsocketAbnormalTermination.into(),
					));
					match client.sender.lock().close(None) {
						Ok(_) => error!("Client closed connection"),
						Err(e) => error!("Client closed connection {:?}", e),
					}

					break Err(ErrorKind::EpicboxWebsocketAbnormalTermination.into());
				}
				Ok(message) => match message {
					Message::Text(_) | Message::Binary(_) => {
						let response =
							match serde_json::from_str::<ProtocolResponse>(&message.to_string()) {
								Ok(x) => x,
								Err(_) => {
									error!("Could not parse response");
									return Ok(());
								}
							};

						match response {
							ProtocolResponse::Challenge { str } => {
								client.challenge = Some(str.clone());
								client
									.challenge_send()
									.map_err(|_| {
										error!("Error attempting to subscribe!");
									})
									.unwrap();

								if !first_run {
									std::thread::sleep(duration);
								} else {
									new_challenge = true;
								}
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
									&client.secret_key,
									Some(&client.address),
								) {
									Ok(x) => x,
									Err(e) => {
										error!("{}", e.to_string());
										return Ok(());
									}
								};

								let address = tx_proof.address.clone();
								client.handler.lock().on_slate(
									&address,
									&slate,
									Some(&mut tx_proof),
								);
							}

							ProtocolResponse::Error {
								kind: _,
								description: _,
							} => {
								error!("ProtocolResponse::Error {}", response);
							}
							_ => {}
						}
					}
					Message::Ping(_) => {}
					Message::Pong(_) => {}
					Message::Frame(_) => {}
					Message::Close(_) => {
						info!("Close {:?}", &message.to_string());
						handler.lock().on_close(CloseReason::Normal);
						client.sender.lock().close(None).unwrap();
						break Ok(());
					}
				},
			};

			if new_challenge {
				client
					.new_challenge()
					.map_err(|_| error!("error attempting challenge!"))
					.unwrap();

				debug!("Refresh epicbox subscription (interval: {:?})", duration);
				if first_run {
					std::thread::sleep(duration);
					first_run = false;
				}
			}
		}; //end loop

		res
	}

	fn post_slate(
		&self,
		slate: &VersionedSlate,
		to: &EpicboxAddress,
		from: &EpicboxAddress,
		secret_key: &SecretKey,
	) -> Result<(), Error> {
		let pkey = to.public_key()?;

		let skey = secret_key.clone();

		let message =
			EncryptedMessage::new(serde_json::to_string(&slate).unwrap(), &to, &pkey, &skey)
				.map_err(|_| error!("could not encrypt slate!"))
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

		self.inner
			.lock()
			.write_message(Message::Text(serde_json::to_string(&request).unwrap()))
			.unwrap();

		Ok(())
	}
	fn stop(&self) -> Result<(), tungsteniteError> {
		self.inner.lock().close(None)
	}
}

struct EpicboxClient<P, L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
	P: Publisher,
{
	sender: Arc<Mutex<WebSocket<MaybeTlsStream<TcpStream>>>>,
	handler: Arc<Mutex<EpicboxController<P, L, C, K>>>,
	challenge: Option<String>,
	address: EpicboxAddress,
	secret_key: SecretKey,
	tx: Sender<bool>,
}

/// client with handler from ws package
impl<P, L, C, K> EpicboxClient<P, L, C, K>
where
	P: Publisher,
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	fn challenge_send(&self) -> Result<(), Error> {
		let request = ProtocolRequest::Challenge;
		self.send(&request)
			.expect("could not send Challenge request!");
		self.tx.send(true).unwrap();
		Ok(())
	}

	fn new_challenge(&self) -> Result<(), Error> {
		let request = ProtocolRequest::Challenge;
		self.send(&request)
			.expect("Could not send Challenge request!");
		Ok(())
	}

	fn send(&self, request: &ProtocolRequest) -> Result<(), ErrorTungstenite> {
		let request = serde_json::to_string(&request).unwrap();

		self.sender
			.lock()
			.write_message(Message::Text(request.into()))
	}
}
