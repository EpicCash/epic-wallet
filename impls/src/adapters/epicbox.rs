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
use crate::libwallet::{Error, ErrorKind, NodeClient, WalletInst, WalletLCProvider};

use crate::libwallet::{Slate, VersionedSlate};
use crate::util::secp::key::SecretKey;
use crate::util::Mutex;

use std::collections::HashMap;
use std::fmt::{self, Debug};

use std::sync::Arc;

use std::thread::JoinHandle;

use crate::libwallet::api_impl::foreign;
use crate::libwallet::api_impl::owner;
use tungstenite::Error as tungsteniteError;
//use ws::util::Token;
//use ws::{
//	connect, CloseCode, Error as WsError, ErrorKind as WsErrorKind, Handler, Handshake, Message,
//	Result as WsResult, Sender,
//};

use std::net::TcpStream;
use std::sync::mpsc::Sender;
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
				debug!("foreign::receive_tx");
				let ret_slate =
					foreign::receive_tx(&mut **w, (mask).as_ref(), &slate, None, None, false);
				*slate = ret_slate.unwrap();
			}

			Ok(false)
		} else {
			debug!("owner::finalize_tx and post");
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
		//println!("Listener for {} started", self.name);
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
						.post_slate(&slate, from, false)
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
	) -> Result<(), Error>
	where
		P: Publisher,
		L: WalletLCProvider<'static, C, K> + 'static,
		C: NodeClient + 'static,
		K: Keychain + 'static,
	{
		let handler = Arc::new(Mutex::new(handler));

		let sender = self.inner.clone();

		let mut client = EpicboxClient {
			sender,
			handler: handler.clone(),
			challenge: None,
			address: address.clone(),
			secret_key: secret_key.clone(),
			tx: self.tx.clone(),
		};

		loop {
			let err = client.sender.lock().read_message();
			let mut new_challenge = false;

			match err {
				Err(e) => {
					error!("Error reading message {:?}", e);
					handler.lock().on_close(CloseReason::Abnormal(
						ErrorKind::EpicboxWebsocketAbnormalTermination.into(),
					));
					client.sender.lock().close(None).unwrap();

					break;
				}
				Ok(message) => match message {
					Message::Text(_) | Message::Binary(_) => {
						let response =
							match serde_json::from_str::<ProtocolResponse>(&message.to_string()) {
								Ok(x) => x,
								Err(_) => {
									error!("{} Could not parse response", "ERROR:");
									return Ok(());
								}
							};

						match response {
							ProtocolResponse::Challenge { str } => {
								client.challenge = Some(str.clone());
								client
									.challenge_subscribe(&str)
									.map_err(|_| {
										error!("error attempting to subscribe!");
									})
									.unwrap();
								//wait one minute before start new subscription
								let duration = std::time::Duration::from_secs(60);
								std::thread::sleep(duration);
								new_challenge = true;
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
										error!("{}", e);
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
						break;
					}
				},
			};

			if new_challenge {
				info!("refresh subscription!");

				client
					.new_challenge()
					.map_err(|_| {
						error!("error attempting challenge!");
					})
					.unwrap();
			}
		} //end loop

		Ok(())
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
	fn challenge_subscribe(&self, challenge: &str) -> Result<(), Error> {
		let signature = sign_challenge(&challenge, &self.secret_key)?.to_hex();
		let request = ProtocolRequest::Subscribe {
			address: self.address.public_key.to_string(),
			signature,
		};

		self.send(&request)
			.expect("could not send subscribe request!");
		self.tx.send(true).unwrap();
		Ok(())
	}

	fn new_challenge(&self) -> Result<(), Error> {
		let unsubscribe = ProtocolRequest::Unsubscribe {
			address: self.address.public_key.to_string(),
		};
		self.send(&unsubscribe)
			.expect("could not send unsubscribe request!");

		let request = ProtocolRequest::Challenge;

		self.send(&request)
			.expect("could not send subscribe request!");

		Ok(())
	}

	fn send(&self, request: &ProtocolRequest) -> Result<(), ErrorTungstenite> {
		let request = serde_json::to_string(&request).unwrap();

		self.sender
			.lock()
			.write_message(Message::Text(request.into()))
	}
}
