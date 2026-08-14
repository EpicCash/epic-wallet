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

use crate::config::{EpicboxConfig, TorConfig};
use crate::epicbox::protocol::{
	ProtocolError, ProtocolRequest, ProtocolRequestV2, ProtocolResponseV2,
};
use crate::keychain::Keychain;
use crate::libwallet::crypto::{sign_challenge, Hex};
use crate::libwallet::message::EncryptedMessage;
use crate::util::secp::key::PublicKey;

use crate::libwallet::wallet_lock;
use crate::libwallet::epicbox_txid::EpicboxTxId;
use crate::libwallet::{
	address, Address, EpicboxAddress, TxProof, DEFAULT_EPICBOX_PORT_443, DEFAULT_EPICBOX_PORT_80,
};
use crate::libwallet::{NodeClient, WalletInst, WalletLCProvider};

use crate::Error;

use crate::libwallet::{Slate, SlateVersion, VersionedSlate};
use crate::util::secp::key::SecretKey;
use crate::util::Mutex;

use std::collections::HashMap;
use std::fmt;

use std::sync::Arc;
use std::thread::JoinHandle;

use crate::libwallet::api_impl::foreign;
use crate::libwallet::api_impl::owner;

use epic_wallet_util::epic_core::core::amount_to_hr_string;
use rand::rng;
use rand::seq::SliceRandom;
use std::env;
use std::net::TcpStream;
use std::string::ToString;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread::spawn;

use tungstenite::connect;
use tungstenite::{protocol::WebSocket, stream::MaybeTlsStream};
use tungstenite::{Error as ErrorTungstenite, Message};

// Used to correlate relay acknowledgements with wallet transactions.
use uuid::Uuid;

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

const EPICBOX_PROTOCOL_VERSION: &str = "3.1.0";

const SUBSCRIBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

const RELAY_ACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

fn supports_stable_epicbox_txid(version: &str) -> bool {
	let mut parts = version.split('.');
	let major = parts.next().and_then(|v| v.parse::<u32>().ok());
	let minor = parts.next().and_then(|v| v.parse::<u32>().ok());
	let patch = parts.next().and_then(|v| v.parse::<u32>().ok());

	match (major, minor, patch) {
		(Some(major), Some(minor), Some(patch)) => {
			(major, minor, patch) >= (3, 1, 0)
		}
		_ => false,
	}
}

fn wait_for_relay_version(
	rx: &Receiver<BrokerEvent>,
	deadline: std::time::Instant,
) -> Option<String> {
	loop {
		let remaining = deadline.saturating_duration_since(std::time::Instant::now());
		if remaining.is_zero() {
			return None;
		}

		match rx.recv_timeout(remaining) {
			Ok(BrokerEvent::RelayVersion { version }) => return Some(version),
			Ok(_) => continue,
			Err(_) => return None,
		}
	}
}

/// Epicbox 'plugin' implementation
pub enum CloseReason {
	Normal,
	Abnormal(Error),
}

#[derive(Debug, Clone)]
pub enum BrokerEvent {
	RelayVersion {
		version: String,
	},
	Subscribed,
	PostAck {
		slate_id: Uuid,
		epicboxtxid: EpicboxTxId,
	},
	Made,
	Cancelled {
		epicboxtxid: EpicboxTxId,
	},
}

/// Metadata for one PostSlate that is waiting for its relay acknowledgement.
///
/// Metadata for a protocol 3.1.0+ PostSlate waiting for its correlated relay
/// acknowledgement. Legacy relays use bare Ok and do not create PendingPost.
#[derive(Debug, Clone)]
struct PendingPost {
	slate_id: Uuid,
	epicboxtxid: EpicboxTxId,
}

#[derive(Clone)]
pub struct EpicboxSubscriber {
	address: EpicboxAddress,
	broker: EpicboxBroker,
	secret_key: SecretKey,
	wallet_mode: String,
	is_node_synced: Arc<AtomicBool>,
}
#[derive(Clone)]
pub struct EpicboxPublisher {
	address: EpicboxAddress,
	broker: EpicboxBroker,
	secret_key: SecretKey,
	wallet_mode: String,
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
		reconnections: &mut u32,
		is_node_synced: Arc<AtomicBool>,
		tor_config: TorConfig,
	) -> Result<(), Error>
	where
		L: WalletLCProvider<'static, C, K> + 'static,
		C: NodeClient + 'static,
		K: Keychain + 'static,
	{
		let (address, sec_key) = {
			let a_keychain = keychain_mask.clone();
			let a_wallet = wallet.clone();
			let mask = a_keychain.lock();
			let mut w_lock = a_wallet.lock();
			let lc = w_lock.lc_provider()?;
			let w_inst = lc.wallet_inst()?;
			let k = w_inst.keychain((&mask).as_ref())?;
			let parent_key_id = w_inst.parent_key_id();
			let sec_key = address::address_from_derivation_path(&k, &parent_key_id, 0)?;
			let pub_key = PublicKey::from_secret_key(k.secp(), &sec_key)?;

			let address = EpicboxAddress::new(
				pub_key.clone(),
				epicbox_config.epicbox_domain.clone(),
				epicbox_config.epicbox_port,
			);

			(address, sec_key)
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
		let (tx, _rx): (Sender<BrokerEvent>, Receiver<BrokerEvent>) = channel();

		debug!("Connecting to the epicbox server at {} ..", url.clone());
		let (socket, _response) = connect(url.clone()).map_err(|e| {
			warn!("{}", Error::EpicboxTungstenite(format!("{}", e).into()));
			*reconnections += 1;
			Error::EpicboxTungstenite(format!("{}", e).into())
		})?;

		let publisher =
			EpicboxPublisher::new(address.clone(), sec_key, socket, tx, "listener".to_string())?;

		let mut subscriber = EpicboxSubscriber::new(&publisher, is_node_synced)?;

		let container = Container::new(epicbox_config.clone());
		let cpublisher = publisher.clone();
		let mask = keychain_mask.lock();
		let km = mask.clone();
		let controller = EpicboxController::new(
			container,
			cpublisher,
			wallet,
			km,
			reconnections,
			tor_config.clone(),
		)
		.expect("Could not init epicbox listener!");

		info!("Starting epicbox listener for: {}", address);
		subscriber.start(controller)
	}
}

/// Remove and stop the one-shot epicbox listener session, if present.
/// Closes the websocket and joins the subscriber thread.
fn stop_epicbox_listener(container: &Arc<Mutex<Container>>) {
	if let Some(l) = container
		.lock()
		.listeners
		.remove(&ListenerInterface::Epicbox)
	{
		let _ = l.stop();
	}
}

fn wait_for<F: FnMut(&BrokerEvent) -> bool>(
	rx: &Receiver<BrokerEvent>,
	deadline: std::time::Instant,
	mut want: F,
) -> bool {
	loop {
		let remaining = deadline.saturating_duration_since(std::time::Instant::now());
		if remaining.is_zero() {
			return false;
		}
		match rx.recv_timeout(remaining) {
			Ok(ev) if want(&ev) => return true,
			Ok(_) => continue,
			Err(_) => return false, // timeout or subscriber thread gone
		}
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
		is_node_synced: Arc<AtomicBool>,
		tor_config: TorConfig,
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

		
		// Generate and persist epicbox_txid before any network operation. Retrying the same
		// Slate reuses the already-stored transaction-wide id
		
		let epicboxtxid = owner::ensure_epicbox_tx_id(
			wallet.clone(),
			keychain_mask.as_ref(),
			&slate.id,
			&EpicboxTxId::new(),
		)?;

		// Keep the one-shot session alive until the relay acknowledges the
		// PostSlate. epicbox_txid is already durable locally at this point
		let (tx, rx): (Sender<BrokerEvent>, Receiver<BrokerEvent>) = channel();
		let listener = start_epicbox(
			container.clone(),
			wallet,
			keychain_mask,
			config,
			tx,
			is_node_synced,
			tor_config.clone(),
		)?;

		container
			.lock()
			.listeners
			.insert(ListenerInterface::Epicbox, listener);

		let version_deadline = std::time::Instant::now() + SUBSCRIBE_TIMEOUT;
		let relay_version = match wait_for_relay_version(&rx, version_deadline) {
			Some(version) => version,
			None => {
				stop_epicbox_listener(&container);
				return Err(Error::EpicboxTungstenite(
					format!(
						"Could not determine Epicbox relay protocol version within {:?}",
						SUBSCRIBE_TIMEOUT
					)
					.into(),
				));
			}
		};

		let relay_supports_3_1_0 = supports_stable_epicbox_txid(&relay_version);
		info!(
			"Connected Epicbox relay protocol version [{}]; stable transaction IDs {}",
			relay_version,
			if relay_supports_3_1_0 { "enabled" } else { "disabled (legacy mode)" }
		);

		let vslate = VersionedSlate::into_version(slate.clone(), SlateVersion::V2);

		if let Err(e) = container
			.lock()
			.listener(ListenerInterface::Epicbox)?
			.publish(&vslate, &self.dest, &epicboxtxid)
		{
			stop_epicbox_listener(&container);
			return Err(e);
		}

		if !relay_supports_3_1_0 {
			// legacy relays acknowledge PostSlate with a bare Ok that cannot be
			// safely correlated with ClientDetails/Subscribe/Made responses

			// preserve the historical behavior: a successful websocket write is
			// sufficient, and cancellation/stable-ID semantics are unavailable
			stop_epicbox_listener(&container);

			let slate: Slate =
				VersionedSlate::into_version(slate.clone(), SlateVersion::V2).into();
			return Ok(slate);
		}

		let ack_deadline = std::time::Instant::now() + RELAY_ACK_TIMEOUT;
		let acknowledged = wait_for(
			&rx,
			ack_deadline,
			|event| {
				match event {
					BrokerEvent::PostAck {
						slate_id,
						epicboxtxid: acknowledged_txid,
					} => {
						slate_id == &slate.id &&
							acknowledged_txid == &epicboxtxid
					}

					_ => false,
				}
			},
		);

		if !acknowledged {
			stop_epicbox_listener(&container);

			return Err(Error::EpicboxTungstenite(
				format!(
					"No relay acknowledgement for Slate [{}] and \
					 epicboxtxid [{}] within {:?}",
					slate.id,
					epicboxtxid,
					RELAY_ACK_TIMEOUT
				)
				.into(),
			));
		}

		stop_epicbox_listener(&container);

		let slate: Slate =
			VersionedSlate::into_version(slate.clone(), SlateVersion::V2).into();
		Ok(slate)
	}

	/// One-shot relay cancellation. Connect, establish the Epicbox session,
	/// send CancelTx for the stable transaction identifier, and wait for the
	/// relay to return TransactionCancelled. After receiving that relay
	/// confirmation, the subscriber cancels the transaction locally and then
	/// emits BrokerEvent::Cancelled to wake this caller.
	pub fn cancel<L, C, K>(
		&self,
		wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
		keychain_mask: Option<SecretKey>,
		epicboxtxid: &EpicboxTxId,
		is_node_synced: Arc<AtomicBool>,
		tor_config: TorConfig,
	) -> Result<(), Error>
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
		let (tx, rx): (Sender<BrokerEvent>, Receiver<BrokerEvent>) = channel();

		let listener = start_epicbox(
			container.clone(),
			wallet.clone(),
			keychain_mask.clone(),
			config,
			tx,
			is_node_synced,
			tor_config.clone(),
		)?;

		container
			.lock()
			.listeners
			.insert(ListenerInterface::Epicbox, listener);

		let version_deadline = std::time::Instant::now() + SUBSCRIBE_TIMEOUT;
		let relay_version = match wait_for_relay_version(&rx, version_deadline) {
			Some(version) => version,
			None => {
				stop_epicbox_listener(&container);
				return Err(Error::EpicboxTungstenite(
					format!(
						"Could not determine Epicbox relay protocol version within {:?}",
						SUBSCRIBE_TIMEOUT
					)
					.into(),
				));
			}
		};

		if !supports_stable_epicbox_txid(&relay_version) {
			stop_epicbox_listener(&container);
			match owner::cancel_epicbox_tx(
				wallet,
				keychain_mask.as_ref(),
				Some(&epicboxtxid),
				None, // Relay-confirmed path; never fall back to a slate uuid here
			) {
				Ok(_) => {
					info!(
						"Transaction for epicboxtxid [{}] marked cancelled",
						epicboxtxid.to_string()
					);
				}
				Err(e) => {
					warn!(
						"Local cancellation for epicboxtxid [{}] failed \
						 (it may already be finalized or cancelled): {:?}",
						epicboxtxid.to_string(),
						e
					);
				}
			}

		} else {

			let sub_deadline = std::time::Instant::now() + SUBSCRIBE_TIMEOUT;
			if !wait_for(&rx, sub_deadline, |event| {
				matches!(event, BrokerEvent::Subscribed)
			}) {
				stop_epicbox_listener(&container);
				return Err(Error::EpicboxTungstenite(
					format!(
						"Could not send CancelTx: Epicbox session ended or the \
						 subscription did not establish within {:?}",
						SUBSCRIBE_TIMEOUT
					)
					.into(),
				));
			}

			if let Err(e) = container
				.lock()
				.listener(ListenerInterface::Epicbox)?
				.cancel(epicboxtxid)
			{
				stop_epicbox_listener(&container);
				return Err(e);
			}

			let confirm_deadline = std::time::Instant::now() + RELAY_ACK_TIMEOUT;
			let confirmed = wait_for(&rx, confirm_deadline, |event| {
				matches!(
					event,
					BrokerEvent::Cancelled { epicboxtxid: id } if id == epicboxtxid
				)
			});

			stop_epicbox_listener(&container);

			if !confirmed {
        	                warn!("No TransactionCancelled response from relay for [{}], \
					proceeding with local-only cancel!",
					epicboxtxid
				);
			}
		}

                Ok(())
	}
}

pub fn start_epicbox<L, C, K>(
	container: Arc<Mutex<Container>>,
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
	keychain_mask: Option<SecretKey>,
	config: EpicboxConfig,
	tx: Sender<BrokerEvent>,
	is_node_synced: Arc<AtomicBool>,
	tor_config: TorConfig,
) -> Result<Box<dyn Listener>, Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	let (address, sec_key) = {
		let a_wallet = wallet.clone();
		let mut w_lock = a_wallet.lock();
		let lc = w_lock.lc_provider()?;
		let w_inst = lc.wallet_inst()?;
		let k = w_inst.keychain(keychain_mask.as_ref())?;
		let parent_key_id = w_inst.parent_key_id();
		let sec_key = address::address_from_derivation_path(&k, &parent_key_id, 0)?;
		let pub_key = PublicKey::from_secret_key(k.secp(), &sec_key)?;

		let address = EpicboxAddress::new(
			pub_key.clone(),
			config.epicbox_domain.clone(),
			config.epicbox_port,
		);
		(address, sec_key)
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
	let (mut socket, _) = connect(url.clone()).expect(CONNECTION_ERR_MSG);

	match socket.get_mut() {
		MaybeTlsStream::Plain(stream) => {
			stream
				.set_read_timeout(Some(std::time::Duration::from_secs(1)))
				.expect("Could not configure epicbox read timeout");
		}
		MaybeTlsStream::NativeTls(stream) => {
			stream
				.get_ref()
				.set_read_timeout(Some(std::time::Duration::from_secs(1)))
				.expect("Could not configure epicbox read timeout");
		}
		_ => {
			warn!("Unable to configure epicbox read timeout for this TLS backend");
		}
	}
	let publisher =
		EpicboxPublisher::new(address.clone(), sec_key, socket, tx, "send".to_string())?;
	let subscriber = EpicboxSubscriber::new(&publisher, is_node_synced)?;

	let mut csubscriber = subscriber.clone();
	let cpublisher = publisher.clone();
	let mut reconnections = 0;

	let handle = spawn(move || {
		let controller = EpicboxController::new(
			container,
			cpublisher,
			wallet,
			keychain_mask,
			&mut reconnections,
			tor_config.clone(),
		)
		.expect("Could not init epicbox controller!");

		if let Err(e) = csubscriber.start(controller) {
			warn!("Epicbox subscriber ended abnormally: {}", e);
		}
	});

	Ok(Box::new(EpicboxListener {
		address,
		publisher,
		subscriber,
		handle,
	}))
}

impl Listener for EpicboxListener {
	fn interface(&self) -> ListenerInterface {
		ListenerInterface::Epicbox
	}

	fn address(&self) -> String {
		self.address.stripped()
	}

	fn publish(
		&self,
		slate: &VersionedSlate,
		to: &String,
		epicboxtxid: &EpicboxTxId,
	) -> Result<(), Error> {
		let address = EpicboxAddress::from_str(to)?;

		// The subscriber must remain open to receive and persist the relay
		// acknowledgement. Teardown is performed by caller
		self.publisher
			.post_slate(slate, &address, false, Some(epicboxtxid))
	}

	fn cancel(&self, epicboxtxid: &EpicboxTxId) -> Result<(), Error> {
		self.publisher.cancel_tx(epicboxtxid)
	}

	fn stop(self: Box<Self>) -> Result<(), Error> {
		let listener = *self;

		listener.subscriber.stop();

		if listener.handle.join().is_err() {
			warn!("Epicbox subscriber thread panicked during shutdown");
		}

		Ok(())
	}
}

impl EpicboxPublisher {
	pub fn new(
		address: EpicboxAddress,
		secret_key: SecretKey,
		socket: WebSocket<MaybeTlsStream<TcpStream>>,
		tx: Sender<BrokerEvent>,
		wallet_mode: String,
	) -> Result<Self, Error> {
		Ok(Self {
			address,
			broker: EpicboxBroker::new(socket, tx)?,
			secret_key,
			wallet_mode,
		})
	}
}

impl Publisher for EpicboxPublisher {
	fn post_slate(
		&self,
		slate: &VersionedSlate,
		to: &EpicboxAddress,
		close_connection: bool,
		epicboxtxid: Option<&EpicboxTxId>,
	) -> Result<(), Error> {
		self.broker.post_slate(
			slate,
			to,
			&self.address,
			&self.secret_key,
			epicboxtxid,
		)?;

		if close_connection {
			self.broker.stop();
		}

		Ok(())
	}

	fn cancel_tx(&self, epicboxtxid: &EpicboxTxId) -> Result<(), Error> {
		self.broker
			.post_cancel_tx(epicboxtxid, &self.address, &self.secret_key)
	}
}

impl EpicboxSubscriber {
	pub fn new(
		publisher: &EpicboxPublisher,
		is_node_synced: Arc<AtomicBool>,
	) -> Result<Self, Error> {
		Ok(Self {
			address: publisher.address.clone(),
			broker: publisher.broker.clone(),
			secret_key: publisher.secret_key.clone(),
			wallet_mode: publisher.wallet_mode.clone(),
			is_node_synced,
		})
	}
}

pub struct EpicboxController<'a, P, L, C, K>
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
	pub reconnections: &'a mut u32,
	pub tor_config: TorConfig,
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
			//TODO: reduce listeners
			listeners: HashMap::with_capacity(4),
		};
		Arc::new(Mutex::new(container))
	}

	pub fn listener(&self, interface: ListenerInterface) -> Result<&Box<dyn Listener>, Error> {
		self.listeners
			.get(&interface)
			.ok_or(Error::NoListener(format!("{}", interface)))
	}
}

pub trait Listener: Send + 'static {
	fn interface(&self) -> ListenerInterface;
	fn address(&self) -> String;

	fn publish(
		&self,
		slate: &VersionedSlate,
		to: &String,
		epicboxtxid: &EpicboxTxId,
	) -> Result<(), Error>;

	fn cancel(&self, epicboxtxid: &EpicboxTxId) -> Result<(), Error>;
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

impl<'a, P, L, C, K> EpicboxController<'a, P, L, C, K>
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
		reconnections: &'a mut u32,
		tor_config: TorConfig,
	) -> Result<Self, Error> {
		Ok(Self {
			publisher,
			wallet,
			keychain_mask,
			reconnections,
			tor_config,
		})
	}

	fn process_tx_cancelled(&self, epicboxtxid: &EpicboxTxId) -> Result<(), Error> {
		info!(
			"Processing relay-confirmed cancellation for epicboxtxid {}",
			epicboxtxid.to_string()
		);

		match owner::cancel_epicbox_tx(
			self.wallet.clone(),
			self.keychain_mask.as_ref(),
			Some(&epicboxtxid),
			None, // Relay-confirmed path; never fall back to a slate uuid here
		) {
			Ok(_) => {
				info!(
					"Transaction for epicboxtxid [{}] marked cancelled",
					epicboxtxid.to_string()
				);
			}
			Err(e) => {
				warn!(
					"Local cancellation for epicboxtxid [{}] failed \
					 (it may already be finalized or cancelled): {:?}",
					epicboxtxid.to_string(),
					e
				);
			}
		}

		Ok(())
	}

	fn process_incoming_slate(
		&self,
		address: Option<String>,
		slate: &mut Slate,
		_tx_proof: Option<&mut TxProof>,
	) -> Result<bool, Error> {
		// Case 1: Receiving a new transaction (not finalized)
		if slate.num_participants > slate.participant_data.len() {
			if slate.tx.inputs().is_empty() {
				// TODO: invoicing
			} else {
				info!("Receive new transaction (foreign::receive_tx)");
				wallet_lock!(self.wallet, w);
				match foreign::receive_tx(
					&mut **w,
					self.keychain_mask.as_ref(),
					&slate,
					None,
					None,
					address,
					false,
				) {
					Ok(ret_slate) => {
						*slate = ret_slate;
					}
					Err(e) => return Err(Error::EpicboxReceiveTx(format!("{:?}", e)).into()),
				};
			}
			return Ok(false);
		}

		// Case 2: Finalizing and posting the transaction
		info!("Finalize transaction (owner::finalize_tx)");
		let (finalized_slate, mut onion_addresses, node_client) = {
			wallet_lock!(self.wallet, w);
			let finalized_slate = owner::finalize_tx(&mut **w, self.keychain_mask.as_ref(), slate)?;
			// Get onion addresses and node client while wallet is still locked
			let onion_addresses = w.w2n_client().get_onion_addresses().unwrap_or_default();
			let node_client = w.w2n_client().clone();
			(finalized_slate, onion_addresses, node_client)
		};

		onion_addresses.shuffle(&mut rng());

		if let Some(tor_node_url) = onion_addresses.first() {
			if self.tor_config.use_tor_listener {
				info!("Post transaction to Tor address: {}", tor_node_url);
				match owner::post_tx_tor(&node_client, &finalized_slate.tx, tor_node_url) {
					Ok(_) => {}
					Err(_) => {
						owner::post_tx(&node_client, &finalized_slate.tx, false)?;
					}
				}
			} else {
				// Tor not enabled, use Dandelion/HTTP fallback
				owner::post_tx(&node_client, &finalized_slate.tx, false)?;
			}
		} else {
			owner::post_tx(&node_client, &finalized_slate.tx, false)?;
		}

		// --- Blocking mempool observation after post_tx ---
		let tx_slate_id = finalized_slate.id;
		let found = owner::wait_for_tx_in_mempool(
			self.wallet.clone(),
			self.keychain_mask.as_ref(),
			&tx_slate_id,
			1,   // poll every 1 second
			240, // up to 240 attempts (4 minutes)
		);
		if let Ok(true) = found {
			{
				wallet_lock!(self.wallet, w);
				owner::update_mempool_status(
					&mut **w,
					self.keychain_mask.as_ref(),
					&finalized_slate,
				)?;
			}
			info!(
				"Transaction with slate_id {} found in mempool and marked as TxSentMempool.",
				tx_slate_id
			);
		} else {
			warn!(
				"Transaction with slate_id {} not found in mempool after waiting.",
				tx_slate_id
			);
		}

		Ok(true)
	}
}
pub trait SubscriptionHandler: Send {
	fn on_slate(
		&self,
		from: &EpicboxAddress,
		slate: &VersionedSlate,
		proof: Option<&mut TxProof>,
		epicboxtxid: Option<&EpicboxTxId>,
	) -> Result<(), Error>;

	fn on_tx_cancelled(&self, epicboxtxid: &EpicboxTxId);
	fn on_close(&self, result: CloseReason);
}

impl<'a, P, L, C, K> SubscriptionHandler for EpicboxController<'a, P, L, C, K>
where
	P: Publisher,
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	fn on_slate(
		&self,
		from: &EpicboxAddress,
		slate: &VersionedSlate,
		tx_proof: Option<&mut TxProof>,
		epicboxtxid: Option<&EpicboxTxId>,
	) -> Result<(), Error> {
		let version = slate.version();
		let mut slate: Slate = slate.into();
		let tx_slate_id = slate.id.clone();

		if slate.num_participants > slate.participant_data.len() {
			debug!(
				"Slate [{}] received from [{}] for [{}] epics",
				slate.id,
				from,
				amount_to_hr_string(slate.amount, false)
			);
		} else {
			debug!(
				"Slate [{}] received back from [{}] for [{}] epics",
				slate.id,
				from,
				amount_to_hr_string(slate.amount, false)
			);
		}

		let is_finalized = self.process_incoming_slate(
			Some(from.to_string()),
			&mut slate,
			tx_proof,
		)?;

		// Only persist an epicbox_txid when the relay actually
		// supplied one. Legacy slates remain local-only cancellation
                // and will have null epicbox_txid.
		let stable_epicboxtxid = match epicboxtxid {
			Some(epicboxtxid) => {
				let stable = owner::ensure_epicbox_tx_id(
					self.wallet.clone(),
					self.keychain_mask.as_ref(),
					&tx_slate_id,
					epicboxtxid,
				)?;

				info!(
					"Stable epicboxtxid [{}] associated with Slate [{}]",
					stable,
					tx_slate_id
				);

				Some(stable)
			}
			None => {
				debug!(
					"Legacy Slate [{}] has no epicboxtxid; using local-only cancellation",
					tx_slate_id
				);
				None
			}
		};

		if !is_finalized {
			let response_slate = VersionedSlate::into_version(slate, version);

                        // we do not create a new epicbox_txid here, sender's job 
			self.publisher.post_slate(
				&response_slate,
				from,
				false,
				stable_epicboxtxid.as_ref(),
			)?;
		} else {
			info!("Slate [{}] finalized successfully", tx_slate_id);
		}

		Ok(())
	}

	fn on_tx_cancelled(&self, epicboxtxid: &EpicboxTxId) {
		warn!(
			"Relay cancelled transaction for epicboxtxid {}",
			epicboxtxid
		);

		if let Err(e) = self.process_tx_cancelled(epicboxtxid) {
			error!(
				"Error handling transaction cancellation [{}]: {:?}",
				epicboxtxid.to_string(),
				e
			);
		}
	}

	fn on_close(&self, reason: CloseReason) {
		match reason {
			CloseReason::Normal => {
				debug!("Listener stopped normally");
			}
			CloseReason::Abnormal(error) => {
				error!("{:?}", error.to_string());
			}
		}
	}
}

impl EpicboxSubscriber {
	fn start<P, L, C, K>(&mut self, handler: EpicboxController<P, L, C, K>) -> Result<(), Error>
	where
		P: Publisher,
		L: WalletLCProvider<'static, C, K> + 'static,
		C: NodeClient + 'static,
		K: Keychain + 'static,
	{
		self.broker.subscribe(
			&self.address,
			&self.secret_key,
			handler,
			&self.wallet_mode,
			self.is_node_synced.clone(),
		)
	}

	fn stop(&self) {
		let _ = self.broker.stop();
	}
}

pub trait Publisher: Send {
	fn post_slate(
		&self,
		slate: &VersionedSlate,
		to: &EpicboxAddress,
		close_connection: bool,
		epicboxtxid: Option<&EpicboxTxId>,
	) -> Result<(), Error>;

	fn cancel_tx(&self, epicboxtxid: &EpicboxTxId) -> Result<(), Error>;
}

/// TODO: reduce to broker.
#[derive(Clone)]
pub struct EpicboxBroker {
	inner: Arc<Mutex<WebSocket<MaybeTlsStream<TcpStream>>>>,
	tx: Sender<BrokerEvent>,
	pending_post: Arc<Mutex<Option<PendingPost>>>,
	relay_version: Arc<Mutex<Option<String>>>,
	subscribed: Arc<AtomicBool>,
	stopping: Arc<AtomicBool>,
}

impl EpicboxBroker {
	/// Create a EpicboxBroker,
	pub fn new(
		inner: WebSocket<MaybeTlsStream<TcpStream>>,
		tx: Sender<BrokerEvent>,
	) -> Result<Self, Error> {
		Ok(Self {
			inner: Arc::new(Mutex::new(inner)),
			tx,
			pending_post: Arc::new(Mutex::new(None)),
			relay_version: Arc::new(Mutex::new(None)),
			subscribed: Arc::new(AtomicBool::new(false)),
			stopping: Arc::new(AtomicBool::new(false)),
		})
	}
	/// Start a listener, passing received messages to the wallet api directly
	pub fn subscribe<P, L, C, K>(
		&mut self,
		address: &EpicboxAddress,
		secret_key: &SecretKey,
		handler: EpicboxController<P, L, C, K>,
		wallet_mode: &String,
		is_node_synced: Arc<AtomicBool>,
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

		let mut client = EpicboxClient {
			sender,
			handler: handler.clone(),
			challenge: None,
			address: address.clone(),
			secret_key: secret_key.clone(),
			tx: self.tx.clone(),
		};

		let ver = EPICBOX_PROTOCOL_VERSION;
		let wallet_mode = wallet_mode;

		loop {
			if self
				.stopping
				.load(std::sync::atomic::Ordering::SeqCst)
			{
				debug!("Subscriber loop ending after stop()");

				match client.sender.lock().close(None) {
					Ok(_) => {
						debug!("Epicbox websocket close frame sent");
					}
					Err(e) => {
						debug!("Unable to send Epicbox websocket close frame: {:?}", e);
					}
			}

				handler.lock().on_close(CloseReason::Normal);
				break Ok(());
			}

			if !is_node_synced.load(
				std::sync::atomic::Ordering::SeqCst,
			) {
				warn!("Node not synced, pausing Epicbox message processing...");

				std::thread::sleep(
					std::time::Duration::from_millis(250),
				);

				continue;
			}

			let read_result = client.sender.lock().read();

			match read_result {
				Err(ErrorTungstenite::Io(ref e))
					if matches!(
						e.kind(),
						std::io::ErrorKind::WouldBlock
							| std::io::ErrorKind::TimedOut
					) =>
				{
					continue;
				}

				Err(e) => {
					*handler.lock().reconnections += 1;
					error!("Error reading Epicbox message: {:?}", e);
					handler.lock().on_close(CloseReason::Abnormal(
						Error::EpicboxWebsocketAbnormalTermination,
					));

					match client.sender.lock().close(None) {
						Ok(_) => error!("Epicbox client connection closed"),
						Err(close_error) => error!(
							"Error closing Epicbox client connection: {:?}",
							close_error
						),
					}

					break Err(Error::EpicboxWebsocketAbnormalTermination);
				}

				Ok(message) => match message {
					Message::Text(text) => {
						let response_text = text.to_string();
						info!("Raw Epicbox response: {}", response_text);

						let response = match serde_json::from_str::<ProtocolResponseV2>(
							&response_text,
						) {
							Ok(response) => response,
							Err(e) => {
								error!(
									"Unable to deserialize Epicbox response [{}]: {}",
									response_text,
									e
								);
								continue;
							}
						};

						debug!("Parsed Epicbox response: {:?}", response);

						*handler.lock().reconnections = 0;

						match response {
							ProtocolResponseV2::Challenge { str } => {
								client.challenge = Some(str.clone());

								if first_run {
									// GetVersion is supported on 3.0.0+, query it so we can gate 
									// epicbox_txid compat on 3.1.0+
									client.get_version()?;
									first_run = false;
									continue;
								}

								let signature =
									sign_challenge(&str, secret_key)?.to_hex();
								let request_sub = ProtocolRequestV2::Subscribe {
									address: client.address.public_key.to_string(),
									ver: ver.to_string(),
									signature,
								};

								match client.send(&request_sub) {
									Ok(()) => {
										self.subscribed.store(
											true,
											std::sync::atomic::Ordering::SeqCst,
										);
										let _ = client.tx.send(BrokerEvent::Subscribed);
									}
									Err(e) => {
										error!("Error sending Subscribe: {:?}", e);
									}
								}
							}

							ProtocolResponseV2::Slate {
								from,
								str,
								challenge: _challenge,
								signature,
								ver: slate_ver,
								epicboxmsgid,
								epicboxtxid,
							} => {
								let (slate, mut tx_proof) = match TxProof::from_response(
									from,
									str,
									signature,
									&client.secret_key,
									Some(&client.address),
								) {
									Ok(value) => value,
									Err(e) => {
										error!("{}", e);
										continue;
									}
								};
								let versioned_ack = match (&slate_ver, &epicboxmsgid) {
									(Some(ver), Some(msgid)) => {
										Some((ver.clone(), msgid.clone()))
									}

									(None, None) => {
										debug!(
											"Received unversioned legacy Slate; \
											relay provided no epicboxmsgid and no Made acknowledgement is required"
										);

										None
									}

									_ => {
										error!("Received malformed Slate response: ver={:?}, epicboxmsgid={:?}", slate_ver, epicboxmsgid);

										continue;
									}
								};

								//TODO; move epicboxtxid parsing to a separate helper function
 								let epicboxtxid = if let Some(value) = epicboxtxid {
									match EpicboxTxId::parse(&value) {
										Ok(id) => Some(id),
										Err(e) => {
											error!(
												"Received Slate message with invalid epicboxtxid [{}]: {}",
												value,
												e
											);
											continue;
										}
									}
								} else {
									if versioned_ack.is_some() {
										debug!(
											"Received legacy Slate message without epicboxtxid; \
			 								leaving epicbox_tx_id unset",
										);
									}
									None
								};

								let proof_address = tx_proof.address.clone();
								if let Err(e) = client.handler.lock().on_slate(
									&proof_address,
									&slate,
									Some(&mut tx_proof),
									epicboxtxid.as_ref(),
								) {
									error!(
										"Could not process/store Slate transaction epicboxtxid={:?}, \
										 : {:?}",
										epicboxtxid,
										e
									);

									// Do not send Made. The relay keeps the Slate and can
									// redeliver it after the local failure is resolved.
									continue;
								}

								let challenge = match client.challenge.as_ref() {
									Some(challenge) => challenge,
									None => {
										error!(
											"Received Slate before an Epicbox challenge"
										);
										continue;
									}
								};

								let signature =
									sign_challenge(challenge, secret_key)?.to_hex();
								let request_sub = ProtocolRequestV2::Subscribe {
									address: client.address.public_key.to_string(),
									ver: ver.to_string(),
									signature,
								};

								match client.send(&request_sub) {
									Ok(()) => {
										if let Some((slate_ver, epicboxmsgid)) = versioned_ack {
											// Versioned 2.0.0/3.x relay: explicitly acknowledge
											// the queued message with Made.
											if let Err(e) =
												client.made_send(epicboxmsgid.clone(), &slate_ver)
											{
												error!("Error sending Made for message [{}]: {}", epicboxmsgid, e);
											}
										} else {
											// Unversioned legacy relays mark the Slate made themselves.
            										// There is no epicboxmsgid with which to send Made.
											debug!("Processed unversioned legacy Slate, skipping Made acknowledgement");
										}
									}
									Err(e) => {
										error!(
											"Could not send Subscribe after Slate: {}",
											e
										);
									}
								}
							}

							ProtocolResponseV2::TransactionCancelled {
								epicboxtxid,
							} => {
								info!(
									"Relay confirmed cancellation for epicboxtxid {}",
									epicboxtxid
								);

 								let epicboxtxid = match EpicboxTxId::parse(&epicboxtxid) {
									Ok(id) => id,
									Err(e) => {
										error!(
											"Received TransactionCancelled response with invalid epicboxtxid [{}]: {}",
											epicboxtxid,
											e
										);
										continue;
									}
								};

								client
									.handler
									.lock()
									.on_tx_cancelled(&epicboxtxid);

								let _ = client.tx.send(BrokerEvent::Cancelled {
									epicboxtxid: epicboxtxid,
								});

								if wallet_mode != "send" {
									if let Some(challenge) = client.challenge.as_ref() {
										let signature = sign_challenge(
											challenge,
											secret_key,
										)?
										.to_hex();

										let request_sub = ProtocolRequestV2::Subscribe {
											address: client
												.address
												.public_key
												.to_string(),
											ver: ver.to_string(),
											signature,
										};

										if let Err(e) = client.send(&request_sub) {
											error!(
												"Could not subscribe after cancellation: {}",
												e
											);
										}
									}
								}
							}

							ProtocolResponseV2::GetVersion { str } => {
								trace!("ProtocolResponseV2::GetVersion {}", str);
								*self.relay_version.lock() = Some(str.clone());
								let _ = client.tx.send(BrokerEvent::RelayVersion {
									version: str,
								});

								// complete the initial session setup only after relay ver so we use
								// compatible protocol msgs, and don't confuse bare Ok with postslate_ack
								client.client_details(wallet_mode.clone())?;

								let challenge = match client.challenge.as_ref() {
									Some(challenge) => challenge,
									None => {
										error!("Received GetVersion before an Epicbox challenge");
										continue;
									}
								};

								let signature =
									sign_challenge(challenge, secret_key)?.to_hex();
								let request_sub = ProtocolRequestV2::Subscribe {
									address: client.address.public_key.to_string(),
									ver: ver.to_string(),
									signature,
								};

								match client.send(&request_sub) {
									Ok(()) => {
										self.subscribed.store(
											true,
											std::sync::atomic::Ordering::SeqCst,
										);
										let _ = client.tx.send(BrokerEvent::Subscribed);
										info!("Starting Epicbox subscription...");
									}
									Err(e) => {
										error!("Error sending initial Subscribe: {:?}", e);
									}
								}
							}

							ProtocolResponseV2::Error {
								ref kind,
								ref description,
							} => {
								error!(
									"Epicbox protocol error: kind=[{}], description=[{}]",
									kind,
									description
								);

								if matches!(kind, ProtocolError::InvalidRequest) {
									error!(
										"Invalid request. Ensure the connected Epicbox \
										 supports the required protocol fields"
									);
								}
							}


							ProtocolResponseV2::Ok {
								epicboxmsgid,
								epicboxtxid,
							} => {
								let returned_epicboxtxid = if let Some(value) = epicboxtxid {
									match EpicboxTxId::parse(&value) {
										Ok(id) => id,
										Err(e) => {
											error!(
												"Received PostSlate Ok with invalid epicboxtxid [{}]: {}",
												value,
												e
											);
											continue;
										}
									}
								} else {
									debug!("Received non-PostSlate Ok: epicboxmsgid={:?}", epicboxmsgid);
									continue;
								};

								let pending = {
									let mut pending_guard = self.pending_post.lock();

									match pending_guard.as_ref() {
										None => {
											warn!(
												"Received PostSlate Ok for epicboxtxid [{}] \
												 without a pending PostSlate",
												returned_epicboxtxid.to_string()
											);
											continue;
										}
										Some(pending)
											if pending.epicboxtxid != returned_epicboxtxid =>
										{
											warn!(
												"Ignoring PostSlate Ok for unexpected \
												 epicboxtxid [{}]; pending Slate [{}] uses [{}]",
												returned_epicboxtxid,
												pending.slate_id,
												pending.epicboxtxid
											);
											continue;
										}
										Some(_) => pending_guard
											.take()
											.expect("pending PostSlate disappeared while locked"),
									}
								};

								info!(
									"Received PostSlate acknowledgement: slate_id=[{}], \
									 epicboxtxid=[{}], epicboxmsgid={:?}",
									pending.slate_id,
									pending.epicboxtxid,
									epicboxmsgid
								);

								if let Err(e) = client.tx.send(BrokerEvent::PostAck {
									slate_id: pending.slate_id,
									epicboxtxid: pending.epicboxtxid,
								}) {
									error!("Unable to emit BrokerEvent::PostAck: {}", e);
								}
							}
						}
					}

					Message::Binary(bytes) => {
						match String::from_utf8(bytes.to_vec()) {
							Ok(text) => warn!(
								"Ignoring unexpected binary Epicbox response: {}",
								text
							),
							Err(e) => warn!(
								"Ignoring non-UTF-8 binary Epicbox response: {}",
								e
							),
						}
					}

					Message::Ping(_) => {}
					Message::Pong(_) => {}
					Message::Frame(_) => {}
					Message::Close(_) => {
						info!("Epicbox connection closed");
						handler.lock().on_close(CloseReason::Normal);
						let _ = client.sender.lock().close(None);
						break Ok(());
					}
				},
			}
		}
	}

	fn post_slate(
		&self,
		slate: &VersionedSlate,
		to: &EpicboxAddress,
		from: &EpicboxAddress,
		secret_key: &SecretKey,
		epicboxtxid: Option<&EpicboxTxId>,
	) -> Result<(), Error> {
		let public_key = to.public_key()?;
		let secret_key_copy = secret_key.clone();

		let message = EncryptedMessage::new(
			serde_json::to_string(slate)?,
			to,
			&public_key,
			&secret_key_copy,
		)?;

		let message_ser = serde_json::to_string(&message)?;
		let signature = sign_challenge(&message_ser, secret_key)?.to_hex();

		let relay_version = self.relay_version.lock().clone();
		let use_stable_txid = epicboxtxid.is_some()
			&& relay_version
				.as_deref()
				.map(supports_stable_epicbox_txid)
				.unwrap_or(false);

		let (request_epicboxtxid, request_epicboxtxidsig) = if use_stable_txid {
			let epicboxtxid = epicboxtxid
				.expect("stable transaction ID disappeared after presence check").to_string();
			let epicboxtxidsig = sign_challenge(&epicboxtxid, secret_key)?.to_hex();
			(Some(epicboxtxid.clone()), Some(epicboxtxidsig))
		} else {
			(None, None)
		};

		let request = ProtocolRequest::PostSlate {
			from: from.stripped(),
			to: to.stripped(),
			str: message_ser,
			signature,
			epicboxtxid: request_epicboxtxid,
			epicboxtxidsig: request_epicboxtxidsig,
		};

		let slate: Slate = slate.into();
		debug!("Starting to send Slate with id [{}]", slate.id);

		if use_stable_txid {
			let epicboxtxid = epicboxtxid
				.expect("stable transaction ID disappeared after presence check");
			let mut pending = self.pending_post.lock();
			if pending.is_some() {
				return Err(Error::EpicboxTungstenite(
					"Cannot post a second Slate while a relay acknowledgement is pending"
						.to_string()
						.into(),
				));
			}

			*pending = Some(PendingPost {
				slate_id: slate.id.clone(),
				epicboxtxid: epicboxtxid.clone(),
			});
		}

		let request_json = serde_json::to_string(&request)?;

		info!(
			"Sending Epicbox PostSlate: slate_id=[{}], epicboxtxid={:?}, \
			 stable_txid_fields={}, relay_version={:?}, to=[{}]",
			slate.id,
			epicboxtxid,
			use_stable_txid,
			relay_version,
			to.stripped(),
		);

		info!("PostSlate JSON: {}", request_json);

		self.inner
			.lock()
			.send(Message::Text(request_json.into()))
			.map_err(|e| {
				*self.pending_post.lock() = None;
				Error::EpicboxTungstenite(
					format!("Could not send PostSlate: {}", e).into(),
				)
			})?;

		debug!("Slate sent successfully");
		Ok(())
	}

	fn post_cancel_tx(
		&self,
		epicboxtxid: &EpicboxTxId,
		from: &EpicboxAddress,
		secret_key: &SecretKey,
	) -> Result<(), Error> {
		let relay_version = self.relay_version.lock().clone();
		if !relay_version
			.as_deref()
			.map(supports_stable_epicbox_txid)
			.unwrap_or(false)
		{
			return Err(Error::EpicboxTungstenite(
				format!(
					"CancelTx requires Epicbox protocol 3.1.0 or newer; relay reported {:?}",
					relay_version
				)
				.into(),
			));
		}

		if !self
			.subscribed
			.load(std::sync::atomic::Ordering::SeqCst)
		{
			return Err(Error::EpicboxTungstenite(
				"CancelTx requires an active Epicbox subscription on this connection"
					.to_string()
					.into(),
			));
		}

		let signature = sign_challenge(&epicboxtxid.to_string(), secret_key)?.to_hex();
		let request = ProtocolRequestV2::CancelTx {
			address: from.public_key.to_string(),
			epicboxtxid: epicboxtxid.to_string(),
			signature,
		};

		debug!(
			"Sending CancelTx for epicboxtxid [{}]",
			epicboxtxid.to_string()
		);

		self.inner
			.lock()
			.send(Message::Text(
				serde_json::to_string(&request)?.into(),
			))
			.map_err(|e| {
				Error::EpicboxTungstenite(
					format!("Could not send CancelTx: {}", e).into(),
				)
			})?;

		Ok(())
	}


	fn stop(&self) {
		self.stopping.store(true, std::sync::atomic::Ordering::SeqCst);
	}
}

struct EpicboxClient<'a, P, L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
	P: Publisher,
{
	sender: Arc<Mutex<WebSocket<MaybeTlsStream<TcpStream>>>>,
	handler: Arc<Mutex<EpicboxController<'a, P, L, C, K>>>,
	challenge: Option<String>,
	address: EpicboxAddress,
	secret_key: SecretKey,
	tx: Sender<BrokerEvent>,
}

/// client with handler from ws package
impl<'a, P, L, C, K> EpicboxClient<'a, P, L, C, K>
where
	P: Publisher,
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	fn made_send(&self, epicboxmsgid: String, ver: &str) -> Result<(), Error> {
		let signature = if ver == "2.0.0" {
			let challenge = self.challenge.as_ref().ok_or_else(|| {
				Error::EpicboxTungstenite(
					"Cannot send legacy 2.0.0 Made without an active challenge"
						.to_string()
						.into(),
				)
			})?;
			sign_challenge(challenge, &self.secret_key)?.to_hex()
		} else {
			sign_challenge(&epicboxmsgid, &self.secret_key)?.to_hex()
		};

		let request = ProtocolRequestV2::Made {
			address: self.address.public_key.to_string(),
			signature,
			epicboxmsgid,
			ver: ver.to_string(),
		};

		match self.send(&request) {
			Ok(_) => {
				let _ = self.tx.send(BrokerEvent::Made);
				Ok(())
			}
			Err(e) => Err(Error::EpicboxTungstenite(
				format!("Could not send 'Made' request! {}", e).into(),
			)),
		}
	}

	fn get_version(&self) -> Result<(), Error> {
		self.send(&ProtocolRequestV2::GetVersion)
			.map_err(|e| {
				Error::EpicboxTungstenite(
					format!("Could not send 'GetVersion' request! {}", e).into(),
				)
			})
	}

	fn client_details(&self, wallet_mode: String) -> Result<(), Error> {
		let version = env!("CARGO_PKG_VERSION");

		let request = ProtocolRequestV2::ClientDetails {
			wallet_version: version.to_string(),
			wallet_mode,
			protocol_version: EPICBOX_PROTOCOL_VERSION.to_string(),
		};

		match self.send(&request) {
			Ok(_) => Ok(()),
			Err(e) => Err(Error::EpicboxTungstenite(
				format!("Could not send 'ClientDetails' request! {}", e).into(),
			)),
		}
	}

	fn send(&self, request: &ProtocolRequestV2) -> Result<(), ErrorTungstenite> {
		let request = serde_json::to_string(&request).unwrap();
		self.sender.lock().send(Message::Text(request.into()))
	}
}
