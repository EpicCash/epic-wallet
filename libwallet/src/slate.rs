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

//! Functions for building partial transactions to be passed
//! around during an interactive wallet exchange

use crate::blake2::blake2b::blake2b;
use crate::epic_core::core::amount_to_hr_string;
use crate::epic_core::core::committed::Committed;
use crate::epic_core::core::transaction::{
	Input, KernelFeatures, Output, Transaction, TransactionBody, TxKernel, Weighting,
};

use crate::epic_core::libtx::{aggsig, build, proof::ProofBuild, secp_ser, tx_fee};
use crate::epic_core::map_vec;
use crate::epic_keychain::{BlindSum, BlindingFactor, Keychain};
use crate::epic_util::secp::key::{PublicKey, SecretKey};
use crate::epic_util::secp::pedersen::Commitment;
use crate::epic_util::secp::Signature;
use crate::epic_util::{self, secp};
use crate::error::Error;
use crate::slate_versions::ser as dalek_ser;

use ed25519_dalek::Signature as DalekSignature;
use ed25519_dalek::VerifyingKey as DalekPublicKey;

use rand::rng;
use epic_wallet_util::mock_rng::StepRng;
use serde::ser::{Serialize, Serializer};
use serde_json;
use std::fmt;
use uuid::Uuid;

use crate::slate_versions::v2::SlateV2;
use crate::slate_versions::v3::{
	CoinbaseV3, InputV3, OutputV3, ParticipantDataV3, PaymentInfoV3, SlateV3, TransactionBodyV3,
	TransactionV3, TxKernelV3, VersionCompatInfoV3,
};
use crate::slate_versions::{CURRENT_SLATE_VERSION, EPIC_BLOCK_HEADER_VERSION};
use crate::types::CbData;

/// Addresses and signatures to confirm payment
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PaymentInfo {
	/// sender address
	#[serde(with = "dalek_ser::dalek_pubkey_serde")]
	pub sender_address: DalekPublicKey,
	/// receiver address
	#[serde(with = "dalek_ser::dalek_pubkey_serde")]
	pub receiver_address: DalekPublicKey,
	/// receiver signature
	#[serde(with = "dalek_ser::option_dalek_sig_serde")]
	pub receiver_signature: Option<DalekSignature>,
}

/// Public data for each participant in the slate
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ParticipantData {
	/// Id of participant in the transaction. (For now, 0=sender, 1=rec)
	#[serde(with = "secp_ser::string_or_u64")]
	pub id: u64,
	/// Public key corresponding to private blinding factor
	#[serde(with = "secp_ser::pubkey_serde")]
	pub public_blind_excess: PublicKey,
	/// Public key corresponding to private nonce
	#[serde(with = "secp_ser::pubkey_serde")]
	pub public_nonce: PublicKey,
	/// Public partial signature
	#[serde(with = "secp_ser::option_sig_serde")]
	pub part_sig: Option<Signature>,
	/// A message for other participants
	pub message: Option<String>,
	/// Signature, created with private key corresponding to 'public_blind_excess'
	#[serde(with = "secp_ser::option_sig_serde")]
	pub message_sig: Option<Signature>,
}

impl ParticipantData {
	/// A helper to return whether this participant
	/// has completed round 1 and round 2;
	/// Round 1 has to be completed before instantiation of this struct
	/// anyhow, and for each participant consists of:
	/// -Inputs added to transaction
	/// -Outputs added to transaction
	/// -Public signature nonce chosen and added
	/// -Public contribution to blinding factor chosen and added
	/// Round 2 can only be completed after all participants have
	/// performed round 1, and adds:
	/// -Part sig is filled out
	pub fn is_complete(&self) -> bool {
		self.part_sig.is_some()
	}
}

/// Public message data (for serialising and storage)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ParticipantMessageData {
	/// id of the particpant in the tx
	#[serde(with = "secp_ser::string_or_u64")]
	pub id: u64,
	/// Public key
	#[serde(with = "secp_ser::pubkey_serde")]
	pub public_key: PublicKey,
	/// Message,
	pub message: Option<String>,
	/// Signature
	#[serde(with = "secp_ser::option_sig_serde")]
	pub message_sig: Option<Signature>,
}

impl ParticipantMessageData {
	/// extract relevant message data from participant data
	pub fn from_participant_data(p: &ParticipantData) -> ParticipantMessageData {
		ParticipantMessageData {
			id: p.id,
			public_key: p.public_blind_excess,
			message: p.message.clone(),
			message_sig: p.message_sig.clone(),
		}
	}
}

impl fmt::Display for ParticipantMessageData {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		writeln!(f, "")?;
		write!(f, "Participant ID {} ", self.id)?;
		if self.id == 0 {
			writeln!(f, "(Sender)")?;
		} else {
			writeln!(f, "(Recipient)")?;
		}
		writeln!(f, "---------------------")?;
		let static_secp = epic_util::static_secp_instance();
		let static_secp = static_secp.lock();
		writeln!(
			f,
			"Public Key: {}",
			&epic_util::to_hex(self.public_key.serialize_vec(&static_secp, true).to_vec())
		)?;
		let message = match self.message.clone() {
			None => "None".to_owned(),
			Some(m) => m,
		};
		writeln!(f, "Message: {}", message)?;
		let message_sig = match self.message_sig.clone() {
			None => "None".to_owned(),
			Some(m) => epic_util::to_hex(m.to_raw_data().to_vec()),
		};
		writeln!(f, "Message Signature: {}", message_sig)
	}
}

/// A 'Slate' is passed around to all parties to build up all of the public
/// transaction data needed to create a finalized transaction. Callers can pass
/// the slate around by whatever means they choose, (but we can provide some
/// binary or JSON serialization helpers here).

#[derive(Deserialize, Debug, Clone)]
pub struct Slate {
	/// Versioning info
	pub version_info: VersionCompatInfo,
	/// The number of participants intended to take part in this transaction
	pub num_participants: usize,
	/// Unique transaction ID, selected by sender
	pub id: Uuid,
	/// The core transaction data:
	/// inputs, outputs, kernels, kernel offset
	pub tx: Transaction,
	/// base amount (excluding fee)
	#[serde(with = "secp_ser::string_or_u64")]
	pub amount: u64,
	/// fee amount
	#[serde(with = "secp_ser::string_or_u64")]
	pub fee: u64,
	/// Block height for the transaction
	#[serde(with = "secp_ser::string_or_u64")]
	pub height: u64,
	/// Lock height
	#[serde(with = "secp_ser::string_or_u64")]
	pub lock_height: u64,
	/// TTL, the block height at which wallets
	/// should refuse to process the transaction and unlock all
	/// associated outputs
	#[serde(with = "secp_ser::opt_string_or_u64")]
	pub ttl_cutoff_height: Option<u64>,
	/// Participant data, each participant in the transaction will
	/// insert their public data here. For now, 0 is sender and 1
	/// is receiver, though this will change for multi-party
	pub participant_data: Vec<ParticipantData>,
	/// Payment Proof
	#[serde(default = "default_payment_none")]
	pub payment_proof: Option<PaymentInfo>,
}

fn default_payment_none() -> Option<PaymentInfo> {
	None
}
/// Versioning and compatibility info about this slate
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VersionCompatInfo {
	/// The current version of the slate format
	pub version: u16,
	/// Original version this slate was converted from
	pub orig_version: u16,
	/// The epic block header version this slate is intended for
	pub block_header_version: u16,
}

/// Helper just to facilitate serialization
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ParticipantMessages {
	/// included messages
	pub messages: Vec<ParticipantMessageData>,
}

impl Slate {
	/// Attempt to find slate version
	pub fn parse_slate_version(slate_json: &str) -> Result<u16, Error> {
		let probe: SlateVersionProbe =
			serde_json::from_str(slate_json).map_err(|_| Error::SlateVersionParse)?;
		Ok(probe.version())
	}

	/// Recieve a slate, upgrade it to the latest version internally
	pub fn deserialize_upgrade(slate_json: &str) -> Result<Slate, Error> {
		let version = Slate::parse_slate_version(slate_json)?;
		let v3: SlateV3 = match version {
			3 => serde_json::from_str(slate_json).map_err(|_| Error::SlateDeser)?,
			2 => {
				let v2: SlateV2 =
					serde_json::from_str(slate_json).map_err(|_| Error::SlateDeser)?;
				SlateV3::from(v2)
			}
			_ => return Err(Error::SlateVersion(version).into()),
		};
		let slate: Slate = v3.into();
		slate.validate_participant_data()?;
		Ok(slate)
	}

	fn invalid_slate(reason: impl Into<String>) -> Error {
		Error::InvalidSlate(reason.into())
	}

	/// Validate participant cardinality and identifiers without requiring every
	/// participant to have joined yet.
	fn validate_participant_data(&self) -> Result<(), Error> {
		if self.num_participants == 0 {
			return Err(Self::invalid_slate("participant count must be nonzero"));
		}
		if self.participant_data.len() > self.num_participants {
			return Err(Self::invalid_slate(format!(
				"participant data contains {} entries for {} participants",
				self.participant_data.len(),
				self.num_participants
			)));
		}

		for (index, participant) in self.participant_data.iter().enumerate() {
			let participant_id = usize::try_from(participant.id)
				.map_err(|_| Self::invalid_slate("participant ID is out of range"))?;
			if participant_id >= self.num_participants {
				return Err(Self::invalid_slate(format!(
					"participant ID {} is out of range",
					participant.id
				)));
			}
			if self.participant_data[..index]
				.iter()
				.any(|existing| existing.id == participant.id)
			{
				return Err(Self::invalid_slate(format!(
					"duplicate participant ID {}",
					participant.id
				)));
			}
		}
		Ok(())
	}

	/// Validate a counterparty slate before adding our participant data. This
	/// must run before any wallet state is persisted.
	pub(crate) fn validate_for_participant(&self, participant_id: usize) -> Result<(), Error> {
		self.validate_participant_data()?;
		self.validate_single_kernel()?;
		let participant_id = u64::try_from(participant_id)
			.map_err(|_| Self::invalid_slate("participant ID is out of range"))?;
		let num_participants = u64::try_from(self.num_participants)
			.map_err(|_| Self::invalid_slate("participant count is out of range"))?;
		if participant_id >= num_participants {
			return Err(Self::invalid_slate(format!(
				"participant ID {} is out of range",
				participant_id
			)));
		}
		if self
			.participant_data
			.iter()
			.any(|participant| participant.id == participant_id)
		{
			return Err(Self::invalid_slate(format!(
				"participant ID {} is already present",
				participant_id
			)));
		}
		if self.participant_data.len().checked_add(1) != Some(self.num_participants) {
			return Err(Self::invalid_slate(format!(
				"expected {} participant entries before round 2, found {}",
				self.num_participants - 1,
				self.participant_data.len()
			)));
		}
		Ok(())
	}

	pub(crate) fn validate_complete_participant_data(&self) -> Result<(), Error> {
		self.validate_participant_data()?;
		if self.participant_data.len() != self.num_participants {
			return Err(Self::invalid_slate(format!(
				"expected {} participant entries, found {}",
				self.num_participants,
				self.participant_data.len()
			)));
		}
		Ok(())
	}

	pub(crate) fn validate_single_kernel(&self) -> Result<(), Error> {
		if self.tx.kernels().len() != 1 {
			return Err(Self::invalid_slate(format!(
				"expected one transaction kernel, found {}",
				self.tx.kernels().len()
			)));
		}
		Ok(())
	}

	/// Create a new slate
	pub fn blank(num_participants: usize) -> Slate {
		Slate {
			num_participants,
			id: Uuid::new_v4(),
			tx: Transaction::empty(),
			amount: 0,
			fee: 0,
			height: 0,
			lock_height: 0,
			ttl_cutoff_height: None,
			participant_data: vec![],
			version_info: VersionCompatInfo {
				version: CURRENT_SLATE_VERSION,
				orig_version: CURRENT_SLATE_VERSION,
				block_header_version: EPIC_BLOCK_HEADER_VERSION,
			},
			payment_proof: None,
		}
	}

	/// Adds selected inputs and outputs to the slate's transaction
	/// Returns blinding factor
	pub fn add_transaction_elements<K, B>(
		&mut self,
		keychain: &K,
		builder: &B,
		elems: Vec<Box<build::Append<K, B>>>,
	) -> Result<BlindingFactor, epic_wallet_util::epic_core::libtx::Error>
	where
		K: Keychain,
		B: ProofBuild,
	{
		self.update_kernel();
		let (tx, blind) = build::partial_transaction(self.tx.clone(), elems, keychain, builder)?;
		self.tx = tx;
		Ok(blind)
	}

	/// Update the tx kernel based on kernel features derived from the current slate.
	/// The fee may change as we build a transaction and we need to
	/// update the tx kernel to reflect this during the tx building process.
	pub fn update_kernel(&mut self) {
		self.tx = self
			.tx
			.clone()
			.replace_kernel(TxKernel::with_features(self.kernel_features()));
	}

	/// Completes callers part of round 1, adding public key info
	/// to the slate
	pub fn fill_round_1<K>(
		&mut self,
		keychain: &K,
		sec_key: &mut SecretKey,
		sec_nonce: &SecretKey,
		participant_id: usize,
		message: Option<String>,
		use_test_rng: bool,
	) -> Result<(), Error>
	where
		K: Keychain,
	{
		// Whoever does this first generates the offset
		if self.tx.offset == BlindingFactor::zero() {
			self.generate_offset(keychain, sec_key, use_test_rng)?;
		}
		self.add_participant_info(
			keychain,
			&sec_key,
			&sec_nonce,
			participant_id,
			None,
			message,
			use_test_rng,
		)?;
		Ok(())
	}

	// Construct the appropriate kernel features based on our fee and lock_height.
	// If lock_height is 0 then its a plain kernel, otherwise its a height locked kernel.
	fn kernel_features(&self) -> KernelFeatures {
		match self.lock_height {
			0 => KernelFeatures::Plain { fee: self.fee },
			_ => KernelFeatures::HeightLocked {
				fee: self.fee,
				lock_height: self.lock_height,
			},
		}
	}

	// This is the msg that we will sign as part of the tx kernel.
	// If lock_height is 0 then build a plain kernel, otherwise build a height locked kernel.
	fn msg_to_sign(
		&self,
	) -> Result<secp::Message, epic_wallet_util::epic_core::core::transaction::Error> {
		let msg = self.kernel_features().kernel_sig_msg()?;
		Ok(msg)
	}

	/// Completes caller's part of round 2, completing signatures
	pub fn fill_round_2<K>(
		&mut self,
		keychain: &K,
		sec_key: &SecretKey,
		sec_nonce: &SecretKey,
		participant_id: usize,
	) -> Result<(), Error>
	where
		K: Keychain,
	{
		self.validate_complete_participant_data()?;
		self.check_fees()?;

		self.verify_part_sigs(keychain.secp())?;
		let sig_part = aggsig::calculate_partial_sig(
			keychain.secp(),
			sec_key,
			sec_nonce,
			&self.pub_nonce_sum(keychain.secp())?,
			Some(&self.pub_blind_sum(keychain.secp())?),
			&self.msg_to_sign()?,
		)?;
		let participant_id = u64::try_from(participant_id)
			.map_err(|_| Self::invalid_slate("participant ID is out of range"))?;
		let participant = self
			.participant_data
			.iter_mut()
			.find(|participant| participant.id == participant_id)
			.ok_or_else(|| Self::invalid_slate("participant ID is not present"))?;
		participant.part_sig = Some(sig_part);
		Ok(())
	}

	/// Creates the final signature, callable by either the sender or recipient
	/// (after phase 3: sender confirmation)
	pub fn finalize<K>(&mut self, keychain: &K) -> Result<(), Error>
	where
		K: Keychain,
	{
		let final_sig = self.finalize_signature(keychain)?;

		self.finalize_transaction(keychain, &final_sig)
	}

	/// Return the participant with the given id
	pub fn participant_with_id(&self, id: usize) -> Option<ParticipantData> {
		for p in self.participant_data.iter() {
			if p.id as usize == id {
				return Some(p.clone());
			}
		}
		None
	}

	/// Return the sum of public nonces
	fn pub_nonce_sum(&self, secp: &secp::Secp256k1) -> Result<PublicKey, Error> {
		let pub_nonces = self
			.participant_data
			.iter()
			.map(|p| &p.public_nonce)
			.collect();
		match PublicKey::from_combination(secp, pub_nonces) {
			Ok(k) => Ok(k),
			Err(e) => Err(Error::Secp(e))?,
		}
	}

	/// Return the sum of public blinding factors
	fn pub_blind_sum(&self, secp: &secp::Secp256k1) -> Result<PublicKey, Error> {
		let pub_blinds = self
			.participant_data
			.iter()
			.map(|p| &p.public_blind_excess)
			.collect();
		match PublicKey::from_combination(secp, pub_blinds) {
			Ok(k) => Ok(k),
			Err(e) => Err(Error::Secp(e))?,
		}
	}

	/// Return vector of all partial sigs
	fn part_sigs(&self) -> Result<Vec<&Signature>, Error> {
		self.participant_data
			.iter()
			.map(|participant| {
				participant.part_sig.as_ref().ok_or_else(|| {
					Self::invalid_slate(format!(
						"participant {} is missing a partial signature",
						participant.id
					))
				})
			})
			.collect()
	}

	/// Adds participants public keys to the slate data
	/// and saves participant's transaction context
	/// sec_key can be overridden to replace the blinding
	/// factor (by whoever split the offset)
	fn add_participant_info<K>(
		&mut self,
		keychain: &K,
		sec_key: &SecretKey,
		sec_nonce: &SecretKey,
		id: usize,
		part_sig: Option<Signature>,
		message: Option<String>,
		use_test_rng: bool,
	) -> Result<(), Error>
	where
		K: Keychain,
	{
		let participant_id = u64::try_from(id)
			.map_err(|_| Self::invalid_slate("participant ID is out of range"))?;
		if id >= self.num_participants
			|| self.participant_data.len() >= self.num_participants
			|| self
				.participant_data
				.iter()
				.any(|participant| participant.id == participant_id)
		{
			return Err(Self::invalid_slate(format!(
				"cannot add participant ID {}",
				id
			)));
		}
		// Add our public key and nonce to the slate
		let pub_key = PublicKey::from_secret_key(keychain.secp(), &sec_key)?;
		let pub_nonce = PublicKey::from_secret_key(keychain.secp(), &sec_nonce)?;

		let test_message_nonce = SecretKey::from_slice(&keychain.secp(), &[1; 32]).unwrap();
		let message_nonce = match use_test_rng {
			false => None,
			true => Some(&test_message_nonce),
		};

		// Sign the provided message
		let message_sig = {
			if let Some(m) = message.clone() {
				let hashed = blake2b(secp::constants::MESSAGE_SIZE, &[], &m.as_bytes()[..]);
				let m = secp::Message::from_slice(&hashed.as_bytes())?;
				let res = aggsig::sign_single(
					&keychain.secp(),
					&m,
					&sec_key,
					message_nonce,
					Some(&pub_key),
				)?;
				Some(res)
			} else {
				None
			}
		};
		self.participant_data.push(ParticipantData {
			id: participant_id,
			public_blind_excess: pub_key,
			public_nonce: pub_nonce,
			part_sig,
			message,
			message_sig,
		});
		Ok(())
	}

	/// helper to return all participant messages
	pub fn participant_messages(&self) -> ParticipantMessages {
		let mut ret = ParticipantMessages { messages: vec![] };
		for ref m in self.participant_data.iter() {
			ret.messages
				.push(ParticipantMessageData::from_participant_data(m));
		}
		ret
	}

	/// Somebody involved needs to generate an offset with their private key
	/// For now, we'll have the transaction initiator be responsible for it
	/// Return offset private key for the participant to use later in the
	/// transaction
	fn generate_offset<K>(
		&mut self,
		keychain: &K,
		sec_key: &mut SecretKey,
		use_test_rng: bool,
	) -> Result<(), Error>
	where
		K: Keychain,
	{
		// Generate a random kernel offset here
		// and subtract it from the blind_sum so we create
		// the aggsig context with the "split" key
		self.tx.offset = match use_test_rng {
			false => BlindingFactor::from_secret_key(SecretKey::new(&keychain.secp(), &mut rng())),
			true => {
				// allow for consistent test results		
				let mut test_rng = StepRng::new(1234567890u64, 1);
				BlindingFactor::from_secret_key(SecretKey::new(&keychain.secp(), &mut test_rng))
			}
		};

		let blind_offset = keychain.blind_sum(
			&BlindSum::new()
				.add_blinding_factor(BlindingFactor::from_secret_key(sec_key.clone()))
				.sub_blinding_factor(self.tx.offset.clone()),
		)?;
		*sec_key = blind_offset.secret_key(&keychain.secp())?;
		Ok(())
	}

	/// Checks the fees in the transaction in the given slate are valid
	fn check_fees(&self) -> Result<(), Error> {
		// double check the fee amount included in the partial tx
		// we don't necessarily want to just trust the sender
		// we could just overwrite the fee here (but we won't) due to the sig
		let fee = tx_fee(
			self.tx.inputs().len(),
			self.tx.outputs().len(),
			self.tx.kernels().len(),
			None,
		);

		if fee > self.tx.fee() {
			return Err(Error::Fee(
				format!("Fee Dispute Error: {}, {}", self.tx.fee(), fee,).to_string(),
			))?;
		}

		let received_amount = self
			.amount
			.checked_add(self.fee)
			.ok_or_else(|| Self::invalid_slate("amount and fee overflow"))?;
		if fee > received_amount {
			let reason = format!(
				"Rejected the transfer because transaction fee ({}) exceeds received amount ({}).",
				amount_to_hr_string(fee, false),
				amount_to_hr_string(received_amount, false)
			);
			info!("{}", reason);
			return Err(Error::Fee(reason.to_string()))?;
		}

		Ok(())
	}

	/// Verifies all of the partial signatures in the Slate are valid
	fn verify_part_sigs(&self, secp: &secp::Secp256k1) -> Result<(), Error> {
		self.validate_participant_data()?;
		// collect public nonces
		for p in self.participant_data.iter() {
			if let Some(part_sig) = p.part_sig.as_ref() {
				aggsig::verify_partial_sig(
					secp,
					part_sig,
					&self.pub_nonce_sum(secp)?,
					&p.public_blind_excess,
					Some(&self.pub_blind_sum(secp)?),
					&self.msg_to_sign()?,
				)?;
			}
		}
		Ok(())
	}

	/// Verifies any messages in the slate's participant data match their signatures
	pub fn verify_messages(&self) -> Result<(), Error> {
		let secp = secp::Secp256k1::with_caps(secp::ContextFlag::VerifyOnly);
		for p in self.participant_data.iter() {
			if let Some(msg) = &p.message {
				let hashed = blake2b(secp::constants::MESSAGE_SIZE, &[], &msg.as_bytes()[..]);
				let m = secp::Message::from_slice(&hashed.as_bytes())?;
				let signature = match p.message_sig {
					None => {
						error!("verify_messages - participant message doesn't have signature. Message: \"{}\"",
						   String::from_utf8_lossy(&msg.as_bytes()[..]));
						return Err(Error::Signature(
							"Optional participant messages doesn't have signature".to_owned(),
						))?;
					}
					Some(s) => s,
				};
				if !aggsig::verify_single(
					&secp,
					&signature,
					&m,
					None,
					&p.public_blind_excess,
					Some(&p.public_blind_excess),
					false,
				) {
					error!("verify_messages - participant message doesn't match signature. Message: \"{}\"",
						   String::from_utf8_lossy(&msg.as_bytes()[..]));
					return Err(Error::Signature(
						"Optional participant messages do not match signatures".to_owned(),
					))?;
				} else {
					info!(
						"verify_messages - signature verified ok. Participant message: \"{}\"",
						String::from_utf8_lossy(&msg.as_bytes()[..])
					);
				}
			}
		}
		Ok(())
	}

	/// This should be callable by either the sender or receiver
	/// once phase 3 is done
	///
	/// Receive Part 3 of interactive transactions from sender, Sender
	/// Confirmation Return Ok/Error
	/// -Receiver receives sS
	/// -Receiver verifies sender's sig, by verifying that
	/// kS * G + e *xS * G = sS* G
	/// -Receiver calculates final sig as s=(sS+sR, kS * G+kR * G)
	/// -Receiver puts into TX kernel:
	///
	/// Signature S
	/// pubkey xR * G+xS * G
	/// fee (= M)
	///
	/// Returns completed transaction ready for posting to the chain

	fn finalize_signature<K>(&mut self, keychain: &K) -> Result<Signature, Error>
	where
		K: Keychain,
	{
		self.validate_complete_participant_data()?;
		self.verify_part_sigs(keychain.secp())?;

		let part_sigs = self.part_sigs()?;
		let pub_nonce_sum = self.pub_nonce_sum(keychain.secp())?;
		let final_pubkey = self.pub_blind_sum(keychain.secp())?;
		// get the final signature
		let final_sig = aggsig::add_signatures(&keychain.secp(), part_sigs, &pub_nonce_sum)?;

		// Calculate the final public key (for our own sanity check)

		// Check our final sig verifies
		aggsig::verify_completed_sig(
			&keychain.secp(),
			&final_sig,
			&final_pubkey,
			Some(&final_pubkey),
			&self.msg_to_sign()?,
		)?;

		Ok(final_sig)
	}

	/// return the final excess
	pub fn calc_excess<K>(&self, keychain: &K) -> Result<Commitment, Error>
	where
		K: Keychain,
	{
		let kernel_offset = &self.tx.offset;
		let tx = self.tx.clone();
		let overage = tx.fee() as i64;
		let tx_excess = tx.sum_commitments(overage)?;

		// subtract the kernel_excess (built from kernel_offset)
		let offset_excess = keychain
			.secp()
			.commit(0, kernel_offset.secret_key(&keychain.secp())?)?;
		Ok(keychain
			.secp()
			.commit_sum(vec![tx_excess], vec![offset_excess])?)
	}

	/// builds a final transaction after the aggregated sig exchange
	fn finalize_transaction<K>(
		&mut self,
		keychain: &K,
		final_sig: &secp::Signature,
	) -> Result<(), Error>
	where
		K: Keychain,
	{
		self.validate_single_kernel()?;
		self.check_fees()?;
		// build the final excess based on final tx and offset
		let final_excess = self.calc_excess(keychain)?;

		debug!("Final Tx excess: {:?}", final_excess);

		let mut final_tx = self.tx.clone();

		// update the tx kernel to reflect the offset excess and sig
		let kernel = final_tx
			.kernels_mut()
			.first_mut()
			.ok_or_else(|| Self::invalid_slate("transaction kernel is missing"))?;
		kernel.excess = final_excess.clone();
		kernel.excess_sig = final_sig.clone();

		// confirm the kernel verifies successfully before proceeding
		debug!("Validating final transaction");
		let kernel = final_tx
			.kernels()
			.first()
			.ok_or_else(|| Self::invalid_slate("transaction kernel is missing"))?;
		let _ = kernel.verify()?;

		// confirm the overall transaction is valid (including the updated kernel)
		// accounting for tx weight limits
		let _ = final_tx.validate(Weighting::AsTransaction)?;

		self.tx = final_tx;
		Ok(())
	}
}

impl Serialize for Slate {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		use serde::ser::Error;

		let v3 = SlateV3::from(self);
		match self.version_info.orig_version {
			3 => v3.serialize(serializer),
			// left as a reminder
			2 => {
				let v2 = SlateV2::from(&v3);
				v2.serialize(serializer)
			}
			v => Err(S::Error::custom(format!("Unknown slate version {}", v))),
		}
	}
}

#[cfg(test)]
mod malformed_slate_tests {
	use super::*;
	use crate::epic_keychain::{ExtKeychain, Keychain};
	use std::panic::{catch_unwind, AssertUnwindSafe};

	fn participant(keychain: &ExtKeychain, id: u64) -> ParticipantData {
		let secret = SecretKey::new(keychain.secp(), &mut rng());
		let nonce = SecretKey::new(keychain.secp(), &mut rng());
		ParticipantData {
			id,
			public_blind_excess: PublicKey::from_secret_key(keychain.secp(), &secret).unwrap(),
			public_nonce: PublicKey::from_secret_key(keychain.secp(), &nonce).unwrap(),
			part_sig: None,
			message: None,
			message_sig: None,
		}
	}

	#[test]
	fn malformed_participant_count_returns_error_without_panicking() {
		let keychain = ExtKeychain::from_random_seed(true).unwrap();
		let secret = SecretKey::new(keychain.secp(), &mut rng());
		let nonce = SecretKey::new(keychain.secp(), &mut rng());
		let mut slate = Slate::blank(2);
		slate.participant_data.push(participant(&keychain, 0));

		let result = catch_unwind(AssertUnwindSafe(|| {
			slate.fill_round_2(&keychain, &secret, &nonce, 1)
		}));
		assert!(result.is_ok(), "malformed participant data must not panic");
		assert!(result.unwrap().is_err());
	}

	#[test]
	fn missing_partial_signatures_return_error_without_panicking() {
		let keychain = ExtKeychain::from_random_seed(true).unwrap();
		let mut slate = Slate::blank(2);
		slate.participant_data.push(participant(&keychain, 0));
		slate.participant_data.push(participant(&keychain, 1));

		let result = catch_unwind(AssertUnwindSafe(|| slate.finalize(&keychain)));
		assert!(result.is_ok(), "missing partial signatures must not panic");
		assert!(result.unwrap().is_err());
	}

	#[test]
	fn invalid_participant_ids_are_rejected() {
		let keychain = ExtKeychain::from_random_seed(true).unwrap();
		let mut duplicate = Slate::blank(2);
		duplicate.participant_data.push(participant(&keychain, 0));
		duplicate.participant_data.push(participant(&keychain, 0));
		assert!(matches!(
			duplicate.validate_participant_data(),
			Err(Error::InvalidSlate(_))
		));

		let mut out_of_range = Slate::blank(2);
		out_of_range
			.participant_data
			.push(participant(&keychain, 2));
		assert!(matches!(
			out_of_range.validate_participant_data(),
			Err(Error::InvalidSlate(_))
		));
	}

	#[test]
	fn participant_and_kernel_shapes_are_validated() {
		let keychain = ExtKeychain::from_random_seed(true).unwrap();
		let mut slate = Slate::blank(2);
		assert!(matches!(
			slate.validate_single_kernel(),
			Err(Error::InvalidSlate(_))
		));

		slate.update_kernel();
		slate.participant_data.push(participant(&keychain, 0));
		assert!(slate.validate_single_kernel().is_ok());
		assert!(slate.validate_participant_data().is_ok());
		slate.participant_data.push(participant(&keychain, 1));
		assert!(slate.validate_complete_participant_data().is_ok());

		let extra_kernel = slate.tx.kernels()[0].clone();
		slate.tx.kernels_mut().push(extra_kernel);
		assert!(matches!(
			slate.validate_single_kernel(),
			Err(Error::InvalidSlate(_))
		));
	}

	#[test]
	fn malformed_v2_and_v3_json_return_errors_without_panicking() {
		let mut v2: serde_json::Value =
			serde_json::from_str(include_str!("../tests/slates/v2.slate")).unwrap();
		v2["num_participants"] = serde_json::json!(0);
		let v2 = serde_json::to_string(&v2).unwrap();
		let result = catch_unwind(|| Slate::deserialize_upgrade(&v2));
		assert!(result.is_ok(), "malformed v2 slate must not panic");
		assert!(result.unwrap().is_err());

		let mut v3 = serde_json::to_value(Slate::blank(2)).unwrap();
		v3["payment_proof"] = serde_json::json!({
			"sender_address": "00",
			"receiver_address": "00",
			"receiver_signature": "00"
		});
		let v3 = serde_json::to_string(&v3).unwrap();
		let result = catch_unwind(|| Slate::deserialize_upgrade(&v3));
		assert!(result.is_ok(), "malformed v3 slate must not panic");
		assert!(result.unwrap().is_err());

		let v2: serde_json::Value =
			serde_json::from_str(include_str!("../tests/slates/v2.slate")).unwrap();
		let mut v3 = v2.clone();
		v3["version_info"]["version"] = serde_json::json!(3);
		v3["version_info"]["orig_version"] = serde_json::json!(3);
		v3["ttl_cutoff_height"] = serde_json::Value::Null;
		v3["payment_proof"] = serde_json::Value::Null;

		for (version, slate) in [("v2", v2), ("v3", v3)] {
			for field in [
				"/participant_data/0/public_blind_excess",
				"/participant_data/0/public_nonce",
				"/participant_data/0/part_sig",
				"/participant_data/0/message_sig",
				"/tx/offset",
				"/tx/body/inputs/0/commit",
				"/tx/body/outputs/0/commit",
				"/tx/body/outputs/0/proof",
				"/tx/body/kernels/0/excess",
				"/tx/body/kernels/0/excess_sig",
			] {
				let mut malformed = slate.clone();
				*malformed.pointer_mut(field).unwrap() = serde_json::json!("é");
				let malformed = serde_json::to_string(&malformed).unwrap();
				let result = catch_unwind(|| Slate::deserialize_upgrade(&malformed));
				assert!(result.is_ok(), "malformed {} {} must not panic", version, field);
				assert!(result.unwrap().is_err());
			}

			let mut oversized_proof = slate;
			*oversized_proof.pointer_mut("/tx/body/outputs/0/proof").unwrap() =
				serde_json::json!("00".repeat(
					crate::epic_util::secp::constants::MAX_PROOF_SIZE + 1
				));
			let oversized_proof = serde_json::to_string(&oversized_proof).unwrap();
			let result = catch_unwind(|| Slate::deserialize_upgrade(&oversized_proof));
			assert!(result.is_ok(), "oversized {} range proof must not panic", version);
			assert!(result.unwrap().is_err());
		}

		let mut converted: serde_json::Value =
			serde_json::from_str(include_str!("../tests/slates/v2.slate")).unwrap();
		converted["version_info"]["version"] = serde_json::json!(3);
		converted["version_info"]["orig_version"] = serde_json::json!(2);
		converted["ttl_cutoff_height"] = serde_json::Value::Null;
		converted["payment_proof"] = serde_json::Value::Null;
		let converted = serde_json::to_string(&converted).unwrap();
		let slate = Slate::deserialize_upgrade(&converted).unwrap();
		let serialized = serde_json::to_string(&slate).unwrap();
		assert!(Slate::deserialize_upgrade(&serialized).is_ok());
	}
}

/// Save the version of Slate
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SlateVersionProbe {
	#[serde(default)]
	version: Option<u64>,
	#[serde(default)]
	version_info: Option<VersionCompatInfo>,
}

impl SlateVersionProbe {
	/// Show the version of SlateVersionProbe
	pub fn version(&self) -> u16 {
		match &self.version_info {
			Some(v) => v.version,
			None => match self.version {
				Some(_) => 1,
				None => 0,
			},
		}
	}
}

// Coinbase data to versioned.
impl From<CbData> for CoinbaseV3 {
	fn from(cb: CbData) -> CoinbaseV3 {
		CoinbaseV3 {
			output: OutputV3::from(&cb.output),
			kernel: TxKernelV3::from(&cb.kernel),
			key_id: cb.key_id,
		}
	}
}

// Current slate version to versioned conversions

// Slate to versioned
impl From<Slate> for SlateV3 {
	fn from(slate: Slate) -> SlateV3 {
		let Slate {
			num_participants,
			id,
			tx,
			amount,
			fee,
			height,
			lock_height,
			ttl_cutoff_height,
			participant_data,
			version_info,
			payment_proof,
		} = slate;
		let participant_data = map_vec!(participant_data, |data| ParticipantDataV3::from(data));
		let version_info = VersionCompatInfoV3::from(&version_info);
		let payment_proof = match payment_proof {
			Some(p) => Some(PaymentInfoV3::from(&p)),
			None => None,
		};
		let tx = TransactionV3::from(tx);
		SlateV3 {
			num_participants,
			id,
			tx,
			amount,
			fee,
			height,
			lock_height,
			ttl_cutoff_height,
			participant_data,
			version_info,
			payment_proof,
		}
	}
}

impl From<&Slate> for SlateV3 {
	fn from(slate: &Slate) -> SlateV3 {
		let Slate {
			num_participants,
			id,
			tx,
			amount,
			fee,
			height,
			lock_height,
			ttl_cutoff_height,
			participant_data,
			version_info,
			payment_proof,
		} = slate;
		let num_participants = *num_participants;
		let id = *id;
		let tx = TransactionV3::from(tx);
		let amount = *amount;
		let fee = *fee;
		let height = *height;
		let lock_height = *lock_height;
		let ttl_cutoff_height = *ttl_cutoff_height;
		let participant_data = map_vec!(participant_data, |data| ParticipantDataV3::from(data));
		let version_info = VersionCompatInfoV3::from(version_info);
		let payment_proof = match payment_proof {
			Some(p) => Some(PaymentInfoV3::from(p)),
			None => None,
		};
		SlateV3 {
			num_participants,
			id,
			tx,
			amount,
			fee,
			height,
			lock_height,
			ttl_cutoff_height,
			participant_data,
			version_info,
			payment_proof,
		}
	}
}

impl From<&ParticipantData> for ParticipantDataV3 {
	fn from(data: &ParticipantData) -> ParticipantDataV3 {
		let ParticipantData {
			id,
			public_blind_excess,
			public_nonce,
			part_sig,
			message,
			message_sig,
		} = data;
		let id = *id;
		let public_blind_excess = *public_blind_excess;
		let public_nonce = *public_nonce;
		let part_sig = *part_sig;
		let message: Option<String> = message.as_ref().map(|t| String::from(&**t));
		let message_sig = *message_sig;
		ParticipantDataV3 {
			id,
			public_blind_excess,
			public_nonce,
			part_sig,
			message,
			message_sig,
		}
	}
}

impl From<&VersionCompatInfo> for VersionCompatInfoV3 {
	fn from(data: &VersionCompatInfo) -> VersionCompatInfoV3 {
		let VersionCompatInfo {
			version: _,
			orig_version,
			block_header_version,
		} = data;
		let version = 3;
		let orig_version = *orig_version;
		let block_header_version = *block_header_version;
		VersionCompatInfoV3 {
			version,
			orig_version,
			block_header_version,
		}
	}
}

impl From<&PaymentInfo> for PaymentInfoV3 {
	fn from(data: &PaymentInfo) -> PaymentInfoV3 {
		let PaymentInfo {
			sender_address,
			receiver_address,
			receiver_signature,
		} = data;
		let sender_address = *sender_address;
		let receiver_address = *receiver_address;
		let receiver_signature = *receiver_signature;
		PaymentInfoV3 {
			sender_address,
			receiver_address,
			receiver_signature,
		}
	}
}

impl From<Transaction> for TransactionV3 {
	fn from(tx: Transaction) -> TransactionV3 {
		let Transaction { offset, body } = tx;
		let body = TransactionBodyV3::from(&body);
		TransactionV3 { offset, body }
	}
}

impl From<&Transaction> for TransactionV3 {
	fn from(tx: &Transaction) -> TransactionV3 {
		let Transaction { offset, body } = tx;
		let offset = offset.clone();
		let body = TransactionBodyV3::from(body);
		TransactionV3 { offset, body }
	}
}

impl From<&TransactionBody> for TransactionBodyV3 {
	fn from(body: &TransactionBody) -> TransactionBodyV3 {
		let TransactionBody {
			inputs,
			outputs,
			kernels,
		} = body;

		let inputs = map_vec!(inputs, |inp| InputV3::from(inp));
		let outputs = map_vec!(outputs, |out| OutputV3::from(out));
		let kernels = map_vec!(kernels, |kern| TxKernelV3::from(kern));
		TransactionBodyV3 {
			inputs,
			outputs,
			kernels,
		}
	}
}

impl From<&Input> for InputV3 {
	fn from(input: &Input) -> InputV3 {
		let Input { features, commit } = *input;
		InputV3 { features, commit }
	}
}

impl From<&Output> for OutputV3 {
	fn from(output: &Output) -> OutputV3 {
		let Output {
			features,
			commit,
			proof,
		} = *output;
		OutputV3 {
			features,
			commit,
			proof,
		}
	}
}

impl From<&TxKernel> for TxKernelV3 {
	fn from(kernel: &TxKernel) -> TxKernelV3 {
		let (features, fee, lock_height) = match kernel.features {
			KernelFeatures::Plain { fee } => (CompatKernelFeatures::Plain, fee, 0),
			KernelFeatures::Coinbase => (CompatKernelFeatures::Coinbase, 0, 0),
			KernelFeatures::HeightLocked { fee, lock_height } => {
				(CompatKernelFeatures::HeightLocked, fee, lock_height)
			}
		};
		TxKernelV3 {
			features,
			fee,
			lock_height,
			excess: kernel.excess,
			excess_sig: kernel.excess_sig,
		}
	}
}

// Versioned to current slate
impl From<SlateV3> for Slate {
	fn from(slate: SlateV3) -> Slate {
		let SlateV3 {
			num_participants,
			id,
			tx,
			amount,
			fee,
			height,
			lock_height,
			ttl_cutoff_height,
			participant_data,
			version_info,
			payment_proof,
		} = slate;
		let participant_data = map_vec!(participant_data, |data| ParticipantData::from(data));
		let version_info = VersionCompatInfo::from(&version_info);
		let payment_proof = match payment_proof {
			Some(p) => Some(PaymentInfo::from(&p)),
			None => None,
		};
		let tx = Transaction::from(tx);
		Slate {
			num_participants,
			id,
			tx,
			amount,
			fee,
			height,
			lock_height,
			ttl_cutoff_height,
			participant_data,
			version_info,
			payment_proof,
		}
	}
}

impl From<&ParticipantDataV3> for ParticipantData {
	fn from(data: &ParticipantDataV3) -> ParticipantData {
		let ParticipantDataV3 {
			id,
			public_blind_excess,
			public_nonce,
			part_sig,
			message,
			message_sig,
		} = data;
		let id = *id;
		let public_blind_excess = *public_blind_excess;
		let public_nonce = *public_nonce;
		let part_sig = *part_sig;
		let message: Option<String> = message.as_ref().map(|t| String::from(&**t));
		let message_sig = *message_sig;
		ParticipantData {
			id,
			public_blind_excess,
			public_nonce,
			part_sig,
			message,
			message_sig,
		}
	}
}

impl From<&VersionCompatInfoV3> for VersionCompatInfo {
	fn from(data: &VersionCompatInfoV3) -> VersionCompatInfo {
		let VersionCompatInfoV3 {
			version,
			orig_version,
			block_header_version,
		} = data;
		let version = *version;
		let orig_version = *orig_version;
		let block_header_version = *block_header_version;
		VersionCompatInfo {
			version,
			orig_version,
			block_header_version,
		}
	}
}

impl From<&PaymentInfoV3> for PaymentInfo {
	fn from(data: &PaymentInfoV3) -> PaymentInfo {
		let PaymentInfoV3 {
			sender_address,
			receiver_address,
			receiver_signature,
		} = data;
		let sender_address = *sender_address;
		let receiver_address = *receiver_address;
		let receiver_signature = *receiver_signature;
		PaymentInfo {
			sender_address,
			receiver_address,
			receiver_signature,
		}
	}
}

impl From<TransactionV3> for Transaction {
	fn from(tx: TransactionV3) -> Transaction {
		let TransactionV3 { offset, body } = tx;
		let body = TransactionBody::from(&body);
		Transaction { offset, body }
	}
}

impl From<&TransactionBodyV3> for TransactionBody {
	fn from(body: &TransactionBodyV3) -> TransactionBody {
		let TransactionBodyV3 {
			inputs,
			outputs,
			kernels,
		} = body;

		let inputs = map_vec!(inputs, |inp| Input::from(inp));
		let outputs = map_vec!(outputs, |out| Output::from(out));
		let kernels = map_vec!(kernels, |kern| TxKernel::from(kern));
		TransactionBody {
			inputs,
			outputs,
			kernels,
		}
	}
}

impl From<&InputV3> for Input {
	fn from(input: &InputV3) -> Input {
		let InputV3 { features, commit } = *input;
		Input { features, commit }
	}
}

impl From<&OutputV3> for Output {
	fn from(output: &OutputV3) -> Output {
		let OutputV3 {
			features,
			commit,
			proof,
		} = *output;
		Output {
			features,
			commit,
			proof,
		}
	}
}

impl From<&TxKernelV3> for TxKernel {
	fn from(kernel: &TxKernelV3) -> TxKernel {
		let (fee, lock_height) = (kernel.fee, kernel.lock_height);
		let features = match kernel.features {
			CompatKernelFeatures::Plain => KernelFeatures::Plain { fee },
			CompatKernelFeatures::Coinbase => KernelFeatures::Coinbase,
			CompatKernelFeatures::HeightLocked => KernelFeatures::HeightLocked { fee, lock_height },
		};
		TxKernel {
			features,
			excess: kernel.excess,
			excess_sig: kernel.excess_sig,
		}
	}
}

/// Save the type of kernel
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum CompatKernelFeatures {
	/// Transaction
	Plain,
	/// Mined block
	Coinbase,
	/// Lock height
	HeightLocked,
}
