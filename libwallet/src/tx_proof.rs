// Copyright 2018 The Grin Developers
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

use super::VersionedSlate;
use crate::crypto::verify_signature;
use crate::crypto::Hex;
use crate::epic_util::secp::key::SecretKey;
use crate::epic_util::secp::pedersen::Commitment;
use crate::epic_util::secp::Signature;
use crate::message::EncryptedMessage;

use crate::{Address, EpicboxAddress};
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("Unable to parse address")]
	ParseAddress,
	#[error("Unable to parse public key")]
	ParsePublicKey,
	#[error("Unable to parse signature")]
	ParseSignature,
	#[error("Unable to verify signature")]
	VerifySignature,
	#[error("Unable to parse encrypted message")]
	ParseEncryptedMessage,
	#[error("Unable to verify destination")]
	VerifyDestination,
	#[error("Unable to determine decryption key")]
	DecryptionKey,
	#[error("Unable to decrypt message")]
	DecryptMessage,
	#[error("Unable to parse slate")]
	ParseSlate,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TxProof {
	pub address: EpicboxAddress,
	pub message: String,
	pub signature: Signature,
	pub key: [u8; 32],
	pub amount: u64,
	pub fee: u64,
	pub inputs: Vec<Commitment>,
	pub outputs: Vec<Commitment>,
}

impl TxProof {
	pub fn verify_extract(
		&self,
		expected_destination: Option<&EpicboxAddress>,
	) -> Result<(EpicboxAddress, VersionedSlate), Error> {
		let mut challenge = String::new();
		challenge.push_str(self.message.as_str());

		let public_key = self
			.address
			.public_key()
			.map_err(|_| Error::ParsePublicKey)?;

		verify_signature(&challenge, &self.signature, &public_key)
			.map_err(|_| Error::VerifySignature)?;

		let encrypted_message: EncryptedMessage =
			serde_json::from_str(&self.message).map_err(|_| Error::ParseEncryptedMessage)?;

		let destination = encrypted_message.destination.clone();
		if expected_destination.is_some()
			&& destination.public_key != expected_destination.unwrap().public_key
		{
			return Err(Error::VerifyDestination);
		}

		let decrypted_message = encrypted_message
			.decrypt_with_key(&self.key)
			.map_err(|_| Error::DecryptMessage)?;

		let slate: VersionedSlate =
			serde_json::from_str(&decrypted_message).map_err(|_| Error::ParseSlate)?;

		Ok((destination, slate))
	}

	pub fn from_response(
		from: String,
		message: String,
		signature: String,
		secret_key: &SecretKey,
		expected_destination: Option<&EpicboxAddress>,
	) -> Result<(VersionedSlate, TxProof), Error> {
		let address = EpicboxAddress::from_str(from.as_str()).map_err(|_| Error::ParseAddress)?;
		let signature =
			Signature::from_hex(signature.as_str()).map_err(|_| Error::ParseSignature)?;
		let public_key = address.public_key().map_err(|_| Error::ParsePublicKey)?;
		let encrypted_message: EncryptedMessage =
			serde_json::from_str(&message).map_err(|_| Error::ParseEncryptedMessage)?;
		let key = encrypted_message
			.key(&public_key, secret_key)
			.map_err(|_| Error::DecryptionKey)?;

		let proof = TxProof {
			address,
			message,
			signature,
			key,
			amount: 0,
			fee: 0,
			inputs: vec![],
			outputs: vec![],
		};

		let (_, slate) = proof.verify_extract(expected_destination)?;

		Ok((slate, proof))
	}
}
