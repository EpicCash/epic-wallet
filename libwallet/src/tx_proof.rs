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
use failure::Fail;
use serde::{Deserialize, Serialize};

#[derive(Debug, Fail)]
pub enum ErrorKind {
	#[fail(display = "Unable to parse address")]
	ParseAddress,
	#[fail(display = "Unable to parse public key")]
	ParsePublicKey,
	#[fail(display = "Unable to parse signature")]
	ParseSignature,
	#[fail(display = "Unable to verify signature")]
	VerifySignature,
	#[fail(display = "Unable to parse encrypted message")]
	ParseEncryptedMessage,
	#[fail(display = "Unable to verify destination")]
	VerifyDestination,
	#[fail(display = "Unable to determine decryption key")]
	DecryptionKey,
	#[fail(display = "Unable to decrypt message")]
	DecryptMessage,
	#[fail(display = "Unable to parse slate")]
	ParseSlate,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TxProof {
	pub address: EpicboxAddress,
	pub message: String,
	pub challenge: String,
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
	) -> Result<(EpicboxAddress, VersionedSlate), ErrorKind> {
		let mut challenge = String::new();
		challenge.push_str(self.message.as_str());
		challenge.push_str(self.challenge.as_str());

		let public_key = self
			.address
			.public_key()
			.map_err(|_| ErrorKind::ParsePublicKey)?;

		verify_signature(&challenge, &self.signature, &public_key)
			.map_err(|_| ErrorKind::VerifySignature)?;

		let encrypted_message: EncryptedMessage =
			serde_json::from_str(&self.message).map_err(|_| ErrorKind::ParseEncryptedMessage)?;

		let destination = encrypted_message.destination.clone();
		if expected_destination.is_some()
			&& destination.public_key != expected_destination.unwrap().public_key
		{
			return Err(ErrorKind::VerifyDestination);
		}

		let decrypted_message = encrypted_message
			.decrypt_with_key(&self.key)
			.map_err(|_| ErrorKind::DecryptMessage)?;

		let slate: VersionedSlate =
			serde_json::from_str(&decrypted_message).map_err(|_| ErrorKind::ParseSlate)?;
		//let slate = Slate::deserialize_upgrade(&decrypted_message)
		//	.map_err(|_| ErrorKind::DecryptMessage)?;

		Ok((destination, slate))
	}

	pub fn from_response(
		from: String,
		message: String,
		challenge: String,
		signature: String,
		secret_key: &SecretKey,
		expected_destination: Option<&EpicboxAddress>,
	) -> Result<(VersionedSlate, TxProof), ErrorKind> {
		let address =
			EpicboxAddress::from_str(from.as_str()).map_err(|_| ErrorKind::ParseAddress)?;
		let signature =
			Signature::from_hex(signature.as_str()).map_err(|_| ErrorKind::ParseSignature)?;
		let public_key = address
			.public_key()
			.map_err(|_| ErrorKind::ParsePublicKey)?;
		let encrypted_message: EncryptedMessage =
			serde_json::from_str(&message).map_err(|_| ErrorKind::ParseEncryptedMessage)?;
		let key = encrypted_message
			.key(&public_key, secret_key)
			.map_err(|_| ErrorKind::DecryptionKey)?;

		let proof = TxProof {
			address,
			message,
			challenge,
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
