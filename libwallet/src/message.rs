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

use crate::EpicboxAddress;

use crate::crypto::{from_hex, to_hex};
use crate::epic_util::secp::key::{PublicKey, SecretKey};
use crate::epic_util::secp::Secp256k1;
use crate::{Error, ErrorKind};
use rand::thread_rng;
use rand::Rng;
use ring::aead;
use ring::{digest, pbkdf2};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedMessage {
	pub destination: EpicboxAddress,
	encrypted_message: String,
	salt: String,
	nonce: String,
}

impl EncryptedMessage {
	pub fn new(
		message: String,
		destination: &EpicboxAddress,
		receiver_public_key: &PublicKey,
		secret_key: &SecretKey,
	) -> Result<EncryptedMessage, Error> {
		let secp = Secp256k1::new();
		let mut common_secret = receiver_public_key.clone();
		common_secret
			.mul_assign(&secp, secret_key)
			.map_err(|_| ErrorKind::Encryption)?;
		let common_secret_ser = common_secret.serialize_vec(&secp, true);
		let common_secret_slice = &common_secret_ser[1..33];

		let salt: [u8; 8] = thread_rng().gen();
		let nonce: [u8; 12] = thread_rng().gen();
		let mut key = [0; 32];
		pbkdf2::derive(&digest::SHA512, 100, &salt, common_secret_slice, &mut key);
		let mut enc_bytes = message.as_bytes().to_vec();
		let suffix_len = aead::CHACHA20_POLY1305.tag_len();
		for _ in 0..suffix_len {
			enc_bytes.push(0);
		}
		let sealing_key = aead::SealingKey::new(&aead::CHACHA20_POLY1305, &key)
			.map_err(|_| ErrorKind::Encryption)?;
		aead::seal_in_place(&sealing_key, &nonce, &[], &mut enc_bytes, suffix_len)
			.map_err(|_| ErrorKind::Encryption)?;

		Ok(EncryptedMessage {
			destination: destination.clone(),
			encrypted_message: to_hex(enc_bytes),
			salt: to_hex(salt.to_vec()),
			nonce: to_hex(nonce.to_vec()),
		})
	}

	pub fn key(
		&self,
		sender_public_key: &PublicKey,
		secret_key: &SecretKey,
	) -> Result<[u8; 32], Error> {
		let salt = from_hex(self.salt.clone()).map_err(|_| ErrorKind::Decryption)?;

		let secp = Secp256k1::new();
		let mut common_secret = sender_public_key.clone();
		common_secret
			.mul_assign(&secp, secret_key)
			.map_err(|_| ErrorKind::Decryption)?;
		let common_secret_ser = common_secret.serialize_vec(&secp, true);
		let common_secret_slice = &common_secret_ser[1..33];

		let mut key = [0; 32];
		pbkdf2::derive(&digest::SHA512, 100, &salt, common_secret_slice, &mut key);

		Ok(key)
	}

	pub fn decrypt_with_key(&self, key: &[u8; 32]) -> Result<String, Error> {
		let mut encrypted_message =
			from_hex(self.encrypted_message.clone()).map_err(|_| ErrorKind::Decryption)?;
		let nonce = from_hex(self.nonce.clone()).map_err(|_| ErrorKind::Decryption)?;

		let opening_key = aead::OpeningKey::new(&aead::CHACHA20_POLY1305, key)
			.map_err(|_| ErrorKind::Decryption)?;
		let decrypted_data =
			aead::open_in_place(&opening_key, &nonce, &[], 0, &mut encrypted_message)
				.map_err(|_| ErrorKind::Decryption)?;

		String::from_utf8(decrypted_data.to_vec()).map_err(|_| ErrorKind::Decryption.into())
	}
}
