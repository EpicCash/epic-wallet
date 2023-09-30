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

use crate::crypto::{from_hex, to_hex};
use crate::epic_util::secp::key::{PublicKey, SecretKey};
use crate::epic_util::secp::Secp256k1;
use core::num::NonZeroU32;

use crate::EpicboxAddress;
use crate::Error;

use serde::{Deserialize, Serialize};

use rand::{thread_rng, Rng};
use ring::aead;
use ring::pbkdf2;

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
			.map_err(|_| Error::Encryption)?;
		let common_secret_ser = common_secret.serialize_vec(&secp, true);
		let common_secret_slice = &common_secret_ser[1..33];

		let salt: [u8; 8] = thread_rng().gen();
		let nonce: [u8; 12] = thread_rng().gen();
		let mut key = [0; 32];

		pbkdf2::derive(
			ring::pbkdf2::PBKDF2_HMAC_SHA512,
			NonZeroU32::new(100).unwrap(),
			&salt,
			common_secret_slice,
			&mut key,
		);

		let mut enc_bytes = message.as_bytes().to_vec();
		//let suffix_len = aead::CHACHA20_POLY1305.tag_len();
		/*for _ in 0..suffix_len {
			enc_bytes.push(0);
		}*/
		/*let sealing_key = aead::SealingKey::new(&aead::CHACHA20_POLY1305, &key)
			.map_err(|_| Error::Encryption)?;
		aead::seal_in_place(&sealing_key, &nonce, &[], &mut enc_bytes, suffix_len)
			.map_err(|_| Error::Encryption)?;*/

		let unbound_key = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key).unwrap();
		let sealing_key: aead::LessSafeKey = aead::LessSafeKey::new(unbound_key);
		let aad = aead::Aad::from(&[]);
		let res = sealing_key.seal_in_place_append_tag(
			aead::Nonce::assume_unique_for_key(nonce),
			aad,
			&mut enc_bytes,
		);
		if let Err(_) = res {
			return Err(Error::Encryption)?;
		}

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
		let salt = from_hex(self.salt.clone()).map_err(|_| Error::Decryption)?;

		let secp = Secp256k1::new();
		let mut common_secret = sender_public_key.clone();
		common_secret
			.mul_assign(&secp, secret_key)
			.map_err(|_| Error::Decryption)?;
		let common_secret_ser = common_secret.serialize_vec(&secp, true);
		let common_secret_slice = &common_secret_ser[1..33];

		let mut key = [0; 32];

		let len = std::num::NonZeroU32::new(100).unwrap();

		pbkdf2::derive(
			pbkdf2::PBKDF2_HMAC_SHA512,
			len,
			&salt,
			common_secret_slice,
			&mut key,
		);

		Ok(key)
	}

	pub fn decrypt_with_key(&self, key: &[u8; 32]) -> Result<String, Error> {
		let mut encrypted_message =
			from_hex(self.encrypted_message.clone()).map_err(|_| Error::Decryption)?;
		let nonce = from_hex(self.nonce.clone()).map_err(|_| Error::Decryption)?;

		let mut n = [0u8; 12];
		n.copy_from_slice(&nonce[0..12]);

		let unbound_key = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key).unwrap();
		let opening_key: aead::LessSafeKey = aead::LessSafeKey::new(unbound_key);
		let aad = aead::Aad::from(&[]);
		let res = opening_key.open_in_place(
			aead::Nonce::assume_unique_for_key(n),
			aad,
			&mut encrypted_message,
		);

		if let Err(_) = res {
			return Err(Error::Encryption)?;
		}
		for _ in 0..aead::AES_256_GCM.tag_len() {
			encrypted_message.pop();
		}

		String::from_utf8(encrypted_message.to_vec()).map_err(|_| Error::Decryption.into())
	}
}
