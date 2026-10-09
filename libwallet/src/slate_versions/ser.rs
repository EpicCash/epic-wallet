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

//! Sane serialization & deserialization of cryptographic structs into hex

const DALEK_PUBLIC_KEY_BYTES: usize = 32;
const SECP_PUBLIC_KEY_BYTES: usize = 33;
const BLINDING_FACTOR_BYTES: usize = 32;
const COMMITMENT_BYTES: usize = 33;
const SIGNATURE_BYTES: usize = 64;
const MAX_RANGE_PROOF_BYTES: usize = crate::epic_util::secp::constants::MAX_PROOF_SIZE;

fn decode_fixed_hex<const N: usize>(value: String) -> Result<[u8; N], String> {
	if N == 0 || value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
		return Err(format!(
			"hex value must be exactly {} hexadecimal characters",
			N * 2
		));
	}

	crate::epic_util::from_hex(value)
		.map_err(|err| err.to_string())?
		.try_into()
		.map_err(|_| format!("hex value must decode to exactly {} bytes", N))
}

fn decode_variable_hex(value: &str) -> Result<Vec<u8>, String> {
	if value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
		return Err("range proof must contain an even number of hexadecimal characters".into());
	}

	value
		.as_bytes()
		.chunks_exact(2)
		.map(|pair| {
			let high = hex_nibble(pair[0]).ok_or_else(|| "invalid range proof".to_owned())?;
			let low = hex_nibble(pair[1]).ok_or_else(|| "invalid range proof".to_owned())?;
			Ok((high << 4) | low)
		})
		.collect()
}

fn hex_nibble(byte: u8) -> Option<u8> {
	match byte {
		b'0'..=b'9' => Some(byte - b'0'),
		b'a'..=b'f' => Some(byte - b'a' + 10),
		b'A'..=b'F' => Some(byte - b'A' + 10),
		_ => None,
	}
}

/// Deserialize a transaction offset without entering the dependency's
/// panic-prone hexadecimal decoder on malformed counterparty input.
pub fn blinding_factor_from_hex<'de, D>(
	deserializer: D,
) -> Result<crate::epic_keychain::BlindingFactor, D::Error>
where
	D: serde::Deserializer<'de>,
{
	use serde::de::Error;
	use serde::Deserialize;

	let bytes = decode_fixed_hex::<BLINDING_FACTOR_BYTES>(String::deserialize(deserializer)?)
		.map_err(Error::custom)?;
	Ok(crate::epic_keychain::BlindingFactor::from_slice(&bytes))
}

/// Serializes a secp public key to and from bounded hexadecimal text.
pub mod secp_pubkey_serde {
	use crate::epic_core::libtx::secp_ser;
	use crate::epic_util::{secp::key::PublicKey, static_secp_instance};
	use serde::{Deserialize, Deserializer, Serializer};

	pub fn serialize<S>(key: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		secp_ser::pubkey_serde::serialize(key, serializer)
	}

	pub fn deserialize<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
	where
		D: Deserializer<'de>,
	{
		use serde::de::Error;
		let bytes = super::decode_fixed_hex::<{ super::SECP_PUBLIC_KEY_BYTES }>(
			String::deserialize(deserializer)?,
		)
		.map_err(Error::custom)?;
		let secp = static_secp_instance();
		let secp = secp.lock();
		PublicKey::from_slice(&secp, &bytes).map_err(|err| Error::custom(err.to_string()))
	}
}

/// Serializes an optional secp signature to and from bounded hexadecimal text.
pub mod option_secp_sig_serde {
	use crate::epic_core::libtx::secp_ser;
	use crate::epic_util::{secp, static_secp_instance};
	use serde::{Deserialize, Deserializer, Serializer};

	pub fn serialize<S>(sig: &Option<secp::Signature>, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		secp_ser::option_sig_serde::serialize(sig, serializer)
	}

	pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<secp::Signature>, D::Error>
	where
		D: Deserializer<'de>,
	{
		use serde::de::Error;
		let Some(value) = Option::<String>::deserialize(deserializer)? else {
			return Ok(None);
		};
		let bytes = super::decode_fixed_hex::<{ super::SIGNATURE_BYTES }>(value)
			.map_err(Error::custom)?;
		let secp = static_secp_instance();
		let secp = secp.lock();
		secp::Signature::from_compact(&secp, &bytes)
			.map(Some)
			.map_err(|err| Error::custom(err.to_string()))
	}
}

/// Serializes a secp signature to and from bounded hexadecimal text.
pub mod secp_sig_serde {
	use crate::epic_core::libtx::secp_ser;
	use crate::epic_util::{secp, static_secp_instance};
	use serde::{Deserialize, Deserializer, Serializer};

	pub fn serialize<S>(sig: &secp::Signature, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		secp_ser::sig_serde::serialize(sig, serializer)
	}

	pub fn deserialize<'de, D>(deserializer: D) -> Result<secp::Signature, D::Error>
	where
		D: Deserializer<'de>,
	{
		use serde::de::Error;
		let bytes = super::decode_fixed_hex::<{ super::SIGNATURE_BYTES }>(
			String::deserialize(deserializer)?,
		)
		.map_err(Error::custom)?;
		let secp = static_secp_instance();
		let secp = secp.lock();
		secp::Signature::from_compact(&secp, &bytes)
			.map_err(|err| Error::custom(err.to_string()))
	}
}

/// Deserialize a Pedersen commitment without using the dependency hex decoder.
pub fn commitment_from_hex<'de, D>(
	deserializer: D,
) -> Result<crate::epic_util::secp::pedersen::Commitment, D::Error>
where
	D: serde::Deserializer<'de>,
{
	use serde::de::Error;
	use serde::Deserialize;
	let bytes = decode_fixed_hex::<COMMITMENT_BYTES>(String::deserialize(deserializer)?)
		.map_err(Error::custom)?;
	Ok(crate::epic_util::secp::pedersen::Commitment(bytes))
}

/// Deserialize a range proof after bounding its decoded length.
pub fn rangeproof_from_hex<'de, D>(
	deserializer: D,
) -> Result<crate::epic_util::secp::pedersen::RangeProof, D::Error>
where
	D: serde::Deserializer<'de>,
{
	use serde::de::Error;
	use serde::Deserialize;
	let value = String::deserialize(deserializer)?;
	if value.len() > MAX_RANGE_PROOF_BYTES * 2 {
		return Err(Error::custom(
			"range proof exceeds the maximum encoded length",
		));
	}
	let bytes = decode_variable_hex(&value).map_err(Error::custom)?;
	let mut proof = [0; MAX_RANGE_PROOF_BYTES];
	proof[..bytes.len()].copy_from_slice(&bytes);
	Ok(crate::epic_util::secp::pedersen::RangeProof {
		proof,
		plen: bytes.len(),
	})
}

/// Serializes an ed25519 PublicKey to and from hex
pub mod dalek_pubkey_serde {
	use crate::epic_util::to_hex;
	use ed25519_dalek::VerifyingKey as DalekPublicKey;
	use serde::{Deserialize, Deserializer, Serializer};

	///
	pub fn serialize<S>(key: &DalekPublicKey, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&to_hex(key.to_bytes().to_vec()))
	}

	///
	pub fn deserialize<'de, D>(deserializer: D) -> Result<DalekPublicKey, D::Error>
	where
		D: Deserializer<'de>,
	{
		use serde::de::Error;
		String::deserialize(deserializer)
			.and_then(|string| {
				super::decode_fixed_hex::<{ super::DALEK_PUBLIC_KEY_BYTES }>(string)
					.map_err(Error::custom)
			})
			.and_then(|bytes| {
				DalekPublicKey::from_bytes(&bytes).map_err(|err| Error::custom(err.to_string()))
			})
	}
}

/// Serializes an Option<ed25519_dalek::PublicKey> to and from hex
pub mod option_dalek_pubkey_serde {

	use ed25519_dalek::VerifyingKey as DalekPublicKey;
	use serde::de::Error;
	use serde::{Deserialize, Deserializer, Serializer};

	use crate::epic_util::to_hex;

	///
	pub fn serialize<S>(key: &Option<DalekPublicKey>, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		match key {
			Some(key) => serializer.serialize_str(&to_hex(key.to_bytes().to_vec())),
			None => serializer.serialize_none(),
		}
	}

	///
	pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<DalekPublicKey>, D::Error>
	where
		D: Deserializer<'de>,
	{
		Option::<String>::deserialize(deserializer).and_then(|res| match res {
			Some(string) => super::decode_fixed_hex::<{ super::DALEK_PUBLIC_KEY_BYTES }>(string)
				.map_err(Error::custom)
				.and_then(|bytes| {
					DalekPublicKey::from_bytes(&bytes)
						.map(|val| Some(val))
						.map_err(|err| Error::custom(err.to_string()))
				}),
			None => Ok(None),
		})
	}
}
/// Serializes an ed25519_dalek::Signature to and from hex
pub mod dalek_sig_serde {
	use ed25519_dalek::Signature as DalekSignature;
	use serde::de::Error;
	use serde::{Deserialize, Deserializer, Serializer};

	use crate::epic_util::to_hex;

	///
	pub fn serialize<S>(key: &DalekSignature, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&to_hex(key.to_bytes().to_vec()))
	}

	///
	pub fn deserialize<'de, D>(deserializer: D) -> Result<DalekSignature, D::Error>
	where
		D: Deserializer<'de>,
	{
		String::deserialize(deserializer)
			.and_then(|string| {
				super::decode_fixed_hex::<{ super::SIGNATURE_BYTES }>(string)
					.map_err(Error::custom)
			})
			.map(|bytes| DalekSignature::from_bytes(&bytes))
	}
}

/// Serializes an Option<ed25519_dalek::PublicKey> to and from hex
pub mod option_dalek_sig_serde {
	use ed25519_dalek::Signature as DalekSignature;
	use serde::de::Error;
	use serde::{Deserialize, Deserializer, Serializer};

	use crate::epic_util::to_hex;

	///
	pub fn serialize<S>(key: &Option<DalekSignature>, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		match key {
			Some(key) => serializer.serialize_str(&to_hex(key.to_bytes().to_vec())),
			None => serializer.serialize_none(),
		}
	}

	///
	pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<DalekSignature>, D::Error>
	where
		D: Deserializer<'de>,
	{
		Option::<String>::deserialize(deserializer).and_then(|res| match res {
			Some(string) => super::decode_fixed_hex::<{ super::SIGNATURE_BYTES }>(string)
				.map_err(Error::custom)
				.map(|bytes| Some(DalekSignature::from_bytes(&bytes))),
			None => Ok(None),
		})
	}
}

// Test serialization methods of components that are being used
#[cfg(test)]
mod test {
	use super::*;

	use epic_wallet_util::mock_rng::StepRng;
	use crate::epic_util::{secp, static_secp_instance};

	use ed25519_dalek::Signature as DalekSignature;
	use ed25519_dalek::Signer;
	use ed25519_dalek::SigningKey as DalekSecretKey;
	use ed25519_dalek::VerifyingKey as DalekPublicKey;
	use serde::Deserialize;

	use serde_json;

	#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
	struct SerTest {
		#[serde(with = "dalek_pubkey_serde")]
		pub pub_key: DalekPublicKey,
		#[serde(with = "option_dalek_pubkey_serde")]
		pub pub_key_opt: Option<DalekPublicKey>,
		#[serde(with = "dalek_sig_serde")]
		pub sig: DalekSignature,
		#[serde(with = "option_dalek_sig_serde")]
		pub sig_opt: Option<DalekSignature>,
	}

	#[allow(dead_code)]
	#[derive(Deserialize)]
	struct OptionalPublicKey {
		#[serde(with = "option_dalek_pubkey_serde")]
		pub key: Option<DalekPublicKey>,
	}

	#[allow(dead_code)]
	#[derive(Deserialize)]
	struct RequiredSignature {
		#[serde(with = "dalek_sig_serde")]
		pub signature: DalekSignature,
	}

	#[test]
	fn malformed_dalek_hex_returns_error_without_panicking() {
		for json in [r#"{"key":""}"#, r#"{"key":"00"}"#, r#"{"key":"éé"}"#] {
			let result = std::panic::catch_unwind(|| {
				serde_json::from_str::<OptionalPublicKey>(json)
			});
			assert!(result.is_ok(), "malformed public key must not panic");
			assert!(result.unwrap().is_err());
		}

		for json in [
			r#"{"signature":""}"#,
			r#"{"signature":"00"}"#,
			r#"{"signature":"éé"}"#,
		] {
			let result = std::panic::catch_unwind(|| {
				serde_json::from_str::<RequiredSignature>(json)
			});
			assert!(result.is_ok(), "malformed signature must not panic");
			assert!(result.unwrap().is_err());
		}
	}

	impl SerTest {
		pub fn random() -> SerTest {
			let secp_inst = static_secp_instance();
			let secp = secp_inst.lock();
			let mut test_rng = StepRng::new(1234567890u64, 1);
			

			// Generate a secp256k1 secret key
			let sec_key = secp::key::SecretKey::new(&secp, &mut test_rng);

			// Create an ed25519 SigningKey from the secp256k1 secret key
			let d_skey = DalekSecretKey::from_bytes(&sec_key.0);

			// Derive the VerifyingKey (public key) from the SigningKey
			let d_pub_key: DalekPublicKey = d_skey.verifying_key();

			// Sign a test message
			let message = b"test sig";
			let d_sig = d_skey.sign(message);

			println!("D sig: {:?}", d_sig);

			SerTest {
				pub_key: d_pub_key.clone(),
				pub_key_opt: Some(d_pub_key),
				sig: d_sig.clone(),
				sig_opt: Some(d_sig),
			}
		}
	}

	#[test]
	fn ser_dalek_primitives() {
		for _ in 0..10 {
			let s = SerTest::random();
			println!("Before Serialization: {:?}", s);
			let serialized = serde_json::to_string_pretty(&s).unwrap();
			println!("JSON: {}", serialized);
			let deserialized: SerTest = serde_json::from_str(&serialized).unwrap();
			println!("After Serialization: {:?}", deserialized);
			println!();
			assert_eq!(s, deserialized);
		}
	}
}
