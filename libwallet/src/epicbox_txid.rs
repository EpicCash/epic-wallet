// Copyright 2026 The Epic Developers
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

use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize, Serializer};
use std::convert::TryFrom;
use std::error::Error;
use std::fmt;
use std::str::FromStr;
use uuid::{Uuid, Variant, Version};

/// Length of an Epicbox transaction identifier.
///
/// Epicbox transaction IDs use the UUID "simple" representation:
///
/// ```text
/// 550e8400e29b41d4a716446655440000
/// ```
///
/// This is a UUIDv4 with the hyphens removed.
pub const EPICBOX_TXID_LEN: usize = 32;

/// A stable, non-secret identifier for an Epicbox transaction.
///
/// An `EpicboxTxId` is generated from a UUIDv4 and encoded using its
/// 32-character hexadecimal representation without hyphens.
///
/// The identifier is used to associate the different Slate states belonging
/// to the same unfinalized transaction across the wallet and Epicbox relay.
///
/// It is not an authentication token. Authentication of operations involving
/// an Epicbox transaction ID must be performed separately, for example with a
/// signature over the ID.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EpicboxTxId(String);

/// Error returned when parsing or validating an Epicbox transaction ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EpicboxTxIdError {
	value: String,
}

impl EpicboxTxIdError {
	fn new(value: &str) -> Self {
		Self {
			value: value.to_string(),
		}
	}
}

impl fmt::Display for EpicboxTxIdError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(
			f,
			"invalid Epicbox transaction ID: expected a 32-character UUIDv4, got '{}'",
			self.value
		)
	}
}

impl Error for EpicboxTxIdError {}

/// Returns `true` if `s` is a valid Epicbox transaction ID.
///
/// A valid Epicbox transaction ID is:
///
/// - exactly 32 characters;
/// - hexadecimal;
/// - a valid UUID;
/// - UUID version 4; and
/// - an RFC4122 UUID variant.
pub fn is_epicbox_txid(s: &str) -> bool {
	if s.len() != EPICBOX_TXID_LEN {
		return false;
	}

	if !s.bytes().all(|b| b.is_ascii_hexdigit()) {
		return false;
	}

	match Uuid::parse_str(s) {
		Ok(uuid) => {
			uuid.get_version_num() == 4
				&& uuid.get_variant() == Variant::RFC4122
		}
		Err(_) => false,
	}
}

impl EpicboxTxId {
	/// Generate a new random Epicbox transaction ID.
	///
	/// The resulting value is a UUIDv4 encoded as 32 lowercase hexadecimal
	/// characters with no hyphens.
	pub fn new() -> Self {
		let value = Uuid::new_v4().simple().to_string();

		// Uuid::new_v4() and simple() should guarantee this invariant.
		// Keep the assertion so that changes to construction cannot silently
		// introduce an invalid Epicbox transaction ID.
		assert!(
			is_epicbox_txid(&value),
			"generated invalid Epicbox transaction ID"
		);

		Self(value)
	}

	/// Parse and validate an existing Epicbox transaction ID.
	pub fn parse(value: &str) -> Result<Self, EpicboxTxIdError> {
		if !is_epicbox_txid(value) {
			return Err(EpicboxTxIdError::new(value));
		}

		// Normalize valid IDs to the same lowercase representation produced
		// by `new()`.
		Ok(Self(value.to_ascii_lowercase()))
	}

	/// Return the transaction ID as a string slice.
	pub fn as_str(&self) -> &str {
		debug_assert!(is_epicbox_txid(&self.0));
		&self.0
	}

	/// Return an owned String representation.
	pub fn into_string(self) -> String {
		debug_assert!(is_epicbox_txid(&self.0));
		self.0
	}

	/// Revalidate this transaction ID.
	///
	/// Normally this will always return true because the inner value is
	/// private and every constructor validates it.
	pub fn is_valid(&self) -> bool {
		is_epicbox_txid(&self.0)
	}

	/// Return the underlying UUID.
	pub fn as_uuid(&self) -> Uuid {
		debug_assert!(is_epicbox_txid(&self.0));

		Uuid::parse_str(&self.0)
			.expect("EpicboxTxId invariant violated")
	}
}

impl Default for EpicboxTxId {
	fn default() -> Self {
		Self::new()
	}
}

impl fmt::Display for EpicboxTxId {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		debug_assert!(is_epicbox_txid(&self.0));
		f.write_str(&self.0)
	}
}

impl AsRef<str> for EpicboxTxId {
	fn as_ref(&self) -> &str {
		self.as_str()
	}
}

impl FromStr for EpicboxTxId {
	type Err = EpicboxTxIdError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Self::parse(s)
	}
}

impl TryFrom<&str> for EpicboxTxId {
	type Error = EpicboxTxIdError;

	fn try_from(value: &str) -> Result<Self, Self::Error> {
		Self::parse(value)
	}
}

impl TryFrom<String> for EpicboxTxId {
	type Error = EpicboxTxIdError;

	fn try_from(value: String) -> Result<Self, Self::Error> {
		Self::parse(&value)
	}
}

impl From<EpicboxTxId> for String {
	fn from(value: EpicboxTxId) -> Self {
		value.into_string()
	}
}

impl Serialize for EpicboxTxId {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		if !self.is_valid() {
			return Err(serde::ser::Error::custom(
				"invalid Epicbox transaction ID",
			));
		}

		serializer.serialize_str(self.as_str())
	}
}

impl<'de> Deserialize<'de> for EpicboxTxId {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let value = String::deserialize(deserializer)?;

		Self::parse(&value).map_err(de::Error::custom)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn new_epicbox_txid_is_valid() {
		let txid = EpicboxTxId::new();

		assert_eq!(txid.as_str().len(), EPICBOX_TXID_LEN);
		assert!(is_epicbox_txid(txid.as_str()));
		assert!(txid.is_valid());
	}

	#[test]
	fn new_epicbox_txids_are_unique() {
		let a = EpicboxTxId::new();
		let b = EpicboxTxId::new();

		assert_ne!(a, b);
	}

	#[test]
	fn parses_valid_uuid_v4() {
		let txid =
			EpicboxTxId::parse("550e8400e29b41d4a716446655440000")
				.unwrap();

		assert_eq!(
			txid.as_str(),
			"550e8400e29b41d4a716446655440000"
		);
	}

	#[test]
	fn normalizes_uppercase() {
		let txid =
			EpicboxTxId::parse("550E8400E29B41D4A716446655440000")
				.unwrap();

		assert_eq!(
			txid.as_str(),
			"550e8400e29b41d4a716446655440000"
		);
	}

	#[test]
	fn rejects_wrong_length() {
		assert!(!is_epicbox_txid("1234"));
		assert!(EpicboxTxId::parse("1234").is_err());
	}

	#[test]
	fn rejects_non_hex_characters() {
		assert!(!is_epicbox_txid(
			"550e8400e29b41d4a71644665544000z"
		));
	}

	#[test]
	fn rejects_hyphenated_uuid() {
		assert!(!is_epicbox_txid(
			"550e8400-e29b-41d4-a716-446655440000"
		));
	}

	#[test]
	fn rejects_non_v4_uuid() {
		// Version nibble is 1 instead of 4.
		assert!(!is_epicbox_txid(
			"550e8400e29b11d4a716446655440000"
		));
	}

	#[test]
	fn serde_round_trip() {
		let txid = EpicboxTxId::new();

		let json = serde_json::to_string(&txid).unwrap();
		let decoded: EpicboxTxId =
			serde_json::from_str(&json).unwrap();

		assert_eq!(decoded, txid);
	}

	#[test]
	fn serde_rejects_invalid_value() {
		let result =
			serde_json::from_str::<EpicboxTxId>("\"not-an-epicbox-id\"");

		assert!(result.is_err());
	}
}
