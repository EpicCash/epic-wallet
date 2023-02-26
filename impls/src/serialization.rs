// Copyright 2023 The Epic Developers
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

//! Responsible for handling the serialization and deserialization of structs common to the database

use epic_wallet_libwallet::{
	AcctPathMapping, Context, OutputData, ScannedBlockInfo, TxLogEntry, WalletInitStatus,
};
use serde::Serialize;
use serde_json::Result;

/// Stores all the structs with data that needs to be stored on the database
/// This enum implements traits used on serde_json
#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum Serializable {
	TxLogEntry(TxLogEntry),
	AcctPathMapping(AcctPathMapping),
	OutputData(OutputData),
	ScannedBlockInfo(ScannedBlockInfo),
	WalletInitStatus(WalletInitStatus),
	Context(Context),
	Numeric(u64),
}

/// Serializes a any data that implements Serialize into a JSON string
pub fn serialize(data: impl Serialize) -> Result<String> {
	let serialized_data: String = serde_json::to_string(&data)?;
	return Ok(serialized_data);
}

/// Serializes a a JSON string into the Serializable enum
pub fn deserialize(data: &str) -> Result<Serializable> {
	let deserialized = serde_json::from_str(data)?;
	return Ok(deserialized);
}

/// Implementation for Serializable, responsible for the conversion into a specific struct
impl Serializable {
	/// Converts a Serializable into a TxLogEntry
	pub fn as_txlogentry(self) -> Option<TxLogEntry> {
		match self {
			Serializable::TxLogEntry(txle) => Some(txle),
			_ => None,
		}
	}

	/// Converts a Serializable into a AcctPathMapping
	pub fn as_acct_path_mapping(self) -> Option<AcctPathMapping> {
		match self {
			Serializable::AcctPathMapping(acct) => Some(acct),
			_ => None,
		}
	}

	/// Converts a Serializable into a OutputData
	pub fn as_output_data(self) -> Option<OutputData> {
		match self {
			Serializable::OutputData(out) => Some(out),
			_ => None,
		}
	}

	/// Converts a Serializable into a Context
	pub fn as_context(self) -> Option<Context> {
		match self {
			Serializable::Context(context) => Some(context),
			_ => None,
		}
	}
}
