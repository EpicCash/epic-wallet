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

//! Implementation specific error types

use crate::core::libtx;
use crate::keychain;
use crate::libwallet;
use crate::util::secp;
use thiserror::Error;
/// Wallet errors, mostly wrappers around underlying crypto or I/O errors.
#[derive(Error, Debug, Deserialize)]
pub enum Error {
	/// LibTX Error
	#[error("LibTx Error")]
	LibTX(#[from] libtx::Error),

	/// LibWallet Error
	#[error("LibWallet Error: {0}")]
	#[serde(skip)]
	LibWallet(#[from] libwallet::Error),

	/// Keychain error
	#[error("Keychain error: {0}")]
	Keychain(#[from] keychain::Error),

	/// Error for std::io::Error
	#[error("Std IO error: {0}")]
	#[serde(skip)]
	IO(#[from] std::io::Error),

	/// Secp Error
	#[error("Secp error: {0}")]
	Secp(#[from] secp::Error),

	/// Error when formatting json
	#[error("Serde JSON error: {0}")]
	#[serde(skip)]
	Format(#[from] serde_json::Error),

	/// Wallet seed already exists
	#[error("Wallet seed file exists: {0}")]
	WalletSeedExists(String),

	/// Wallet seed doesn't exist
	#[error("Wallet seed doesn't exist error")]
	WalletSeedDoesntExist,

	/// Wallet seed doesn't exist
	#[error("Wallet doesn't exist at {0}. {1}")]
	WalletDoesntExist(String, String),

	/// Enc/Decryption Error
	#[error("Enc/Decryption error (check password?)")]
	Encryption,

	/// BIP 39 word list
	#[error("BIP39 Mnemonic (word list) Error")]
	Mnemonic,

	/// Command line argument error
	#[error("ArgumentError {0}")]
	ArgumentError(String),

	/// Generating ED25519 Public Key
	#[error("Error generating ed25519 secret key: {0}")]
	ED25519Key(String),

	/// Checking for onion address
	#[error("Address is not an Onion v3 Address: {0}")]
	NotOnion(String),

	/// From sqlite::Error
	#[error("SQLite Error: {0}")]
	#[serde(skip)]
	FromSqlite(#[from] sqlite::Error),

	/// Other
	#[error("Generic error: {0}")]
	GenericError(String),

	#[error("Epicbox Error: {0}")]
	EpicboxTungstenite(String),

	#[error("No listener on: {0}")]
	NoListener(String),

	#[error("Epicbox websocket terminated unexpectedly")]
	EpicboxWebsocketAbnormalTermination,

	#[error("Epicbox ReceiveTx: {0}")]
	EpicboxReceiveTx(String),
}

impl From<Error> for crate::libwallet::Error {
	fn from(error: Error) -> crate::libwallet::Error {
		crate::libwallet::Error::LibWallet(format!("{error}"))
	}
}
