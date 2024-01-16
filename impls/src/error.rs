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

/// Wallet errors, mostly wrappers around underlying crypto or I/O errors.
#[derive(Clone, thiserror::Error, Eq, PartialEq, Debug)]
pub enum Error {
	/// LibTX Error
	#[error("LibTx Error")]
	LibTX(libtx::ErrorKind),

	/// LibWallet Error
	#[error("LibWallet Error")]
	LibWallet(libwallet::Error),

	/// Keychain error
	#[error("Keychain error")]
	Keychain(keychain::Error),

	/// Error when formatting json
	#[error("IO error")]
	IO,

	/// Secp Error
	#[error("Secp error")]
	Secp(secp::Error),

	/// Error when formatting json
	#[error("Serde JSON error")]
	Format,

	/// Wallet seed already exists
	#[error("Wallet seed file exists: {}", _0)]
	WalletSeedExists(String),

	/// Wallet seed doesn't exist
	#[error("Wallet seed doesn't exist error")]
	WalletSeedDoesntExist,

	/// Wallet seed doesn't exist
	#[error("Wallet doesn't exist at {}. {}", _0, _1)]
	WalletDoesntExist(String, String),

	/// Enc/Decryption Error
	#[error("Enc/Decryption error (check password?)")]
	Encryption,

	/// BIP 39 word list
	#[error("BIP39 Mnemonic (word list) Error")]
	Mnemonic,

	/// Command line argument error
	#[error("{}", _0)]
	ArgumentError(String),

	/// Generating ED25519 Public Key
	#[error("Error generating ed25519 secret key: {}", _0)]
	ED25519Key(String),

	/// Checking for onion address
	#[error("Address is not an Onion v3 Address: {}", _0)]
	NotOnion(String),

	/// SQLite Errors
	#[error("SQLite Error")]
	SQLiteError(String),

	/// Other
	#[error("Generic error: {}", _0)]
	GenericError(String),

	#[error("Epicbox Error {}", _0)]
	EpicboxTungstenite(String),

	#[error("No listener on {}", 0)]
	NoListener(String),

	#[error("Epicbox websocket terminated unexpectedly")]
	EpicboxWebsocketAbnormalTermination,

	#[error("Epicbox ReceiveTx {}", _0)]
	EpicboxReceiveTx(String),
}

impl From<libwallet::Error> for Error {
	fn from(error: libwallet::Error) -> Error {
		Error::LibWallet(error)
	}
}

impl From<sqlite::Error> for Error {
	fn from(error: sqlite::Error) -> Error {
		Error::SQLiteError(error.to_string())
	}
}

impl From<Error> for epic_wallet_libwallet::Error {
	fn from(error: Error) -> epic_wallet_libwallet::Error {
		epic_wallet_libwallet::Error::LibWallet(error.to_string())
	}
}

impl From<epic_wallet_util::epic_keychain::Error> for Error {
	fn from(error: epic_wallet_util::epic_keychain::Error) -> Error {
		Error::Keychain(error)
	}
}
