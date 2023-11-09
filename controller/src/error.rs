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
use crate::api;
use crate::core::core::transaction;
use crate::core::libtx;
use crate::impls;
use crate::keychain;
use crate::libwallet;

use epic_wallet_libwallet::Error::LibWallet;

/// Wallet errors, mostly wrappers around underlying crypto or I/O errors.
#[derive(Clone, Eq, PartialEq, Debug, thiserror::Error)]
pub enum Error {
	/// LibTX Error
	#[error("LibTx Error")]
	LibTX(libtx::ErrorKind),

	/// Impls error
	#[error("Impls Error")]
	Impls(impls::Error),

	/// LibWallet Error
	#[error("LibWallet Error: {}", _1)]
	LibWallet(libwallet::Error, String),

	/// Keychain error
	#[error("Keychain error")]
	Keychain(keychain::Error),

	/// Transaction Error
	#[error("Transaction error")]
	Transaction(transaction::Error),

	/// Secp Error
	#[error("Secp error")]
	Secp,

	/// Filewallet error
	#[error("Wallet data error: {}", _0)]
	FileWallet(&'static str),

	/// Error when formatting json
	#[error("IO error")]
	IO,

	/// Error when formatting json
	#[error("Serde JSON error")]
	Format,

	/// Error when contacting a node through its API
	#[error("Node API error")]
	Node(api::Error),

	/// Error originating from hyper.
	#[error("Hyper error")]
	Hyper,

	/// Error originating from hyper uri parsing.
	#[error("Uri parsing error")]
	Uri,

	/// Attempt to use duplicate transaction id in separate transactions
	#[error("Duplicate transaction ID error")]
	DuplicateTransactionId,

	/// Wallet seed already exists
	#[error("Wallet seed file exists: {}", _0)]
	WalletSeedExists(String),

	/// Wallet seed doesn't exist
	#[error("Wallet seed doesn't exist error")]
	WalletSeedDoesntExist,

	/// Enc/Decryption Error
	#[error("Enc/Decryption error (check password?)")]
	Encryption,

	/// BIP 39 word list
	#[error("BIP39 Mnemonic (word list) Error")]
	Mnemonic,

	/// Command line argument error
	#[error("{}", _0)]
	ArgumentError(String),

	/// Other
	#[error("Generic error: {}", _0)]
	GenericError(String),

	#[error("Too many unsuccessful attempts at reconnection")]
	EpicboxReconnectLimit,
}

impl From<Error> for epic_wallet_libwallet::Error {
	fn from(error: Error) -> epic_wallet_libwallet::Error {
		LibWallet(error.to_string())
	}
}
