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

//! Error types for libwallet

use crate::epic_core::core::{committed, transaction};

use crate::epic_keychain;
use crate::epic_util::secp;
use std::io;
/// Error definition

/// Wallet errors, mostly wrappers around underlying crypto or I/O errors.
#[derive(Clone, Eq, PartialEq, Debug, thiserror::Error, Serialize, Deserialize)]
pub enum Error {
	/// Not enough funds
	#[error(
		"Not enough funds. Required: {}, Available: {}",
		needed_disp,
		available_disp
	)]
	NotEnoughFunds {
		/// available funds
		available: u64,
		/// Display friendly
		available_disp: String,
		/// Needed funds
		needed: u64,
		/// Display friendly
		needed_disp: String,
	},

	/// Fee error
	#[error("Fee Error: {}", _0)]
	Fee(String),

	/// LibTX Error
	#[error("LibTx Error: {}", _0)]
	LibTX(String),

	/// Keychain error
	#[error("Keychain error")]
	Keychain(epic_keychain::Error),

	/// Transaction Error
	#[error("Transaction error")]
	Transaction(transaction::Error),

	/// API Error
	#[error("Client Callback Error: {}", _0)]
	ClientCallback(String),

	/// Secp Error
	#[error("Secp error")]
	Secp(secp::Error),

	/// Callback implementation error conversion
	#[error("Trait Implementation error")]
	CallbackImpl(&'static str),

	/// Wallet backend error
	#[error("Wallet store error: {}", _0)]
	Backend(String),

	/// Callback implementation error conversion
	#[error("Restore Error")]
	Restore,

	/// An error in the format of the JSON structures exchanged by the wallet
	#[error("JSON format error: {}", _0)]
	Format(String),

	/// Other serialization errors
	#[error("Ser/Deserialization error")]
	Deser(crate::epic_core::ser::Error),

	/// IO Error
	#[error("I/O error")]
	IO,

	/// Error when contacting a node through its API
	#[error("Node API error")]
	Node,

	/// Error contacting wallet API
	#[error("Wallet Communication Error: {}", _0)]
	WalletComms(String),

	/// Error originating from hyper.
	#[error("Hyper error")]
	Hyper,

	/// Error originating from hyper uri parsing.
	#[error("Uri parsing error")]
	Uri,

	/// Signature error
	#[error("Signature error: {}", _0)]
	Signature(String),

	/// OwnerAPIEncryption
	#[error("{}", _0)]
	APIEncryption(String),

	/// Attempt to use duplicate transaction id in separate transactions
	#[error("Duplicate transaction ID error")]
	DuplicateTransactionId,

	/// Wallet seed already exists
	#[error("Wallet seed exists error: {}", _0)]
	WalletSeedExists(String),

	/// Wallet seed doesn't exist
	#[error("Wallet seed doesn't exist error")]
	WalletSeedDoesntExist,

	/// Wallet seed doesn't exist
	#[error("Wallet seed decryption error")]
	WalletSeedDecryption,

	/// Transaction doesn't exist
	#[error("Transaction {} doesn't exist", _0)]
	TransactionDoesntExist(String),

	/// Transaction already rolled back
	#[error("Transaction {} cannot be cancelled", _0)]
	TransactionNotCancellable(String),

	/// Cancellation error
	#[error("Cancellation Error: {}", _0)]
	TransactionCancellationError(&'static str),

	/// Cancellation error
	#[error("Tx dump Error: {}", _0)]
	TransactionDumpError(&'static str),

	/// Attempt to repost a transaction that's already confirmed
	#[error("Transaction already confirmed error")]
	TransactionAlreadyConfirmed,

	/// Transaction has already been received
	#[error("Transaction {} has already been received", _0)]
	TransactionAlreadyReceived(String),

	/// Attempt to repost a transaction that's not completed and stored
	#[error("Transaction building not completed: {}", _0)]
	TransactionBuildingNotCompleted(u32),

	/// Invalid BIP-32 Depth
	#[error("Invalid BIP32 Depth (must be 1 or greater)")]
	InvalidBIP32Depth,

	/// Attempt to add an account that exists
	#[error("Account Label '{}' already exists", _0)]
	AccountLabelAlreadyExists(String),

	/// Reference unknown account label
	#[error("Unknown Account Label '{}'", _0)]
	UnknownAccountLabel(String),

	/// Error from summing commitments via committed trait.
	#[error("Committed Error")]
	Committed(committed::Error),

	/// Can't parse slate version
	#[error("Can't parse slate version")]
	SlateVersionParse,

	/// Can't serialize slate
	#[error("Can't Serialize slate")]
	SlateSer,

	/// Can't deserialize slate
	#[error("Can't Deserialize slate")]
	SlateDeser,

	/// Unknown slate version
	#[error("Unknown Slate Version: {}", _0)]
	SlateVersion(u16),

	/// Compatibility error between incoming slate versions and what's expected
	#[error("Compatibility Error: {}", _0)]
	Compatibility(String),

	/// Keychain doesn't exist (wallet not openend)
	#[error("Keychain doesn't exist (has wallet been opened?)")]
	KeychainDoesntExist,

	/// Lifecycle Error
	#[error("Lifecycle Error: {}", _0)]
	Lifecycle(String),

	/// Invalid Keychain Mask Error
	#[error("Supplied Keychain Mask Token is incorrect")]
	InvalidKeychainMask,

	/// Tor Process error
	#[error("Tor Process Error: {}", _0)]
	TorProcess(String),

	/// Tor Configuration Error
	#[error("Tor Config Error: {}", _0)]
	TorConfig(String),

	/// Generating ED25519 Public Key
	#[error("Error generating ed25519 secret key: {}", _0)]
	ED25519Key(String),

	/// Generating Payment Proof
	#[error("Payment Proof generation error: {}", _0)]
	PaymentProof(String),

	/// Retrieving Payment Proof
	#[error("Payment Proof retrieval error: {}", _0)]
	PaymentProofRetrieval(String),

	/// Retrieving Payment Proof
	#[error("Payment Proof parsing error: {}", _0)]
	PaymentProofParsing(String),

	/// Decoding OnionV3 addresses to payment proof addresses
	#[error("Proof Address decoding: {}", _0)]
	AddressDecoding(String),

	/// Transaction has expired it's TTL
	#[error("Transaction Expired")]
	TransactionExpired,

	#[error("SQLite Error: {}", _0)]
	SQLiteError(String),

	#[error("Invalid base58 character!")]
	InvalidBase58Character(char, usize),
	#[error("Invalid base58 length")]
	InvalidBase58Length,
	#[error("Invalid base58 checksum")]
	InvalidBase58Checksum,
	#[error("Invalid base58 version bytes")]
	InvalidBase58Version,
	#[error("Invalid key")]
	InvalidBase58Key,

	#[error("Could not parse number from string")]
	NumberParsingError,
	#[error("Listener for {} closed", 0)]
	ClosedListener(String),
	#[error("Unable to encrypt message")]
	Encryption,
	#[error("Unable to decrypt message")]
	Decryption,
	#[error("Could not parse '{}' to a epicbox address", 0)]
	EpicboxAddressParsingError(String),

	/// Other
	#[error("Generic error: {}", _0)]
	GenericError(String),

	#[error("Request error: {0}")]
	RequestError(String),

	#[error("Invalid Arguments: {}", _0)]
	ArgumentError(String),
	#[error("Parsing IO error: {}", _0)]
	IOError(String),
	#[error("User Cancelled")]
	CancelledError,

	#[error("Too many unsuccessful attempts at reconnection")]
	EpicboxReconnectLimit,

	/// LibWallet Error
	#[error("LibWallet Error: {:?}", _0)]
	LibWallet(String),

	#[error("NotFoundErr Error: {}", _0)]
	NotFoundErr(String),
}

impl From<io::Error> for Error {
	fn from(_error: io::Error) -> Error {
		Error::IO
	}
}

impl From<epic_keychain::Error> for Error {
	fn from(error: epic_keychain::Error) -> Error {
		Error::Keychain(error)
	}
}

impl From<transaction::Error> for Error {
	fn from(error: transaction::Error) -> Error {
		Error::Transaction(error)
	}
}

impl From<crate::epic_core::ser::Error> for Error {
	fn from(error: crate::epic_core::ser::Error) -> Error {
		Error::Deser(error)
	}
}

impl From<secp::Error> for Error {
	fn from(error: secp::Error) -> Error {
		Error::Secp(error)
	}
}

impl From<sqlite::Error> for Error {
	fn from(error: sqlite::Error) -> Error {
		Error::SQLiteError(format!("{}", error))
	}
}
impl From<crate::epic_core::libtx::Error> for Error {
	fn from(error: crate::epic_core::libtx::Error) -> Error {
		Error::LibTX(format!("{}", error))
	}
}
impl From<committed::Error> for Error {
	fn from(error: committed::Error) -> Error {
		Error::Committed(error)
	}
}
