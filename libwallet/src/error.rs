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

use thiserror::Error;
/// Error definition

/// Wallet errors, mostly wrappers around underlying crypto or I/O errors.
#[derive(Error, Debug, Deserialize, Serialize)]
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

	/// Error from epic_wallet_impls
	#[error("Impls Error: {0}")]
	FromImpls(String),

	/// Fee error
	#[error("Fee Error: {0}")]
	Fee(String),

	/// LibTX Error
	#[error("LibTx Error: {0}")]
	LibTX(#[from] crate::epic_core::libtx::Error),

	/// LibTX Reward Error
	#[error("LibTx Reward Error: {0}")]
	#[serde(skip)]
	LibTXReward(#[from] crate::epic_core::libtx::reward::Error),

	/// Keychain error
	#[error("Keychain error")]
	Keychain(#[from] epic_keychain::Error),

	/// Transaction Error
	#[error("Transaction error")]
	Transaction(#[from] transaction::Error),

	/// API Error
	#[error("Client Callback Error: {0}")]
	ClientCallback(String),

	/// Secp Error
	#[error("Secp error")]
	Secp(#[from] secp::Error),

	/// Callback implementation error conversion
	#[error("Trait Implementation error")]
	CallbackImpl(&'static str),

	/// Wallet backend error
	#[error("Wallet store error: {0}")]
	Backend(String),

	/// Callback implementation error conversion
	#[error("Restore Error")]
	Restore,

	/// Error when formatting json
	#[error("Serde JSON error: {0}")]
	#[serde(skip)]
	Format(#[from] serde_json::Error),

	/// Other serialization errors
	#[error("Ser/Deserialization error")]
	Deser(#[from] crate::epic_core::ser::Error),

	/// Error for std::io::Error
	#[error("Std IO error: {0}")]
	#[serde(skip)]
	StdIO(#[from] std::io::Error),

	/// Error when contacting a node through its API
	#[error("Node API error")]
	Node,

	/// Error when the node is not in the expected sync status
	#[error("Node status error: {0}")]
	NodeStatus(String),

	/// Error contacting wallet API
	#[error("Wallet Communication Error: {0}")]
	WalletComms(String),

	/// Error originating from hyper.
	#[error("Hyper error")]
	Hyper,

	/// Error originating from hyper uri parsing.
	#[error("Uri parsing error")]
	Uri,

	/// Signature error
	#[error("Signature error: {0}")]
	Signature(String),

	/// OwnerAPIEncryption
	#[error("{0}")]
	APIEncryption(String),

	/// Attempt to use duplicate transaction id in separate transactions
	#[error("Duplicate transaction ID error")]
	DuplicateTransactionId,

	/// Wallet seed already exists
	#[error("Wallet seed exists error: {0}")]
	WalletSeedExists(String),

	/// Wallet seed doesn't exist
	#[error("Wallet seed doesn't exist error")]
	WalletSeedDoesntExist,

	/// Wallet seed doesn't exist
	#[error("Wallet seed decryption error")]
	WalletSeedDecryption,

	/// Transaction doesn't exist
	#[error("Transaction {0} doesn't exist")]
	TransactionDoesntExist(String),

	/// Transaction already rolled back
	#[error("Transaction {0} cannot be cancelled")]
	TransactionNotCancellable(String),

	/// Cancellation error
	#[error("Cancellation Error: {0}")]
	TransactionCancellationError(&'static str),

	/// Cancellation error
	#[error("Tx dump Error: {0}")]
	TransactionDumpError(&'static str),

	/// Attempt to repost a transaction that's already confirmed
	#[error("Transaction already confirmed error")]
	TransactionAlreadyConfirmed,

	/// Transaction has already been received
	#[error("Transaction {0} has already been received")]
	TransactionAlreadyReceived(String),

	/// Attempt to repost a transaction that's not completed and stored
	#[error("Transaction building not completed: {0}")]
	TransactionBuildingNotCompleted(u32),

	/// Invalid BIP-32 Depth
	#[error("Invalid BIP32 Depth (must be 1 or greater)")]
	InvalidBIP32Depth,

	/// Attempt to add an account that exists
	#[error("Account Label '{0}' already exists")]
	AccountLabelAlreadyExists(String),

	/// Reference unknown account label
	#[error("Unknown Account Label '{0}'")]
	UnknownAccountLabel(String),

	/// Error from summing commitments via committed trait.
	#[error("Committed Error")]
	Committed(#[from] committed::Error),

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
	#[error("Unknown Slate Version: {0}")]
	SlateVersion(u16),

	/// Compatibility error between incoming slate versions and what's expected
	#[error("Compatibility Error: {0}")]
	Compatibility(String),

	/// Keychain doesn't exist (wallet not openend)
	#[error("Keychain doesn't exist (has wallet been opened?)")]
	KeychainDoesntExist,

	/// Lifecycle Error
	#[error("Lifecycle Error: {0}")]
	Lifecycle(String),

	/// Invalid Keychain Mask Error
	#[error("Supplied Keychain Mask Token is incorrect")]
	InvalidKeychainMask,

	/// Tor Process error
	#[error("Tor Process Error: {0}")]
	TorProcess(String),

	/// Tor Configuration Error
	#[error("Tor Config Error: {0}")]
	TorConfig(String),

	/// Generating ED25519 Public Key
	#[error("Error generating ed25519 secret key: {0}")]
	ED25519Key(String),

	/// Generating Payment Proof
	#[error("Payment Proof generation error: {0}")]
	PaymentProof(String),

	/// Retrieving Payment Proof
	#[error("Payment Proof retrieval error: {0}")]
	PaymentProofRetrieval(String),

	/// Retrieving Payment Proof
	#[error("Payment Proof parsing error: {0}")]
	PaymentProofParsing(String),

	/// Decoding OnionV3 addresses to payment proof addresses
	#[error("Proof Address decoding: {0}")]
	AddressDecoding(String),

	/// Transaction has expired it's TTL
	#[error("Transaction Expired")]
	TransactionExpired,

	/// From sqlite::Error
	#[error("SQLite Error: {0}")]
	#[serde(skip)]
	FromSqlite(#[from] sqlite::Error),

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

	#[error("Listener for {0} closed")]
	ClosedListener(String),

	#[error("Unable to encrypt message")]
	Encryption,

	#[error("Unable to decrypt message")]
	Decryption,

	#[error("Could not parse '{0}' to a epicbox address")]
	EpicboxAddressParsingError(String),

	/// Other
	#[error("Generic error: {0}")]
	GenericError(String),

	#[error("Request error: {0}")]
	RequestError(String),

	#[error("Invalid Arguments: {0}")]
	ArgumentError(String),

	#[error("Parsing IO error: {0}")]
	IOError(String),

	#[error("User Cancelled")]
	CancelledError,

	#[error("Too many unsuccessful attempts at reconnection")]
	EpicboxReconnectLimit,

	/// LibWallet Error
	#[error("LibWallet Error: {0}")]
	LibWallet(String),

	#[error("NotFoundErr Error: {0}")]
	NotFoundErr(String),
}
