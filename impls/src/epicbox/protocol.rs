// Copyright 2026 The Epic Developers
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

use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter, Result as FmtResult};

#[derive(Serialize, Deserialize, Debug)]
pub enum ProtocolError {
	UnknownError,
	InvalidRequest,
	InvalidSignature,
	InvalidChallenge,
	TooManySubscriptions,
}

impl Display for ProtocolError {
	fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
		match self {
			ProtocolError::UnknownError => write!(f, "unknown error!"),
			ProtocolError::InvalidRequest => write!(f, "invalid request!"),
			ProtocolError::InvalidSignature => write!(f, "invalid signature!"),
			ProtocolError::InvalidChallenge => write!(f, "invalid challenge!"),
			ProtocolError::TooManySubscriptions => write!(f, "too many subscriptions!"),
		}
	}
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum ProtocolRequest {
	Challenge,

	Subscribe {
		address: String,
		signature: String,
	},

	PostSlate {
		from: String,
		to: String,
		str: String,
		signature: String,

		/// stable tx-wide identifier used by epicbox protocol 3.1.0+
		/// omitted for legacy relays
		#[serde(default, skip_serializing_if = "Option::is_none")]
		epicboxtxid: Option<String>,

		/// signature by the posting wallet over epicboxtxid.
		/// only present if epicboxtxid is
		#[serde(default, skip_serializing_if = "Option::is_none")]
		epicboxtxidsig: Option<String>,
	},

	Unsubscribe {
		address: String,
	},
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum ProtocolRequestV2 {
	Challenge,

	/// Supported by 3.0.0+ relays, client uses to select legacy vs 3.1.0+ mechanics
	GetVersion,

	Subscribe {
		address: String,
		ver: String,
		signature: String,
	},

	PostSlate {
		from: String,
		to: String,
		str: String,
		signature: String,

		#[serde(default, skip_serializing_if = "Option::is_none")]
		epicboxtxid: Option<String>,

		#[serde(default, skip_serializing_if = "Option::is_none")]
		epicboxtxidsig: Option<String>,
	},

	Unsubscribe {
		address: String,
	},

	Made {
		address: String,
		signature: String,
		ver: String,
		epicboxmsgid: String,
	},

	ClientDetails {
		wallet_version: String,
		wallet_mode: String,
		protocol_version: String,
	},

	CancelTx {
		address: String,
		epicboxtxid: String,
		signature: String,
	},
}

impl Display for ProtocolRequest {
	fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
		match self {
			ProtocolRequest::Challenge => write!(f, "Challenge"),
			ProtocolRequest::Subscribe { address, .. } => write!(f, "Subscribe to {}", address),
			ProtocolRequest::PostSlate {
				from,
				to,
				epicboxtxid,
				..
			} => match epicboxtxid {
				Some(txid) => write!(
					f,
					"PostSlate from {} to {} for epicboxtxid {}",
					from, to, txid
				),
				None => write!(f, "PostSlate from {} to {}", from, to),
			},
			ProtocolRequest::Unsubscribe { address } => write!(f, "Unsubscribe from {}", address),
		}
	}
}

impl Display for ProtocolRequestV2 {
	fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
		match self {
			ProtocolRequestV2::Challenge => write!(f, "Challenge"),
			ProtocolRequestV2::GetVersion => write!(f, "GetVersion"),
			ProtocolRequestV2::Subscribe { address, .. } => write!(f, "Subscribe to {}", address),
			ProtocolRequestV2::PostSlate {
				from,
				to,
				epicboxtxid,
				..
			} => match epicboxtxid {
				Some(txid) => write!(
					f,
					"PostSlate from {} to {} for epicboxtxid {}",
					from, to, txid
				),
				None => write!(f, "PostSlate from {} to {}", from, to),
			},
			ProtocolRequestV2::Unsubscribe { address } => write!(f, "Unsubscribe from {}", address),
			ProtocolRequestV2::Made { epicboxmsgid, .. } => {
				write!(f, "Made for epicboxmsgid {}", epicboxmsgid)
			}
			ProtocolRequestV2::ClientDetails {
				wallet_version,
				wallet_mode,
				protocol_version,
			} => write!(
				f,
				"Wallet Version {}, Wallet Mode {}, Protocol Version {}",
				wallet_version, wallet_mode, protocol_version
			),
			ProtocolRequestV2::CancelTx {
				address,
				epicboxtxid,
				..
			} => write!(
				f,
				"CancelTx for epicboxtxid {} as {}",
				epicboxtxid, address
			),
		}
	}
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum ProtocolResponse {
	Ok,
	Error {
		kind: ProtocolError,
		description: String,
	},
	Challenge {
		str: String,
	},
	Slate {
		from: String,
		str: String,
		signature: String,
		challenge: String,
	},
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum ProtocolResponseV2 {
	Ok {
		#[serde(default, skip_serializing_if = "Option::is_none")]
		epicboxmsgid: Option<String>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		epicboxtxid: Option<String>,
	},

	Error {
		kind: ProtocolError,
		description: String,
	},

	Challenge {
		str: String,
	},

	Slate {
		from: String,
		str: String,
		challenge: String,
		signature: String,

		/// Protocol version selected by the relay for this Slate delivery.
		///
		/// Legacy 3.0.0 relays treat an unknown Subscribe version (including 3.1.0)
		/// as 3.0.0 and return `ver: "3.0.0"` in the Slate. Use this value when
		/// constructing Made so the acknowledgement remains compatible with the
		/// relay's selected protocol behavior.
		#[serde(default, skip_serializing_if = "Option::is_none")]
		ver: Option<String>,

		/// Stable transaction identifier. Legacy records/relays may omit it.
		#[serde(default, skip_serializing_if = "Option::is_none")]
		epicboxmsgid: Option<String>,

		#[serde(default, skip_serializing_if = "Option::is_none")]
		epicboxtxid: Option<String>,
	},

	GetVersion {
		str: String,
	},

	TransactionCancelled {
		epicboxtxid: String,
	},
}

impl Display for ProtocolResponse {
	fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
		match self {
			ProtocolResponse::Ok => write!(f, "Ok"),
			ProtocolResponse::Error { kind, .. } => write!(f, "error: {}", kind),
			ProtocolResponse::Challenge { str } => write!(f, "Challenge {}", str),
			ProtocolResponse::Slate { from, .. } => write!(f, "Slate from {}", from),
		}
	}
}

impl Display for ProtocolResponseV2 {
	fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
		match self {
			ProtocolResponseV2::Ok {
				epicboxmsgid,
				epicboxtxid,
			} => match (epicboxmsgid, epicboxtxid) {
				(Some(msgid), Some(txid)) => write!(
					f,
					"Ok (epicboxmsgid {}, epicboxtxid {})",
					msgid, txid
				),
				(Some(msgid), None) => write!(f, "Ok (epicboxmsgid {})", msgid),
				(None, Some(txid)) => write!(f, "Ok (epicboxtxid {})", txid),
				(None, None) => write!(f, "Ok"),
			},
			ProtocolResponseV2::Error { kind, .. } => write!(f, "error: {}", kind),
			ProtocolResponseV2::Challenge { str } => write!(f, "Challenge {}", str),
			ProtocolResponseV2::GetVersion { str } => write!(f, "Version {}", str),
			ProtocolResponseV2::TransactionCancelled { epicboxtxid } => {
				write!(f, "transaction {} cancelled on relay", epicboxtxid)
			}
			ProtocolResponseV2::Slate {
				from,
//				_epicboxmsgid,
				epicboxtxid,
				..
			} => match epicboxtxid {
				Some(txid) => write!(
					f,
					"Slate from {} for epicboxtxid {}",
					from, txid
				),
				None => write!(f, "Slate from {}", from),
			},
		}
	}
}
