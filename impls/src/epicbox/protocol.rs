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
use std::fmt::{Display, Formatter, Result};

#[derive(Serialize, Deserialize, Debug)]
pub enum ProtocolError {
	UnknownError,
	InvalidRequest,
	InvalidSignature,
	InvalidChallenge,
	TooManySubscriptions,
}

impl Display for ProtocolError {
	fn fmt(&self, f: &mut Formatter) -> Result {
		match *self {
			ProtocolError::UnknownError => write!(f, "{}", "unknown error!"),
			ProtocolError::InvalidRequest => write!(f, "{}", "invalid request!"),
			ProtocolError::InvalidSignature => write!(f, "{}", "invalid signature!"),
			ProtocolError::InvalidChallenge => write!(f, "{}", "invalid challenge!"),
			ProtocolError::TooManySubscriptions => write!(f, "{}", "too many subscriptions!"),
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
	},
	Unsubscribe {
		address: String,
	},
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum ProtocolRequestV2 {
	Challenge,
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
}

impl Display for ProtocolRequest {
	fn fmt(&self, f: &mut Formatter) -> Result {
		match *self {
			ProtocolRequest::Challenge => write!(f, "{}", "Challenge"),
			ProtocolRequest::Subscribe {
				ref address,
				signature: _,
			} => write!(f, "{} to {}", "Subscribe", address),
			ProtocolRequest::Unsubscribe { ref address } => {
				write!(f, "{} from {}", "Unsubscribe", address)
			}
			ProtocolRequest::PostSlate {
				ref from,
				ref to,
				str: _,
				signature: _,
			} => write!(f, "{} from {} to {}", "PostSlate", from, to),
		}
	}
}

impl Display for ProtocolRequestV2 {
	fn fmt(&self, f: &mut Formatter) -> Result {
		match *self {
			ProtocolRequestV2::Challenge => write!(f, "{}", "Challenge"),
			ProtocolRequestV2::Subscribe {
				ref address,
				signature: _,
				ver: _,
			} => write!(f, "{} to {}", "Subscribe", address),
			ProtocolRequestV2::Unsubscribe { ref address } => {
				write!(f, "{} from {}", "Unsubscribe", address)
			}
			ProtocolRequestV2::PostSlate {
				ref from,
				ref to,
				str: _,
				signature: _,
			} => write!(f, "{} from {} to {}", "PostSlate", from, to),
			ProtocolRequestV2::Made {
				ref epicboxmsgid,
				address: _,
				signature: _,
				ver: _,
			} => write!(f, "{} to {}", "Made for", epicboxmsgid),
			ProtocolRequestV2::ClientDetails {
				ref wallet_version,
				ref wallet_mode,
				ref protocol_version,
			} => write!(
				f,
				"Wallet Version {}, Wallet Mode {}, Protocol Version {}",
				wallet_version, wallet_mode, protocol_version
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
		ver: String,
		epicboxmsgid: String,
	},
	GetVersion {
		str: String,
	},
}

impl Display for ProtocolResponse {
	fn fmt(&self, f: &mut Formatter) -> Result {
		match *self {
			ProtocolResponse::Ok => write!(f, "{}", "Ok"),
			ProtocolResponse::Error {
				ref kind,
				description: _,
			} => write!(f, "{}: {}", "error", kind),
			ProtocolResponse::Challenge { ref str } => {
				write!(f, "{} {}", "Challenge", str)
			}
			ProtocolResponse::Slate {
				ref from,
				str: _,
				signature: _,
				challenge: _,
			} => write!(f, "{} from {}", "Slate", from),
		}
	}
}

impl Display for ProtocolResponseV2 {
	fn fmt(&self, f: &mut Formatter) -> Result {
		match *self {
			ProtocolResponseV2::Ok => write!(f, "{}", "Ok"),
			ProtocolResponseV2::Error {
				ref kind,
				description: _,
			} => write!(f, "{}: {}", "error", kind),
			ProtocolResponseV2::Challenge { ref str } => {
				write!(f, "{} {}", "Challenge", str)
			}
			ProtocolResponseV2::GetVersion { ref str } => {
				write!(f, "{} {}", "Version", str)
			}

			ProtocolResponseV2::Slate {
				ref from,
				str: _,
				signature: _,
				challenge: _,
				ver: _,
				ref epicboxmsgid,
			} => write!(
				f,
				"{} from {} with epicboxmsgid {}",
				"Slate", from, epicboxmsgid
			),
		}
	}
}
