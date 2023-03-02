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

use crate::base58::{FromBase58, ToBase58};
use crate::epic_core::global::is_floonet;
use crate::epic_util::secp::key::PublicKey;
use crate::epic_util::secp::Secp256k1;
use crate::error::{Error, ErrorKind};
use regex::Regex;
use std::fmt::{self, Debug, Display};
const EPICBOX_ADDRESS_VERSION_MAINNET: [u8; 2] = [1, 0];
const EPICBOX_ADDRESS_VERSION_TESTNET: [u8; 2] = [1, 136];

const EPICBOX_ADDRESS_REGEX: &str = r"^(epicbox://)?(?P<public_key>[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{52})(@(?P<domain>[a-zA-Z0-9\.]+)(:(?P<port>[0-9]*))?)?$";
const DEFAULT_EPICBOX_DOMAIN: &str = "epicbox.epic.tech";
pub const DEFAULT_EPICBOX_PORT_80: u16 = 80;
pub const DEFAULT_EPICBOX_PORT_443: u16 = 443;

pub fn version_bytes() -> Vec<u8> {
	if is_floonet() {
		EPICBOX_ADDRESS_VERSION_TESTNET.to_vec()
	} else {
		EPICBOX_ADDRESS_VERSION_MAINNET.to_vec()
	}
}
#[derive(PartialEq)]
pub enum AddressType {
	Epicbox,
}
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct EpicboxAddress {
	pub public_key: String,
	pub domain: String,
	pub port: Option<u16>,
}

pub trait Address: Debug + Display {
	fn from_str(s: &str) -> Result<Self, Error>
	where
		Self: Sized;
	fn address_type(&self) -> AddressType;
	fn stripped(&self) -> String;
}

impl EpicboxAddress {
	pub fn new(public_key: PublicKey, domain: Option<String>, port: Option<u16>) -> Self {
		Self {
			public_key: public_key.to_base58_check(version_bytes()),
			domain: domain.unwrap_or(DEFAULT_EPICBOX_DOMAIN.to_string()),
			port,
		}
	}

	pub fn public_key(&self) -> Result<PublicKey, Error> {
		PublicKey::from_base58_check(&self.public_key, version_bytes())
	}
}

impl Address for EpicboxAddress {
	fn from_str(s: &str) -> Result<Self, Error> {
		let re = Regex::new(EPICBOX_ADDRESS_REGEX).unwrap();

		let captures = re.captures(s);
		if captures.is_none() {
			Err(ErrorKind::EpicboxAddressParsingError(s.to_string()))?;
		}

		let captures = captures.unwrap();
		let public_key = captures.name("public_key").unwrap().as_str().to_string();
		let domain = captures.name("domain").map(|m| m.as_str().to_string());
		let port = captures
			.name("port")
			.map(|m| u16::from_str_radix(m.as_str(), 10).unwrap());

		let public_key = PublicKey::from_base58_check(&public_key, version_bytes())?;

		Ok(EpicboxAddress::new(public_key, domain, port))
	}

	fn address_type(&self) -> AddressType {
		AddressType::Epicbox
	}

	fn stripped(&self) -> String {
		format!("{}", self)
	}
}

impl Display for EpicboxAddress {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}", self.public_key)?;
		if self.domain != DEFAULT_EPICBOX_DOMAIN
			|| (self.port.is_some() && self.port.unwrap() != DEFAULT_EPICBOX_PORT_443)
		{
			write!(f, "@{}", self.domain)?;
			if self.port.is_some() && self.port.unwrap() != DEFAULT_EPICBOX_PORT_443 {
				write!(f, ":{}", self.port.unwrap())?;
			}
		}
		Ok(())
	}
}

pub trait Base58<T> {
	fn from_base58(str: &str) -> Result<T, Error>;
	fn to_base58(&self) -> String;

	fn from_base58_check(str: &str, version_bytes: Vec<u8>) -> Result<T, Error>;
	fn to_base58_check(&self, version: Vec<u8>) -> String;
}
impl Base58<PublicKey> for PublicKey {
	fn from_base58(str: &str) -> Result<PublicKey, Error> {
		let secp = Secp256k1::new();
		let str = str::from_base58(str)?;
		PublicKey::from_slice(&secp, &str).map_err(|_| ErrorKind::InvalidBase58Key.into())
	}

	fn to_base58(&self) -> String {
		serialize_public_key(self).to_base58()
	}

	fn from_base58_check(str: &str, version_expect: Vec<u8>) -> Result<PublicKey, Error> {
		let secp = Secp256k1::new();
		let n_version = version_expect.len();
		let (version_actual, key_bytes) = str::from_base58_check(str, n_version)?;
		if version_actual != version_expect {
			return Err(ErrorKind::InvalidBase58Version.into());
		}
		PublicKey::from_slice(&secp, &key_bytes).map_err(|_| ErrorKind::InvalidBase58Key.into())
	}

	fn to_base58_check(&self, version: Vec<u8>) -> String {
		serialize_public_key(self).to_base58_check(version)
	}
}

fn serialize_public_key(public_key: &PublicKey) -> Vec<u8> {
	let secp = Secp256k1::new();
	let ser = public_key.serialize_vec(&secp, true);
	ser[..].to_vec()
}
