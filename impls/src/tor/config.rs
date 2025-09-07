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

//! Tor Configuration + Onion (Hidden) Service operations
use crate::util::secp::key::SecretKey;
use crate::Error;
use epic_wallet_libwallet::address;

use ed25519_dalek::SigningKey as DalekSecretKey;
use ed25519_dalek::VerifyingKey as DalekPublicKey;

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, MAIN_SEPARATOR};

const SEC_KEY_FILE: &'static str = "hs_ed25519_secret_key";
const PUB_KEY_FILE: &'static str = "hs_ed25519_public_key";
const HOSTNAME_FILE: &'static str = "hostname";
const TORRC_FILE: &'static str = "torrc";
const TOR_DATA_DIR: &'static str = "data";
const AUTH_CLIENTS_DIR: &'static str = "authorized_clients";
const HIDDEN_SERVICES_DIR: &'static str = "onion_service_addresses";

#[cfg(unix)]
fn set_permissions(file_path: &str) -> Result<(), Error> {
	use std::os::unix::prelude::*;
	fs::set_permissions(file_path, fs::Permissions::from_mode(0o700))?;
	Ok(())
}

#[cfg(windows)]
fn set_permissions(_file_path: &str) -> Result<(), Error> {
	Ok(())
}

struct TorRcConfigItem {
	pub name: String,
	pub value: String,
}

impl TorRcConfigItem {
	/// Create new
	pub fn new(name: &str, value: &str) -> Self {
		Self {
			name: name.into(),
			value: value.into(),
		}
	}
}

struct TorRcConfig {
	pub items: Vec<TorRcConfigItem>,
}

impl TorRcConfig {
	/// Create new
	pub fn new() -> Self {
		Self { items: vec![] }
	}

	/// add item
	pub fn add_item(&mut self, name: &str, value: &str) {
		self.items.push(TorRcConfigItem::new(name, value));
	}

	/// write to file
	pub fn write_to_file(&self, file_path: &str) -> Result<(), Error> {
		let mut file = File::create(file_path)?;
		for item in &self.items {
			file.write_all(item.name.as_bytes())?;
			file.write_all(b" ")?;
			file.write_all(item.value.as_bytes())?;
			file.write_all(b"\n")?;
		}
		Ok(())
	}
}

/// helper to get address
pub fn onion_address_from_seckey(sec_key: &SecretKey) -> Result<String, Error> {
	let (_, d_pub_key) = address::ed25519_keypair(sec_key)?;
	Ok(address::onion_v3_from_pubkey(&d_pub_key)?)
}

pub fn create_onion_service_sec_key_file(
	os_directory: &str,
	d_sec_key: &DalekSecretKey,
	d_pub_key: &DalekPublicKey,
) -> Result<(), Error> {
	let key_file_path = format!("{}{}{}", os_directory, MAIN_SEPARATOR, SEC_KEY_FILE);
	let mut file = File::create(&key_file_path)?;

	// Tag is always 32 bytes, so pad with null zeroes
	file.write(b"== ed25519v1-secret: type0 ==\0\0\0")?;

	// Write the full 64-byte keypair (32-byte seed + 32-byte public key)
	// This matches what Tor expects and generates itself
	file.write_all(&d_sec_key.to_bytes())?; // 32-byte seed
	file.write_all(&d_pub_key.to_bytes())?; // 32-byte public key

	// Explicitly flush and sync to ensure the file is written to disk
	file.flush()?;
	file.sync_all()?;

	// Set file permissions to 0600 (owner read/write only)
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(&key_file_path, std::fs::Permissions::from_mode(0o600))?;
	}
	Ok(())
}

pub fn create_onion_service_pub_key_file(
	os_directory: &str,
	pub_key: &DalekPublicKey,
) -> Result<(), Error> {
	let key_file_path = format!("{}{}{}", os_directory, MAIN_SEPARATOR, PUB_KEY_FILE);
	let mut file = File::create(&key_file_path)?;
	// Tag is always 32 bytes, so pad with null zeroes
	file.write(b"== ed25519v1-public: type0 ==\0\0\0")?;
	file.write_all(&pub_key.to_bytes())?;

	// Explicitly flush and sync to ensure the file is written to disk
	file.flush()?;
	file.sync_all()?;

	// Set file permissions to 0600 (owner read/write only)
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(key_file_path, std::fs::Permissions::from_mode(0o600))?;
	}
	Ok(())
}

pub fn create_onion_service_hostname_file(os_directory: &str, hostname: &str) -> Result<(), Error> {
	let file_path = format!("{}{}{}", os_directory, MAIN_SEPARATOR, HOSTNAME_FILE);
	let mut file = File::create(&file_path)?;
	file.write_all(&format!("{}.onion\n", hostname).as_bytes())?;

	// Explicitly flush and sync to ensure the file is written to disk
	file.flush()?;
	file.sync_all()?;

	// Set file permissions to 0600 (owner read/write only)
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(file_path, std::fs::Permissions::from_mode(0o600))?;
	}
	Ok(())
}

pub fn create_onion_auth_clients_dir(os_directory: &str) -> Result<(), Error> {
	let auth_dir_path = &format!("{}{}{}", os_directory, MAIN_SEPARATOR, AUTH_CLIENTS_DIR);
	fs::create_dir_all(auth_dir_path)?;
	set_permissions(&auth_dir_path)?;

	Ok(())
}
/// output an onion service config for the secret key, and return the address
pub fn output_onion_service_config(
	tor_config_directory: &str,
	sec_key: &SecretKey,
) -> Result<String, Error> {
	let (_, d_pub_key) = address::ed25519_keypair(&sec_key)?;
	let address = address::onion_v3_from_pubkey(&d_pub_key)?;
	let hs_dir_file_path = format!(
		"{}{}{}{}{}",
		tor_config_directory, MAIN_SEPARATOR, HIDDEN_SERVICES_DIR, MAIN_SEPARATOR, address
	);

	// If file already exists, don't overwrite it, just return address
	if Path::new(&hs_dir_file_path).exists() {
		return Ok(address);
	}

	// create directory if it doesn't exist
	fs::create_dir_all(&hs_dir_file_path)?;

	// Set permissions on the parent directory too
	let hidden_services_parent = format!(
		"{}{}{}",
		tor_config_directory, MAIN_SEPARATOR, HIDDEN_SERVICES_DIR
	);
	set_permissions(&hidden_services_parent)?;
	set_permissions(&hs_dir_file_path)?;

	let (d_sec_key, d_pub_key) = address::ed25519_keypair(&sec_key)?;
	create_onion_service_sec_key_file(&hs_dir_file_path, &d_sec_key, &d_pub_key)?;
	create_onion_service_pub_key_file(&hs_dir_file_path, &d_pub_key)?;
	create_onion_service_hostname_file(&hs_dir_file_path, &address)?;
	create_onion_auth_clients_dir(&hs_dir_file_path)?;

	set_permissions(&hs_dir_file_path)?;

	Ok(address)
}

/// output torrc file given a list of hidden service directories
pub fn output_torrc(
	tor_config_directory: &str,
	wallet_listener_addr: &str,
	socks_port: &str,
	service_dirs: &Vec<String>,
) -> Result<(), Error> {
	let torrc_file_path = format!("{}{}{}", tor_config_directory, MAIN_SEPARATOR, TORRC_FILE);

	let tor_data_dir = format!("{}{}{}", tor_config_directory, MAIN_SEPARATOR, TOR_DATA_DIR);

	let mut props = TorRcConfig::new();
	props.add_item("SocksPort", socks_port);
	props.add_item("DataDirectory", &tor_data_dir);

	for dir in service_dirs {
		let service_file_name = format!("{}", dir);
		props.add_item("HiddenServiceDir", &service_file_name);
		props.add_item("HiddenServicePort", &format!("80 {}", wallet_listener_addr));
	}

	props.write_to_file(&torrc_file_path)?;

	Ok(())
}

/// output entire tor config for a list of secret keys
pub fn output_tor_listener_config(
	tor_config_directory: &str,
	wallet_listener_addr: &str,
	listener_keys: &Vec<SecretKey>,
) -> Result<(), Error> {
	let tor_data_dir = format!("{}{}{}", tor_config_directory, MAIN_SEPARATOR, TOR_DATA_DIR);

	// create data directory if it doesn't exist
	fs::create_dir_all(&tor_data_dir)?;
	set_permissions(&tor_data_dir)?;
	let mut service_dirs = vec![];

	for k in listener_keys {
		let service_dir = output_onion_service_config(tor_config_directory, &k)?;
		service_dirs.push(service_dir);
	}

	// hidden service listener doesn't need a socks port
	output_torrc(
		tor_config_directory,
		wallet_listener_addr,
		"0",
		&service_dirs,
	)?;

	Ok(())
}

/// output tor config for a send
pub fn output_tor_sender_config(
	tor_config_dir: &str,
	socks_listener_addr: &str,
) -> Result<(), Error> {
	// create data directory if it doesn't exist
	fs::create_dir_all(&tor_config_dir)?;

	output_torrc(tor_config_dir, "", socks_listener_addr, &vec![])?;

	Ok(())
}

pub fn is_tor_address(input: &str) -> Result<(), Error> {
	match address::pubkey_from_onion_v3(input) {
		Ok(_) => Ok(()),
		Err(e) => {
			let msg = format!("{}", e);
			Err(Error::NotOnion(msg))?
		}
	}
}

pub fn complete_tor_address(input: &str) -> Result<String, Error> {
	let _ = is_tor_address(input)?;
	let mut input = input.to_uppercase();
	if !input.starts_with("HTTP://") && !input.starts_with("HTTPS://") {
		input = format!("HTTP://{}", input);
	}
	if !input.ends_with(".ONION") {
		input = format!("{}.ONION", input);
	}
	Ok(input.to_lowercase())
}

/// output entire tor config for a list of secret keys
pub fn output_tor_listener_config_auto(
	tor_config_directory: &str,
	api_http_addr: &str,
	socks_listener_addr: &str,
	sec_key: &SecretKey,
) -> Result<(), Error> {
	let tor_data_dir = format!("{}{}{}", tor_config_directory, MAIN_SEPARATOR, TOR_DATA_DIR);

	// create data directory if it doesn't exist
	fs::create_dir_all(&tor_data_dir)?;
	set_permissions(&tor_data_dir)?;

	// ✅ GENERATE KEYPAIR ONLY ONCE
	let (d_sec_key, d_pub_key) = address::ed25519_keypair(&sec_key)?;

	// ✅ USE THE SAME PUBLIC KEY FOR ADDRESS GENERATION
	let address = address::onion_v3_from_pubkey(&d_pub_key)?;
	let hs_dir_file_path = format!(
		"{}{}{}{}{}",
		tor_config_directory, MAIN_SEPARATOR, HIDDEN_SERVICES_DIR, MAIN_SEPARATOR, address
	);

	// If file already exists, don't overwrite it, just return address
	/*if Path::new(&hs_dir_file_path).exists() {
		return Ok(())
	}*/
	fs::create_dir_all(&hs_dir_file_path)?;

	// Set permissions on the parent directory too
	let hidden_services_parent = format!(
		"{}{}{}",
		tor_config_directory, MAIN_SEPARATOR, HIDDEN_SERVICES_DIR
	);
	set_permissions(&hidden_services_parent)?;
	set_permissions(&hs_dir_file_path)?;

	create_onion_service_sec_key_file(&hs_dir_file_path, &d_sec_key, &d_pub_key)?;
	create_onion_service_pub_key_file(&hs_dir_file_path, &d_pub_key)?;
	create_onion_service_hostname_file(&hs_dir_file_path, &address)?;
	create_onion_auth_clients_dir(&hs_dir_file_path)?;
	// Schreibe torrc
	output_torrc(
		tor_config_directory,
		api_http_addr,
		socks_listener_addr,
		&vec![hs_dir_file_path],
	)?;
	set_permissions(&tor_config_directory)?;
	Ok(())
}

pub fn output_onion_service_config_auto(tor_config_directory: &str) -> Result<String, Error> {
	// Erzeuge einen zufälligen Verzeichnisnamen für den Hidden Service
	use rand::distr::Alphanumeric;
	use rand::Rng;
	let mut rng = rand::rng();
	let address: String = (&mut rng)
		.sample_iter(&Alphanumeric)
		.take(56)
		.map(char::from)
		.collect();

	let hs_dir_file_path = format!(
		"{}{}{}{}{}",
		tor_config_directory, MAIN_SEPARATOR, HIDDEN_SERVICES_DIR, MAIN_SEPARATOR, address
	);

	// Lege das Verzeichnis an (ohne Schlüsseldateien)
	fs::create_dir_all(&hs_dir_file_path)?;
	set_permissions(&hs_dir_file_path)?;
	// Tor erzeugt die Schlüssel beim Start selbst!
	Ok(address)
}

#[cfg(test)]
mod tests {
	use super::*;
	use ed25519_dalek::{Signer, Verifier};

	use rand::rng;

	use crate::mock_rng::StepRng;
	use crate::util::{self, secp, static_secp_instance};

	pub fn clean_output_dir(test_dir: &str) {
		let _ = fs::remove_dir_all(test_dir);
	}

	pub fn setup(test_dir: &str) {
		util::init_test_logger();
		clean_output_dir(test_dir);
	}

	#[test]
	fn gen_ed25519_pub_key() -> Result<(), Error> {
		let secp_inst = static_secp_instance();
		let secp = secp_inst.lock();
		let mut test_rng = StepRng::new(1234567890u64, 1);
		let sec_key = secp::key::SecretKey::new(&secp, &mut test_rng);
		println!("{:?}", sec_key);
		let (_, d_pub_key) = address::ed25519_keypair(&sec_key)?;
		println!("{:?}", d_pub_key);
		// some randoms
		for _ in 0..1000 {
			let sec_key = secp::key::SecretKey::new(&secp, &mut rng());
			let (_, _) = address::ed25519_keypair(&sec_key)?;
		}
		Ok(())
	}

	#[test]
	fn gen_onion_address() -> Result<(), Error> {
		let secp_inst = static_secp_instance();
		let secp = secp_inst.lock();
		let mut test_rng = StepRng::new(1234567890u64, 1);
		let sec_key = secp::key::SecretKey::new(&secp, &mut test_rng);
		println!("{:?}", sec_key);
		let (_, d_pub_key) = address::ed25519_keypair(&sec_key)?;
		let address = address::onion_v3_from_pubkey(&d_pub_key)?;
		assert_eq!(
			"3bievy3e2mesnq6woy2y2tafhhpjpfnbihjdh4t4skwyff5tinoqvzad",
			address
		);
		println!("{}", address);
		Ok(())
	}

	#[test]
	fn test_service_config() -> Result<(), Error> {
		let test_dir = "target/test_output/onion_service";
		setup(test_dir);
		let secp_inst = static_secp_instance();
		let secp = secp_inst.lock();
		let mut test_rng = StepRng::new(1234567890u64, 1);
		let sec_key = secp::key::SecretKey::new(&secp, &mut test_rng);
		output_onion_service_config(test_dir, &sec_key)?;
		clean_output_dir(test_dir);
		Ok(())
	}

	#[test]
	fn test_output_tor_config() -> Result<(), Error> {
		let test_dir = "./target/test_output/tor";
		setup(test_dir);
		let secp_inst = static_secp_instance();
		let secp = secp_inst.lock();
		let mut test_rng = StepRng::new(1234567890u64, 1);
		let sec_key = secp::key::SecretKey::new(&secp, &mut test_rng);
		output_tor_listener_config(test_dir, "127.0.0.1:3415", &vec![sec_key])?;
		clean_output_dir(test_dir);
		Ok(())
	}

	#[test]
	fn test_is_tor_address() -> Result<(), Error> {
		assert!(is_tor_address("2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid").is_ok());
		assert!(is_tor_address("2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid").is_ok());
		assert!(is_tor_address("kcgiy5g6m76nzlzz4vyqmgdv34f6yokdqwfhdhaafanpo5p4fceibyid").is_ok());
		assert!(is_tor_address(
			"http://kcgiy5g6m76nzlzz4vyqmgdv34f6yokdqwfhdhaafanpo5p4fceibyid.onion"
		)
		.is_ok());
		assert!(is_tor_address(
			"https://kcgiy5g6m76nzlzz4vyqmgdv34f6yokdqwfhdhaafanpo5p4fceibyid.onion"
		)
		.is_ok());
		assert!(
			is_tor_address("http://kcgiy5g6m76nzlzz4vyqmgdv34f6yokdqwfhdhaafanpo5p4fceibyid")
				.is_ok()
		);
		assert!(
			is_tor_address("kcgiy5g6m76nzlzz4vyqmgdv34f6yokdqwfhdhaafanpo5p4fceibyid.onion")
				.is_ok()
		);
		// address too short
		assert!(is_tor_address(
			"http://kcgiy5g6m76nzlz4vyqmgdv34f6yokdqwfhdhaafanpo5p4fceibyid.onion"
		)
		.is_err());
		assert!(is_tor_address("kcgiy5g6m76nzlz4vyqmgdv34f6yokdqwfhdhaafanpo5p4fceibyid").is_err());
		Ok(())
	}

	#[test]
	fn test_complete_tor_address() -> Result<(), Error> {
		assert_eq!(
			"http://2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid.onion",
			complete_tor_address("2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid")
				.unwrap()
		);
		assert_eq!(
			"http://2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid.onion",
			complete_tor_address("http://2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid")
				.unwrap()
		);
		assert_eq!(
			"http://2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid.onion",
			complete_tor_address("2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid.onion")
				.unwrap()
		);
		assert!(
			complete_tor_address("2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyi")
				.is_err()
		);
		Ok(())
	}
	#[test]
	fn test_ed25519_keypair_deterministic() -> Result<(), Error> {
		let secp_inst = static_secp_instance();
		let secp = secp_inst.lock();
		let mut test_rng = StepRng::new(1234567890u64, 1);
		let sec_key = secp::key::SecretKey::new(&secp, &mut test_rng);

		// Call ed25519_keypair multiple times with the same sec_key
		let (d_sec_key1, d_pub_key1) = address::ed25519_keypair(&sec_key)?;
		let (d_sec_key2, d_pub_key2) = address::ed25519_keypair(&sec_key)?;
		let (d_sec_key3, d_pub_key3) = address::ed25519_keypair(&sec_key)?;

		// Check if they are the same
		assert_eq!(
			d_pub_key1.to_bytes(),
			d_pub_key2.to_bytes(),
			"Public keys should be identical"
		);
		assert_eq!(
			d_pub_key2.to_bytes(),
			d_pub_key3.to_bytes(),
			"Public keys should be identical"
		);
		assert_eq!(
			d_sec_key1.to_bytes(),
			d_sec_key2.to_bytes(),
			"Secret keys should be identical"
		);
		assert_eq!(
			d_sec_key2.to_bytes(),
			d_sec_key3.to_bytes(),
			"Secret keys should be identical"
		);

		// Also test the onion addresses
		let address1 = address::onion_v3_from_pubkey(&d_pub_key1)?;
		let address2 = address::onion_v3_from_pubkey(&d_pub_key2)?;
		let address3 = address::onion_v3_from_pubkey(&d_pub_key3)?;

		assert_eq!(address1, address2, "Onion addresses should be identical");
		assert_eq!(address2, address3, "Onion addresses should be identical");

		Ok(())
	}

	#[test]
	fn test_rfc8032_vector_1_tor_compatible() -> Result<(), Error> {
		// RFC 8032 test vector to ensure Ed25519 compatibility with Tor
		let seed_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
		let expected_pk_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
		let message = b""; // empty message
		let expected_sig_hex = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

		let seed = data_encoding::HEXLOWER.decode(seed_hex.as_bytes()).unwrap();
		let expected_pk = data_encoding::HEXLOWER
			.decode(expected_pk_hex.as_bytes())
			.unwrap();
		let expected_sig = data_encoding::HEXLOWER
			.decode(expected_sig_hex.as_bytes())
			.unwrap();

		// Create secret key from seed
		let secret_key = DalekSecretKey::from_bytes(&seed[..32].try_into().unwrap());
		let public_key = secret_key.verifying_key();

		// Test public key derivation
		assert_eq!(
			public_key.to_bytes(),
			expected_pk.as_slice(),
			"Public key should match RFC 8032 test vector"
		);

		// Test signing
		let signature = secret_key.sign(message);
		assert_eq!(
			signature.to_bytes(),
			expected_sig.as_slice(),
			"Signature should match RFC 8032 test vector"
		);

		// Test verification
		assert!(
			public_key.verify(message, &signature).is_ok(),
			"Signature should verify"
		);

		Ok(())
	}

	#[test]
	fn test_current_wallet_keys_compatibility() -> Result<(), Error> {
		// Test that our current wallet key generation is compatible with Ed25519 standard
		let secp_inst = static_secp_instance();
		let secp = secp_inst.lock();
		let mut test_rng = StepRng::new(1234567890u64, 1);
		let sec_key = secp::key::SecretKey::new(&secp, &mut test_rng);

		// Generate keys using our wallet's method
		let (d_sec_key, d_pub_key) = address::ed25519_keypair(&sec_key)?;

		// Test that the secret key can derive the same public key
		let derived_pub_key = d_sec_key.verifying_key();
		assert_eq!(
			d_pub_key.to_bytes(),
			derived_pub_key.to_bytes(),
			"Public keys should match"
		);

		// Test signing and verification
		let message = b"Epic wallet test message";
		let signature = d_sec_key.sign(message);
		assert!(
			d_pub_key.verify(message, &signature).is_ok(),
			"Signature should verify"
		);

		// Test that what we write to files can be read back and used
		let secret_seed = d_sec_key.to_bytes();
		let reconstructed_secret = DalekSecretKey::from_bytes(&secret_seed);
		let reconstructed_public = reconstructed_secret.verifying_key();

		assert_eq!(
			d_pub_key.to_bytes(),
			reconstructed_public.to_bytes(),
			"Reconstructed public key should match"
		);

		let reconstructed_signature = reconstructed_secret.sign(message);
		assert!(
			reconstructed_public
				.verify(message, &reconstructed_signature)
				.is_ok(),
			"Reconstructed signature should verify"
		);

		Ok(())
	}
}
