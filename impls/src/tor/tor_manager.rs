use crate::keychain::Keychain;
use crate::libwallet::{address, Error, NodeClient, WalletInst, WalletLCProvider};
use crate::tor::config as tor_config;
use crate::tor::process::TorProcess;
use crate::util::secp::key::SecretKey;
use epic_wallet_util::epic_util::Mutex;
use once_cell::sync::OnceCell;
use std::net::TcpStream;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

pub static TOR_MANAGER: OnceCell<Arc<Mutex<TorManager>>> = OnceCell::new();

pub struct TorManager {
	socks_proxy_addr: String,
	tor_process: Option<TorProcess>,
}

impl TorManager {
	pub fn init_tor_listener<L, C, K>(
		socks_proxy_addr: &str,
		wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
		keychain_mask: Arc<Mutex<Option<SecretKey>>>,
		addr: &str,
	) -> Result<(Arc<Mutex<Self>>, Option<String>), Error>
	where
		L: WalletLCProvider<'static, C, K> + 'static,
		C: NodeClient + 'static,
		K: Keychain + 'static,
	{
		// 1. Init hidden service (onion address)
		let mask_guard = keychain_mask.lock();
		let mut w_lock = wallet.lock();
		let lc = w_lock.lc_provider()?;
		let w_inst = lc.wallet_inst()?;
		let k = w_inst.keychain(mask_guard.as_ref())?;
		let parent_key_id = w_inst.parent_key_id();

		let sec_key = address::address_from_derivation_path(&k, &parent_key_id, 0)
			.map_err(|e| Error::TorConfig(format!("{:?}", e).into()))?;
		let onion_address = tor_config::onion_address_from_seckey(&sec_key)
			.map_err(|e| Error::TorConfig(format!("{:?}", e).into()))?;

		warn!(
			"Adding wallet tor Hidden Service for API listener at address {}, binding to {}",
			onion_address, addr
		);
		let top_dir = lc.get_top_level_directory()?;
		let tor_dir = format!("{}/wallet_tor", top_dir);

		tor_config::output_tor_listener_config_auto(&tor_dir, addr, socks_proxy_addr, &sec_key)
			.map_err(|e| Error::TorConfig(format!("{:?}", e).into()))?;
		// 2. Ensure Tor is running
		let manager = Self::ensure_running(socks_proxy_addr, &tor_dir);

		let onion_base = format!("{}/onion_service_addresses", tor_dir);
		let api_port = addr.split(':').last().unwrap_or("3415");
		let onion_addr = std::fs::read_dir(&onion_base)
			.ok()
			.and_then(|mut entries| {
				entries.find_map(|entry| {
					let hostname_path = entry.ok()?.path().join("hostname");
					std::fs::read_to_string(hostname_path).ok()
				})
			})
			.map(|s| s.trim().to_string());

		let onion_api_addr = onion_addr
			.as_ref()
			.map(|addr| format!("http://{}:{}", addr, api_port));

		Ok((manager, onion_api_addr))
	}

	pub fn ensure_running(socks_proxy_addr: &str, tor_dir: &str) -> Arc<Mutex<Self>> {
		let manager = Arc::new(Mutex::new(TorManager {
			socks_proxy_addr: socks_proxy_addr.to_string(),
			tor_process: None,
		}));

		// Check if Tor SOCKS proxy is available
		let available = TcpStream::connect_timeout(
			&socks_proxy_addr
				.parse()
				.expect("Invalid SOCKS proxy address"),
			Duration::from_secs(2),
		)
		.is_ok();

		if !available {
			let manager_clone = manager.clone();
			let socks_proxy_addr = socks_proxy_addr.to_string();
			let tor_dir = tor_dir.to_string();
			thread::spawn(move || {
				let torrc_path = format!("{}/torrc", tor_dir);

				let mut tor = TorProcess::new();
				tor.torrc_path(&torrc_path)
					.working_dir(&tor_dir)
					.timeout(20)
					.completion_percent(100)
					.launch()
					.expect("Failed to launch Tor process");
				// Wait for Tor to become available
				let mut waited = 0;
				let max_wait = 20;
				while TcpStream::connect_timeout(
					&socks_proxy_addr
						.parse()
						.expect("Invalid SOCKS proxy address"),
					Duration::from_secs(2),
				)
				.is_err()
				{
					if waited >= max_wait {
						panic!("Tor did not become available after {} seconds.", max_wait);
					}
					std::thread::sleep(Duration::from_secs(1));
					waited += 1;
				}
				manager_clone.lock().tor_process = Some(tor);
			});
		}
		manager
	}
	pub fn socks_proxy_addr(&self) -> &str {
		&self.socks_proxy_addr
	}
}
