use epic_wallet_libwallet::{
	AcctPathMapping, OutputData, ScannedBlockInfo, TxLogEntry, WalletInitStatus,
};
use serde::Serialize;
use serde_json::Result;

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum Serializable {
	TxLogEntry(TxLogEntry),
	AcctPathMapping(AcctPathMapping),
	OutputData(OutputData),
	ScannedBlockInfo(ScannedBlockInfo),
	WalletInitStatus(WalletInitStatus),
}

pub fn serialize(data: impl Serialize) -> Result<String> {
	let serialized_data: String = serde_json::to_string(&data)?;
	return Ok(serialized_data);
}

pub fn deserialize(data: &str) -> Result<Serializable> {
	let deserialized = serde_json::from_str(data)?;
	return Ok(deserialized);
}

impl Serializable {
	pub fn as_txlogentry(self) -> Option<TxLogEntry> {
		match self {
			Serializable::TxLogEntry(txle) => Some(txle),
			_ => None,
		}
	}

	pub fn as_acct_path_mapping(self) -> Option<AcctPathMapping> {
		match self {
			Serializable::AcctPathMapping(acct) => Some(acct),
			_ => None,
		}
	}

	pub fn as_output_data(self) -> Option<OutputData> {
		match self {
			Serializable::OutputData(out) => Some(out),
			_ => None,
		}
	}

	pub fn as_scanned_block_info(self) -> Option<ScannedBlockInfo> {
		match self {
			Serializable::ScannedBlockInfo(scan) => Some(scan),
			_ => None,
		}
	}

	pub fn as_wallet_init_status(self) -> Option<WalletInitStatus> {
		match self {
			Serializable::WalletInitStatus(status) => Some(status),
			_ => None,
		}
	}
}
