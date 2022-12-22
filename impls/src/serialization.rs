use epic_wallet_libwallet::{AcctPathMapping, OutputData, TxLogEntry};
use serde::Serialize;
use serde_json::{json, Result, Value};

#[derive(Serialize, Deserialize)]
pub enum Serializable {
	TxLogEntry(TxLogEntry),
	AcctPathMapping(AcctPathMapping),
	OutputData(OutputData),
}
// T: Enum?
pub fn serialize(data: impl Serialize) -> Result<Value> {
	let serialized_data: Value = json!(data);
	return Ok(serialized_data);
}

pub fn deserialize(data: &str) -> Result<Serializable> {
	let deserialized = serde_json::from_str(data)?;
	return Ok(deserialized);
}
