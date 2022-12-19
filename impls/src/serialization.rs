use serde::Serialize;
use serde_json::{json, Result, Value};

//
pub fn serialize<T>(data: impl Serialize) -> Result<Value> {
	let serialized_data = json!(data);
	return Ok(serialized_data);
}

pub fn deserialize(data: &str) -> Result<impl Serialize> {
	let deserialized = serde_json::from_str(data)?;
	return Ok(deserialized);
}
