use epic_wallet_libwallet::Slate;
use epic_wallet_util::epic_keychain::{ExtKeychain, Keychain};
use serde_json::{json, Map, Number, Value};
use std::sync::OnceLock;

const MAX_INPUT: usize = 64 * 1024;
const MAX_COLLECTION: usize = 16;
const V2_TEMPLATE: &str = include_str!("../../libwallet/tests/slates/v2.slate");

fn keychain() -> &'static ExtKeychain {
    static KEYCHAIN: OnceLock<ExtKeychain> = OnceLock::new();
    KEYCHAIN.get_or_init(|| {
        ExtKeychain::from_seed(&[0x5a; 32], true).expect("fixed fuzz keychain seed is valid")
    })
}

/// Exercise the production counterparty-slate boundary.
pub fn exercise_json(data: &[u8]) {
    if data.len() > MAX_INPUT {
        return;
    }
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    let _ = Slate::parse_slate_version(input);
    let Ok(slate) = Slate::deserialize_upgrade(input) else {
        return;
    };

    let _ = slate.verify_messages();
    for participant_id in 0..slate.num_participants.min(MAX_COLLECTION) {
        let _ = slate.participant_with_id(participant_id);
    }

    // Finalization reaches the hardened participant/signature/kernel paths. A
    // malformed or incomplete slate should return an error, never panic.
    let mut finalizing = slate.clone();
    let _ = finalizing.finalize(keychain());

    // Legacy orig_version values can be accepted for upgrade but deliberately
    // cannot be emitted. If serialization is supported, its output must remain
    // accepted by the same production boundary.
    if let Ok(serialized) = serde_json::to_vec(&slate) {
        Slate::deserialize_upgrade(
            std::str::from_utf8(&serialized).expect("serde_json always emits UTF-8"),
        )
        .expect("serialized slate must survive a deserialization round trip");
    }
}

/// Apply a structure-aware mutation before exercising the same production
/// boundary. Raw byte mutation alone spends most iterations failing JSON
/// syntax and does not adequately cover the slate's nested fields.
pub fn exercise_structured(data: &[u8]) {
    if data.is_empty() {
        return;
    }

    let mut slate: Value = serde_json::from_str(V2_TEMPLATE).expect("checked-in v2 slate");
    if data[0] & 1 == 1 {
        slate["version_info"]["version"] = json!(3);
        slate["version_info"]["orig_version"] = json!(3);
        slate["ttl_cutoff_height"] = Value::Null;
        slate["payment_proof"] = Value::Null;
    }

    let action = data.get(1).copied().unwrap_or(0) % 26;
    let payload = data.get(2..).unwrap_or_default();
    let value = fuzz_value(payload);
    match action {
        0 => slate["version_info"]["version"] = value,
        1 => slate["version_info"]["orig_version"] = value,
        2 => slate["num_participants"] = value,
        3 => slate["amount"] = value,
        4 => slate["fee"] = value,
        5 => slate["height"] = value,
        6 => slate["lock_height"] = value,
        7 => slate["participant_data"] = repeated_member(&slate, "participant_data", payload),
        8 => slate["participant_data"][0]["id"] = value,
        9 => slate["participant_data"][0]["public_blind_excess"] = value,
        10 => slate["participant_data"][0]["public_nonce"] = value,
        11 => slate["participant_data"][0]["part_sig"] = value,
        12 => slate["participant_data"][0]["message"] = value,
        13 => slate["participant_data"][0]["message_sig"] = value,
        14 => {
            slate["tx"]["body"]["kernels"] =
                repeated_member(&slate["tx"]["body"], "kernels", payload)
        }
        15 => slate["tx"]["body"]["kernels"][0]["excess"] = value,
        16 => slate["tx"]["body"]["kernels"][0]["excess_sig"] = value,
        17 => slate["payment_proof"] = payment_proof(payload),
        18 => slate["ttl_cutoff_height"] = value,
        19 => slate["tx"]["offset"] = value,
        20 => slate["tx"] = value,
        21 => slate["tx"]["body"]["inputs"][0]["commit"] = value,
        22 => slate["tx"]["body"]["outputs"][0]["commit"] = value,
        23 => slate["tx"]["body"]["outputs"][0]["proof"] = value,
        24 => {
            slate["tx"]["body"]["inputs"] =
                repeated_member(&slate["tx"]["body"], "inputs", payload)
        }
        _ => {
            slate["tx"]["body"]["outputs"] =
                repeated_member(&slate["tx"]["body"], "outputs", payload)
        }
    }

    let encoded = serde_json::to_vec(&slate).expect("JSON value must serialize");
    exercise_json(&encoded);
}

fn repeated_member(parent: &Value, field: &str, data: &[u8]) -> Value {
    let count = data.first().copied().unwrap_or(0) as usize % (MAX_COLLECTION + 1);
    let Some(member) = parent
        .get(field)
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .cloned()
    else {
        return Value::Array(Vec::new());
    };
    Value::Array(vec![member; count])
}

fn payment_proof(data: &[u8]) -> Value {
    let split = data.len().min(192) / 3;
    let first = fuzz_string(&data[..split]);
    let second = fuzz_string(&data[split..split.saturating_mul(2)]);
    let third = fuzz_string(&data[split.saturating_mul(2)..data.len().min(192)]);
    json!({
        "sender_address": first,
        "receiver_address": second,
        "receiver_signature": if data.first().copied().unwrap_or(0) & 1 == 0 {
            Value::String(third)
        } else {
            Value::Null
        }
    })
}

fn fuzz_value(data: &[u8]) -> Value {
    match data.first().copied().unwrap_or(0) % 7 {
        0 => Value::Null,
        1 => Value::Bool(data.get(1).copied().unwrap_or(0) & 1 == 1),
        2 => Value::Number(Number::from(read_u64(data))),
        3 => Value::String(fuzz_string(data.get(1..).unwrap_or_default())),
        4 => Value::Array(
            data.iter()
                .skip(1)
                .take(MAX_COLLECTION)
                .map(|byte| Value::Number(Number::from(*byte)))
                .collect(),
        ),
        5 => json!({ "fuzz": fuzz_string(data.get(1..).unwrap_or_default()) }),
        _ => Value::Object(Map::new()),
    }
}

fn read_u64(data: &[u8]) -> u64 {
    let mut bytes = [0u8; 8];
    let source = data.get(1..).unwrap_or_default();
    let length = source.len().min(bytes.len());
    bytes[..length].copy_from_slice(&source[..length]);
    u64::from_le_bytes(bytes)
}

fn fuzz_string(data: &[u8]) -> String {
    String::from_utf8_lossy(&data[..data.len().min(4096)]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpus_seeds_reach_the_production_parser() {
        for seed in [
            include_bytes!("../corpus/slate_json/v2.json").as_slice(),
            include_bytes!("../corpus/slate_json/v3.json").as_slice(),
        ] {
            let input = std::str::from_utf8(seed).unwrap();
            assert!(Slate::deserialize_upgrade(input).is_ok());
            exercise_json(seed);
        }

        for regression in [
            include_bytes!("../corpus/slate_json/invalid-offset.json").as_slice(),
            include_bytes!("../corpus/slate_json/mixed-version.json").as_slice(),
        ] {
            exercise_json(regression);
        }
    }

    #[test]
    fn structured_actions_are_bounded_and_panic_free() {
        for version in 0..=1 {
            for action in 0..26 {
                exercise_structured(&[version, action, 0, 0xff, b'a', b'F']);
            }
        }
        exercise_structured(include_bytes!(
            "../corpus/slate_mutations/invalid-partial-signature"
        ));
        exercise_structured(include_bytes!(
            "../corpus/slate_mutations/participant-payment-kernel"
        ));
    }
}
