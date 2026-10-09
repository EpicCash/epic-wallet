#![no_main]

use epic_wallet_fuzz::exercise_structured;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| exercise_structured(data));
