// Copyright 2022 The Epic Developers
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

use bitvec::prelude::*;
use std::io::{Read, Write};

use crate::libwallet::{Error, ErrorKind, Slate, SlateVersion, VersionedSlate};

extern crate flate2;
use super::emoji_map::EMOJI_MAP;

use emoji::Emoji;

use super::compress::{compress, decompress, CompressionFormat};
use std::collections::HashMap;

static TYPE_TRANSACTION: &str = "compress";
pub const GZIP_METHOD: Emoji = emoji::activities::arts_and_crafts::THREAD;
pub const ZLIB_METHOD: Emoji = emoji::activities::arts_and_crafts::THREAD;
pub const DEFLATE_METHOD: Emoji = emoji::activities::arts_and_crafts::THREAD;
pub const VERSION_0: Emoji = emoji::activities::arts_and_crafts::THREAD;
pub const VERSION_1: Emoji = emoji::activities::arts_and_crafts::THREAD;

/// The default method to compress and decompress in Epic
const COMPRESS_METHOD: CompressionFormat = CompressionFormat::Gzip;

#[derive(Debug)]
struct Header {
	algo: CompressionFormat,
	version: u16,
}

impl From<Vec<String>> for Header {
	fn from(input: Vec<String>) -> Self {
		let algo_str = &input[0];
		let version_str = &input[1];

		let algo = match algo_str.as_ref() {
			"gzip" => CompressionFormat::Gzip,
			"zlib" => CompressionFormat::Zlib,
			"deflate" => CompressionFormat::Deflate,
			_ => panic!("Invalid compression format!"),
		};

		let version = match version_str.parse() {
			Ok(version) => version,
			Err(_) => panic!("Invalid version number!"),
		};

		Header { algo, version }
	}
}

fn get_header_dict() -> HashMap<String, String> {
	let mut map: HashMap<String, String> = HashMap::new();

	// Add all methods to Dict
	map.insert(
		CompressionFormat::Gzip.to_string(),
		GZIP_METHOD.glyph.to_string().clone(),
	);
	map.insert(
		CompressionFormat::Zlib.to_string(),
		ZLIB_METHOD.glyph.to_string().clone(),
	);
	map.insert(
		CompressionFormat::Deflate.to_string(),
		DEFLATE_METHOD.glyph.to_string().clone(),
	);

	// Add all versions to Dict
	map.insert(0.to_string(), VERSION_0.glyph.to_string().clone());
	map.insert(1.to_string(), VERSION_1.glyph.to_string().clone());

	map
}

fn invert_hashmap(map: &HashMap<String, String>) -> HashMap<String, String> {
	let mut inverted = HashMap::new();
	for (key, value) in map {
		inverted.insert(value.clone(), key.clone());
	}
	inverted
}

impl Header {
	fn new() -> Header {
		Header {
			algo: COMPRESS_METHOD,
			version: 1,
		}
	}

	fn to_emoji_string(&self) -> String {
		let method2emoji = get_header_dict();
		let method = self.algo.to_string();
		let emoji_method = method2emoji.get(&method).unwrap();

		emoji_method.to_owned()
	}

	fn to_header(emoji_string: String) -> Header {
		let method2emoji = get_header_dict();
		let emoji2method = invert_hashmap(&method2emoji);

		let emojis = emoji_string.chars();

		let mut header_vec = Vec::new();

		for emoji_header in emojis {
			let a = emoji_header.to_string();
			let b = emoji2method.get(&a).unwrap().to_owned();
			header_vec.push(b);
		}

		let header = Header::from(header_vec);
		header
	}
}

/// EmojiSlate is the struct that stores Slate in emoji format to transact
#[derive(Clone)]
pub struct EmojiSlate();

enum TranslateType {
	Normal(String),
	Compressed(Vec<u8>),
}

/// Transform implementations between, slate_json, EmojiSlate, Vec<u8>, and BitVec
impl EmojiSlate {
	/// Function that transform one byte into a BitVec
	fn byte2bitvec(&self, byte: u8) -> BitVec {
		let mut bit_vec = BitVec::new();
		for i in 0..8 {
			let mut bit = byte << i;
			bit = bit >> 7;

			if bit == 1 {
				bit_vec.push(true);
			} else {
				bit_vec.push(false);
			}
		}
		return bit_vec;
	}

	/// Function that transform one BitVec into a byte
	fn bitvec2byte(&self, bit_vec: BitVec) -> u8 {
		let mut byte = 0;

		// 2^(exp)
		let mut exp = 0;
		for i in (0..bit_vec.len()).rev() {
			byte = byte + bit_vec[i] as usize * (2_i32.pow(exp) as usize);
			exp = exp + 1;
		}

		return byte as u8;
	}

	/// Adds extra bits for BitVec as an emoji is 10 bits and we want an 8 bit message
	fn set_extra_bits(&self, data_len: usize) -> BitVec {
		let mut bit_vec = BitVec::new();
		let extra_bits = (10 - ((data_len * 8) % 10)) as u8;
		let extra_bits_vec = self.byte2bitvec(extra_bits);

		for _ in 0..6 {
			bit_vec.push(false);
		}
		for i in 4..extra_bits_vec.len() {
			bit_vec.push(extra_bits_vec[i]);
		}
		for _ in 0..extra_bits {
			bit_vec.push(false);
		}

		return bit_vec;
	}

	/// Transform a Vec<u16> into a sequence of Emojis
	fn translate2emoji(&self, content: Vec<u16>) -> String {
		// Final string
		let mut emoji_string = "".to_owned();
		// For element in Vec<u16>
		for value in content {
			// Add in the final string the correspondent emoji
			emoji_string.push_str(EMOJI_MAP[value as usize].glyph);
		}

		return emoji_string;
	}

	/// Transform a String of emojis into a slate_json
	fn translate(&self, emoji_string: &str, type_transaction: &str) -> TranslateType {
		// Final slate_json string
		let mut content_string = String::new();

		// BitVec message
		let mut bit_vec: BitVec = BitVec::new();

		// For emoji i in message
		for i in 0..emoji_string.len() {
			// Break point
			if emoji_string.chars().nth(i) == None {
				break;
			}

			// Get the char from Emoji
			let emoji = emoji_string.chars().nth(i).unwrap();
			// Get the ID in EMOJI_MAP from the emoji[i]
			let idx = EMOJI_MAP
				.iter()
				.position(|r| r.glyph == emoji.to_string())
				.unwrap() as u16;

			for k in (1..11).rev() {
				let mut bit = idx << (16 - k);
				bit = bit >> 15;

				if bit == 1 {
					bit_vec.push(true);
				} else {
					bit_vec.push(false);
				}
			}
		}

		// get the first emoji as char
		let emoji = emoji_string.chars().nth(0).unwrap();

		let num_extra_bits = EMOJI_MAP
			.iter()
			.position(|r| r.glyph == emoji.to_string())
			.unwrap();

		for i in ((10 + num_extra_bits)..bit_vec.len()).step_by(8) {
			let mut bit_vec_8b_slice: BitVec = BitVec::new();
			for j in i..(i + 8) {
				bit_vec_8b_slice.push(bit_vec[j]);
			}
			content_string.push(self.bitvec2byte(bit_vec_8b_slice.clone()) as char);
		}

		let content_vec: Vec<u8> = content_string.chars().map(|c| c.to_owned() as u8).collect();

		match type_transaction {
			"compress" => TranslateType::Compressed(content_vec),
			_ => TranslateType::Normal(content_string),
		}
	}

	/// Encode the Slate struct into a Emoji String
	pub fn encode(&self, slate: &Slate) -> String {
		// get the slate
		let out_slate = {
			if slate.payment_proof.is_some() || slate.ttl_cutoff_height.is_some() {
				warn!("Transaction contains features that require epic-wallet 3.0.0 or later");
				warn!("Please ensure the other party is running epic-wallet v3.0.0 or later before sending");
				VersionedSlate::into_version(slate.clone(), SlateVersion::V3)
			} else {
				let mut s = slate.clone();
				s.version_info.version = 2;
				s.version_info.orig_version = 2;
				VersionedSlate::into_version(s, SlateVersion::V2)
			}
		};

		// String from Slate
		let slate_json = match serde_json::to_string(&out_slate).map_err(|_| ErrorKind::SlateSer) {
			Ok(s) => s,
			Err(_) => "ERROR - Slate JSON generation".to_string(),
		};

		let slate_str = match TYPE_TRANSACTION {
			"compress" => {
				// Compressed slate_json
				//let slate_str = compress(&slate_json);
				let slate_str = compress(&slate_json.as_bytes(), COMPRESS_METHOD);
				slate_str
			}
			_ => slate_json.into_bytes(),
		};

		// Emoji BitVec
		let mut bitstream: BitVec = BitVec::new();

		// Get the extra bits
		for bit in self.set_extra_bits(slate_str.len()) {
			bitstream.push(bit);
		}

		// For binary letter, transform into Emoji
		for i in 0..slate_str.len() {
			let char_bitvector = self.byte2bitvec(slate_str[i]);
			for bit in char_bitvector {
				bitstream.push(bit);
			}
		}

		let mut emoji_map_idx = Vec::new();
		while bitstream.len() > 0 {
			let slice = bitstream.drain(0..10);
			let mut bv: BitVec = BitVec::new();
			for _ in 0..6 {
				bv.push(false);
			}
			for bit in slice {
				bv.push(bit);
			}
			bv.reverse();

			emoji_map_idx.push(bv.load::<u16>());
		}

		let emoji_string = self.translate2emoji(emoji_map_idx);

		return emoji_string;
	}

	/// Transform a emoji string into a Slate
	pub fn decode(&self, emoji_string: &str) -> Result<Slate, Error> {
		// get the Vec<u8> from emoji_string
		//let compressed_vec = self.translate2vec(emoji_string);

		let compressed_msg = self.translate(emoji_string, TYPE_TRANSACTION);

		let slate_string = match compressed_msg {
			TranslateType::Compressed(compressed_vec) => {
				// decompress
				//let slate_string = decompress(compressed_vec);
				let slate_string = decompress(&compressed_vec[..], COMPRESS_METHOD);
				slate_string
			}
			TranslateType::Normal(slate_string) => slate_string,
		};
		Ok(Slate::deserialize_upgrade(&slate_string)?)
	}
}
