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

//! The main implementarion for Emoji
//! Has the main operations to handle the Emoji transaction
//! This was built to expand the Epic Cash ways to send coins

use bitvec::prelude::*;

use crate::libwallet::{Error, ErrorKind, Slate, SlateVersion, VersionedSlate};

extern crate flate2;
use super::emoji_map::{EMOJI_DIVIDER, EMOJI_MAP, VERSION_0, VERSION_1};

use super::compress::{compress, decompress, CompressionFormat};
use std::collections::HashMap;

/// Globally controls which type of transaction we will consider, compressed or normal
static TYPE_TRANSACTION: &str = "compress";

/// The default method to compress and decompress in this version of Epic
const COMPRESS_METHOD: CompressionFormat = CompressionFormat::Gzip;

/// The default version of the emoji in this version of Epic
const EMOJI_VERSION: u16 = 1;

/// Saves all information and the type of compressor and which version of the epic for the emoji we are using
#[derive(Debug)]
struct Header {
	/// Method to compress/decompress
	algo: CompressionFormat,
	/// Version of emoji in Epic
	version: u16,
}

/// This function returns a Dictionary that contains keys such as compression method and version of emoji
/// And the values are the corresponding emojis, as there are few algorithms that we want to keep, we don't need something generic
/// Something like an Encode for the Header without having to create a custom EMOJI_MAP for the Header
fn get_header_dict() -> HashMap<String, String> {
	// dict
	let mut map: HashMap<String, String> = HashMap::new();

	// Add all versions to Dict
	map.insert(0.to_string(), VERSION_0.glyph.to_string().clone());
	map.insert(1.to_string(), VERSION_1.glyph.to_string().clone());

	map
}

/// Inverts the dictionary resulting in a Dictionary where the Keys are emojis and the values are the compression methods and version of the emoji
/// Something like an Dencoder for the Header without having to create a custom EMOJI_MAP for the Header
fn invert_hashmap(map: &HashMap<String, String>) -> HashMap<String, String> {
	let mut inverted = HashMap::new();
	for (key, value) in map {
		inverted.insert(value.clone(), key.clone());
	}
	inverted
}

/// Helper function for compressed transactions
pub fn string2compressedvec(content_string: String) -> Vec<u8> {
	// Separates the string into chars and then into bits so the compressor can handle the message
	let content_vec: Vec<u8> = content_string.chars().map(|c| c.to_owned() as u8).collect();

	content_vec
}

/// Implementations that help handle Header in code
impl Header {
	/// Returns a default value to modify without having to manually create a Header
	fn default() -> Header {
		let method: CompressionFormat = match EMOJI_VERSION {
			// Version 0 had no compression method so it doesn't go here.
			1 => CompressionFormat::Gzip,    // Latest version of emoji is version 1
			2 => CompressionFormat::Zlib,    // just for example
			_ => CompressionFormat::Deflate, // just for example
		};

		Header {
			algo: method,
			version: EMOJI_VERSION,
		}
	}

	/// Returns a default value to modify without having to manually create a Header
	fn new(ver: u16) -> Header {
		let method: CompressionFormat = match ver {
			// Version 0 had no compression method so it doesn't go here.
			1 => CompressionFormat::Gzip,    // Latest version of emoji is version 1
			2 => CompressionFormat::Zlib,    // just for example
			_ => CompressionFormat::Deflate, // just for example
		};

		Header {
			algo: method,
			version: ver,
		}
	}

	/// Transforms the Header into a string of emojis, transforming only the values of each Header entry, in this case we only have Method and Version
	fn to_emoji_string(&self) -> String {
		// Get the "Encoder"
		let method2emoji = get_header_dict();

		// Get the version
		let version = self.version.to_string();
		// Transform this Version into a correspondent emoji
		let emoji_version = method2emoji.get(&version).unwrap();

		// Version will determinate all
		emoji_version.to_string()
	}

	/// Turns an emoji string into a Header, consider the input as just 2 emojis, one emoji is the compression method the other is the version
	fn to_header(emoji_string: String) -> Header {
		// Get the "Encoder" Header -> String_Emoji
		let method2emoji = get_header_dict();
		// Get the "Decoder" reversing the "Encoder" so we have String_Emoji -> Header
		let emoji2method = invert_hashmap(&method2emoji);

		let version_str = emoji2method.get(&emoji_string).unwrap().to_owned();

		// Get the version from str
		let version: u16 = version_str
			.parse()
			.unwrap_or_else(|_| panic!("Invalid version number!"));

		// New header based on version
		let header = Header::new(version);

		header
	}
}

/// EmojiSlate is the struct that stores Slate in emoji format to transact
#[derive(Clone)]
pub struct EmojiSlate();

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
	fn translate(&self, emoji_string: &str) -> String {
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

		content_string
	}

	/// Encode the Slate struct into a Emoji String
	pub fn encode(&self, slate: &Slate, receive_compressed: bool) -> String {
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

		let slate_str = if receive_compressed {
			let slate_str = match TYPE_TRANSACTION {
				"compress" => {
					// Compressed slate_json
					//let slate_str = compress(&slate_json);
					let slate_str = compress(&slate_json.as_bytes(), COMPRESS_METHOD);
					slate_str
				}
				_ => slate_json.into_bytes(),
			};
			slate_str
		} else {
			slate_json.into_bytes()
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

		// get the emoji string from slate_json
		let emoji_string = self.translate2emoji(emoji_map_idx);

		let final_emoji_string = if receive_compressed {
			let final_emoji_string = match TYPE_TRANSACTION {
				// if compressed
				"compress" => {
					// Get a default header (Gzip method and Version 1)
					let header = Header::default();
					// Turns the header into emoji_string
					let h_emoji = header.to_emoji_string();
					// Merge all strings of Emojis: Header + Divider + Transaction
					let emoji_string_header = h_emoji + EMOJI_DIVIDER.glyph + &emoji_string;

					emoji_string_header
				}
				// If normal method
				_ => emoji_string,
			};

			final_emoji_string
		} else {
			// The receive emoji_string is not compressed, so the reply-to-sender emoji string has to be normal
			emoji_string
		};

		return final_emoji_string;
	}

	/// Transform a emoji string into a Slate
	pub fn decode(&self, emoji_string: &str) -> Result<(Slate, bool), Error> {
		// get the Emoji Divider
		let div = EMOJI_DIVIDER.glyph.to_string().chars().next().unwrap();
		// If countain divider -> Compressed with header
		let (slate_string, receive_compressed) = if emoji_string.contains(div) {
			// Split the emoji_string into divider emoji
			let mut splited_slate = emoji_string.split(div);

			// get the header emojis (before divider)
			let header_emoji = splited_slate.next().unwrap();
			// get the transaction emojis (after divider)
			let slate_emoji = splited_slate.next().unwrap();

			// get the compressed message from emoji string
			let compressed_msg = self.translate(slate_emoji);

			// get the header from emoji string
			let header = Header::to_header(header_emoji.to_string());

			// get the method of compression from emoji message
			let compress_method = header.algo.clone();
			// get the number of version from emoji message (don't used yet)
			let _emoji_version = header.version.clone();

			// Get the Vec<u8> from string to code can descompress this message
			let compressed_vec = string2compressedvec(compressed_msg);

			// decompress
			let slate_string = decompress(&compressed_vec[..], compress_method);

			(slate_string, true)
		} else {
			// Get the decompressed message from emoji string
			let slate_string = self.translate(emoji_string);

			(slate_string, false)
		};

		let slate = Slate::deserialize_upgrade(&slate_string)?;
		Ok((slate, receive_compressed))
	}
}
