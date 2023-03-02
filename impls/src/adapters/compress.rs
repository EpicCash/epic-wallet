// Copyright 2023 The Epic Developers
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

//! The main implementarion for Compression and Decopression to transactions
//! Has the main operations to handle the Emoji transaction, for now.
//! This was built to make the transaction more efficient using less memory

use std::io::{Read, Write};
extern crate flate2;
use flate2::{
	read::{DeflateDecoder, GzDecoder, ZlibDecoder},
	write::{DeflateEncoder, GzEncoder, ZlibEncoder},
	Compression,
};

use super::emoji_map::{VERSION_0, VERSION_1};
use super::{EMOJI_VERSION, QR_VERSION};
use std::collections::HashMap;

/// Enum to specify the desired compression format
#[derive(Debug, Eq, Hash, PartialEq, Clone)]
pub enum CompressionFormat {
	// Zlib method based on flate2
	Zlib,
	// Glib method based on flate2
	Gzip,
	// Deflate method based on flate2
	Deflate,
}

/// Transform CompressionFormat into a Vec with all options
impl Into<Vec<CompressionFormat>> for CompressionFormat {
	fn into(self) -> Vec<CompressionFormat> {
		vec![
			CompressionFormat::Zlib,
			CompressionFormat::Gzip,
			CompressionFormat::Deflate,
		]
	}
}

/// Transform into a string version of CompressionFormat
impl ToString for CompressionFormat {
	fn to_string(&self) -> String {
		match *self {
			CompressionFormat::Zlib => "zlib".to_owned(),
			CompressionFormat::Gzip => "gzip".to_owned(),
			CompressionFormat::Deflate => "deflate".to_owned(),
		}
	}
}

/// The function that handles the compression code, for now we have Zlib, Gzip and Deflate
///  # Example
/// ```
/// let data = "data to compress".as_bytes();
/// let compressed = compress(data, CompressionFormat::Gzip);
/// ```
pub fn compress(data: &[u8], mode: CompressionFormat) -> Vec<u8> {
	// Check the desired compression format
	let output: Vec<u8> = match mode {
		// Zlib compression
		CompressionFormat::Zlib => {
			// level of compression, default is 6 and best is 9;
			let compressor = Compression::new(9);
			// Create a ZlibEncoder instance
			let mut encoder = ZlibEncoder::new(Vec::new(), compressor);
			// Write the data to be compressed
			encoder.write_all(data).unwrap();
			// Finish the compression and store the result in the output vector
			let output = encoder.finish().unwrap();

			output
		}
		// Gzip compression
		CompressionFormat::Gzip => {
			// level of compression, default is 6 and best is 9;
			let compressor = Compression::new(9);
			// Create a GzEncoder instance
			let mut encoder = GzEncoder::new(Vec::new(), compressor);
			// Write the data to be compressed
			encoder.write_all(data).unwrap();
			// Finish the compression and store the result in the output vector
			let output = encoder.finish().unwrap();

			output
		}
		// Deflate compression
		CompressionFormat::Deflate => {
			// level of compression, default is 6 and best is 9;
			let compressor = Compression::new(9);
			// Create a DeflateEncoder instance
			let mut encoder = DeflateEncoder::new(Vec::new(), compressor);
			// Write the data to be compressed
			encoder.write_all(data).unwrap();
			// Finish the compression and store the result in the output vector
			let output = encoder.finish().unwrap();

			output
		}
	};

	output
}

/// The generic function that handles the decompression, for now we have Zlib, Gzip and Deflate
///  # Example
/// ```
/// let data = "data to compress".as_bytes();
/// let compressed = compress(data, CompressionFormat::Gzip);
/// let decompressed = decompress(&compressed[..], CompressionFormat::Gzip);
/// ```
pub fn decompress(data: &[u8], mode: CompressionFormat) -> String {
	// String that will store the uncompressed message
	let mut decompressed = String::new();

	// Check the desired compression format
	match mode {
		// Zlib decompression
		CompressionFormat::Zlib => {
			// Create a ZlibDecoder instance
			let mut decoder = ZlibDecoder::new(data);
			// Decompress the data and store the result in the output String
			decoder.read_to_string(&mut decompressed).unwrap();
		}
		// Gzip decompression
		CompressionFormat::Gzip => {
			// Create a GzDecoder instance
			let mut decoder = GzDecoder::new(data);
			// Decompress the data and store the result in the output String
			decoder.read_to_string(&mut decompressed).unwrap();
		}
		// Deflate decompression
		CompressionFormat::Deflate => {
			// Create a GzDecoder instance
			let mut decoder = DeflateDecoder::new(data);
			// Decompress the data and store the result in the output String
			decoder.read_to_string(&mut decompressed).unwrap();
		}
	};

	decompressed
}

/// Header traits

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

/// Saves all information and the type of compressor and which version of the epic for the emoji/qr we are using
#[derive(Debug)]
pub struct Header {
	/// Method to compress/decompress
	pub algo: CompressionFormat,
	/// Version of emoji/qr in Epic
	pub version: u8,
}

/// Implementations that help handle Header in code
impl Header {
	/// Returns a default value to modify without having to manually create a Header
	pub fn default(method_context: &str) -> Header {
		let default_version = match method_context {
			"qr" => QR_VERSION,
			"emoji" => EMOJI_VERSION,
			&_ => panic!("The method {} is not implemented yet!", method_context),
		};

		let method: CompressionFormat = match default_version {
			// Version 0 had no compression method so it doesn't go here.
			1 => CompressionFormat::Gzip, // Latest version of emoji/qr is version 1
			2 => CompressionFormat::Zlib, // just for example
			_ => CompressionFormat::Deflate, // just for example
		};

		Header {
			algo: method,
			version: default_version,
		}
	}

	/// Returns a default value to modify without having to manually create a Header
	pub fn new(ver: u8) -> Header {
		let method: CompressionFormat = match ver {
			// Version 0 had no compression method so it doesn't go here.
			1 => CompressionFormat::Gzip, // Latest version of emoji/qr is version 1
			2 => CompressionFormat::Zlib, // just for example
			_ => CompressionFormat::Deflate, // just for example
		};

		Header {
			algo: method,
			version: ver,
		}
	}

	/// Transforms the Header into a string of emojis, transforming only the values of each Header entry, in this case we only have Method and Version
	pub fn to_emoji_string(&self) -> String {
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
	pub fn to_header(emoji_string: String) -> Header {
		// Get the "Encoder" Header -> String_Emoji
		let method2emoji = get_header_dict();
		// Get the "Decoder" reversing the "Encoder" so we have String_Emoji -> Header
		let emoji2method = invert_hashmap(&method2emoji);

		let version_str = emoji2method.get(&emoji_string).unwrap().to_owned();

		// Get the version from str
		let version: u8 = version_str
			.parse()
			.unwrap_or_else(|_| panic!("Invalid version number!"));

		// New header based on version
		let header = Header::new(version);

		header
	}
}
