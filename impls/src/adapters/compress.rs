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
