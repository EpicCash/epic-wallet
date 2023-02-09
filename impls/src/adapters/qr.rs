// Copyright 2019 The Epic Developers
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

//use image::{ImageBuffer, Rgb};
use super::compress::{compress, decompress, CompressionFormat};
/// File Output 'plugin' implementation
use crate::libwallet::{Error, ErrorKind, Slate, SlateVersion, VersionedSlate};
use crate::{SlateGetter, SlatePutter};
use image::Luma;
use qrcode::QrCode;
use quircs;
use std::path::PathBuf;

/// The default version of the QR in this version of Epic
const QR_VERSION: u8 = 1;

const LIMIT_QR_BIN: f32 = 2330.0;

pub const RESPONSE_EXTENTION: &str = "response_";

/// Saves all information and the type of compressor and which version of the epic for the emoji we are using
struct QrHeader {
	/// Method to compress/decompress
	algo: CompressionFormat,
	/// Version of emoji in Epic
	version: u8,
}

/// Implementations that help handle Header in code
impl QrHeader {
	/// Returns a default value to modify without having to manually create a Header
	fn default() -> QrHeader {
		let method: CompressionFormat = match QR_VERSION {
			// Version 0 had no compression method so it doesn't go here.
			1 => CompressionFormat::Gzip,    // Latest version of emoji is version 1
			2 => CompressionFormat::Zlib,    // just for example
			_ => CompressionFormat::Deflate, // just for example
		};

		QrHeader {
			algo: method,
			version: QR_VERSION,
		}
	}

	/// Returns a default value to modify without having to manually create a Header
	fn new(ver: u8) -> QrHeader {
		let method: CompressionFormat = match ver {
			// Version 0 had no compression method so it doesn't go here.
			1 => CompressionFormat::Gzip,    // Latest version of emoji is version 1
			2 => CompressionFormat::Zlib,    // just for example
			_ => CompressionFormat::Deflate, // just for example
		};

		QrHeader {
			algo: method,
			version: ver,
		}
	}
}

#[derive(Clone)]
pub struct QrToSlate(pub PathBuf);

/// This function will receive a skateboard as a `data` and save the QR code in image format based on `path_save`
fn save2qr(data: &str, path_save: &str, receive_op: bool) {
	// Header that will define the compression algorithm
	let header = QrHeader::default();

	// Compressing the data
	let compressed_data = compress(data.as_bytes(), header.algo);

	// Adding the QR code version at the beginning of the vector
	let mut compressed_data_header: Vec<u8> = vec![QR_VERSION as u8];

	// Adding the compressed data
	compressed_data_header.extend(compressed_data);

	// The response file is larger than send, so we limit to different scales
	let scalar: f32 = if receive_op { 1.0 } else { 5.0 / 9.0 };

	let num_out = data.matches("commit").count();
	let num_ele: f32 = compressed_data_header.len() as f32;

	// If have more than 4 commits => use more than 2 outputs to generate, because of that the QR can't be generated
	// Also, the limit to QR is 2335 elements, so the response file is almost 1.8 = 9/5 biggest than the Send slate_json.
	// So we limit the message size to be sent by 5 / 9 = length / (9/5)
	if num_out > 3 || num_ele > LIMIT_QR_BIN * scalar {
		panic!(
			"DataTooLong to generate the QR code! Try to perform the transaction by another method.\n
			The size of compressed Slate is: {:?}
			The number of Outputs used is: {:?}",
			num_ele,
			num_out,
		);
	}

	// Encode the data into bits
	let code = QrCode::new(compressed_data_header).unwrap();

	// Generate the image
	let img = code.render::<Luma<u8>>().build();

	// Save the image
	img.save(path_save).unwrap();
}

/// This function will read an image and get all the QR code written and will transcribe it into a binary vector and at the end it will return the slate_json
fn read_qr(path_read: &PathBuf) -> String {
	// Open the image from disk
	let img = image::open(path_read).expect("failed to open image");

	// Convert to gray scale
	let img_gray = img.into_luma8();

	// Create a decoder
	let mut decoder = quircs::Quirc::default();

	// Identify all qr codes
	let codes = decoder.identify(
		img_gray.width() as usize,
		img_gray.height() as usize,
		&img_gray,
	);

	// All qr into the image
	let mut all_qr: Vec<u8> = Vec::new();

	// For all code into the codes
	for code in codes {
		// Get the Code struct
		let code = code.expect("failed to extract qr code");

		// Make the decoding process
		let decoded = code.decode().expect("failed to decode qr code");

		// Get the compressed data
		let compressed_data = decoded.payload;

		// Save
		all_qr.extend(compressed_data);
	}

	// Get the version of QR
	let version = all_qr[0];

	// Get the compressed data
	let compressed_data = all_qr[1..].to_vec();

	// Defines the Header to get the compression algorithm
	let header = QrHeader::new(version);

	// Decompress the data
	let decompress_data = decompress(&compressed_data, header.algo);

	// Return the slate_json
	decompress_data
}

impl SlatePutter for QrToSlate {
	fn put_tx(&self, slate: &Slate) -> Result<(), Error> {
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
		let slate_json = serde_json::to_string(&out_slate).map_err(|_| ErrorKind::SlateSer)?;

		let path_save = self.0.to_str().unwrap();

		// If have response_ in the path => it's
		let receive_op = path_save.contains(RESPONSE_EXTENTION);

		// Save the slate_json into a QR image
		save2qr(&slate_json, path_save, receive_op);

		Ok(())
	}
}

impl SlateGetter for QrToSlate {
	fn get_tx(&self) -> Result<Slate, Error> {
		let path = &self.0;
		// Read the QR code and return the slate_json
		let pub_tx_f = read_qr(path);
		Ok(Slate::deserialize_upgrade(&pub_tx_f)?)
	}
}
