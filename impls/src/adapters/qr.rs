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

/// The default method to compress and decompress in this version of Epic
const COMPRESS_METHOD: CompressionFormat = CompressionFormat::Gzip;

#[derive(Clone)]
pub struct QrToSlate(pub PathBuf);

fn save2qr(data: &str, path_save: &str) {
	let compressed_data = compress(data, mode);

	//let data_compressed = compress(data, COMPRESS_METHOD);
	//println!("Data Compressed: {:?}", data_compressed.len());
	// Encode some data into bits.
	let code = QrCode::new(data).unwrap();
	println!("--2");
	// Render the bits into an image.

	//let b = code.to_colors();

	let img = code.render::<Luma<u8>>().build();
	println!("--3");
	// Save the image.
	img.save(path_save).unwrap();
	println!("--4");
}

fn read_qr_2(path_read: &PathBuf) -> String {
	// open the image from disk
	let img = image::open(path_read).expect("failed to open image");

	// convert to gray scale
	let img_gray = img.into_luma8();

	// create a decoder
	let mut decoder = quircs::Quirc::default();

	// identify all qr codes
	let codes = decoder.identify(
		img_gray.width() as usize,
		img_gray.height() as usize,
		&img_gray,
	);

	for code in codes {
		let code = code.expect("failed to extract qr code");
		let decoded = code.decode().expect("failed to decode qr code");
		println!("qrcode: {}", std::str::from_utf8(&decoded.payload).unwrap());
	}

	String::from("aa")
}

// fn read_qr(path_read: &PathBuf) -> String {
// 	println!("==1");
// 	// Load the PNG image
// 	let img = image::open(path_read).unwrap().to_rgb8();

// 	println!("==2: {:?}", img.to_vec().len());
// 	// Convert the PNG image to a 2D binary matrix representation of the QR code
// 	let qr_matrix = QrCode::new(img.to_vec()).unwrap();
// 	println!("==3");
// 	// Get the data encoded in the QR code
// 	let string = qr_matrix.render().light_color(' ').dark_color('#').build();
// 	println!("==4");
// 	println!("QR code data: {}", string);

// 	string
// }

impl SlatePutter for QrToSlate {
	fn put_tx(&self, slate: &Slate) -> Result<(), Error> {
		println!("-1");
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
		println!("-2");
		let slate_json = serde_json::to_string(&out_slate).map_err(|_| ErrorKind::SlateSer)?;
		println!("-3");
		let slate_bytes = slate_json.as_bytes();
		println!("-4");
		let path_save = self.0.to_str().unwrap(); //"Test_QR.png";
		println!("-5, path: {:?}", path_save);
		save2qr(&slate_json, path_save);
		println!("-6");
		Ok(())
	}
}

impl SlateGetter for QrToSlate {
	fn get_tx(&self) -> Result<Slate, Error> {
		println!("=1");
		let path = &self.0; //.to_str().unwrap();
		println!("=2, path: {:?}", path);
		let pub_tx_f = read_qr_2(path);
		println!("=3");
		Ok(Slate::deserialize_upgrade(&pub_tx_f)?)
	}
}
