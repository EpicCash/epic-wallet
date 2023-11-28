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

use crate::adapters::{SlateReceiver, SlateSender};
use crate::config::{ImapConfig, SmtpConfig};
use crate::keychain::Keychain;
/// SMTP Wallet 'plugin' implementation
use crate::libwallet::slate_versions::{SlateVersion, VersionedSlate};
use crate::libwallet::{Error, NodeClient, Slate, WalletInst, WalletLCProvider};

use crate::util::secp::key::SecretKey;
use crate::util::Mutex;

extern crate imap;
extern crate native_tls;
use lettre::{
	transport::smtp::authentication::Credentials, AsyncSmtpTransport, AsyncTransport, Message,
	Tokio1Executor,
};

use serde_json::json;

use mail_parser::*;
use std::str;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use tokio::runtime::Runtime;

const LISTEN_SLEEP_DURATION: Duration = Duration::from_millis(10000);

/// Receives slates on all channels with topic SLATE_NEW
pub struct SmtpSlateReceiver {}

impl SmtpSlateReceiver {
	/// Create a KeybaseAllChannels, return error if keybase executable is not present
	pub fn new() -> Result<SmtpSlateReceiver, Box<dyn std::error::Error>> {
		Ok(SmtpSlateReceiver {})
	}
}
impl SmtpSlateReceiver {
	pub fn listen<L, C, K>(
		&self,
		wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
		keychain_mask: Arc<Mutex<Option<SecretKey>>>,
		imap_config: ImapConfig,
		smtp_config: SmtpConfig,
	) -> Result<(), Error>
	where
		L: WalletLCProvider<'static, C, K> + 'static,
		C: NodeClient + 'static,
		K: Keychain + 'static,
	{
		//info!("imap config {:?}", imap_config);
		//info!("smtp config: {:?}", smtp_config);
		let server = imap_config.server.unwrap();
		let username = imap_config.username.unwrap();
		let password = imap_config.password.unwrap();
		let port = imap_config.port.unwrap();
		let inbox = imap_config.inbox.unwrap();

		let tls = native_tls::TlsConnector::builder().build().unwrap();

		// we pass in the domain twice to check that the server's TLS
		// certificate is valid for the domain we're connecting to.
		let client = imap::connect((server.clone(), port), server, &tls).unwrap();

		// the client we have here is unauthenticated.
		// to do anything useful with the e-mails, we need to log in
		let mut imap_session = client.login(username, password).map_err(|e| e.0).unwrap();

		loop {
			// we want to fetch the first email in the INBOX mailbox
			let mailbox = match imap_session.select(inbox.clone()) {
				Ok(mailbox) => {
					info!("select epiccash mailbox");
					mailbox
				}
				Err(_) => match imap_session.create(inbox.clone()) {
					Ok(created) => {
						let mailbox = imap_session.select(inbox.clone()).expect("no mailbox");
						info!("created epiccash mailbox: {:?}", created);
						mailbox
					}
					Err(e) => {
						error!("{:?}", e);
						break;
					}
				},
			};

			if let Some(uid) = mailbox.unseen {
				// fetch message number 1 in this mailbox, along with its RFC822 field.
				// RFC 822 dictates the format of the body of e-mails
				let messages = match imap_session.fetch(uid.to_string(), "RFC822") {
					Ok(ms) => ms,
					Err(e) => {
						error!("{:?}", e);
						break;
					}
				};
				if let Some(message) = messages.iter().next() {
					// extract the message's body
					let body = message.body().expect("message did not have a body!");
					/*let body = std::str::from_utf8(body)
					.expect("message was not valid utf-8")
					.to_string();*/
					let message = MessageParser::default().parse(body).unwrap();
					let attachment = message.attachment(0).unwrap();

					//info!("mail parsed nested_attachment {:?}", attachment.body);
					//info!("{:?}", body);

					let content = str::from_utf8(attachment.contents()).unwrap();
					info!("parsed string content {:?}", content);
					let slate = match Slate::deserialize_upgrade(&content) {
						Ok(ms) => ms,
						Err(e) => {
							error!("{:?}", e);
							break;
						}
					};
					info!("received slate: {:?}", slate);
				} else {
					info!("No new messages found");
				}
			} else {
				info!("No new messages found");
			}

			sleep(LISTEN_SLEEP_DURATION);
		}

		// be nice to the server and log out
		imap_session.logout().unwrap();
		Ok(())
	}
}

#[derive(Clone)]
pub struct SmtpSlateSender {
	mailer: AsyncSmtpTransport<Tokio1Executor>,
}

impl SmtpSlateSender {
	/// Create, return Err if scheme is not "smtp"
	pub fn new(
		smtp_username: String,
		smtp_password: String,
	) -> Result<SmtpSlateSender, Box<dyn std::error::Error>> {
		let smtp_credentials = Credentials::new(smtp_username, smtp_password);

		let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay("")?
			.credentials(smtp_credentials)
			.build();

		Ok(SmtpSlateSender { mailer })
	}
	async fn send_email_smtp(&self, from: &str, to: &str, subject: &str, body: String) -> bool {
		let email = Message::builder()
			.from(from.parse().unwrap())
			.to(to.parse().unwrap())
			.subject(subject)
			.body(body.to_string())
			.unwrap();

		let _ = self.mailer.send(email).await;

		true
	}
}
impl SlateSender for SmtpSlateSender {
	fn send_tx(&self, slate: &Slate) -> Result<Slate, Error> {
		// set up tor send process if needed
		let from = "Hello World <hello@world.com>";
		let to = "42 <42@42.com>";
		let subject = "Hello World";
		let body = "<h1>Hello World</h1>".to_string();

		let slate_send = VersionedSlate::into_version(slate.clone(), SlateVersion::V3);
		// Note: not using easy-jsonrpc as don't want the dependencies in this crate
		let req = json!({
			"jsonrpc": "2.0",
			"method": "receive_tx",
			"id": 1,
			"params": [
						slate_send,
						null,
						null
					]
		});
		trace!("Sending receive_tx request: {}", req);
		let mut rt = Runtime::new().unwrap();

		let future = self.send_email_smtp(from, to, subject, body);
		let _ = rt.block_on(future);

		Ok(slate.clone())
	}
}
