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

use crate::adapters::SlateSender;
use crate::config::{ImapConfig, SmtpConfig};
use crate::keychain::Keychain;
use crate::libwallet::api_impl::foreign;
use crate::libwallet::api_impl::owner;

use crate::libwallet::{Error, NodeClient, Slate, WalletInst, WalletLCProvider};
use crate::util::secp::key::SecretKey;
use crate::util::Mutex;

extern crate imap;
extern crate native_tls;
use lettre::message::{header::ContentType, Attachment, MultiPart, SinglePart};
use lettre::{
	transport::smtp::authentication::Credentials, AsyncSmtpTransport, AsyncTransport, Message,
	Tokio1Executor,
};

use mail_parser::*;
use serde_json::to_string;

use std::str;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use tokio::runtime::Runtime;

const LISTEN_SLEEP_DURATION: Duration = Duration::from_millis(60000);

/// Receives slates on all channels with topic SLATE_NEW
pub struct SmtpSlateReceiver {}

impl SmtpSlateReceiver {
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
		let server = imap_config.server.unwrap();
		let username = imap_config.username.unwrap();
		let password = imap_config.password.unwrap();
		let port = imap_config.port.unwrap();
		let inbox = imap_config.inbox.unwrap();
		let smtp_username = smtp_config.username.unwrap();
		let smtp_password = smtp_config.password.unwrap();
		let smtp_server = smtp_config.server.unwrap();
		let reply_subject = imap_config.reply_subject.unwrap();
		let reply_body = imap_config.reply_body.unwrap();

		let mut w_lock = wallet.lock();
		let lc = w_lock.lc_provider()?;
		let w_inst = lc.wallet_inst()?;
		let mask = keychain_mask.lock();

		let tls = native_tls::TlsConnector::builder().build().unwrap();
		let smtp_credentials = Credentials::new(smtp_username, smtp_password);
		let mailer: AsyncSmtpTransport<Tokio1Executor> =
			AsyncSmtpTransport::<Tokio1Executor>::relay(&smtp_server)
				.unwrap()
				.credentials(smtp_credentials)
				.build();

		// +> connect to imap and listen on mailbox "INBOX.EPICASH" for transactions
		// we pass in the domain twice to check that the server's TLS
		// certificate is valid for the domain we're connecting to.
		let client = imap::connect((server.clone(), port), server, &tls).unwrap();
		let mut imap_session = client.login(username, password).map_err(|e| e.0).unwrap();

		//start listen
		loop {
			// fetch every unread message in INBOX.EPICCASH
			// if the inbox does not exist, create it
			let mailbox = match imap_session.select(inbox.clone()) {
				Ok(mailbox) => {
					info!("Get unread messages from mailbox {:?}", inbox);
					mailbox
				}
				Err(_) => match imap_session.create(inbox.clone()) {
					Ok(created) => {
						let mailbox = imap_session.select(inbox.clone()).expect("no mailbox");
						info!("Created epiccash mailbox: {:?}", created);
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
				let messages = match imap_session
					.fetch(uid.to_string(), "(RFC822 ENVELOPE INTERNALDATE UID)")
				{
					Ok(ms) => ms,
					Err(e) => {
						error!("{:?}", e);
						break;
					}
				};
				if let Some(message) = messages.iter().next() {
					// extract the message's body
					let body = match message.body() {
						Some(body) => body,
						None => {
							error!("No message body found.");
							break;
						}
					};

					let envelope = match message.envelope() {
						Some(envelope) => envelope,
						None => {
							error!("No envelope in message found.");
							break;
						}
					};

					let from = &envelope.from.as_ref().unwrap()[0];
					let to = &envelope.to.as_ref().unwrap()[0];

					let message = MessageParser::default().parse(body).unwrap();
					let attachment = message.attachment(0).unwrap();

					let content = str::from_utf8(attachment.contents()).unwrap();

					let slate = match Slate::deserialize_upgrade(&content) {
						Ok(ms) => ms,
						Err(e) => {
							error!("{:?}", e);
							break;
						}
					};

					if let Err(e) = slate.verify_messages() {
						error!("Error validating participant messages: {}", e);
						break;
					}

					if slate.num_participants > slate.participant_data.len() {
						match foreign::receive_tx(
							&mut **w_inst,
							(mask).as_ref(),
							&slate,
							None,
							None,
							false,
						) {
							Ok(slate) => {
								//reply with tx response
								let address_to = lettre::Address::new(
									std::str::from_utf8(from.mailbox.unwrap()).unwrap(),
									std::str::from_utf8(from.host.unwrap()).unwrap(),
								);

								let address_from = lettre::Address::new(
									std::str::from_utf8(to.mailbox.unwrap()).unwrap(),
									std::str::from_utf8(to.host.unwrap()).unwrap(),
								);

								let mailbox_to =
									lettre::message::Mailbox::new(None, address_to.unwrap());
								let mailbox_from =
									lettre::message::Mailbox::new(None, address_from.unwrap());

								debug!("slate id: {:?}", slate.id);
								let filename = slate.id.to_string() + ".tx.response";
								let content_type =
									ContentType::parse("application/octet-stream").unwrap();

								let email = Message::builder()
									.from(mailbox_from)
									.to(mailbox_to)
									.subject(reply_subject.clone())
									.multipart(
										MultiPart::mixed().multipart(
											MultiPart::related()
												.singlepart(SinglePart::html(String::from(
													reply_body.to_string(),
												)))
												.singlepart(Attachment::new(filename).body(
													to_string(&slate).unwrap(),
													content_type,
												)),
										),
									)
									.unwrap();

								let rt = Runtime::new().unwrap();
								let _ = rt.block_on(async {
									let test = mailer.send(email).await;
									debug!("send mail {:?}", test);
								});
							}
							Err(e) => {
								error!("Incoming tx failed with error: {}", e);
							}
						};
					} else {
						info!("Finalize transaction (owner::finalize_tx)");
						let slate = owner::finalize_tx(&mut **w_inst, (mask).as_ref(), &slate)?;

						info!("Post transaction to the network (owner::post_tx)");
						owner::post_tx(w_inst.w2n_client(), &slate.tx, false)?;
					}
				} else {
					info!("No new messages found.");
				}
			} else {
				info!("No new messages found.");
			}

			sleep(LISTEN_SLEEP_DURATION);
		}

		imap_session.logout().unwrap();
		//close listener
		Ok(())
	}
}

#[derive(Clone)]
pub struct SmtpSlateSender {
	mailer: AsyncSmtpTransport<Tokio1Executor>,
	to: String,
	from: String,
	subject: String,
	body: String,
}

impl SmtpSlateSender {
	pub fn new(
		to: String,
		smtp_config: Option<SmtpConfig>,
	) -> Result<SmtpSlateSender, Box<dyn std::error::Error>> {
		let config = smtp_config.unwrap();
		let smtp_username = config.username.unwrap();
		let smtp_password = config.password.unwrap();
		let smtp_server = config.server.unwrap();
		let subject = config.subject.unwrap();
		let body = config.body.unwrap();

		let smtp_credentials = Credentials::new(smtp_username, smtp_password);

		let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay(&smtp_server)?
			.credentials(smtp_credentials)
			.build();

		let from = config.from_address.unwrap();

		Ok(SmtpSlateSender {
			mailer,
			to,
			from,
			subject,
			body,
		})
	}
}
impl SlateSender for SmtpSlateSender {
	fn send_tx(&self, slate: &Slate) -> Result<Slate, Error> {
		let from = self.from.clone();
		let to = self.to.clone();
		let subject = self.subject.clone();
		let body = self.body.clone();

		debug!("slate id: {:?}", slate.id);
		let filename = slate.id.to_string() + ".tx";

		let content_type = ContentType::parse("application/octet-stream").unwrap();
		let email = Message::builder()
			.from(from.parse().unwrap())
			.to(to.parse().unwrap())
			.subject(subject)
			.multipart(
				MultiPart::mixed().multipart(
					MultiPart::related()
						.singlepart(SinglePart::html(String::from(body.to_string())))
						.singlepart(
							Attachment::new(filename)
								.body(to_string(&slate).unwrap(), content_type),
						),
				),
			)
			.unwrap();

		let rt = Runtime::new().unwrap();
		let _ = rt.block_on(async {
			let mailsend = self.mailer.send(email).await;
			info!("Mail send: {:?}", mailsend);
		});

		Ok(slate.clone())
	}
}
