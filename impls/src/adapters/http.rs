// Copyright 2026 The Epic Cash Developers
// Copyright 2019 The Grin Developers
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

/// HTTP Wallet 'plugin' implementation
use crate::client_utils::{Client, ClientError};
use crate::libwallet::slate_versions::{SlateVersion, VersionedSlate};
use crate::libwallet::{Error, Slate};
use crate::SlateSender;
use serde::Serialize;
use serde_json::{json, Value};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

fn parse_version_response(response: &str) -> Result<SlateVersion, Error> {
    let response: Value = serde_json::from_str(response)
        .map_err(|err| Error::ClientCallback(format!("Invalid version response: {}", err)))?;
    if response["error"] != json!(null) {
        return Err(Error::ClientCallback(format!(
            "Posting transaction: Error: {}, Message: {}",
            response["error"]["code"], response["error"]["message"]
        )));
    }

    let result = response
        .get("result")
        .and_then(|result| result.get("Ok"))
        .ok_or_else(|| Error::ClientCallback("Version response is missing result.Ok".into()))?;
    let foreign_api_version: u16 = serde_json::from_value(
        result
            .get("foreign_api_version")
            .cloned()
            .ok_or_else(|| {
                Error::ClientCallback("Version response is missing foreign_api_version".into())
            })?,
    )
    .map_err(|err| Error::ClientCallback(format!("Invalid foreign API version: {}", err)))?;
    let supported_slate_versions: Vec<String> = serde_json::from_value(
        result
            .get("supported_slate_versions")
            .cloned()
            .ok_or_else(|| {
                Error::ClientCallback("Version response is missing supported_slate_versions".into())
            })?,
    )
    .map_err(|err| Error::ClientCallback(format!("Invalid slate version list: {}", err)))?;

    if foreign_api_version < 2 {
        return Err(Error::ClientCallback(
            "Other wallet reports unrecognized API format.".into(),
        ));
    }
    if supported_slate_versions.contains(&"V3".to_owned()) {
        return Ok(SlateVersion::V3);
    }
    if supported_slate_versions.contains(&"V2".to_owned()) {
        return Ok(SlateVersion::V2);
    }
    Err(Error::ClientCallback(
        "Unable to negotiate slate format with other wallet.".into(),
    ))
}

fn parse_slate_response(response: &str) -> Result<Slate, Error> {
    let response: Value = serde_json::from_str(response)
        .map_err(|err| Error::ClientCallback(format!("Invalid slate response: {}", err)))?;
    if response["error"] != json!(null) {
        return Err(Error::ClientCallback(format!(
            "Posting transaction slate: Error: {}, Message: {}",
            response["error"]["code"], response["error"]["message"]
        )));
    }
    let slate = response
        .get("result")
        .and_then(|result| result.get("Ok"))
        .ok_or_else(|| Error::ClientCallback("Slate response is missing result.Ok".into()))?;
    let slate = serde_json::to_string(slate)?;
    Slate::deserialize_upgrade(&slate)
}

#[derive(Clone)]
pub struct HttpSlateSender {
    base_url: String,
    is_node_synced: Arc<AtomicBool>,
}

impl HttpSlateSender {
    /// Create, return Err if scheme is not "http"
    pub fn new(
        base_url: &str,
        is_node_synced: Arc<AtomicBool>,
    ) -> Result<HttpSlateSender, SchemeNotHttp> {
        if !base_url.starts_with("http") && !base_url.starts_with("https") {
            Err(SchemeNotHttp)
        } else {
            Ok(HttpSlateSender {
                base_url: base_url.to_owned(),
                is_node_synced,
            })
        }
    }

    /// Check version of the listening wallet
    fn check_other_version(&self, url: &str) -> Result<SlateVersion, Error> {
        let req = json!({
            "jsonrpc": "2.0",
            "method": "check_version",
            "id": 1,
            "params": []
        });

        let res: String = self.post(url, None, req).map_err(|e| {
            let mut report = format!("Performing version check (is recipient listening?): {}", e);
            let err_string = format!("{}", e);
            if err_string.contains("404") {
                // Report that the other version of the wallet is out of date
                report = format!(
                    "Other wallet is incompatible and requires an upgrade. \
					 Please urge the other wallet owner to upgrade and try the transaction again."
                );
            }
            error!("{}", report);
            Error::ClientCallback(report)
        })?;

        trace!("Response: {}", res);
        parse_version_response(&res)
    }

    fn post<IN>(
        &self,
        url: &str,
        api_secret: Option<String>,
        input: IN,
    ) -> Result<String, ClientError>
    where
        IN: Serialize,
    {
        let client = Client::new()
            .map_err(|_| ClientError::Internal("Unable to create http client".into()))?;
        let req = client.create_post_request(url, api_secret, &input)?;
        let res = client.send_request(req)?;
        Ok(res)
    }
}

impl SlateSender for HttpSlateSender {
    fn send_tx(&self, slate: &Slate) -> Result<Slate, Error> {
        if !self
            .is_node_synced
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(Error::ClientCallback("Node not synchronized".into()));
        }

        let trailing = match self.base_url.ends_with('/') {
            true => "",
            false => "/",
        };
        let url_str = format!("{}{}v2/foreign", self.base_url, trailing);

        let slate_send = match self.check_other_version(&url_str)? {
            SlateVersion::V3 => VersionedSlate::into_version(slate.clone(), SlateVersion::V3),
            SlateVersion::V2 => {
                let mut slate = slate.clone();
                if let Some(_) = slate.payment_proof {
                    return Err(Error::ClientCallback("Payment proof requested, but other wallet does not support payment proofs. Please urge other user to upgrade, or re-send tx without a payment proof".into()).into());
                }
                if let Some(_) = slate.ttl_cutoff_height {
                    warn!("Slate TTL value will be ignored and removed by other wallet, as other wallet does not support this feature. Please urge other user to upgrade");
                }
                slate.version_info.version = 2;
                slate.version_info.orig_version = 2;
                VersionedSlate::into_version(slate, SlateVersion::V2)
            }
        };
        // Note: not using easy-jsonrpc as don't want the dependencies in this crate
        let req = json!({
            "jsonrpc": "2.0",
            "method": "receive_tx",
            "id": 1,
            "params": [
                        slate_send,
                        null,
                        null,
                        null,
            ]
        });
        trace!("Sending receive_tx request: {}", req);

        let res: String = self.post(&url_str, None, req).map_err(|e| {
            let report = format!("Posting transaction slate (is recipient listening?): {}", e);
            error!("{}", report);
            Error::ClientCallback(report)
        })?;

        trace!("Response: {}", res);
        parse_slate_response(&res)
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct SchemeNotHttp;

impl Into<Error> for SchemeNotHttp {
    fn into(self) -> Error {
        let err_str = format!("url scheme must be http",);
        Error::GenericError(err_str).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::libwallet::Slate;

    #[test]
    fn test_send_tx_node_not_synced() {
        let is_node_synced = Arc::new(AtomicBool::new(false));
        let sender =
            HttpSlateSender::new("http://localhost:13415", is_node_synced.clone()).unwrap();

        let dummy_slate = Slate::blank(2); // or construct a minimal valid Slate for your context

        let result = sender.send_tx(&dummy_slate);

        assert!(result.is_err());
        let err_str = format!("{:?}", result.err().unwrap());
        assert!(err_str.contains("Node not synchronized"));
    }

    #[test]
    fn malformed_remote_responses_return_errors() {
        for response in [
            "not json",
            r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":{"Ok":{"foreign_api_version":"bad","supported_slate_versions":[]}}}"#,
        ] {
            assert!(parse_version_response(response).is_err());
        }

        for response in [
            "not json",
            r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":{"Ok":{}}}"#,
        ] {
            assert!(parse_slate_response(response).is_err());
        }
    }
}
