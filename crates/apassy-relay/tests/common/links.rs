//! Public links in the tests (connect-share-v1): the contract vectors, creation bodies, and
//! a request that answers its headers too. Synthetic values only.
#![allow(dead_code)]

use std::time::Duration;

use apassy_relay::hostkeys::{decode_b64, encode_b64};
use serde_json::{Value, json};

const VECTORS: &str = include_str!("../../../../tests/fixtures/connect-share-v1/link-vectors.json");

/// The link vectors of the contract.
pub fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("vectors")
}

/// The vector link named `name` (`anyone`, `one_time_emails`).
pub fn vector(name: &str) -> Value {
    vectors()["links"]
        .as_array()
        .expect("links")
        .iter()
        .find(|link| link["name"] == name)
        .cloned()
        .expect("vector")
}

/// The creation body of the vector `name`, expiring `expires_in` seconds from now (the
/// vectors' own expiry is in the past; Connect does not read the binding).
pub fn vector_body(name: &str, expires_in: u64) -> Value {
    let mut body = vector(name)["create"].clone();
    body["expires_at"] = json!(apassy_relay::now_unix() + expires_in);
    body
}

/// A new link id: 32 lowercase hex.
pub fn new_link_id() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).unwrap();
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A sealed form of `blocks` KiB of plaintext: random bytes of the right length.
pub fn sealed(blocks: usize) -> String {
    let mut bytes = vec![0u8; 12 + blocks * 1024 + 16];
    getrandom::fill(&mut bytes).unwrap();
    encode_b64(&bytes)
}

/// The body of a new link for anyone with a random id.
pub fn anyone_body(one_time: bool, expires_in: u64) -> Value {
    json!({"link_id": new_link_id(), "sealed": sealed(1),
           "expires_at": apassy_relay::now_unix() + expires_in, "one_time": one_time,
           "access": "anyone", "address_hashes": []})
}

/// The address hashes of `addresses` under the address key of the vector `name`.
pub fn hashes_for(name: &str, addresses: &[&str]) -> Vec<String> {
    let key = address_key(name);
    addresses
        .iter()
        .map(|address| {
            let normal = apassy_relay::server::links::normal_address(address).expect("address");
            apassy_relay::server::links::address_hash(&key, &normal)
        })
        .collect()
}

/// The address key of the vector `name` (32 bytes).
pub fn address_key(name: &str) -> Vec<u8> {
    decode_b64(vector(name)["address_key_b64u"].as_str().unwrap(), 32).unwrap()
}

/// The body of `open` without a code.
pub fn open_body(confirm: bool) -> Value {
    json!({"confirm": confirm, "email": null, "address_key": null, "code": null})
}

/// A request with the edge header and `headers`: the status, the answer's headers
/// (lowercase names), and the body.
pub fn call_with_headers(
    base: &str,
    edge: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&Value>,
) -> (u16, Vec<(String, String)>, String) {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(60)))
        .build()
        .into();
    let mut builder = ureq::http::Request::builder()
        .method(method)
        .uri(format!("{base}{path}"))
        .header("X-Apassy-Edge", edge);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let bytes = match body {
        Some(body) => {
            builder = builder.header("Content-Type", "application/json");
            serde_json::to_vec(body).expect("json")
        }
        None => Vec::new(),
    };
    let mut response = agent
        .run(builder.body(bytes).expect("request"))
        .expect("http call");
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_ascii_lowercase(),
                value.to_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    let text = response.body_mut().read_to_string().unwrap_or_default();
    (status, headers, text)
}

/// The value of the header `name` (lowercase) in `headers`.
pub fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}
