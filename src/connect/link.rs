//! Public links (ADR 0047 section 4, release A; contract
//! [connect-share-v1](../../docs/contracts/connect-share-v1.md)): the snapshot of a
//! secret or a folder, sealed with a fresh key `K` that only the link holds, and the calls
//! that keep, list, and revoke it at Connect.
//!
//! The steps, in order:
//!
//! 1. [`PendingLink::prepare`] reads the snapshot from the vault (names, fields, notes;
//!    never a one-time-code seed, a passkey, an archived credential, a received one, or
//!    the history), pads it to a multiple of 1 KiB, and refuses one over 32 KiB **before
//!    the owner check**, with how many of the secrets fit ([`LinkError::TooLarge`]). It
//!    checks the origin (`https:` only, `http:` only on loopback) and the addresses (their
//!    normal form, section 6), then seals with a fresh `K`.
//! 2. The app asks the owner check [`PendingLink::action`] (`CreatePublicLink`, which
//!    names the secrets, the expiry, "show once", the access mode, and the addresses;
//!    the "how often to ask" window never covers it).
//! 3. [`ConnectAccount::create_public_link`] checks the proof and sends the body. The
//!    pending link keeps the **exact** body (the same `K`, the same sealed form) until an
//!    answer comes: [`ConnectAccount::send_public_link`] repeats it after a failure that
//!    gave no answer. A `409 conflict` reads the list: a link that is listed was made;
//!    one that is not was not ([`LinkError::NotMade`]), and a new try is a new `K`.
//! 4. The answer is a [`LinkCreated`] receipt; [`LinkCreated::apply`] writes the vault
//!    row (with `K` and the account) and the history. Only a receipt writes a row. The app
//!    writes it with [`ConnectAccount::keep_or_revoke`] on the step that made the link:
//!    when the row cannot be written (a lock, another vault), that step revokes the new
//!    link at Connect at once, so no live link is left that no device can copy.
//! 5. [`ConnectAccount::revoke_public_link`] deletes the link at Connect for the account
//!    that made it. A `200`, or a `404` for its own link that carries the marker of the
//!    links routes ([`LINKS_MARKER`]), is a [`LinkRevoked`] receipt; only
//!    [`LinkRevoked::apply`] writes the revoke. A `404` without the marker (a relay
//!    without the routes, such as an older image after a rollback), any other answer,
//!    and no answer write nothing ([`LinkError::NotConfirmed`], "Try Again").
//! 6. A relay without the links routes (an older or a self-hosted image) answers
//!    `GET /v1/account/links` and `POST /v1/account/links` with a `404` without the
//!    marker: that is [`LinkError::NoLinks`], and the app offers no link there.
//!
//! `K` is erased on drop, never in a `Debug` text or a log, and leaves this module only
//! in the link text ([`link_text`]).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ring::{aead, hkdf, hmac};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{ConnectAccount, ConnectError};
use crate::broker::approvals::{OwnerAction, OwnerProof};
use crate::contracts::CredentialKind;
use crate::vault::{
    Folder, LinkRoot, MAX_LINK_ADDRESSES, NewPublicLink, PublicLink, Vault, VaultErrorKind,
    is_passkey_field, is_setup_key_field,
};

/// HKDF info of the link id (section 3).
pub const TAG_ID: &str = "apassy-connect public-link id v1";
/// HKDF info of the seal key.
pub const TAG_KEY: &str = "apassy-connect public-link key v1";
/// HKDF info of the address key.
pub const TAG_ADDRESS: &str = "apassy-connect public-link address v1";
/// The first part of the associated data.
pub const TAG_SEAL: &str = "apassy-connect public-link v1";
/// The plaintext is padded to a multiple of this.
pub const PAD: usize = 1024;
/// The largest padded plaintext.
pub const MAX_PLAINTEXT: usize = 32 * 1024;
/// The most items of a snapshot.
pub const MAX_ITEMS: usize = 100;
/// The most fields of an item.
pub const MAX_FIELDS: usize = 64;
/// The shortest expiry the app offers: 10 minutes.
pub const MIN_EXPIRY: u64 = 10 * 60;
/// The longest expiry: 30 days.
pub const MAX_EXPIRY: u64 = 30 * 24 * 60 * 60;
/// The header that every answer of the links routes carries with the value `1`. A `404`
/// of a revoke is "gone" only with it.
pub const LINKS_MARKER: &str = "x-apassy-links";
/// The default expiry: 7 days.
pub const DEFAULT_EXPIRY: u64 = 7 * 24 * 60 * 60;

const MAX_TITLE_BYTES: usize = 128;
const MAX_NAME_BYTES: usize = 64;

/// What the owner shares: a credential by its ID, or a folder by its UUID.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LinkTarget {
    Item(u64),
    Folder(String),
}

/// The choices of the sheet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkOptions {
    /// Seconds from now, [`MIN_EXPIRY`] to [`MAX_EXPIRY`].
    pub expires_in: u64,
    /// "Show once".
    pub one_time: bool,
    /// `None`: "Anyone with the link". Some: "Only these e-mail addresses", the texts as
    /// typed.
    pub emails: Option<Vec<String>>,
}

impl Default for LinkOptions {
    fn default() -> Self {
        Self {
            expires_in: DEFAULT_EXPIRY,
            one_time: false,
            emails: None,
        }
    }
}

/// Why a link was not made or not revoked. No value holds a key or a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkError {
    /// The Connect origin is not one that a browser opens the link at.
    Origin,
    /// Nothing to share: the folder has no credential that a link may hold.
    Empty,
    /// The credential is archived.
    Archived,
    /// The credential came from someone else.
    Received,
    /// The credential or the folder is gone.
    NotFound,
    /// The snapshot is over 32 KiB or 100 items: `fit` of the `total` secrets fit, in the
    /// order of the list.
    TooLarge { fit: usize, total: usize },
    /// The expiry is outside 10 minutes to 30 days.
    Expiry,
    /// "Only these e-mail addresses" with none, or with more than 20.
    AddressCount,
    /// A text that is not an e-mail address.
    BadAddress(String),
    /// `403 link_limit`: the account has its most live links.
    LinkLimit,
    /// `503 mail_unavailable`: this relay has no mail sender for the code mails.
    MailUnavailable,
    /// The relay has no links routes: a `404` without [`LINKS_MARKER`].
    NoLinks,
    /// Connect took the link, and the vault row could not be written (the vault locked
    /// or another vault opened meanwhile). `revoked`: the link was revoked at Connect at
    /// once; else it is still live there, without a row.
    NotSaved { revoked: bool },
    /// A retry met `409 conflict` and Connect does not list the link: it was not made.
    NotMade,
    /// The link was made by another account; only that account revokes it.
    NotMaker,
    /// Connect answered a revoke with `404` without the marker of the links routes (for
    /// example a relay image without them): the revoke is not done, and the link may
    /// still open.
    NotConfirmed,
    /// Another failure of the call.
    Connect(ConnectError),
    /// The vault could not be read or written.
    Vault,
}

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Origin => f.write_str("Links work only with a Connect that uses HTTPS."),
            Self::Empty => f.write_str("This folder has no secret to share."),
            Self::Archived => f.write_str("An archived secret cannot be shared."),
            Self::Received => {
                f.write_str("A secret that someone shared with you cannot be shared further.")
            }
            Self::NotFound => f.write_str("This secret or folder is gone."),
            Self::TooLarge { fit, total } => write!(
                f,
                "Too large for one link: {fit} of {total} secrets fit. Share fewer."
            ),
            Self::Expiry => f.write_str("A link lasts 10 minutes to 30 days."),
            Self::AddressCount => f.write_str("Add 1 to 20 e-mail addresses."),
            Self::BadAddress(text) => write!(
                f,
                "\u{201c}{}\u{201d} is not an e-mail address.",
                short(text)
            ),
            Self::LinkLimit => {
                f.write_str("This account has its most live links. Revoke one first.")
            }
            Self::MailUnavailable => f.write_str(
                "This relay cannot send e-mail codes. Choose \u{201c}Anyone with the link\u{201d}.",
            ),
            Self::NoLinks => f.write_str("This relay does not offer links."),
            Self::NotSaved { revoked: true } => {
                f.write_str("The link was not saved in the vault, so Apassy revoked it.")
            }
            Self::NotSaved { revoked: false } => f.write_str(
                "The link was not saved in the vault. Revoke it under Links not in this vault.",
            ),
            Self::NotMade => f.write_str("The link was not made. Create it again."),
            Self::NotMaker => {
                f.write_str("Another account made this link. Only that account can revoke it.")
            }
            Self::NotConfirmed => f.write_str(
                "Connect did not confirm the revoke. The link may still open. Try again.",
            ),
            Self::Connect(error) => error.fmt(f),
            Self::Vault => f.write_str("Apassy could not read or write the vault."),
        }
    }
}

impl std::error::Error for LinkError {}

impl From<ConnectError> for LinkError {
    fn from(error: ConnectError) -> Self {
        match &error {
            ConnectError::Refused { status: 403, code } if code == "link_limit" => Self::LinkLimit,
            ConnectError::Refused { status: 503, code } if code == "mail_unavailable" => {
                Self::MailUnavailable
            }
            _ => Self::Connect(error),
        }
    }
}

impl LinkError {
    /// Whether a new try of the same step may work (no answer, or a busy Connect).
    pub fn can_retry(&self) -> bool {
        match self {
            Self::NotConfirmed => true,
            Self::Connect(error) => {
                matches!(
                    error,
                    ConnectError::Offline
                        | ConnectError::Broken
                        | ConnectError::RateLimited(_)
                        | ConnectError::Unauthenticated
                        | ConnectError::SignedOut
                ) || matches!(error, ConnectError::Refused { status, .. } if *status >= 500)
            }
            _ => false,
        }
    }
}

fn short(text: &str) -> String {
    let clean: String = text.chars().filter(|c| !c.is_control()).collect();
    cut(clean.trim(), 64).to_owned()
}

/// `text` cut to at most `max` bytes on a character boundary.
fn cut(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn vault_error(error: crate::vault::VaultError) -> LinkError {
    match error.kind() {
        VaultErrorKind::NotFound => LinkError::NotFound,
        _ => LinkError::Vault,
    }
}

// ---- Origins and addresses. ----

/// The Connect origin of a link, as the app makes no link for any other (section 2):
/// `https://` with a DNS name of the public internet, or `http://localhost` and
/// `http://127.0.0.1` (tests). Not an IP address, a `.onion`, `.local`, `.lan`,
/// `.internal`, `.home.arpa`, or `.localhost` name, and no path.
pub fn link_origin(origin: &str) -> Result<String, LinkError> {
    let origin = origin.trim_end_matches('/');
    if !crate::vault::valid_link_origin(origin) || origin.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(LinkError::Origin);
    }
    if let Some(rest) = origin.strip_prefix("https://") {
        let host = match rest.rsplit_once(':') {
            Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
                host
            }
            _ => rest,
        };
        let private = [
            ".onion",
            ".local",
            ".lan",
            ".internal",
            ".home.arpa",
            ".localhost",
            ".home",
        ];
        let labels: Vec<&str> = host.split('.').collect();
        let last = labels.last().copied().unwrap_or_default();
        if host.starts_with('[')
            || labels.len() < 2
            || host == "localhost"
            || last.bytes().all(|byte| byte.is_ascii_digit())
            || private.iter().any(|suffix| host.ends_with(suffix))
        {
            return Err(LinkError::Origin);
        }
    }
    Ok(origin.to_owned())
}

/// The normal form of an e-mail address (section 6), or `None` when the text is not one.
pub fn normalize_address(text: &str) -> Option<String> {
    let trimmed = text.trim_matches(|c| matches!(c, ' ' | '\t' | '\r' | '\n'));
    let mut parts = trimmed.split('@');
    let (local, domain) = (parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let local_ok = (1..=64).contains(&local.len())
        && local
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~.".contains(&byte));
    if !local_ok || local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return None;
    }
    if domain.is_empty()
        || domain
            .chars()
            .any(|c| c.is_ascii() && !(c.is_ascii_alphanumeric() || c == '.' || c == '-'))
    {
        return None;
    }
    // UTS #46 ToASCII, non-transitional; then one trailing dot goes.
    let ascii = idna::domain_to_ascii(domain).ok()?;
    let domain = ascii.strip_suffix('.').unwrap_or(&ascii);
    let labels: Vec<&str> = domain.split('.').collect();
    if domain.len() > 253 || labels.len() < 2 {
        return None;
    }
    let label_ok = |label: &&str| {
        (1..=63).contains(&label.len())
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    };
    if !labels.iter().all(label_ok) || !labels.last()?.starts_with(|c: char| c.is_ascii_lowercase())
    {
        return None;
    }
    let address = format!("{}@{domain}", local.to_ascii_lowercase());
    (address.len() <= 254).then_some(address)
}

/// The addresses of a text that the owner typed: split at new lines, commas,
/// semicolons, and spaces; each in its normal form, each once, in the order typed.
pub fn parse_addresses(text: &str) -> Result<Vec<String>, LinkError> {
    normal_addresses(text.split(['\n', '\r', ',', ';', ' ', '\t']))
}

fn normal_addresses<'a>(
    texts: impl IntoIterator<Item = &'a str>,
) -> Result<Vec<String>, LinkError> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for text in texts {
        if text.trim().is_empty() {
            continue;
        }
        let address =
            normalize_address(text).ok_or_else(|| LinkError::BadAddress(text.to_owned()))?;
        if seen.insert(address.clone()) {
            out.push(address);
        }
    }
    if out.is_empty() || out.len() > MAX_ADDRESSES {
        return Err(LinkError::AddressCount);
    }
    Ok(out)
}

/// The most addresses of a link.
pub const MAX_ADDRESSES: usize = MAX_LINK_ADDRESSES;

// ---- Keys and the seal (section 3). ----

struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// HKDF-SHA256 of `key` with an empty salt and `info`.
fn derive(key: &[u8], info: &str, len: usize) -> Zeroizing<Vec<u8>> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(key);
    let info = [info.as_bytes()];
    let mut out = Zeroizing::new(vec![0; len]);
    // A length of 16 or 32 bytes always expands.
    if let Ok(okm) = prk.expand(&info, Len(len)) {
        let _ = okm.fill(&mut out);
    }
    out
}

/// The link id of `key`: 32 lowercase hex.
pub fn link_id(key: &[u8]) -> String {
    derive(key, TAG_ID, 16)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The address hash of `normalized` under the address key of `key`.
pub fn address_hash(key: &[u8], normalized: &str) -> String {
    let address_key = derive(key, TAG_ADDRESS, 32);
    let mac = hmac::Key::new(hmac::HMAC_SHA256, &address_key);
    crate::sync::encode_b64u(hmac::sign(&mac, normalized.as_bytes()).as_ref())
}

/// The associated data of section 3.
pub fn associated_data(
    origin: &str,
    link_id: &str,
    expires_at: u64,
    one_time: bool,
    access: &str,
) -> Vec<u8> {
    [
        TAG_SEAL,
        origin,
        link_id,
        &expires_at.to_string(),
        if one_time { "1" } else { "0" },
        access,
    ]
    .join("\0")
    .into_bytes()
}

/// The link text `<origin>/s#v1.<K>`.
pub fn link_text(origin: &str, key: &[u8]) -> Zeroizing<String> {
    Zeroizing::new(format!("{origin}/s#v1.{}", crate::sync::encode_b64u(key)))
}

/// The plaintext of `json`: followed by spaces up to the next multiple of 1 KiB, at least
/// 1 KiB. `None` above 32 KiB.
pub fn pad(json: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let size = json.len().div_ceil(PAD).max(1) * PAD;
    if size > MAX_PLAINTEXT {
        return None;
    }
    let mut out = Zeroizing::new(Vec::with_capacity(size));
    out.extend_from_slice(json);
    out.resize(size, b' ');
    Some(out)
}

/// The sealed form of `plaintext` under the seal key of `key` with `nonce`: the nonce,
/// then the ciphertext and its tag.
pub fn seal(key: &[u8], nonce: [u8; 12], associated: &[u8], plaintext: &[u8]) -> Option<Vec<u8>> {
    let seal_key = derive(key, TAG_KEY, 32);
    let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, &seal_key).ok()?;
    let sealing = aead::LessSafeKey::new(unbound);
    let mut buffer = Zeroizing::new(plaintext.to_vec());
    let tag = sealing
        .seal_in_place_separate_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(associated),
            &mut buffer,
        )
        .ok()?;
    let mut out = Vec::with_capacity(12 + buffer.len() + 16);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&buffer);
    out.extend_from_slice(tag.as_ref());
    Some(out)
}

// ---- The snapshot (section 3). ----

/// One field of a snapshot. The value is erased on drop.
pub struct SnapshotField {
    pub name: String,
    pub value: Zeroizing<String>,
    pub secret: bool,
}

/// One item of a snapshot.
pub struct SnapshotItem {
    /// The credential in the vault (never in the snapshot).
    pub item_id: u64,
    pub title: String,
    pub kind: CredentialKind,
    pub path: Vec<String>,
    pub fields: Vec<SnapshotField>,
    pub notes: Zeroizing<String>,
}

/// What a link shows: names, fields, and notes.
pub struct Snapshot {
    pub title: String,
    pub items: Vec<SnapshotItem>,
}

impl fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Snapshot")
            .field("items", &self.items.len())
            .finish_non_exhaustive()
    }
}

fn kind_name(kind: CredentialKind) -> &'static str {
    match kind {
        CredentialKind::ApiKey => "api_key",
        CredentialKind::Login => "login",
        CredentialKind::SshKey => "ssh_key",
        CredentialKind::Database => "database",
        CredentialKind::Custom => "custom",
    }
}

#[derive(Serialize)]
struct FieldOut<'a> {
    name: &'a str,
    value: &'a str,
    secret: bool,
}

#[derive(Serialize)]
struct ItemOut<'a> {
    title: &'a str,
    kind: &'static str,
    path: &'a [String],
    fields: Vec<FieldOut<'a>>,
    notes: &'a str,
}

#[derive(Serialize)]
struct SnapshotOut<'a> {
    v: u8,
    title: &'a str,
    items: Vec<ItemOut<'a>>,
}

impl Snapshot {
    /// The JSON of the first `count` items, in the field order of the contract.
    fn json(&self, count: usize) -> Zeroizing<Vec<u8>> {
        let out = SnapshotOut {
            v: 1,
            title: &self.title,
            items: self.items[..count.min(self.items.len())]
                .iter()
                .map(|item| ItemOut {
                    title: &item.title,
                    kind: kind_name(item.kind),
                    path: &item.path,
                    fields: item
                        .fields
                        .iter()
                        .map(|field| FieldOut {
                            name: &field.name,
                            value: &field.value,
                            secret: field.secret,
                        })
                        .collect(),
                    notes: &item.notes,
                })
                .collect(),
        };
        let mut buffer = Zeroizing::new(Vec::with_capacity(MAX_PLAINTEXT + PAD));
        // Writing to a vector does not fail.
        let _ = serde_json::to_writer(&mut *buffer, &out);
        buffer
    }

    /// The padded plaintext, or [`LinkError::TooLarge`] with how many items fit.
    pub fn plaintext(&self) -> Result<Zeroizing<Vec<u8>>, LinkError> {
        let total = self.items.len();
        if total <= MAX_ITEMS
            && let Some(padded) = pad(&self.json(total))
        {
            return Ok(padded);
        }
        let mut fit = 0;
        for count in 1..=total.min(MAX_ITEMS) {
            if pad(&self.json(count)).is_none() {
                break;
            }
            fit = count;
        }
        Err(LinkError::TooLarge { fit, total })
    }

    /// Read the snapshot of `target` from the vault.
    pub fn read(vault: &Vault, target: &LinkTarget) -> Result<Self, LinkError> {
        match target {
            LinkTarget::Item(id) => {
                let item = read_item(vault, *id, Vec::new())?;
                Ok(Self {
                    title: item.title.clone(),
                    items: vec![item],
                })
            }
            LinkTarget::Folder(uuid) => read_folder(vault, uuid),
        }
    }
}

/// The owner-facing name of a field, as the app shows it.
fn field_label(name: &str) -> String {
    let label = match name {
        "token" => "Token".to_owned(),
        "password" => "Password".to_owned(),
        "private_key" => "Private key".to_owned(),
        "passphrase" => "Key passphrase".to_owned(),
        "username" => "Username".to_owned(),
        "website" => "Website".to_owned(),
        "host" => "Host".to_owned(),
        "database" => "Database".to_owned(),
        "public_key" => "Public key".to_owned(),
        "service" => "Service".to_owned(),
        "project" => "Project".to_owned(),
        other => crate::vault::custom_detail_label(other).unwrap_or_else(|| other.to_owned()),
    };
    let label = cut(label.trim(), MAX_NAME_BYTES).to_owned();
    if label.is_empty() {
        "Field".to_owned()
    } else {
        label
    }
}

fn title_of(text: &str) -> String {
    let title = cut(text.trim(), MAX_TITLE_BYTES).to_owned();
    if title.is_empty() {
        "Untitled".to_owned()
    } else {
        title
    }
}

/// Whether a credential may be in a link: not archived and not received from someone.
fn shareable(vault: &Vault, id: u64) -> Result<(), LinkError> {
    if vault.is_archived(id).map_err(vault_error)? {
        return Err(LinkError::Archived);
    }
    if vault.item_home(id).map_err(vault_error)?.is_some() {
        return Err(LinkError::Received);
    }
    Ok(())
}

/// One credential: its name, kind, the fields that a link may hold, and its notes.
fn read_item(vault: &Vault, id: u64, path: Vec<String>) -> Result<SnapshotItem, LinkError> {
    shareable(vault, id)?;
    let details = vault.details(id).map_err(vault_error)?;
    let mut fields = Vec::new();
    for field in &details.fields {
        if fields.len() == MAX_FIELDS || is_passkey_field(&field.name) {
            continue;
        }
        let value = match vault.reveal(id, &field.name) {
            Ok(value) => Zeroizing::new(value.expose().to_owned()),
            Err(error) if error.kind() == VaultErrorKind::NotFound => continue,
            Err(error) => return Err(vault_error(error)),
        };
        // A one-time-code seed never leaves in a link, as a hidden detail or a link.
        if is_setup_key_field(&field.name, &value) {
            continue;
        }
        fields.push(SnapshotField {
            name: field_label(&field.name),
            value,
            secret: field.secret,
        });
    }
    Ok(SnapshotItem {
        item_id: id,
        title: title_of(&details.summary.title),
        kind: details.summary.kind,
        path,
        fields,
        notes: Zeroizing::new(details.notes.clone()),
    })
}

/// A folder with its subfolders: each credential once, with its path below the folder,
/// in the order of the paths and then the names. Archived and received credentials stay
/// out.
fn read_folder(vault: &Vault, uuid: &str) -> Result<Snapshot, LinkError> {
    let folders = vault.folders().map_err(vault_error)?;
    let by_uuid: BTreeMap<&str, &Folder> = folders.iter().map(|f| (f.uuid.as_str(), f)).collect();
    let root = by_uuid.get(uuid).ok_or(LinkError::NotFound)?;
    // The path of `folder` below the shared folder, or `None` outside it.
    let below = |folder: &str| -> Option<Vec<String>> {
        let mut names = Vec::new();
        let mut at = folder;
        let mut steps = 0;
        while at != uuid {
            let entry = by_uuid.get(at)?;
            names.push(cut(entry.name.trim(), MAX_NAME_BYTES).to_owned());
            at = entry.parent.as_deref()?;
            steps += 1;
            if steps > folders.len() {
                return None;
            }
        }
        names.reverse();
        Some(names)
    };
    let mut items = Vec::new();
    for id in vault
        .items_in_folder(Some(uuid), true)
        .map_err(vault_error)?
    {
        if shareable(vault, id).is_err() {
            continue;
        }
        let path = vault
            .item_folders(id)
            .map_err(vault_error)?
            .iter()
            .find_map(|folder| below(folder))
            .unwrap_or_default();
        items.push(read_item(vault, id, path)?);
    }
    if items.is_empty() {
        return Err(LinkError::Empty);
    }
    items.sort_by(|a, b| {
        (
            a.path.join("\u{0}").to_lowercase(),
            a.title.to_lowercase(),
            a.item_id,
        )
            .cmp(&(
                b.path.join("\u{0}").to_lowercase(),
                b.title.to_lowercase(),
                b.item_id,
            ))
    });
    Ok(Snapshot {
        title: title_of(&root.name),
        items,
    })
}

// ---- The wire (sections 4.1 to 4.3). ----

/// The body of `POST /v1/account/links`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CreateBody {
    pub link_id: String,
    pub sealed: String,
    pub expires_at: u64,
    pub one_time: bool,
    pub access: String,
    pub address_hashes: Vec<String>,
}

/// A link as Connect lists it (section 4.2).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct LinkView {
    pub link_id: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub one_time: bool,
    pub access: String,
    pub addresses: u64,
    /// `live`, or `opened` for a one-time link after its open.
    pub state: String,
    pub opens: u64,
    pub last_opened_at: Option<u64>,
}

/// `GET /v1/account/links`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct LinkList {
    pub links: Vec<LinkView>,
    pub live: u64,
    pub limit: Option<u64>,
    pub mail: bool,
    /// When this device asked for the list (Unix seconds; not on the wire): it speaks
    /// only for the links made before.
    #[serde(skip)]
    pub asked_at: u64,
}

impl LinkList {
    /// The account has its most live links: a new one is refused (`403 link_limit`).
    pub fn at_limit(&self) -> bool {
        self.limit.is_some_and(|limit| self.live >= limit)
    }
}

/// `DELETE /v1/account/links/{link_id}`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct LinkDeleted {
    pub link_id: String,
    pub deleted: bool,
}

// ---- The pending link. ----

/// A link that the owner chose and this device sealed, until Connect answers. It keeps the
/// exact body, so a repeat after a lost answer is the same request.
pub struct PendingLink {
    key: Zeroizing<[u8; 32]>,
    body: CreateBody,
    origin: String,
    account_id: String,
    root: LinkRoot,
    name: String,
    titles: Vec<String>,
    items: Vec<u64>,
    addresses: Vec<String>,
    created_at: u64,
    approved: bool,
}

impl fmt::Debug for PendingLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingLink")
            .field("link_id", &self.body.link_id)
            .field("items", &self.items.len())
            .field("approved", &self.approved)
            .field("key", &"[redacted]")
            .finish_non_exhaustive()
    }
}

impl PendingLink {
    /// Read and seal the link of `target` for the account `account_id` at `origin`, at
    /// `now` (Unix seconds). Every refusal comes before the owner check.
    pub fn prepare(
        vault: &Vault,
        target: &LinkTarget,
        origin: &str,
        account_id: &str,
        options: &LinkOptions,
        now: u64,
    ) -> Result<Self, LinkError> {
        let mut key = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut key[..]).map_err(|_| LinkError::Connect(ConnectError::Local))?;
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce).map_err(|_| LinkError::Connect(ConnectError::Local))?;
        Self::prepare_with(vault, target, origin, account_id, options, now, key, nonce)
    }

    /// [`Self::prepare`] with a chosen key and nonce (the vectors).
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_with(
        vault: &Vault,
        target: &LinkTarget,
        origin: &str,
        account_id: &str,
        options: &LinkOptions,
        now: u64,
        key: Zeroizing<[u8; 32]>,
        nonce: [u8; 12],
    ) -> Result<Self, LinkError> {
        let origin = link_origin(origin)?;
        if !(MIN_EXPIRY..=MAX_EXPIRY).contains(&options.expires_in) {
            return Err(LinkError::Expiry);
        }
        let addresses = match &options.emails {
            None => Vec::new(),
            Some(texts) => normal_addresses(texts.iter().map(String::as_str))?,
        };
        let root = match target {
            LinkTarget::Item(id) => LinkRoot::Item(
                vault
                    .item_uuid(*id)
                    .map_err(vault_error)?
                    .ok_or(LinkError::NotFound)?,
            ),
            LinkTarget::Folder(uuid) => LinkRoot::Folder(uuid.clone()),
        };
        let snapshot = Snapshot::read(vault, target)?;
        let plaintext = snapshot.plaintext()?;
        let expires_at = now + options.expires_in;
        let access = if addresses.is_empty() {
            "anyone"
        } else {
            "emails"
        };
        let id = link_id(&key[..]);
        let associated = associated_data(&origin, &id, expires_at, options.one_time, access);
        let sealed = seal(&key[..], nonce, &associated, &plaintext)
            .ok_or(LinkError::Connect(ConnectError::Local))?;
        let address_hashes = addresses
            .iter()
            .map(|address| address_hash(&key[..], address))
            .collect();
        Ok(Self {
            body: CreateBody {
                link_id: id,
                sealed: crate::sync::encode_b64u(&sealed),
                expires_at,
                one_time: options.one_time,
                access: access.to_owned(),
                address_hashes,
            },
            key,
            origin,
            account_id: account_id.to_owned(),
            root,
            name: snapshot.title.clone(),
            titles: snapshot
                .items
                .iter()
                .map(|item| item.title.clone())
                .collect(),
            items: snapshot.items.iter().map(|item| item.item_id).collect(),
            addresses,
            created_at: now,
            approved: false,
        })
    }

    /// The owner check of this link.
    pub fn action(&self) -> OwnerAction {
        OwnerAction::CreatePublicLink {
            account_id: self.account_id.clone(),
            link_id: self.body.link_id.clone(),
            name: self.name.clone(),
            secrets: self.titles.clone(),
            expires_at: self.body.expires_at,
            one_time: self.body.one_time,
            addresses: self.addresses.clone(),
        }
    }

    /// The exact body of the creation.
    pub fn body(&self) -> &CreateBody {
        &self.body
    }

    pub fn link_id(&self) -> &str {
        &self.body.link_id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// The names of the secrets of the snapshot, in its order.
    pub fn secrets(&self) -> &[String] {
        &self.titles
    }

    pub fn addresses(&self) -> &[String] {
        &self.addresses
    }

    /// The link text. Show it only after Connect took the link.
    pub fn link(&self) -> Zeroizing<String> {
        link_text(&self.origin, &self.key[..])
    }

    /// Whether the owner check passed, so [`ConnectAccount::send_public_link`] may repeat
    /// the body.
    pub fn is_approved(&self) -> bool {
        self.approved
    }
}

/// `Ok(None)` for a `404` without [`LINKS_MARKER`] (a relay without the links routes),
/// else the result as it is.
fn unmarked_404<T>(
    (result, marked): (Result<T, ConnectError>, bool),
) -> Result<Option<T>, ConnectError> {
    match result {
        Err(ConnectError::NotFound) if !marked => Ok(None),
        other => other.map(Some),
    }
}

/// What a `DELETE` of a link came to.
enum Deleted {
    /// `200`.
    Done(LinkDeleted),
    /// `404` with the marker of the links routes: the link is gone at Connect.
    Gone,
}

/// A link that Connect took. Only [`Self::apply`] writes its row.
#[derive(Debug)]
pub struct LinkCreated {
    pub view: LinkView,
    pending: PendingLink,
}

impl LinkCreated {
    /// The link text to copy.
    pub fn link(&self) -> Zeroizing<String> {
        self.pending.link()
    }

    pub fn name(&self) -> &str {
        &self.pending.name
    }

    pub fn link_id(&self) -> &str {
        &self.pending.body.link_id
    }

    /// Write the row of the link and `link_created` in the history of its secrets.
    pub fn apply(&self, vault: &mut Vault) -> Result<PublicLink, LinkError> {
        let pending = &self.pending;
        vault
            .add_public_link(&NewPublicLink {
                link_id: &pending.body.link_id,
                root: &pending.root,
                name: &pending.name,
                key: &pending.key,
                origin: &pending.origin,
                account_id: &pending.account_id,
                expires_at: pending.body.expires_at,
                one_time: pending.body.one_time,
                addresses: &pending.addresses,
                created_at: self.view.created_at.min(pending.created_at).max(1),
                items: &pending.items,
            })
            .map_err(vault_error)
    }
}

/// A link that Connect took and whose row the vault holds
/// ([`ConnectAccount::keep_or_revoke`]): the row and the link text to copy.
pub struct LinkKept {
    pub row: PublicLink,
    /// The link as Connect took it.
    pub view: LinkView,
    link: Zeroizing<String>,
}

impl fmt::Debug for LinkKept {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinkKept")
            .field("link_id", &self.row.link_id)
            .finish_non_exhaustive()
    }
}

impl LinkKept {
    /// The link text to copy.
    pub fn link(&self) -> Zeroizing<String> {
        self.link.clone()
    }
}

/// A link that Connect deleted for the account that made it. Only [`Self::apply`] writes
/// the revoke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkRevoked {
    uuid: String,
    account_id: String,
}

impl LinkRevoked {
    /// Mark the row revoked: its key and addresses go. Returns whether it changed.
    pub fn apply(&self, vault: &mut Vault) -> Result<bool, LinkError> {
        vault
            .mark_public_link_revoked(&self.uuid, &self.account_id)
            .map_err(|error| match error.kind() {
                VaultErrorKind::InvalidInput => LinkError::NotMaker,
                _ => LinkError::Vault,
            })
    }
}

impl ConnectAccount {
    fn check_link_origin(&self, origin: &str, account_id: &str) -> Result<(), LinkError> {
        if self.client().origin() != origin || self.state().account_id != account_id {
            return Err(LinkError::Connect(ConnectError::OriginMismatch));
        }
        Ok(())
    }

    /// Send the link after the owner check [`PendingLink::action`] in the vault session
    /// `epoch`. On a failure that gave no answer the pending link stays approved, and
    /// [`Self::send_public_link`] repeats the exact body.
    pub fn create_public_link(
        &mut self,
        pending: PendingLink,
        proof: OwnerProof,
        epoch: &[u8; 32],
    ) -> Result<LinkCreated, (LinkError, Option<Box<PendingLink>>)> {
        if let Err(refusal) = proof.check(&pending.action(), epoch) {
            return Err((
                LinkError::Connect(ConnectError::OwnerCheck(refusal)),
                Some(Box::new(pending)),
            ));
        }
        drop(proof);
        let mut pending = pending;
        pending.approved = true;
        self.send_public_link(pending)
    }

    /// Send the exact body of an approved link again. A `409 conflict` reads the list:
    /// a listed link was made. The error keeps the pending link when a new try of the same
    /// body may work.
    pub fn send_public_link(
        &mut self,
        pending: PendingLink,
    ) -> Result<LinkCreated, (LinkError, Option<Box<PendingLink>>)> {
        if !pending.approved {
            return Err((
                LinkError::Connect(ConnectError::OwnerCheck(
                    crate::broker::approvals::ProofRefusal::WrongAction,
                )),
                Some(Box::new(pending)),
            ));
        }
        if let Err(error) = self.check_link_origin(&pending.origin, &pending.account_id) {
            return Err((error, None));
        }
        let sent =
            self.with_token(|client, token| unmarked_404(client.create_link(token, &pending.body)));
        let view = match sent {
            Ok(Some(view)) => view,
            // A relay without the routes kept nothing.
            Ok(None) => return Err((LinkError::NoLinks, None)),
            Err(ConnectError::Conflict) => match self.public_links() {
                Ok(list) => match list
                    .links
                    .into_iter()
                    .find(|v| v.link_id == pending.body.link_id)
                {
                    Some(view) => view,
                    None => return Err((LinkError::NotMade, None)),
                },
                Err(error) => {
                    let keep = error.can_retry().then(|| Box::new(pending));
                    return Err((error, keep));
                }
            },
            Err(error) => {
                let error = LinkError::from(error);
                let keep = error.can_retry().then(|| Box::new(pending));
                return Err((error, keep));
            }
        };
        if view.link_id != pending.body.link_id
            || view.expires_at != pending.body.expires_at
            || view.one_time != pending.body.one_time
            || view.access != pending.body.access
        {
            return Err((LinkError::Connect(ConnectError::BadAnswer), None));
        }
        Ok(LinkCreated { view, pending })
    }

    /// `GET /v1/account/links`: the links of this account at Connect. A `404` without
    /// [`LINKS_MARKER`] is [`LinkError::NoLinks`]: this relay has no links routes.
    pub fn public_links(&mut self) -> Result<LinkList, LinkError> {
        let asked_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        let mut list = self
            .with_token(|client, token| unmarked_404(client.links(token)))
            .map_err(LinkError::from)?
            .ok_or(LinkError::NoLinks)?;
        list.asked_at = asked_at;
        Ok(list)
    }

    /// Write the row of `created` with `write` while this step still holds the account,
    /// and give the row and the link text. When the row cannot be written (the vault was
    /// locked, or another vault opened, between Connect's answer and the write), revoke
    /// the new link at Connect at once with the account token, which needs no vault: a
    /// link that no row holds can never be copied, and it counts toward the limit. `K`
    /// stays only in memory, in `created`, and goes with it after the revoke. A revoke
    /// that fails leaves the link at Connect; Settings › Connect lists it among the links
    /// not in this vault.
    pub fn keep_or_revoke(
        &mut self,
        created: LinkCreated,
        write: impl FnOnce(&LinkCreated) -> Result<PublicLink, LinkError>,
    ) -> Result<LinkKept, LinkError> {
        match write(&created) {
            Ok(row) => Ok(LinkKept {
                link: created.link(),
                view: created.view.clone(),
                row,
            }),
            Err(error) => {
                tracing::debug!(error = %error, "public link row not written; revoking");
                let revoked = self.revoke_unknown_link(created.link_id()).is_ok();
                drop(created);
                Err(LinkError::NotSaved { revoked })
            }
        }
    }

    /// Revoke `link` at Connect. Only the account that made it may: a link of another
    /// account is [`LinkError::NotMaker`], and nothing is sent. A `200`, or a `404` with
    /// [`LINKS_MARKER`] (the link is gone at Connect already), is the receipt that writes
    /// the revoke; a `404` without the marker is [`LinkError::NotConfirmed`]; any other
    /// answer, and no answer, writes nothing.
    pub fn revoke_public_link(&mut self, link: &PublicLink) -> Result<LinkRevoked, LinkError> {
        if link.account_id != self.state().account_id {
            return Err(LinkError::NotMaker);
        }
        if link.origin != self.client().origin() {
            return Err(LinkError::Connect(ConnectError::OriginMismatch));
        }
        let receipt = LinkRevoked {
            uuid: link.uuid.clone(),
            account_id: link.account_id.clone(),
        };
        match self.delete_marked(&link.link_id)? {
            Deleted::Done(answer) if answer.link_id == link.link_id => Ok(receipt),
            Deleted::Done(_) => Err(LinkError::Connect(ConnectError::BadAnswer)),
            Deleted::Gone => Ok(receipt),
        }
    }

    /// `DELETE` of `link_id`: done on `200`, gone on a `404` that carries
    /// [`LINKS_MARKER`]; a `404` without it is [`LinkError::NotConfirmed`].
    fn delete_marked(&mut self, link_id: &str) -> Result<Deleted, LinkError> {
        let answer = self.with_token(|client, token| match client.delete_link(token, link_id) {
            (Ok(answer), _) => Ok(Some(Deleted::Done(answer))),
            (Err(ConnectError::NotFound), true) => Ok(Some(Deleted::Gone)),
            (Err(ConnectError::NotFound), false) => Ok(None),
            (Err(error), _) => Err(error),
        });
        answer
            .map_err(LinkError::from)?
            .ok_or(LinkError::NotConfirmed)
    }

    /// Revoke at Connect a link id that the vault does not hold (a link whose row was
    /// never written).
    pub fn revoke_unknown_link(&mut self, link_id: &str) -> Result<(), LinkError> {
        self.delete_marked(link_id).map(|_| ())
    }
}
