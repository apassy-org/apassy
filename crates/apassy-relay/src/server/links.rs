//! Public links of Apassy Connect (docs/contracts/connect-share-v1.md, docs/SPEC.md
//! section 38): the sealed snapshots that a Mac or Linux computer makes, the account routes
//! that keep, list, and revoke them, the public routes that open them, the one-time code of
//! a link for e-mail addresses, and the viewer page `/s` for a relay without the edge
//! Worker.
//!
//! Links live in `links.db`, a file of their own in the data directory. No backup holds
//! it (`admin backup` copies `relay.db` and the team files, the stopped backup and the
//! backup check list the same files), so no restore brings a link back. In `connect` mode
//! it is a plain file, as `relay.db` is; else it is encrypted with the master key.
//!
//! Connect never gets the key of a link: it keeps the sealed form, the link id, the times,
//! the flags, the address hashes, the hash of each live code, and the counts. No log line
//! names a link id, an address, or a code.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, PoisonError};
use std::time::Duration;

use ring::hmac;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::config::{LinkSettings, RelayConfig};
use crate::error::{RelayError, RelayResult, codes};
use crate::hostkeys::decode_b64;
use crate::server::account::{AccountCaller, Sharing, no_body, strict, to_value};
use crate::server::hub::Hub;
use crate::server::store::{Store, db, is_unique_violation, to_i, to_u};

// ---- The contract's numbers (sections 2, 3, and 7). ----

/// The schema version of `links.db`.
pub const LINKS_VERSION: i64 = 3;
/// The first version of `links.db`, before `link.code_failures` and `link.code_requests`.
const LINKS_VERSION_1: i64 = 1;
/// The version before the relay secret, the counts of each recipient, and the counts of
/// new links (`SCHEMA_3`).
const LINKS_VERSION_2: i64 = 2;
/// The padding block of the plaintext, and its smallest and largest padded length.
pub const PAD: usize = 1024;
pub const MIN_PLAINTEXT: usize = PAD;
pub const MAX_PLAINTEXT: usize = 32 * 1024;
/// The nonce and the tag around the ciphertext of a sealed form.
pub const SEAL_OVERHEAD: usize = 12 + 16;
/// The expiry of a new link: 10 minutes to 30 days after Connect's clock, with 60 seconds
/// for the clocks (section 4.1).
pub const MIN_EXPIRY_SECS: u64 = 540;
pub const MAX_EXPIRY_SECS: u64 = 2_592_060;
/// The address hashes of a link for e-mail addresses.
pub const MAX_ADDRESSES: usize = 20;
/// A code has 8 digits, lives 15 minutes, and its fifth wrong try ends it.
pub const CODE_DIGITS: usize = 8;
pub const CODE_SECS: u64 = 900;
pub const CODE_TRIES: i64 = 5;
/// The wrong tries of one link and address over the whole life of the link: after the
/// tenth, no code goes to that address for that link any more.
pub const PAIR_WRONG_TRIES: i64 = 10;
/// The codes of one link and address in one UTC day.
pub const PAIR_CODES_PER_DAY: i64 = 5;
/// The code requests that wait for the mail thread; above it 503 `busy`.
const MAX_JOBS: usize = 10_000;
/// The window of the code requests of each link.
pub const CODE_LINK_WINDOW_SECS: u64 = 3600;
/// A code mail that cannot be handed to the SMTP server within this is deleted.
pub const MAIL_LIFETIME_SECS: u64 = 3600;
/// The most links that `GET /v1/account/links` lists, the newest first.
pub const MAX_LISTED: u32 = 1000;
/// The most windows of code requests that the relay holds in memory.
const MAX_WINDOWS: usize = 100_000;
/// The maintenance pass of the links runs at most this often.
const PRUNE_SECS: u64 = 60;
/// The `account_id` of the relay's own row in `mail_count`: no account id is empty.
const RELAY_COUNT: &str = "";
/// The `account_id` of the row in `mail_count` that all accounts without a plan share: no
/// account id is `-`.
const NO_PLAN_COUNT: &str = "-";
/// The HMAC tag of the key of a recipient's daily count.
const RECIPIENT_TAG: &str = "apassy-connect mail recipient v1";
/// The HMAC tag of a code's hash.
const CODE_TAG: &str = "apassy-connect public-link code v1";

/// The subject and the text of the code mail (section 10). The code takes `{code}`.
pub const MAIL_SUBJECT: &str = "Your Apassy code";
const MAIL_TEXT: &str = "Your code to open a shared Apassy item: {code}\r\n\r\nIt works for 15 minutes. If you did not ask for it, ignore this mail.\r\n";
/// The subject and the text of the test mail of `apassy-relay mail-test`: no code, no link.
pub const TEST_SUBJECT: &str = "Apassy relay test mail";
pub const TEST_TEXT: &str = "This is a test mail of an Apassy relay. Its operator sent it to check the mail settings.\r\n\r\nIt holds no code. If you did not expect it, ignore this mail.\r\n";

const SCHEMA: &str = "
CREATE TABLE link (
  link_id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  one_time INTEGER NOT NULL CHECK (one_time IN (0, 1)),
  access TEXT NOT NULL CHECK (access IN ('anyone', 'emails')),
  addresses INTEGER NOT NULL,
  sealed TEXT,
  create_hash BLOB NOT NULL,
  code_failures INTEGER NOT NULL DEFAULT 0,
  code_requests INTEGER NOT NULL DEFAULT 0,
  opens INTEGER NOT NULL DEFAULT 0,
  last_opened_at INTEGER);
CREATE INDEX link_account ON link(account_id, created_at);
CREATE INDEX link_expiry ON link(expires_at);
CREATE TABLE link_address (
  link_id TEXT NOT NULL REFERENCES link(link_id) ON DELETE CASCADE,
  address_hash TEXT NOT NULL,
  wrong_tries INTEGER NOT NULL DEFAULT 0,
  code_day INTEGER NOT NULL DEFAULT 0,
  codes INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (link_id, address_hash));
CREATE TABLE link_id_used (link_id TEXT PRIMARY KEY) WITHOUT ROWID;
CREATE TABLE mail_count (
  day INTEGER NOT NULL,
  account_id TEXT NOT NULL,
  mails INTEGER NOT NULL,
  PRIMARY KEY (day, account_id)) WITHOUT ROWID;
CREATE TABLE link_code (
  link_id TEXT NOT NULL REFERENCES link(link_id) ON DELETE CASCADE,
  address_hash TEXT NOT NULL,
  code_hash BLOB NOT NULL,
  expires_at INTEGER NOT NULL,
  tries INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (link_id, address_hash));
CREATE TABLE mail_outbox (
  id INTEGER PRIMARY KEY,
  recipient TEXT NOT NULL,
  text TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  next_at INTEGER NOT NULL,
  tries INTEGER NOT NULL DEFAULT 0);
CREATE INDEX mail_outbox_next ON mail_outbox(next_at);
";

/// The tables of version 3, made by a new file and by the move from an older version: the
/// random secret of the relay that keys the recipients' counts (one row, made at the first
/// open), the code mails of each recipient on each UTC day under a keyed hash of its
/// normal form, and the new links of each account on each UTC day.
const SCHEMA_3: &str = "
CREATE TABLE IF NOT EXISTS link_secret (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  secret BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS mail_recipient (
  day INTEGER NOT NULL,
  recipient TEXT NOT NULL,
  mails INTEGER NOT NULL,
  PRIMARY KEY (day, recipient)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS link_creates (
  day INTEGER NOT NULL,
  account_id TEXT NOT NULL,
  creates INTEGER NOT NULL,
  PRIMARY KEY (day, account_id)) WITHOUT ROWID;
PRAGMA user_version = 3;
";

/// The whole schema of a new `links.db`.
fn schema() -> String {
    format!("{SCHEMA}{SCHEMA_3}")
}

/// Moves a `links.db` of version 1 or 2 to `LINKS_VERSION`, in one transaction: the two
/// counts of the link row, when they are missing (a file of a build before them), and the
/// tables of `SCHEMA_3`. A file of the current version is left as it is; any other version
/// is refused by the caller.
fn migrate(store: &Store) -> RelayResult<()> {
    let version = store.user_version()?;
    if version != LINKS_VERSION_1 && version != LINKS_VERSION_2 {
        return Ok(());
    }
    store.tx(|tx| {
        for column in ["code_failures", "code_requests"] {
            if !crate::server::store::has_column(tx, "link", column)? {
                tx.execute_batch(&format!(
                    "ALTER TABLE link ADD COLUMN {column} INTEGER NOT NULL DEFAULT 0;"
                ))
                .map_err(db)?;
            }
        }
        tx.execute_batch(SCHEMA_3).map_err(db)
    })
}

/// The random secret of the relay in `links.db`, made at its first open and never
/// changed: the key of the recipients' daily counts.
fn relay_secret(store: &Store) -> RelayResult<zeroize::Zeroizing<Vec<u8>>> {
    let mut fresh = zeroize::Zeroizing::new(vec![0u8; 32]);
    getrandom::fill(fresh.as_mut_slice())
        .map_err(|_| RelayError::internal("The random source failed."))?;
    store.tx(|tx| {
        tx.execute(
            "INSERT OR IGNORE INTO link_secret (id, secret) VALUES (1, ?1)",
            params![fresh.as_slice()],
        )
        .map_err(db)?;
        tx.query_row("SELECT secret FROM link_secret WHERE id = 1", [], |row| {
            row.get::<_, Vec<u8>>(0)
        })
        .map(zeroize::Zeroizing::new)
        .map_err(db)
    })
}

// ---- Errors. ----

/// The one answer for a link that does not open (section 1).
fn link_not_found() -> RelayError {
    RelayError::new(codes::NOT_FOUND, "This link does not open.")
}

/// 429 `link_create_limit`: the account made `budget` links this UTC day.
fn create_limit(budget: u64) -> RelayError {
    RelayError::new(
        codes::LINK_CREATE_LIMIT,
        format!(
            "This account made {budget} links today, as many as it may make in one UTC day. Make the next one tomorrow."
        ),
    )
}

fn mail_unavailable() -> RelayError {
    RelayError::new(
        codes::MAIL_UNAVAILABLE,
        "This relay sends no code mail now, so it has no link for e-mail addresses.",
    )
}

fn code_invalid() -> RelayError {
    RelayError::new(
        codes::CODE_INVALID,
        "The code does not open this link. Ask for a new code.",
    )
}

// ---- The normal form of an address (section 6). ----

/// The normal form of an address (connect-share-v1 section 6), or `None` when the text is
/// not one: white space off both ends, one `@`, an ASCII local part in lowercase, and the
/// ASCII form of the domain by UTS #46.
pub fn normal_address(text: &str) -> Option<String> {
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
    // UTS #46 ToASCII, non-transitional; then one trailing dot goes, so a mapped full-width
    // dot counts as one too.
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

/// The form of a normal address that the daily cap of one recipient counts under
/// (connect-share-v1 section 11): one inbox, one count. A `+tag` of the local part goes,
/// and for Gmail the dots of the local part go and `googlemail.com` is `gmail.com`. The
/// mail itself goes to the address as the reader typed it.
pub fn recipient_form(normal: &str) -> String {
    let Some((local, domain)) = normal.rsplit_once('@') else {
        return normal.to_owned();
    };
    let local = local.split('+').next().unwrap_or(local);
    let (local, domain) = match domain {
        "gmail.com" | "googlemail.com" => (local.replace('.', ""), "gmail.com"),
        _ => (local.to_owned(), domain),
    };
    if local.is_empty() {
        return normal.to_owned();
    }
    format!("{local}@{domain}")
}

/// The address hash of section 6: b64u of HMAC-SHA256 of the normal form under the
/// address key of the link.
pub fn address_hash(address_key: &[u8], normal: &str) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, address_key);
    crate::hostkeys::encode_b64(hmac::sign(&key, normal.as_bytes()).as_ref())
}

/// The hash of a code: HMAC-SHA256 under the address key of the link, which Connect does
/// not keep, over the tag, the link id, and the code. So `links.db` alone gives no code.
fn code_hash(address_key: &[u8], link_id: &str, code: &str) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, address_key);
    let message = [CODE_TAG, link_id, code].join("\0");
    hmac::sign(&key, message.as_bytes()).as_ref().to_vec()
}

/// True when `stored` is the hash of `code` (`code_hash`), compared in constant time.
fn code_matches(address_key: &[u8], link_id: &str, code: &str, stored: &[u8]) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA256, address_key);
    let message = [CODE_TAG, link_id, code].join("\0");
    hmac::verify(&key, message.as_bytes(), stored).is_ok()
}

/// Eight random decimal digits, each value equally likely.
fn new_code() -> RelayResult<String> {
    // The largest multiple of 10^8 below 2^32: a value above it is drawn again.
    const LIMIT: u32 = 4_200_000_000;
    loop {
        let mut bytes = [0u8; 4];
        getrandom::fill(&mut bytes)
            .map_err(|_| RelayError::internal("The random source failed."))?;
        let value = u32::from_be_bytes(bytes);
        if value < LIMIT {
            return Ok(format!("{:08}", value % 100_000_000));
        }
    }
}

/// True for an origin that may carry links (connect-share-v1 section 2): `https:`, or
/// `http://localhost` and `http://127.0.0.1` with any port, for tests.
pub fn link_origin_ok(origin: &str) -> bool {
    if origin.starts_with("https://") {
        return true;
    }
    let Some(rest) = origin.strip_prefix("http://") else {
        return false;
    };
    let host = rest.split_once(':').map_or(rest, |(host, port)| {
        if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) {
            host
        } else {
            ""
        }
    });
    host == "localhost" || host == "127.0.0.1"
}

fn valid_link_id(text: &str) -> bool {
    text.len() == 32
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// b64u of exactly `len` bytes, or `None`.
fn b64u_of(text: &str, len: usize) -> Option<Vec<u8>> {
    decode_b64(text, len)
        .ok()
        .filter(|bytes| bytes.len() == len)
}

// ---- Routes. ----

/// The account routes of section 4 (`Need::Account`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountLinkEndpoint {
    /// `POST /v1/account/links`.
    Create,
    /// `GET /v1/account/links`.
    List,
    /// `DELETE /v1/account/links/{link_id}`.
    Revoke(String),
}

/// The endpoint of `/v1/account/links` and below (`rest` is the path after `links`).
pub fn account_route(method: &str, rest: &[&str]) -> RelayResult<AccountLinkEndpoint> {
    let wrong_method = || {
        RelayError::new(
            codes::METHOD_NOT_ALLOWED,
            "This path does not allow this method.",
        )
    };
    match rest {
        [] => match method {
            "POST" => Ok(AccountLinkEndpoint::Create),
            "GET" => Ok(AccountLinkEndpoint::List),
            _ => Err(wrong_method()),
        },
        [id] if valid_link_id(id) => match method {
            "DELETE" => Ok(AccountLinkEndpoint::Revoke((*id).to_string())),
            _ => Err(wrong_method()),
        },
        // A link id of another form names no link: the answer of a revoke that is done.
        [_] if method == "DELETE" => Err(link_not_found()),
        _ => Err(RelayError::new(codes::NOT_FOUND, "No such path.")),
    }
}

/// The public routes of section 4 (no `Authorization`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicLinkEndpoint {
    /// `POST /v1/links/{link_id}/open`.
    Open(String),
    /// `POST /v1/links/{link_id}/code`.
    Code(String),
}

/// The largest body of a public route (the Worker's cap too): a few hundred bytes are
/// enough for both.
pub const MAX_PUBLIC_BODY: usize = 4096;

/// The prefix of the public routes.
pub const PUBLIC_PREFIX: &str = "/v1/links/";

/// The header that every answer of the routes of public links carries (connect-share-v1
/// section 4), errors included: a client takes a `404` for a revoke as done only with it,
/// and one without it (a relay or image without these routes) as not done.
pub const MARKER: (&str, &str) = ("x-apassy-links", "1");

/// True for an account route of public links: `/v1/account/links` and below.
pub fn is_account_links_path(path: &str) -> bool {
    path == "/v1/account/links" || path.starts_with("/v1/account/links/")
}

/// True for a public route of this contract: `/v1/links` and below.
pub fn is_public_path(path: &str) -> bool {
    path == "/v1/links" || path.starts_with(PUBLIC_PREFIX)
}

/// The endpoint of a public path. Every link id of another form is the answer of a link
/// that does not open.
pub fn public_route(method: &str, path: &str) -> RelayResult<PublicLinkEndpoint> {
    let rest = path.strip_prefix(PUBLIC_PREFIX).unwrap_or_default();
    let parts: Vec<&str> = rest.split('/').collect();
    let endpoint = match parts.as_slice() {
        [id, "open"] => PublicLinkEndpoint::Open((*id).to_string()),
        [id, "code"] => PublicLinkEndpoint::Code((*id).to_string()),
        _ => return Err(RelayError::new(codes::NOT_FOUND, "No such path.")),
    };
    if method != "POST" {
        return Err(RelayError::new(
            codes::METHOD_NOT_ALLOWED,
            "This path does not allow this method.",
        ));
    }
    Ok(endpoint)
}

// ---- The viewer page (section 5). ----

/// The page, its script, and its style, as the edge Worker serves them
/// (`deploy/worker/public/`): one copy of each file for the hosted and the self-run relay.
const SHARE_HTML: &str = include_str!("../../deploy/worker/public/share.html");
const SHARE_JS: &str = include_str!("../../deploy/worker/public/share.js");
const SHARE_CSS: &str = include_str!("../../deploy/worker/public/share.css");

/// The headers of the viewer's answers (section 5), the same as the Worker's.
pub const VIEWER_HEADERS: [(&str, &str); 7] = [
    (
        "Content-Security-Policy",
        "default-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types 'none'",
    ),
    ("Cache-Control", "no-store"),
    ("Referrer-Policy", "no-referrer"),
    ("X-Robots-Tag", "noindex, nofollow"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
];

/// The content type and the body of a viewer path: `/s`, `/share.js`, or `/share.css`.
pub fn viewer_file(path: &str) -> Option<(&'static str, &'static str)> {
    match path {
        "/s" => Some(("text/html; charset=utf-8", SHARE_HTML)),
        "/share.js" => Some(("text/javascript; charset=utf-8", SHARE_JS)),
        "/share.css" => Some(("text/css; charset=utf-8", SHARE_CSS)),
        _ => None,
    }
}

// ---- Requests and answers. ----

/// A field that must be present and may be `null`: a missing one is 400, as an unknown or
/// a duplicate one is (section 1).
fn nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CreateLink {
    link_id: String,
    sealed: String,
    expires_at: u64,
    one_time: bool,
    access: String,
    address_hashes: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenRequest {
    confirm: bool,
    #[serde(deserialize_with = "nullable")]
    email: Option<String>,
    #[serde(deserialize_with = "nullable")]
    address_key: Option<String>,
    #[serde(deserialize_with = "nullable")]
    code: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CodeRequest {
    email: String,
    address_key: String,
}

/// One link in `GET /v1/account/links` and the answer of a creation (section 4.2).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LinkView {
    pub link_id: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub one_time: bool,
    pub access: String,
    pub addresses: u64,
    pub state: &'static str,
    pub opens: u64,
    pub last_opened_at: Option<u64>,
}

#[derive(Debug, Serialize)]
struct LinkList {
    links: Vec<LinkView>,
    live: u64,
    limit: Option<u64>,
    mail: bool,
}

#[derive(Debug, Serialize)]
struct Opened {
    expires_at: u64,
    one_time: bool,
    access: String,
    sealed: Option<String>,
}

const VIEW_COLUMNS: &str = "link_id, created_at, expires_at, one_time, access, addresses, sealed IS NOT NULL, opens, last_opened_at";

fn view_of(row: &rusqlite::Row<'_>) -> rusqlite::Result<LinkView> {
    let one_time: i64 = row.get(3)?;
    let has_sealed: bool = row.get(6)?;
    Ok(LinkView {
        link_id: row.get(0)?,
        created_at: to_u(row.get(1)?),
        expires_at: to_u(row.get(2)?),
        one_time: one_time == 1,
        access: row.get(4)?,
        addresses: to_u(row.get(5)?),
        state: if has_sealed { "live" } else { "opened" },
        opens: to_u(row.get(7)?),
        last_opened_at: row.get::<_, Option<i64>>(8)?.map(to_u),
    })
}

// ---- The store and its state. ----

/// A sliding window of request times for each key.
#[derive(Default)]
struct Windows {
    times: HashMap<String, VecDeque<u64>>,
}

impl Windows {
    /// The requests of `key` in the `window` before `now`, after dropping older ones.
    fn count(&mut self, key: &str, window: u64, now: u64) -> (usize, Option<u64>) {
        let Some(times) = self.times.get_mut(key) else {
            return (0, None);
        };
        while times
            .front()
            .is_some_and(|at| at.saturating_add(window) <= now)
        {
            times.pop_front();
        }
        let oldest = times.front().copied();
        if times.is_empty() {
            self.times.remove(key);
        }
        (self.times.get(key).map_or(0, VecDeque::len), oldest)
    }

    fn record(&mut self, key: String, now: u64) {
        self.times.entry(key).or_default().push_back(now);
    }

    /// Drops every time older than the longest window.
    fn sweep(&mut self, now: u64) {
        let longest = CODE_LINK_WINDOW_SECS;
        self.times.retain(|_, times| {
            times.retain(|at| at.saturating_add(longest) > now);
            !times.is_empty()
        });
    }
}

/// The public links of a relay: `links.db`, the limits, the windows of the code
/// requests, and the outbox signal of the mail sender.
pub struct Links {
    store: Store,
    settings: LinkSettings,
    /// A mail sender is set up (`APASSY_CONNECT_SMTP_HOST`) and its thread runs. Off from
    /// the moment the mail thread ends (`mail_stopped`).
    mail: std::sync::atomic::AtomicBool,
    /// The last check of the SMTP session passed, and no mail failed at AUTH or `MAIL
    /// FROM` since (`probed`, `sender_refused`). Always true without checks.
    mail_healthy: std::sync::atomic::AtomicBool,
    /// The checks of the SMTP session so far (tests).
    probes: AtomicU64,
    /// The key of the recipients' daily counts (`recipient_key`), from `link_secret`.
    recipient_hmac: hmac::Key,
    /// The counts that each mail in the outbox took, kept in memory only, so a mail lost
    /// before its recipient was named gives them back (`refund`). A restart forgets them:
    /// such a mail then keeps its counts.
    refunds: Mutex<HashMap<i64, Refund>>,
    /// The submission client, built at start (a start without it is refused).
    mailer: Option<std::sync::Arc<crate::server::mail::Mailer>>,
    windows: Mutex<Windows>,
    /// The code requests that the mail thread has not looked at yet. Memory only: the
    /// address key in them is never stored.
    jobs: Mutex<VecDeque<CodeJob>>,
    /// While true the mail thread leaves the jobs waiting (`hold_jobs`, tests).
    jobs_held: std::sync::atomic::AtomicBool,
    /// Set when a job or a mail arrives; the mail thread waits on it.
    outbox: Mutex<bool>,
    outbox_ready: Condvar,
    pruned_at: AtomicU64,
}

/// The counts that one mail of the outbox took: the account's, the recipient's, and the
/// codes of the link and address on the UTC day `day`; `relay_fault` when its last try
/// failed before the recipient was named.
struct Refund {
    day: i64,
    account: String,
    link_id: String,
    address_hash: String,
    recipient: String,
    relay_fault: bool,
}

/// A code request after its answer: the mail thread looks the address up on the link and,
/// when it is there, makes the code, its row, and the mail.
struct CodeJob {
    link_id: String,
    /// The account of the link, and its daily mail cap.
    account: String,
    account_cap: u64,
    /// The account has no plan: its mails count in the relay's share for accounts
    /// without a plan too.
    no_plan: bool,
    normal: zeroize::Zeroizing<String>,
    address_key: zeroize::Zeroizing<Vec<u8>>,
    at: u64,
}

impl Links {
    /// Opens `links.db` in the data directory, or makes it. A plain file in `connect`
    /// mode, else encrypted with the master key. A file of the other form, or of another
    /// version, stops the start: it holds only public links, which no backup keeps, so
    /// the operator may remove it.
    pub fn open(config: &RelayConfig) -> RelayResult<Self> {
        let path = config.links_path();
        let exists = std::fs::symlink_metadata(&path).is_ok();
        let plain = config.connect.plain_files();
        let opened = match (exists, plain) {
            (false, true) => Store::create_plain(&path, config, &schema()),
            (false, false) => Store::create_at(&path, &config.master_key, &schema()),
            (true, true) => Store::open_plain(&path, config),
            (true, false) => Store::open_at(&path, &config.master_key),
        };
        let refused = || {
            RelayError::internal(
                "links.db cannot be opened in this mode, or is not a file of public links of this version: nothing was changed. Keep it: it holds the ids of every link ever made, so a revoked link stays revoked. Start the image that wrote it, or, after a move to APASSY_RELAY_MODE=connect, let connect-cutover convert it (docs/OPERATIONS.md section 30).",
            )
        };
        let store = opened.map_err(|_| refused())?;
        migrate(&store).map_err(|_| refused())?;
        // The mail sender is built here, so a relay whose sender cannot be built (no
        // system roots, a host that is no name) does not start.
        let mailer = config
            .connect
            .mail
            .as_ref()
            .map(|settings| crate::server::mail::Mailer::new(settings).map(std::sync::Arc::new))
            .transpose()?;
        if store.user_version().map_err(|_| refused())? != LINKS_VERSION {
            return Err(refused());
        }
        let secret = relay_secret(&store)?;
        Ok(Self {
            store,
            settings: config.connect.links,
            mail: std::sync::atomic::AtomicBool::new(mailer.is_some()),
            mail_healthy: std::sync::atomic::AtomicBool::new(true),
            probes: AtomicU64::new(0),
            recipient_hmac: hmac::Key::new(hmac::HMAC_SHA256, secret.as_slice()),
            refunds: Mutex::new(HashMap::new()),
            mailer,
            windows: Mutex::new(Windows::default()),
            jobs: Mutex::new(VecDeque::new()),
            jobs_held: std::sync::atomic::AtomicBool::new(false),
            outbox: Mutex::new(false),
            outbox_ready: Condvar::new(),
            pruned_at: AtomicU64::new(0),
        })
    }

    /// True when this relay sends the code mail: a sender, its thread, and a session that
    /// passes its check (`probed`).
    pub fn mail_on(&self) -> bool {
        self.mail.load(Ordering::SeqCst) && self.mail_healthy.load(Ordering::SeqCst)
    }

    /// True when a mail sender is set up and its thread has not ended (whatever the check
    /// of the session says): the node listener starts the mail thread then.
    pub(crate) fn mail_sender(&self) -> bool {
        self.mail.load(Ordering::SeqCst)
    }

    /// True while the last check of the SMTP session passed and no mail failed at AUTH or
    /// `MAIL FROM` since.
    pub fn mail_healthy(&self) -> bool {
        self.mail_healthy.load(Ordering::SeqCst)
    }

    /// The checks of the SMTP session that ended so far (tests).
    pub fn probes(&self) -> u64 {
        self.probes.load(Ordering::SeqCst)
    }

    /// How often the mail thread checks its session, or `None`: never.
    pub(crate) fn probe_secs(&self) -> Option<u64> {
        (self.settings.probe_secs > 0).then_some(self.settings.probe_secs)
    }

    /// The end of a check of the SMTP session (`mail::Mailer::probe`). A change of the
    /// state logs one line: the mail is off from a failed check until one passes.
    pub(crate) fn probed(&self, failure: Option<&crate::server::mail::MailError>) {
        match failure {
            None => {
                if !self.mail_healthy.swap(true, Ordering::SeqCst) {
                    eprintln!(
                        "apassy-relay: the check of the SMTP session passes again: the code mail is on"
                    );
                }
            }
            // A 4xx is a busy server (a rate limit): the state stays as it is.
            Some(error) if error.reply.is_some_and(|code| (400..500).contains(&code)) => {}
            Some(error) => {
                if self.mail_healthy.swap(false, Ordering::SeqCst) {
                    eprintln!(
                        "apassy-relay: the check of the SMTP session failed at step {error}: no code mail is sent, and links for e-mail addresses and code requests answer 503 mail_unavailable, until a check passes (every {} s)",
                        self.settings.probe_secs
                    );
                }
            }
        }
        self.probes.fetch_add(1, Ordering::SeqCst);
    }

    /// A mail failed at AUTH or `MAIL FROM`: the server refuses the relay's account or
    /// sender, so the mail is off until a check of the session passes. Without checks the
    /// state does not change (nothing would turn it on again).
    pub(crate) fn sender_refused(&self, error: &crate::server::mail::MailError) {
        if self.probe_secs().is_some() && self.mail_healthy.swap(false, Ordering::SeqCst) {
            eprintln!(
                "apassy-relay: a code mail failed at step {error}: the SMTP server refuses the relay's account or sender; no code mail is sent, and links for e-mail addresses and code requests answer 503 mail_unavailable, until a check of the session passes (every {} s)",
                self.settings.probe_secs
            );
        }
    }

    /// The key of a recipient's daily count: b64u of HMAC-SHA256 of the normal form under
    /// the relay's secret (`link_secret`). Kept for one UTC day.
    fn recipient_key(&self, normal: &str) -> String {
        let folded = recipient_form(normal);
        let message = [RECIPIENT_TAG, folded.as_str()].join("\0");
        crate::hostkeys::encode_b64(hmac::sign(&self.recipient_hmac, message.as_bytes()).as_ref())
    }

    /// The submission client (the mail thread).
    pub(crate) fn mailer(&self) -> Option<std::sync::Arc<crate::server::mail::Mailer>> {
        self.mailer.clone()
    }

    /// The mail thread ended (or never started): no mail goes any more, so links for
    /// e-mail addresses and code requests answer 503 `mail_unavailable`, and the waiting
    /// code requests go with their address keys.
    pub(crate) fn mail_stopped(&self) {
        self.mail.store(false, Ordering::SeqCst);
        self.jobs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }

    /// The live-link limit of a sharing level (`None`: no limit).
    fn limit_of(&self, sharing: Sharing) -> Option<u64> {
        match sharing {
            Sharing::NoPlan | Sharing::Standard => Some(self.settings.links),
            Sharing::Team => Some(self.settings.links_team),
            Sharing::Open => None,
        }
    }

    /// The live links of `account`: not expired, not revoked, not an opened one-time link.
    fn live(conn: &Connection, account: &str, now: u64) -> RelayResult<u64> {
        conn.query_row(
            "SELECT count(*) FROM link WHERE account_id = ?1 AND expires_at > ?2 AND sealed IS NOT NULL",
            params![account, to_i(now)],
            |row| row.get::<_, i64>(0),
        )
        .map(to_u)
        .map_err(db)
    }

    /// Deletes every link of `account` with its address hashes and codes (an account
    /// that is deleted, connect-share-v1 section 1). Answers how many went.
    pub fn delete_account(&self, account: &str) -> RelayResult<usize> {
        self.store.tx(|tx| {
            tx.execute(
                "DELETE FROM mail_count WHERE account_id = ?1",
                params![account],
            )
            .map_err(db)?;
            tx.execute(
                "DELETE FROM link_creates WHERE account_id = ?1",
                params![account],
            )
            .map_err(db)?;
            tx.execute("DELETE FROM link WHERE account_id = ?1", params![account])
                .map_err(db)
        })
    }

    /// The new links of `account` on the UTC day `day`.
    fn creates_of(conn: &Connection, account: &str, day: i64) -> RelayResult<u64> {
        conn.query_row(
            "SELECT creates FROM link_creates WHERE day = ?1 AND account_id = ?2",
            params![day, account],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map(|creates| creates.map_or(0, to_u))
        .map_err(db)
    }

    /// The links that an account of `sharing` may make in one UTC day (`None`: no budget).
    fn create_budget(&self, sharing: Sharing) -> Option<u64> {
        match sharing {
            Sharing::NoPlan | Sharing::Standard => Some(self.settings.creates),
            Sharing::Team => Some(self.settings.creates_team),
            Sharing::Open => None,
        }
    }

    /// The code mails of `account`, of the relay (`RELAY_COUNT`), and of all accounts
    /// without a plan (`NO_PLAN_COUNT`) on the UTC day `day`.
    fn mail_counts(conn: &Connection, account: &str, day: i64) -> RelayResult<(u64, u64, u64)> {
        let count = |who: &str| -> RelayResult<u64> {
            conn.query_row(
                "SELECT mails FROM mail_count WHERE day = ?1 AND account_id = ?2",
                params![day, who],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map(|mails| mails.map_or(0, to_u))
            .map_err(db)
        };
        Ok((count(account)?, count(RELAY_COUNT)?, count(NO_PLAN_COUNT)?))
    }

    /// The link ids of `account` (tests and the operator).
    pub fn ids_of(&self, account: &str) -> RelayResult<Vec<String>> {
        self.store.with(|conn| {
            let mut statement = conn
                .prepare("SELECT link_id FROM link WHERE account_id = ?1 ORDER BY link_id")
                .map_err(db)?;
            statement
                .query_map(params![account], |row| row.get(0))
                .map_err(db)?
                .collect::<Result<Vec<String>, _>>()
                .map_err(db)
        })
    }

    // ---- The outbox (section 10). ----

    /// The mails that are due now, the oldest first: `(id, recipient, text, tries)`. Only
    /// mails with at least `ahead` seconds of their hour left, so a mail that the thread
    /// sends never expires (and gives its counts back) while it is sent; an older one
    /// waits for its expiry.
    pub(crate) fn due_mail(
        &self,
        now: u64,
        limit: u32,
        ahead: u64,
    ) -> RelayResult<Vec<(i64, String, String, i64)>> {
        let fresh = to_i(now.saturating_sub(MAIL_LIFETIME_SECS.saturating_sub(ahead)));
        self.store.with(|conn| {
            let mut statement = conn
                .prepare(
                    "SELECT id, recipient, text, tries FROM mail_outbox WHERE next_at <= ?1 AND created_at > ?3 ORDER BY next_at, id LIMIT ?2",
                )
                .map_err(db)?;
            statement
                .query_map(params![to_i(now), limit, fresh], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                })
                .map_err(db)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db)
        })
    }

    /// A mail that the SMTP server took leaves the outbox at once, with its counts.
    pub(crate) fn mail_sent(&self, id: i64) -> RelayResult<()> {
        self.store.tx(|tx| {
            tx.execute("DELETE FROM mail_outbox WHERE id = ?1", params![id])
                .map_err(db)?;
            self.refunds
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&id);
            Ok(())
        })
    }

    /// A mail that the server refused for good (5xx) leaves the outbox at once. When it
    /// failed before its recipient was named (`setup`: a refused AUTH or `MAIL FROM`, the
    /// relay's own settings), it gives back what it counted for the account, the recipient,
    /// and the link and address; a refused recipient keeps its counts.
    pub(crate) fn mail_dropped(&self, id: i64, setup: bool) -> RelayResult<()> {
        self.store.tx(|tx| {
            let refund = self
                .refunds
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&id);
            if setup && let Some(refund) = refund {
                Self::refund(tx, &refund)?;
            }
            tx.execute("DELETE FROM mail_outbox WHERE id = ?1", params![id])
                .map_err(db)
                .map(drop)
        })
    }

    /// A mail that failed waits `retry` seconds, and remembers whether the failure was
    /// before its recipient (`setup`); one older than an hour is deleted (`expire_mail`).
    pub(crate) fn mail_failed(
        &self,
        id: i64,
        now: u64,
        retry: u64,
        setup: bool,
    ) -> RelayResult<()> {
        self.store.tx(|tx| {
            tx.execute(
                "UPDATE mail_outbox SET tries = tries + 1, next_at = ?2 WHERE id = ?1",
                params![id, to_i(now.saturating_add(retry))],
            )
            .map_err(db)?;
            if let Some(refund) = self
                .refunds
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get_mut(&id)
            {
                refund.relay_fault = setup;
            }
            self.expire_mail(tx, now)
        })
    }

    /// Deletes the mails older than an hour. One whose last try failed before its
    /// recipient was named gives its counts back (`refund`).
    fn expire_mail(&self, tx: &Connection, now: u64) -> RelayResult<()> {
        let cutoff = to_i(now.saturating_sub(MAIL_LIFETIME_SECS));
        let ids: Vec<i64> = {
            let mut statement = tx
                .prepare("SELECT id FROM mail_outbox WHERE created_at <= ?1")
                .map_err(db)?;
            statement
                .query_map(params![cutoff], |row| row.get(0))
                .map_err(db)?
                .collect::<Result<_, _>>()
                .map_err(db)?
        };
        {
            let mut refunds = self.refunds.lock().unwrap_or_else(PoisonError::into_inner);
            for id in ids {
                if let Some(refund) = refunds.remove(&id)
                    && refund.relay_fault
                {
                    Self::refund(tx, &refund)?;
                }
            }
        }
        tx.execute(
            "DELETE FROM mail_outbox WHERE created_at <= ?1",
            params![cutoff],
        )
        .map_err(db)
        .map(drop)
    }

    /// Gives back what one mail counted: the account's mails, the recipient's mails, and
    /// the codes of the link and address, of its UTC day. The relay's own count, and the
    /// share of the accounts without a plan, keep it.
    fn refund(tx: &Connection, refund: &Refund) -> RelayResult<()> {
        tx.execute(
            "UPDATE mail_count SET mails = mails - 1 WHERE day = ?1 AND account_id = ?2 AND mails > 0",
            params![refund.day, refund.account],
        )
        .map_err(db)?;
        tx.execute(
            "UPDATE mail_recipient SET mails = mails - 1 WHERE day = ?1 AND recipient = ?2 AND mails > 0",
            params![refund.day, refund.recipient],
        )
        .map_err(db)?;
        tx.execute(
            "UPDATE link_address SET codes = codes - 1 WHERE link_id = ?1 AND address_hash = ?2 \
             AND code_day = ?3 AND codes > 0",
            params![refund.link_id, refund.address_hash, refund.day],
        )
        .map_err(db)
        .map(drop)
    }

    /// The mails in the outbox (tests).
    pub fn outbox_len(&self) -> RelayResult<u64> {
        self.store.with(|conn| {
            conn.query_row("SELECT count(*) FROM mail_outbox", [], |row| {
                row.get::<_, i64>(0)
            })
            .map(to_u)
            .map_err(db)
        })
    }

    /// Wakes the mail thread.
    fn wake_mail(&self) {
        *self.outbox.lock().unwrap_or_else(PoisonError::into_inner) = true;
        self.outbox_ready.notify_all();
    }

    /// Waits up to `timeout` for a new mail in the outbox (the mail thread).
    pub(crate) fn wait_for_mail(&self, timeout: Duration) {
        let guard = self.outbox.lock().unwrap_or_else(PoisonError::into_inner);
        let (mut guard, _) = self
            .outbox_ready
            .wait_timeout_while(guard, timeout, |ready| !*ready)
            .unwrap_or_else(PoisonError::into_inner);
        *guard = false;
    }

    /// Wakes a waiting mail thread so it sees the stop (`RunningRelay::stop`).
    pub fn wake(&self) {
        self.wake_mail();
    }

    // ---- Maintenance. ----

    /// Deletes expired links with their address hashes and codes, ended codes, and mails
    /// older than an hour; then the links of every account that `relay.db` does not hold
    /// any more (a deletion whose second step did not run). At most once a minute.
    pub fn maintain(&self, directory: &Store, now: u64) {
        let last = self.pruned_at.load(Ordering::Relaxed);
        if last != 0 && now < last.saturating_add(PRUNE_SECS) {
            return;
        }
        self.pruned_at.store(now, Ordering::Relaxed);
        if self.prune(directory, now).is_err() {
            eprintln!("apassy-relay: the maintenance pass of the public links failed");
        }
        self.windows
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .sweep(now);
    }

    /// The pass of `maintain`. Answers the links that went.
    pub fn prune(&self, directory: &Store, now: u64) -> RelayResult<usize> {
        let expired = self.store.tx(|tx| {
            let links = tx
                .execute(
                    "DELETE FROM link WHERE expires_at <= ?1",
                    params![to_i(now)],
                )
                .map_err(db)?;
            tx.execute(
                "DELETE FROM link_code WHERE expires_at <= ?1 OR tries >= ?2",
                params![to_i(now), CODE_TRIES],
            )
            .map_err(db)?;
            self.expire_mail(tx, now)?;
            // The counts of past UTC days, with the keyed hashes of the recipients.
            for table in ["mail_count", "mail_recipient", "link_creates"] {
                tx.execute(
                    &format!("DELETE FROM {table} WHERE day < ?1"),
                    params![to_i(now / 86_400)],
                )
                .map_err(db)?;
            }
            Ok(links)
        })?;
        let accounts: Vec<String> = self.store.with(|conn| {
            let mut statement = conn
                .prepare("SELECT DISTINCT account_id FROM link")
                .map_err(db)?;
            statement
                .query_map([], |row| row.get(0))
                .map_err(db)?
                .collect::<Result<Vec<String>, _>>()
                .map_err(db)
        })?;
        let mut gone = 0;
        for account in accounts {
            if !account_exists(directory, &account)? {
                gone += self.delete_account(&account)?;
            }
        }
        Ok(expired + gone)
    }
}

/// `apassy-relay purge-links`, with the relay stopped (it takes `relay.lock`): every link
/// goes with its address hashes, codes, and counts, and the mails of the outbox go too;
/// `link_id_used` stays, so no id that was revoked opens or is made again. For a relay
/// that comes back to links after an image without them (whose revokes a device took as
/// done), and for an operator who wants no live link left (docs/OPERATIONS.md 30.5). A
/// relay without `links.db` has nothing to purge. Answers the counts.
pub fn purge_stopped(config: &RelayConfig) -> RelayResult<Value> {
    let _lock = crate::server::hub::lock_data_dir(config).map_err(|error| {
        if error.code == codes::CONFLICT {
            RelayError::new(
                codes::CONFLICT,
                "The relay runs (relay.lock is held): stop it first. `apassy-relay purge-links` runs only with the relay stopped.",
            )
        } else {
            error
        }
    })?;
    let path = config.links_path();
    if std::fs::symlink_metadata(&path).is_err() {
        return Ok(serde_json::json!({"links": 0, "mails": 0, "ids_kept": 0}));
    }
    let store = if config.connect.plain_files() {
        Store::open_plain(&path, config)
    } else {
        Store::open_at(&path, &config.master_key)
    }
    .map_err(|_| {
        RelayError::internal(
            "links.db does not open in this mode: nothing was changed. Run the purge with the configuration of the relay that wrote it.",
        )
    })?;
    migrate(&store)?;
    if store.user_version()? != LINKS_VERSION {
        return Err(RelayError::internal(
            "links.db is of another version: nothing was changed. Run the purge of the image that wrote it.",
        ));
    }
    let (links, mails, kept) = store.tx(|tx| {
        let links = tx.execute("DELETE FROM link", []).map_err(db)?;
        tx.execute("DELETE FROM link_code", []).map_err(db)?;
        tx.execute("DELETE FROM link_address", []).map_err(db)?;
        tx.execute("DELETE FROM mail_count", []).map_err(db)?;
        tx.execute("DELETE FROM mail_recipient", []).map_err(db)?;
        tx.execute("DELETE FROM link_creates", []).map_err(db)?;
        let mails = tx.execute("DELETE FROM mail_outbox", []).map_err(db)?;
        let kept: i64 = tx
            .query_row("SELECT count(*) FROM link_id_used", [], |row| row.get(0))
            .map_err(db)?;
        Ok((links, mails, to_u(kept)))
    })?;
    store.with(|conn| conn.execute_batch("VACUUM").map_err(db))?;
    Ok(serde_json::json!({"links": links, "mails": mails, "ids_kept": kept}))
}

/// True when `relay.db` holds the account (deleted accounts have no row).
fn account_exists(directory: &Store, account: &str) -> RelayResult<bool> {
    directory.with(|conn| {
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM account WHERE id = ?1)",
            params![account],
            |row| row.get(0),
        )
        .map_err(db)
    })
}

fn links_of(hub: &Hub) -> RelayResult<&Links> {
    hub.links()
        .map(AsRef::as_ref)
        .ok_or_else(|| RelayError::new(codes::NOT_FOUND, "No such path."))
}

// ---- The account routes (sections 4.1 to 4.3). ----

/// Serves an account route of section 4 for a signed-in device of `caller`'s account.
pub fn dispatch(
    hub: &Hub,
    caller: &AccountCaller,
    endpoint: &AccountLinkEndpoint,
    body: &[u8],
    now: u64,
) -> RelayResult<Value> {
    let links = links_of(hub)?;
    match endpoint {
        AccountLinkEndpoint::Create => create(hub, links, caller, &strict(body)?, now),
        AccountLinkEndpoint::List => list(hub, links, caller, now),
        AccountLinkEndpoint::Revoke(link_id) => {
            no_body(body)?;
            revoke(links, caller, link_id)
        }
    }
}

/// Checks the form of a creation (section 4.1): 400 for any field out of its rule.
fn check_create(request: &CreateLink, now: u64) -> RelayResult<()> {
    if !valid_link_id(&request.link_id) {
        return Err(RelayError::invalid("The link id is 32 lowercase hex."));
    }
    let sealed_len = b64u_of_any(&request.sealed, SEAL_OVERHEAD + MAX_PLAINTEXT)
        .map(|bytes| bytes.len())
        .ok_or_else(|| RelayError::invalid("The sealed form is b64u."))?;
    let plain = sealed_len.saturating_sub(SEAL_OVERHEAD);
    if !(MIN_PLAINTEXT..=MAX_PLAINTEXT).contains(&plain) || plain % PAD != 0 {
        return Err(RelayError::invalid(
            "The sealed form holds a padded plaintext of 1 to 32 KiB, a multiple of 1 KiB.",
        ));
    }
    if request.expires_at < now.saturating_add(MIN_EXPIRY_SECS)
        || request.expires_at > now.saturating_add(MAX_EXPIRY_SECS)
    {
        return Err(RelayError::invalid(
            "A link expires 10 minutes to 30 days from now.",
        ));
    }
    match request.access.as_str() {
        "anyone" if request.address_hashes.is_empty() => Ok(()),
        "anyone" => Err(RelayError::invalid(
            "A link for anyone has no address hashes.",
        )),
        "emails" => {
            let count = request.address_hashes.len();
            let distinct: std::collections::BTreeSet<&String> =
                request.address_hashes.iter().collect();
            let well_formed = request
                .address_hashes
                .iter()
                .all(|hash| hash.len() == 43 && b64u_of(hash, 32).is_some());
            if (1..=MAX_ADDRESSES).contains(&count) && distinct.len() == count && well_formed {
                Ok(())
            } else {
                Err(RelayError::invalid(
                    "A link for e-mail addresses has 1 to 20 distinct address hashes.",
                ))
            }
        }
        _ => Err(RelayError::invalid("The access is anyone or emails.")),
    }
}

/// b64u of at most `max` bytes, or `None`.
fn b64u_of_any(text: &str, max: usize) -> Option<Vec<u8>> {
    decode_b64(text, max).ok()
}

/// `POST /v1/account/links` (section 4.1).
fn create(
    hub: &Hub,
    links: &Links,
    caller: &AccountCaller,
    request: &CreateLink,
    now: u64,
) -> RelayResult<Value> {
    let body_hash = Sha256::digest(
        serde_json::to_vec(request)
            .map_err(|_| RelayError::internal("The request cannot be written."))?,
    )
    .to_vec();
    // A retry first: the same id and the same body from the same account answer the
    // stored view, before the checks of the expiry, which a late retry may fail.
    let stored = links.store.with(|conn| {
        conn.query_row(
            &format!(
                "SELECT {VIEW_COLUMNS} FROM link WHERE link_id = ?1 AND account_id = ?2 AND create_hash = ?3"
            ),
            params![request.link_id, caller.account, body_hash],
            view_of,
        )
        .optional()
        .map_err(db)
    })?;
    if let Some(view) = stored {
        return to_value(&view);
    }
    check_create(request, now)?;
    if !link_origin_ok(&hub.config.public_url) {
        return Err(RelayError::new(
            codes::FORBIDDEN,
            "This relay's origin is not https, so it makes no public link.",
        ));
    }
    if request.access == "emails" && !links.mail_on() {
        return Err(mail_unavailable());
    }
    let sharing = hub
        .accounts
        .plans()
        .sharing(&hub.directory.store, &caller.account, now)?;
    let limit = links.limit_of(sharing);
    // The links that the account may make today, read before the write lock of
    // `links.db`: over it the answer is 429 at once. The transaction reads it again.
    let budget = links.create_budget(sharing);
    let day = to_i(now / 86_400);
    if let Some(budget) = budget
        && links
            .store
            .with(|conn| Links::creates_of(conn, &caller.account, day))?
            >= budget
    {
        return Err(create_limit(budget));
    }
    // The outer result is the transaction's; the inner one is the answer, and a refusal
    // there still commits the count of the try.
    let view = links.store.tx(|tx| -> RelayResult<RelayResult<LinkView>> {
        let known: Option<(String, Vec<u8>)> = tx
            .query_row(
                "SELECT account_id, create_hash FROM link WHERE link_id = ?1",
                params![request.link_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(db)?;
        if let Some((account, hash)) = &known {
            // The same body again from the same account: the stored view (a lost answer).
            if *account == caller.account && *hash == body_hash {
                return tx
                    .query_row(
                        &format!("SELECT {VIEW_COLUMNS} FROM link WHERE link_id = ?1"),
                        params![request.link_id],
                        view_of,
                    )
                    .map(Ok)
                    .map_err(db);
            }
        }
        // Every try past the retry counts in the budget of the day, also one refused
        // below, so a refused try still takes from it.
        if let Some(budget) = budget {
            if Links::creates_of(tx, &caller.account, day)? >= budget {
                return Ok(Err(create_limit(budget)));
            }
            tx.execute(
                "INSERT INTO link_creates (day, account_id, creates) VALUES (?1, ?2, 1) \
                 ON CONFLICT (day, account_id) DO UPDATE SET creates = creates + 1",
                params![day, caller.account],
            )
            .map_err(db)?;
        }
        if known.is_some() {
            return Ok(Err(RelayError::new(
                codes::CONFLICT,
                "A link with this id exists. Make a new link.",
            )));
        }
        // An id is used once, ever: revoked, expired, and deleted ids stay in `link_id_used`.
        let used: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM link_id_used WHERE link_id = ?1)",
                params![request.link_id],
                |row| row.get(0),
            )
            .map_err(db)?;
        if used {
            return Ok(Err(RelayError::new(
                codes::CONFLICT,
                "A link with this id existed. Make a new link.",
            )));
        }
        if let Some(limit) = limit
            && Links::live(tx, &caller.account, now)? >= limit
        {
            return Ok(Err(RelayError::new(
                codes::LINK_LIMIT,
                format!(
                    "This account has {limit} live links, its limit. Revoke one, or wait until one expires."
                ),
            )));
        }
        tx.execute(
            "INSERT INTO link (link_id, account_id, created_at, expires_at, one_time, access, addresses, sealed, create_hash) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                request.link_id,
                caller.account,
                to_i(now),
                to_i(request.expires_at),
                i64::from(request.one_time),
                request.access,
                request.address_hashes.len() as i64,
                request.sealed,
                body_hash,
            ],
        )
        .map_err(|error| {
            if is_unique_violation(&error) {
                RelayError::new(codes::CONFLICT, "A link with this id exists. Make a new link.")
            } else {
                db(error)
            }
        })?;
        tx.execute(
            "INSERT INTO link_id_used (link_id) VALUES (?1)",
            params![request.link_id],
        )
        .map_err(db)?;
        for hash in &request.address_hashes {
            tx.execute(
                "INSERT INTO link_address (link_id, address_hash) VALUES (?1, ?2)",
                params![request.link_id, hash],
            )
            .map_err(db)?;
        }
        Ok(Ok(LinkView {
            link_id: request.link_id.clone(),
            created_at: now,
            expires_at: request.expires_at,
            one_time: request.one_time,
            access: request.access.clone(),
            addresses: request.address_hashes.len() as u64,
            state: "live",
            opens: 0,
            last_opened_at: None,
        }))
    })??;
    to_value(&view)
}

/// `GET /v1/account/links` (section 4.2).
fn list(hub: &Hub, links: &Links, caller: &AccountCaller, now: u64) -> RelayResult<Value> {
    let sharing = hub
        .accounts
        .plans()
        .sharing(&hub.directory.store, &caller.account, now)?;
    let (rows, live) = links.store.with(|conn| {
        let mut statement = conn
            .prepare(&format!(
                "SELECT {VIEW_COLUMNS} FROM link WHERE account_id = ?1 AND expires_at > ?2 \
                 ORDER BY created_at DESC, link_id LIMIT ?3"
            ))
            .map_err(db)?;
        let rows = statement
            .query_map(params![caller.account, to_i(now), MAX_LISTED], view_of)
            .map_err(db)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db)?;
        Ok((rows, Links::live(conn, &caller.account, now)?))
    })?;
    to_value(&LinkList {
        links: rows,
        live,
        limit: links.limit_of(sharing),
        mail: links.mail_on(),
    })
}

/// `DELETE /v1/account/links/{link_id}` (section 4.3): the row, the sealed form, the
/// address hashes, and the codes in one transaction. A link of another account is 404.
fn revoke(links: &Links, caller: &AccountCaller, link_id: &str) -> RelayResult<Value> {
    let deleted = links.store.tx(|tx| {
        tx.execute(
            "DELETE FROM link WHERE link_id = ?1 AND account_id = ?2",
            params![link_id, caller.account],
        )
        .map_err(db)
    })?;
    if deleted == 0 {
        return Err(link_not_found());
    }
    Ok(serde_json::json!({"link_id": link_id, "deleted": true}))
}

// ---- The public routes (sections 4.4 and 4.5). ----

/// The live link `link_id`: not expired, not revoked, not opened, of an account that
/// `relay.db` still holds. A tombstoned id (`link_id_used` without a row) is never live. `(account, expires_at, one_time, access, sealed)`.
type LiveLink = (String, u64, bool, String, String);

fn live_link(conn: &Connection, link_id: &str, now: u64) -> RelayResult<Option<LiveLink>> {
    conn.query_row(
        "SELECT account_id, expires_at, one_time, access, sealed FROM link \
         WHERE link_id = ?1 AND expires_at > ?2 AND sealed IS NOT NULL",
        params![link_id, to_i(now)],
        |row| {
            Ok((
                row.get(0)?,
                to_u(row.get(1)?),
                row.get::<_, i64>(2)? == 1,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )
    .optional()
    .map_err(db)
}

/// What the transaction of an open decided.
enum OpenOutcome {
    Answer(Opened),
    CodeInvalid,
}

/// `POST /v1/links/{link_id}/open` (section 4.4).
pub fn open(hub: &Hub, link_id: &str, body: &[u8], now: u64) -> RelayResult<Value> {
    let links = links_of(hub)?;
    let request: OpenRequest = strict(body)?;
    let with_code = match (&request.email, &request.address_key, &request.code) {
        (None, None, None) => None,
        (Some(email), Some(key), Some(code)) => Some((email, key, code)),
        _ => {
            return Err(RelayError::invalid(
                "email, address_key, and code are all null or all set.",
            ));
        }
    };
    if !valid_link_id(link_id) {
        return Err(link_not_found());
    }
    // A link of an account that is gone does not open, also before the maintenance pass.
    let account = links
        .store
        .with(|conn| live_link(conn, link_id, now))?
        .map(|link| link.0);
    match account {
        Some(account) if account_exists(&hub.directory.store, &account)? => {}
        _ => return Err(link_not_found()),
    }
    let outcome = links.store.tx(|tx| {
        let Some((_, expires_at, one_time, access, sealed)) = live_link(tx, link_id, now)? else {
            return Err(link_not_found());
        };
        let answer = |sealed: Option<String>| Opened {
            expires_at,
            one_time,
            access: access.clone(),
            sealed,
        };
        // The reader must act first: nothing changes.
        let held = |tx: &Connection, used_code: Option<&str>| -> RelayResult<OpenOutcome> {
            if let Some(hash) = used_code {
                tx.execute(
                    "DELETE FROM link_code WHERE link_id = ?1 AND address_hash = ?2",
                    params![link_id, hash],
                )
                .map_err(db)?;
            }
            tx.execute(
                "UPDATE link SET opens = opens + 1, last_opened_at = ?2 WHERE link_id = ?1",
                params![link_id, to_i(now)],
            )
            .map_err(db)?;
            if one_time {
                // The first open of a one-time link deletes its sealed form, its address
                // hashes, and its codes; its row stays until its expiry, for the list.
                tx.execute(
                    "UPDATE link SET sealed = NULL WHERE link_id = ?1",
                    params![link_id],
                )
                .map_err(db)?;
                tx.execute(
                    "DELETE FROM link_address WHERE link_id = ?1",
                    params![link_id],
                )
                .map_err(db)?;
                tx.execute("DELETE FROM link_code WHERE link_id = ?1", params![link_id])
                    .map_err(db)?;
            }
            Ok(OpenOutcome::Answer(answer(Some(sealed.clone()))))
        };
        match (access.as_str(), with_code) {
            ("anyone", Some(_)) => Err(RelayError::invalid(
                "A link for anyone opens without a code.",
            )),
            ("anyone", None) if one_time && !request.confirm => {
                Ok(OpenOutcome::Answer(answer(None)))
            }
            ("anyone", None) => held(tx, None),
            (_, None) => Ok(OpenOutcome::Answer(answer(None))),
            (_, Some((email, key, code))) => {
                let normal = normal_address(email)
                    .ok_or_else(|| RelayError::invalid("The e-mail address is not one."))?;
                let address_key = b64u_of(key, 32)
                    .ok_or_else(|| RelayError::invalid("The address key is b64u of 32 bytes."))?;
                if code.len() != CODE_DIGITS || !code.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(RelayError::invalid("The code is 8 digits."));
                }
                let hash = address_hash(&address_key, &normal);
                // The same reads, the same HMAC, and the same writes and commit for every
                // code that does not open, for an address of the link and for any other
                // one (section 4.4). A live code exists only for an address of the link.
                let live_code: Option<Vec<u8>> = tx
                    .query_row(
                        "SELECT code_hash FROM link_code WHERE link_id = ?1 AND address_hash = ?2 \
                         AND expires_at > ?3 AND tries < ?4",
                        params![link_id, hash, to_i(now), CODE_TRIES],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(db)?;
                let stored = live_code.clone().unwrap_or_else(|| vec![0u8; 32]);
                let matches = code_matches(&address_key, link_id, code, &stored);
                if !(matches && live_code.is_some()) {
                    // The link's own count of codes that did not open: a write on every
                    // path. Then a try of the live code of this address, if there is one,
                    // and with it, only then, a wrong try of the pair over the life of the
                    // link. The fifth try ends the code; the tenth wrong try of the pair
                    // ends it and every later code of that address.
                    tx.execute(
                        "UPDATE link SET code_failures = code_failures + 1 WHERE link_id = ?1",
                        params![link_id],
                    )
                    .map_err(db)?;
                    let counted = tx
                        .execute(
                            "UPDATE link_code SET tries = tries + 1 WHERE link_id = ?1 AND address_hash = ?2 \
                             AND expires_at > ?3 AND tries < ?4",
                            params![link_id, hash, to_i(now), CODE_TRIES],
                        )
                        .map_err(db)?;
                    tx.execute(
                        "UPDATE link_address SET wrong_tries = wrong_tries + ?3 WHERE link_id = ?1 AND address_hash = ?2",
                        params![link_id, hash, counted as i64],
                    )
                    .map_err(db)?;
                    tx.execute(
                        "DELETE FROM link_code WHERE link_id = ?1 AND address_hash = ?2 AND (tries >= ?3 \
                         OR (SELECT wrong_tries FROM link_address WHERE link_id = ?1 AND address_hash = ?2) >= ?4)",
                        params![link_id, hash, CODE_TRIES, PAIR_WRONG_TRIES],
                    )
                    .map_err(db)?;
                    return Ok(OpenOutcome::CodeInvalid);
                }
                if one_time && !request.confirm {
                    // The code stays and no try counts.
                    return Ok(OpenOutcome::Answer(answer(None)));
                }
                held(tx, Some(&hash))
            }
        }
    })?;
    match outcome {
        OpenOutcome::Answer(opened) => to_value(&opened),
        OpenOutcome::CodeInvalid => Err(code_invalid()),
    }
}

/// A refusal of the code route that carries its own `Retry-After`.
pub struct CodeRefusal {
    pub error: RelayError,
    pub retry_after: Option<u64>,
}

impl From<RelayError> for CodeRefusal {
    fn from(error: RelayError) -> Self {
        Self {
            error,
            retry_after: None,
        }
    }
}

/// The seconds until the next UTC day.
pub(crate) fn until_tomorrow(now: u64) -> u64 {
    (now / 86_400 + 1) * 86_400 - now
}

/// `POST /v1/links/{link_id}/code` (section 4.5). The answer comes before any look at the
/// addresses. In this order, and only these: the form of the body, the normal form of
/// `email` and the address key (400); the link, live, for e-mail addresses, of an account
/// that exists (404); a mail sender whose session passes its check, and the daily mail
/// caps of the account, of the accounts without a plan (for one of them), and of the relay
/// (503 `mail_unavailable` until the day ends); the code requests of the link (429).
/// None of these depends on the address. The lookup of the address on the link, the code,
/// its row, and the mail happen later in the mail thread (`process_jobs`), so an address on
/// the link and one that is not look the same on the wire and in time.
pub fn request_code(hub: &Hub, link_id: &str, body: &[u8], now: u64) -> Result<Value, CodeRefusal> {
    let links = links_of(hub)?;
    let request: CodeRequest = strict(body)?;
    let normal = zeroize::Zeroizing::new(
        normal_address(&request.email)
            .ok_or_else(|| RelayError::invalid("The e-mail address is not one."))?,
    );
    let address_key = zeroize::Zeroizing::new(
        b64u_of(&request.address_key, 32)
            .ok_or_else(|| RelayError::invalid("The address key is b64u of 32 bytes."))?,
    );
    if !valid_link_id(link_id) {
        return Err(link_not_found().into());
    }
    let link = links.store.with(|conn| live_link(conn, link_id, now))?;
    let Some((account, _, _, access, _)) = link else {
        return Err(link_not_found().into());
    };
    if access != "emails" || !account_exists(&hub.directory.store, &account)? {
        return Err(link_not_found().into());
    }
    if !links.mail_on() {
        return Err(mail_unavailable().into());
    }
    // The daily caps: the account's that made the link first, then the relay's. They count
    // the mails that the mail thread made, so above a cap every code request of the
    // account's links gets the same 503, whatever the address.
    let sharing = hub
        .accounts
        .plans()
        .sharing(&hub.directory.store, &account, now)?;
    let account_cap = links.mail_cap(sharing);
    let no_plan = sharing == Sharing::NoPlan;
    let day = to_i(now / 86_400);
    let (account_mails, relay_mails, no_plan_mails) = links
        .store
        .with(|conn| Links::mail_counts(conn, &account, day))?;
    if account_mails >= account_cap
        || relay_mails >= links.settings.mail_per_day
        || (no_plan && no_plan_mails >= links.settings.mail_no_plan)
    {
        return Err(CodeRefusal {
            error: mail_unavailable(),
            retry_after: Some(until_tomorrow(now)),
        });
    }
    // The code requests of the link: every request counts, with or without a mail.
    {
        let mut windows = links.windows.lock().unwrap_or_else(PoisonError::into_inner);
        let name = format!("l:{link_id}");
        let (count, oldest) = windows.count(&name, CODE_LINK_WINDOW_SECS, now);
        if count as u64 >= links.settings.mail_per_link {
            let retry = oldest.map_or(CODE_LINK_WINDOW_SECS, |at| {
                (at + CODE_LINK_WINDOW_SECS).saturating_sub(now)
            });
            return Err(CodeRefusal {
                error: RelayError::new(
                    codes::RATE_LIMITED,
                    "Too many code requests for this link. Try again later.",
                ),
                retry_after: Some(retry.max(1)),
            });
        }
        if windows.times.len() >= MAX_WINDOWS {
            windows.sweep(now);
            if windows.times.len() >= MAX_WINDOWS {
                return Err(RelayError::new(
                    codes::BUSY,
                    "The relay is busy. Try again in a moment.",
                )
                .into());
            }
        }
        windows.record(name, now);
    }
    {
        let mut jobs = links.jobs.lock().unwrap_or_else(PoisonError::into_inner);
        if jobs.len() >= MAX_JOBS {
            return Err(
                RelayError::new(codes::BUSY, "The relay is busy. Try again in a moment.").into(),
            );
        }
        jobs.push_back(CodeJob {
            link_id: link_id.to_string(),
            account,
            account_cap,
            no_plan,
            normal,
            address_key,
            at: now,
        });
    }
    links.wake_mail();
    Ok(serde_json::json!({"expires_in": CODE_SECS}))
}

impl Links {
    /// While `held`, the mail thread leaves the code requests waiting (tests: what the
    /// code route does before the lookup).
    pub fn hold_jobs(&self, held: bool) {
        self.jobs_held.store(held, Ordering::SeqCst);
        if !held {
            self.wake_mail();
        }
    }

    /// The daily mail cap of an account of `sharing`.
    fn mail_cap(&self, sharing: Sharing) -> u64 {
        match sharing {
            Sharing::NoPlan | Sharing::Standard => self.settings.mail_per_account,
            Sharing::Team => self.settings.mail_per_account_team,
            Sharing::Open => self.settings.mail_per_account_open,
        }
    }

    /// The code requests that wait for the mail thread.
    pub fn jobs_waiting(&self) -> usize {
        self.jobs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// The mail thread's part of the code requests: for each, in one transaction, the
    /// address hash on the link, its wrong tries (under 10 over the life of the link) and
    /// its codes today (under 5), the recipient's mails today (under
    /// `mail_per_recipient`, across all links and accounts), and the daily caps; then a
    /// new code, which ends the one before, its hash, and the mail in the outbox. An
    /// address that is not on the link, or that is over a count, gets nothing. The address
    /// key leaves memory with the job.
    pub(crate) fn process_jobs(&self) -> RelayResult<()> {
        if self.jobs_held.load(Ordering::SeqCst) {
            return Ok(());
        }
        loop {
            let job = self
                .jobs
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pop_front();
            let Some(job) = job else {
                return Ok(());
            };
            self.make_code(&job)?;
        }
    }

    fn make_code(&self, job: &CodeJob) -> RelayResult<()> {
        let now = job.at.max(crate::now_unix());
        let day = to_i(now / 86_400);
        let hash = address_hash(&job.address_key, &job.normal);
        let recipient = self.recipient_key(&job.normal);
        let code = zeroize::Zeroizing::new(new_code()?);
        let stored = code_hash(&job.address_key, &job.link_id, &code);
        let text = zeroize::Zeroizing::new(MAIL_TEXT.replace("{code}", &code));
        // The same reads and the same statements for every request, for an address of the
        // link and for any other: whether a code is made is a parameter of each write. The
        // rows that the writes touch differ (none when no code is made), so the time of the
        // transaction, of its lock of `links.db` and of its commit, is close on both paths,
        // not equal: the accepted signal of contract section 4.5.
        let outbox_id = self.store.tx(|tx| {
            let live = live_link(tx, &job.link_id, now)?.is_some();
            let pair: Option<(i64, i64, i64)> = tx
                .query_row(
                    "SELECT wrong_tries, code_day, codes FROM link_address WHERE link_id = ?1 AND address_hash = ?2",
                    params![job.link_id, hash],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(db)?;
            let (account_mails, relay_mails, no_plan_mails) =
                Links::mail_counts(tx, &job.account, day)?;
            let recipient_mails = tx
                .query_row(
                    "SELECT mails FROM mail_recipient WHERE day = ?1 AND recipient = ?2",
                    params![day, recipient],
                    |row| row.get::<_, i64>(0),
                )
                .optional()
                .map_err(db)?
                .map_or(0, to_u);
            let pair_room = pair.is_some_and(|(wrong, code_day, codes)| {
                let today = if code_day == day { codes } else { 0 };
                wrong < PAIR_WRONG_TRIES && today < PAIR_CODES_PER_DAY
            });
            // The caps hold for the mails of the thread too.
            let made = live
                && pair_room
                && account_mails < job.account_cap
                && relay_mails < self.settings.mail_per_day
                && (!job.no_plan || no_plan_mails < self.settings.mail_no_plan)
                && recipient_mails < self.settings.mail_per_recipient;
            let (made, pooled) = (i64::from(made), i64::from(made && job.no_plan));
            tx.execute(
                "UPDATE link SET code_requests = code_requests + 1 WHERE link_id = ?1",
                params![job.link_id],
            )
            .map_err(db)?;
            for (who, counted) in [
                (job.account.as_str(), made),
                (RELAY_COUNT, made),
                (NO_PLAN_COUNT, pooled),
            ] {
                tx.execute(
                    "INSERT INTO mail_count (day, account_id, mails) SELECT ?1, ?2, 1 WHERE ?3 = 1 \
                     ON CONFLICT (day, account_id) DO UPDATE SET mails = mails + 1",
                    params![day, who, counted],
                )
                .map_err(db)?;
            }
            tx.execute(
                "INSERT INTO mail_recipient (day, recipient, mails) SELECT ?1, ?2, 1 WHERE ?3 = 1 \
                 ON CONFLICT (day, recipient) DO UPDATE SET mails = mails + 1",
                params![day, recipient, made],
            )
            .map_err(db)?;
            tx.execute(
                "UPDATE link_address SET codes = CASE WHEN code_day = ?3 THEN codes + 1 ELSE 1 END, \
                 code_day = ?3 WHERE link_id = ?1 AND address_hash = ?2 AND ?4 = 1",
                params![job.link_id, hash, day, made],
            )
            .map_err(db)?;
            // One live code for each link and address: a new one ends the one before.
            tx.execute(
                "INSERT INTO link_code (link_id, address_hash, code_hash, expires_at, tries) \
                 SELECT ?1, ?2, ?3, ?4, 0 WHERE ?5 = 1 \
                 ON CONFLICT (link_id, address_hash) DO UPDATE SET code_hash = excluded.code_hash, \
                 expires_at = excluded.expires_at, tries = 0",
                params![job.link_id, hash, stored, to_i(now + CODE_SECS), made],
            )
            .map_err(db)?;
            tx.execute(
                "INSERT INTO mail_outbox (recipient, text, created_at, next_at) \
                 SELECT ?1, ?2, ?3, ?3 WHERE ?4 = 1",
                params![job.normal.as_str(), text.as_str(), to_i(now), made],
            )
            .map_err(db)?;
            Ok((made == 1).then(|| tx.last_insert_rowid()))
        })?;
        if let Some(id) = outbox_id {
            self.refunds
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(
                    id,
                    Refund {
                        day,
                        account: job.account.clone(),
                        link_id: job.link_id.clone(),
                        address_hash: hash,
                        recipient,
                        relay_fault: false,
                    },
                );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_inbox_counts_once_for_the_daily_cap() {
        for (normal, form) in [
            ("ada@example.com", "ada@example.com"),
            ("ada+links@example.com", "ada@example.com"),
            ("ada+a+b@example.com", "ada@example.com"),
            ("a.d.a@example.com", "a.d.a@example.com"),
            ("a.d.a+x@gmail.com", "ada@gmail.com"),
            ("ada@googlemail.com", "ada@gmail.com"),
            ("+tag@example.com", "+tag@example.com"),
        ] {
            assert_eq!(recipient_form(normal), form, "{normal}");
        }
    }

    #[test]
    fn the_normal_form_follows_the_contract() {
        assert_eq!(
            normal_address(" Ada.Lovelace@Example.COM ").as_deref(),
            Some("ada.lovelace@example.com")
        );
        assert_eq!(
            normal_address("\tgrace@BÜCHER.example.\n").as_deref(),
            Some("grace@xn--bcher-kva.example")
        );
        for refused in [
            "no-at-sign.example",
            "two@at@example.com",
            "dot.@example.com",
            "a..b@example.com",
            "user@localhost",
            "user@192.168.0.1",
            "user@[127.0.0.1]",
            "zoë@example.com",
        ] {
            assert_eq!(normal_address(refused), None, "{refused}");
        }
    }

    #[test]
    fn a_links_db_of_version_1_gets_the_two_counts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("links.db");
        let key = crate::secret::SecretString::new("a synthetic master key for tests".into());
        let version_1 = format!(
            "{}PRAGMA user_version = 1;",
            SCHEMA.replace(
                "  code_failures INTEGER NOT NULL DEFAULT 0,\n  code_requests INTEGER NOT NULL DEFAULT 0,\n",
                "",
            )
        );
        assert!(!version_1.contains("code_failures"));
        let store = Store::create_at(&path, &key, &version_1).unwrap();
        store
            .with(|conn| {
                conn.execute(
                    "INSERT INTO link (link_id, account_id, created_at, expires_at, one_time, access, addresses, sealed, create_hash) \
                     VALUES ('d4e59a0011f71c40fb1dfdb1a8446660', 'acc_aaaaaaaaaa', 1, 2, 0, 'anyone', 0, 'x', x'00')",
                    [],
                )
                .map_err(db)
            })
            .unwrap();
        migrate(&store).unwrap();
        assert_eq!(store.user_version().unwrap(), LINKS_VERSION);
        let counts: (i64, i64) = store
            .with(|conn| {
                conn.query_row("SELECT code_failures, code_requests FROM link", [], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .map_err(db)
            })
            .unwrap();
        assert_eq!(counts, (0, 0));
        // Again: nothing changes.
        migrate(&store).unwrap();
        assert_eq!(store.user_version().unwrap(), LINKS_VERSION);
    }

    #[test]
    fn a_links_db_of_version_2_gets_the_tables_of_version_3_and_one_secret() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("links.db");
        let key = crate::secret::SecretString::new("a synthetic master key for tests".into());
        let version_2 = format!("{SCHEMA}PRAGMA user_version = 2;");
        let store = Store::create_at(&path, &key, &version_2).unwrap();
        migrate(&store).unwrap();
        assert_eq!(store.user_version().unwrap(), LINKS_VERSION);
        let tables: i64 = store
            .with(|conn| {
                conn.query_row(
                    "SELECT count(*) FROM sqlite_master WHERE name IN ('link_secret', 'mail_recipient', 'link_creates')",
                    [],
                    |row| row.get(0),
                )
                .map_err(db)
            })
            .unwrap();
        assert_eq!(tables, 3);
        // The secret is made once and kept.
        let first = relay_secret(&store).unwrap();
        let second = relay_secret(&store).unwrap();
        assert_eq!(first.len(), 32);
        assert_eq!(*first, *second);
        // A new file has the same schema at once.
        let fresh = Store::create_at(&dir.path().join("new.db"), &key, &schema()).unwrap();
        assert_eq!(fresh.user_version().unwrap(), LINKS_VERSION);
        migrate(&fresh).unwrap();
        assert_eq!(relay_secret(&fresh).unwrap().len(), 32);
    }

    #[test]
    fn requests_are_strict() {
        let good = r#"{"link_id":"d4e59a0011f71c40fb1dfdb1a8446660","sealed":"x","expires_at":1,"one_time":false,"access":"anyone","address_hashes":[]}"#;
        assert!(strict::<CreateLink>(good.as_bytes()).is_ok());
        let duplicate = good.replace(r#""one_time":false"#, r#""one_time":false,"one_time":true"#);
        assert!(strict::<CreateLink>(duplicate.as_bytes()).is_err());
        let open = r#"{"confirm":false,"email":null,"address_key":null,"code":null}"#;
        assert!(strict::<OpenRequest>(open.as_bytes()).is_ok());
        for bad in [
            r#"{"confirm":false,"email":null,"address_key":null}"#,
            r#"{"confirm":false,"email":null,"address_key":null,"code":null,"code":null}"#,
            r#"{"confirm":false,"email":null,"address_key":null,"code":null,"x":1}"#,
        ] {
            assert!(strict::<OpenRequest>(bad.as_bytes()).is_err(), "{bad}");
        }
    }

    #[test]
    fn link_origins_are_https_or_a_loopback_test_origin() {
        for good in [
            "https://apassy-relay.wyderka.cc",
            "http://127.0.0.1:8080",
            "http://localhost",
            "http://localhost:3000",
        ] {
            assert!(link_origin_ok(good), "{good}");
        }
        for bad in [
            "http://relay.example.com",
            "http://127.0.0.1.example.com",
            "http://localhost.example:80",
            "http://10.0.0.1",
            "ftp://localhost",
            "http://localhost:x",
        ] {
            assert!(!link_origin_ok(bad), "{bad}");
        }
    }

    #[test]
    fn a_code_is_eight_digits() {
        for _ in 0..200 {
            let code = new_code().unwrap();
            assert_eq!(code.len(), CODE_DIGITS);
            assert!(code.bytes().all(|byte| byte.is_ascii_digit()));
        }
    }

    #[test]
    fn the_routes_take_only_their_methods() {
        assert_eq!(
            public_route("POST", "/v1/links/abc/open").unwrap(),
            PublicLinkEndpoint::Open("abc".into())
        );
        assert_eq!(
            public_route("GET", "/v1/links/abc/open").unwrap_err().code,
            codes::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            public_route("POST", "/v1/links/abc").unwrap_err().code,
            codes::NOT_FOUND
        );
        assert_eq!(
            account_route("PUT", &[]).unwrap_err().code,
            codes::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            account_route("DELETE", &["d4e59a0011f71c40fb1dfdb1a8446660"]).unwrap(),
            AccountLinkEndpoint::Revoke("d4e59a0011f71c40fb1dfdb1a8446660".into())
        );
        assert_eq!(
            account_route("DELETE", &["NOT-AN-ID"]).unwrap_err().code,
            codes::NOT_FOUND
        );
        assert!(viewer_file("/s").is_some_and(|(kind, _)| kind.starts_with("text/html")));
        assert!(viewer_file("/share.html").is_none());
    }
}
