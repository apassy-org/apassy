//! The public links of the vault (schema 35, ADR 0047 section 4, contract
//! connect-share-v1): one row of `public_link` for each link that an account made.
//!
//! - The row syncs ([`super::merge`], last writer wins, a revoke wins over any edit), so
//!   every device of the vault lists the link. Only devices of the account that made it
//!   (`account_id`) copy it again and revoke it; a device of another account that shares
//!   the vault lists it as made by that account.
//! - `key` is the link key `K`: secret material, like a field value. It leaves the vault
//!   only in the link text that the owner copies ([`PublicLink::key`]), never in a log,
//!   a `Debug` text, an answer to an agent, or an export.
//! - The writes are crate-internal. The app writes a row only after Connect took the
//!   link, and a revoke only after Connect deleted it (`crate::connect::link`): a row
//!   that says revoked is a link that no longer opens.
//! - The history of each credential of the link gets `link_created` and `link_revoked`
//!   with the name of the link, never its key. They stay on the device that wrote them.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use zeroize::Zeroizing;

use super::Vault;
use super::history::{self, ItemEventKind};
use super::to_sql_id;
use super::types::{VaultErrorKind, VaultResult, err};

/// The most addresses of a link (connect-share-v1 section 7).
pub const MAX_LINK_ADDRESSES: usize = super::schema35::MAX_LINK_ADDRESSES;
/// The longest name of a link in bytes (the `title` of the snapshot).
pub const MAX_LINK_NAME_BYTES: usize = 128;

fn storage<E>(_: E) -> super::VaultError {
    err(VaultErrorKind::Storage)
}

/// What a link shows.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum LinkRoot {
    /// One credential, by its sync UUID.
    Item(String),
    /// A folder with its subfolders, by its UUID.
    Folder(String),
}

impl LinkRoot {
    /// The stored `root_kind`.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Item(_) => super::schema35::ROOT_ITEM,
            Self::Folder(_) => super::schema35::ROOT_FOLDER,
        }
    }

    /// The stored `root_uuid`.
    pub fn uuid(&self) -> &str {
        match self {
            Self::Item(uuid) | Self::Folder(uuid) => uuid,
        }
    }

    fn parse(kind: &str, uuid: String) -> VaultResult<Self> {
        match kind {
            super::schema35::ROOT_ITEM => Ok(Self::Item(uuid)),
            super::schema35::ROOT_FOLDER => Ok(Self::Folder(uuid)),
            _ => Err(storage(())),
        }
    }
}

/// One public link as the vault keeps it.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicLink {
    pub uuid: String,
    /// The link id at Connect: 32 lowercase hex.
    pub link_id: String,
    pub root: LinkRoot,
    /// The name of the secret or the folder when the link was made.
    pub name: String,
    key: Zeroizing<Vec<u8>>,
    /// The Connect origin of the link, without a trailing slash.
    pub origin: String,
    /// The Connect account that made the link.
    pub account_id: String,
    /// Unix seconds.
    pub expires_at: u64,
    pub one_time: bool,
    /// The normal forms of the allowed addresses; empty for "Anyone with the link".
    pub addresses: Vec<String>,
    /// Unix seconds.
    pub created_at: u64,
    /// Unix seconds of the revoke; `None` while the link was not revoked.
    pub revoked_at: Option<u64>,
}

impl fmt::Debug for PublicLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicLink")
            .field("uuid", &self.uuid)
            .field("link_id", &self.link_id)
            .field("root", &self.root)
            .field("account_id", &self.account_id)
            .field("expires_at", &self.expires_at)
            .field("one_time", &self.one_time)
            .field("addresses", &self.addresses.len())
            .field("revoked_at", &self.revoked_at)
            .field("key", &"[redacted]")
            .finish_non_exhaustive()
    }
}

impl PublicLink {
    /// The link key `K` (32 bytes), or `None` for a revoked link, whose key is gone.
    pub fn key(&self) -> Option<&[u8]> {
        (self.key.len() == 32).then_some(self.key.as_slice())
    }

    /// Whether the link was made for the e-mail addresses in [`Self::addresses`].
    pub fn for_emails(&self) -> bool {
        !self.addresses.is_empty()
    }

    /// Whether the link may still open at `now` (not revoked, not expired). A one-time
    /// link that was opened is known only to Connect.
    pub fn is_live(&self, now: u64) -> bool {
        self.revoked_at.is_none() && self.expires_at > now
    }
}

/// A new row: what the app writes after Connect took the link.
pub(crate) struct NewPublicLink<'a> {
    pub link_id: &'a str,
    pub root: &'a LinkRoot,
    pub name: &'a str,
    pub key: &'a [u8; 32],
    pub origin: &'a str,
    pub account_id: &'a str,
    pub expires_at: u64,
    pub one_time: bool,
    pub addresses: &'a [String],
    pub created_at: u64,
    /// The credentials of the snapshot, whose history gets `link_created`.
    pub items: &'a [u64],
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        })
}

fn now_unix() -> i64 {
    now_ms() / 1000
}

/// The version of a change by this device after `previous` (Unix milliseconds, later
/// than `previous`) and the sync device ID.
fn next_version(conn: &Connection, previous: Option<i64>) -> VaultResult<(i64, String)> {
    let device: Option<String> = conn
        .query_row(
            "SELECT device_id FROM sync_device WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage)?;
    let at = match previous {
        Some(previous) => now_ms().max(previous.saturating_add(1)),
        None => now_ms(),
    };
    Ok((at, device.unwrap_or_default()))
}

fn new_uuid() -> VaultResult<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| err(VaultErrorKind::Io))?;
    Ok(super::to_hex(&bytes))
}

fn valid_link_id(text: &str) -> bool {
    text.len() == 32
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The origin rule of the table and of connect-share-v1 section 2: `https://`, or
/// `http://localhost` and `http://127.0.0.1` with an optional port; no path.
pub(crate) fn valid_link_origin(origin: &str) -> bool {
    let rest = if let Some(rest) = origin.strip_prefix("https://") {
        rest
    } else if let Some(rest) = origin.strip_prefix("http://") {
        let host = rest.split(':').next().unwrap_or_default();
        if host != "localhost" && host != "127.0.0.1" {
            return false;
        }
        rest
    } else {
        return false;
    };
    !rest.is_empty()
        && !rest.contains('/')
        && rest.len() <= 260
        && rest.bytes().all(|byte| byte.is_ascii_graphic())
}

const COLUMNS: &str = "uuid, link_id, root_kind, root_uuid, name, key, origin, account_id, \
                       expires_at, one_time, access, addresses, created_at, deleted_at";

fn row_to_link(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawLink> {
    Ok(RawLink {
        uuid: row.get(0)?,
        link_id: row.get(1)?,
        root_kind: row.get(2)?,
        root_uuid: row.get(3)?,
        name: row.get(4)?,
        key: Zeroizing::new(row.get(5)?),
        origin: row.get(6)?,
        account_id: row.get(7)?,
        expires_at: row.get(8)?,
        one_time: row.get(9)?,
        access: row.get(10)?,
        addresses: row.get(11)?,
        created_at: row.get(12)?,
        deleted_at: row.get(13)?,
    })
}

struct RawLink {
    uuid: String,
    link_id: String,
    root_kind: String,
    root_uuid: String,
    name: String,
    key: Zeroizing<Vec<u8>>,
    origin: String,
    account_id: String,
    expires_at: i64,
    one_time: bool,
    access: String,
    addresses: String,
    created_at: i64,
    deleted_at: Option<i64>,
}

impl RawLink {
    fn into_link(self) -> VaultResult<PublicLink> {
        let time = |at: i64| u64::try_from(at).map_err(storage);
        let addresses: Vec<String> = if self.access == super::schema35::ACCESS_EMAILS {
            self.addresses.lines().map(str::to_owned).collect()
        } else {
            Vec::new()
        };
        Ok(PublicLink {
            root: LinkRoot::parse(&self.root_kind, self.root_uuid)?,
            uuid: self.uuid,
            link_id: self.link_id,
            name: self.name,
            key: self.key,
            origin: self.origin,
            account_id: self.account_id,
            expires_at: time(self.expires_at)?,
            one_time: self.one_time,
            addresses,
            created_at: time(self.created_at)?,
            revoked_at: self.deleted_at.map(time).transpose()?,
        })
    }
}

fn load(
    conn: &Connection,
    filter: &str,
    params: &[&dyn rusqlite::ToSql],
) -> VaultResult<Vec<PublicLink>> {
    let sql = format!("SELECT {COLUMNS} FROM public_link {filter} ORDER BY created_at DESC, uuid");
    let mut stmt = conn.prepare(&sql).map_err(storage)?;
    let rows = stmt.query_map(params, row_to_link).map_err(storage)?;
    let mut links = Vec::new();
    for row in rows {
        links.push(row.map_err(storage)?.into_link()?);
    }
    Ok(links)
}

/// The credentials that a link shows now: the one credential, or each credential of the
/// folder and its subfolders. A root that is gone shows none.
fn items_of(vault: &Vault, root: &LinkRoot) -> VaultResult<Vec<u64>> {
    match root {
        LinkRoot::Item(uuid) => Ok(vault.item_by_uuid(uuid)?.into_iter().collect()),
        LinkRoot::Folder(uuid) => match vault.items_in_folder(Some(uuid), true) {
            Ok(items) => Ok(items),
            Err(error) if error.kind() == VaultErrorKind::NotFound => Ok(Vec::new()),
            Err(error) => Err(error),
        },
    }
}

impl Vault {
    /// Every link of the vault that was not revoked, the newest first; expired ones too.
    pub fn public_links(&self) -> VaultResult<Vec<PublicLink>> {
        load(self.conn_ref()?, "WHERE deleted_at IS NULL", &[])
    }

    /// The links of [`Self::public_links`] that show `root`.
    pub fn public_links_of(&self, root: &LinkRoot) -> VaultResult<Vec<PublicLink>> {
        load(
            self.conn_ref()?,
            "WHERE deleted_at IS NULL AND root_kind = ?1 AND root_uuid = ?2",
            &[&root.kind(), &root.uuid()],
        )
    }

    /// The row of `uuid`, also a revoked one.
    pub fn public_link(&self, uuid: &str) -> VaultResult<Option<PublicLink>> {
        Ok(load(self.conn_ref()?, "WHERE uuid = ?1", &[&uuid])?
            .into_iter()
            .next())
    }

    /// Write the row of a link that Connect took, with `link_created` in the history of
    /// each credential of its snapshot, in one transaction. Returns the stored row.
    ///
    /// `InvalidInput`: a link id that is not 32 lowercase hex, an empty name or one over
    /// [`MAX_LINK_NAME_BYTES`], an origin that is not `https://` (or loopback `http://`),
    /// an empty account id, an expiry not after the creation, more than
    /// [`MAX_LINK_ADDRESSES`] addresses or an empty or multi-line one. `AlreadyExists`: a
    /// row holds this link id already.
    pub(crate) fn add_public_link(&mut self, link: &NewPublicLink<'_>) -> VaultResult<PublicLink> {
        let invalid = || err(VaultErrorKind::InvalidInput);
        if !valid_link_id(link.link_id)
            || link.name.is_empty()
            || link.name.len() > MAX_LINK_NAME_BYTES
            || !valid_link_origin(link.origin)
            || link.account_id.is_empty()
            || link.expires_at <= link.created_at
            || link.addresses.len() > MAX_LINK_ADDRESSES
            || link
                .addresses
                .iter()
                .any(|address| address.trim().is_empty() || address.contains(['\n', '\r']))
        {
            return Err(invalid());
        }
        let access = if link.addresses.is_empty() {
            super::schema35::ACCESS_ANYONE
        } else {
            super::schema35::ACCESS_EMAILS
        };
        let expires_at = i64::try_from(link.expires_at).map_err(|_| invalid())?;
        let created_at = i64::try_from(link.created_at).map_err(|_| invalid())?;
        let uuid = new_uuid()?;
        let items: Vec<i64> = link
            .items
            .iter()
            .map(|id| to_sql_id(*id))
            .collect::<VaultResult<_>>()?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let taken: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM public_link WHERE link_id = ?1)",
                [link.link_id],
                |row| row.get(0),
            )
            .map_err(storage)?;
        if taken {
            return Err(err(VaultErrorKind::AlreadyExists));
        }
        let (at, by) = next_version(&tx, None)?;
        tx.execute(
            "INSERT INTO public_link (uuid, link_id, root_kind, root_uuid, name, key, origin,
                 account_id, expires_at, one_time, access, addresses, created_at, updated_at,
                 updated_by)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            rusqlite::params![
                uuid,
                link.link_id,
                link.root.kind(),
                link.root.uuid(),
                link.name,
                link.key.as_slice(),
                link.origin,
                link.account_id,
                expires_at,
                link.one_time,
                access,
                link.addresses.join("\n"),
                created_at,
                at,
                by,
            ],
        )
        .map_err(storage)?;
        for item in items {
            // A credential that went meanwhile has no history to write.
            if super::agents::require_item(&tx, item).is_ok() {
                history::record(&tx, item, ItemEventKind::LinkCreated, link.name)?;
            }
        }
        let stored = load(&tx, "WHERE uuid = ?1", &[&uuid])?
            .into_iter()
            .next()
            .ok_or_else(|| storage(()))?;
        tx.commit().map_err(storage)?;
        Ok(stored)
    }

    /// Mark the link `uuid` revoked after Connect deleted it for `account_id`: the row
    /// keeps its id with `deleted_at`, loses its key and its addresses, and each
    /// credential that it shows gets `link_revoked`. The revoke reaches every device and
    /// wins over any later edit. Returns whether a live row was revoked.
    ///
    /// `InvalidInput`: the row was made by another account, which alone may revoke it.
    pub(crate) fn mark_public_link_revoked(
        &mut self,
        uuid: &str,
        account_id: &str,
    ) -> VaultResult<bool> {
        let Some(link) = self.public_link(uuid)? else {
            return Ok(false);
        };
        if link.revoked_at.is_some() {
            return Ok(false);
        }
        if link.account_id != account_id {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        let items = items_of(self, &link.root)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let previous: Option<i64> = tx
            .query_row(
                "SELECT updated_at FROM public_link WHERE uuid = ?1 AND deleted_at IS NULL",
                [uuid],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?;
        let Some(previous) = previous else {
            return Ok(false);
        };
        let (at, by) = next_version(&tx, Some(previous))?;
        tx.execute(
            "UPDATE public_link SET deleted_at = ?1, key = X'', addresses = '',
                 updated_at = ?2, updated_by = ?3
             WHERE uuid = ?4",
            rusqlite::params![now_unix().max(1), at, by, uuid],
        )
        .map_err(storage)?;
        for item in items {
            let item = to_sql_id(item)?;
            if super::agents::require_item(&tx, item).is_ok() {
                history::record(&tx, item, ItemEventKind::LinkRevoked, &link.name)?;
            }
        }
        tx.commit().map_err(storage)?;
        Ok(true)
    }
}

/// A live row of an item link with a synthetic key, for the tests of the app.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn public_link_for_test(
    uuid: &str,
    link_id: &str,
    name: &str,
    account_id: &str,
    expires_at: u64,
    one_time: bool,
    addresses: Vec<String>,
    created_at: u64,
) -> PublicLink {
    PublicLink {
        uuid: uuid.to_owned(),
        link_id: link_id.to_owned(),
        root: LinkRoot::Item("item".to_owned()),
        name: name.to_owned(),
        key: Zeroizing::new(vec![7; 32]),
        origin: "https://connect.example.test".to_owned(),
        account_id: account_id.to_owned(),
        expires_at,
        one_time,
        addresses,
        created_at,
        revoked_at: None,
    }
}
