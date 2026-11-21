//! Schema version 35: a credential in several folders, and the public links of the vault
//! (ADR 0047 sections 2 and 4, release A of sharing; contract vault-v1, schema 35).
//!
//! - `item_folder` gets the key `(item_id, folder_uuid)`: a credential is in any number
//!   of folders, or in none. Each row is one membership and merges on its own
//!   ([`super::merge`]): `updated_at` (Unix milliseconds) and `updated_by` (the device)
//!   are its version, and `removed_at` (Unix milliseconds) marks a membership that ended,
//!   a tombstone that stays so the removal reaches every device. The later version wins,
//!   a removal wins a tie, and `added_at` (Unix milliseconds) takes the earliest value
//!   that any device has, so every device agrees on the first folder of a credential.
//!   Only rows without `removed_at` count. The rows stay child rows of the credential
//!   ([`super::merge::CHILD_TABLES`]): a change marks a change of the credential. The
//!   step rebuilds the table, so it makes its triggers again (the sync triggers of schema
//!   14 and the bouncer scope triggers of schema 20, [`item_folder_triggers_sql`]), and
//!   an index on `folder_uuid` serves the list of one folder. Every row of schema 34
//!   stays, with the `updated_at` and `updated_by` of its item as `added_at` and as its
//!   version; a credential had one folder then, so it stays its first folder.
//! - `public_link` (synced row by row, [`super::merge`]) holds each public link that the
//!   owner made: what it shows (`root_kind` `item` or `folder`, `root_uuid`), its name,
//!   the Connect origin, `account_id` (the Connect account that made the link), the
//!   expiry, "show once" (`one_time`), and the access: `anyone`, or `emails` with
//!   `addresses`, the normal forms of the allowed e-mail addresses (connect-share-v1
//!   section 6), one a line, 1 to 20, for the owner's list only (Connect keeps only their
//!   hashes). `key` is the 32-byte link key `K`: it is secret material like a field
//!   value. It leaves the vault only in the link that the owner copies, never in a log or
//!   an answer to an agent.
//!
//!   A revoke keeps the row with `deleted_at`, an empty `key`, and empty `addresses`, so
//!   it reaches every device and wins over any edit, also a later one. A device writes it
//!   only after Connect answered the revoke of the account in `account_id` with a success
//!   (`200`, or `404` for a link of that account): a device of another account in a
//!   shared vault shows the link but neither revokes it nor writes a revoke. A link id is
//!   used once (`UNIQUE`). The origin is `https://…`, or `http://localhost` and
//!   `http://127.0.0.1` with or without a port for tests, without a path. `created_at`,
//!   `expires_at` (after `created_at`), and `deleted_at` are Unix seconds; `updated_at`
//!   is Unix milliseconds, the version of the row.
//!
//! The content hash of a credential with no live folder or one is the hash of schema 34,
//! so a copy of schema 34 merges without a conflict copy. Two or more add a part of their
//! own (`merge::Record::content_hash`).
//!
//! Schema 35 follows [`PREVIOUS_SCHEMA_VERSION`]: a vault of an earlier schema runs the
//! steps before it and then this one, in one migration. A failure rolls the whole
//! migration back and the file keeps its old version. A device of the previous schema or
//! earlier refuses a copy of schema 35 (`UnsupportedSchema`).
//!
//! The way back ([`downgrade_sql`], for the fixtures and the rollback notes) keeps one
//! live membership of each credential, a folder that is still there first, then by
//! `added_at` and UUID, and drops the links.
//!
//! The number lives in [`MULTI_FOLDER_SCHEMA_VERSION`] only, and the step before it in
//! [`PREVIOUS_SCHEMA_VERSION`], so a release coordinator that renumbers this step changes
//! those two constants.

use rusqlite::Transaction;

use super::types::{SCHEMA_VERSION, VaultErrorKind, VaultResult, err};
use super::{merge, verify_expected_columns_in};

/// The schema version of several folders per credential and of public links.
pub(super) const MULTI_FOLDER_SCHEMA_VERSION: i64 = 35;
/// The newest schema before this one in the migration chain.
pub(super) const PREVIOUS_SCHEMA_VERSION: i64 = super::schema34::ACCOUNT_KEY_SCHEMA_VERSION;

const _: () = assert!(SCHEMA_VERSION == MULTI_FOLDER_SCHEMA_VERSION);
const _: () = assert!(PREVIOUS_SCHEMA_VERSION < MULTI_FOLDER_SCHEMA_VERSION);

/// The stored `root_kind` of a link that shows one credential.
#[allow(dead_code)]
pub(super) const ROOT_ITEM: &str = "item";
/// The stored `root_kind` of a link that shows a folder with its subfolders.
#[allow(dead_code)]
pub(super) const ROOT_FOLDER: &str = "folder";
/// The stored `access` of a link that anyone with the link opens.
#[allow(dead_code)]
pub(super) const ACCESS_ANYONE: &str = "anyone";
/// The stored `access` of a link that opens only for the listed e-mail addresses.
#[allow(dead_code)]
pub(super) const ACCESS_EMAILS: &str = "emails";
/// The most addresses of a link of `emails` (connect-share-v1 section 7).
#[allow(dead_code)]
pub(super) const MAX_LINK_ADDRESSES: usize = 20;

/// The rebuilt `item_folder`, then the links. The triggers of `item_folder` come from
/// [`item_folder_triggers_sql`] after this.
const SCHEMA_V35_SQL: &str = "
CREATE TABLE item_folder_v35 (
    item_id INTEGER NOT NULL,
    folder_uuid TEXT NOT NULL,
    added_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    updated_by TEXT NOT NULL,
    removed_at INTEGER,
    PRIMARY KEY (item_id, folder_uuid)
);
INSERT INTO item_folder_v35 (item_id, folder_uuid, added_at, updated_at, updated_by)
    SELECT f.item_id, f.folder_uuid, COALESCE(i.updated_at, 0), COALESCE(i.updated_at, 0),
        COALESCE(i.updated_by, '')
    FROM item_folder f LEFT JOIN item i ON i.id = f.item_id;
DROP TABLE item_folder;
ALTER TABLE item_folder_v35 RENAME TO item_folder;
CREATE INDEX item_folder_folder ON item_folder(folder_uuid);
CREATE TABLE public_link (
    uuid TEXT PRIMARY KEY,
    link_id TEXT NOT NULL UNIQUE
        CHECK (length(link_id) = 32 AND link_id NOT GLOB '*[^0-9a-f]*'),
    root_kind TEXT NOT NULL CHECK (root_kind IN ('item', 'folder')),
    root_uuid TEXT NOT NULL,
    name TEXT NOT NULL,
    key BLOB NOT NULL CHECK (typeof(key) = 'blob'),
    origin TEXT NOT NULL CHECK (
        (origin GLOB 'https://?*'
            OR origin = 'http://localhost' OR origin GLOB 'http://localhost:[0-9]*'
            OR origin = 'http://127.0.0.1' OR origin GLOB 'http://127.0.0.1:[0-9]*')
        AND instr(substr(origin, instr(origin, '://') + 3), '/') = 0
        AND origin NOT GLOB '*[ ?#]*'),
    account_id TEXT NOT NULL CHECK (account_id <> ''),
    expires_at INTEGER NOT NULL,
    one_time INTEGER NOT NULL DEFAULT 0 CHECK (one_time IN (0, 1)),
    access TEXT NOT NULL DEFAULT 'anyone' CHECK (access IN ('anyone', 'emails')),
    addresses TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    updated_by TEXT NOT NULL,
    deleted_at INTEGER,
    CHECK (expires_at > created_at),
    CHECK (deleted_at IS NOT NULL OR length(key) = 32),
    CHECK (deleted_at IS NULL OR (length(key) = 0 AND addresses = '')),
    CHECK (deleted_at IS NOT NULL
        OR (access = 'anyone' AND addresses = '')
        OR (access = 'emails' AND addresses <> ''
            AND length(addresses) - length(replace(addresses, char(10), '')) < 20
            AND instr(addresses, char(10) || char(10)) = 0
            AND substr(addresses, 1, 1) <> char(10)
            AND substr(addresses, -1, 1) <> char(10)
            AND instr(addresses, ' ') = 0
            AND instr(addresses, char(13)) = 0))
);
CREATE INDEX public_link_root ON public_link(root_kind, root_uuid);
";

/// What `verify_expected_columns_in` reads for schema 35 and later.
pub(super) const COLUMNS: [&str; 2] = [
    "SELECT item_id, folder_uuid, added_at, updated_at, updated_by, removed_at
         FROM item_folder LIMIT 0",
    "SELECT uuid, link_id, root_kind, root_uuid, name, key, origin, account_id, expires_at,
         one_time, access, addresses, created_at, updated_at, updated_by, deleted_at
         FROM public_link LIMIT 0",
];

/// The version marks of `version` in `vault_meta` and in the header.
fn marks_sql(version: i64) -> String {
    format!(
        "UPDATE vault_meta SET schema_version = {version} WHERE id = 1;
         PRAGMA user_version = {version};"
    )
}

/// The triggers of `item_folder`, which a rebuild of the table drops: a change of a row
/// is a change of its credential (`merge::child_triggers_sql`, schema 14), and it ends
/// the bouncer scopes of the credential (the triggers of `schema20.rs`, which also run
/// while sync applies rows).
fn item_folder_triggers_sql() -> String {
    let mut sql = merge::child_triggers_sql(&["item_folder"]);
    for (event, target) in [("insert", "NEW"), ("delete", "OLD")] {
        sql.push_str(&format!(
            "CREATE TRIGGER bouncer_scope_item_folder_{event} AFTER {event} ON item_folder BEGIN
             DELETE FROM bouncer_scope WHERE item_id = {target}.item_id; END;\n"
        ));
    }
    sql.push_str(
        "CREATE TRIGGER bouncer_scope_item_folder_update AFTER UPDATE ON item_folder BEGIN
         DELETE FROM bouncer_scope WHERE item_id IN (OLD.item_id, NEW.item_id); END;\n",
    );
    sql
}

/// Add schema version 35 in the migration or create transaction. Then the columns of
/// schema 35 are checked in the same transaction.
pub(super) fn add_schema_v35(tx: &Transaction<'_>) -> VaultResult<()> {
    let storage = |_| err(VaultErrorKind::Storage);
    tx.execute_batch(SCHEMA_V35_SQL).map_err(storage)?;
    tx.execute_batch(&item_folder_triggers_sql())
        .map_err(storage)?;
    tx.execute_batch(&marks_sql(MULTI_FOLDER_SCHEMA_VERSION))
        .map_err(storage)?;
    verify_expected_columns_in(tx, "main", MULTI_FOLDER_SCHEMA_VERSION)
}

/// The way back to the previous schema, for test fixtures and for the rollback notes:
/// each credential keeps one live membership (a folder that is still there first, then
/// by `added_at` and UUID), and the links go.
#[cfg(test)]
pub(super) fn downgrade_sql() -> String {
    let mut sql = "
DROP TABLE public_link;
CREATE TABLE item_folder_v34 (
    item_id INTEGER PRIMARY KEY,
    folder_uuid TEXT NOT NULL
);
WITH live AS (
    SELECT f.item_id, f.folder_uuid, f.added_at,
        CASE WHEN EXISTS (
            SELECT 1 FROM folder d WHERE d.uuid = f.folder_uuid AND d.deleted_at IS NULL
        ) THEN 0 ELSE 1 END AS gone
    FROM item_folder f WHERE f.removed_at IS NULL
)
INSERT INTO item_folder_v34 (item_id, folder_uuid)
    SELECT a.item_id, a.folder_uuid FROM live a
    WHERE NOT EXISTS (
        SELECT 1 FROM live b
        WHERE b.item_id = a.item_id
            AND (b.gone, b.added_at, b.folder_uuid) < (a.gone, a.added_at, a.folder_uuid)
    );
DROP TABLE item_folder;
ALTER TABLE item_folder_v34 RENAME TO item_folder;
"
    .to_owned();
    sql.push_str(&item_folder_triggers_sql());
    sql.push_str(&marks_sql(PREVIOUS_SCHEMA_VERSION));
    sql
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use super::*;
    use crate::contracts::CredentialKind;
    use crate::vault::{
        Field, ItemDraft, OPEN_EXISTING, SecretValue, Vault, VaultErrorKind, apply_key, close_conn,
    };

    const PASS: &str = "synthetic-schema35-pass";

    fn version(conn: &Connection) -> i64 {
        conn.query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap()
    }

    fn meta_version(conn: &Connection) -> i64 {
        conn.query_row(
            "SELECT schema_version FROM vault_meta WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .unwrap()
    }

    fn raw(path: &std::path::Path) -> Connection {
        let conn = Connection::open_with_flags(path, OPEN_EXISTING).unwrap();
        apply_key(&conn, PASS).unwrap();
        conn
    }

    fn has_table(conn: &Connection, name: &str) -> bool {
        conn.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = ?1",
            [name],
            |row| row.get::<_, i64>(0),
        )
        .unwrap()
            > 0
    }

    fn add(vault: &mut Vault, title: &str) -> u64 {
        vault
            .add(ItemDraft {
                title: title.to_owned(),
                kind: CredentialKind::ApiKey,
                notes: String::new(),
                tags: Vec::new(),
                fields: vec![Field {
                    name: "token".to_owned(),
                    value: SecretValue::new(format!("SYNTH-{title}")),
                    secret: true,
                }],
            })
            .unwrap()
            .id
    }

    /// A vault of the previous schema: three credentials, two in folders, one at the top
    /// level. Returns the path, the items, and the two folders.
    fn previous_file(dir: &tempfile::TempDir) -> (std::path::PathBuf, [u64; 3], [String; 2]) {
        let path = dir.path().join("previous.db");
        let mut vault = Vault::create(&path, PASS).unwrap();
        vault.unlock(PASS).unwrap();
        let a = add(&mut vault, "Alpha");
        let b = add(&mut vault, "Beta");
        let c = add(&mut vault, "Gamma");
        let work = vault.create_folder(None, "Work").unwrap().uuid;
        let home = vault.create_folder(None, "Home").unwrap().uuid;
        vault.set_item_folder(a, Some(&work)).unwrap();
        vault.set_item_folder(b, Some(&home)).unwrap();
        vault.lock().unwrap();
        drop(vault);
        let conn = raw(&path);
        conn.execute_batch(&downgrade_sql()).unwrap();
        assert_eq!(version(&conn), PREVIOUS_SCHEMA_VERSION);
        assert_eq!(meta_version(&conn), PREVIOUS_SCHEMA_VERSION);
        assert!(!has_table(&conn, "public_link"));
        assert!(
            conn.prepare("SELECT added_at FROM item_folder").is_err(),
            "item_folder has the shape of schema 34"
        );
        close_conn(conn).unwrap();
        (path, [a, b, c], [work, home])
    }

    #[test]
    fn a_vault_of_schema_34_keeps_each_folder() {
        let dir = tempfile::TempDir::new().unwrap();
        let (path, [a, b, c], [work, home]) = previous_file(&dir);
        let mut vault = Vault::open(&path).unwrap();
        vault.unlock(PASS).unwrap();
        {
            let conn = vault.conn_ref().unwrap();
            assert_eq!(version(conn), SCHEMA_VERSION);
            assert_eq!(meta_version(conn), SCHEMA_VERSION);
            assert!(has_table(conn, "public_link"));
            // The rows of schema 34 take the `updated_at` and `updated_by` of their item, and
            // they are live.
            let rows: Vec<(i64, i64, String, String, Option<i64>)> = conn
                .prepare(
                    "SELECT f.added_at, f.updated_at, f.updated_by, i.updated_by, f.removed_at
                     FROM item_folder f JOIN item i ON i.id = f.item_id
                     WHERE f.added_at = i.updated_at ORDER BY f.item_id",
                )
                .unwrap()
                .query_map([], |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                })
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            assert_eq!(rows.len(), 2);
            for (added_at, updated_at, by, item_by, removed_at) in rows {
                assert!(added_at > 0);
                assert_eq!(added_at, updated_at);
                assert_eq!(by, item_by);
                assert!(removed_at.is_none());
            }
            // The child triggers and the index are there again.
            let names: Vec<String> = conn
                .prepare(
                    "SELECT name FROM sqlite_schema WHERE tbl_name = 'item_folder'
                     AND type IN ('trigger', 'index') AND name NOT LIKE 'sqlite_%'
                     ORDER BY name",
                )
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            assert_eq!(
                names,
                [
                    "bouncer_scope_item_folder_delete",
                    "bouncer_scope_item_folder_insert",
                    "bouncer_scope_item_folder_update",
                    "item_folder_folder",
                    "item_folder_sync_delete",
                    "item_folder_sync_insert",
                    "item_folder_sync_update",
                ]
            );
        }
        assert_eq!(vault.item_folders(a).unwrap(), std::slice::from_ref(&work));
        assert_eq!(vault.item_folders(b).unwrap(), std::slice::from_ref(&home));
        assert!(vault.item_folders(c).unwrap().is_empty());
        assert_eq!(
            vault.item_folder(a).unwrap().as_deref(),
            Some(work.as_str())
        );
        // The new key takes a second folder; the first stays the first.
        vault.add_item_to_folder(a, &home).unwrap();
        assert_eq!(vault.item_folders(a).unwrap(), [work.clone(), home.clone()]);
        assert_eq!(
            vault.item_folder(a).unwrap().as_deref(),
            Some(work.as_str())
        );
    }

    #[test]
    fn a_change_of_a_folder_row_is_a_change_of_its_credential() {
        let dir = tempfile::TempDir::new().unwrap();
        let (path, [a, _, _], [_, home]) = previous_file(&dir);
        let mut vault = Vault::open(&path).unwrap();
        vault.unlock(PASS).unwrap();
        let stamp = |vault: &Vault| -> (i64, String) {
            vault
                .conn_ref()
                .unwrap()
                .query_row(
                    "SELECT updated_at, updated_by FROM item WHERE id = ?1",
                    [i64::try_from(a).unwrap()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap()
        };
        vault
            .conn_ref()
            .unwrap()
            .execute(
                "UPDATE item SET updated_at = 1, updated_by = 'old' WHERE id = ?1",
                [i64::try_from(a).unwrap()],
            )
            .unwrap();
        assert_eq!(stamp(&vault), (1, "old".to_owned()));
        vault.add_item_to_folder(a, &home).unwrap();
        let (at, by) = stamp(&vault);
        assert!(at > 1);
        assert_ne!(by, "old");
    }

    #[test]
    fn a_failed_step_keeps_schema_34() {
        let dir = tempfile::TempDir::new().unwrap();
        let (path, [a, _, _], [work, _]) = previous_file(&dir);
        let mut conn = raw(&path);
        let tx = conn.transaction().unwrap();
        add_schema_v35(&tx).unwrap();
        // Roll back, as a failure of a later step does.
        drop(tx);
        assert_eq!(version(&conn), PREVIOUS_SCHEMA_VERSION);
        assert_eq!(meta_version(&conn), PREVIOUS_SCHEMA_VERSION);
        assert!(!has_table(&conn, "public_link"));
        // A table of that name already there makes the unlock fail after the rebuild of
        // `item_folder`, and the file keeps the previous schema with its folder rows.
        conn.execute_batch("CREATE TABLE public_link (uuid TEXT PRIMARY KEY);")
            .unwrap();
        close_conn(conn).unwrap();
        let mut vault = Vault::open(&path).unwrap();
        assert_eq!(
            vault.unlock(PASS).unwrap_err().kind(),
            VaultErrorKind::Storage
        );
        drop(vault);
        let conn = raw(&path);
        assert_eq!(version(&conn), PREVIOUS_SCHEMA_VERSION);
        assert_eq!(meta_version(&conn), PREVIOUS_SCHEMA_VERSION);
        assert!(conn.prepare("SELECT added_at FROM item_folder").is_err());
        let kept: String = conn
            .query_row(
                "SELECT folder_uuid FROM item_folder WHERE item_id = ?1",
                [i64::try_from(a).unwrap()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(kept, work);
        conn.execute_batch("DROP TABLE public_link;").unwrap();
        close_conn(conn).unwrap();
        let mut vault = Vault::open(&path).unwrap();
        vault.unlock(PASS).unwrap();
        assert_eq!(version(vault.conn_ref().unwrap()), SCHEMA_VERSION);
        assert_eq!(vault.item_folders(a).unwrap(), [work]);
    }

    #[test]
    fn the_way_back_keeps_the_first_live_folder() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("down.db");
        let mut vault = Vault::create(&path, PASS).unwrap();
        vault.unlock(PASS).unwrap();
        let a = add(&mut vault, "Alpha");
        let work = vault.create_folder(None, "Work").unwrap().uuid;
        let home = vault.create_folder(None, "Home").unwrap().uuid;
        let bills = vault.create_folder(None, "Bills").unwrap().uuid;
        let gone = vault.create_folder(None, "Gone").unwrap().uuid;
        let b = add(&mut vault, "Beta");
        // Alpha: "Bills" first but removed, then "Home", then "Work".
        vault.add_item_to_folder(a, &bills).unwrap();
        vault.add_item_to_folder(a, &home).unwrap();
        vault.add_item_to_folder(a, &work).unwrap();
        vault.remove_item_from_folder(a, &bills).unwrap();
        // Beta: "Gone" first, then "Work"; then "Gone" is deleted elsewhere, so its
        // membership is still live here.
        vault.add_item_to_folder(b, &gone).unwrap();
        vault.add_item_to_folder(b, &work).unwrap();
        vault
            .conn_ref()
            .unwrap()
            .execute("UPDATE folder SET deleted_at = 1 WHERE uuid = ?1", [&gone])
            .unwrap();
        vault.lock().unwrap();
        drop(vault);
        let conn = raw(&path);
        conn.execute_batch(&downgrade_sql()).unwrap();
        let beta: String = conn
            .query_row(
                "SELECT folder_uuid FROM item_folder WHERE item_id = ?1",
                [i64::try_from(b).unwrap()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(beta, work, "a folder that is still there first");
        conn.execute(
            "DELETE FROM item_folder WHERE item_id = ?1",
            [i64::try_from(b).unwrap()],
        )
        .unwrap();
        let kept: Vec<String> = conn
            .prepare("SELECT folder_uuid FROM item_folder")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(kept, std::slice::from_ref(&home));
        close_conn(conn).unwrap();
        let mut vault = Vault::open(&path).unwrap();
        vault.unlock(PASS).unwrap();
        assert_eq!(vault.item_folders(a).unwrap(), [home]);
    }

    /// The columns of one link row, for the checks of the table.
    struct Link {
        uuid: &'static str,
        link_id: &'static str,
        root_kind: &'static str,
        key: Vec<u8>,
        origin: &'static str,
        account_id: &'static str,
        expires_at: i64,
        access: &'static str,
        addresses: String,
        deleted_at: Option<i64>,
    }

    impl Link {
        fn live(uuid: &'static str, link_id: &'static str) -> Self {
            Self {
                uuid,
                link_id,
                root_kind: ROOT_ITEM,
                key: vec![7; 32],
                origin: "https://connect.example.test",
                account_id: "acc_synthetic01",
                expires_at: 3600,
                access: ACCESS_ANYONE,
                addresses: String::new(),
                deleted_at: None,
            }
        }

        fn insert(&self, conn: &Connection) -> rusqlite::Result<usize> {
            conn.execute(
                "INSERT INTO public_link
                     (uuid, link_id, root_kind, root_uuid, name, key, origin, account_id,
                      expires_at, one_time, access, addresses, created_at, updated_at,
                      updated_by, deleted_at)
                 VALUES (?1, ?2, ?3, 'root', 'Name', ?4, ?5, ?6, ?7, 0, ?8, ?9, 1, 1000, 'dev',
                         ?10)",
                rusqlite::params![
                    self.uuid,
                    self.link_id,
                    self.root_kind,
                    self.key,
                    self.origin,
                    self.account_id,
                    self.expires_at,
                    self.access,
                    self.addresses,
                    self.deleted_at
                ],
            )
        }
    }

    /// A link id of 32 lowercase hex characters that ends with `n`.
    fn link_id(n: u8) -> &'static str {
        Box::leak(format!("d4e59a0011f71c40fb1dfdb1a84466{n:02x}").into_boxed_str())
    }

    #[test]
    fn a_link_row_holds_its_key_and_addresses_until_it_is_revoked() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = Vault::create(&dir.path().join("links.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        let conn = vault.conn_ref().unwrap();
        let emails = |n: usize| {
            (0..n)
                .map(|i| format!("person{i}@example.test"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        let good = [
            Link::live("g1", link_id(1)),
            Link {
                access: ACCESS_EMAILS,
                addresses: emails(1),
                ..Link::live("g2", link_id(2))
            },
            Link {
                access: ACCESS_EMAILS,
                addresses: emails(MAX_LINK_ADDRESSES),
                root_kind: ROOT_FOLDER,
                ..Link::live("g3", link_id(3))
            },
            Link {
                origin: "http://localhost",
                ..Link::live("g4", link_id(4))
            },
            Link {
                origin: "http://127.0.0.1:8787",
                ..Link::live("g5", link_id(5))
            },
            // A revoke: no key and no addresses.
            Link {
                key: Vec::new(),
                access: ACCESS_EMAILS,
                deleted_at: Some(5),
                ..Link::live("g6", link_id(6))
            },
        ];
        for link in &good {
            link.insert(conn)
                .unwrap_or_else(|error| panic!("{}: {error}", link.uuid));
        }
        let bad = [
            (
                "a key of 31 bytes",
                Link {
                    key: vec![7; 31],
                    ..Link::live("b1", link_id(11))
                },
            ),
            (
                "a live link without a key",
                Link {
                    key: Vec::new(),
                    ..Link::live("b2", link_id(12))
                },
            ),
            (
                "addresses for anyone",
                Link {
                    addresses: emails(1),
                    ..Link::live("b3", link_id(13))
                },
            ),
            (
                "emails without addresses",
                Link {
                    access: ACCESS_EMAILS,
                    ..Link::live("b4", link_id(14))
                },
            ),
            (
                "21 addresses",
                Link {
                    access: ACCESS_EMAILS,
                    addresses: emails(MAX_LINK_ADDRESSES + 1),
                    ..Link::live("b5", link_id(15))
                },
            ),
            (
                "a blank line",
                Link {
                    access: ACCESS_EMAILS,
                    addresses: "a@example.test\n\nb@example.test".to_owned(),
                    ..Link::live("b6", link_id(16))
                },
            ),
            (
                "a trailing line break",
                Link {
                    access: ACCESS_EMAILS,
                    addresses: "a@example.test\n".to_owned(),
                    ..Link::live("b7", link_id(17))
                },
            ),
            (
                "an unknown access",
                Link {
                    access: "addresses",
                    ..Link::live("b8", link_id(18))
                },
            ),
            (
                "an id in capitals",
                Link::live("b9", "D4E59A0011F71C40FB1DFDB1A8446619"),
            ),
            ("a short id", Link::live("b10", "d4e59a0011f71c40")),
            ("a used id", Link::live("b11", link_id(1))),
            (
                "another kind",
                Link {
                    root_kind: "vault",
                    ..Link::live("b12", link_id(20))
                },
            ),
            (
                "plain http",
                Link {
                    origin: "http://connect.example.test",
                    ..Link::live("b13", link_id(21))
                },
            ),
            (
                "a path",
                Link {
                    origin: "https://connect.example.test/s",
                    ..Link::live("b14", link_id(22))
                },
            ),
            (
                "a trailing slash",
                Link {
                    origin: "https://connect.example.test/",
                    ..Link::live("b15", link_id(23))
                },
            ),
            (
                "no host",
                Link {
                    origin: "https://",
                    ..Link::live("b16", link_id(24))
                },
            ),
            (
                "no account",
                Link {
                    account_id: "",
                    ..Link::live("b17", link_id(25))
                },
            ),
            (
                "an expiry before the creation",
                Link {
                    expires_at: 1,
                    ..Link::live("b18", link_id(26))
                },
            ),
            (
                "a revoke that keeps the key",
                Link {
                    deleted_at: Some(5),
                    ..Link::live("b19", link_id(27))
                },
            ),
            (
                "a revoke that keeps the addresses",
                Link {
                    key: Vec::new(),
                    access: ACCESS_EMAILS,
                    addresses: emails(1),
                    deleted_at: Some(5),
                    ..Link::live("b20", link_id(28))
                },
            ),
        ];
        for (why, link) in &bad {
            assert!(link.insert(conn).is_err(), "{why}");
        }
        assert!(
            conn.execute(
                "INSERT INTO public_link
                     (uuid, link_id, root_kind, root_uuid, name, key, origin, account_id,
                      expires_at, created_at, updated_at, updated_by)
                 VALUES ('t1', ?1, 'item', 'root', 'Name', ?2, 'https://connect.example.test',
                         'acc_synthetic01', 3600, 1, 1000, 'dev')",
                (link_id(30), String::from_utf8(vec![b'k'; 32]).unwrap()),
            )
            .is_err(),
            "the key is a blob"
        );
        // The revoke of a live link wipes the key and the addresses in the same write.
        let revoke = |uuid: &str, wipe: bool| {
            let sql = if wipe {
                "UPDATE public_link SET deleted_at = 9, key = X'', addresses = '',
                     updated_at = 2000 WHERE uuid = ?1"
            } else {
                "UPDATE public_link SET deleted_at = 9, updated_at = 2000 WHERE uuid = ?1"
            };
            conn.execute(sql, [uuid])
        };
        assert!(revoke("g2", false).is_err());
        revoke("g2", true).unwrap();
        // A revoked row never becomes live again without a key.
        assert!(
            conn.execute(
                "UPDATE public_link SET deleted_at = NULL WHERE uuid = 'g2'",
                []
            )
            .is_err()
        );
    }

    #[test]
    fn every_new_table_is_classified_and_copies_of_34_still_merge() {
        assert!(merge::SYNCED_TABLES.contains(&"public_link"));
        assert!(merge::SYNCED_TABLES.contains(&"item_folder"));
        assert!(merge::CHILD_TABLES.contains(&"item_folder"));
        assert!(!merge::LOCAL_TABLES.contains(&"public_link"));
        for version in [16, PREVIOUS_SCHEMA_VERSION, MULTI_FOLDER_SCHEMA_VERSION] {
            assert!(merge::is_mergeable_schema(version), "{version}");
        }
        for version in [30, 31, 33, MULTI_FOLDER_SCHEMA_VERSION + 1] {
            assert!(!merge::is_mergeable_schema(version), "{version}");
        }
    }
}
