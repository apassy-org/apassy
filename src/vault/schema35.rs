//! Schema version 35: a credential in several folders, and the public links of the vault
//! (ADR 0047 sections 2 and 4, release A of sharing).
//!
//! - `item_folder` gets the key `(item_id, folder_uuid)` and the column `added_at` (Unix
//!   milliseconds). A credential is in any number of folders, or in none. The rows stay
//!   child rows of the credential ([`super::merge::CHILD_TABLES`]): the step rebuilds the
//!   table, so it makes its triggers again (the sync triggers of schema 14 and the
//!   bouncer scope triggers of schema 20, [`item_folder_triggers_sql`]), and an index on
//!   `folder_uuid` serves the list of one folder. Every row of schema 34 stays, with the
//!   `updated_at` of its item as `added_at`; a credential had one folder then, so it
//!   stays its first folder.
//! - `public_link` (synced row by row, [`super::merge`]) holds each public link that the
//!   owner made: what it shows (`root_kind` `item` or `folder`, `root_uuid`), its name,
//!   the Connect origin, the expiry, "show once" (`one_time`), and the access: `anyone`,
//!   or `emails` with `addresses`, the normal forms of the allowed e-mail addresses
//!   (connect-share-v1 section 6), one a line, for the owner's list only (Connect keeps
//!   only their hashes). The columns are those of contract vault-v1, schema 35.
//!   `key` is the 32-byte link key `K`: it is secret material like a field value. It
//!   leaves the vault only in the link that the owner copies, never in a log or an
//!   answer to an agent. A revoked link keeps its row with `deleted_at`, so the revoke
//!   reaches every device and wins over any edit; such a row may drop its key (an empty
//!   blob) and its addresses. `created_at`, `expires_at`, and `deleted_at` are Unix
//!   seconds; `updated_at` is Unix milliseconds, the version of the row.
//!
//! The content hash of a credential with no folder or one folder is the hash of schema
//! 34, so a copy of schema 34 merges without a conflict copy. Two or more folders add a
//! part of their own (`merge::Record::content_hash`).
//!
//! Schema 35 follows [`PREVIOUS_SCHEMA_VERSION`]: a vault of an earlier schema runs the
//! steps before it and then this one, in one migration. A failure rolls the whole
//! migration back and the file keeps its old version. A device of the previous schema or
//! earlier refuses a copy of schema 35 (`UnsupportedSchema`).
//!
//! The way back ([`downgrade_sql`], for the fixtures and the rollback notes) keeps the
//! first folder of each credential (by `added_at`, then UUID) and drops the links.
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

/// The rebuilt `item_folder`, then the links. The triggers of `item_folder` come from
/// [`item_folder_triggers_sql`] after this.
const SCHEMA_V35_SQL: &str = "
CREATE TABLE item_folder_v35 (
    item_id INTEGER NOT NULL,
    folder_uuid TEXT NOT NULL,
    added_at INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (item_id, folder_uuid)
);
INSERT INTO item_folder_v35 (item_id, folder_uuid, added_at)
    SELECT f.item_id, f.folder_uuid, COALESCE(i.updated_at, 0)
    FROM item_folder f LEFT JOIN item i ON i.id = f.item_id;
DROP TABLE item_folder;
ALTER TABLE item_folder_v35 RENAME TO item_folder;
CREATE INDEX item_folder_folder ON item_folder(folder_uuid);
CREATE TABLE public_link (
    uuid TEXT PRIMARY KEY,
    link_id TEXT NOT NULL
        CHECK (length(link_id) = 32 AND link_id NOT GLOB '*[^0-9a-f]*'),
    root_kind TEXT NOT NULL CHECK (root_kind IN ('item', 'folder')),
    root_uuid TEXT NOT NULL,
    name TEXT NOT NULL,
    key BLOB NOT NULL,
    origin TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    one_time INTEGER NOT NULL DEFAULT 0 CHECK (one_time IN (0, 1)),
    access TEXT NOT NULL DEFAULT 'anyone' CHECK (access IN ('anyone', 'emails')),
    addresses TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    updated_by TEXT NOT NULL,
    deleted_at INTEGER,
    CHECK (typeof(key) = 'blob' AND (length(key) = 32 OR deleted_at IS NOT NULL)),
    CHECK (access = 'emails' OR addresses = ''),
    CHECK (access = 'anyone' OR addresses <> '' OR deleted_at IS NOT NULL)
);
CREATE INDEX public_link_root ON public_link(root_kind, root_uuid);
";

/// What `verify_expected_columns_in` reads for schema 35 and later.
pub(super) const COLUMNS: [&str; 2] = [
    "SELECT item_id, folder_uuid, added_at FROM item_folder LIMIT 0",
    "SELECT uuid, link_id, root_kind, root_uuid, name, key, origin, expires_at, one_time,
         access, addresses, created_at, updated_at, updated_by, deleted_at
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
/// each credential keeps its first folder (by `added_at`, then UUID), and the links go.
#[cfg(test)]
pub(super) fn downgrade_sql() -> String {
    let mut sql = "
DROP TABLE public_link;
CREATE TABLE item_folder_v34 (
    item_id INTEGER PRIMARY KEY,
    folder_uuid TEXT NOT NULL
);
INSERT INTO item_folder_v34 (item_id, folder_uuid)
    SELECT f.item_id, f.folder_uuid FROM item_folder f
    WHERE NOT EXISTS (
        SELECT 1 FROM item_folder g
        WHERE g.item_id = f.item_id AND (g.added_at, g.folder_uuid) < (f.added_at, f.folder_uuid)
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
            // The rows of schema 34 take the `updated_at` of their item.
            let added: Vec<(i64, i64)> = conn
                .prepare(
                    "SELECT f.added_at, i.updated_at FROM item_folder f
                     JOIN item i ON i.id = f.item_id ORDER BY f.item_id",
                )
                .unwrap()
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            assert_eq!(added.len(), 2);
            for (added_at, updated_at) in added {
                assert!(added_at > 0);
                assert_eq!(added_at, updated_at);
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
    fn the_way_back_keeps_the_first_folder() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("down.db");
        let mut vault = Vault::create(&path, PASS).unwrap();
        vault.unlock(PASS).unwrap();
        let a = add(&mut vault, "Alpha");
        let work = vault.create_folder(None, "Work").unwrap().uuid;
        let home = vault.create_folder(None, "Home").unwrap().uuid;
        vault.add_item_to_folder(a, &home).unwrap();
        vault.add_item_to_folder(a, &work).unwrap();
        vault.lock().unwrap();
        drop(vault);
        let conn = raw(&path);
        conn.execute_batch(&downgrade_sql()).unwrap();
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

    #[test]
    fn a_link_row_holds_a_key_of_32_bytes_until_it_is_revoked() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = Vault::create(&dir.path().join("links.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        let conn = vault.conn_ref().unwrap();
        const LINK_ID: &str = "d4e59a0011f71c40fb1dfdb1a8446660";
        let insert = |uuid: &str,
                      link_id: &str,
                      key: Vec<u8>,
                      access: &str,
                      addresses: &str,
                      deleted: Option<i64>|
         -> rusqlite::Result<usize> {
            conn.execute(
                "INSERT INTO public_link
                     (uuid, link_id, root_kind, root_uuid, name, key, origin, expires_at,
                      one_time, access, addresses, created_at, updated_at, updated_by,
                      deleted_at)
                 VALUES (?1, ?2, 'item', 'root', 'Name', ?3, 'https://connect.example.test',
                         2, 0, ?4, ?5, 1, 1000, 'dev', ?6)",
                rusqlite::params![uuid, link_id, key, access, addresses, deleted],
            )
        };
        insert("l1", LINK_ID, vec![7; 32], ACCESS_ANYONE, "", None).unwrap();
        insert(
            "l2",
            LINK_ID,
            vec![7; 32],
            ACCESS_EMAILS,
            "ola@example.test\npiotr@example.test",
            None,
        )
        .unwrap();
        // A revoked link may drop its key and its addresses.
        insert("l3", LINK_ID, Vec::new(), ACCESS_EMAILS, "", Some(5)).unwrap();
        for (uuid, link_id, key, access, addresses) in [
            ("b1", LINK_ID, vec![7; 31], ACCESS_ANYONE, ""),
            ("b2", LINK_ID, Vec::new(), ACCESS_ANYONE, ""),
            (
                "b3",
                LINK_ID,
                vec![7; 32],
                ACCESS_ANYONE,
                "ola@example.test",
            ),
            ("b4", LINK_ID, vec![7; 32], ACCESS_EMAILS, ""),
            ("b5", LINK_ID, vec![7; 32], "addresses", ""),
            (
                "b6",
                "D4E59A0011F71C40FB1DFDB1A8446660",
                vec![7; 32],
                ACCESS_ANYONE,
                "",
            ),
            ("b7", "d4e59a0011f71c40", vec![7; 32], ACCESS_ANYONE, ""),
        ] {
            assert!(
                insert(uuid, link_id, key, access, addresses, None).is_err(),
                "{uuid}"
            );
        }
        assert!(
            conn.execute(
                "INSERT INTO public_link
                     (uuid, link_id, root_kind, root_uuid, name, key, origin, expires_at,
                      created_at, updated_at, updated_by)
                 VALUES ('t1', 'd4e59a0011f71c40fb1dfdb1a8446660', 'item', 'root', 'Name',
                         ?1, 'o', 2, 1, 1000, 'dev')",
                [String::from_utf8(vec![b'k'; 32]).unwrap()],
            )
            .is_err(),
            "the key is a blob"
        );
        assert!(
            conn.execute(
                "INSERT INTO public_link
                     (uuid, link_id, root_kind, root_uuid, name, key, origin, expires_at,
                      created_at, updated_at, updated_by)
                 VALUES ('t2', 'd4e59a0011f71c40fb1dfdb1a8446660', 'vault', 'root', 'Name',
                         ?1, 'o', 2, 1, 1000, 'dev')",
                [vec![7u8; 32]],
            )
            .is_err(),
            "a link shows a credential or a folder"
        );
        // A revoke may clear the key.
        conn.execute(
            "UPDATE public_link SET deleted_at = 9, key = X'', addresses = '', updated_at = 2000
             WHERE uuid = 'l2'",
            [],
        )
        .unwrap();
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
