//! Folders of the vault (schema 18, ADR 0026 §5).
//!
//! A folder has a random UUID, a name, an optional parent, and a position among its
//! siblings. A credential is in any number of folders (schema 35, ADR 0047 §2): each
//! membership is an `item_folder` row, a child row of the credential, with the time it
//! was added and a version of its own. A membership that ends keeps its row with
//! `removed_at`, so the removal reaches the other devices; the reads see only the rows
//! without it. A credential without a folder is at the top level. Its first folder (by
//! `added_at`, then UUID) is the one that a single-folder reader shows
//! ([`Vault::item_folder`]). Folders nest to [`MAX_FOLDER_DEPTH`] levels.
//!
//! A membership of a folder that this device does not have (yet) stays as it is through
//! every change here, a move and an Undo included: the folder can arrive with the next
//! sync.
//!
//! [`Vault::set_item_folder`] and [`Vault::move_items_to_folder`] replace every folder of
//! a credential; [`Vault::add_item_to_folder`] adds one, [`Vault::remove_item_from_folder`]
//! removes one, and [`Vault::move_item`] replaces one folder with another. Each change
//! records a synced "moved" event whose detail names the folders after the change.
//!
//! Folder rows sync one by one: the later `(updated_at, updated_by)` wins
//! (`merge::merge_lww`). `created_at` and `deleted_at` are Unix seconds; `updated_at` is
//! Unix milliseconds, the version of the row. A deleted folder keeps its row with
//! `deleted_at`, so the delete reaches the other Macs.
//!
//! Two Macs can make a state that this API refuses: a credential or a folder in a folder
//! that the other Mac deleted, or a cycle of two moves. The reads resolve it: a parent
//! that is gone counts as the top level, and a cycle is cut at the folder with the
//! smallest UUID. Moving a credential changes nothing else. Deleting a folder never
//! deletes a credential: each membership of that folder moves to its parent (it goes
//! when the folder was at the top level), and the other folders of the credential stay.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

use super::history::{self, ItemEventKind};
use super::types::{VaultErrorKind, VaultResult, err};
use super::{Vault, agents, to_hex, to_public_id, to_sql_id};

/// A folder name has at most this many bytes.
pub const MAX_FOLDER_NAME_BYTES: usize = 64;
/// Folders nest at most this many levels: a folder at the top level is level 1.
pub const MAX_FOLDER_DEPTH: usize = 4;

/// The separator of a folder path in the detail of a "moved" event.
const PATH_SEPARATOR: &str = " / ";
/// The separator of two folder paths in the detail of a "moved" event.
const FOLDERS_SEPARATOR: &str = "; ";

/// A folder that is not deleted. `parent` is `None` at the top level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Folder {
    pub uuid: String,
    pub parent: Option<String>,
    pub name: String,
    pub position: i64,
}

/// One credential changed by a batch move. The receipt is bound to this unlocked
/// session and the exact move event, so a later move cannot be overwritten by Undo.
/// Read the destinations for feedback; pass the unchanged receipt back to Undo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemFolderMove {
    pub item_id: u64,
    /// The first folder before the move (`None`: the top level).
    pub from: Option<String>,
    pub to: Option<String>,
    /// Every folder before the move with its `added_at`, for Undo.
    from_all: Vec<(String, i64)>,
    epoch: [u8; 32],
    move_event: i64,
}

/// The live folders of every credential and the path of every folder, read once for a
/// whole list (the agent catalog, the list of the iPhone) instead of once per credential.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FolderIndex {
    items: BTreeMap<u64, Vec<String>>,
    paths: BTreeMap<String, Vec<String>>,
}

impl FolderIndex {
    /// The folders of a credential, first folder first, as [`Vault::item_folders`]
    /// answers. Empty: the top level, also for an ID that is not a credential.
    pub fn folders(&self, item_id: u64) -> &[String] {
        self.items.get(&item_id).map_or(&[], Vec::as_slice)
    }

    /// The names from the top level to `folder`, as [`Vault::folder_path`] answers;
    /// empty for a folder that is not here.
    pub fn path(&self, folder: &str) -> Vec<String> {
        self.paths.get(folder).cloned().unwrap_or_default()
    }
}

/// The folders that are not deleted, with each parent resolved (see the module
/// documentation).
struct Tree {
    folders: BTreeMap<String, Folder>,
}

impl Tree {
    fn load(conn: &Connection) -> VaultResult<Self> {
        let storage = |_| err(VaultErrorKind::Storage);
        let mut stmt = conn
            .prepare(
                "SELECT uuid, parent_uuid, name, position FROM folder
                 WHERE deleted_at IS NULL",
            )
            .map_err(storage)?;
        let rows = stmt
            .query_map([], |row| {
                Ok(Folder {
                    uuid: row.get(0)?,
                    parent: row.get(1)?,
                    name: row.get(2)?,
                    position: row.get(3)?,
                })
            })
            .map_err(storage)?;
        let mut folders = BTreeMap::new();
        for row in rows {
            let folder = row.map_err(storage)?;
            folders.insert(folder.uuid.clone(), folder);
        }
        // A parent that is gone counts as the top level.
        let live: BTreeSet<String> = folders.keys().cloned().collect();
        for folder in folders.values_mut() {
            if folder
                .parent
                .as_ref()
                .is_some_and(|parent| !live.contains(parent) || *parent == folder.uuid)
            {
                folder.parent = None;
            }
        }
        let mut tree = Self { folders };
        tree.cut_cycles();
        Ok(tree)
    }

    /// Cut each cycle at the folder with the smallest UUID: it goes to the top level.
    fn cut_cycles(&mut self) {
        let uuids: Vec<String> = self.folders.keys().cloned().collect();
        for start in uuids {
            loop {
                let mut path: Vec<String> = Vec::new();
                let mut at = Some(start.clone());
                let mut cycle = None;
                while let Some(uuid) = at {
                    if let Some(index) = path.iter().position(|seen| *seen == uuid) {
                        cycle = path[index..].iter().min().cloned();
                        break;
                    }
                    at = self.folders.get(&uuid).and_then(|f| f.parent.clone());
                    path.push(uuid);
                }
                match cycle.and_then(|cut| self.folders.get_mut(&cut)) {
                    Some(folder) => folder.parent = None,
                    None => break,
                }
            }
        }
    }

    fn get(&self, uuid: &str) -> VaultResult<&Folder> {
        self.folders
            .get(uuid)
            .ok_or_else(|| err(VaultErrorKind::NotFound))
    }

    /// The level of `uuid`: 1 at the top level.
    fn depth(&self, uuid: &str) -> usize {
        let mut depth = 0;
        let mut at = Some(uuid);
        while let Some(uuid) = at {
            depth += 1;
            at = self.folders.get(uuid).and_then(|f| f.parent.as_deref());
        }
        depth
    }

    /// The levels of `uuid` and the folders below it: 1 without subfolders.
    fn height(&self, uuid: &str) -> usize {
        1 + self
            .children(Some(uuid))
            .iter()
            .map(|child| self.height(&child.uuid))
            .max()
            .unwrap_or(0)
    }

    /// The subfolders of `parent` (`None`: the top level), by position, name, and UUID.
    fn children(&self, parent: Option<&str>) -> Vec<&Folder> {
        let mut children: Vec<&Folder> = self
            .folders
            .values()
            .filter(|folder| folder.parent.as_deref() == parent)
            .collect();
        children
            .sort_by(|a, b| (a.position, &a.name, &a.uuid).cmp(&(b.position, &b.name, &b.uuid)));
        children
    }

    /// `uuid` and every folder below it.
    fn subtree(&self, uuid: &str) -> BTreeSet<String> {
        let mut all = BTreeSet::from([uuid.to_owned()]);
        for child in self.children(Some(uuid)) {
            all.extend(self.subtree(&child.uuid));
        }
        all
    }

    /// The names from the top level to `uuid`.
    fn path(&self, uuid: &str) -> Vec<String> {
        let mut names = Vec::new();
        let mut at = self.folders.get(uuid);
        while let Some(folder) = at {
            names.push(folder.name.clone());
            at = folder.parent.as_deref().and_then(|p| self.folders.get(p));
        }
        names.reverse();
        names
    }

    /// Every folder, depth first, each level in the order of [`Tree::children`].
    fn ordered(&self) -> Vec<Folder> {
        fn walk(tree: &Tree, parent: Option<&str>, out: &mut Vec<Folder>) {
            for child in tree.children(parent) {
                out.push(child.clone());
                walk(tree, Some(&child.uuid), out);
            }
        }
        let mut out = Vec::new();
        walk(self, None, &mut out);
        out
    }

    /// A sibling of `parent` other than `except` has `name` (case-insensitive).
    fn name_taken(&self, parent: Option<&str>, name: &str, except: Option<&str>) -> bool {
        let lower = name.to_lowercase();
        self.children(parent).iter().any(|folder| {
            Some(folder.uuid.as_str()) != except && folder.name.to_lowercase() == lower
        })
    }

    /// The position after the last subfolder of `parent`.
    fn next_position(&self, parent: Option<&str>) -> i64 {
        self.children(parent)
            .iter()
            .map(|folder| folder.position)
            .max()
            .map_or(0, |last| last.saturating_add(1))
    }

    /// The folders of a credential from its stored rows, in their order: without the
    /// folders that are gone.
    fn resolve(&self, stored: Vec<(String, i64)>) -> Vec<(String, i64)> {
        stored
            .into_iter()
            .filter(|(uuid, _)| self.folders.contains_key(uuid))
            .collect()
    }
}

/// The UUIDs of `folders`, in their order.
fn uuids(folders: &[(String, i64)]) -> Vec<String> {
    folders.iter().map(|(uuid, _)| uuid.clone()).collect()
}

/// A folder name: trimmed, not empty, at most [`MAX_FOLDER_NAME_BYTES`], no control
/// characters.
fn clean_name(name: &str) -> VaultResult<String> {
    let name = name.trim();
    if name.is_empty() || name.len() > MAX_FOLDER_NAME_BYTES || name.chars().any(char::is_control) {
        return Err(err(VaultErrorKind::InvalidInput));
    }
    Ok(name.to_owned())
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        })
}

/// The version of a change by this device: now in Unix milliseconds and the device ID.
fn version(conn: &Connection) -> VaultResult<(i64, String)> {
    let device: Option<String> = conn
        .query_row(
            "SELECT device_id FROM sync_device WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| err(VaultErrorKind::Storage))?;
    Ok((now_ms(), device.unwrap_or_default()))
}

fn new_uuid() -> VaultResult<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| err(VaultErrorKind::Io))?;
    Ok(to_hex(&bytes))
}

/// The stored folder rows of an item with their `added_at`, first folder first, as they
/// are (one can name a folder that is gone).
fn stored_folders(conn: &Connection, item: i64) -> VaultResult<Vec<(String, i64)>> {
    let storage = |_| err(VaultErrorKind::Storage);
    let mut stmt = conn
        .prepare(
            "SELECT folder_uuid, added_at FROM item_folder
             WHERE item_id = ?1 AND removed_at IS NULL
             ORDER BY added_at, folder_uuid",
        )
        .map_err(storage)?;
    stmt.query_map([item], |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(storage)?
        .collect::<Result<_, _>>()
        .map_err(storage)
}

fn last_move_event(conn: &Connection, item: i64) -> VaultResult<Option<i64>> {
    conn.query_row(
        "SELECT MAX(id) FROM item_event WHERE item_id = ?1 AND kind = 'moved'",
        [item],
        |row| row.get(0),
    )
    .map_err(|_| err(VaultErrorKind::Storage))
}

/// Make `folders` (each with its `added_at`) the live folders of the item that this
/// device knows, and record a "moved" event with the path of each of its folders that is
/// here. A membership of a folder that is not here (yet, or any more) stays as it is: a
/// folder of another device can arrive with the next sync. A membership that ends keeps
/// its row with `removed_at`, so the removal syncs (schema 35); a folder that the item was
/// in before comes back on the same row. Each changed row gets this device and a version
/// after its last one. The caller checked the item and the folders.
fn set_folders(
    tx: &rusqlite::Transaction<'_>,
    tree: &Tree,
    item: i64,
    folders: &[(String, i64)],
) -> VaultResult<()> {
    let storage = |_| err(VaultErrorKind::Storage);
    let rows: Vec<(String, i64, bool)> = {
        let mut stmt = tx
            .prepare(
                "SELECT folder_uuid, updated_at, removed_at IS NOT NULL FROM item_folder
                 WHERE item_id = ?1",
            )
            .map_err(storage)?;
        stmt.query_map([item], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .map_err(storage)?
            .collect::<Result<_, _>>()
            .map_err(storage)?
    };
    let (now, device) = version(tx)?;
    let at = |last: i64| now.max(last.saturating_add(1));
    let wanted = |uuid: &str| folders.iter().any(|(folder, _)| folder == uuid);
    for (folder, last, removed) in &rows {
        if !removed && !wanted(folder) && tree.folders.contains_key(folder) {
            let at = at(*last);
            tx.execute(
                "UPDATE item_folder SET removed_at = ?1, updated_at = ?1, updated_by = ?2
                 WHERE item_id = ?3 AND folder_uuid = ?4",
                (at, &device, item, folder),
            )
            .map_err(storage)?;
        }
    }
    for (folder, added_at) in folders {
        match rows.iter().find(|(uuid, _, _)| uuid == folder) {
            Some((_, _, false)) => {}
            Some((_, last, true)) => {
                tx.execute(
                    "UPDATE item_folder SET removed_at = NULL, added_at = ?1, updated_at = ?2,
                         updated_by = ?3
                     WHERE item_id = ?4 AND folder_uuid = ?5",
                    (added_at, at(*last), &device, item, folder),
                )
                .map_err(storage)?;
            }
            None => {
                tx.execute(
                    "INSERT INTO item_folder
                         (item_id, folder_uuid, added_at, updated_at, updated_by)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    (item, folder, added_at, now, &device),
                )
                .map_err(storage)?;
            }
        }
    }
    let detail = tree
        .resolve(stored_folders(tx, item)?)
        .iter()
        .map(|(uuid, _)| tree.path(uuid).join(PATH_SEPARATOR))
        .collect::<Vec<_>>()
        .join(FOLDERS_SEPARATOR);
    history::record(tx, item, ItemEventKind::Moved, &detail)
}

/// A new `added_at` for a folder added to `current`: now, and after the last folder, so
/// the order of adding stays the order of the folders also with a clock that stepped back.
fn next_added_at(current: &[(String, i64)]) -> i64 {
    let last = current.iter().map(|(_, at)| *at).max().unwrap_or(0);
    now_ms().max(last.saturating_add(1))
}

/// The folders of a credential that `set_item_folder` gives it: `folder` alone, with the
/// time it had when it was one of them.
fn only(current: &[(String, i64)], folder: Option<&str>) -> Vec<(String, i64)> {
    match folder {
        Some(folder) => {
            let at = current
                .iter()
                .find(|(uuid, _)| uuid == folder)
                .map_or_else(|| next_added_at(current), |(_, at)| *at);
            vec![(folder.to_owned(), at)]
        }
        None => Vec::new(),
    }
}

impl Vault {
    /// The folders that are not deleted, depth first; each level by position, name, and
    /// UUID.
    pub fn folders(&self) -> VaultResult<Vec<Folder>> {
        Ok(Tree::load(self.conn_ref()?)?.ordered())
    }

    /// Make a folder in `parent` (`None`: the top level), after its last subfolder.
    ///
    /// - `InvalidInput`: the name is empty, longer than [`MAX_FOLDER_NAME_BYTES`], or has
    ///   a control character, or the folder would be below [`MAX_FOLDER_DEPTH`].
    /// - `NotFound`: the parent is not a folder.
    /// - `AlreadyExists`: a sibling has the same name (case-insensitive).
    pub fn create_folder(&mut self, parent: Option<&str>, name: &str) -> VaultResult<Folder> {
        let name = clean_name(name)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let tree = Tree::load(&tx)?;
        let depth = match parent {
            Some(parent) => tree.get(parent).map(|_| tree.depth(parent))?,
            None => 0,
        };
        if depth + 1 > MAX_FOLDER_DEPTH {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        if tree.name_taken(parent, &name, None) {
            return Err(err(VaultErrorKind::AlreadyExists));
        }
        let folder = Folder {
            uuid: new_uuid()?,
            parent: parent.map(str::to_owned),
            name,
            position: tree.next_position(parent),
        };
        let (at, by) = version(&tx)?;
        tx.execute(
            "INSERT INTO folder (uuid, parent_uuid, name, position, created_at, updated_at,
                 updated_by) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            (
                &folder.uuid,
                &folder.parent,
                &folder.name,
                folder.position,
                at / 1000,
                at,
                &by,
            ),
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))?;
        Ok(folder)
    }

    /// Rename a folder. The same name changes nothing. The errors are those of
    /// [`Vault::create_folder`].
    pub fn rename_folder(&mut self, uuid: &str, name: &str) -> VaultResult<()> {
        let name = clean_name(name)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let tree = Tree::load(&tx)?;
        let folder = tree.get(uuid)?;
        if folder.name == name {
            return Ok(());
        }
        if tree.name_taken(folder.parent.as_deref(), &name, Some(uuid)) {
            return Err(err(VaultErrorKind::AlreadyExists));
        }
        let (at, by) = version(&tx)?;
        tx.execute(
            "UPDATE folder SET name = ?1, updated_at = ?2, updated_by = ?3 WHERE uuid = ?4",
            (&name, at, &by, uuid),
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))
    }

    /// Move a folder with its subfolders and credentials into `parent` (`None`: the top
    /// level), after its last subfolder. The same parent changes nothing.
    ///
    /// - `InvalidInput`: `parent` is the folder or one of its subfolders (a cycle), or the
    ///   deepest subfolder would be below [`MAX_FOLDER_DEPTH`] and not higher than now (a
    ///   subtree that two Macs made too deep can move up).
    /// - `NotFound`: the folder or the parent is not a folder.
    /// - `AlreadyExists`: a folder in `parent` has the same name.
    pub fn move_folder(&mut self, uuid: &str, parent: Option<&str>) -> VaultResult<()> {
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let tree = Tree::load(&tx)?;
        let folder = tree.get(uuid)?;
        let depth = match parent {
            Some(parent) => {
                tree.get(parent)?;
                if tree.subtree(uuid).contains(parent) {
                    return Err(err(VaultErrorKind::InvalidInput));
                }
                tree.depth(parent)
            }
            None => 0,
        };
        if folder.parent.as_deref() == parent {
            return Ok(());
        }
        // Two Macs can make a subtree deeper than the limit. It can still move up: only a
        // move whose deepest level is below the limit and lower than now is refused.
        let height = tree.height(uuid);
        let bottom = depth + height;
        let bottom_now = tree.depth(uuid) - 1 + height;
        if bottom > MAX_FOLDER_DEPTH && bottom >= bottom_now {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        if tree.name_taken(parent, &folder.name, Some(uuid)) {
            return Err(err(VaultErrorKind::AlreadyExists));
        }
        let (at, by) = version(&tx)?;
        tx.execute(
            "UPDATE folder SET parent_uuid = ?1, position = ?2, updated_at = ?3,
                 updated_by = ?4 WHERE uuid = ?5",
            (parent, tree.next_position(parent), at, &by, uuid),
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))
    }

    /// Delete a folder. Its subfolders go to its parent (the top level when it has none).
    /// Only its memberships change: each credential in it is in the parent instead (in
    /// its place among the folders of the credential), or, for a folder at the top level,
    /// just not in it; its other folders stay, and no credential is deleted. Each
    /// credential gets a "moved" event. Returns the count of credentials that moved.
    /// `NotFound`: not a folder.
    pub fn delete_folder(&mut self, uuid: &str) -> VaultResult<usize> {
        let storage = |_| err(VaultErrorKind::Storage);
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let tree = Tree::load(&tx)?;
        let parent = tree.get(uuid)?.parent.clone();
        let items: Vec<i64> = {
            let mut stmt = tx
                .prepare(
                    "SELECT item_id FROM item_folder
                     WHERE folder_uuid = ?1 AND removed_at IS NULL ORDER BY item_id",
                )
                .map_err(storage)?;
            stmt.query_map([uuid], |row| row.get(0))
                .map_err(storage)?
                .collect::<Result<_, _>>()
                .map_err(storage)?
        };
        for item in &items {
            let current = stored_folders(&tx, *item)?;
            let mut next: Vec<(String, i64)> = Vec::new();
            for (folder, added_at) in &current {
                if folder != uuid {
                    next.push((folder.clone(), *added_at));
                }
            }
            if let Some(parent) = &parent
                && let Some((_, added_at)) = current.iter().find(|(folder, _)| folder == uuid)
            {
                match next.iter_mut().find(|(folder, _)| folder == parent) {
                    Some((_, at)) => *at = (*at).min(*added_at),
                    None => next.push((parent.clone(), *added_at)),
                }
            }
            set_folders(&tx, &tree, *item, &next)?;
        }
        let (at, by) = version(&tx)?;
        let children: Vec<String> = tree
            .children(Some(uuid))
            .iter()
            .map(|child| child.uuid.clone())
            .collect();
        let mut position = tree.next_position(parent.as_deref());
        for child in children {
            tx.execute(
                "UPDATE folder SET parent_uuid = ?1, position = ?2, updated_at = ?3,
                     updated_by = ?4 WHERE uuid = ?5",
                (&parent, position, at, &by, &child),
            )
            .map_err(storage)?;
            position = position.saturating_add(1);
        }
        tx.execute(
            "UPDATE folder SET deleted_at = ?1, updated_at = ?2, updated_by = ?3 WHERE uuid = ?4",
            (at / 1000, at, &by, uuid),
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)?;
        Ok(items.len())
    }

    /// The first folder of a credential (by the time it was added, then UUID). `None`:
    /// the top level, also when its folders are gone. `NotFound`: no such credential.
    pub fn item_folder(&self, item_id: u64) -> VaultResult<Option<String>> {
        Ok(self.item_folders(item_id)?.into_iter().next())
    }

    /// The live folders of every credential and the path of every folder, in one read of
    /// the folder tree ([`FolderIndex`]).
    pub fn folder_index(&self) -> VaultResult<FolderIndex> {
        let storage = |_| err(VaultErrorKind::Storage);
        let conn = self.conn_ref()?;
        let tree = Tree::load(conn)?;
        let mut stmt = conn
            .prepare(
                "SELECT item_id, folder_uuid FROM item_folder WHERE removed_at IS NULL
                 ORDER BY item_id, added_at, folder_uuid",
            )
            .map_err(storage)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(storage)?;
        let mut items: BTreeMap<u64, Vec<String>> = BTreeMap::new();
        for row in rows {
            let (id, folder) = row.map_err(storage)?;
            if tree.folders.contains_key(&folder) {
                items.entry(to_public_id(id)?).or_default().push(folder);
            }
        }
        let paths = tree
            .folders
            .keys()
            .map(|uuid| (uuid.clone(), tree.path(uuid)))
            .collect();
        Ok(FolderIndex { items, paths })
    }

    /// Every folder of a credential, first folder first (by the time it was added, then
    /// UUID), without the folders that are gone. Empty: the top level. A folder in a cycle
    /// is still a folder. `NotFound`: no such credential.
    pub fn item_folders(&self, item_id: u64) -> VaultResult<Vec<String>> {
        let item = to_sql_id(item_id)?;
        let conn = self.conn_ref()?;
        let found: Option<i64> = conn
            .query_row("SELECT id FROM item WHERE id = ?1", [item], |row| {
                row.get(0)
            })
            .optional()
            .map_err(|_| err(VaultErrorKind::Storage))?;
        if found.is_none() {
            return Err(err(VaultErrorKind::NotFound));
        }
        let tree = Tree::load(conn)?;
        Ok(uuids(&tree.resolve(stored_folders(conn, item)?)))
    }

    /// Put a credential in `folder` alone (`None`: the top level): it leaves every other
    /// folder. A "moved" event syncs. The same single folder changes nothing.
    /// `NotFound`: no such credential or folder.
    pub fn set_item_folder(&mut self, item_id: u64, folder: Option<&str>) -> VaultResult<()> {
        let item = to_sql_id(item_id)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        agents::require_item(&tx, item)?;
        let tree = Tree::load(&tx)?;
        if let Some(folder) = folder {
            tree.get(folder)?;
        }
        let current = tree.resolve(stored_folders(&tx, item)?);
        if uuids(&current) == folder.map(str::to_owned).into_iter().collect::<Vec<_>>() {
            return Ok(());
        }
        set_folders(&tx, &tree, item, &only(&current, folder))?;
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))
    }

    /// Add a credential to `folder` ("Add to Folder…"); its other folders stay, and the
    /// new one comes last. A "moved" event syncs. A folder that it is in already changes
    /// nothing. `NotFound`: no such credential or folder.
    pub fn add_item_to_folder(&mut self, item_id: u64, folder: &str) -> VaultResult<()> {
        let item = to_sql_id(item_id)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        agents::require_item(&tx, item)?;
        let tree = Tree::load(&tx)?;
        tree.get(folder)?;
        // The rows of folders that are not here (yet) stay: a folder of another Mac can
        // arrive with the next sync.
        let mut current = stored_folders(&tx, item)?;
        if current.iter().any(|(uuid, _)| uuid == folder) {
            return Ok(());
        }
        let at = next_added_at(&current);
        current.push((folder.to_owned(), at));
        set_folders(&tx, &tree, item, &current)?;
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))
    }

    /// Take a credential out of `folder` ("Remove from This Folder"); its other folders
    /// stay. Without folders it is at the top level. A "moved" event syncs. A folder that
    /// it is not in changes nothing. `NotFound`: no such credential or folder.
    pub fn remove_item_from_folder(&mut self, item_id: u64, folder: &str) -> VaultResult<()> {
        let item = to_sql_id(item_id)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        agents::require_item(&tx, item)?;
        let tree = Tree::load(&tx)?;
        tree.get(folder)?;
        let current = stored_folders(&tx, item)?;
        if !current.iter().any(|(uuid, _)| uuid == folder) {
            return Ok(());
        }
        let rest: Vec<(String, i64)> = current
            .into_iter()
            .filter(|(uuid, _)| uuid != folder)
            .collect();
        set_folders(&tx, &tree, item, &rest)?;
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))
    }

    /// Move a credential from the folder of the list the owner is in to `to` ("Move to
    /// Folder…"). `from`: that folder; the credential leaves it, `to` takes its place
    /// among the folders of the credential, and its other folders stay. `from` `None` (the
    /// list of every credential or of the top level) replaces every folder, as
    /// [`Vault::set_item_folder`] does. `to` `None`: the credential only leaves `from`.
    /// A "moved" event syncs. `from` equal to `to` changes nothing.
    ///
    /// - `NotFound`: no such credential, or `from` or `to` is not a folder.
    /// - `Conflict`: the credential is not in `from` (the list is out of date).
    pub fn move_item(
        &mut self,
        item_id: u64,
        from: Option<&str>,
        to: Option<&str>,
    ) -> VaultResult<()> {
        let Some(from) = from else {
            return self.set_item_folder(item_id, to);
        };
        let item = to_sql_id(item_id)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        agents::require_item(&tx, item)?;
        let tree = Tree::load(&tx)?;
        tree.get(from)?;
        if let Some(to) = to {
            tree.get(to)?;
        }
        let current = stored_folders(&tx, item)?;
        let Some(added_at) = current
            .iter()
            .find(|(uuid, _)| uuid == from)
            .map(|(_, at)| *at)
        else {
            return Err(err(VaultErrorKind::Conflict));
        };
        if Some(from) == to {
            return Ok(());
        }
        let mut next: Vec<(String, i64)> = current
            .into_iter()
            .filter(|(uuid, _)| uuid != from)
            .collect();
        if let Some(to) = to
            && !next.iter().any(|(uuid, _)| uuid == to)
        {
            next.push((to.to_owned(), added_at));
        }
        set_folders(&tx, &tree, item, &next)?;
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))
    }

    /// Move each distinct ID into `folder` in one transaction. Every item and the
    /// destination are checked before writing. Unchanged items are omitted from the
    /// Undo receipt. Credentials, grants, revisions and existing history are retained;
    /// each changed item gets the usual `Moved` event.
    ///
    /// `InvalidInput`: repeated/invalid IDs. `NotFound`: an item or folder is gone.
    pub fn move_items_to_folder(
        &mut self,
        item_ids: &[u64],
        folder: Option<&str>,
    ) -> VaultResult<Vec<ItemFolderMove>> {
        let epoch = self.epoch();
        let storage = |_| err(VaultErrorKind::Storage);
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let tree = Tree::load(&tx)?;
        if let Some(folder) = folder {
            tree.get(folder)?;
        }
        let mut seen = BTreeSet::new();
        let mut moves = Vec::new();
        for &item_id in item_ids {
            let item = to_sql_id(item_id)?;
            if !seen.insert(item) {
                return Err(err(VaultErrorKind::InvalidInput));
            }
            agents::require_item(&tx, item)?;
            let from_all = tree.resolve(stored_folders(&tx, item)?);
            if uuids(&from_all) != folder.map(str::to_owned).into_iter().collect::<Vec<_>>() {
                moves.push(ItemFolderMove {
                    item_id,
                    from: from_all.first().map(|(uuid, _)| uuid.clone()),
                    to: folder.map(str::to_owned),
                    from_all,
                    epoch,
                    move_event: 0,
                });
            }
        }
        for moved in &mut moves {
            let item = to_sql_id(moved.item_id)?;
            set_folders(
                &tx,
                &tree,
                item,
                &only(&moved.from_all, moved.to.as_deref()),
            )?;
            moved.move_event =
                last_move_event(&tx, item)?.ok_or_else(|| err(VaultErrorKind::Storage))?;
        }
        tx.commit().map_err(storage)?;
        Ok(moves)
    }

    /// Undo an unchanged batch receipt atomically. Any deleted item/original folder,
    /// later move (even away and back), or lock/switch/reopen rejects the whole Undo.
    /// Existing metadata, access and history are retained, with a new `Moved` event.
    pub fn undo_item_folder_moves(&mut self, moves: &[ItemFolderMove]) -> VaultResult<()> {
        let epoch = self.epoch();
        let storage = |_| err(VaultErrorKind::Storage);
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let tree = Tree::load(&tx)?;
        let mut seen = BTreeSet::new();
        for moved in moves {
            let item = to_sql_id(moved.item_id)?;
            if !seen.insert(item) {
                return Err(err(VaultErrorKind::InvalidInput));
            }
            agents::require_item(&tx, item)?;
            for (folder, _) in &moved.from_all {
                tree.get(folder)?;
            }
            if moved.epoch != epoch
                || uuids(&tree.resolve(stored_folders(&tx, item)?))
                    != moved.to.iter().cloned().collect::<Vec<_>>()
                || last_move_event(&tx, item)? != Some(moved.move_event)
            {
                return Err(err(VaultErrorKind::Conflict));
            }
        }
        for moved in moves {
            set_folders(&tx, &tree, to_sql_id(moved.item_id)?, &moved.from_all)?;
        }
        tx.commit().map_err(storage)
    }

    /// The names from the top level to `folder`; empty for `None`. `NotFound`: not a
    /// folder.
    pub fn folder_path(&self, folder: Option<&str>) -> VaultResult<Vec<String>> {
        let Some(folder) = folder else {
            return Ok(Vec::new());
        };
        let tree = Tree::load(self.conn_ref()?)?;
        tree.get(folder)?;
        Ok(tree.path(folder))
    }

    /// The credentials in `folder` by ID, each once. `None` is the top level: the
    /// credentials without a folder or whose folders are gone. `recursive` adds the
    /// credentials of the subfolders; with `None` that is every credential. A credential
    /// in several folders is in the list of each. Archived credentials count.
    /// `NotFound`: not a folder.
    pub fn items_in_folder(&self, folder: Option<&str>, recursive: bool) -> VaultResult<Vec<u64>> {
        let storage = |_| err(VaultErrorKind::Storage);
        let conn = self.conn_ref()?;
        let tree = Tree::load(conn)?;
        let wanted: Option<BTreeSet<String>> = match folder {
            Some(folder) => {
                tree.get(folder)?;
                Some(if recursive {
                    tree.subtree(folder)
                } else {
                    BTreeSet::from([folder.to_owned()])
                })
            }
            None => None,
        };
        let mut stmt = conn
            .prepare(
                "SELECT i.id, p.folder_uuid FROM item i
                 LEFT JOIN item_folder p ON p.item_id = i.id AND p.removed_at IS NULL
                 ORDER BY i.id",
            )
            .map_err(storage)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, Option<String>>(1)?))
            })
            .map_err(storage)?;
        // The live folders of each credential, in the order of the IDs.
        let mut placed: Vec<(i64, Vec<String>)> = Vec::new();
        for row in rows {
            let (id, stored) = row.map_err(storage)?;
            if placed.last().is_none_or(|(last, _)| *last != id) {
                placed.push((id, Vec::new()));
            }
            if let Some(uuid) = stored.filter(|uuid| tree.folders.contains_key(uuid))
                && let Some((_, folders)) = placed.last_mut()
            {
                folders.push(uuid);
            }
        }
        let mut items = Vec::new();
        for (id, folders) in placed {
            let inside = match &wanted {
                Some(wanted) => folders.iter().any(|uuid| wanted.contains(uuid)),
                None => recursive || folders.is_empty(),
            };
            if inside {
                items.push(to_public_id(id)?);
            }
        }
        Ok(items)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::CredentialKind;
    use crate::vault::{Field, ItemDraft, ItemEventKind, MAX_ITEM_EVENTS, SecretValue};

    const PASS: &str = "synthetic-folder-pass";

    fn vault(dir: &tempfile::TempDir) -> Vault {
        let mut vault = Vault::create(&dir.path().join("folders.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        vault
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
                    value: SecretValue::new("SYNTH-folder-token".to_owned()),
                    secret: true,
                }],
            })
            .unwrap()
            .id
    }

    fn names(vault: &Vault) -> Vec<(String, Option<String>)> {
        let folders = vault.folders().unwrap();
        let name_of = |uuid: &str| {
            folders
                .iter()
                .find(|folder| folder.uuid == uuid)
                .unwrap()
                .name
                .clone()
        };
        folders
            .iter()
            .map(|folder| (folder.name.clone(), folder.parent.as_deref().map(name_of)))
            .collect()
    }

    #[test]
    fn create_rename_and_list_in_tree_order() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut v = vault(&dir);
        let work = v.create_folder(None, "  Work ").unwrap();
        assert_eq!(work.name, "Work");
        assert_eq!(work.position, 0);
        assert_eq!(work.uuid.len(), 32);
        let acme = v.create_folder(Some(&work.uuid), "Acme").unwrap();
        let home = v.create_folder(None, "Home").unwrap();
        assert_eq!(home.position, 1);
        assert_eq!(
            names(&v),
            [
                ("Work".to_owned(), None),
                ("Acme".to_owned(), Some("Work".to_owned())),
                ("Home".to_owned(), None),
            ]
        );
        v.rename_folder(&acme.uuid, "Acme billing").unwrap();
        assert_eq!(
            v.folder_path(Some(&acme.uuid)).unwrap(),
            ["Work", "Acme billing"]
        );
        assert!(v.folder_path(None).unwrap().is_empty());

        // Names: empty, too long, control characters, a sibling with the same name.
        for bad in ["", "   ", "a\nb", &"x".repeat(MAX_FOLDER_NAME_BYTES + 1)] {
            assert_eq!(
                v.create_folder(None, bad).unwrap_err().kind(),
                VaultErrorKind::InvalidInput,
                "{bad:?}"
            );
            assert_eq!(
                v.rename_folder(&work.uuid, bad).unwrap_err().kind(),
                VaultErrorKind::InvalidInput,
                "{bad:?}"
            );
        }
        assert!(
            v.create_folder(None, &"ż".repeat(MAX_FOLDER_NAME_BYTES / 2))
                .is_ok()
        );
        assert_eq!(
            v.create_folder(None, "work").unwrap_err().kind(),
            VaultErrorKind::AlreadyExists
        );
        assert_eq!(
            v.rename_folder(&home.uuid, "WORK").unwrap_err().kind(),
            VaultErrorKind::AlreadyExists
        );
        // The same name in another folder is fine; a missing parent is not.
        v.create_folder(Some(&work.uuid), "Home").unwrap();
        assert_eq!(
            v.create_folder(Some("0123"), "Lost").unwrap_err().kind(),
            VaultErrorKind::NotFound
        );
        assert_eq!(
            v.rename_folder("0123", "Lost").unwrap_err().kind(),
            VaultErrorKind::NotFound
        );
    }

    #[test]
    fn depth_and_cycles_are_refused() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut v = vault(&dir);
        let mut chain = Vec::new();
        let mut parent: Option<String> = None;
        for level in 1..=MAX_FOLDER_DEPTH {
            let folder = v
                .create_folder(parent.as_deref(), &format!("Level {level}"))
                .unwrap();
            parent = Some(folder.uuid.clone());
            chain.push(folder.uuid);
        }
        assert_eq!(
            v.create_folder(parent.as_deref(), "Too deep")
                .unwrap_err()
                .kind(),
            VaultErrorKind::InvalidInput
        );
        // A cycle: a folder into itself or below itself.
        for target in &chain {
            assert_eq!(
                v.move_folder(&chain[0], Some(target)).unwrap_err().kind(),
                VaultErrorKind::InvalidInput
            );
        }
        // Depth: level 2 with its two levels below goes under another top folder: 1 + 3.
        let other = v.create_folder(None, "Other").unwrap();
        v.move_folder(&chain[1], Some(&other.uuid)).unwrap();
        assert_eq!(
            v.folder_path(Some(&chain[3])).unwrap(),
            ["Other", "Level 2", "Level 3", "Level 4"]
        );
        // One level more is refused, and the tree stays.
        let deeper = v.create_folder(Some(&other.uuid), "Deeper").unwrap();
        assert_eq!(
            v.move_folder(&chain[1], Some(&deeper.uuid))
                .unwrap_err()
                .kind(),
            VaultErrorKind::InvalidInput
        );
        assert_eq!(
            v.folder_path(Some(&chain[3])).unwrap(),
            ["Other", "Level 2", "Level 3", "Level 4"]
        );
        // To the top level, and missing folders.
        v.move_folder(&chain[1], None).unwrap();
        assert_eq!(v.folder_path(Some(&chain[1])).unwrap(), ["Level 2"]);
        assert_eq!(
            v.move_folder("0123", None).unwrap_err().kind(),
            VaultErrorKind::NotFound
        );
        assert_eq!(
            v.move_folder(&chain[1], Some("0123")).unwrap_err().kind(),
            VaultErrorKind::NotFound
        );
    }

    #[test]
    fn items_move_with_a_synced_event_and_delete_moves_them_to_the_parent() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut v = vault(&dir);
        let a = add(&mut v, "Alpha");
        let b = add(&mut v, "Beta");
        let c = add(&mut v, "Gamma");
        let work = v.create_folder(None, "Work").unwrap();
        let acme = v.create_folder(Some(&work.uuid), "Acme").unwrap();
        let sub = v.create_folder(Some(&acme.uuid), "Sub").unwrap();
        v.set_item_folder(a, Some(&acme.uuid)).unwrap();
        v.set_item_folder(b, Some(&work.uuid)).unwrap();
        v.set_item_folder(c, Some(&sub.uuid)).unwrap();
        assert_eq!(
            v.item_folder(a).unwrap().as_deref(),
            Some(acme.uuid.as_str())
        );
        let moved = v.item_events(a, MAX_ITEM_EVENTS).unwrap();
        assert_eq!(moved[0].kind, ItemEventKind::Moved);
        assert_eq!(moved[0].detail, "Work / Acme");
        assert!(super::super::merge::SYNCED_EVENT_KINDS.contains(&"moved"));
        // The same folder again records nothing.
        v.set_item_folder(a, Some(&acme.uuid)).unwrap();
        assert_eq!(
            v.item_events(a, MAX_ITEM_EVENTS).unwrap().len(),
            moved.len()
        );
        assert_eq!(v.items_in_folder(Some(&acme.uuid), false).unwrap(), [a]);
        assert_eq!(
            v.items_in_folder(Some(&work.uuid), true).unwrap(),
            [a, b, c]
        );
        assert!(v.items_in_folder(None, false).unwrap().is_empty());
        assert_eq!(v.items_in_folder(None, true).unwrap(), [a, b, c]);
        assert_eq!(
            v.set_item_folder(a, Some("0123")).unwrap_err().kind(),
            VaultErrorKind::NotFound
        );
        assert_eq!(
            v.set_item_folder(999, None).unwrap_err().kind(),
            VaultErrorKind::NotFound
        );
        assert_eq!(
            v.item_folder(999).unwrap_err().kind(),
            VaultErrorKind::NotFound
        );

        // Delete "Acme": its item and its subfolder go to "Work".
        assert_eq!(v.delete_folder(&acme.uuid).unwrap(), 1);
        assert_eq!(
            v.item_folder(a).unwrap().as_deref(),
            Some(work.uuid.as_str())
        );
        let events = v.item_events(a, MAX_ITEM_EVENTS).unwrap();
        assert_eq!(events[0].kind, ItemEventKind::Moved);
        assert_eq!(events[0].detail, "Work");
        assert_eq!(v.folder_path(Some(&sub.uuid)).unwrap(), ["Work", "Sub"]);
        assert_eq!(
            v.item_folder(c).unwrap().as_deref(),
            Some(sub.uuid.as_str())
        );
        assert_eq!(
            v.folder_path(Some(&acme.uuid)).unwrap_err().kind(),
            VaultErrorKind::NotFound
        );
        // Delete "Work": everything goes to the top level; no credential is deleted.
        assert_eq!(v.delete_folder(&work.uuid).unwrap(), 2);
        assert_eq!(v.item_folder(a).unwrap(), None);
        assert_eq!(v.item_folder(b).unwrap(), None);
        assert_eq!(v.folder_path(Some(&sub.uuid)).unwrap(), ["Sub"]);
        assert_eq!(v.search("").unwrap().len(), 3);
        assert_eq!(v.items_in_folder(None, false).unwrap(), [a, b]);
        let events = v.item_events(b, MAX_ITEM_EVENTS).unwrap();
        assert_eq!(
            (events[0].kind, events[0].detail.as_str()),
            (ItemEventKind::Moved, "")
        );
        // The deleted rows stay for sync.
        let rows: i64 = v
            .conn_ref()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM folder WHERE deleted_at IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rows, 2);
        assert_eq!(
            v.delete_folder(&work.uuid).unwrap_err().kind(),
            VaultErrorKind::NotFound
        );
    }

    #[test]
    fn a_folder_that_is_gone_or_a_cycle_reads_as_the_top_level() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut v = vault(&dir);
        let a = add(&mut v, "Alpha");
        let x = v.create_folder(None, "X").unwrap();
        let y = v.create_folder(None, "Y").unwrap();
        // As after a merge: the item names a folder that only the other Mac knows, and
        // two concurrent moves made a cycle.
        let conn = v.conn_ref().unwrap();
        conn.execute(
            "INSERT INTO item_folder (item_id, folder_uuid, added_at, updated_at, updated_by)
             VALUES (?1, 'ffff', 1, 1, 'other')",
            [a as i64],
        )
        .unwrap();
        conn.execute(
            "UPDATE folder SET parent_uuid = ?1 WHERE uuid = ?2",
            (&y.uuid, &x.uuid),
        )
        .unwrap();
        conn.execute(
            "UPDATE folder SET parent_uuid = ?1 WHERE uuid = ?2",
            (&x.uuid, &y.uuid),
        )
        .unwrap();
        assert_eq!(v.item_folder(a).unwrap(), None);
        assert_eq!(v.items_in_folder(None, false).unwrap(), [a]);
        let cut = x.uuid.clone().min(y.uuid.clone());
        let folders = v.folders().unwrap();
        assert_eq!(folders.len(), 2);
        assert_eq!(folders[0].uuid, cut);
        assert_eq!(folders[0].parent, None);
        assert_eq!(folders[1].parent.as_deref(), Some(cut.as_str()));
        // Each still works.
        v.set_item_folder(a, Some(&x.uuid)).unwrap();
        assert_eq!(v.item_folder(a).unwrap().as_deref(), Some(x.uuid.as_str()));
        v.set_item_folder(a, None).unwrap();
        assert_eq!(v.item_folder(a).unwrap(), None);
    }

    #[test]
    fn deleting_an_item_removes_its_folder_row() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut v = vault(&dir);
        let a = add(&mut v, "Alpha");
        let work = v.create_folder(None, "Work").unwrap();
        v.set_item_folder(a, Some(&work.uuid)).unwrap();
        let revision = v.details(a).unwrap().summary.revision;
        v.delete(a, revision).unwrap();
        assert!(
            v.items_in_folder(Some(&work.uuid), true)
                .unwrap()
                .is_empty()
        );
        let rows: i64 = v
            .conn_ref()
            .unwrap()
            .query_row("SELECT count(*) FROM item_folder", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 0);
    }

    #[test]
    fn a_credential_is_in_several_folders() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut v = vault(&dir);
        let a = add(&mut v, "Alpha");
        let b = add(&mut v, "Beta");
        let work = v.create_folder(None, "Work").unwrap().uuid;
        let acme = v.create_folder(Some(&work), "Acme").unwrap().uuid;
        let home = v.create_folder(None, "Home").unwrap().uuid;
        v.add_item_to_folder(a, &home).unwrap();
        v.add_item_to_folder(a, &acme).unwrap();
        // The first folder stays the first; the order is the order of adding.
        assert_eq!(v.item_folders(a).unwrap(), [home.clone(), acme.clone()]);
        assert_eq!(v.item_folder(a).unwrap(), Some(home.clone()));
        let events = v.item_events(a, MAX_ITEM_EVENTS).unwrap();
        assert_eq!(events[0].kind, ItemEventKind::Moved);
        assert_eq!(events[0].detail, "Home; Work / Acme");
        // Adding a folder that it is in already records nothing.
        v.add_item_to_folder(a, &acme).unwrap();
        assert_eq!(
            v.item_events(a, MAX_ITEM_EVENTS).unwrap().len(),
            events.len()
        );
        // The list of each folder has it once; the top level does not.
        assert_eq!(v.items_in_folder(Some(&home), false).unwrap(), [a]);
        assert_eq!(v.items_in_folder(Some(&acme), false).unwrap(), [a]);
        assert_eq!(v.items_in_folder(Some(&work), true).unwrap(), [a]);
        assert_eq!(v.items_in_folder(None, false).unwrap(), [b]);
        assert_eq!(v.items_in_folder(None, true).unwrap(), [a, b]);

        // "Move to Folder…" from the list of "Home" replaces that folder only, in its
        // place.
        v.move_item(a, Some(&home), Some(&work)).unwrap();
        assert_eq!(v.item_folders(a).unwrap(), [work.clone(), acme.clone()]);
        // A move from a folder that it is not in is out of date.
        assert_eq!(
            v.move_item(a, Some(&home), Some(&work)).unwrap_err().kind(),
            VaultErrorKind::Conflict
        );
        // Into a folder that it is in already: it only leaves the other one.
        v.move_item(a, Some(&work), Some(&acme)).unwrap();
        assert_eq!(v.item_folders(a).unwrap(), std::slice::from_ref(&acme));
        v.add_item_to_folder(a, &home).unwrap();
        // "Remove from This Folder".
        v.remove_item_from_folder(a, &acme).unwrap();
        assert_eq!(v.item_folders(a).unwrap(), std::slice::from_ref(&home));
        v.remove_item_from_folder(a, &acme).unwrap();
        v.remove_item_from_folder(a, &home).unwrap();
        assert!(v.item_folders(a).unwrap().is_empty());
        // From the list of every credential, a move replaces every folder.
        v.add_item_to_folder(a, &home).unwrap();
        v.add_item_to_folder(a, &acme).unwrap();
        v.move_item(a, None, Some(&work)).unwrap();
        assert_eq!(v.item_folders(a).unwrap(), std::slice::from_ref(&work));
        // `set_item_folder` keeps its meaning: one folder, or none.
        v.add_item_to_folder(a, &home).unwrap();
        v.set_item_folder(a, Some(&home)).unwrap();
        assert_eq!(v.item_folders(a).unwrap(), std::slice::from_ref(&home));
        v.add_item_to_folder(a, &work).unwrap();
        v.set_item_folder(a, None).unwrap();
        assert!(v.item_folders(a).unwrap().is_empty());
        // Errors.
        for result in [
            v.add_item_to_folder(a, "0123"),
            v.remove_item_from_folder(a, "0123"),
            v.move_item(a, Some("0123"), None),
            v.move_item(a, Some(&home), Some("0123")),
            v.add_item_to_folder(999, &home),
        ] {
            assert_eq!(result.unwrap_err().kind(), VaultErrorKind::NotFound);
        }
        assert_eq!(
            v.item_folders(999).unwrap_err().kind(),
            VaultErrorKind::NotFound
        );
    }

    #[test]
    fn deleting_a_folder_removes_only_that_membership() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut v = vault(&dir);
        let a = add(&mut v, "Alpha");
        let b = add(&mut v, "Beta");
        let work = v.create_folder(None, "Work").unwrap().uuid;
        let acme = v.create_folder(Some(&work), "Acme").unwrap().uuid;
        let home = v.create_folder(None, "Home").unwrap().uuid;
        v.add_item_to_folder(a, &home).unwrap();
        v.add_item_to_folder(a, &acme).unwrap();
        v.add_item_to_folder(b, &acme).unwrap();
        // A subfolder: its memberships move to the parent, in their place.
        assert_eq!(v.delete_folder(&acme).unwrap(), 2);
        assert_eq!(v.item_folders(a).unwrap(), [home.clone(), work.clone()]);
        assert_eq!(v.item_folders(b).unwrap(), std::slice::from_ref(&work));
        // A folder at the top level: the membership goes, the other folders stay.
        assert_eq!(v.delete_folder(&home).unwrap(), 1);
        assert_eq!(v.item_folders(a).unwrap(), std::slice::from_ref(&work));
        let events = v.item_events(a, MAX_ITEM_EVENTS).unwrap();
        assert_eq!(
            (events[0].kind, events[0].detail.as_str()),
            (ItemEventKind::Moved, "Work")
        );
        // A credential already in the parent is there once.
        let sub = v.create_folder(Some(&work), "Sub").unwrap().uuid;
        v.add_item_to_folder(a, &sub).unwrap();
        assert_eq!(v.delete_folder(&sub).unwrap(), 1);
        assert_eq!(v.item_folders(a).unwrap(), std::slice::from_ref(&work));
        // No credential is ever deleted.
        assert_eq!(v.delete_folder(&work).unwrap(), 2);
        assert_eq!(v.search("").unwrap().len(), 2);
        assert_eq!(v.items_in_folder(None, false).unwrap(), [a, b]);
    }

    #[test]
    fn undo_of_a_move_gives_back_every_folder() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut v = vault(&dir);
        let a = add(&mut v, "Alpha");
        let b = add(&mut v, "Beta");
        let work = v.create_folder(None, "Work").unwrap().uuid;
        let home = v.create_folder(None, "Home").unwrap().uuid;
        let bills = v.create_folder(None, "Bills").unwrap().uuid;
        v.add_item_to_folder(a, &home).unwrap();
        v.add_item_to_folder(a, &work).unwrap();
        v.add_item_to_folder(b, &bills).unwrap();
        let moves = v.move_items_to_folder(&[a, b], Some(&bills)).unwrap();
        // Only the credential that changes is in the receipt; `from` is its first folder.
        assert_eq!(moves.len(), 1);
        assert_eq!(moves[0].from, Some(home.clone()));
        assert_eq!(v.item_folders(a).unwrap(), std::slice::from_ref(&bills));
        v.undo_item_folder_moves(&moves).unwrap();
        assert_eq!(v.item_folders(a).unwrap(), [home.clone(), work.clone()]);
        // A later change of the folders refuses the Undo.
        let moves = v.move_items_to_folder(&[a], None).unwrap();
        v.add_item_to_folder(a, &bills).unwrap();
        v.remove_item_from_folder(a, &bills).unwrap();
        assert_eq!(
            v.undo_item_folder_moves(&moves).unwrap_err().kind(),
            VaultErrorKind::Conflict
        );
    }

    /// The live rows and the tombstones of an item: (folder, removed).
    fn rows(v: &Vault, item: u64) -> Vec<(String, bool)> {
        v.conn_ref()
            .unwrap()
            .prepare(
                "SELECT folder_uuid, removed_at IS NOT NULL FROM item_folder
                 WHERE item_id = ?1 ORDER BY folder_uuid",
            )
            .unwrap()
            .query_map([i64::try_from(item).unwrap()], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    #[test]
    fn a_row_of_a_folder_that_is_not_here_stays_through_every_change() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut v = vault(&dir);
        let a = add(&mut v, "Alpha");
        let work = v.create_folder(None, "Work").unwrap().uuid;
        let home = v.create_folder(None, "Home").unwrap().uuid;
        // A membership of a folder that only another device has, as after a merge.
        v.conn_ref()
            .unwrap()
            .execute(
                "INSERT INTO item_folder (item_id, folder_uuid, added_at, updated_at, updated_by)
                 VALUES (?1, 'ffff', 5, 5, 'other')",
                [i64::try_from(a).unwrap()],
            )
            .unwrap();
        let other = ("ffff".to_owned(), false);
        assert!(v.item_folders(a).unwrap().is_empty());
        v.add_item_to_folder(a, &work).unwrap();
        assert_eq!(v.item_folders(a).unwrap(), std::slice::from_ref(&work));
        assert!(rows(&v, a).contains(&other));
        let events = v.item_events(a, MAX_ITEM_EVENTS).unwrap();
        assert_eq!(events[0].detail, "Work");
        // `set_item_folder` replaces the folders here and keeps that one.
        v.set_item_folder(a, Some(&home)).unwrap();
        assert_eq!(v.item_folders(a).unwrap(), std::slice::from_ref(&home));
        assert!(rows(&v, a).contains(&other));
        v.set_item_folder(a, None).unwrap();
        assert!(v.item_folders(a).unwrap().is_empty());
        assert!(rows(&v, a).contains(&other));
        // A batch move and its Undo keep it too.
        v.add_item_to_folder(a, &work).unwrap();
        let moves = v.move_items_to_folder(&[a], Some(&home)).unwrap();
        assert!(rows(&v, a).contains(&other));
        v.undo_item_folder_moves(&moves).unwrap();
        assert_eq!(v.item_folders(a).unwrap(), std::slice::from_ref(&work));
        assert!(rows(&v, a).contains(&other));
    }

    #[test]
    fn a_removed_membership_keeps_a_tombstone_and_comes_back_on_its_row() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut v = vault(&dir);
        let a = add(&mut v, "Alpha");
        let work = v.create_folder(None, "Work").unwrap().uuid;
        let home = v.create_folder(None, "Home").unwrap().uuid;
        v.add_item_to_folder(a, &work).unwrap();
        v.add_item_to_folder(a, &home).unwrap();
        v.remove_item_from_folder(a, &work).unwrap();
        let mut expected = vec![(work.clone(), true), (home.clone(), false)];
        expected.sort();
        assert_eq!(rows(&v, a), expected);
        assert!(v.items_in_folder(Some(&work), false).unwrap().is_empty());
        v.add_item_to_folder(a, &work).unwrap();
        assert_eq!(
            rows(&v, a).iter().filter(|(_, removed)| *removed).count(),
            0
        );
        assert_eq!(rows(&v, a).len(), 2, "the same row again");
        // The version of a row grows with each change, also with a clock that stepped
        // back.
        let version = |v: &Vault| -> i64 {
            v.conn_ref()
                .unwrap()
                .query_row(
                    "SELECT updated_at FROM item_folder WHERE folder_uuid = ?1",
                    [&work],
                    |row| row.get(0),
                )
                .unwrap()
        };
        v.conn_ref()
            .unwrap()
            .execute(
                "UPDATE item_folder SET updated_at = 9000000000000 WHERE folder_uuid = ?1",
                [&work],
            )
            .unwrap();
        v.remove_item_from_folder(a, &work).unwrap();
        assert_eq!(version(&v), 9_000_000_000_001);
    }

    #[test]
    fn a_folder_change_ends_the_bouncer_scopes_of_the_credential() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut v = vault(&dir);
        let a = add(&mut v, "Alpha");
        let b = add(&mut v, "Beta");
        let work = v.create_folder(None, "Work").unwrap().uuid;
        let scope = |v: &Vault, item: u64| {
            v.conn_ref()
                .unwrap()
                .execute(
                    "INSERT INTO bouncer_scope
                         (agent_id, item_id, item_uuid, project_key, project_label, action_kind,
                          revision, hosts, answered_on)
                     VALUES (1, ?1, 'uuid', ?2, 'Project', 'read', 1, '[]', 'mac')",
                    (i64::try_from(item).unwrap(), format!("project-{item}")),
                )
                .unwrap();
        };
        let scopes = |v: &Vault, item: u64| -> i64 {
            v.conn_ref()
                .unwrap()
                .query_row(
                    "SELECT count(*) FROM bouncer_scope WHERE item_id = ?1",
                    [i64::try_from(item).unwrap()],
                    |row| row.get(0),
                )
                .unwrap()
        };
        for change in 0..3 {
            scope(&v, a);
            scope(&v, b);
            match change {
                0 => v.add_item_to_folder(a, &work).unwrap(),
                1 => v.move_item(a, Some(&work), None).unwrap(),
                _ => {
                    v.add_item_to_folder(a, &work).unwrap();
                    scope(&v, a);
                    v.remove_item_from_folder(a, &work).unwrap();
                }
            }
            assert_eq!(scopes(&v, a), 0, "change {change}");
            assert_eq!(scopes(&v, b), 1, "the other credential keeps its scope");
            v.conn_ref()
                .unwrap()
                .execute("DELETE FROM bouncer_scope", [])
                .unwrap();
        }
    }
}
