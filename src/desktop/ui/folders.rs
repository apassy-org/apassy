//! Folders of the personal vault (ADR 0026 §5): the tree that the sidebar and the
//! list read, and the sheets New Folder, Rename, Delete, Move to Folder, and Add to
//! Folder.
//!
//! A credential is in any number of folders (ADR 0047 §2) and shows in the list of each.
//! "Move to Folder…" replaces the folder of the list the owner is in (every folder in
//! "All credentials"), "Add to Folder…" adds one, and "Remove from This Folder" removes
//! the folder of the list. Each of them, and a drag onto a folder of the sidebar, has an
//! Undo.
//!
//! The sheets change the vault through the folders API (`src/vault/folders.rs`). A
//! folder change needs no owner check: it changes no access. Moving a credential
//! changes nothing else, and deleting a folder moves its credentials to the parent: it
//! never deletes a credential.

use std::collections::{BTreeMap, BTreeSet};

use eframe::egui::{self, Label};

use super::kit::{self, Font, Icon, Style};
use super::{Sheet, close_sheet, save_pressed};
use crate::desktop::{DesktopApp, Place};
use crate::vault::{
    Folder, FolderChange, MAX_FOLDER_DEPTH, MAX_FOLDER_NAME_BYTES, VaultError, VaultErrorKind,
};

/// The label of the top level for a credential: it is in no folder. Display only: the
/// vault stores no name for the top level. "Personal" stays the name of the vault.
pub(crate) const NO_FOLDER: &str = "No folder";

/// The label of the top level for a folder, in Move Folder.
pub(crate) const TOP_LEVEL: &str = "Top level";

/// The actions on the folders of a credential (ADR 0047 §2), in the More menu, the
/// selection bar, and the Item menu of the Mac.
pub(crate) const MOVE_TO_FOLDER: &str = "Move to Folder…";
pub(crate) const ADD_TO_FOLDER: &str = "Add to Folder…";
pub(crate) const REMOVE_FROM_FOLDER: &str = "Remove from This Folder";
/// The lead of Add to Folder.
const ADD_LEAD_ONE: &str = "Its other folders stay.";
const ADD_LEAD_MANY: &str = "Their other folders stay.";
/// The row of the detail for a credential in several folders.
pub(crate) const FOLDERS_LABEL: &str = "Folders";
/// The folders changed on another device between the list and the change.
const STALE: &str = "The folders changed on another device. Nothing moved.";

/// What the Undo of the list gives back.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FolderUndo {
    #[default]
    Moved,
    Added,
    Removed,
}

impl FolderUndo {
    /// The note of the list: "2 credentials moved".
    pub(crate) fn note(self, count: usize) -> String {
        let verb = match self {
            Self::Moved => "moved",
            Self::Added => "added",
            Self::Removed => "removed",
        };
        match count {
            1 => format!("1 credential {verb}"),
            _ => format!("{count} credentials {verb}"),
        }
    }

    /// The Undo button of the list and the Edit menu of the Mac.
    pub(crate) fn button(self) -> &'static str {
        match self {
            Self::Moved => "Undo Move",
            Self::Added => "Undo Add",
            Self::Removed => "Undo Remove",
        }
    }

    fn done(self) -> &'static str {
        match self {
            Self::Moved => "Move undone. Credentials are back in their original folders.",
            Self::Added => "Add undone.",
            Self::Removed => "Remove undone.",
        }
    }
}

/// Every fixed text of the folder actions of ADR 0047 §2, for the wording tests.
#[cfg(test)]
pub(crate) const TEXTS: &[&str] = &[
    MOVE_TO_FOLDER,
    ADD_TO_FOLDER,
    REMOVE_FROM_FOLDER,
    ADD_LEAD_ONE,
    ADD_LEAD_MANY,
    FOLDERS_LABEL,
    STALE,
    "Undo Add",
    "Undo Remove",
    "Add undone.",
    "Remove undone.",
    "Add",
    "Add…",
    "Remove",
];

/// The folders of the open vault and the folders of each credential, read once for a
/// frame.
#[derive(Debug, Default, Clone)]
pub(crate) struct FolderTree {
    /// Depth first; each level by position, name, and UUID.
    pub(crate) folders: Vec<Folder>,
    /// The folders of each credential in a folder, first folder first.
    pub(crate) item_folders: BTreeMap<u64, Vec<String>>,
}

impl FolderTree {
    /// Read the tree. A locked vault or an error gives an empty tree: the list then
    /// shows every credential at the top level.
    pub(crate) fn load(app: &DesktopApp) -> Self {
        app.owner_ui
            .session
            .with_vault(|vault| -> Result<Self, VaultError> {
                Ok(Self {
                    folders: vault.folders()?,
                    item_folders: vault.folder_index()?.credentials().clone(),
                })
            })
            .and_then(Result::ok)
            .unwrap_or_default()
    }

    pub(crate) fn get(&self, uuid: &str) -> Option<&Folder> {
        self.folders.iter().find(|folder| folder.uuid == uuid)
    }

    pub(crate) fn name(&self, uuid: &str) -> Option<String> {
        self.get(uuid).map(|folder| folder.name.clone())
    }

    /// The folders right under `parent`.
    pub(crate) fn children<'a>(
        &'a self,
        parent: Option<&'a str>,
    ) -> impl Iterator<Item = &'a Folder> + 'a {
        self.folders
            .iter()
            .filter(move |folder| folder.parent.as_deref() == parent)
    }

    pub(crate) fn has_children(&self, uuid: &str) -> bool {
        self.children(Some(uuid)).next().is_some()
    }

    /// The names from the top level to `uuid`.
    pub(crate) fn path(&self, uuid: &str) -> Vec<String> {
        let mut names = Vec::new();
        let mut at = self.get(uuid);
        while let Some(folder) = at {
            names.push(folder.name.clone());
            if names.len() > MAX_FOLDER_DEPTH * 4 {
                break;
            }
            at = folder.parent.as_deref().and_then(|parent| self.get(parent));
        }
        names.reverse();
        names
    }

    /// The label of the folder of a credential: "Work › Acme", or [`NO_FOLDER`] for the
    /// top level and for a folder that is gone.
    pub(crate) fn path_label(&self, uuid: Option<&str>) -> String {
        match uuid {
            Some(uuid) if self.get(uuid).is_some() => self.path(uuid).join(" › "),
            _ => NO_FOLDER.to_owned(),
        }
    }

    /// The folder in a status sentence: " in Work › Acme", as in "Added GitHub in
    /// Work.", or nothing for the top level, where a new credential goes by default.
    pub(crate) fn in_folder(&self, uuid: Option<&str>) -> String {
        match uuid {
            Some(uuid) if self.get(uuid).is_some() => {
                format!(" in {}", self.path_label(Some(uuid)))
            }
            _ => String::new(),
        }
    }

    /// The places of a folder menu: [`NO_FOLDER`] (the top level), then each folder in
    /// tree order with its path, such as "Work › Acme".
    pub(crate) fn choices(&self) -> Vec<(Option<String>, String)> {
        std::iter::once((None, self.path_label(None)))
            .chain(self.folders.iter().map(|folder| {
                (
                    Some(folder.uuid.clone()),
                    self.path_label(Some(&folder.uuid)),
                )
            }))
            .collect()
    }

    /// The folder of a place: the folder of a folder place that still exists, else the
    /// top level. New credentials go there (ADR 0026 §4).
    pub(crate) fn folder_of_place(&self, place: &Place) -> Option<String> {
        match place {
            Place::Folder(Some(uuid)) if self.get(uuid).is_some() => Some(uuid.clone()),
            _ => None,
        }
    }

    /// The level of a folder: 0 at the top level.
    pub(crate) fn level(&self, uuid: &str) -> usize {
        self.path(uuid).len().saturating_sub(1)
    }

    /// The folder and its subfolders.
    pub(crate) fn subtree(&self, uuid: &str) -> BTreeSet<String> {
        let mut found = BTreeSet::from([uuid.to_owned()]);
        loop {
            let more: Vec<String> = self
                .folders
                .iter()
                .filter(|folder| {
                    folder
                        .parent
                        .as_ref()
                        .is_some_and(|parent| found.contains(parent))
                        && !found.contains(&folder.uuid)
                })
                .map(|folder| folder.uuid.clone())
                .collect();
            if more.is_empty() {
                return found;
            }
            found.extend(more);
        }
    }

    /// The first folder of a credential, `None` at the top level.
    pub(crate) fn folder_of(&self, item_id: u64) -> Option<&str> {
        self.folders_of(item_id).first().map(String::as_str)
    }

    /// Every folder of a credential, first folder first; empty at the top level.
    pub(crate) fn folders_of(&self, item_id: u64) -> &[String] {
        self.item_folders.get(&item_id).map_or(&[], Vec::as_slice)
    }

    /// The label of every folder of a credential: "Work, Home › Bills", or
    /// [`NO_FOLDER`].
    pub(crate) fn paths_label(&self, item_id: u64) -> String {
        let folders = self.folders_of(item_id);
        if folders.is_empty() {
            return NO_FOLDER.to_owned();
        }
        folders
            .iter()
            .map(|uuid| self.path_label(Some(uuid)))
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// The credential is in `place`: every credential for "All credentials", the
    /// credentials of the folder and its subfolders for a folder. A credential in
    /// several folders is in the list of each.
    pub(crate) fn contains(&self, place: &Place, item_id: u64) -> bool {
        match place {
            Place::Folder(None) => true,
            Place::Folder(Some(_)) => self.list_folder(place, item_id).is_some(),
            _ => false,
        }
    }

    /// The folder through which a credential is in the list of a folder: the folder
    /// itself, else its first folder below it. `None` outside a folder list, and for a
    /// credential that is not in the list. "Move to Folder…" replaces this folder.
    pub(crate) fn list_folder(&self, place: &Place, item_id: u64) -> Option<&str> {
        let Place::Folder(Some(uuid)) = place else {
            return None;
        };
        let folders = self.folders_of(item_id);
        if let Some(folder) = folders.iter().find(|folder| *folder == uuid) {
            return Some(folder);
        }
        let subtree = self.subtree(uuid);
        folders
            .iter()
            .find(|folder| subtree.contains(*folder))
            .map(String::as_str)
    }

    /// The folder under which a credential is grouped in the list of `place`: the
    /// folder of the list, else its first folder.
    pub(crate) fn group_folder(&self, place: &Place, item_id: u64) -> Option<&str> {
        self.list_folder(place, item_id)
            .or_else(|| self.folder_of(item_id))
    }

    /// The credential is in the folder of the list itself, not only in a subfolder:
    /// "Remove from This Folder" applies.
    pub(crate) fn directly_in(&self, place: &Place, item_id: u64) -> Option<&str> {
        match place {
            Place::Folder(Some(uuid)) => self
                .folders_of(item_id)
                .iter()
                .find(|folder| *folder == uuid)
                .map(String::as_str),
            _ => None,
        }
    }

    /// The credentials of `items` in the folder or its subfolders, for the sidebar. A
    /// credential in several of them counts once; one in two folders counts in each.
    pub(crate) fn count(&self, uuid: &str, items: &[u64]) -> usize {
        let subtree = self.subtree(uuid);
        items
            .iter()
            .filter(|id| self.folders_of(**id).iter().any(|f| subtree.contains(f)))
            .count()
    }

    /// A folder that the credential is not in: "Add to Folder…" has a choice.
    pub(crate) fn can_add(&self, item_id: u64) -> bool {
        let current = self.folders_of(item_id);
        self.folders
            .iter()
            .any(|folder| !current.contains(&folder.uuid))
    }
}

/// What the owner reads when a folder change fails.
fn folder_error(error: &VaultError) -> String {
    match error.kind() {
        VaultErrorKind::AlreadyExists => "A folder with this name is already there.".to_owned(),
        VaultErrorKind::InvalidInput => format!(
            "Type a name of at most {MAX_FOLDER_NAME_BYTES} bytes, without control characters. Folders nest at most {MAX_FOLDER_DEPTH} levels deep."
        ),
        VaultErrorKind::NotFound => concat!(
            "The folder is gone. Another ",
            crate::computer!(),
            " may have deleted it."
        )
        .to_owned(),
        _ => format!("The folder did not change: {error}."),
    }
}

/// Open "New Folder" in `parent`.
pub(super) fn open_new(app: &mut DesktopApp, parent: Option<String>) {
    app.ui.folder_name.clear();
    app.ui.sheet = Some(Sheet::NewFolder { parent });
}

/// Open "Rename Folder" with the current name.
pub(super) fn open_rename(app: &mut DesktopApp, uuid: &str) {
    app.ui.folder_name = FolderTree::load(app).name(uuid).unwrap_or_default();
    app.ui.sheet = Some(Sheet::RenameFolder {
        uuid: uuid.to_owned(),
    });
}

pub(super) fn open_delete(app: &mut DesktopApp, uuid: &str) {
    app.ui.sheet = Some(Sheet::DeleteFolder {
        uuid: uuid.to_owned(),
    });
}

/// Open "Move to Folder" with the folder that the move replaces selected.
pub(super) fn open_move(app: &mut DesktopApp, item_id: u64) {
    app.ui.move_target = FolderTree::load(app)
        .group_folder(&app.place, item_id)
        .map(str::to_owned);
    app.ui.sheet = Some(Sheet::MoveToFolder { item_id });
}

/// Open "Add to Folder" for `item_ids`, with no folder chosen.
pub(super) fn open_add(app: &mut DesktopApp, item_ids: Vec<u64>) {
    if item_ids.is_empty() {
        return;
    }
    app.ui.move_target = None;
    app.ui.sheet = Some(Sheet::AddToFolder { item_ids });
}

/// The credentials that a list action acts on: the selection, else the selected
/// credential.
pub(super) fn chosen_items(app: &DesktopApp) -> Vec<u64> {
    if app.ui.selected_items.is_empty() {
        app.selected_item_id
            .as_deref()
            .and_then(|v| v.parse().ok())
            .into_iter()
            .collect()
    } else {
        app.ui.selected_items.iter().copied().collect()
    }
}

/// Make a folder. On success the sidebar opens its parent and selects it.
pub(crate) fn create(app: &mut DesktopApp, parent: Option<&str>, name: &str) -> Option<Folder> {
    let result = app
        .owner_ui
        .session
        .with_vault(|vault| vault.create_folder(parent, name.trim()));
    match result {
        Some(Ok(folder)) => {
            if let Some(parent) = parent {
                app.ui.open_folders.insert(parent.to_owned());
            }
            app.place = Place::Folder(Some(folder.uuid.clone()));
            app.selected_item_id = None;
            app.set_ok(format!("The folder “{}” is made.", folder.name));
            Some(folder)
        }
        Some(Err(error)) => {
            app.set_err(folder_error(&error));
            None
        }
        None => {
            app.set_err("No vault is open.");
            None
        }
    }
}

pub(crate) fn rename(app: &mut DesktopApp, uuid: &str, name: &str) -> bool {
    match app
        .owner_ui
        .session
        .with_vault(|vault| vault.rename_folder(uuid, name.trim()))
    {
        Some(Ok(())) => {
            app.set_ok(format!("The folder is now “{}”.", name.trim()));
            true
        }
        Some(Err(error)) => {
            app.set_err(folder_error(&error));
            false
        }
        None => false,
    }
}

/// Delete a folder. Its credentials and subfolders go to its parent. A list that showed
/// the folder shows its parent.
pub(crate) fn delete(app: &mut DesktopApp, uuid: &str) -> bool {
    let tree = FolderTree::load(app);
    let parent = tree.get(uuid).and_then(|folder| folder.parent.clone());
    let name = tree.name(uuid).unwrap_or_default();
    match app
        .owner_ui
        .session
        .with_vault(|vault| vault.delete_folder(uuid))
    {
        Some(Ok(moved)) => {
            if let Place::Folder(Some(shown)) = &app.place
                && tree.subtree(uuid).contains(shown)
            {
                app.place = Place::Folder(parent.clone());
            }
            app.ui.open_folders.remove(uuid);
            let place = tree.path_label(parent.as_deref());
            app.set_ok(match (moved, parent.is_some()) {
                (0, _) => format!("The folder “{name}” is deleted."),
                (1, true) => {
                    format!("The folder “{name}” is deleted. Its credential is in {place}.")
                }
                (1, false) => {
                    format!("The folder “{name}” is deleted. Its credential is not in a folder now.")
                }
                (_, true) => format!(
                    "The folder “{name}” is deleted. Its {moved} credentials are in {place}."
                ),
                (_, false) => format!(
                    "The folder “{name}” is deleted. Its {moved} credentials are not in a folder now."
                ),
            });
            true
        }
        Some(Err(error)) => {
            app.set_err(folder_error(&error));
            false
        }
        None => false,
    }
}

/// "Move to Folder…" for one credential: `folder` (`None`: the top level) replaces the
/// folder of the list. Sharing, rules, and history stay.
pub(crate) fn move_item(app: &mut DesktopApp, item_id: u64, folder: Option<&str>) -> bool {
    move_items(app, &[item_id], folder)
}

/// "Move to Folder…": in a folder list, `folder` replaces the folder through which each
/// credential is in the list, and its other folders stay; in "All credentials" each
/// credential leaves every folder for `folder`. One transaction; the source context
/// stays open.
pub(crate) fn move_items(app: &mut DesktopApp, ids: &[u64], folder: Option<&str>) -> bool {
    let tree = FolderTree::load(app);
    let changes: Vec<(u64, FolderChange)> = ids
        .iter()
        .map(|&id| {
            (
                id,
                FolderChange::Move {
                    from: tree.list_folder(&app.place, id).map(str::to_owned),
                    to: folder.map(str::to_owned),
                },
            )
        })
        .collect();
    let Some(count) = change(app, &changes, FolderUndo::Moved) else {
        return false;
    };
    let tree = FolderTree::load(app);
    let what = credentials(count);
    app.set_ok(match folder.filter(|uuid| tree.get(uuid).is_some()) {
        Some(uuid) => format!("Moved {what} to {}.", tree.path_label(Some(uuid))),
        None => format!("Moved {what} out of folders."),
    });
    true
}

/// "Add to Folder…": each credential is also in `folder`; its other folders stay.
pub(crate) fn add_items(app: &mut DesktopApp, ids: &[u64], folder: &str) -> bool {
    let changes: Vec<(u64, FolderChange)> = ids
        .iter()
        .map(|&id| (id, FolderChange::Add(folder.to_owned())))
        .collect();
    let Some(count) = change(app, &changes, FolderUndo::Added) else {
        return false;
    };
    let place = FolderTree::load(app).path_label(Some(folder));
    app.set_ok(match count {
        0 => format!("Already in {place}."),
        _ => format!("Added {} to {place}.", credentials(count)),
    });
    true
}

/// "Remove from This Folder": each credential leaves `folder`; its other folders stay.
/// Without folders it is in "No folder".
pub(crate) fn remove_items(app: &mut DesktopApp, ids: &[u64], folder: &str) -> bool {
    let place = FolderTree::load(app).path_label(Some(folder));
    let changes: Vec<(u64, FolderChange)> = ids
        .iter()
        .map(|&id| (id, FolderChange::Remove(folder.to_owned())))
        .collect();
    let Some(count) = change(app, &changes, FolderUndo::Removed) else {
        return false;
    };
    app.set_ok(format!("Removed {} from {place}.", credentials(count)));
    true
}

/// "1 credential", "2 credentials".
fn credentials(count: usize) -> String {
    match count {
        1 => "1 credential".to_owned(),
        _ => format!("{count} credentials"),
    }
}

/// Apply `changes` in one transaction and keep its Undo. Returns the count of the
/// credentials that changed, or `None` after an error (the status says it).
fn change(
    app: &mut DesktopApp,
    changes: &[(u64, FolderChange)],
    kind: FolderUndo,
) -> Option<usize> {
    match app.owner_ui.session.change_items_folders(changes) {
        Ok(receipt) => {
            let count = receipt.len();
            if count > 0 {
                app.ui.move_undo = receipt;
                app.ui.move_undo_kind = kind;
            }
            app.ui.selected_items.clear();
            app.ui.selection_anchor = None;
            // A credential that leaves the list is no longer selected.
            let tree = FolderTree::load(app);
            if app
                .selected_item_id
                .as_deref()
                .and_then(|id| id.parse().ok())
                .is_some_and(|id| !tree.contains(&app.place, id))
                || kind == FolderUndo::Moved
            {
                app.selected_item_id = None;
            }
            Some(count)
        }
        Err(error) if error.code == "conflict" => {
            app.set_err(STALE);
            None
        }
        Err(error) => {
            app.set_err(error.message);
            None
        }
    }
}

pub(super) fn undo_move(app: &mut DesktopApp) {
    if app.ui.move_undo.is_empty() {
        return;
    }
    match app
        .owner_ui
        .session
        .undo_item_folder_moves(&app.ui.move_undo)
    {
        Ok(()) => {
            app.ui.move_undo.clear();
            app.set_ok(app.ui.move_undo_kind.done());
        }
        Err(error) => app.set_err(error.message),
    }
}

/// The credentials dragged from the list onto a folder of the sidebar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DraggedItems {
    pub(crate) ids: Vec<u64>,
    /// The name of the credential, or "3 credentials", next to the pointer.
    pub(crate) label: String,
}

/// A drop of dragged credentials on `folder`: a move, as "Move to Folder…" does; with
/// Option (Alt on Linux) held, an add, as "Add to Folder…" does.
pub(crate) fn drop_on_folder(app: &mut DesktopApp, ids: &[u64], folder: &str, add: bool) -> bool {
    if add {
        add_items(app, ids, folder)
    } else {
        move_items(app, ids, Some(folder))
    }
}

pub(super) fn open_move_many(app: &mut DesktopApp) {
    let ids = chosen_items(app);
    if ids.is_empty() {
        return;
    }
    app.ui.move_target = FolderTree::load(app)
        .group_folder(&app.place, ids[0])
        .map(str::to_owned);
    app.ui.sheet = Some(Sheet::MoveItemsToFolder { item_ids: ids });
}

pub(super) fn open_move_folder(app: &mut DesktopApp, uuid: String) {
    app.ui.move_target = FolderTree::load(app)
        .get(&uuid)
        .and_then(|f| f.parent.clone());
    app.ui.sheet = Some(Sheet::MoveFolder { uuid });
}

pub(super) fn move_many_sheet(app: &mut DesktopApp, ctx: &egui::Context, ids: &[u64]) -> bool {
    destination_sheet(
        app,
        ctx,
        &format!("Move {} Credentials", ids.len()),
        None,
        NO_FOLDER,
        |app, target| move_items(app, ids, target),
    )
}

pub(super) fn move_folder_sheet(app: &mut DesktopApp, ctx: &egui::Context, uuid: &str) -> bool {
    let tree = FolderTree::load(app);
    let name = tree
        .name(uuid)
        .unwrap_or_else(|| "Missing Folder".to_owned());
    let excluded = tree.subtree(uuid);
    destination_sheet(
        app,
        ctx,
        &format!("Move Folder “{name}”"),
        Some(&excluded),
        TOP_LEVEL,
        |app, target| match app.owner_ui.session.move_folder(uuid, target) {
            Ok(()) => {
                let fresh = FolderTree::load(app);
                let mut above = target;
                while let Some(parent) = above {
                    app.ui.open_folders.insert(parent.to_owned());
                    above = fresh
                        .get(parent)
                        .and_then(|folder| folder.parent.as_deref());
                }
                app.set_ok(format!("Moved folder “{name}”."));
                true
            }
            Err(error) => {
                app.set_err(error.message);
                false
            }
        },
    )
}

fn destination_sheet(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    title: &str,
    excluded: Option<&BTreeSet<String>>,
    top: &str,
    apply: impl FnOnce(&mut DesktopApp, Option<&str>) -> bool,
) -> bool {
    let tree = FolderTree::load(app);
    let options: Vec<_> = tree
        .choices()
        .into_iter()
        .filter(|(uuid, _)| {
            !uuid
                .as_ref()
                .is_some_and(|id| excluded.is_some_and(|set| set.contains(id)))
        })
        .map(|(uuid, label)| match uuid {
            None => (None, top.to_owned()),
            Some(_) => (uuid, label),
        })
        .collect();
    let mut choice = app.ui.move_target.clone();
    let mut confirm = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "move-destination", 440.0, |ui| {
        kit::sheet_title(
            ui,
            title,
            Some("Choose a destination. Sharing, rules, and history stay the same."),
        );
        kit::sheet_body(ui, |ui| {
            for (uuid, label) in &options {
                ui.selectable_value(&mut choice, uuid.clone(), label);
            }
        });
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                confirm = kit::button(ui, "Move", Style::Prominent).clicked();
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });
    app.ui.move_target = choice.clone();
    if (confirm || save_pressed(app, ctx)) && apply(app, choice.as_deref()) || cancel {
        close_sheet(app, ctx);
    }
    response.escape
}

/// The name field of New Folder and Rename.
fn name_field(app: &mut DesktopApp, ui: &mut egui::Ui) -> egui::Response {
    let response = kit::text_input(ui, &mut app.ui.folder_name, "folder-name", "Name");
    ui.ctx()
        .accesskit_node_builder(response.id, |node| node.set_label("Folder name"));
    response
}

/// "New Folder". Returns true on Escape.
pub(super) fn new_folder_sheet(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    parent: Option<&str>,
) -> bool {
    let tree = FolderTree::load(app);
    let place = match parent.filter(|uuid| tree.get(uuid).is_some()) {
        Some(uuid) => format!("In {}.", tree.path_label(Some(uuid))),
        None => "At the top level.".to_owned(),
    };
    let mut create_now = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "new-folder", 400.0, |ui| {
        kit::sheet_title(ui, "New Folder", Some(&place));
        name_field(app, ui);
        ui.add_space(8.0);
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                let ready = !app.ui.folder_name.trim().is_empty();
                create_now = ui
                    .add_enabled_ui(ready, |ui| kit::button(ui, "Create", Style::Prominent))
                    .inner
                    .clicked();
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });
    if save_pressed(app, ctx) && !app.ui.folder_name.trim().is_empty() {
        create_now = true;
    }
    if create_now {
        let name = app.ui.folder_name.clone();
        if create(app, parent, &name).is_some() {
            close_sheet(app, ctx);
        }
    } else if cancel {
        close_sheet(app, ctx);
    }
    response.escape
}

/// "Rename Folder". Returns true on Escape.
pub(super) fn rename_sheet(app: &mut DesktopApp, ctx: &egui::Context, uuid: &str) -> bool {
    let Some(old) = FolderTree::load(app).name(uuid) else {
        close_sheet(app, ctx);
        return false;
    };
    let mut save = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "rename-folder", 400.0, |ui| {
        kit::sheet_title(ui, &format!("Rename “{old}”"), None);
        name_field(app, ui);
        ui.add_space(8.0);
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                let ready = !app.ui.folder_name.trim().is_empty();
                save = ui
                    .add_enabled_ui(ready, |ui| kit::button(ui, "Rename", Style::Prominent))
                    .inner
                    .clicked();
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });
    if save_pressed(app, ctx) && !app.ui.folder_name.trim().is_empty() {
        save = true;
    }
    if save {
        let name = app.ui.folder_name.clone();
        if rename(app, uuid, &name) {
            close_sheet(app, ctx);
        }
    } else if cancel {
        close_sheet(app, ctx);
    }
    response.escape
}

/// "Delete Folder": an alert. Return and Space press Cancel. Returns true on Escape.
pub(super) fn delete_sheet(app: &mut DesktopApp, ctx: &egui::Context, uuid: &str) -> bool {
    let tree = FolderTree::load(app);
    let Some(folder) = tree.get(uuid).cloned() else {
        close_sheet(app, ctx);
        return false;
    };
    let moves = match folder
        .parent
        .as_deref()
        .filter(|uuid| tree.get(uuid).is_some())
    {
        Some(parent) => format!(
            "Its credentials and subfolders move to {}.",
            tree.path_label(Some(parent))
        ),
        None => {
            "Its credentials move out of folders, and its subfolders to the top level.".to_owned()
        }
    };
    let mut confirm = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "delete-folder", 400.0, |ui| {
        kit::sheet_title(
            ui,
            &format!("Delete “{}”?", folder.name),
            Some(&format!("{moves} No credential is deleted.")),
        );
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                confirm = kit::button(ui, "Delete", Style::DestructiveProminent).clicked();
                cancel = kit::alert_cancel(ui).clicked();
            },
        );
    });
    if confirm {
        if delete(app, uuid) {
            close_sheet(app, ctx);
        }
    } else if cancel {
        close_sheet(app, ctx);
    }
    response.escape
}

/// "Move to Folder": [`NO_FOLDER`] (the top level), then each folder, indented by its
/// level. Returns true on Escape.
pub(super) fn move_sheet(app: &mut DesktopApp, ctx: &egui::Context, item_id: u64) -> bool {
    let Ok(details) = app.owner_ui.session.details(item_id) else {
        close_sheet(app, ctx);
        return false;
    };
    let tree = FolderTree::load(app);
    // In a folder list the move replaces the folder of the list; in "All credentials"
    // it replaces every folder.
    let from = tree.list_folder(&app.place, item_id).map(str::to_owned);
    let all = tree.folders_of(item_id).to_vec();
    let mut choice = app.ui.move_target.clone();
    let mut confirm = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "move-to-folder", 440.0, |ui| {
        kit::sheet_title(
            ui,
            &format!("Move “{}”", details.name),
            Some("Sharing, rules, and history do not change."),
        );
        kit::sheet_body(ui, |ui| {
            kit::section(ui, None, None, |s| {
                // A folder is not inside "No folder": the top folders line up with it.
                let options = std::iter::once((None, NO_FOLDER.to_owned(), 0)).chain(
                    tree.folders.iter().map(|folder| {
                        (
                            Some(folder.uuid.clone()),
                            folder.name.clone(),
                            tree.level(&folder.uuid),
                        )
                    }),
                );
                for (uuid, name, level) in options {
                    let selected = choice == uuid;
                    if folder_row(s, &name, level, selected).clicked() {
                        choice = uuid;
                    }
                }
            });
        });
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                confirm = kit::button(ui, "Move", Style::Prominent).clicked();
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });
    app.ui.move_target = choice.clone();
    if save_pressed(app, ctx) {
        confirm = true;
    }
    if confirm {
        // The same folder changes nothing.
        let unchanged = match &from {
            Some(from) => choice.as_ref() == Some(from),
            None => all == choice.iter().cloned().collect::<Vec<_>>(),
        };
        if unchanged || move_item(app, item_id, choice.as_deref()) {
            close_sheet(app, ctx);
        }
    } else if cancel {
        close_sheet(app, ctx);
    }
    response.escape
}

/// A row of a folder choice: the folder icon, the name indented by its level, and a
/// check when it is the chosen one.
fn folder_row(
    s: &mut kit::Section<'_>,
    name: &str,
    level: usize,
    selected: bool,
) -> egui::Response {
    let response = s.clickable_row(name, |ui| {
        ui.horizontal(|ui| {
            ui.add_space(14.0 * level as f32);
            kit::paint_icon_in(ui, Icon::Folder, 15.0, kit::palette().accent);
            ui.add(Label::new(kit::text(name, Font::Body).color(kit::palette().label)).truncate());
            if selected {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    kit::paint_icon_in(ui, Icon::Check, 13.0, kit::palette().accent)
                });
            }
        });
    });
    ui_selected(&response, selected);
    response
}

/// "Add to Folder": each folder that is not a folder of every credential, indented by
/// its level. The credentials stay in their other folders. Returns true on Escape.
pub(super) fn add_sheet(app: &mut DesktopApp, ctx: &egui::Context, ids: &[u64]) -> bool {
    let tree = FolderTree::load(app);
    let title = match ids {
        [id] => match app.owner_ui.session.details(*id) {
            Ok(details) => format!("Add “{}” to Folder", details.name),
            Err(_) => {
                close_sheet(app, ctx);
                return false;
            }
        },
        _ => format!("Add {} Credentials to Folder", ids.len()),
    };
    let lead = if ids.len() == 1 {
        ADD_LEAD_ONE
    } else {
        ADD_LEAD_MANY
    };
    // A folder of every one of them is no choice.
    let options: Vec<(String, String, usize)> = tree
        .folders
        .iter()
        .filter(|folder| {
            !ids.iter()
                .all(|id| tree.folders_of(*id).contains(&folder.uuid))
        })
        .map(|folder| {
            (
                folder.uuid.clone(),
                folder.name.clone(),
                tree.level(&folder.uuid),
            )
        })
        .collect();
    let mut choice = app
        .ui
        .move_target
        .clone()
        .filter(|uuid| options.iter().any(|(option, _, _)| option == uuid));
    let mut confirm = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "add-to-folder", 440.0, |ui| {
        kit::sheet_title(ui, &title, Some(lead));
        kit::sheet_body(ui, |ui| {
            kit::section(ui, None, None, |s| {
                for (uuid, name, level) in &options {
                    let selected = choice.as_ref() == Some(uuid);
                    if folder_row(s, name, *level, selected).clicked() {
                        choice = Some(uuid.clone());
                    }
                }
            });
        });
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                confirm = ui
                    .add_enabled_ui(choice.is_some(), |ui| {
                        kit::button(ui, "Add", Style::Prominent)
                    })
                    .inner
                    .clicked();
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });
    app.ui.move_target = choice.clone();
    if save_pressed(app, ctx) {
        confirm = true;
    }
    if confirm {
        if let Some(folder) = choice
            && add_items(app, ids, &folder)
        {
            close_sheet(app, ctx);
        }
    } else if cancel {
        close_sheet(app, ctx);
    }
    response.escape
}

/// A row of a choice says to VoiceOver that it is the selected one.
fn ui_selected(response: &egui::Response, selected: bool) {
    response
        .ctx
        .accesskit_node_builder(response.id, |node| node.set_selected(selected));
}

#[cfg(test)]
mod label_tests {
    use super::*;

    fn folder(uuid: &str, parent: Option<&str>, name: &str) -> Folder {
        Folder {
            uuid: uuid.to_owned(),
            parent: parent.map(str::to_owned),
            name: name.to_owned(),
            position: 0,
        }
    }

    /// The top level reads "No folder", not the name of the vault.
    #[test]
    fn the_top_level_is_no_folder() {
        let tree = FolderTree {
            folders: vec![folder("w", None, "Work"), folder("a", Some("w"), "Acme")],
            item_folders: BTreeMap::new(),
        };
        assert_eq!(tree.path_label(None), "No folder");
        assert_eq!(tree.path_label(Some("gone")), "No folder");
        assert_eq!(tree.path_label(Some("a")), "Work › Acme");
        assert_eq!(
            tree.choices(),
            vec![
                (None, "No folder".to_owned()),
                (Some("w".to_owned()), "Work".to_owned()),
                (Some("a".to_owned()), "Work › Acme".to_owned()),
            ]
        );
        assert!(
            tree.choices().iter().all(|(_, label)| label != "Personal"),
            "Personal is the vault"
        );
        assert_eq!(tree.in_folder(Some("a")), " in Work › Acme");
        assert_eq!(tree.in_folder(None), "");
        assert_eq!(tree.in_folder(Some("gone")), "");
        assert_eq!(FolderTree::default().path_label(None), NO_FOLDER);
    }

    /// ADR 0047 §2: the tree keeps every folder of a credential, the first (smallest
    /// `added_at`, as the vault reads them) first. It is in the list and the count of
    /// each, once in a parent of two of them, and a move from the list of a folder
    /// replaces only that folder.
    #[test]
    fn a_credential_counts_in_each_of_its_folders() {
        let tree = FolderTree {
            folders: vec![
                folder("w", None, "Work"),
                folder("a", Some("w"), "Acme"),
                folder("h", None, "Home"),
                folder("b", None, "Bills"),
            ],
            // 1: Home first, then Acme and Work. 2: Work only. 3: no folder.
            item_folders: BTreeMap::from([
                (1, vec!["h".to_owned(), "a".to_owned(), "w".to_owned()]),
                (2, vec!["w".to_owned()]),
            ]),
        };
        let items = [1, 2, 3];
        let place = |uuid: &str| Place::Folder(Some(uuid.to_owned()));
        assert_eq!(tree.folder_of(1), Some("h"), "the first folder");
        assert_eq!(tree.folders_of(1), ["h", "a", "w"]);
        assert_eq!(tree.paths_label(1), "Home, Work › Acme, Work");
        assert_eq!(tree.paths_label(3), NO_FOLDER);
        // Counts: once in Work although it is in Work and in Acme below it.
        assert_eq!(tree.count("w", &items), 2);
        assert_eq!(tree.count("a", &items), 1);
        assert_eq!(tree.count("h", &items), 1);
        assert_eq!(tree.count("b", &items), 0);
        for uuid in ["w", "a", "h"] {
            assert!(tree.contains(&place(uuid), 1), "{uuid}");
        }
        assert!(!tree.contains(&place("b"), 1));
        assert!(tree.contains(&Place::CREDENTIALS, 3));
        // The folder that a move from a list replaces, and the group of the row.
        assert_eq!(
            tree.list_folder(&place("w"), 1),
            Some("w"),
            "the list itself"
        );
        assert_eq!(tree.list_folder(&place("a"), 1), Some("a"));
        assert_eq!(tree.list_folder(&place("h"), 2), None, "not in the list");
        assert_eq!(
            tree.list_folder(&Place::CREDENTIALS, 1),
            None,
            "every folder"
        );
        assert_eq!(tree.group_folder(&Place::CREDENTIALS, 1), Some("h"));
        assert_eq!(tree.group_folder(&place("w"), 1), Some("w"));
        // Remove from This Folder only in a folder that holds it itself.
        assert_eq!(tree.directly_in(&place("w"), 1), Some("w"));
        assert_eq!(tree.directly_in(&place("w"), 2), Some("w"));
        assert_eq!(tree.directly_in(&Place::CREDENTIALS, 1), None);
        assert!(tree.can_add(1), "Bills is left");
        assert!(tree.can_add(2));
    }
}
