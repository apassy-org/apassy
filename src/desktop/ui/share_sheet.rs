//! The Share sheet of a secret and of a folder, and the list of public links in
//! Settings › Connect (ADR 0047 sections 4 and 9, release A; contract connect-share-v1;
//! `crate::connect::link`).
//!
//! - **Public Link**: the links of the secret or folder, each with Copy, Revoke, and how
//!   often it opened; "Create Link…" opens the choices: the expiry (10 minutes to 30
//!   days, 7 days by default), "Show once", and who opens it ("Anyone with the link" or
//!   "Only these e-mail addresses", 1 to 20). "Create Link" checks the size first, then
//!   asks the owner check `CreatePublicLink`, then sends the link; the row is written
//!   only after Connect took it. An account without a plan makes links too.
//! - A failure that gave no answer keeps the exact body: "Try Again" sends it again.
//! - **Revoke** writes the revoke only after Connect answered for the account that made
//!   the link. A link that another account made (a shared vault) shows "Made by
//!   <name>" and has no Revoke and no Copy.
//! - Settings › Connect › Public Links lists every link of the vault, and the links that
//!   Connect lists for the account but the vault does not hold, with Revoke.
//!
//! The People part of the sheet comes with release B.
//!
//! One step at a time runs on a worker with the account of the one session of the app;
//! the UI thread never waits on Connect.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use eframe::egui::{self, Ui};
use zeroize::Zeroizing;

use super::devices::rows;
use super::kit::{self, Font, Style, Tone};
use crate::connect::link::{
    DEFAULT_EXPIRY, LinkCreated, LinkError, LinkList, LinkOptions, LinkRevoked, LinkTarget,
    LinkView, PendingLink, parse_addresses,
};
use crate::connect::{ConnectAccount, ConnectError};
use crate::desktop::DesktopApp;
use crate::desktop::owner_check::{OwnerRequest, Task, TaskPoll};
use crate::vault::{LinkRoot, PublicLink};

// ---- Texts. ----

pub(crate) const PART: &str = "Public Link";
pub(crate) const LEAD: &str = "A copy that opens in a browser. Later changes do not reach it.";
pub(crate) const CREATE: &str = "Create Link…";
pub(crate) const CREATE_GO: &str = "Create Link";
pub(crate) const NONE_YET: &str = "No link yet.";
pub(crate) const EXPIRES: &str = "Expires after";
pub(crate) const SHOW_ONCE: &str = "Show once";
pub(crate) const SHOW_ONCE_NOTE: &str = "It opens one time, then it is gone.";
pub(crate) const WHO: &str = "Who can open it";
pub(crate) const ANYONE: &str = "Anyone with the link";
pub(crate) const EMAILS: &str = "Only these e-mail addresses";
pub(crate) const EMAILS_HINT: &str = "ada@example.com";
pub(crate) const EMAILS_NOTE: &str = "1 to 20 addresses. Each gets a code by e-mail.";
pub(crate) const COPY: &str = "Copy";
pub(crate) const COPY_LINK: &str = "Copy Link";
pub(crate) const REVOKE: &str = "Revoke";
pub(crate) const READY: &str = "Link ready";
pub(crate) const COPIED: &str = "Link copied. It clears from the clipboard in 30 seconds.";
pub(crate) const TRY_AGAIN: &str = "Try Again";
pub(crate) const DONE: &str = "Done";
pub(crate) const CANCEL: &str = "Cancel";
pub(crate) const NO_ACCOUNT: &str =
    "Public links need an Apassy Connect account. Create one in Settings › Connect.";
pub(crate) const SIGNED_OUT: &str = "Sign in to Apassy Connect in Settings › Connect first.";
pub(crate) const SETTINGS_GROUP: &str = "Public Links";
pub(crate) const UNKNOWN_LINK: &str = "A link this vault does not hold";
pub(crate) const OPENED_ONCE: &str = "Opened";
pub(crate) const NOT_LISTED: &str = "Not at Connect";
pub(crate) const ANOTHER_ACCOUNT: &str = "another account";

/// The expiries of the picker.
pub(crate) const EXPIRIES: [(u64, &str); 5] = [
    (10 * 60, "10 minutes"),
    (60 * 60, "1 hour"),
    (24 * 60 * 60, "1 day"),
    (7 * 24 * 60 * 60, "7 days"),
    (30 * 24 * 60 * 60, "30 days"),
];

/// Every fixed text, for the wording tests.
#[cfg(test)]
pub(crate) const TEXTS: &[&str] = &[
    PART,
    LEAD,
    CREATE,
    CREATE_GO,
    NONE_YET,
    EXPIRES,
    SHOW_ONCE,
    SHOW_ONCE_NOTE,
    WHO,
    ANYONE,
    EMAILS,
    EMAILS_HINT,
    EMAILS_NOTE,
    COPY,
    COPY_LINK,
    REVOKE,
    READY,
    COPIED,
    TRY_AGAIN,
    DONE,
    CANCEL,
    NO_ACCOUNT,
    SIGNED_OUT,
    SETTINGS_GROUP,
    UNKNOWN_LINK,
    OPENED_ONCE,
    NOT_LISTED,
    ANOTHER_ACCOUNT,
];

/// "Made by Ola".
pub(crate) fn made_by(name: &str) -> String {
    format!("Made by {name}")
}

/// "Expires 28 Nov 2026".
pub(crate) fn expires_on(at: u64) -> String {
    format!("Expires {}", super::connect::day(at))
}

/// "Opened 3 times".
pub(crate) fn opened(count: u64) -> String {
    match count {
        0 => "Not opened".to_owned(),
        1 => "Opened once".to_owned(),
        n => format!("Opened {n} times"),
    }
}

/// Who opens a link: anyone, one address, or a count.
pub(crate) fn audience(addresses: &[String]) -> String {
    match addresses {
        [] => ANYONE.to_owned(),
        [one] => one.clone(),
        many => format!("{} e-mail addresses", many.len()),
    }
}

/// "Link ready. Anyone with the link can open it until 28 Nov 2026."
pub(crate) fn ready_note(addresses: &[String], expires_at: u64) -> String {
    let who = if addresses.is_empty() {
        "Anyone with the link".to_owned()
    } else {
        audience(addresses)
    };
    format!(
        "{who} can open it until {}.",
        super::connect::day(expires_at)
    )
}

/// The text of a link error for the sheet.
pub(crate) fn error_text(error: &LinkError, limit: Option<u64>) -> String {
    match (error, limit) {
        (LinkError::LinkLimit, Some(limit)) => {
            format!("This account has {limit} live links, the most it can have. Revoke one first.")
        }
        _ => error.to_string(),
    }
}

// ---- The view (pure: the view in, a press out). ----

/// Whether the sheet can make links now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ready {
    Yes,
    NoAccount,
    SignedOut,
}

/// One link in a list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinkRow {
    /// The vault row; empty for a link that only Connect lists.
    pub(crate) uuid: String,
    pub(crate) link_id: String,
    /// The first line: the name in Settings, who opens it in the sheet.
    pub(crate) title: String,
    /// The second line: the expiry, the opens, "Made by …".
    pub(crate) detail: String,
    pub(crate) can_copy: bool,
    pub(crate) can_revoke: bool,
}

/// The choices of a new link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Form {
    pub(crate) expires_in: u64,
    pub(crate) one_time: bool,
    pub(crate) emails: bool,
    pub(crate) addresses: String,
}

impl Default for Form {
    fn default() -> Self {
        Self {
            expires_in: DEFAULT_EXPIRY,
            one_time: false,
            emails: false,
            addresses: String::new(),
        }
    }
}

impl Form {
    fn options(&self) -> Result<LinkOptions, LinkError> {
        Ok(LinkOptions {
            expires_in: self.expires_in,
            one_time: self.one_time,
            emails: if self.emails {
                Some(parse_addresses(&self.addresses)?)
            } else {
                None
            },
        })
    }
}

/// What the sheet shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SheetView {
    pub(crate) name: String,
    pub(crate) ready: Ready,
    pub(crate) links: Vec<LinkRow>,
    pub(crate) form: Option<Form>,
    /// The note of a link that was just made.
    pub(crate) made: Option<String>,
    pub(crate) busy: bool,
    pub(crate) error: Option<String>,
    pub(crate) retry: bool,
}

/// What the owner pressed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LinkAction {
    OpenForm,
    CancelForm,
    Submit,
    Copy(String),
    CopyMade,
    Revoke { uuid: String, link_id: String },
    Retry,
    Done,
}

fn link_rows(ui: &mut Ui, links: &[LinkRow], action: &mut Option<LinkAction>) {
    rows::group_box(ui, |g| {
        for link in links {
            g.row(|ui| {
                let copy = format!("Copy the link {}", link.title);
                let revoke = format!("Revoke the link {}", link.title);
                // The rightmost button first.
                let mut buttons: Vec<(&str, &str, Style)> = Vec::new();
                if link.can_revoke {
                    buttons.push((REVOKE, revoke.as_str(), Style::Bordered));
                }
                if link.can_copy {
                    buttons.push((COPY, copy.as_str(), Style::Bordered));
                }
                let title = rows::label_text(&link.title);
                if let Some(index) =
                    rows::text_buttons_detailed(ui, title, Some(&link.detail), &buttons)
                {
                    *action = Some(if buttons[index].0 == REVOKE {
                        LinkAction::Revoke {
                            uuid: link.uuid.clone(),
                            link_id: link.link_id.clone(),
                        }
                    } else {
                        LinkAction::Copy(link.uuid.clone())
                    });
                }
                ui.add(egui::Label::new(rows::note(&link.detail)).wrap());
            });
        }
    });
}

fn form_rows(ui: &mut Ui, form: &mut Form) {
    rows::group_box(ui, |g| {
        g.field(EXPIRES, |ui| {
            let options: Vec<(u64, String)> = EXPIRIES
                .iter()
                .map(|(seconds, label)| (*seconds, (*label).to_owned()))
                .collect();
            let shown = EXPIRIES
                .iter()
                .find(|(seconds, _)| *seconds == form.expires_in)
                .map_or("7 days", |(_, label)| label);
            kit::picker(
                ui,
                "link-expiry",
                &mut form.expires_in,
                &options,
                shown,
                140.0,
            )
        });
        g.toggle(SHOW_ONCE, Some(SHOW_ONCE_NOTE), &mut form.one_time);
        g.row(|ui| {
            ui.label(rows::label_text(WHO));
            ui.add_space(4.0);
            kit::segmented(
                ui,
                "link-who",
                &mut form.emails,
                &[(false, ANYONE), (true, EMAILS)],
            );
        });
        if form.emails {
            g.row(|ui| {
                kit::text_area(ui, &mut form.addresses, "link-addresses", EMAILS_HINT, 3);
                ui.add(egui::Label::new(rows::note(EMAILS_NOTE)).wrap());
            });
        }
    });
}

/// The body of the sheet: the title, the Public Link part, and the buttons.
pub(crate) fn draw_sheet(ui: &mut Ui, view: &mut SheetView) -> Option<LinkAction> {
    let mut action = None;
    kit::sheet_title(
        ui,
        &format!("Share \u{201c}{}\u{201d}", view.name),
        Some(LEAD),
    );
    rows::group_label(ui, PART);
    match view.ready {
        Ready::NoAccount => rows::footnote(ui, NO_ACCOUNT),
        Ready::SignedOut => rows::footnote(ui, SIGNED_OUT),
        Ready::Yes => {}
    }
    ui.add_enabled_ui(!view.busy, |ui| {
        if view.links.is_empty() && view.form.is_none() && view.made.is_none() {
            if view.ready == Ready::Yes {
                rows::footnote(ui, NONE_YET);
            }
        } else if !view.links.is_empty() {
            link_rows(ui, &view.links, &mut action);
        }
        if let Some(made) = &view.made {
            ui.add_space(8.0);
            let copy = kit::notice(ui, Tone::Good, READY, Some(made.as_str()), |ui| {
                kit::small_button(ui, COPY_LINK, Style::Prominent).clicked()
            });
            if copy {
                action = Some(LinkAction::CopyMade);
            }
        }
        if let Some(form) = view.form.as_mut() {
            ui.add_space(8.0);
            form_rows(ui, form);
        }
    });
    if let Some(error) = &view.error {
        ui.add_space(4.0);
        kit::paragraph(ui, error.as_str(), Font::Callout, Tone::Critical.text());
    }
    ui.add_space(8.0);
    let mut leading = None;
    let mut trailing = None;
    kit::sheet_buttons(
        ui,
        |ui| {
            if view.busy {
                kit::spinner(ui, 14.0);
            }
            if view.retry
                && ui
                    .add_enabled_ui(!view.busy, |ui| kit::button(ui, TRY_AGAIN, Style::Bordered))
                    .inner
                    .clicked()
            {
                leading = Some(LinkAction::Retry);
            }
        },
        |ui| {
            let enabled = !view.busy && view.ready == Ready::Yes;
            if view.form.is_some() {
                if ui
                    .add_enabled_ui(enabled, |ui| kit::button(ui, CREATE_GO, Style::Prominent))
                    .inner
                    .clicked()
                {
                    trailing = Some(LinkAction::Submit);
                }
                if kit::button(ui, CANCEL, Style::Bordered).clicked() {
                    trailing = Some(LinkAction::CancelForm);
                }
            } else {
                if kit::button(ui, DONE, Style::Prominent).clicked() {
                    trailing = Some(LinkAction::Done);
                }
                // An account without a plan makes links too: the button shows for every
                // account, and only waits for the sign-in.
                if ui
                    .add_enabled_ui(enabled, |ui| kit::button(ui, CREATE, Style::Bordered))
                    .inner
                    .clicked()
                {
                    trailing = Some(LinkAction::OpenForm);
                }
            }
        },
    );
    action.or(leading).or(trailing)
}

/// The Public Links group of Settings › Connect. `None` while the vault holds no link
/// and Connect lists none.
pub(crate) fn draw_settings(
    ui: &mut Ui,
    links: &[LinkRow],
    error: Option<&str>,
    busy: bool,
) -> Option<LinkAction> {
    if links.is_empty() && error.is_none() {
        return None;
    }
    let mut action = None;
    rows::group_label(ui, SETTINGS_GROUP);
    if let Some(error) = error {
        rows::footnote_colored(ui, error, Tone::Critical.text());
    }
    ui.add_enabled_ui(!busy, |ui| {
        if !links.is_empty() {
            link_rows(ui, links, &mut action);
        }
    });
    action
}

// ---- The rows. ----

/// The rows of `links` (the vault rows) with what Connect listed (`list`), for the
/// account `own` (`None`: no account here). `names` names the other accounts. With
/// `titles` the first line is the name of the link (Settings), else who opens it.
pub(crate) fn rows_of(
    links: &[PublicLink],
    list: Option<&LinkList>,
    own: Option<&str>,
    names: &BTreeMap<String, String>,
    titles: bool,
    now: u64,
) -> Vec<LinkRow> {
    let listed: BTreeMap<&str, &LinkView> = list
        .map(|list| list.links.iter().map(|v| (v.link_id.as_str(), v)).collect())
        .unwrap_or_default();
    links
        .iter()
        .filter(|link| link.is_live(now))
        .map(|link| {
            let mine = own == Some(link.account_id.as_str());
            let mut parts = Vec::new();
            if titles {
                parts.push(audience(&link.addresses));
            }
            parts.push(expires_on(link.expires_at));
            if mine && let Some(list) = list {
                match listed.get(link.link_id.as_str()) {
                    Some(view) if view.state == "opened" => parts.push(OPENED_ONCE.to_owned()),
                    Some(view) => parts.push(opened(view.opens)),
                    None if !list.links.is_empty() || list.live == 0 => {
                        parts.push(NOT_LISTED.to_owned());
                    }
                    None => {}
                }
            }
            if link.one_time {
                parts.push(SHOW_ONCE.to_owned());
            }
            if !mine {
                let name = names
                    .get(&link.account_id)
                    .map_or(ANOTHER_ACCOUNT, String::as_str);
                parts.push(made_by(name));
            }
            LinkRow {
                uuid: link.uuid.clone(),
                link_id: link.link_id.clone(),
                title: if titles {
                    link.name.clone()
                } else {
                    audience(&link.addresses)
                },
                detail: parts.join(" · "),
                can_copy: mine && link.key().is_some(),
                can_revoke: mine,
            }
        })
        .collect()
}

/// The links that Connect lists for the account and the vault rows do not hold.
pub(crate) fn unknown_rows(links: &[PublicLink], list: Option<&LinkList>) -> Vec<LinkRow> {
    let Some(list) = list else {
        return Vec::new();
    };
    list.links
        .iter()
        .filter(|view| !links.iter().any(|link| link.link_id == view.link_id))
        .map(|view| LinkRow {
            uuid: String::new(),
            link_id: view.link_id.clone(),
            title: UNKNOWN_LINK.to_owned(),
            detail: format!("{} · {}", expires_on(view.expires_at), opened(view.opens)),
            can_copy: false,
            can_revoke: true,
        })
        .collect()
}

// ---- The state. ----

/// The answer of a creation: the receipt, or the error with the pending link when a
/// repeat of the exact body may work.
type CreateResult = Result<LinkCreated, (LinkError, Option<Box<PendingLink>>)>;

/// What a worker step came to.
pub(crate) enum Outcome {
    Listed(Result<LinkList, LinkError>),
    Created(Box<CreateResult>),
    Revoked(String, Result<LinkRevoked, LinkError>),
    RevokedUnknown(Result<(), LinkError>),
}

/// The step that "Try Again" repeats.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Retry {
    Create,
    Revoke { uuid: String, link_id: String },
}

/// The link that was just made: its note and its link text.
struct Made {
    target: LinkTarget,
    note: String,
    link: Zeroizing<String>,
}

/// The state of the sheet and of the Settings list.
#[derive(Default)]
pub(crate) struct LinksUi {
    task: Option<Task<Outcome>>,
    list: Option<LinkList>,
    listed_at: Option<Instant>,
    /// The sheet's choices of a new link, while they are open.
    pub(crate) form: Option<Form>,
    /// The sealed link between "Create Link" and Connect's answer.
    pending: Option<PendingLink>,
    /// The owner check of [`Self::pending`] was asked.
    asked: bool,
    made: Option<Made>,
    error: Option<String>,
    retry: Option<Retry>,
    /// The target of the open sheet, so a new sheet starts clean.
    target: Option<LinkTarget>,
}

impl LinksUi {
    fn busy(&self) -> bool {
        self.task.is_some()
    }

    /// Forget everything at a lock or another vault session: the pending link and its
    /// key go.
    pub(crate) fn reset(&mut self) {
        *self = Self::default();
    }
}

fn now() -> u64 {
    crate::desktop::companion::now()
}

fn spawn(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    work: impl FnOnce(&mut ConnectAccount) -> Outcome + Send + 'static,
) {
    let session = app.connect_session();
    let links = &mut app.ui.connect.links;
    links.task = Some(Task::spawn(Some(ctx.clone()), move || {
        let mut done = None;
        let result = session.with_account(|account| {
            done = Some(work(account));
            Ok(())
        });
        match (done, result) {
            (Some(outcome), _) => outcome,
            (None, Err(error)) => Outcome::Listed(Err(LinkError::Connect(error))),
            (None, Ok(())) => Outcome::Listed(Err(LinkError::Connect(ConnectError::Local))),
        }
    }));
}

fn ready(app: &DesktopApp) -> Ready {
    if app.ui.connect.live.account_id().is_none() {
        Ready::NoAccount
    } else if !app.connect_session().is_open() {
        Ready::SignedOut
    } else {
        Ready::Yes
    }
}

fn root_of(app: &DesktopApp, target: &LinkTarget) -> Option<LinkRoot> {
    match target {
        LinkTarget::Item(id) => app
            .owner_ui
            .session
            .with_vault(|vault| vault.item_uuid(*id).ok().flatten())
            .flatten()
            .map(LinkRoot::Item),
        LinkTarget::Folder(uuid) => Some(LinkRoot::Folder(uuid.clone())),
    }
}

fn vault_links(app: &DesktopApp) -> Vec<PublicLink> {
    app.owner_ui
        .session
        .with_vault(|vault| vault.public_links().unwrap_or_default())
        .unwrap_or_default()
}

fn names(app: &DesktopApp) -> BTreeMap<String, String> {
    app.ui.connect.share.people_names()
}

fn target_name(app: &DesktopApp, target: &LinkTarget) -> String {
    match target {
        LinkTarget::Item(id) => app
            .owner_ui
            .session
            .details(*id)
            .map(|details| details.name)
            .unwrap_or_default(),
        LinkTarget::Folder(uuid) => app
            .owner_ui
            .session
            .with_vault(|vault| {
                vault
                    .folders()
                    .ok()
                    .and_then(|folders| folders.into_iter().find(|f| &f.uuid == uuid))
                    .map(|folder| folder.name)
            })
            .flatten()
            .unwrap_or_default(),
    }
}

/// The view of the sheet of `target`.
pub(crate) fn sheet_view(app: &DesktopApp, target: &LinkTarget) -> SheetView {
    let links = &app.ui.connect.links;
    let root = root_of(app, target);
    let own = app.ui.connect.live.account_id();
    let of_root: Vec<PublicLink> = vault_links(app)
        .into_iter()
        .filter(|link| Some(&link.root) == root.as_ref())
        .collect();
    SheetView {
        name: target_name(app, target),
        ready: ready(app),
        links: rows_of(
            &of_root,
            links.list.as_ref(),
            own.as_deref(),
            &names(app),
            false,
            now(),
        ),
        form: links.form.clone(),
        made: links
            .made
            .as_ref()
            .filter(|made| &made.target == target)
            .map(|made| made.note.clone()),
        busy: links.busy() || links.asked,
        error: links.error.clone(),
        retry: links.retry.is_some(),
    }
}

/// The rows of Settings › Connect › Public Links.
pub(crate) fn settings_rows(app: &DesktopApp) -> Vec<LinkRow> {
    let links = vault_links(app);
    let own = app.ui.connect.live.account_id();
    let list = app.ui.connect.links.list.as_ref();
    let mut out = rows_of(&links, list, own.as_deref(), &names(app), true, now());
    out.extend(unknown_rows(&links, list));
    out
}

/// The sheet of `target`. Returns true on Escape.
pub(crate) fn sheet(app: &mut DesktopApp, ctx: &egui::Context, target: LinkTarget) -> bool {
    if app.ui.connect.links.target.as_ref() != Some(&target) {
        let links = &mut app.ui.connect.links;
        links.form = None;
        links.error = None;
        links.retry = None;
        links.target = Some(target.clone());
        links.listed_at = None;
    }
    step(app, ctx);
    let mut view = sheet_view(app, &target);
    let mut action = None;
    let response = kit::sheet(ctx, "share-sheet", 460.0, |ui| {
        action = draw_sheet(ui, &mut view);
    });
    if view.form.is_some() {
        app.ui.connect.links.form = view.form.clone();
    }
    if let Some(action) = action {
        act(app, ctx, &target, action);
    } else if response.escape {
        close(app, ctx);
    }
    response.escape
}

fn close(app: &mut DesktopApp, ctx: &egui::Context) {
    let links = &mut app.ui.connect.links;
    links.form = None;
    links.made = None;
    links.error = None;
    links.target = None;
    if links.task.is_none() && !links.asked {
        links.pending = None;
        links.retry = None;
    }
    super::close_sheet(app, ctx);
}

/// The Public Links group of Settings › Connect, and its steps.
pub(crate) fn settings_section(app: &mut DesktopApp, ui: &mut Ui) {
    let ctx = ui.ctx().clone();
    step(app, &ctx);
    let rows = settings_rows(app);
    let links = &app.ui.connect.links;
    let error = links
        .target
        .is_none()
        .then(|| links.error.clone())
        .flatten();
    if let Some(action) = draw_settings(ui, &rows, error.as_deref(), links.busy()) {
        let target = LinkTarget::Folder(String::new());
        act(app, &ctx, &target, action);
    }
}

fn act(app: &mut DesktopApp, ctx: &egui::Context, target: &LinkTarget, action: LinkAction) {
    match action {
        LinkAction::OpenForm => {
            let links = &mut app.ui.connect.links;
            links.form = Some(Form::default());
            links.made = None;
            links.error = None;
        }
        LinkAction::CancelForm => app.ui.connect.links.form = None,
        LinkAction::Done => close(app, ctx),
        LinkAction::Submit => submit(app, ctx, target),
        LinkAction::Copy(uuid) => {
            let link = app.owner_ui.session.with_vault(|vault| {
                vault.public_link(&uuid).ok().flatten().and_then(|link| {
                    link.key()
                        .map(|key| crate::connect::link::link_text(&link.origin, key))
                })
            });
            if let Some(Some(text)) = link {
                copy(app, text);
            }
        }
        LinkAction::CopyMade => {
            if let Some(text) = app
                .ui
                .connect
                .links
                .made
                .as_ref()
                .map(|made| made.link.clone())
            {
                copy(app, text);
            }
        }
        LinkAction::Revoke { uuid, link_id } => revoke(app, ctx, uuid, link_id),
        LinkAction::Retry => match app.ui.connect.links.retry.take() {
            Some(Retry::Create) => resend(app, ctx),
            Some(Retry::Revoke { uuid, link_id }) => revoke(app, ctx, uuid, link_id),
            None => {}
        },
    }
}

fn copy(app: &mut DesktopApp, text: Zeroizing<String>) {
    let Some(epoch) = app.owner_ui.session.epoch() else {
        return;
    };
    match app.owner.clipboard.copy_secret(text, epoch, Instant::now()) {
        Ok(_) => app.set_ok(COPIED),
        Err(err) => app.set_err(err.message()),
    }
}

fn submit(app: &mut DesktopApp, ctx: &egui::Context, target: &LinkTarget) {
    let links = &app.ui.connect.links;
    if links.busy() || links.asked {
        return;
    }
    let Some(form) = links.form.clone() else {
        return;
    };
    let limit = links.list.as_ref().and_then(|list| list.limit);
    let fail = |app: &mut DesktopApp, error: LinkError| {
        app.ui.connect.links.error = Some(error_text(&error, limit));
    };
    let options = match form.options() {
        Ok(options) => options,
        Err(error) => return fail(app, error),
    };
    let (Some(origin), Some(account_id)) = (
        app.ui.connect.live.account_origin(),
        app.ui.connect.live.account_id(),
    ) else {
        return fail(app, LinkError::Connect(ConnectError::NoAccount));
    };
    // The size, the origin, and the addresses are checked here, before the owner check.
    let prepared = app.owner_ui.session.with_vault(|vault| {
        PendingLink::prepare(vault, target, &origin, &account_id, &options, now())
    });
    let pending = match prepared {
        Some(Ok(pending)) => pending,
        Some(Err(error)) => return fail(app, error),
        None => return fail(app, LinkError::Vault),
    };
    let request = request_of(&pending);
    let links = &mut app.ui.connect.links;
    links.error = None;
    links.retry = None;
    links.pending = Some(pending);
    links.asked = true;
    app.ask_owner(request, Some(ctx));
}

/// The owner request of `pending`: exactly its action.
fn request_of(pending: &PendingLink) -> OwnerRequest {
    let crate::broker::approvals::OwnerAction::CreatePublicLink {
        account_id,
        link_id,
        name,
        secrets,
        expires_at,
        one_time,
        addresses,
    } = pending.action()
    else {
        unreachable!("a pending link asks CreatePublicLink");
    };
    OwnerRequest::CreatePublicLink {
        account_id,
        link_id,
        name,
        secrets,
        expires_at,
        one_time,
        addresses,
    }
}

fn resend(app: &mut DesktopApp, ctx: &egui::Context) {
    let Some(pending) = app.ui.connect.links.pending.take() else {
        return;
    };
    app.ui.connect.links.error = None;
    spawn(app, ctx, move |account| {
        Outcome::Created(Box::new(account.send_public_link(pending)))
    });
}

fn revoke(app: &mut DesktopApp, ctx: &egui::Context, uuid: String, link_id: String) {
    if app.ui.connect.links.busy() {
        return;
    }
    app.ui.connect.links.error = None;
    if uuid.is_empty() {
        spawn(app, ctx, move |account| {
            Outcome::RevokedUnknown(account.revoke_unknown_link(&link_id))
        });
        return;
    }
    let link = app
        .owner_ui
        .session
        .with_vault(|vault| vault.public_link(&uuid).ok().flatten())
        .flatten();
    let Some(link) = link else {
        return;
    };
    spawn(app, ctx, move |account| {
        Outcome::Revoked(uuid, account.revoke_public_link(&link))
    });
}

/// The steps of one frame: the worker's result, the owner proof, and the list.
pub(crate) fn step(app: &mut DesktopApp, ctx: &egui::Context) {
    if let Some(task) = &app.ui.connect.links.task {
        match task.poll() {
            TaskPoll::Waiting => {}
            TaskPoll::Lost => {
                let links = &mut app.ui.connect.links;
                links.task = None;
                links.error = Some(ConnectError::Local.to_string());
            }
            TaskPoll::Done(outcome) => {
                app.ui.connect.links.task = None;
                apply(app, outcome);
            }
        }
    }
    guarded(app, ctx);
    let links = &app.ui.connect.links;
    if links.busy() {
        ctx.request_repaint_after(Duration::from_millis(250));
        return;
    }
    let due = links
        .listed_at
        .is_none_or(|at| at.elapsed() >= Duration::from_secs(30));
    if due && app.connect_session().is_open() && app.owner_ui.session.epoch().is_some() {
        app.ui.connect.links.listed_at = Some(Instant::now());
        spawn(app, ctx, |account| Outcome::Listed(account.public_links()));
    }
}

fn guarded(app: &mut DesktopApp, ctx: &egui::Context) {
    if !app.ui.connect.links.asked || app.ui.connect.links.busy() {
        return;
    }
    let Some(proof) = take_proof(app) else {
        if app.owner.check.is_none() {
            // The owner cancelled: the sealed link and its key go; a new try seals anew.
            let links = &mut app.ui.connect.links;
            links.asked = false;
            links.pending = None;
        }
        return;
    };
    let links = &mut app.ui.connect.links;
    links.asked = false;
    let (Some(pending), Some(epoch)) = (links.pending.take(), app.owner_ui.session.epoch()) else {
        return;
    };
    spawn(app, ctx, move |account| {
        Outcome::Created(Box::new(account.create_public_link(pending, proof, &epoch)))
    });
}

/// The proof of the owner check of the pending link, when it is that one.
fn take_proof(app: &mut DesktopApp) -> Option<crate::broker::approvals::OwnerProof> {
    let expected = app.ui.connect.links.pending.as_ref()?.action();
    let proof = app.owner.take_connect_proof()?;
    if proof.action() == &expected {
        Some(proof)
    } else {
        // Another part of Settings › Connect asked; give it back.
        app.owner.connect_proof = Some(proof);
        None
    }
}

fn apply(app: &mut DesktopApp, outcome: Outcome) {
    let limit = app
        .ui
        .connect
        .links
        .list
        .as_ref()
        .and_then(|list| list.limit);
    match outcome {
        Outcome::Listed(Ok(list)) => app.ui.connect.links.list = Some(list),
        Outcome::Listed(Err(error)) => {
            // A failed read keeps the last list; the sheet says so only for a link step.
            tracing::debug!(error = %error, "public links not listed");
        }
        Outcome::Created(result) => match *result {
            Ok(created) => {
                let written = app
                    .owner_ui
                    .session
                    .with_vault(|vault| created.apply(vault));
                let links = &mut app.ui.connect.links;
                links.form = None;
                links.retry = None;
                links.listed_at = None;
                match written {
                    Some(Ok(row)) => {
                        let target = links
                            .target
                            .clone()
                            .unwrap_or(LinkTarget::Folder(String::new()));
                        links.made = Some(Made {
                            target,
                            note: ready_note(&row.addresses, row.expires_at),
                            link: created.link(),
                        });
                    }
                    _ => links.error = Some(LinkError::Vault.to_string()),
                }
            }
            Err((error, pending)) => {
                let links = &mut app.ui.connect.links;
                links.error = Some(error_text(&error, limit));
                links.retry = pending.is_some().then_some(Retry::Create);
                links.pending = pending.map(|pending| *pending);
            }
        },
        Outcome::Revoked(uuid, result) => {
            let links = &mut app.ui.connect.links;
            links.listed_at = None;
            match result {
                Ok(receipt) => {
                    let written = app
                        .owner_ui
                        .session
                        .with_vault(|vault| receipt.apply(vault));
                    if !matches!(written, Some(Ok(_))) {
                        app.ui.connect.links.error = Some(LinkError::Vault.to_string());
                    }
                }
                Err(error) => {
                    let link_id = app
                        .owner_ui
                        .session
                        .with_vault(|vault| vault.public_link(&uuid).ok().flatten())
                        .flatten()
                        .map(|link| link.link_id)
                        .unwrap_or_default();
                    let links = &mut app.ui.connect.links;
                    links.retry = error.can_retry().then_some(Retry::Revoke { uuid, link_id });
                    links.error = Some(error_text(&error, limit));
                }
            }
        }
        Outcome::RevokedUnknown(result) => {
            let links = &mut app.ui.connect.links;
            links.listed_at = None;
            if let Err(error) = result {
                links.error = Some(error_text(&error, limit));
            }
        }
    }
}

#[cfg(test)]
#[path = "share_sheet_tests.rs"]
mod share_sheet_tests;
