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
//! - Settings › Connect › Public Links lists every link of the vault. The links that
//!   Connect lists for the account and the open vault does not hold are in one collapsed
//!   group, "Links not in this vault (N)": the account belongs to the computer, which can
//!   hold several vaults, so such a link is mostly a live link of another vault or another
//!   device. Its Revoke asks first.
//! - The list of Connect (`live`, `limit`, `mail`) is checked before the owner check:
//!   "Create Link" is off at the limit, and "Only these e-mail addresses" on a relay that
//!   sends no mail. A relay without the links routes says so, and the sheet stops asking
//!   it until it opens again.
//! - Connect's answer to a creation and the write of the row are one step of the worker,
//!   which holds the account: when the row cannot be written (a lock or another vault
//!   came between), that step revokes the new link at once.
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
use crate::broker::SharedVault;
use crate::connect::link::{
    DEFAULT_EXPIRY, LinkCreated, LinkError, LinkKept, LinkList, LinkOptions, LinkRevoked,
    LinkTarget, LinkView, PendingLink, parse_addresses,
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
pub(crate) const UNKNOWN_LINK: &str = "Link not in this vault";
pub(crate) const REVOKE_UNKNOWN: &str = "Revoke this link?";
pub(crate) const REVOKE_UNKNOWN_NOTE: &str =
    "It may belong to another vault or device. Someone may still use it.";
pub(crate) const NO_EMAIL: &str = "This relay cannot send e-mail codes.";
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
    REVOKE_UNKNOWN,
    REVOKE_UNKNOWN_NOTE,
    NO_EMAIL,
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

/// "Links not in this vault (3)".
pub(crate) fn not_in_vault(count: usize) -> String {
    format!("Links not in this vault ({count})")
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
    /// "Copy Link" of the link that was just made takes the focus, until it holds it.
    pub(crate) focus_copy: bool,
    pub(crate) busy: bool,
    pub(crate) error: Option<String>,
    pub(crate) retry: bool,
    /// Why "Create Link" is off before any owner check: the relay has no links routes, or
    /// the account has its most live links.
    pub(crate) blocked: Option<String>,
    /// The relay sends no code mail: "Only these e-mail addresses" is off.
    pub(crate) no_email: bool,
}

/// What the owner pressed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LinkAction {
    OpenForm,
    CancelForm,
    Submit,
    Copy(String),
    CopyMade,
    Revoke {
        uuid: String,
        link_id: String,
    },
    /// Revoke of a link that the vault does not hold: it asks first.
    AskRevoke(String),
    CancelRevoke,
    Retry,
    Done,
}

fn link_rows(ui: &mut Ui, links: &[LinkRow], action: &mut Option<LinkAction>) {
    rows::group_box(ui, |g| {
        for link in links {
            g.row(|ui| {
                let copy = format!("Copy the link {}", link.title);
                let revoke = format!("Revoke the link {}", link.title);
                // The rightmost button first, and the first that takes the focus: Copy.
                // Revoke never comes first, so a focus that the sheet moves to its first
                // control (after the owner check, or when a focused button goes) never
                // lands on it, and Return never revokes.
                let mut buttons: Vec<(&str, &str, Style)> = Vec::new();
                if link.can_copy {
                    buttons.push((COPY, copy.as_str(), Style::Bordered));
                }
                if link.can_revoke {
                    buttons.push((REVOKE, revoke.as_str(), Style::Bordered));
                }
                let title = rows::label_text(&link.title);
                if let Some(index) =
                    rows::text_buttons_detailed(ui, title, Some(&link.detail), &buttons)
                {
                    *action = Some(if buttons[index].0 == REVOKE && link.uuid.is_empty() {
                        LinkAction::AskRevoke(link.link_id.clone())
                    } else if buttons[index].0 == REVOKE {
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

fn form_rows(ui: &mut Ui, form: &mut Form, no_email: bool) {
    if no_email {
        form.emails = false;
    }
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
            ui.add_enabled_ui(!no_email, |ui| {
                kit::segmented(
                    ui,
                    "link-who",
                    &mut form.emails,
                    &[(false, ANYONE), (true, EMAILS)],
                );
            });
            if no_email {
                ui.add(egui::Label::new(rows::note(NO_EMAIL)).wrap());
            }
        });
        if form.emails {
            g.row(|ui| {
                kit::text_area(ui, &mut form.addresses, "link-addresses", EMAILS_HINT, 3);
                ui.add(egui::Label::new(rows::note(EMAILS_NOTE)).wrap());
            });
        }
    });
}

/// The body of the sheet: the title, the Public Link part, and the buttons. With
/// `view.focus_copy`, "Copy Link" takes the focus; once it holds the focus from the frame
/// before, `view.focus_copy` turns off.
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
    if let Some(blocked) = &view.blocked
        && view.ready == Ready::Yes
    {
        rows::footnote(ui, blocked.as_str());
    }
    let no_email = view.no_email;
    ui.add_enabled_ui(!view.busy, |ui| {
        if view.links.is_empty() && view.form.is_none() && view.made.is_none() {
            if view.ready == Ready::Yes && view.blocked.is_none() {
                rows::footnote(ui, NONE_YET);
            }
        } else if !view.links.is_empty() {
            link_rows(ui, &view.links, &mut action);
        }
        if let Some(made) = &view.made {
            ui.add_space(8.0);
            let focus = view.focus_copy;
            let (copy, held) = kit::notice(ui, Tone::Good, READY, Some(made.as_str()), |ui| {
                let button = kit::small_button(ui, COPY_LINK, Style::Prominent);
                // Return on the new link copies it.
                let held = button.has_focus();
                if focus && !held {
                    button.request_focus();
                }
                (button.clicked(), held)
            });
            if held {
                view.focus_copy = false;
            }
            if copy {
                action = Some(LinkAction::CopyMade);
            }
        }
        if let Some(form) = view.form.as_mut() {
            ui.add_space(8.0);
            form_rows(ui, form, no_email);
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
            let enabled = !view.busy && view.ready == Ready::Yes && view.blocked.is_none();
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

/// What Settings › Connect › Public Links shows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SettingsView {
    /// The links of the open vault.
    pub(crate) links: Vec<LinkRow>,
    /// The links that Connect lists for the account and the vault does not hold.
    pub(crate) unknown: Vec<LinkRow>,
    /// The group of [`Self::unknown`] is open.
    pub(crate) open: bool,
    /// The link id whose Revoke waits for its confirmation.
    pub(crate) confirm: Option<String>,
    pub(crate) error: Option<String>,
    pub(crate) busy: bool,
}

/// The Public Links group of Settings › Connect. Nothing while the vault holds no link
/// and Connect lists none. The links that the vault does not hold are in one group,
/// collapsed until the owner opens it (`view.open` flips); their Revoke asks first.
pub(crate) fn draw_settings(ui: &mut Ui, view: &mut SettingsView) -> Option<LinkAction> {
    if view.links.is_empty() && view.unknown.is_empty() && view.error.is_none() {
        return None;
    }
    let mut action = None;
    rows::group_label(ui, SETTINGS_GROUP);
    if let Some(error) = &view.error {
        rows::footnote_colored(ui, error.as_str(), Tone::Critical.text());
    }
    ui.add_enabled_ui(!view.busy, |ui| {
        if !view.links.is_empty() {
            link_rows(ui, &view.links, &mut action);
        }
        if view.unknown.is_empty() {
            return;
        }
        ui.add_space(6.0);
        kit::disclosure(ui, &mut view.open, &not_in_vault(view.unknown.len()));
        if !view.open {
            return;
        }
        if let Some(link_id) = view.confirm.clone() {
            ui.add_space(4.0);
            kit::notice(
                ui,
                Tone::Warning,
                REVOKE_UNKNOWN,
                Some(REVOKE_UNKNOWN_NOTE),
                |ui| {
                    ui.horizontal(|ui| {
                        if kit::small_button(ui, CANCEL, Style::Bordered).clicked() {
                            action = Some(LinkAction::CancelRevoke);
                        }
                        if kit::small_button(ui, REVOKE, Style::DestructiveProminent).clicked() {
                            action = Some(LinkAction::Revoke {
                                uuid: String::new(),
                                link_id,
                            });
                        }
                    });
                },
            );
        }
        link_rows(ui, &view.unknown, &mut action);
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
            // A link that the list of Connect does not hold (it speaks only for the links
            // made before it was asked), and a one-time link that was opened, open no
            // more: no Copy.
            let mut gone = false;
            if mine && let Some(list) = list {
                match listed.get(link.link_id.as_str()) {
                    Some(view) if view.state == "opened" => {
                        parts.push(OPENED_ONCE.to_owned());
                        gone = true;
                    }
                    Some(view) => parts.push(opened(view.opens)),
                    None if link.created_at < list.asked_at
                        && (!list.links.is_empty() || list.live == 0) =>
                    {
                        parts.push(NOT_LISTED.to_owned());
                        gone = true;
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
                can_copy: mine && !gone && link.key().is_some(),
                can_revoke: mine,
            }
        })
        .collect()
}

/// The links that Connect lists for the account and the rows of the open vault do not
/// hold: links of another vault or device of the account, or one whose row was never
/// written. Revoke asks first; nothing copies them.
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

/// The answer of a creation with its row written: the row and the link text, or the
/// error with the pending link when a repeat of the exact body may work.
type CreateResult = Result<LinkKept, (LinkError, Option<Box<PendingLink>>)>;

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
    /// "Copy Link" still has to take the focus.
    focus: bool,
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
    /// The relay answered the list without the links routes: no link here, and no new
    /// list until a sheet opens.
    no_links: bool,
    /// Settings › Connect: the group of the links not in this vault is open.
    unknown_open: bool,
    /// Settings › Connect: the link id whose Revoke waits for its confirmation.
    confirm: Option<String>,
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

/// Why a new link cannot be made now, before any owner check: a relay without the links
/// routes, or the most live links of the account (from the list of Connect).
fn blocked(links: &LinksUi) -> Option<String> {
    if links.no_links {
        return Some(LinkError::NoLinks.to_string());
    }
    links
        .list
        .as_ref()
        .filter(|list| list.at_limit())
        .map(|list| error_text(&LinkError::LinkLimit, list.limit))
}

/// The relay of the account sends no code mail (from the list of Connect).
fn no_email(links: &LinksUi) -> bool {
    links.list.as_ref().is_some_and(|list| !list.mail)
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
        focus_copy: links
            .made
            .as_ref()
            .is_some_and(|made| &made.target == target && made.focus),
        busy: links.busy() || links.asked,
        error: links.error.clone(),
        retry: links.retry.is_some(),
        blocked: blocked(links),
        no_email: no_email(links),
    }
}

/// The view of Settings › Connect › Public Links.
pub(crate) fn settings_view(app: &DesktopApp) -> SettingsView {
    let links = vault_links(app);
    let own = app.ui.connect.live.account_id();
    let state = &app.ui.connect.links;
    let list = state.list.as_ref();
    let unknown = unknown_rows(&links, list);
    SettingsView {
        links: rows_of(&links, list, own.as_deref(), &names(app), true, now()),
        open: state.unknown_open,
        confirm: state
            .confirm
            .clone()
            .filter(|id| unknown.iter().any(|row| &row.link_id == id)),
        unknown,
        error: state
            .target
            .is_none()
            .then(|| state.error.clone())
            .flatten(),
        busy: state.busy(),
    }
}

/// The sheet of `target`. Returns true on Escape.
pub(crate) fn sheet(app: &mut DesktopApp, ctx: &egui::Context, target: LinkTarget) -> bool {
    if app.ui.connect.links.target.as_ref() != Some(&target) {
        let links = &mut app.ui.connect.links;
        links.form = None;
        links.error = None;
        links.retry = None;
        links.target = Some(target.clone());
        // A new sheet asks Connect again, also a relay that had no links routes.
        links.listed_at = None;
        links.no_links = false;
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
    if !view.focus_copy
        && let Some(made) = app.ui.connect.links.made.as_mut()
    {
        made.focus = false;
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
    let mut view = settings_view(app);
    let action = draw_settings(ui, &mut view);
    app.ui.connect.links.unknown_open = view.open;
    if let Some(action) = action {
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
        LinkAction::Revoke { uuid, link_id } => {
            app.ui.connect.links.confirm = None;
            revoke(app, ctx, uuid, link_id);
        }
        LinkAction::AskRevoke(link_id) => app.ui.connect.links.confirm = Some(link_id),
        LinkAction::CancelRevoke => app.ui.connect.links.confirm = None,
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
    // What the list of Connect says, before the owner check (ADR 0047 section 6).
    if links.no_links {
        return fail(app, LinkError::NoLinks);
    }
    if links.list.as_ref().is_some_and(LinkList::at_limit) {
        return fail(app, LinkError::LinkLimit);
    }
    if form.emails && no_email(links) {
        return fail(app, LinkError::MailUnavailable);
    }
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
    let Some(epoch) = app.owner_ui.session.epoch() else {
        return;
    };
    let Some(pending) = app.ui.connect.links.pending.take() else {
        return;
    };
    app.ui.connect.links.error = None;
    let vault = app.owner_ui.session.shared_vault();
    spawn(app, ctx, move |account| {
        let sent = account.send_public_link(pending);
        Outcome::Created(Box::new(keep(account, sent, &vault, &epoch)))
    });
}

/// Write the row of a link that Connect took, on the step that holds the account; when
/// it cannot be written, the link is revoked at once
/// ([`ConnectAccount::keep_or_revoke`]).
fn keep(
    account: &mut ConnectAccount,
    created: Result<LinkCreated, (LinkError, Option<Box<PendingLink>>)>,
    vault: &SharedVault,
    epoch: &[u8; 32],
) -> CreateResult {
    let created = created?;
    account
        .keep_or_revoke(created, |created| write_row(vault, epoch, created))
        .map_err(|error| (error, None))
}

/// The row of `created` in the vault of the session `epoch`: refused when that vault is
/// locked or another one is open now.
pub(crate) fn write_row(
    vault: &SharedVault,
    epoch: &[u8; 32],
    created: &LinkCreated,
) -> Result<crate::vault::PublicLink, LinkError> {
    let mut slot = vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match slot.as_mut() {
        Some(open) if !open.is_locked() && open.epoch() == *epoch => created.apply(open),
        _ => Err(LinkError::Vault),
    }
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
    let due = !links.no_links
        && links
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
    let vault = app.owner_ui.session.shared_vault();
    spawn(app, ctx, move |account| {
        let created = account.create_public_link(pending, proof, &epoch);
        Outcome::Created(Box::new(keep(account, created, &vault, &epoch)))
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
        Outcome::Listed(Ok(list)) => {
            let links = &mut app.ui.connect.links;
            links.list = Some(list);
            links.no_links = false;
        }
        Outcome::Listed(Err(LinkError::NoLinks)) => {
            // An older or a self-hosted relay: no link here, and no new list until a
            // sheet opens.
            let links = &mut app.ui.connect.links;
            links.no_links = true;
            links.list = None;
        }
        Outcome::Listed(Err(error)) => {
            // A failed read keeps the last list; the sheet says so only for a link step.
            tracing::debug!(error = %error, "public links not listed");
        }
        Outcome::Created(result) => match *result {
            Ok(kept) => {
                // The worker wrote the row already.
                let links = &mut app.ui.connect.links;
                links.form = None;
                links.retry = None;
                links.listed_at = None;
                if let Some(list) = links.list.as_mut()
                    && !list
                        .links
                        .iter()
                        .any(|view| view.link_id == kept.view.link_id)
                {
                    list.links.insert(0, kept.view.clone());
                    list.live += 1;
                }
                let target = links
                    .target
                    .clone()
                    .unwrap_or(LinkTarget::Folder(String::new()));
                links.made = Some(Made {
                    target,
                    note: ready_note(&kept.row.addresses, kept.row.expires_at),
                    link: kept.link(),
                    focus: true,
                });
            }
            Err((error, pending)) => {
                let links = &mut app.ui.connect.links;
                if error == LinkError::NoLinks {
                    links.no_links = true;
                    links.form = None;
                }
                if matches!(error, LinkError::NotSaved { .. }) {
                    links.form = None;
                    links.listed_at = None;
                }
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

impl DesktopApp {
    /// A step of the screenshot tour (`connect link-…`, scene `connect-links`):
    /// `link-item` opens the Share sheet of the first credential, `link-folder` that of
    /// the first folder, `link-form` opens the choices, `link-emails` picks "Only these
    /// e-mail addresses" with two synthetic addresses, `link-anyone` picks "Anyone with
    /// the link" again, and `link-create` presses "Create Link" (the owner check opens).
    /// Returns false when the step does not fit the window.
    pub(crate) fn tour_link(&mut self, ctx: &egui::Context, step: &str) -> bool {
        use super::Sheet;
        match step {
            "link-item" => {
                let first = self
                    .owner_ui
                    .session
                    .with_vault(|vault| vault.search("").ok())
                    .flatten()
                    .and_then(|items| items.into_iter().map(|item| item.id).min());
                let Some(item_id) = first else {
                    return false;
                };
                self.ui.sheet = Some(Sheet::Share { item_id });
                true
            }
            "link-folder" => {
                let first = self
                    .owner_ui
                    .session
                    .with_vault(|vault| vault.folders().ok())
                    .flatten()
                    .and_then(|folders| folders.into_iter().find(|f| f.parent.is_none()));
                let Some(folder) = first else {
                    return false;
                };
                self.ui.sheet = Some(Sheet::ShareFolder { uuid: folder.uuid });
                true
            }
            "link-form" => {
                act(self, ctx, &LinkTarget::Item(0), LinkAction::OpenForm);
                self.ui.connect.links.form.is_some()
            }
            "link-emails" | "link-anyone" => {
                let Some(form) = self.ui.connect.links.form.as_mut() else {
                    return false;
                };
                form.emails = step == "link-emails";
                form.addresses = if form.emails {
                    "ada@example.com\ngrace@example.com".to_owned()
                } else {
                    String::new()
                };
                true
            }
            "link-create" => {
                let target = match &self.ui.sheet {
                    Some(Sheet::Share { item_id }) => LinkTarget::Item(*item_id),
                    Some(Sheet::ShareFolder { uuid }) => LinkTarget::Folder(uuid.clone()),
                    _ => return false,
                };
                act(self, ctx, &target, LinkAction::Submit);
                self.owner.check.is_some()
            }
            _ => false,
        }
    }
}
