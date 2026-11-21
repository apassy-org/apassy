//! Headless tests of the Share sheet and Settings › Connect › Public Links
//! (connect-share-v1): each state shows its text, the choices name the expiry and "Show
//! once", a link of another account has no Revoke, and the texts stay short and plain.
//! Synthetic values only.

use std::collections::BTreeMap;

use eframe::egui;

use super::*;
use crate::desktop::ui::owner_tests::{collect, input};

/// The painted text of three frames of `add` (a new sheet is invisible in its first).
fn painted(mut add: impl FnMut(&mut Ui)) -> String {
    let ctx = egui::Context::default();
    let mut text = String::new();
    for _ in 0..3 {
        let output = ctx.run_ui(input(0.0, Vec::new()), |ui| add(ui));
        text.clear();
        for clipped in &output.shapes {
            collect(&clipped.shape, &mut text);
        }
        output.drop_without_applying_deltas();
    }
    text
}

fn view() -> SheetView {
    SheetView {
        name: "Staging database".to_owned(),
        ready: Ready::Yes,
        links: Vec::new(),
        form: None,
        made: None,
        busy: false,
        error: None,
        retry: false,
    }
}

const NOW: u64 = 1_790_000_000;

fn link(account: &str, addresses: &[&str], one_time: bool) -> PublicLink {
    // Built through the row type of the vault: the key is private there, so a test link
    // comes from a list of one row parsed by `rows_of` only through its public fields.
    crate::vault::public_link_for_test(
        "u1",
        "d4e59a0011f71c40fb1dfdb1a8446660",
        "Staging database",
        account,
        NOW + 7 * 86_400,
        one_time,
        addresses.iter().map(|a| (*a).to_owned()).collect(),
        NOW - 60,
    )
}

#[test]
fn the_link_sheet_names_expiry_and_one_time() {
    let mut shown = view();
    shown.form = Some(Form::default());
    let text = painted(|ui| {
        let mut shown = shown.clone();
        let _ = draw_sheet(ui, &mut shown);
    });
    for expected in [
        "Share \u{201c}Staging database\u{201d}",
        PART,
        EXPIRES,
        "7 days",
        SHOW_ONCE,
        SHOW_ONCE_NOTE,
        WHO,
        ANYONE,
        EMAILS,
        CREATE_GO,
        CANCEL,
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    // The addresses field shows only for "Only these e-mail addresses".
    assert!(!text.contains(EMAILS_NOTE), "{text}");
    let mut emails = view();
    emails.form = Some(Form {
        emails: true,
        ..Form::default()
    });
    let text = painted(|ui| {
        let mut shown = emails.clone();
        let _ = draw_sheet(ui, &mut shown);
    });
    assert!(text.contains(EMAILS_NOTE), "{text}");
    // The default expiry is 7 days, and the picker runs from 10 minutes to 30 days.
    assert_eq!(Form::default().expires_in, 7 * 24 * 60 * 60);
    assert_eq!(EXPIRIES.first().map(|e| e.0), Some(600));
    assert_eq!(EXPIRIES.last().map(|e| e.0), Some(30 * 24 * 60 * 60));
}

/// An account without a plan makes links too: the sheet offers "Create Link…", and the
/// People part of release B is not there, not even as a placeholder.
#[test]
fn every_account_gets_create_link_and_no_people_part() {
    let text = painted(|ui| {
        let mut shown = view();
        let _ = draw_sheet(ui, &mut shown);
    });
    assert!(text.contains(CREATE), "{text}");
    assert!(text.contains(NONE_YET), "{text}");
    for absent in ["People", "Add Person", "Read", "Edit", "plan", "Plan"] {
        assert!(!text.contains(absent), "{absent}: {text}");
    }
    let mut none = view();
    none.ready = Ready::NoAccount;
    let text = painted(|ui| {
        let mut shown = none.clone();
        let _ = draw_sheet(ui, &mut shown);
    });
    assert!(text.contains(NO_ACCOUNT), "{text}");
}

#[test]
fn a_link_shows_copy_revoke_and_its_opens() {
    let list = LinkList {
        links: vec![LinkView {
            link_id: "d4e59a0011f71c40fb1dfdb1a8446660".to_owned(),
            created_at: NOW - 60,
            expires_at: NOW + 7 * 86_400,
            one_time: false,
            access: "anyone".to_owned(),
            addresses: 0,
            state: "live".to_owned(),
            opens: 2,
            last_opened_at: Some(NOW - 10),
        }],
        live: 1,
        limit: Some(25),
        mail: true,
    };
    let rows = rows_of(
        &[link("acc_k7m2q4x3ca", &[], false)],
        Some(&list),
        Some("acc_k7m2q4x3ca"),
        &BTreeMap::new(),
        false,
        NOW,
    );
    assert_eq!(rows.len(), 1);
    assert!(rows[0].can_copy && rows[0].can_revoke);
    assert_eq!(rows[0].title, ANYONE);
    assert!(
        rows[0].detail.contains("Opened 2 times"),
        "{}",
        rows[0].detail
    );
    let mut shown = view();
    shown.links = rows;
    let text = painted(|ui| {
        let mut shown = shown.clone();
        let _ = draw_sheet(ui, &mut shown);
    });
    for expected in [COPY, REVOKE, "Opened 2 times", ANYONE] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
}

/// A device of another account in a shared vault lists the link as made by that
/// account, and offers neither Copy nor Revoke.
#[test]
fn a_link_of_another_account_has_no_revoke() {
    let names = BTreeMap::from([("acc_olaaaaaaaa".to_owned(), "Ola".to_owned())]);
    let rows = rows_of(
        &[link("acc_olaaaaaaaa", &["ada@example.com"], true)],
        None,
        Some("acc_k7m2q4x3ca"),
        &names,
        true,
        NOW,
    );
    assert_eq!(rows.len(), 1);
    assert!(!rows[0].can_revoke && !rows[0].can_copy);
    assert!(rows[0].detail.contains("Made by Ola"), "{}", rows[0].detail);
    assert!(
        rows[0].detail.contains("ada@example.com"),
        "{}",
        rows[0].detail
    );
    assert!(rows[0].detail.contains(SHOW_ONCE), "{}", rows[0].detail);
    let text = painted(|ui| {
        let _ = draw_settings(ui, &rows, None, false);
    });
    assert!(text.contains(SETTINGS_GROUP), "{text}");
    assert!(text.contains("Made by Ola"), "{text}");
    assert!(!text.contains(REVOKE), "{text}");
    // Without a name: "Made by another account".
    let rows = rows_of(
        &[link("acc_olaaaaaaaa", &[], false)],
        None,
        Some("acc_k7m2q4x3ca"),
        &BTreeMap::new(),
        true,
        NOW,
    );
    assert!(rows[0].detail.contains(&made_by(ANOTHER_ACCOUNT)));
}

#[test]
fn an_expired_link_leaves_the_lists_and_an_unknown_one_can_be_revoked() {
    let mut old = link("acc_k7m2q4x3ca", &[], false);
    old.expires_at = NOW - 1;
    assert!(
        rows_of(
            &[old.clone()],
            None,
            Some("acc_k7m2q4x3ca"),
            &BTreeMap::new(),
            true,
            NOW
        )
        .is_empty()
    );
    let list = LinkList {
        links: vec![LinkView {
            link_id: "a".repeat(32),
            created_at: NOW - 60,
            expires_at: NOW + 600,
            one_time: true,
            access: "anyone".to_owned(),
            addresses: 0,
            state: "live".to_owned(),
            opens: 0,
            last_opened_at: None,
        }],
        live: 1,
        limit: None,
        mail: false,
    };
    let unknown = unknown_rows(&[old], Some(&list));
    assert_eq!(unknown.len(), 1);
    assert!(unknown[0].can_revoke && !unknown[0].can_copy);
    assert_eq!(unknown[0].title, UNKNOWN_LINK);
}

#[test]
fn the_link_errors_are_clear() {
    assert_eq!(
        error_text(&LinkError::LinkLimit, Some(25)),
        "This account has 25 live links, the most it can have. Revoke one first."
    );
    assert!(error_text(&LinkError::LinkLimit, None).contains("Revoke one first"));
    assert!(LinkError::MailUnavailable.to_string().contains(ANYONE));
    assert_eq!(
        LinkError::TooLarge { fit: 12, total: 40 }.to_string(),
        "Too large for one link: 12 of 40 secrets fit. Share fewer."
    );
    // No price and no purchase hint in a limit (connect-share-v1 section 8).
    for error in [LinkError::LinkLimit, LinkError::MailUnavailable] {
        let text = error_text(&error, Some(25));
        for word in ["€", "plan", "Plan", "upgrade", "buy", "price"] {
            assert!(!text.contains(word), "{word}: {text}");
        }
    }
}

#[test]
fn the_texts_are_short_and_name_no_platform() {
    let made = [
        made_by("Ola"),
        expires_on(NOW),
        opened(0),
        opened(1),
        opened(3),
        ready_note(&[], NOW),
        ready_note(&["ada@example.com".to_owned()], NOW),
    ];
    for text in TEXTS.iter().copied().chain(made.iter().map(String::as_str)) {
        assert!(text.chars().count() <= 90, "{text}");
        for word in [
            "Touch ID",
            "Keychain",
            "macOS",
            "token",
            "upgrade",
            "subscribe",
            "€",
            "key",
        ] {
            assert!(!text.contains(word), "{word}: {text}");
        }
        assert!(
            !text
                .split(|c: char| !c.is_alphanumeric())
                .any(|word| word == "Mac"),
            "{text}"
        );
    }
    assert_eq!(opened(1), "Opened once");
    assert_eq!(audience(&[]), ANYONE);
    assert_eq!(
        audience(&["a@example.com".to_owned(), "b@example.com".to_owned()]),
        "2 e-mail addresses"
    );
}

/// A form of "Only these e-mail addresses" takes 1 to 20 addresses in their normal form
/// and refuses a text that is not one, before any owner check.
#[test]
fn the_form_checks_the_addresses_first() {
    let form = Form {
        emails: true,
        addresses: " Ada.Lovelace@Example.COM, grace@example.com\n".to_owned(),
        ..Form::default()
    };
    let options = form.options().expect("options");
    assert_eq!(
        options.emails.as_deref(),
        Some(
            &[
                "ada.lovelace@example.com".to_owned(),
                "grace@example.com".to_owned()
            ][..]
        )
    );
    let empty = Form {
        emails: true,
        ..Form::default()
    };
    assert_eq!(empty.options(), Err(LinkError::AddressCount));
    let bad = Form {
        emails: true,
        addresses: "not-an-address".to_owned(),
        ..Form::default()
    };
    assert!(matches!(bad.options(), Err(LinkError::BadAddress(_))));
    let many = Form {
        emails: true,
        addresses: (0..21)
            .map(|n| format!("p{n}@example.com"))
            .collect::<Vec<_>>()
            .join(","),
        ..Form::default()
    };
    assert_eq!(many.options(), Err(LinkError::AddressCount));
}
