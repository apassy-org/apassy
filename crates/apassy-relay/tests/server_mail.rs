//! The code mail of public links (connect-share-v1 sections 4.5 and 10, docs/SPEC.md
//! section 38.7): a link for e-mail addresses opens only with the code that Connect mailed,
//! the answer is the same for an address that is not on the link, the code ends at its
//! fifth wrong try, the caps hold, a relay without a mail sender has no such link, and no
//! log line holds an address or a code. A fake SMTP server (`common/fake_smtp.rs`) runs on
//! a free loopback port with its own test certificate authority; each test has its own
//! relay and temporary directory. Synthetic values only.

#[path = "common/relay.rs"]
mod relay;

#[path = "common/fake_stripe.rs"]
mod fake_stripe;

#[path = "common/connect.rs"]
mod connect;

#[path = "common/links.rs"]
mod links;

#[path = "common/fake_smtp.rs"]
mod fake_smtp;

use std::io::Read;
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use apassy_relay::config::{LinkSettings, MailSettings};
use apassy_relay::device::{self, DeviceKey};
use apassy_relay::hostkeys::encode_b64;
use connect::{Connect, Dev, now};
use fake_smtp::FakeSmtp;
use links::{call_with_headers, header, open_body, vector, vector_body};
use relay::{EDGE_SECRET, VAULT_KEY};
use serde_json::{Value, json};

const ADA: &str = " Ada.Lovelace@Example.COM ";
const ADA_NORMAL: &str = "ada.lovelace@example.com";

fn start_with_mail(
    smtp: &FakeSmtp,
    edit: impl FnOnce(&mut apassy_relay::config::RelayConfig),
) -> Connect {
    let settings = smtp.settings();
    connect::start_with_config(move |cfg| {
        cfg.connect.mail = Some(settings);
        edit(cfg);
    })
}

/// A one-time link of the vector `one_time_emails` (Ada and Grace may open it).
fn one_time_email_link(c: &Connect, dev: &Dev) -> (String, String) {
    let body = vector_body("one_time_emails", 3600);
    c.ok("POST", "/v1/account/links", Some(&dev.token), Some(&body));
    (
        body["link_id"].as_str().unwrap().to_string(),
        vector("one_time_emails")["address_key_b64u"]
            .as_str()
            .unwrap()
            .to_string(),
    )
}

/// A link for e-mail addresses that is not one-time: the sealed form of the vector
/// `anyone`, with the address hashes of `addresses` under its address key, and an id of
/// its own.
fn email_link(c: &Connect, dev: &Dev, addresses: &[&str]) -> (String, String) {
    let mut body = vector_body("anyone", 3600);
    // Connect cannot tell an id from the key it comes from: each link here has its own.
    body["link_id"] = json!(links::new_link_id());
    body["access"] = json!("emails");
    body["address_hashes"] = json!(links::hashes_for("anyone", addresses));
    c.ok("POST", "/v1/account/links", Some(&dev.token), Some(&body));
    (
        body["link_id"].as_str().unwrap().to_string(),
        vector("anyone")["address_key_b64u"]
            .as_str()
            .unwrap()
            .to_string(),
    )
}

fn ask_code(c: &Connect, link_id: &str, email: &str, key: &str) -> (u16, Value) {
    c.call(
        "POST",
        &format!("/v1/links/{link_id}/code"),
        None,
        Some(&json!({"email": email, "address_key": key})),
    )
}

fn open_with(
    c: &Connect,
    link_id: &str,
    email: &str,
    key: &str,
    code: &str,
    confirm: bool,
) -> (u16, Value) {
    c.call(
        "POST",
        &format!("/v1/links/{link_id}/open"),
        None,
        Some(&json!({"confirm": confirm, "email": email, "address_key": key, "code": code})),
    )
}

/// The outbox length once it is empty, or after 15 s: the server records a mail before
/// its `250`, and the relay deletes the mail after it.
fn outbox_after_send(links: &apassy_relay::server::links::Links) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let len = links.outbox_len().unwrap();
        if len == 0 || Instant::now() > deadline {
            return len;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Another code than `code`, of eight digits.
fn other_code(code: &str) -> String {
    let value: u32 = code.parse().unwrap();
    format!("{:08}", (value + 1) % 100_000_000)
}

#[test]
fn an_email_link_opens_only_with_the_mailed_code() {
    let smtp = fake_smtp::start(false);
    let c = start_with_mail(&smtp, |_| {});
    let a = c.account("Ada");
    assert_eq!(
        c.ok("GET", "/v1/account/links", Some(&a.token), None)["mail"],
        true
    );
    let (link_id, key) = one_time_email_link(&c, &a);
    let listed = c.ok("GET", "/v1/account/links", Some(&a.token), None);
    assert_eq!(listed["links"][0]["access"], "emails");
    assert_eq!(listed["links"][0]["addresses"], 2);
    // Without a code: no sealed form, and nothing changes.
    let asked = c.ok(
        "POST",
        &format!("/v1/links/{link_id}/open"),
        None,
        Some(&open_body(true)),
    );
    assert_eq!(asked["sealed"], Value::Null);
    assert_eq!(asked["access"], "emails");
    // A code before any mail does not open.
    let (status, answer) = open_with(&c, &link_id, ADA, &key, "00000000", true);
    assert_eq!(
        (status, answer["error"]["code"].as_str()),
        (403, Some("code_invalid"))
    );

    let (status, headers, text) = call_with_headers(
        &c.relay.url,
        EDGE_SECRET,
        "POST",
        &format!("/v1/links/{link_id}/code"),
        &[],
        Some(&json!({"email": ADA, "address_key": key})),
    );
    assert_eq!(status, 200, "{text}");
    assert_eq!(header(&headers, "referrer-policy"), Some("no-referrer"));
    assert_eq!(header(&headers, "cache-control"), Some("no-store"));
    assert_eq!(
        serde_json::from_str::<Value>(&text).unwrap()["result"],
        json!({"expires_in": 900})
    );
    let mails = smtp.wait_for(1);
    assert_eq!(mails.len(), 1);
    let mail = &mails[0];
    assert_eq!(mail.to, ADA_NORMAL);
    assert_eq!(mail.from, fake_smtp::FROM);
    assert_eq!(mail.user.as_deref(), Some(fake_smtp::USER));
    assert!(mail.tls, "the mail went over TLS (STARTTLS)");
    // Plain text, only the code: no link, no image, no name of the person who made it.
    assert!(mail.data.contains("\r\nSubject: Your Apassy code\r\n"));
    assert!(mail.data.contains("Content-Type: text/plain"));
    let code = mail.code();
    assert!(mail.data.contains(&format!(
        "\r\n\r\nYour code to open a shared Apassy item: {code}\r\n\r\nIt works for 15 minutes. If you did not ask for it, ignore this mail.\r\n"
    )));
    for absent in ["http", "<img", "/s#", "Ada's", &link_id] {
        assert!(!mail.data.contains(absent), "{absent}");
    }
    // The mail left the outbox at once.
    assert_eq!(outbox_after_send(c.relay.hub().links().unwrap()), 0);

    // Another address of the link cannot use Ada's code.
    let grace = "grace@BÜCHER.example";
    let (status, _) = open_with(&c, &link_id, grace, &key, &code, true);
    assert_eq!(status, 403);
    // The right code and no yes yet: no sealed form, the code stays, no try counts.
    for _ in 0..6 {
        let held = open_with(&c, &link_id, ADA, &key, &code, false);
        assert_eq!(held.0, 200);
        assert_eq!(held.1["result"]["sealed"], Value::Null);
        assert_eq!(held.1["result"]["one_time"], true);
    }
    let opened = open_with(&c, &link_id, ADA, &key, &code, true);
    assert_eq!(opened.0, 200, "{}", opened.1);
    assert_eq!(
        opened.1["result"]["sealed"],
        vector("one_time_emails")["sealed_b64u"]
    );
    // One-time: gone for everyone, also with a new code.
    assert_eq!(open_with(&c, &link_id, ADA, &key, &code, true).0, 404);
    assert_eq!(ask_code(&c, &link_id, ADA, &key).0, 404);

    // A link that is not one-time opens with each new code, once per code.
    let (link_id, key) = email_link(&c, &a, &["ada.lovelace@example.com"]);
    assert_eq!(ask_code(&c, &link_id, ADA, &key).0, 200);
    let code = smtp.wait_for(2)[1].code();
    let opened = open_with(&c, &link_id, ADA, &key, &code, false);
    assert_eq!(
        opened.1["result"]["sealed"],
        vector("anyone")["sealed_b64u"]
    );
    let (status, answer) = open_with(&c, &link_id, ADA, &key, &code, false);
    assert_eq!(
        (status, answer["error"]["code"].as_str()),
        (403, Some("code_invalid"))
    );
    assert_eq!(ask_code(&c, &link_id, ADA, &key).0, 200);
    let next = smtp.wait_for(3)[2].code();
    assert_eq!(open_with(&c, &link_id, ADA, &key, &next, false).0, 200);
    let listed = c.ok("GET", "/v1/account/links", Some(&a.token), None);
    let row = listed["links"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["link_id"] == link_id.as_str())
        .unwrap()
        .clone();
    assert_eq!(row["opens"], 2);
}

#[test]
fn submission_over_tls_from_the_first_byte_works() {
    let smtp = fake_smtp::start(true);
    let c = start_with_mail(&smtp, |_| {});
    let a = c.account("Ada");
    let (link_id, key) = email_link(&c, &a, &[ADA_NORMAL]);
    assert_eq!(ask_code(&c, &link_id, ADA, &key).0, 200);
    let mails = smtp.wait_for(1);
    assert_eq!(mails.len(), 1);
    assert!(mails[0].tls);
    assert_eq!(mails[0].to, ADA_NORMAL);
    // A new code ends the code before it: one live code for each link and address.
    let first = mails[0].code();
    assert_eq!(ask_code(&c, &link_id, ADA, &key).0, 200);
    let second = smtp.wait_for(2)[1].code();
    if first != second {
        assert_eq!(open_with(&c, &link_id, ADA, &key, &first, false).0, 403);
    }
    assert_eq!(open_with(&c, &link_id, ADA, &key, &second, false).0, 200);
}

#[test]
fn the_code_answer_is_the_same_for_an_unknown_address() {
    let smtp = fake_smtp::start(false);
    let c = start_with_mail(&smtp, |_| {});
    let a = c.account("Ada");
    let (link_id, key) = email_link(&c, &a, &[ADA_NORMAL]);
    let ask = |email: &str, key: &str| {
        call_with_headers(
            &c.relay.url,
            EDGE_SECRET,
            "POST",
            &format!("/v1/links/{link_id}/code"),
            &[],
            Some(&json!({"email": email, "address_key": key})),
        )
    };
    let listed = ask(ADA, &key);
    let unknown = ask("nobody@example.com", &key);
    // An address key of another link gives hashes that no link holds.
    let other_key = encode_b64(&[5u8; 32]);
    let wrong_key = ask(ADA, &other_key);
    for answer in [&unknown, &wrong_key] {
        assert_eq!(answer.0, listed.0);
        assert_eq!(answer.2, listed.2);
        assert_eq!(
            header(&answer.1, "cache-control"),
            header(&listed.1, "cache-control")
        );
        assert_eq!(
            header(&answer.1, "referrer-policy"),
            header(&listed.1, "referrer-policy")
        );
    }
    // Only the address on the link gets a mail.
    assert_eq!(smtp.wait_for(1).len(), 1);
    std::thread::sleep(Duration::from_millis(1500));
    let mails = smtp.mails();
    assert_eq!(mails.len(), 1);
    assert_eq!(mails[0].to, ADA_NORMAL);
    // A text without a normal form is 400 for every link alike.
    for bad in ["no-at-sign.example", "user@localhost", "zoë@example.com"] {
        assert_eq!(ask(bad, &key).0, 400, "{bad}");
    }
    assert_eq!(ask(ADA, "short").0, 400);
    // A link of anyone has no code route: the one answer of a link that does not open.
    let anyone = links::anyone_body(false, 3600);
    c.ok("POST", "/v1/account/links", Some(&a.token), Some(&anyone));
    let (status, _) = ask_code(&c, anyone["link_id"].as_str().unwrap(), ADA, &key);
    assert_eq!(status, 404);
}

#[test]
fn five_wrong_codes_end_the_code() {
    let smtp = fake_smtp::start(false);
    let c = start_with_mail(&smtp, |_| {});
    let a = c.account("Ada");
    let (link_id, key) = email_link(&c, &a, &[ADA_NORMAL]);
    assert_eq!(ask_code(&c, &link_id, ADA, &key).0, 200);
    let code = smtp.wait_for(1)[0].code();
    let wrong = other_code(&code);
    for _ in 0..5 {
        let (status, answer) = open_with(&c, &link_id, ADA, &key, &wrong, false);
        assert_eq!(
            (status, answer["error"]["code"].as_str()),
            (403, Some("code_invalid"))
        );
    }
    // The fifth wrong try ended it: the right code does not open any more.
    let (status, answer) = open_with(&c, &link_id, ADA, &key, &code, false);
    assert_eq!(
        (status, answer["error"]["code"].as_str()),
        (403, Some("code_invalid"))
    );
    // Under five tries a new code is usable. The pair has 6 wrong tries now (the right
    // code of an ended code counts too); 3 more leave it under its 10.
    assert_eq!(ask_code(&c, &link_id, ADA, &key).0, 200);
    let code = smtp.wait_for(2)[1].code();
    let wrong = other_code(&code);
    for _ in 0..3 {
        assert_eq!(open_with(&c, &link_id, ADA, &key, &wrong, false).0, 403);
    }
    let opened = open_with(&c, &link_id, ADA, &key, &code, false);
    assert_eq!(opened.0, 200, "{}", opened.1);
    assert_eq!(
        opened.1["result"]["sealed"],
        vector("anyone")["sealed_b64u"]
    );
    // An expired code does not open.
    assert_eq!(ask_code(&c, &link_id, ADA, &key).0, 200);
    let code = smtp.wait_for(3)[2].code();
    let conn = rusqlite::Connection::open(c.relay.config.links_path()).unwrap();
    conn.execute_batch(&format!("PRAGMA key = '{VAULT_KEY}';"))
        .unwrap();
    conn.execute(
        "UPDATE link_code SET expires_at = ?1",
        [i64::try_from(now()).unwrap()],
    )
    .unwrap();
    assert_eq!(open_with(&c, &link_id, ADA, &key, &code, false).0, 403);
    // links.db keeps a 32-byte hash of each code, never the code.
    let hashes: Vec<Vec<u8>> = conn
        .prepare("SELECT code_hash FROM link_code")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(hashes.iter().all(|hash| hash.len() == 32));
    assert!(
        !hashes
            .iter()
            .any(|hash| hash.windows(6).any(|w| w == code.as_bytes()))
    );
}

#[test]
fn the_mail_caps_hold() {
    let smtp = fake_smtp::start(false);
    let c = start_with_mail(&smtp, |cfg| {
        cfg.connect.links = LinkSettings {
            mail_per_link: 4,
            ..LinkSettings::default()
        };
    });
    let a = c.account("Ada");
    // The code requests of a link (4 an hour here): every request counts, for an address
    // on the link and one that is not, before any look at the address.
    let (link_id, key) = email_link(&c, &a, &[ADA_NORMAL]);
    for email in [ADA, "nobody@example.com", "third@example.com", ADA] {
        assert_eq!(ask_code(&c, &link_id, email, &key).0, 200, "{email}");
    }
    for email in [ADA, "nobody@example.com"] {
        let (status, headers, text) = call_with_headers(
            &c.relay.url,
            EDGE_SECRET,
            "POST",
            &format!("/v1/links/{link_id}/code"),
            &[],
            Some(&json!({"email": email, "address_key": key})),
        );
        assert_eq!(status, 429, "{email}: {text}");
        let retry: u64 = header(&headers, "retry-after").unwrap().parse().unwrap();
        assert!((1..=3600).contains(&retry), "{retry}");
    }
    // Another link has its own count.
    let (other, other_key) = email_link(&c, &a, &[ADA_NORMAL]);
    assert_eq!(ask_code(&c, &other, ADA, &other_key).0, 200);
    assert_eq!(smtp.wait_for(3).len(), 3);
}

/// The daily caps of code mails: each account's (counted first), then the relay's. They
/// count the mails that the mail thread made; above a cap every code request of that
/// account's links gets the same 503 `mail_unavailable`, whatever the address.
#[test]
fn the_daily_caps_of_an_account_and_of_the_relay_hold() {
    let smtp = fake_smtp::start(false);
    let c = start_with_mail(&smtp, |cfg| {
        cfg.connect.links = LinkSettings {
            mail_per_account: 2,
            mail_per_day: 3,
            ..LinkSettings::default()
        };
    });
    let a = c.account("Ada");
    let b = c.account("Bea");
    let d = c.account("Dan");
    let (a_link, a_key) = email_link(&c, &a, &[ADA_NORMAL]);
    // A request for an address that is not on the link makes no mail and counts nothing.
    for _ in 0..3 {
        assert_eq!(ask_code(&c, &a_link, "nobody@example.com", &a_key).0, 200);
    }
    for count in 1..=2 {
        assert_eq!(ask_code(&c, &a_link, ADA, &a_key).0, 200);
        assert_eq!(smtp.wait_for(count).len(), count);
    }
    std::thread::sleep(Duration::from_millis(300));
    // The account's cap (2): the same 503 for every address of its links.
    let refusals: Vec<(u16, Value)> = [ADA, "nobody@example.com", "other@example.com"]
        .iter()
        .map(|email| ask_code(&c, &a_link, email, &a_key))
        .collect();
    for refusal in &refusals {
        assert_eq!(refusal, &refusals[0]);
    }
    assert_eq!(refusals[0].0, 503);
    assert_eq!(refusals[0].1["error"]["code"], "mail_unavailable");
    let (_, headers, _) = call_with_headers(
        &c.relay.url,
        EDGE_SECRET,
        "POST",
        &format!("/v1/links/{a_link}/code"),
        &[],
        Some(&json!({"email": ADA, "address_key": a_key})),
    );
    let retry: u64 = header(&headers, "retry-after").unwrap().parse().unwrap();
    assert!((1..=86_400).contains(&retry));
    // Another account has its own cap, inside the relay's (3 here).
    let (b_link, b_key) = email_link(&c, &b, &["bea@example.com"]);
    assert_eq!(ask_code(&c, &b_link, "bea@example.com", &b_key).0, 200);
    assert_eq!(smtp.wait_for(3).len(), 3);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(ask_code(&c, &b_link, "bea@example.com", &b_key).0, 503);
    let (d_link, d_key) = email_link(&c, &d, &["dan@example.com"]);
    assert_eq!(ask_code(&c, &d_link, "dan@example.com", &d_key).0, 503);
    std::thread::sleep(Duration::from_millis(1000));
    assert_eq!(smtp.mails().len(), 3);
}

/// A link and address get at most 5 codes in a UTC day and 10 wrong tries over the whole
/// life of the link; after them no code goes to that address, and the answer does not
/// change.
#[test]
fn a_link_and_address_get_five_codes_a_day_and_ten_wrong_tries() {
    let smtp = fake_smtp::start(false);
    let c = start_with_mail(&smtp, |_| {});
    let a = c.account("Ada");
    let (link_id, key) = email_link(&c, &a, &[ADA_NORMAL]);
    for _ in 0..6 {
        assert_eq!(
            ask_code(&c, &link_id, ADA, &key).1["result"],
            json!({"expires_in": 900})
        );
    }
    let mails = smtp.wait_for(5);
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(smtp.mails().len(), 5, "{mails:?}");
    // The fifth code still opens.
    let last = smtp.mails()[4].code();
    assert_eq!(open_with(&c, &link_id, ADA, &key, &last, false).0, 200);

    let (link_id, key) = email_link(&c, &a, &[ADA_NORMAL]);
    let before = smtp.mails().len();
    for round in 0..2 {
        assert_eq!(ask_code(&c, &link_id, ADA, &key).0, 200);
        let code = smtp.wait_for(before + round + 1)[before + round].code();
        let wrong = other_code(&code);
        for _ in 0..5 {
            assert_eq!(open_with(&c, &link_id, ADA, &key, &wrong, false).0, 403);
        }
        assert_eq!(open_with(&c, &link_id, ADA, &key, &code, false).0, 403);
    }
    // Ten wrong tries: the answer stays the same, and no code goes any more.
    assert_eq!(
        ask_code(&c, &link_id, ADA, &key).1["result"],
        json!({"expires_in": 900})
    );
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(smtp.mails().len(), before + 2);
}

/// The code route answers before it looks the address up: with the mail thread held, an
/// address on the link and one that is not get the same answer, and there is no code row
/// and no mail yet; the lookup comes later.
#[test]
fn the_code_route_answers_before_the_lookup() {
    let smtp = fake_smtp::start(false);
    let c = start_with_mail(&smtp, |_| {});
    let a = c.account("Ada");
    let (link_id, key) = email_link(&c, &a, &[ADA_NORMAL]);
    let links = c.relay.hub().links().unwrap().clone();
    links.hold_jobs(true);
    let on_link = ask_code(&c, &link_id, ADA, &key);
    let not_on_link = ask_code(&c, &link_id, "nobody@example.com", &key);
    assert_eq!(on_link, not_on_link);
    assert_eq!(on_link.0, 200);
    assert_eq!(links.jobs_waiting(), 2);
    assert_eq!(links.outbox_len().unwrap(), 0);
    let conn = rusqlite::Connection::open(c.relay.config.links_path()).unwrap();
    conn.execute_batch(&format!("PRAGMA key = '{VAULT_KEY}';"))
        .unwrap();
    conn.busy_timeout(Duration::from_secs(10)).unwrap();
    let codes: i64 = conn
        .query_row("SELECT count(*) FROM link_code", [], |row| row.get(0))
        .unwrap();
    assert_eq!(codes, 0);
    std::thread::sleep(Duration::from_millis(1200));
    assert!(smtp.mails().is_empty());
    links.hold_jobs(false);
    let mails = smtp.wait_for(1);
    assert_eq!(mails.len(), 1);
    assert_eq!(mails[0].to, ADA_NORMAL);
    assert_eq!(links.jobs_waiting(), 0);
    // links.db never holds the address key.
    let key_bytes = apassy_relay::hostkeys::decode_b64(&key, 32).unwrap();
    let file = std::fs::read(c.relay.config.links_path()).unwrap();
    assert!(!file.windows(32).any(|w| w == key_bytes.as_slice()));
    let tables: Vec<String> = conn
        .prepare("SELECT sql FROM sqlite_master WHERE sql IS NOT NULL")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(
        !tables.iter().any(|sql| sql.contains("address_key")),
        "{tables:?}"
    );
}

#[test]
fn without_smtp_an_email_link_is_refused() {
    let c = connect::start();
    let a = c.account("Ada");
    assert_eq!(
        c.ok("GET", "/v1/account/links", Some(&a.token), None)["mail"],
        false
    );
    let body = vector_body("one_time_emails", 3600);
    let (status, answer) = c.call("POST", "/v1/account/links", Some(&a.token), Some(&body));
    assert_eq!(
        (status, answer["error"]["code"].as_str()),
        (503, Some("mail_unavailable"))
    );
    // Nothing was kept, and a link for anyone still works.
    assert_eq!(
        c.ok("GET", "/v1/account/links", Some(&a.token), None)["links"],
        json!([])
    );
    c.ok(
        "POST",
        "/v1/account/links",
        Some(&a.token),
        Some(&links::anyone_body(false, 3600)),
    );
    // No link for e-mail addresses exists here: a code request finds no link.
    let (status, answer) = ask_code(
        &c,
        body["link_id"].as_str().unwrap(),
        ADA,
        vector("one_time_emails")["address_key_b64u"]
            .as_str()
            .unwrap(),
    );
    assert_eq!(
        (status, answer["error"]["code"].as_str()),
        (404, Some("not_found"))
    );
}

#[test]
fn a_refused_mail_waits_and_goes_after_an_hour() {
    let smtp = fake_smtp::start(false);
    smtp.refuse.store(true, std::sync::atomic::Ordering::SeqCst);
    let c = start_with_mail(&smtp, |_| {});
    let a = c.account("Ada");
    let (link_id, key) = email_link(&c, &a, &[ADA_NORMAL]);
    assert_eq!(ask_code(&c, &link_id, ADA, &key).0, 200);
    let links = c.relay.hub().links().unwrap().clone();
    let deadline = Instant::now() + Duration::from_secs(15);
    while smtp.sessions.load(std::sync::atomic::Ordering::SeqCst) == 0 && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(50));
    }
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(links.outbox_len().unwrap(), 1, "a refused mail waits");
    assert!(smtp.mails().is_empty());
    // The server takes it again: the next try sends it.
    smtp.refuse
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let conn = rusqlite::Connection::open(c.relay.config.links_path()).unwrap();
    conn.execute_batch(&format!("PRAGMA key = '{VAULT_KEY}';"))
        .unwrap();
    conn.busy_timeout(Duration::from_secs(10)).unwrap();
    conn.execute_batch("UPDATE mail_outbox SET next_at = 0;")
        .unwrap();
    assert_eq!(smtp.wait_for(1).len(), 1);
    assert_eq!(outbox_after_send(&links), 0);
    // A mail that is not taken within an hour is deleted.
    smtp.refuse.store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(ask_code(&c, &link_id, ADA, &key).0, 200);
    // The mail thread writes the outbox row after the answer.
    let deadline = Instant::now() + Duration::from_secs(15);
    while links.outbox_len().unwrap() == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(links.outbox_len().unwrap(), 1);
    conn.execute(
        "UPDATE mail_outbox SET created_at = ?1, next_at = ?2",
        [
            i64::try_from(now() - 3601).unwrap(),
            i64::try_from(now() + 3600).unwrap(),
        ],
    )
    .unwrap();
    let hub = c.relay.hub();
    links.prune(&hub.directory.store, now()).unwrap();
    assert_eq!(links.outbox_len().unwrap(), 0);
}

#[test]
fn the_mail_settings_are_checked_at_start() {
    let dir = tempfile::tempdir().unwrap();
    let password = dir.path().join("smtp-password");
    std::fs::write(&password, "synthetic-password\n").unwrap();
    let password = password.to_string_lossy().into_owned();
    let base: Vec<(&str, String)> = vec![
        (
            "APASSY_RELAY_DATA",
            dir.path().join("data").to_string_lossy().into_owned(),
        ),
        (
            "APASSY_RELAY_PUBLIC_URL",
            "https://connect.example.test".into(),
        ),
        ("APASSY_RELAY_EDGE_SECRET", EDGE_SECRET.into()),
        ("APASSY_RELAY_KEY", VAULT_KEY.into()),
        ("APASSY_RELAY_CONNECT_ACCOUNTS", "1".into()),
    ];
    let with = |extra: &[(&'static str, &str)]| {
        let mut pairs = base.clone();
        pairs.extend(extra.iter().map(|(key, value)| (*key, value.to_string())));
        apassy_relay::config::RelayConfig::from_lookup(move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.clone())
        })
    };
    assert!(with(&[]).unwrap().connect.mail.is_none());
    let full = with(&[
        ("APASSY_CONNECT_SMTP_HOST", "Mail.Example.Test"),
        ("APASSY_CONNECT_SMTP_USER", "connect@apassy.wyderka.cc"),
        ("APASSY_CONNECT_SMTP_PASSWORD_FILE", &password),
        ("APASSY_CONNECT_SMTP_FROM", "connect@apassy.wyderka.cc"),
    ])
    .unwrap();
    let mail: MailSettings = full.connect.mail.unwrap();
    assert_eq!(mail.host, "mail.example.test");
    assert_eq!(mail.port, 587);
    assert!(!mail.implicit_tls());
    assert_eq!(mail.from, "connect@apassy.wyderka.cc");
    let (user, secret) = mail.auth.as_ref().unwrap();
    assert_eq!(user, "connect@apassy.wyderka.cc");
    assert_eq!(secret.expose(), "synthetic-password");
    assert!(!format!("{mail:?}").contains("synthetic-password"));
    assert!(
        with(&[
            ("APASSY_CONNECT_SMTP_HOST", "mail.example.test"),
            ("APASSY_CONNECT_SMTP_PORT", "465"),
            ("APASSY_CONNECT_SMTP_FROM", "connect@apassy.wyderka.cc"),
        ])
        .unwrap()
        .connect
        .mail
        .unwrap()
        .implicit_tls()
    );
    for refused in [
        // No sender: there is no default.
        vec![("APASSY_CONNECT_SMTP_HOST", "mail.example.test")],
        // A setting without the host.
        vec![("APASSY_CONNECT_SMTP_FROM", "connect@apassy.wyderka.cc")],
        // A user without the password, or the other way round.
        vec![
            ("APASSY_CONNECT_SMTP_HOST", "mail.example.test"),
            ("APASSY_CONNECT_SMTP_FROM", "connect@apassy.wyderka.cc"),
            ("APASSY_CONNECT_SMTP_USER", "connect@apassy.wyderka.cc"),
        ],
        // A sender that is not one address in its normal form.
        vec![
            ("APASSY_CONNECT_SMTP_HOST", "mail.example.test"),
            (
                "APASSY_CONNECT_SMTP_FROM",
                "Apassy <connect@apassy.wyderka.cc>",
            ),
        ],
        vec![
            ("APASSY_CONNECT_SMTP_HOST", "mail example"),
            ("APASSY_CONNECT_SMTP_FROM", "connect@apassy.wyderka.cc"),
        ],
        vec![
            ("APASSY_CONNECT_SMTP_HOST", "mail.example.test"),
            ("APASSY_CONNECT_SMTP_FROM", "connect@apassy.wyderka.cc"),
            ("APASSY_CONNECT_SMTP_PORT", "0"),
        ],
        vec![("APASSY_CONNECT_MAIL_PER_LINK", "0")],
    ] {
        assert!(with(&refused).is_err(), "{refused:?}");
    }
}

// ---- No log line holds an address or a code. ----

/// A server that greets every connection with 554, so each mail fails at its first step
/// and the relay logs the failure.
fn refusing_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut stream = stream;
            let _ = std::io::Write::write_all(&mut stream, b"554 no service here\r\n");
        }
    });
    port
}

/// A new account on the relay at `url` with the origin `origin`, signed in.
fn binary_account(url: &str, origin: &str) -> String {
    let key = DeviceKey::generate().unwrap();
    let account = connect::new_account_id();
    let public_key = key.public_key_b64();
    let recovery_key = device::RecoveryKey::from_code(&[9u8; 16])
        .unwrap()
        .public_key_b64();
    let signature = key
        .sign(&device::account_message(origin, &public_key, &recovery_key))
        .unwrap();
    let device_name = "Ada's Mac";
    let statement = key
        .sign(&device::account_list_message(
            origin,
            &account,
            1,
            device::LIST_NONE,
            "root",
            &public_key,
            device::LIST_NONE,
            device_name,
            &public_key,
        ))
        .unwrap();
    let call = |method: &str, path: &str, token: Option<&str>, body: &Value| {
        let (status, value) =
            relay::call_url(url, Some(EDGE_SECRET), method, path, token, Some(body));
        assert_eq!(status, 200, "{path}: {value}");
        value["result"].clone()
    };
    call(
        "POST",
        "/v1/account",
        None,
        &json!({"account_id": account, "name": "Ada", "device_name": device_name,
                "platform": "mac", "public_key": public_key, "recovery_key": recovery_key,
                "signature": encode_b64(&signature), "statement": encode_b64(&statement)}),
    );
    let challenge = call(
        "POST",
        "/v1/account/challenge",
        None,
        &json!({"account_id": account, "public_key": public_key}),
    );
    let nonce = challenge["nonce"].as_str().unwrap();
    let message = device::account_sign_in_message(origin, &account, &public_key, nonce);
    let granted = call(
        "POST",
        "/v1/account/token",
        None,
        &json!({"account_id": account, "public_key": public_key, "nonce": nonce,
                "signature": encode_b64(&key.sign(&message).unwrap())}),
    );
    granted["token"].as_str().unwrap().to_string()
}

#[test]
fn no_log_line_holds_an_address() {
    let dir = tempfile::tempdir().unwrap();
    let smtp_port = refusing_server();
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let listen = format!("127.0.0.1:{port}");
    let origin = format!("http://{listen}");
    let relay = |args: &[&str]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_apassy-relay"));
        command
            .env_clear()
            .env("APASSY_RELAY_DATA", dir.path().join("data"))
            .env("APASSY_RELAY_LISTEN", &listen)
            .env("APASSY_RELAY_PUBLIC_URL", &origin)
            .env("APASSY_RELAY_EDGE_SECRET", EDGE_SECRET)
            .env("APASSY_RELAY_KEY", VAULT_KEY)
            .env("APASSY_RELAY_CONNECT_ACCOUNTS", "1")
            .env("APASSY_CONNECT_SMTP_HOST", "localhost")
            .env("APASSY_CONNECT_SMTP_PORT", smtp_port.to_string())
            .env("APASSY_CONNECT_SMTP_FROM", "connect@apassy.test")
            .args(args);
        command
    };
    let init = relay(&["init", "--team", "Acme", "--owner", "olga"])
        .output()
        .unwrap();
    assert_eq!(init.status.code(), Some(0));
    let mut child = relay(&[])
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while ureq::get(&format!("{origin}/healthz")).call().is_err() {
        assert!(Instant::now() < deadline, "the relay did not start");
        std::thread::sleep(Duration::from_millis(50));
    }
    let token = binary_account(&origin, &origin);
    let mut body = vector_body("one_time_emails", 3600);
    body["one_time"] = json!(false);
    let link_id = body["link_id"].as_str().unwrap().to_string();
    let key = vector("one_time_emails")["address_key_b64u"]
        .as_str()
        .unwrap()
        .to_string();
    let call = |method: &str, path: &str, token: Option<&str>, body: &Value| {
        relay::call_url(&origin, Some(EDGE_SECRET), method, path, token, Some(body))
    };
    assert_eq!(
        call("POST", "/v1/account/links", Some(&token), &body).0,
        200
    );
    for email in [ADA, "grace@BÜCHER.example", "nobody@example.com"] {
        let (status, _) = call(
            "POST",
            &format!("/v1/links/{link_id}/code"),
            None,
            &json!({"email": email, "address_key": key}),
        );
        assert_eq!(status, 200, "{email}");
    }
    for code in ["12345678", "87654321"] {
        call(
            "POST",
            &format!("/v1/links/{link_id}/open"),
            None,
            &json!({"confirm": true, "email": ADA, "address_key": key, "code": code}),
        );
    }
    // The codes in the outbox, for the check below.
    let conn = rusqlite::Connection::open(dir.path().join("data/links.db")).unwrap();
    conn.execute_batch(&format!("PRAGMA key = '{VAULT_KEY}';"))
        .unwrap();
    conn.busy_timeout(Duration::from_secs(10)).unwrap();
    let texts: Vec<String> = conn
        .prepare("SELECT text FROM mail_outbox")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(texts.len(), 2, "two addresses are on the link");
    let codes: Vec<String> = texts
        .iter()
        .map(|text| {
            let at = text.find("item: ").unwrap() + 6;
            text[at..at + 8].to_string()
        })
        .collect();
    // Let the mail thread fail a first time for both mails.
    std::thread::sleep(Duration::from_secs(3));
    child.kill().unwrap();
    child.wait().unwrap();
    let mut log = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut log)
        .unwrap();
    assert!(
        log.contains("a code mail was not taken by the SMTP server at step greeting (554)"),
        "the failure is logged: {log}"
    );
    let lower = log.to_lowercase();
    for secret in [
        ADA_NORMAL,
        "ada.lovelace",
        "lovelace",
        "grace",
        "xn--bcher-kva",
        "bücher",
        "nobody",
        "example.com",
        &link_id,
        &key,
    ]
    .iter()
    .map(|text| text.to_lowercase())
    .chain(codes.iter().cloned())
    {
        assert!(!lower.contains(&secret), "the log holds {secret}: {log}");
    }
}
