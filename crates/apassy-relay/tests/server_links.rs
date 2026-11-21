//! Public links of Apassy Connect on the relay (connect-share-v1, docs/SPEC.md section 38):
//! creation, the list, the revoke, the open of each kind of link, the one refusal, the plan
//! limits, the deletion of an account, the backups, and the viewer page. Each test starts
//! its own relay on a free loopback port in a temporary directory, with the contract
//! vectors and synthetic values only. The code mail is in `server_mail.rs`.

#[path = "common/relay.rs"]
mod relay;

#[path = "common/fake_stripe.rs"]
mod fake_stripe;

#[path = "common/connect.rs"]
mod connect;

#[path = "common/links.rs"]
mod links;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use apassy_relay::api::PlanView;
use apassy_relay::config::LinkSettings;
use apassy_relay::error::RelayResult;
use apassy_relay::server::account::Plans;
use apassy_relay::server::store::Store;
use connect::{Connect, Dev, now};
use links::{anyone_body, call_with_headers, header, open_body, vector, vector_body};
use relay::{EDGE_SECRET, VAULT_KEY};
use serde_json::{Value, json};

// ---- Plans of the tests. ----

#[derive(Default)]
struct TestPlans(Mutex<HashMap<String, PlanView>>);

impl TestPlans {
    fn set(&self, account: &str, plan: &str) {
        self.0.lock().unwrap().insert(
            account.to_string(),
            PlanView {
                plan: Some(plan.to_string()),
                status: "active".into(),
                entitled: true,
                interval: Some("month".into()),
                quantity: Some(1),
                ..PlanView::none()
            },
        );
    }
}

impl Plans for TestPlans {
    fn plan(&self, _directory: &Store, account: &str, _now: u64) -> RelayResult<PlanView> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .get(account)
            .cloned()
            .unwrap_or_else(PlanView::none))
    }
}

// ---- Helpers. ----

fn create(c: &Connect, dev: &Dev, body: &Value) -> (u16, Value) {
    c.call("POST", "/v1/account/links", Some(&dev.token), Some(body))
}

fn create_ok(c: &Connect, dev: &Dev, body: &Value) -> Value {
    c.ok("POST", "/v1/account/links", Some(&dev.token), Some(body))
}

fn list(c: &Connect, dev: &Dev) -> Value {
    c.ok("GET", "/v1/account/links", Some(&dev.token), None)
}

fn open(c: &Connect, link_id: &str, body: &Value) -> (u16, Value) {
    c.call(
        "POST",
        &format!("/v1/links/{link_id}/open"),
        None,
        Some(body),
    )
}

/// Runs SQL on `links.db` while the relay runs (it is keyed with the master key here).
fn edit_links(c: &Connect, sql: &str) {
    let conn = rusqlite::Connection::open(c.relay.config.links_path()).unwrap();
    conn.execute_batch(&format!("PRAGMA key = '{VAULT_KEY}';"))
        .unwrap();
    conn.busy_timeout(std::time::Duration::from_secs(10))
        .unwrap();
    conn.execute_batch(sql).unwrap();
}

fn link_rows(c: &Connect) -> i64 {
    let conn = rusqlite::Connection::open(c.relay.config.links_path()).unwrap();
    conn.execute_batch(&format!("PRAGMA key = '{VAULT_KEY}';"))
        .unwrap();
    conn.query_row("SELECT count(*) FROM link", [], |row| row.get(0))
        .unwrap()
}

fn prune(c: &Connect) -> usize {
    let hub = c.relay.hub();
    hub.links()
        .unwrap()
        .prune(&hub.directory.store, now())
        .unwrap()
}

// ---- Tests. ----

#[test]
fn a_link_opens_until_its_expiry() {
    let c = connect::start();
    let a = c.account("Ada");
    let body = vector_body("anyone", 7 * 86_400);
    let link_id = body["link_id"].as_str().unwrap().to_string();
    let made = create_ok(&c, &a, &body);
    assert_eq!(made["link_id"], body["link_id"]);
    assert_eq!(made["state"], "live");
    assert_eq!(made["opens"], 0);
    assert_eq!(made["last_opened_at"], Value::Null);
    assert_eq!(made["addresses"], 0);
    // The same body again answers the stored view; another body with the id is 409.
    assert_eq!(create_ok(&c, &a, &body), made);
    let mut other = body.clone();
    other["one_time"] = json!(true);
    assert_eq!(create(&c, &a, &other).0, 409);
    let b = c.account("Bea");
    assert_eq!(create(&c, &b, &body).0, 409);

    // A link of anyone that is not one-time opens with one request, as often as asked.
    for round in 1..=2u64 {
        let opened = c.ok(
            "POST",
            &format!("/v1/links/{link_id}/open"),
            None,
            Some(&open_body(false)),
        );
        assert_eq!(opened["sealed"], body["sealed"]);
        assert_eq!(opened["expires_at"], body["expires_at"]);
        assert_eq!(opened["one_time"], false);
        assert_eq!(opened["access"], "anyone");
        let listed = list(&c, &a);
        assert_eq!(listed["links"][0]["opens"], round);
        assert!(listed["links"][0]["last_opened_at"].as_u64().is_some());
    }
    let listed = list(&c, &a);
    assert_eq!(listed["live"], 1);
    assert_eq!(listed["limit"], 25);
    assert_eq!(listed["mail"], false);

    // The answers carry no-store and no-referrer.
    let (status, headers, _) = call_with_headers(
        &c.relay.url,
        EDGE_SECRET,
        "POST",
        &format!("/v1/links/{link_id}/open"),
        &[],
        Some(&open_body(false)),
    );
    assert_eq!(status, 200);
    assert_eq!(header(&headers, "cache-control"), Some("no-store"));
    assert_eq!(header(&headers, "referrer-policy"), Some("no-referrer"));

    // At its expiry it does not open, leaves the list, and the pass deletes it.
    edit_links(
        &c,
        &format!(
            "UPDATE link SET expires_at = {} WHERE link_id = '{link_id}';",
            now() - 1
        ),
    );
    assert_eq!(open(&c, &link_id, &open_body(false)).0, 404);
    assert_eq!(list(&c, &a)["links"], json!([]));
    assert_eq!(list(&c, &a)["live"], 0);
    assert_eq!(prune(&c), 1);
    assert_eq!(link_rows(&c), 0);

    // The expiry of a new link: 10 minutes to 30 days.
    for expires_in in [0, 539, 2_592_061, 40 * 86_400] {
        let mut body = anyone_body(false, 0);
        body["expires_at"] = json!(now() + expires_in);
        assert_eq!(create(&c, &a, &body).0, 400, "{expires_in}");
    }
    for expires_in in [600, 2_592_000] {
        assert_eq!(create(&c, &a, &anyone_body(false, expires_in)).0, 200);
    }
}

#[test]
fn a_creation_is_strict() {
    let c = connect::start();
    let a = c.account("Ada");
    let good = anyone_body(false, 3600);
    let mut cases: Vec<Value> = Vec::new();
    for (field, value) in [
        ("link_id", json!("D4E59A0011F71C40FB1DFDB1A8446660")),
        ("link_id", json!("d4e59a0011f71c40fb1dfdb1a844666")),
        ("sealed", json!(links::sealed(0))),
        ("sealed", json!(links::sealed(33))),
        ("sealed", json!("not b64u!")),
        ("access", json!("everyone")),
        (
            "address_hashes",
            json!(["i2AM6gQVsjR_--a_6MLEn6sp6hO4wJpb80l1Jrpexe0"]),
        ),
    ] {
        let mut body = good.clone();
        body[field] = value;
        cases.push(body);
    }
    // A sealed form whose plaintext is not a multiple of 1 KiB.
    let mut odd = good.clone();
    odd["sealed"] = json!(apassy_relay::hostkeys::encode_b64(&[7u8; 12 + 1500 + 16]));
    cases.push(odd);
    // Unknown, missing, and duplicate fields.
    let mut unknown = good.clone();
    unknown["name"] = json!("Staging database");
    cases.push(unknown);
    let mut missing = good.clone();
    missing.as_object_mut().unwrap().remove("one_time");
    cases.push(missing);
    // A link of e-mail addresses with none, with 21, or with a hash twice.
    let hashes = links::hashes_for("one_time_emails", &["ada.lovelace@example.com"]);
    for addresses in [
        json!([]),
        json!(vec![hashes[0].clone(); 2]),
        json!(
            (0..21u8)
                .map(|n| apassy_relay::hostkeys::encode_b64(&[n; 32]))
                .collect::<Vec<_>>()
        ),
    ] {
        let mut body = good.clone();
        body["access"] = json!("emails");
        body["address_hashes"] = addresses;
        cases.push(body);
    }
    for body in &cases {
        let (status, answer) = create(&c, &a, body);
        assert_eq!(
            (status, answer["error"]["code"].as_str()),
            (400, Some("invalid_request")),
            "{body}"
        );
    }
    assert_eq!(list(&c, &a)["links"], json!([]));
    // Without a token: 401; the routes exist only with the account routes.
    assert_eq!(c.call("GET", "/v1/account/links", None, None).0, 401);
    assert_eq!(create(&c, &a, &good).0, 200);
}

#[test]
fn a_one_time_link_opens_once() {
    let c = connect::start();
    let a = c.account("Ada");
    let body = anyone_body(true, 3600);
    let link_id = body["link_id"].as_str().unwrap().to_string();
    create_ok(&c, &a, &body);
    // Without the reader's yes nothing changes.
    for _ in 0..3 {
        let asked = c.ok(
            "POST",
            &format!("/v1/links/{link_id}/open"),
            None,
            Some(&open_body(false)),
        );
        assert_eq!(asked["sealed"], Value::Null);
        assert_eq!(asked["one_time"], true);
    }
    assert_eq!(list(&c, &a)["links"][0]["opens"], 0);
    // Of two opens at the same moment one gets the sealed form, the other 404.
    let url = c.relay.url.clone();
    let answers: Vec<(u16, Value)> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let (url, link_id) = (url.clone(), link_id.clone());
                scope.spawn(move || {
                    relay::call_url(
                        &url,
                        Some(EDGE_SECRET),
                        "POST",
                        &format!("/v1/links/{link_id}/open"),
                        None,
                        Some(&open_body(true)),
                    )
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let opened: Vec<_> = answers
        .iter()
        .filter(|(status, _)| *status == 200)
        .collect();
    assert_eq!(opened.len(), 1, "{answers:?}");
    assert_eq!(opened[0].1["result"]["sealed"], body["sealed"]);
    assert!(answers.iter().any(|(status, _)| *status == 404));
    assert_eq!(open(&c, &link_id, &open_body(true)).0, 404);
    // The row stays for the list until its expiry, as opened, without its sealed form,
    // and it does not count.
    let listed = list(&c, &a);
    assert_eq!(listed["links"][0]["state"], "opened");
    assert_eq!(listed["links"][0]["opens"], 1);
    assert_eq!(listed["live"], 0);
    let conn = rusqlite::Connection::open(c.relay.config.links_path()).unwrap();
    conn.execute_batch(&format!("PRAGMA key = '{VAULT_KEY}';"))
        .unwrap();
    let sealed: Option<String> = conn
        .query_row(
            "SELECT sealed FROM link WHERE link_id = ?1",
            [&link_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(sealed, None);
}

#[test]
fn a_revoked_link_is_gone_at_once() {
    let c = connect::start();
    let a = c.account("Ada");
    let b = c.account("Bea");
    let body = anyone_body(false, 3600);
    let link_id = body["link_id"].as_str().unwrap().to_string();
    create_ok(&c, &a, &body);
    let path = format!("/v1/account/links/{link_id}");
    // Another account cannot revoke it: 404, and it still opens.
    c.fails("DELETE", &path, Some(&b.token), None, 404, "not_found");
    assert_eq!(open(&c, &link_id, &open_body(false)).0, 200);
    let revoked = c.ok("DELETE", &path, Some(&a.token), Some(&json!({})));
    assert_eq!(revoked, json!({"link_id": link_id, "deleted": true}));
    assert_eq!(open(&c, &link_id, &open_body(false)).0, 404);
    assert_eq!(link_rows(&c), 0);
    // A second revoke is the 404 that a client takes for a revoke that is done.
    c.fails("DELETE", &path, Some(&a.token), None, 404, "not_found");
    assert_eq!(list(&c, &a)["links"], json!([]));
    // A revoke takes no other body.
    let other = anyone_body(false, 3600);
    create_ok(&c, &a, &other);
    let path = format!("/v1/account/links/{}", other["link_id"].as_str().unwrap());
    c.fails(
        "DELETE",
        &path,
        Some(&a.token),
        Some(&json!({"why": "x"})),
        400,
        "invalid_request",
    );
    c.ok("DELETE", &path, Some(&a.token), None);
}

#[test]
fn open_gives_one_refusal_for_every_reason() {
    let c = connect::start();
    let a = c.account("Ada");
    let make = |one_time: bool| {
        let body = anyone_body(one_time, 3600);
        create_ok(&c, &a, &body);
        body["link_id"].as_str().unwrap().to_string()
    };
    let expired = make(false);
    edit_links(
        &c,
        &format!(
            "UPDATE link SET expires_at = {} WHERE link_id = '{expired}';",
            now() - 5
        ),
    );
    let revoked = make(false);
    c.ok(
        "DELETE",
        &format!("/v1/account/links/{revoked}"),
        Some(&a.token),
        None,
    );
    let opened = make(true);
    assert_eq!(open(&c, &opened, &open_body(true)).0, 200);
    let unknown = links::new_link_id();
    let mut answers = Vec::new();
    for link_id in [
        &expired,
        &revoked,
        &opened,
        &unknown,
        &"NOT-A-LINK".to_string(),
    ] {
        for (route, body) in [
            ("open", open_body(false)),
            ("open", open_body(true)),
            (
                "code",
                json!({"email": "ada@example.com", "address_key": vector("anyone")["address_key_b64u"]}),
            ),
        ] {
            let (status, headers, text) = call_with_headers(
                &c.relay.url,
                EDGE_SECRET,
                "POST",
                &format!("/v1/links/{link_id}/{route}"),
                &[],
                Some(&body),
            );
            assert_eq!(header(&headers, "referrer-policy"), Some("no-referrer"));
            answers.push((status, text));
        }
    }
    let first = answers[0].clone();
    assert_eq!(first.0, 404);
    assert!(answers.iter().all(|answer| *answer == first), "{answers:?}");
    // A live link: the form of the body first, and an Authorization header is 400.
    let live = make(false);
    for bad in [
        json!({"confirm": false}),
        json!({"confirm": false, "email": null, "address_key": null}),
        json!({"confirm": false, "email": "ada@example.com", "address_key": null, "code": null}),
        json!({"confirm": false, "email": null, "address_key": null, "code": null, "x": 1}),
        json!({"confirm": "yes", "email": null, "address_key": null, "code": null}),
    ] {
        assert_eq!(open(&c, &live, &bad).0, 400, "{bad}");
    }
    let (status, _) = relay::call_url(
        &c.relay.url,
        Some(EDGE_SECRET),
        "POST",
        &format!("/v1/links/{live}/open"),
        Some(&a.token),
        Some(&open_body(false)),
    );
    assert_eq!(status, 400);
    // A link of anyone takes no code.
    let key = vector("anyone")["address_key_b64u"].clone();
    let (status, _) = open(
        &c,
        &live,
        &json!({"confirm": false, "email": "ada@example.com", "address_key": key, "code": "123456"}),
    );
    assert_eq!(status, 400);
    // Only POST.
    assert_eq!(
        c.call("GET", &format!("/v1/links/{live}/open"), None, None)
            .0,
        405
    );
}

#[test]
fn the_link_count_stops_at_the_plan_limit() {
    let c = connect::start_with_config(|cfg| {
        cfg.connect.links = LinkSettings {
            links: 3,
            links_team: 5,
            ..LinkSettings::default()
        };
    });
    let plans = Arc::new(TestPlans::default());
    c.relay.hub().set_plans(plans.clone());
    let personal = c.account("Ada");
    plans.set(&personal.account, "personal");
    let team = c.account("Tom");
    plans.set(&team.account, "team");
    for (dev, limit) in [(&personal, 3u64), (&team, 5)] {
        let mut ids = Vec::new();
        for _ in 0..limit {
            let body = anyone_body(false, 3600);
            create_ok(&c, dev, &body);
            ids.push(body["link_id"].as_str().unwrap().to_string());
        }
        let over = anyone_body(false, 3600);
        let (status, answer) = create(&c, dev, &over);
        assert_eq!(
            (status, answer["error"]["code"].as_str()),
            (403, Some("link_limit")),
            "{answer}"
        );
        let message = answer["error"]["message"].as_str().unwrap();
        assert!(message.contains(&limit.to_string()), "{message}");
        // Nothing was kept.
        assert_eq!(
            open(&c, over["link_id"].as_str().unwrap(), &open_body(false)).0,
            404
        );
        let listed = list(&c, dev);
        assert_eq!(listed["live"], limit);
        assert_eq!(listed["limit"], limit);
        // A revoke makes room.
        c.ok(
            "DELETE",
            &format!("/v1/account/links/{}", ids[0]),
            Some(&dev.token),
            None,
        );
        create_ok(&c, dev, &over);
    }
    // An opened one-time link does not count.
    let personal_again = c.account("Bea");
    plans.set(&personal_again.account, "personal");
    for _ in 0..2 {
        create_ok(&c, &personal_again, &anyone_body(false, 3600));
    }
    let once = anyone_body(true, 3600);
    create_ok(&c, &personal_again, &once);
    assert_eq!(
        create(&c, &personal_again, &anyone_body(false, 3600)).0,
        403
    );
    assert_eq!(
        open(&c, once["link_id"].as_str().unwrap(), &open_body(true)).0,
        200
    );
    create_ok(&c, &personal_again, &anyone_body(false, 3600));
    // A Team plan that ends: the links stay until their expiry, and a new one counts
    // against the new limit.
    plans.0.lock().unwrap().remove(&team.account);
    assert_eq!(list(&c, &team)["live"], 5);
    assert_eq!(list(&c, &team)["limit"], 3);
    assert_eq!(create(&c, &team, &anyone_body(false, 3600)).0, 403);
}

#[test]
fn an_account_without_a_plan_makes_links_up_to_25() {
    let c = connect::start();
    let a = c.account("Ada");
    assert_eq!(
        c.ok("GET", "/v1/account/plan", Some(&a.token), None)["status"],
        "none"
    );
    for _ in 0..25 {
        create_ok(&c, &a, &anyone_body(false, 3600));
    }
    let (status, answer) = create(&c, &a, &anyone_body(false, 3600));
    assert_eq!(
        (status, answer["error"]["code"].as_str()),
        (403, Some("link_limit"))
    );
    // The refusal names the limit and never a price or a purchase.
    let message = answer["error"]["message"].as_str().unwrap().to_lowercase();
    assert!(message.contains("25"), "{message}");
    for word in ["€", "$", "price", "buy", "upgrade", "plan", "subscribe"] {
        assert!(!message.contains(word), "{message}");
    }
    let listed = list(&c, &a);
    assert_eq!(listed["live"], 25);
    assert_eq!(listed["links"].as_array().unwrap().len(), 25);
}

#[test]
fn a_deleted_account_takes_its_links() {
    let c = connect::start();
    let a = c.account("Ada");
    let b = c.account("Bea");
    let mut ids = Vec::new();
    for one_time in [false, true] {
        let body = anyone_body(one_time, 3600);
        create_ok(&c, &a, &body);
        ids.push(body["link_id"].as_str().unwrap().to_string());
    }
    let kept = anyone_body(false, 3600);
    create_ok(&c, &b, &kept);
    let hub = c.relay.hub();
    assert_eq!(hub.links().unwrap().ids_of(&a.account).unwrap().len(), 2);
    c.ok("DELETE", "/v1/account", Some(&a.token), Some(&json!({})));
    assert!(hub.links().unwrap().ids_of(&a.account).unwrap().is_empty());
    for id in &ids {
        assert_eq!(open(&c, id, &open_body(true)).0, 404);
    }
    // The other account keeps its link.
    assert_eq!(
        open(&c, kept["link_id"].as_str().unwrap(), &open_body(false)).0,
        200
    );
    // A link whose account is gone from relay.db, as after a deletion whose second step
    // did not run, does not open, and the maintenance pass deletes it.
    let orphan = links::new_link_id();
    edit_links(
        &c,
        &format!(
            "INSERT INTO link (link_id, account_id, created_at, expires_at, one_time, access, addresses, sealed, create_hash) \
             VALUES ('{orphan}', 'acc_aaaaaaaaaa', {n}, {e}, 0, 'anyone', 0, '{s}', x'00');",
            n = now(),
            e = now() + 3600,
            s = links::sealed(1),
        ),
    );
    assert_eq!(open(&c, &orphan, &open_body(false)).0, 404);
    assert_eq!(prune(&c), 1);
    assert_eq!(link_rows(&c), 1);
}

#[test]
fn the_backup_holds_no_link() {
    let c = connect::start();
    let a = c.account("Ada");
    let body = vector_body("anyone", 3600);
    create_ok(&c, &a, &body);
    let sealed = body["sealed"].as_str().unwrap().to_string();
    let link_id = body["link_id"].as_str().unwrap().to_string();
    assert!(c.relay.config.links_path().exists());
    // `admin backup` while the relay runs.
    let manifest = c.relay.hub().backup(now()).unwrap();
    let folder = std::path::PathBuf::from(manifest["dir"].as_str().unwrap());
    let text = manifest.to_string();
    assert!(!text.contains("links.db"), "{text}");
    assert_no_link_in(&folder, &sealed, &link_id);
    // The stopped backup of the whole data directory.
    let Connect { relay, .. } = c;
    let (config, _dir) = relay.stop_keep();
    let stopped = apassy_relay::server::cutover::stopped_backup(&config, now() + 1).unwrap();
    let text = stopped.to_string();
    assert!(!text.contains("links.db"), "{text}");
    assert_no_link_in(
        &std::path::PathBuf::from(stopped["dir"].as_str().unwrap()),
        &sealed,
        &link_id,
    );
    assert!(config.links_path().exists());
}

/// No file under `folder` is `links.db` or holds the sealed form or the link id. The
/// files of the relay are encrypted here, so the names are what can be checked in them;
/// the manifests list every file.
fn assert_no_link_in(folder: &std::path::Path, sealed: &str, link_id: &str) {
    let mut stack = vec![folder.to_path_buf()];
    let mut files = 0;
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            files += 1;
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            assert!(!name.starts_with("links"), "{}", path.display());
            let bytes = std::fs::read(&path).unwrap();
            let text = String::from_utf8_lossy(&bytes);
            assert!(!text.contains(&sealed[..64]), "{}", path.display());
            assert!(!text.contains(link_id), "{}", path.display());
        }
    }
    assert!(files >= 2, "the backup holds relay.db and its manifest");
}

#[test]
fn the_viewer_is_served_with_its_headers() {
    let c = connect::start();
    for (path, kind, file) in [
        ("/s", "text/html", "share.html"),
        ("/share.js", "text/javascript", "share.js"),
        ("/share.css", "text/css", "share.css"),
    ] {
        let (status, headers, text) =
            call_with_headers(&c.relay.url, EDGE_SECRET, "GET", path, &[], None);
        assert_eq!(status, 200, "{path}");
        let expected = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("deploy/worker/public")
                .join(file),
        )
        .unwrap();
        assert_eq!(text, expected, "{path}: the Worker's file");
        assert!(header(&headers, "content-type").unwrap().starts_with(kind));
        for (name, value) in [
            (
                "content-security-policy",
                "default-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types 'none'",
            ),
            ("cache-control", "no-store"),
            ("referrer-policy", "no-referrer"),
            ("x-robots-tag", "noindex, nofollow"),
            ("x-content-type-options", "nosniff"),
            ("x-frame-options", "DENY"),
            ("cross-origin-opener-policy", "same-origin"),
        ] {
            assert_eq!(header(&headers, name), Some(value), "{path} {name}");
        }
        let (status, headers, _) = call_with_headers(
            &c.relay.url,
            EDGE_SECRET,
            "POST",
            path,
            &[],
            Some(&json!({})),
        );
        assert_eq!(status, 405, "{path}");
        assert_eq!(header(&headers, "cache-control"), Some("no-store"));
    }
    // The relay never redirects `/s`: a query is the same page, `/s/` is no page.
    let (status, headers, _) =
        call_with_headers(&c.relay.url, EDGE_SECRET, "GET", "/s?x=1", &[], None);
    assert_eq!(status, 200);
    assert_eq!(header(&headers, "location"), None);
    let (status, headers, _) =
        call_with_headers(&c.relay.url, EDGE_SECRET, "GET", "/s/", &[], None);
    assert_eq!(status, 404);
    assert_eq!(header(&headers, "location"), None);
    // A relay without the account routes has no viewer and no link route.
    let plain = relay::start(apassy_relay::config::UpstreamOptions::default());
    assert_eq!(plain.call("GET", "/s", None, None).0, 404);
    assert_eq!(
        plain
            .call(
                "POST",
                "/v1/links/d4e59a0011f71c40fb1dfdb1a8446660/open",
                None,
                Some(&open_body(false))
            )
            .0,
        404
    );
    assert!(!plain.config.links_path().exists());
}

#[test]
fn a_revoked_id_cannot_be_registered_again() {
    let c = connect::start();
    let a = c.account("Ada");
    let b = c.account("Bea");
    // Revoked.
    let body = anyone_body(false, 3600);
    let link_id = body["link_id"].as_str().unwrap().to_string();
    create_ok(&c, &a, &body);
    c.ok(
        "DELETE",
        &format!("/v1/account/links/{link_id}"),
        Some(&a.token),
        None,
    );
    for dev in [&a, &b] {
        let (status, answer) = create(&c, dev, &body);
        assert_eq!(
            (status, answer["error"]["code"].as_str()),
            (409, Some("conflict"))
        );
    }
    assert_eq!(open(&c, &link_id, &open_body(false)).0, 404);
    // Expired and pruned.
    let body = anyone_body(false, 3600);
    let expired = body["link_id"].as_str().unwrap().to_string();
    create_ok(&c, &a, &body);
    edit_links(
        &c,
        &format!(
            "UPDATE link SET expires_at = {} WHERE link_id = '{expired}';",
            now() - 1
        ),
    );
    assert_eq!(prune(&c), 1);
    let mut again = body.clone();
    again["expires_at"] = json!(now() + 3600);
    assert_eq!(create(&c, &a, &again).0, 409);
    // Of a deleted account.
    let body = anyone_body(false, 3600);
    create_ok(&c, &b, &body);
    c.ok("DELETE", "/v1/account", Some(&b.token), Some(&json!({})));
    assert_eq!(create(&c, &a, &body).0, 409);
    // The tombstone holds the id only, no account; an opened one-time link still answers
    // a retry of its creation with its stored view.
    let conn = rusqlite::Connection::open(c.relay.config.links_path()).unwrap();
    conn.execute_batch(&format!("PRAGMA key = '{VAULT_KEY}';"))
        .unwrap();
    let columns: Vec<String> = conn
        .prepare("SELECT name FROM pragma_table_info('link_id_used')")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(columns, vec!["link_id".to_string()]);
    let used: i64 = conn
        .query_row("SELECT count(*) FROM link_id_used", [], |row| row.get(0))
        .unwrap();
    assert_eq!(used, 3);
    let once = anyone_body(true, 3600);
    create_ok(&c, &a, &once);
    assert_eq!(
        open(&c, once["link_id"].as_str().unwrap(), &open_body(true)).0,
        200
    );
    assert_eq!(create_ok(&c, &a, &once)["state"], "opened");
}

#[test]
fn a_service_worker_script_request_is_refused() {
    let c = connect::start();
    let a = c.account("Ada");
    let body = anyone_body(false, 3600);
    create_ok(&c, &a, &body);
    let open_path = format!("/v1/links/{}/open", body["link_id"].as_str().unwrap());
    for (method, path) in [
        ("GET", "/s"),
        ("GET", "/share.js"),
        ("GET", "/healthz"),
        ("GET", "/v1/account/links"),
        ("POST", open_path.as_str()),
        ("GET", "/no/such/path"),
    ] {
        for value in ["script", "Script"] {
            let (status, _, text) = call_with_headers(
                &c.relay.url,
                EDGE_SECRET,
                method,
                path,
                &[("Service-Worker", value)],
                (method == "POST").then(|| open_body(false)).as_ref(),
            );
            assert_eq!(status, 400, "{method} {path}: {text}");
        }
    }
    // The page itself, without the header, is served.
    let (status, _, _) =
        call_with_headers(&c.relay.url, EDGE_SECRET, "GET", "/share.js", &[], None);
    assert_eq!(status, 200);
}

#[test]
fn a_link_needs_an_https_origin() {
    let c = connect::start_with_config(|cfg| {
        cfg.public_url = "http://relay.example.test".to_string();
    });
    let a = c.account("Ada");
    let (status, answer) = create(&c, &a, &anyone_body(false, 3600));
    assert_eq!(
        (status, answer["error"]["code"].as_str()),
        (403, Some("forbidden"))
    );
    assert_eq!(list(&c, &a)["links"], json!([]));
}

/// Every address of the contract vectors: the relay's normal form, and for the addresses
/// of each link the hash under its address key.
#[test]
fn every_address_vector_has_the_relays_normal_form_and_hash() {
    use apassy_relay::server::links::{address_hash, normal_address};
    let vectors = links::vectors();
    let cases = vectors["addresses"].as_array().unwrap();
    assert!(cases.len() >= 20, "the edge cases of contract section 9");
    for case in cases {
        let input = case["input"].as_str().unwrap();
        assert_eq!(
            normal_address(input).as_deref(),
            case["normalized"].as_str(),
            "{input:?} ({})",
            case["note"]
        );
    }
    let mut hashes = 0;
    for link in vectors["links"].as_array().unwrap() {
        let key =
            apassy_relay::hostkeys::decode_b64(link["address_key_b64u"].as_str().unwrap(), 32)
                .unwrap();
        for address in link["addresses"].as_array().unwrap() {
            let normal = normal_address(address["input"].as_str().unwrap()).unwrap();
            assert_eq!(normal, address["normalized"].as_str().unwrap());
            assert_eq!(
                address_hash(&key, &normal),
                address["hash"].as_str().unwrap()
            );
            hashes += 1;
        }
        assert_eq!(
            link["create"]["address_hashes"].as_array().unwrap().len(),
            link["addresses"].as_array().unwrap().len()
        );
    }
    assert!(hashes >= 2);
}

/// `apassy-relay purge-links`: only with the relay stopped; every link goes with its codes
/// and counts, and the ids stay used, so a purged link neither opens nor is made again.
#[test]
fn the_purge_empties_the_links_and_keeps_their_ids() {
    let c = connect::start();
    let a = c.account("Ada");
    let live = anyone_body(false, 3600);
    let revoked = anyone_body(false, 3600);
    for body in [&live, &revoked] {
        create_ok(&c, &a, body);
    }
    c.ok(
        "DELETE",
        &format!("/v1/account/links/{}", revoked["link_id"].as_str().unwrap()),
        Some(&a.token),
        None,
    );
    let error = apassy_relay::server::links::purge_stopped(&c.relay.config).unwrap_err();
    assert_eq!(error.code, "conflict");
    let Connect { relay, stripe, .. } = c;
    let (config, dir) = relay.stop_keep();
    let counts = apassy_relay::server::links::purge_stopped(&config).unwrap();
    assert_eq!(counts, json!({"links": 1, "mails": 0, "ids_kept": 2}));
    let relay = relay::start_existing(config, dir, None, "");
    let c = Connect::around(relay, stripe);
    let mut a = a;
    a.token = c.sign_in(&a);
    assert_eq!(list(&c, &a)["links"], json!([]));
    for body in [&live, &revoked] {
        let link_id = body["link_id"].as_str().unwrap();
        assert_eq!(open(&c, link_id, &open_body(false)).0, 404);
        let mut again = body.clone();
        again["expires_at"] = json!(now() + 3600);
        let (status, answer) = create(&c, &a, &again);
        assert_eq!(
            (status, answer["error"]["code"].as_str()),
            (409, Some("conflict"))
        );
    }
    create_ok(&c, &a, &anyone_body(false, 3600));
}

/// A late retry of a creation gets its stored view, also once its expiry would no longer
/// pass the check of a new link.
#[test]
fn a_retry_gets_the_stored_view_before_the_expiry_check() {
    let c = connect::start();
    let a = c.account("Ada");
    let body = anyone_body(false, 542);
    let made = create_ok(&c, &a, &body);
    std::thread::sleep(std::time::Duration::from_secs(4));
    // The same expiry is now less than 540 s away: a new link with it is refused...
    let mut fresh = body.clone();
    fresh["link_id"] = json!(links::new_link_id());
    assert_eq!(create(&c, &a, &fresh).0, 400);
    // ...and the retry of the first gets its stored view.
    assert_eq!(create_ok(&c, &a, &body), made);
}
