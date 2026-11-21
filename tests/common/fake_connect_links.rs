//! The account routes of public links (contract connect-share-v1 sections 4.1 to 4.3) in
//! the fake Connect: `POST /v1/account/links` with the strict body, the size of the
//! sealed form, the expiry window, the address hashes of each access mode, the live limit
//! of the account (`403 link_limit`), a tombstone of every id (`409 conflict`), and the
//! retry rule (the same body from the same account answers the stored view);
//! `GET /v1/account/links`; `DELETE /v1/account/links/{link_id}` for the account that
//! made the link only (another account and an unknown id are `404`). The public routes
//! are the relay's (PR #167); this fake keeps only what the app sends.

use super::*;

pub(super) struct StoredLink {
    pub(super) account: String,
    pub(super) body: Value,
    pub(super) created_at: u64,
    pub(super) opens: u64,
}

pub(super) struct LinkState {
    pub(super) links: BTreeMap<String, StoredLink>,
    pub(super) used: std::collections::BTreeSet<String>,
    pub(super) limit: Option<u64>,
    pub(super) mail: bool,
    /// The answers of the links routes carry `x-apassy-links: 1`.
    pub(super) marker: bool,
}

impl Default for LinkState {
    fn default() -> Self {
        Self {
            links: BTreeMap::new(),
            used: Default::default(),
            limit: Some(25),
            mail: true,
            marker: true,
        }
    }
}

fn hex32(text: &str) -> bool {
    text.len() == 32
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn view(link_id: &str, link: &StoredLink) -> Value {
    let body = &link.body;
    json!({
        "link_id": link_id,
        "created_at": link.created_at,
        "expires_at": body["expires_at"],
        "one_time": body["one_time"],
        "access": body["access"],
        "addresses": body["address_hashes"].as_array().map_or(0, Vec::len),
        "state": "live",
        "opens": link.opens,
        "last_opened_at": null,
    })
}

fn live(state: &State, account: &str) -> u64 {
    let now = now();
    state
        .public_links
        .links
        .values()
        .filter(|link| {
            link.account == account && link.body["expires_at"].as_u64().unwrap_or(0) > now
        })
        .count() as u64
}

/// The body of section 4.1: exactly its six fields, each of its type and form.
fn valid(body: &Value) -> bool {
    let Some(map) = body.as_object() else {
        return false;
    };
    let keys = [
        "link_id",
        "sealed",
        "expires_at",
        "one_time",
        "access",
        "address_hashes",
    ];
    if map.len() != keys.len() || !keys.iter().all(|key| map.contains_key(*key)) {
        return false;
    }
    let Some(sealed) = body["sealed"].as_str().and_then(decode_b64u) else {
        return false;
    };
    let size_ok = (1052..=32796).contains(&sealed.len()) && (sealed.len() - 28) % 1024 == 0;
    let now = now();
    let expires_ok = body["expires_at"]
        .as_u64()
        .is_some_and(|at| at >= now + 540 && at <= now + 2_592_060);
    let Some(hashes) = body["address_hashes"].as_array() else {
        return false;
    };
    let hashes_ok = hashes.iter().all(|hash| {
        hash.as_str().is_some_and(|text| {
            text.len() == 43 && decode_b64u(text).is_some_and(|b| b.len() == 32)
        })
    });
    let distinct = hashes
        .iter()
        .filter_map(Value::as_str)
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        == hashes.len();
    let access_ok = match body["access"].as_str() {
        Some("anyone") => hashes.is_empty(),
        Some("emails") => (1..=20).contains(&hashes.len()),
        _ => false,
    };
    body["link_id"].as_str().is_some_and(hex32)
        && body["one_time"].is_boolean()
        && size_ok
        && expires_ok
        && hashes_ok
        && distinct
        && access_ok
}

impl FakeConnect {
    /// The creation bodies that the fake keeps, by link id.
    pub fn link_bodies(&self) -> BTreeMap<String, Value> {
        lock(&self.shared)
            .public_links
            .links
            .iter()
            .map(|(id, link)| (id.clone(), link.body.clone()))
            .collect()
    }

    /// The live link limit of every account (`None`: no limit).
    pub fn set_link_limit(&self, limit: Option<u64>) {
        lock(&self.shared).public_links.limit = limit;
    }

    /// Whether this Connect can send the code mails.
    pub fn set_link_mail(&self, mail: bool) {
        lock(&self.shared).public_links.mail = mail;
    }

    /// The answers of the links routes carry their marker (`true`), or not (`false`: a
    /// relay image without the routes, which answers `404` without it).
    pub fn set_links_marker(&self, on: bool) {
        lock(&self.shared).public_links.marker = on;
    }

    /// A reader opened the link `link_id`.
    pub fn open_link(&self, link_id: &str) {
        if let Some(link) = lock(&self.shared).public_links.links.get_mut(link_id) {
            link.opens += 1;
        }
    }
}

/// The marker header line of an answer to `path`: on the links routes, while it is on.
pub(super) fn marked(state: &State, path: &str) -> &'static str {
    let links = path.starts_with("/v1/account/links") || path.starts_with("/v1/links/");
    if links && state.public_links.marker {
        "x-apassy-links: 1\r\n"
    } else {
        ""
    }
}

/// The routes of section 4, or `None` for another path.
pub(super) fn route(
    state: &mut State,
    method: &str,
    rest: &[&str],
    body: &Value,
    account: &str,
) -> Option<Outgoing> {
    let answer = match (method, rest) {
        ("POST", ["links"]) => {
            if !valid(body) {
                return Some(fail(400, "invalid_request"));
            }
            if body["access"] == "emails" && !state.public_links.mail {
                return Some(fail(503, "mail_unavailable"));
            }
            let link_id = text(body, "link_id").to_owned();
            if let Some(stored) = state.public_links.links.get(&link_id) {
                return Some(if stored.account == account && stored.body == *body {
                    ok(view(&link_id, stored))
                } else {
                    fail(409, "conflict")
                });
            }
            if state.public_links.used.contains(&link_id) {
                return Some(fail(409, "conflict"));
            }
            if let Some(limit) = state.public_links.limit
                && live(state, account) >= limit
            {
                return Some(fail(403, "link_limit"));
            }
            let stored = StoredLink {
                account: account.to_owned(),
                body: body.clone(),
                created_at: now(),
                opens: 0,
            };
            let answer = view(&link_id, &stored);
            state.public_links.used.insert(link_id.clone());
            state.public_links.links.insert(link_id, stored);
            ok(answer)
        }
        ("GET", ["links"]) => {
            let mut links: Vec<(&String, &StoredLink)> = state
                .public_links
                .links
                .iter()
                .filter(|(_, link)| link.account == account)
                .collect();
            links.sort_by_key(|link| std::cmp::Reverse(link.1.created_at));
            ok(json!({
                "links": links.iter().map(|(id, link)| view(id, link)).collect::<Vec<_>>(),
                "live": live(state, account),
                "limit": state.public_links.limit,
                "mail": state.public_links.mail,
            }))
        }
        ("DELETE", ["links", link_id]) => {
            let mine = state
                .public_links
                .links
                .get(*link_id)
                .is_some_and(|link| link.account == account);
            if !mine {
                return Some(fail(404, "not_found"));
            }
            state.public_links.links.remove(*link_id);
            ok(json!({"link_id": link_id, "deleted": true}))
        }
        _ => return None,
    };
    Some(answer)
}
