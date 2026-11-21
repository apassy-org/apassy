#![cfg(feature = "vault")]

//! Public links on the Mac and Linux (contract connect-share-v1, ADR 0047 release A,
//! unit A1) against the in-process fake Connect (`common/fake_connect_links.rs`).
//! Synthetic values only; no real Connect.
//!
//! The sealed forms are opened here with `ring` directly, from the contract's steps, not
//! with the app's code.

use std::sync::{Arc, Mutex};

use apassy::broker::SharedVault;
use apassy::broker::approvals::{OwnerAction, OwnerCheck, OwnerGate, OwnerProof};
use apassy::connect::link::{
    self, LinkError, LinkOptions, LinkTarget, PendingLink, Snapshot, SnapshotField, SnapshotItem,
};
use apassy::connect::{
    ConnectAccount, ConnectClient, JoinPoll, JoinRequest, MemoryKeyStore, account_file,
};
use apassy::contracts::CredentialKind;
use apassy::sync::{decode_b64u, encode_b64u};
use apassy::vault::passkey::{ES256, PasskeyCreate, PasskeyTarget};
use apassy::vault::{Field, ItemDraft, ItemEventKind, LinkRoot, SecretValue, SyncScope, Vault};
use ring::{aead, hkdf, hmac};
use serde_json::Value;
use tempfile::TempDir;
use zeroize::Zeroizing;

use crate::common::fake_connect::FakeConnect;

const PASS: &str = "synthetic-link-pass";
const VECTORS: &str = include_str!("fixtures/connect-share-v1/link-vectors.json");
const SEED: &str = "JBSWY3DPEHPK3PXP";

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("vectors")
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

// ---- The contract's algorithm, written here with ring. ----

struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

fn derive(key: &[u8], info: &str, len: usize) -> Vec<u8> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(key);
    let info = [info.as_bytes()];
    let okm = prk.expand(&info, Len(len)).unwrap();
    let mut out = vec![0; len];
    okm.fill(&mut out).unwrap();
    out
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

/// The viewer's steps: the key from the link, the id, the seal key, the associated data
/// from the answer and the origin, then the AES-GCM open and the JSON.
fn open_as_viewer(link_text: &str, origin: &str, body: &Value) -> Value {
    let (page, key) = link_text.split_once("#v1.").expect("fragment");
    assert_eq!(page, format!("{origin}/s"));
    let key = decode_b64u(key).expect("key");
    assert_eq!(key.len(), 32);
    let link_id = hex(&derive(&key, "apassy-connect public-link id v1", 16));
    assert_eq!(body["link_id"].as_str(), Some(link_id.as_str()));
    let associated = [
        "apassy-connect public-link v1",
        origin,
        &link_id,
        &body["expires_at"].as_u64().unwrap().to_string(),
        if body["one_time"].as_bool().unwrap() {
            "1"
        } else {
            "0"
        },
        body["access"].as_str().unwrap(),
    ]
    .join("\0");
    let sealed = decode_b64u(body["sealed"].as_str().unwrap()).unwrap();
    let (nonce, rest) = sealed.split_at(12);
    let seal_key = derive(&key, "apassy-connect public-link key v1", 32);
    let opening =
        aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, &seal_key).unwrap());
    let mut buffer = rest.to_vec();
    let plain = opening
        .open_in_place(
            aead::Nonce::try_assume_unique_for_key(nonce).unwrap(),
            aead::Aad::from(associated.as_bytes()),
            &mut buffer,
        )
        .expect("the sealed form opens");
    assert_eq!(plain.len() % 1024, 0);
    assert!(plain.len() >= 1024 && plain.len() <= 32 * 1024);
    serde_json::from_slice(plain).expect("JSON with spaces")
}

fn viewer_hash(link_text: &str, normalized: &str) -> String {
    let key = decode_b64u(link_text.split_once("#v1.").unwrap().1).unwrap();
    let address_key = derive(&key, "apassy-connect public-link address v1", 32);
    let mac = hmac::Key::new(hmac::HMAC_SHA256, &address_key);
    encode_b64u(hmac::sign(&mac, normalized.as_bytes()).as_ref())
}

// ---- Devices, vaults, and accounts. ----

/// One computer: its vault (behind an owner gate) and its account key store.
struct Computer {
    dir: TempDir,
    shared: SharedVault,
    gate: OwnerGate,
    keys: MemoryKeyStore,
}

impl Computer {
    fn new() -> Self {
        let dir = TempDir::new().expect("dir");
        let mut vault = Vault::create(&dir.path().join("vault.db"), PASS).expect("vault");
        vault.unlock(PASS).expect("unlock");
        Self::with_vault(dir, vault)
    }

    fn with_vault(dir: TempDir, vault: Vault) -> Self {
        let shared: SharedVault = Arc::new(Mutex::new(Some(vault)));
        let gate = OwnerGate::new(Arc::clone(&shared), None);
        Self {
            dir,
            shared,
            gate,
            keys: MemoryKeyStore::new(),
        }
    }

    /// A second computer with a copy of this vault (the sync of the vault).
    fn copy(&self) -> Self {
        let dir = TempDir::new().expect("dir");
        let seed = dir.path().join("seed.db");
        self.vault(|vault| vault.write_sync_copy(&seed, "Laptop").expect("copy"));
        let (mut vault, _) =
            Vault::adopt_sync_copy(&seed, &dir.path().join("vault.db"), PASS).expect("adopt");
        vault.unlock(PASS).expect("unlock");
        Self::with_vault(dir, vault)
    }

    /// Merge the vault of `other` into this one.
    fn pull(&self, other: &Computer) {
        let copy = self.dir.path().join(format!("from-{}.db", rand_name()));
        other.vault(|vault| vault.write_sync_copy(&copy, "Other").expect("copy"));
        self.vault(|vault| vault.merge_from(&copy, &SyncScope::vault()).expect("merge"));
    }

    fn vault<T>(&self, f: impl FnOnce(&mut Vault) -> T) -> T {
        f(self.shared.lock().unwrap().as_mut().expect("vault"))
    }

    fn proof(&self, action: OwnerAction) -> (OwnerProof, [u8; 32]) {
        let proof = self
            .gate
            .authorize(action, OwnerCheck::passphrase(PASS))
            .expect("owner check");
        (proof, self.vault(|vault| vault.epoch()))
    }

    fn account_path(&self) -> std::path::PathBuf {
        account_file(&self.dir.path().join("account"))
    }
}

fn rand_name() -> String {
    let mut bytes = [0u8; 6];
    getrandom::fill(&mut bytes).unwrap();
    hex(&bytes)
}

fn client(connect: &FakeConnect) -> ConnectClient {
    ConnectClient::new(&connect.url).expect("client")
}

/// A new account on `computer` (no plan), its recovery code seen.
fn create(connect: &FakeConnect, computer: &Computer, name: &str) -> ConnectAccount {
    std::fs::create_dir_all(computer.dir.path().join("account")).unwrap();
    let (mut account, _) = ConnectAccount::create(
        client(connect),
        &computer.keys,
        &computer.account_path(),
        name,
        "Desktop",
    )
    .expect("create");
    account.set_sleeper(Arc::new(|_| {}));
    account.recovery_code_seen().expect("I Saved It");
    account
}

/// `second` joins the account of `account` on `first`.
fn join(
    connect: &FakeConnect,
    account: &mut ConnectAccount,
    first: &Computer,
    second: &Computer,
) -> ConnectAccount {
    std::fs::create_dir_all(second.dir.path().join("account")).unwrap();
    let code = account.start_link().expect("link");
    let mut request = JoinRequest::start(
        client(connect),
        &second.keys,
        &second.account_path(),
        code.code(),
        "Laptop",
    )
    .expect("join");
    assert!(matches!(request.poll().expect("poll"), JoinPoll::Waiting));
    let pending = account.pending_joins(&code).expect("pending");
    let (proof, epoch) = first.proof(pending[0].owner_action(&account.state().account_id));
    account
        .confirm_join(&code, &pending[0], proof, &epoch)
        .expect("confirm");
    match request.poll().expect("poll") {
        JoinPoll::Confirmed(joined) => {
            let mut joined = *joined;
            joined.set_sleeper(Arc::new(|_| {}));
            joined
        }
        other => panic!("not confirmed: {other:?}"),
    }
}

fn field(name: &str, value: &str, secret: bool) -> Field {
    Field {
        name: name.to_owned(),
        value: SecretValue::new(value.to_owned()),
        secret,
    }
}

/// The field name of a custom detail with `label`, as the app names it.
fn detail(label: &str) -> String {
    format!("x_{}", hex(label.as_bytes()))
}

fn custom(vault: &mut Vault, title: &str, fields: Vec<Field>, notes: &str) -> u64 {
    vault
        .add(ItemDraft {
            title: title.to_owned(),
            kind: CredentialKind::Custom,
            notes: notes.to_owned(),
            tags: Vec::new(),
            fields,
        })
        .expect("add")
        .id
}

fn api_key(vault: &mut Vault, title: &str, token: &str) -> u64 {
    vault
        .add(ItemDraft {
            title: title.to_owned(),
            kind: CredentialKind::ApiKey,
            notes: String::new(),
            tags: Vec::new(),
            fields: vec![field("token", token, true)],
        })
        .expect("add")
        .id
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Prepare, confirm, and send a link of `target`; write its row. The link text and the
/// row.
fn make_link(
    computer: &Computer,
    account: &mut ConnectAccount,
    target: &LinkTarget,
    options: &LinkOptions,
) -> (Zeroizing<String>, apassy::vault::PublicLink) {
    let origin = account.client().origin().to_owned();
    let account_id = account.state().account_id.clone();
    let pending = computer
        .vault(|vault| PendingLink::prepare(vault, target, &origin, &account_id, options, now()))
        .expect("prepare");
    let (proof, epoch) = computer.proof(pending.action());
    let created = account
        .create_public_link(pending, proof, &epoch)
        .map_err(|(error, _)| error)
        .expect("created");
    let row = computer.vault(|vault| created.apply(vault)).expect("row");
    (created.link(), row)
}

fn creates(connect: &FakeConnect) -> usize {
    connect
        .log()
        .iter()
        .filter(|line| line.starts_with("POST /v1/account/links"))
        .count()
}

fn deletes(connect: &FakeConnect) -> usize {
    connect
        .log()
        .iter()
        .filter(|line| line.starts_with("DELETE /v1/account/links"))
        .count()
}

// ---- The tests. ----

/// The steps of this build give the vectors of the contract byte for byte: the link id,
/// the link text, the padded plaintext of each snapshot, the associated data, the sealed
/// form, and the address hashes. The vector of one API key comes whole from a vault item.
/// A link made here and sent to Connect opens with the viewer's steps at its origin.
#[test]
fn a_link_made_here_opens_with_the_viewer_vector() {
    let v = vectors();
    let origin = v["origin"].as_str().unwrap();
    for vector in v["links"].as_array().unwrap() {
        let key = decode_b64u(vector["key_b64u"].as_str().unwrap()).unwrap();
        let name = vector["name"].as_str().unwrap();
        assert_eq!(
            link::link_id(&key),
            vector["link_id"].as_str().unwrap(),
            "{name}"
        );
        assert_eq!(
            link::link_text(origin, &key).as_str(),
            vector["link"].as_str().unwrap()
        );
        // The snapshot of the vector, as this build writes it.
        let snapshot = vector["snapshot"].clone();
        let built = Snapshot {
            title: snapshot["title"].as_str().unwrap().to_owned(),
            items: snapshot["items"]
                .as_array()
                .unwrap()
                .iter()
                .enumerate()
                .map(|(index, item)| SnapshotItem {
                    item_id: index as u64 + 1,
                    title: item["title"].as_str().unwrap().to_owned(),
                    kind: serde_json::from_value(item["kind"].clone()).unwrap(),
                    path: serde_json::from_value(item["path"].clone()).unwrap(),
                    fields: item["fields"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|f| SnapshotField {
                            name: f["name"].as_str().unwrap().to_owned(),
                            value: Zeroizing::new(f["value"].as_str().unwrap().to_owned()),
                            secret: f["secret"].as_bool().unwrap(),
                        })
                        .collect(),
                    notes: Zeroizing::new(item["notes"].as_str().unwrap().to_owned()),
                })
                .collect(),
        };
        let plaintext = built.plaintext().expect("fits");
        assert_eq!(
            encode_b64u(&plaintext),
            vector["plaintext_b64u"].as_str().unwrap(),
            "{name}"
        );
        let associated = link::associated_data(
            origin,
            vector["link_id"].as_str().unwrap(),
            vector["expires_at"].as_u64().unwrap(),
            vector["one_time"].as_bool().unwrap(),
            vector["access"].as_str().unwrap(),
        );
        assert_eq!(
            encode_b64u(&associated),
            vector["associated_data_b64u"].as_str().unwrap()
        );
        let nonce: [u8; 12] = unhex(vector["nonce_hex"].as_str().unwrap())
            .try_into()
            .unwrap();
        let sealed = link::seal(&key, nonce, &associated, &plaintext).unwrap();
        assert_eq!(
            encode_b64u(&sealed),
            vector["sealed_b64u"].as_str().unwrap(),
            "{name}"
        );
        for address in vector["addresses"].as_array().unwrap() {
            let normal = link::normalize_address(address["input"].as_str().unwrap()).unwrap();
            assert_eq!(normal, address["normalized"].as_str().unwrap());
            assert_eq!(
                link::address_hash(&key, &normal),
                address["hash"].as_str().unwrap()
            );
        }
    }
    // The address cases of section 6: the normal form of this build is the reference.
    for case in v["addresses"].as_array().unwrap() {
        assert_eq!(
            link::normalize_address(case["input"].as_str().unwrap()).as_deref(),
            case["normalized"].as_str(),
            "{}",
            case["note"]
        );
    }

    // The vector of one API key, whole, from a vault item.
    let vector = &v["links"][1];
    assert_eq!(vector["name"], "one_time_anyone");
    let computer = Computer::new();
    let id = computer.vault(|vault| api_key(vault, "Deploy token", "synthetic-token-0004"));
    let key: [u8; 32] = decode_b64u(vector["key_b64u"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let nonce: [u8; 12] = unhex(vector["nonce_hex"].as_str().unwrap())
        .try_into()
        .unwrap();
    let expires_at = vector["expires_at"].as_u64().unwrap();
    let pending = computer
        .vault(|vault| {
            PendingLink::prepare_with(
                vault,
                &LinkTarget::Item(id),
                origin,
                "acc_k7m2q4x3ca",
                &LinkOptions {
                    expires_in: 3600,
                    one_time: true,
                    emails: None,
                },
                expires_at - 3600,
                Zeroizing::new(key),
                nonce,
            )
        })
        .expect("prepare");
    assert_eq!(
        serde_json::to_value(pending.body()).unwrap(),
        vector["create"]
    );
    assert_eq!(pending.link().as_str(), vector["link"].as_str().unwrap());

    // A link made here, at the fake Connect, opens with the viewer's steps.
    let connect = FakeConnect::start();
    let mut account = create(&connect, &computer, "Ada");
    let item = computer.vault(|vault| {
        custom(
            vault,
            "Staging database",
            vec![
                field("host", "db.staging.example", false),
                field(&detail("User"), "app", false),
                field("password", "synthetic-Pa55-0001", true),
            ],
            "Synthetic. Not a real credential.",
        )
    });
    let (text, row) = make_link(
        &computer,
        &mut account,
        &LinkTarget::Item(item),
        &LinkOptions::default(),
    );
    let body = connect
        .link_bodies()
        .remove(&row.link_id)
        .expect("kept at Connect");
    let opened = open_as_viewer(&text, &connect.url, &body);
    let expected: Value = serde_json::json!({"v":1,"title":"Staging database","items":[{
        "title":"Staging database","kind":"custom","path":[],
        "fields":[{"name":"Host","value":"db.staging.example","secret":false},
                  {"name":"User","value":"app","secret":false},
                  {"name":"Password","value":"synthetic-Pa55-0001","secret":true}],
        "notes":"Synthetic. Not a real credential."}]});
    assert_eq!(opened, expected);
    // The vault row: the key of the link, the account, the root, the history names it.
    assert_eq!(
        row.key()
            .map(|k| link::link_text(&connect.url, k).to_string()),
        Some(text.to_string())
    );
    assert_eq!(row.account_id, account.state().account_id);
    assert_eq!(row.origin, connect.url);
    let uuid = computer.vault(|vault| vault.item_uuid(item).unwrap().unwrap());
    assert_eq!(row.root, LinkRoot::Item(uuid));
    let events = computer.vault(|vault| vault.item_events(item, 10).unwrap());
    assert_eq!(events[0].kind, ItemEventKind::LinkCreated);
    assert_eq!(events[0].detail, "Staging database");
    // The key is in no Debug text.
    let key_text = text.split_once("#v1.").unwrap().1;
    assert!(!format!("{row:?}").contains(key_text));
    // The owner check names the link, and the global owner window never covers it.
    let pending = computer
        .vault(|vault| {
            PendingLink::prepare(
                vault,
                &LinkTarget::Item(item),
                &connect.url,
                "acc_k7m2q4x3ca",
                &LinkOptions::default(),
                now(),
            )
        })
        .unwrap();
    assert!(pending.action().needs_fresh_local_check());
    let pending_key = pending.link().split_once("#v1.").unwrap().1.to_owned();
    assert!(!format!("{pending:?}").contains(&pending_key));
}

/// A link never holds a one-time-code seed (a hidden code detail, or an `otpauth://`
/// link in a plain field), a passkey, an archived credential, or the history.
#[test]
fn a_link_never_holds_a_code_seed_or_a_passkey() {
    let computer = Computer::new();
    let connect = FakeConnect::start();
    let mut account = create(&connect, &computer, "Ada");
    let folder = computer.vault(|vault| vault.create_folder(None, "Team").unwrap().uuid);
    let sub = computer.vault(|vault| vault.create_folder(Some(&folder), "Cloud").unwrap().uuid);
    let with_code = computer.vault(|vault| {
        custom(
            vault,
            "Console",
            vec![
                field("username", "ada", false),
                field("password", "synthetic-console-1", true),
                field(&detail("One-time password"), SEED, true),
                field(
                    &detail("Setup"),
                    &format!("otpauth://totp/Console?secret={SEED}"),
                    false,
                ),
            ],
            "",
        )
    });
    let passkey = computer.vault(|vault| {
        vault
            .create_passkey(PasskeyCreate {
                rp_id: "example.com",
                user_handle: b"synthetic-user",
                user_name: "synthetic-passkey-user",
                user_display_name: "Synthetic Passkey",
                client_data_hash: &[0x3c; 32],
                algorithms: &[ES256],
                exclude: &[],
                target: PasskeyTarget::NewItem {
                    title: "Passkey login".into(),
                },
            })
            .unwrap()
            .item_id
    });
    let archived = computer.vault(|vault| api_key(vault, "Old key", "synthetic-archived-token"));
    let kept = computer.vault(|vault| api_key(vault, "Deploy", "synthetic-deploy-token"));
    computer.vault(|vault| {
        vault.set_item_folder(with_code, Some(&folder)).unwrap();
        vault.set_item_folder(passkey, Some(&sub)).unwrap();
        vault.set_item_folder(archived, Some(&folder)).unwrap();
        vault.set_item_folder(kept, Some(&sub)).unwrap();
        vault.set_archived(archived, true).unwrap();
        vault.record_reveal(kept).unwrap();
    });
    let (text, row) = make_link(
        &computer,
        &mut account,
        &LinkTarget::Folder(folder.clone()),
        &LinkOptions::default(),
    );
    let body = connect.link_bodies().remove(&row.link_id).unwrap();
    let opened = open_as_viewer(&text, &connect.url, &body);
    let json = opened.to_string();
    assert!(!json.contains(SEED), "{json}");
    assert!(!json.contains("otpauth"), "{json}");
    assert!(!json.contains("passkey_"), "{json}");
    assert!(!json.contains("synthetic-archived-token"), "{json}");
    assert!(!json.contains("Old key"), "{json}");
    assert!(!json.contains("revealed"), "{json}");
    let titles: Vec<(&str, Vec<&str>)> = opened["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            (
                item["title"].as_str().unwrap(),
                item["path"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|p| p.as_str().unwrap())
                    .collect(),
            )
        })
        .collect();
    // In the order of the paths, then the names; the path is below the shared folder.
    assert_eq!(
        titles,
        [
            ("Console", vec![]),
            ("Deploy", vec!["Cloud"]),
            ("Passkey login", vec!["Cloud"]),
        ]
    );
    let console = &opened["items"][0]["fields"];
    let names: Vec<&str> = console
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["Username", "Password"]);
    // The passkey's login keeps its plain user name; no field of the passkey leaves.
    let login: Vec<&str> = opened["items"][2]["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["name"].as_str().unwrap())
        .collect();
    assert_eq!(login, ["Username"]);
    assert_eq!(opened["title"], "Team");
    // An archived secret alone makes no link.
    let refused = computer.vault(|vault| {
        PendingLink::prepare(
            vault,
            &LinkTarget::Item(archived),
            &connect.url,
            "acc_k7m2q4x3ca",
            &LinkOptions::default(),
            now(),
        )
    });
    assert_eq!(refused.err(), Some(LinkError::Archived));
}

/// A second device of the same account lists the link through the sync of the vault and
/// revokes it at Connect; the revoke reaches the first device, and wins over an edit.
#[test]
fn a_second_mac_revokes_the_link() {
    let connect = FakeConnect::start();
    let first = Computer::new();
    let mut a = create(&connect, &first, "Ada");
    let item = first.vault(|vault| api_key(vault, "Deploy", "synthetic-deploy-token"));
    let (text, row) = make_link(
        &first,
        &mut a,
        &LinkTarget::Item(item),
        &LinkOptions::default(),
    );
    let second = first.copy();
    let mut b = join(&connect, &mut a, &first, &second);
    let listed = second.vault(|vault| vault.public_links().unwrap());
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].link_id, row.link_id);
    // The second device copies the same link.
    let key = listed[0].key().expect("key");
    assert_eq!(
        link::link_text(&listed[0].origin, key).as_str(),
        text.as_str()
    );
    let receipt = b
        .revoke_public_link(&listed[0])
        .expect("revoked at Connect");
    assert!(connect.link_bodies().is_empty());
    assert!(second.vault(|vault| receipt.apply(vault)).unwrap());
    let revoked = second.vault(|vault| vault.public_link(&row.uuid).unwrap().unwrap());
    assert!(revoked.revoked_at.is_some());
    assert!(revoked.key().is_none() && revoked.addresses.is_empty());
    first.pull(&second);
    assert!(
        first
            .vault(|vault| vault.public_links().unwrap())
            .is_empty()
    );
    let on_first = first.vault(|vault| vault.public_link(&row.uuid).unwrap().unwrap());
    assert!(on_first.revoked_at.is_some() && on_first.key().is_none());
    // Each device that wrote the revoke has it in its history.
    let events = second.vault(|vault| vault.item_events(item, 5).unwrap());
    assert_eq!(events[0].kind, ItemEventKind::LinkRevoked);
    // A later sync of the first device's older row does not bring the link back.
    second.pull(&first);
    assert!(
        second
            .vault(|vault| vault.public_links().unwrap())
            .is_empty()
    );
}

/// A folder whose snapshot passes 32 KiB is refused before the owner check, with how many
/// of its secrets fit; nothing reaches Connect. Those that fit make a link.
#[test]
fn an_oversized_folder_is_refused_before_the_owner_check() {
    let connect = FakeConnect::start();
    let computer = Computer::new();
    let mut account = create(&connect, &computer, "Ada");
    let folder = computer.vault(|vault| vault.create_folder(None, "Big").unwrap().uuid);
    let value = "s".repeat(2000);
    for n in 0..40 {
        let id =
            computer.vault(|vault| api_key(vault, &format!("Key {n:02}"), &format!("{value}{n}")));
        computer.vault(|vault| vault.set_item_folder(id, Some(&folder)).unwrap());
    }
    let origin = account.client().origin().to_owned();
    let account_id = account.state().account_id.clone();
    let refused = computer.vault(|vault| {
        PendingLink::prepare(
            vault,
            &LinkTarget::Folder(folder.clone()),
            &origin,
            &account_id,
            &LinkOptions::default(),
            now(),
        )
    });
    let Err(LinkError::TooLarge { fit, total }) = refused else {
        panic!("not refused: {refused:?}");
    };
    assert_eq!(total, 40);
    assert!(fit > 0 && fit < 40, "{fit}");
    assert_eq!(
        LinkError::TooLarge { fit, total }.to_string(),
        format!("Too large for one link: {fit} of 40 secrets fit. Share fewer.")
    );
    assert_eq!(creates(&connect), 0);
    // `fit` secrets make a link; one more does not.
    let small = computer.vault(|vault| vault.create_folder(None, "Fits").unwrap().uuid);
    let ids = computer.vault(|vault| vault.items_in_folder(Some(&folder), false).unwrap());
    let mut ids = ids;
    ids.sort_unstable();
    for id in &ids[..fit] {
        computer.vault(|vault| vault.set_item_folder(*id, Some(&small)).unwrap());
    }
    let (_, row) = make_link(
        &computer,
        &mut account,
        &LinkTarget::Folder(small.clone()),
        &LinkOptions::default(),
    );
    let sealed = decode_b64u(
        connect.link_bodies()[&row.link_id]["sealed"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert!(sealed.len() <= 32796);
    computer.vault(|vault| vault.set_item_folder(ids[fit], Some(&small)).unwrap());
    let refused = computer.vault(|vault| {
        PendingLink::prepare(
            vault,
            &LinkTarget::Folder(small.clone()),
            &origin,
            &account_id,
            &LinkOptions::default(),
            now(),
        )
    });
    assert!(
        matches!(refused, Err(LinkError::TooLarge { .. })),
        "{refused:?}"
    );
    assert_eq!(creates(&connect), 1);
}

/// "Only these e-mail addresses": Connect gets only the address hashes under the
/// address key of the link, never an address; the vault keeps the normal forms for the
/// owner's list.
#[test]
fn an_email_link_stores_only_address_hashes_at_connect() {
    let connect = FakeConnect::start();
    let computer = Computer::new();
    let mut account = create(&connect, &computer, "Ada");
    let item = computer.vault(|vault| api_key(vault, "Wi-Fi", "synthetic-wifi-pass"));
    let options = LinkOptions {
        emails: Some(vec![
            " Ada.Lovelace@Example.COM ".into(),
            "grace@BÜCHER.example".into(),
            "ada.lovelace@example.com".into(),
        ]),
        ..LinkOptions::default()
    };
    let (text, row) = make_link(&computer, &mut account, &LinkTarget::Item(item), &options);
    let body = connect.link_bodies().remove(&row.link_id).unwrap();
    assert_eq!(body["access"], "emails");
    let hashes: Vec<&str> = body["address_hashes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h.as_str().unwrap())
        .collect();
    let normal = ["ada.lovelace@example.com", "grace@xn--bcher-kva.example"];
    assert_eq!(
        hashes,
        normal
            .map(|address| viewer_hash(&text, address))
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
    );
    for sent in connect.bodies() {
        let lower = sent.to_lowercase();
        assert!(
            !lower.contains("lovelace") && !lower.contains("grace") && !lower.contains("bcher"),
            "{sent}"
        );
    }
    assert_eq!(row.addresses, normal);
    assert!(row.for_emails());
    // The associated data binds the mode: the link opens as `emails` only.
    let opened = open_as_viewer(&text, &connect.url, &body);
    assert_eq!(opened["items"][0]["title"], "Wi-Fi");
    // The address checks come before the owner check.
    for (emails, error) in [
        (vec![], LinkError::AddressCount),
        (
            vec!["not-an-address".to_owned()],
            LinkError::BadAddress("not-an-address".into()),
        ),
        (
            (0..21).map(|n| format!("p{n}@example.com")).collect(),
            LinkError::AddressCount,
        ),
    ] {
        let refused = computer.vault(|vault| {
            PendingLink::prepare(
                vault,
                &LinkTarget::Item(item),
                &connect.url,
                "acc_k7m2q4x3ca",
                &LinkOptions {
                    emails: Some(emails),
                    ..LinkOptions::default()
                },
                now(),
            )
        });
        assert_eq!(refused.err(), Some(error));
    }
    // A Connect without mail refuses `emails` with `mail_unavailable`.
    connect.set_link_mail(false);
    let origin = account.client().origin().to_owned();
    let account_id = account.state().account_id.clone();
    let pending = computer
        .vault(|vault| {
            PendingLink::prepare(
                vault,
                &LinkTarget::Item(item),
                &origin,
                &account_id,
                &options,
                now(),
            )
        })
        .unwrap();
    let (proof, epoch) = computer.proof(pending.action());
    let refused = account
        .create_public_link(pending, proof, &epoch)
        .err()
        .map(|(error, _)| error);
    assert_eq!(refused, Some(LinkError::MailUnavailable));
}

/// A device of another account (a shared vault) lists the link and cannot revoke it:
/// nothing is sent, and no receipt exists that writes a revoke.
#[test]
fn another_accounts_device_cannot_revoke() {
    let connect = FakeConnect::start();
    let first = Computer::new();
    let mut ada = create(&connect, &first, "Ada");
    let item = first.vault(|vault| api_key(vault, "Shared key", "synthetic-shared-token"));
    let (_, row) = make_link(
        &first,
        &mut ada,
        &LinkTarget::Item(item),
        &LinkOptions::default(),
    );
    let other = first.copy();
    let mut ola = create(&connect, &other, "Ola");
    let listed = other.vault(|vault| vault.public_links().unwrap());
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].account_id, ada.state().account_id);
    assert_ne!(listed[0].account_id, ola.state().account_id);
    assert_eq!(
        ola.revoke_public_link(&listed[0]).err(),
        Some(LinkError::NotMaker)
    );
    assert_eq!(deletes(&connect), 0);
    // Connect refuses the id from another account anyway, and the link stays.
    assert!(ola.revoke_unknown_link(&row.link_id).is_ok());
    assert!(connect.link_bodies().contains_key(&row.link_id));
    let still = other.vault(|vault| vault.public_link(&row.uuid).unwrap().unwrap());
    assert!(still.revoked_at.is_none() && still.key().is_some());
}

/// The revoke is written only after Connect answered for the account that made the link:
/// without an answer nothing changes in the vault; a repeat that meets `404` (the delete
/// had happened) writes it.
#[test]
fn a_revoke_is_written_only_after_connect_confirms() {
    let connect = FakeConnect::start();
    let computer = Computer::new();
    let mut account = create(&connect, &computer, "Ada");
    let item = computer.vault(|vault| api_key(vault, "Deploy", "synthetic-deploy-token"));
    let (_, row) = make_link(
        &computer,
        &mut account,
        &LinkTarget::Item(item),
        &LinkOptions::default(),
    );
    let live = |computer: &Computer| {
        let link = computer.vault(|vault| vault.public_link(&row.uuid).unwrap().unwrap());
        link.revoked_at.is_none() && link.key().is_some()
    };
    // An error of Connect: nothing is written.
    connect.answer_route_error("DELETE /v1/account/links", 500, "internal");
    let failed = account.revoke_public_link(&row).expect_err("refused");
    assert!(failed.can_retry(), "{failed:?}");
    assert!(live(&computer));
    connect.clear_route_errors();
    // The delete happens and its answer is lost: still nothing is written.
    connect.lose_next_answers("DELETE /v1/account/links", 1);
    assert!(account.revoke_public_link(&row).is_err());
    assert!(live(&computer));
    assert!(connect.link_bodies().is_empty());
    // "Try Again": Connect answers 404 for the account's own link that is gone, and the
    // revoke is written.
    let receipt = account.revoke_public_link(&row).expect("404 is done");
    assert!(computer.vault(|vault| receipt.apply(vault)).unwrap());
    assert!(!live(&computer));
}

/// A `404` of a revoke is "gone" only with the marker of the links routes
/// (`x-apassy-links: 1`). A `404` without it (an older relay image after a rollback,
/// which has no such route) is not done: the link stays live in the vault, the error
/// offers "Try Again", and the repeat at a relay with the routes revokes it.
#[test]
fn a_revoke_404_without_the_links_marker_is_not_done() {
    let connect = FakeConnect::start();
    let computer = Computer::new();
    let mut account = create(&connect, &computer, "Ada");
    let item = computer.vault(|vault| api_key(vault, "Deploy", "synthetic-deploy-token"));
    let (_, row) = make_link(
        &computer,
        &mut account,
        &LinkTarget::Item(item),
        &LinkOptions::default(),
    );
    let live = |computer: &Computer| {
        let link = computer.vault(|vault| vault.public_link(&row.uuid).unwrap().unwrap());
        link.revoked_at.is_none() && link.key().is_some()
    };
    // A relay without the links routes: every link path is a plain 404.
    connect.set_links_marker(false);
    connect.answer_route_error("DELETE /v1/account/links", 404, "not_found");
    let refused = account.revoke_public_link(&row).expect_err("not done");
    assert_eq!(refused, LinkError::NotConfirmed);
    assert!(refused.can_retry());
    assert!(refused.to_string().contains("Try again"), "{refused}");
    assert!(live(&computer));
    assert!(
        connect.link_bodies().contains_key(&row.link_id),
        "the link still opens"
    );
    // A link the vault does not hold is not taken as revoked either.
    assert_eq!(
        account.revoke_unknown_link(&row.link_id),
        Err(LinkError::NotConfirmed)
    );
    // The relay with the routes again: "Try Again" revokes it (200).
    connect.clear_route_errors();
    connect.set_links_marker(true);
    let receipt = account.revoke_public_link(&row).expect("revoked");
    assert!(connect.link_bodies().is_empty());
    assert!(computer.vault(|vault| receipt.apply(vault)).unwrap());
    assert!(!live(&computer));
    // Its 404 with the marker, for the link that is gone now, is done.
    assert!(account.revoke_unknown_link(&row.link_id).is_ok());
}

/// A lost answer of a creation is sent again with the exact body; Connect keeps one link.
/// `409` of a repeat reads the list. The limit is `link_limit`, also for an account
/// without a plan, which may make links.
#[test]
fn a_lost_creation_is_repeated_with_the_same_body_and_the_limit_is_clear() {
    let connect = FakeConnect::start();
    let computer = Computer::new();
    let mut account = create(&connect, &computer, "Ada");
    let item = computer.vault(|vault| api_key(vault, "Deploy", "synthetic-deploy-token"));
    let origin = account.client().origin().to_owned();
    let account_id = account.state().account_id.clone();
    let prepare = |computer: &Computer| {
        computer
            .vault(|vault| {
                PendingLink::prepare(
                    vault,
                    &LinkTarget::Item(item),
                    &origin,
                    &account_id,
                    &LinkOptions::default(),
                    now(),
                )
            })
            .unwrap()
    };
    let pending = prepare(&computer);
    let body = serde_json::to_value(pending.body()).unwrap();
    connect.lose_next_answers("POST /v1/account/links", 1);
    let (proof, epoch) = computer.proof(pending.action());
    let (error, kept) = account
        .create_public_link(pending, proof, &epoch)
        .expect_err("lost");
    assert!(error.can_retry(), "{error:?}");
    let kept = kept.expect("the exact body stays");
    assert!(kept.is_approved());
    let created = account
        .send_public_link(*kept)
        .map_err(|(e, _)| e)
        .expect("repeat");
    assert_eq!(connect.link_bodies().len(), 1);
    assert_eq!(connect.link_bodies()[&created.view.link_id], body);
    let bodies: Vec<Value> = connect
        .bodies()
        .iter()
        .filter_map(|b| serde_json::from_str::<Value>(b).ok())
        .filter(|b| b.get("sealed").is_some())
        .collect();
    assert_eq!(bodies, [body.clone(), body]);
    // An unapproved link is never sent.
    let fresh = prepare(&computer);
    assert!(account.send_public_link(fresh).is_err());
    // The limit of the account.
    connect.set_link_limit(Some(1));
    let pending = prepare(&computer);
    let (proof, epoch) = computer.proof(pending.action());
    let refused = account
        .create_public_link(pending, proof, &epoch)
        .err()
        .map(|(e, _)| e);
    assert_eq!(refused, Some(LinkError::LinkLimit));
    let list = account.public_links().expect("list");
    assert_eq!((list.live, list.limit), (1, Some(1)));
}

/// The origin rules of section 2: `https:` with a public name, or loopback `http:`.
#[test]
fn links_are_made_only_for_https_origins() {
    for good in [
        "https://apassy-relay.wyderka.cc",
        "https://connect.example.com:8443",
        "http://127.0.0.1:9",
        "http://localhost",
    ] {
        assert!(link::link_origin(good).is_ok(), "{good}");
    }
    for bad in [
        "http://connect.example.com",
        "http://192.168.1.10:8080",
        "https://192.168.1.10",
        "https://abc.onion",
        "https://mac.local",
        "https://relay.home.arpa",
        "https://[::1]",
        "https://example.com/path",
        "ftp://example.com",
        "https://Example.com",
        "https://user@example.com",
        "https://example.com:",
        "https://example.com:123456",
        "https://example.com:80a",
        "http://localhost:abc",
        "https://example.com?x",
    ] {
        assert_eq!(link::link_origin(bad), Err(LinkError::Origin), "{bad}");
    }
}

/// Prepare and confirm a link of `item` and send it: the receipt, its row not written.
fn created(
    computer: &Computer,
    account: &mut ConnectAccount,
    item: u64,
) -> apassy::connect::link::LinkCreated {
    let origin = account.client().origin().to_owned();
    let account_id = account.state().account_id.clone();
    let pending = computer
        .vault(|vault| {
            PendingLink::prepare(
                vault,
                &LinkTarget::Item(item),
                &origin,
                &account_id,
                &LinkOptions::default(),
                now(),
            )
        })
        .expect("prepare");
    let (proof, epoch) = computer.proof(pending.action());
    account
        .create_public_link(pending, proof, &epoch)
        .map_err(|(error, _)| error)
        .expect("created")
}

/// A row that cannot be written after Connect took the link (the vault locked, or
/// another vault opened, between the answer and the write) revokes the link at Connect
/// on the same step, so no live link is left that no device can copy. A revoke that
/// fails leaves the link live, and Connect lists it for the account (Settings shows it
/// among the links not in this vault).
#[test]
fn a_link_whose_row_is_not_written_is_revoked_at_once() {
    let connect = FakeConnect::start();
    let computer = Computer::new();
    let mut account = create(&connect, &computer, "Ada");
    let item = computer.vault(|vault| api_key(vault, "Deploy", "synthetic-deploy-token"));
    let made = created(&computer, &mut account, item);
    assert!(connect.link_bodies().contains_key(made.link_id()));
    let refused = account
        .keep_or_revoke(made, |_| Err(LinkError::Vault))
        .expect_err("not saved");
    assert_eq!(refused, LinkError::NotSaved { revoked: true });
    assert!(connect.link_bodies().is_empty(), "revoked at Connect");
    assert!(
        computer
            .vault(|vault| vault.public_links().unwrap())
            .is_empty()
    );
    assert!(refused.to_string().contains("revoked"), "{refused}");
    // The revoke fails: the link stays live at Connect, where the list shows it.
    let made = created(&computer, &mut account, item);
    let link_id = made.link_id().to_owned();
    connect.answer_route_error("DELETE /v1/account/links", 500, "internal");
    let refused = account
        .keep_or_revoke(made, |_| Err(LinkError::Vault))
        .expect_err("not saved");
    assert_eq!(refused, LinkError::NotSaved { revoked: false });
    connect.clear_route_errors();
    let list = account.public_links().expect("list");
    assert!(list.links.iter().any(|view| view.link_id == link_id));
    assert!(account.revoke_unknown_link(&link_id).is_ok());
    // A row that is written keeps the link, with its text.
    let made = created(&computer, &mut account, item);
    let kept = account
        .keep_or_revoke(made, |made| computer.vault(|vault| made.apply(vault)))
        .expect("kept");
    let rows = computer.vault(|vault| vault.public_links().unwrap());
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].link_id, kept.row.link_id);
    let key = rows[0].key().expect("key");
    assert_eq!(
        kept.link().as_str(),
        link::link_text(&rows[0].origin, key).as_str()
    );
    assert!(connect.link_bodies().contains_key(&kept.row.link_id));
}

/// A relay without the links routes (an older or a self-hosted image: a `404` without
/// `x-apassy-links: 1`) is `NoLinks`, "This relay does not offer links.", for the list
/// and for a creation, which keeps nothing to repeat.
#[test]
fn a_relay_without_the_links_routes_offers_no_links() {
    let connect = FakeConnect::start();
    let computer = Computer::new();
    let mut account = create(&connect, &computer, "Ada");
    let item = computer.vault(|vault| api_key(vault, "Deploy", "synthetic-deploy-token"));
    connect.set_links_marker(false);
    connect.answer_route_error("GET /v1/account/links", 404, "not_found");
    connect.answer_route_error("POST /v1/account/links", 404, "not_found");
    assert_eq!(account.public_links(), Err(LinkError::NoLinks));
    assert_eq!(
        LinkError::NoLinks.to_string(),
        "This relay does not offer links."
    );
    assert!(!LinkError::NoLinks.can_retry());
    let origin = account.client().origin().to_owned();
    let account_id = account.state().account_id.clone();
    let pending = computer
        .vault(|vault| {
            PendingLink::prepare(
                vault,
                &LinkTarget::Item(item),
                &origin,
                &account_id,
                &LinkOptions::default(),
                now(),
            )
        })
        .expect("prepare");
    let (proof, epoch) = computer.proof(pending.action());
    let (error, kept) = account
        .create_public_link(pending, proof, &epoch)
        .expect_err("no routes");
    assert_eq!(error, LinkError::NoLinks);
    assert!(kept.is_none());
    // The relay with the routes again: the list answers.
    connect.clear_route_errors();
    connect.set_links_marker(true);
    assert!(account.public_links().is_ok());
}

/// "Public link revoked" goes to the credentials of the link's snapshot: not to one that
/// joined the folder after the link was made, and also to one that left it.
#[test]
fn a_revoke_writes_the_history_of_the_snapshot() {
    let connect = FakeConnect::start();
    let computer = Computer::new();
    let mut account = create(&connect, &computer, "Ada");
    let (folder, inside, moved_out) = computer.vault(|vault| {
        let folder = vault.create_folder(None, "Deploys").unwrap().uuid;
        let inside = api_key(vault, "Inside", "synthetic-inside-token");
        let moved_out = api_key(vault, "Moved out", "synthetic-out-token");
        vault.set_item_folder(inside, Some(&folder)).unwrap();
        vault.set_item_folder(moved_out, Some(&folder)).unwrap();
        (folder, inside, moved_out)
    });
    let (_, row) = make_link(
        &computer,
        &mut account,
        &LinkTarget::Folder(folder.clone()),
        &LinkOptions::default(),
    );
    let later = computer.vault(|vault| {
        let later = api_key(vault, "Later", "synthetic-later-token");
        vault.set_item_folder(later, Some(&folder)).unwrap();
        vault.set_item_folder(moved_out, None).unwrap();
        later
    });
    let receipt = account.revoke_public_link(&row).expect("revoked");
    assert!(computer.vault(|vault| receipt.apply(vault)).unwrap());
    let revoked = |id: u64| {
        computer
            .vault(|vault| vault.item_events(id, 20).unwrap())
            .iter()
            .filter(|event| event.kind == ItemEventKind::LinkRevoked)
            .count()
    };
    assert_eq!(revoked(inside), 1);
    assert_eq!(revoked(moved_out), 1);
    assert_eq!(revoked(later), 0, "never in the link");
}
