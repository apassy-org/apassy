#![cfg(feature = "vault")]
//! Normal broker entry points, a synthetic vault, and an unserved loopback SMTP
//! socket. No real credentials, mail server, or external network are used.

use apassy::agent::wire::{Action, WireRequest, WireResponse};
use apassy::broker::approvals::{ApprovalQueue, OwnerCheck, OwnerGate};
use apassy::broker::bouncer::BouncerClient;
use apassy::broker::decide::{BrokerContext, handle};
use apassy::broker::mail_tasks::{MailTaskSnapshot, MailTaskState};
use apassy::broker::prompts::PromptStore;
use apassy::contracts::CredentialKind;
use apassy::vault::{
    Declaration, Environment, Field, ItemDraft, Reversibility, RiskLevel, Scope, SecretValue, Vault,
};
use std::io::{ErrorKind, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const PASS: &str = "synthetic-mail-task-passphrase";
const SESSION: &str = "synthetic-mail-host-session";
const RECIPIENT: &str = "recipient@example.invalid";
const PURPOSE: &str = "Send the synthetic project update to its approved recipient.";

#[test]
fn reconnect_recovers_one_proposal_and_cancellation_withdraws_it() {
    use apassy::agent::client::{SendOptions, send_with};
    let f = Fixture::new();
    let socket = f.dir.path().join("private/broker.sock");
    let broker =
        apassy::broker::start_with_tls(f.ctx.vault.clone(), &socket, f.ctx.tls.clone()).unwrap();
    let call = |action| {
        send_with(
            &socket,
            &f.token,
            action,
            SendOptions {
                host_session: Some(SESSION),
                timeout: Some(Duration::from_secs(3)),
            },
        )
        .unwrap()
    };
    let operation_id = "c468bf1416ec45c485a17e70282446be";
    let prepare = || Action::Tracked {
        operation_id: operation_id.into(),
        idempotency_key: Some("synthetic-recovery".into()),
        action: Box::new(f.proposal(&[RECIPIENT])),
    };
    let created = call(prepare()).result.unwrap();
    let id = created["task_id"].as_str().unwrap();
    let replay = call(prepare()).result.unwrap();
    assert_eq!(replay["outcome"]["result"]["task_id"], id);
    assert_eq!(replay["outcome"]["result"]["state"], "pending");
    assert!(!replay.to_string().contains(RECIPIENT));
    let epoch = f.ctx.vault.lock().unwrap().as_ref().unwrap().epoch();
    assert_eq!(
        broker
            .approvals()
            .mail_tasks()
            .pending_count(&epoch)
            .unwrap(),
        1
    );
    for _ in 0..2 {
        let cancelled = call(Action::CancelOperation {
            operation_id: operation_id.into(),
        });
        assert_eq!(cancelled.result.unwrap()["outcome"]["code"], "cancelled");
    }
    let state = call(Action::MailTaskStatus {
        task_id: id.into(),
        cwd: f.cwd(),
    });
    assert_eq!(state.result.unwrap()["state"], "revoked");
    assert_eq!(
        broker
            .approvals()
            .mail_tasks()
            .pending_count(&epoch)
            .unwrap(),
        0
    );
    f.ctx
        .vault
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .lock()
        .unwrap();
    assert!(
        broker
            .approvals()
            .mail_tasks()
            .list_for_owner(&epoch)
            .unwrap()
            .is_empty()
    );
    f.assert_no_contact();
}

struct Fixture {
    dir: tempfile::TempDir,
    smtp: TcpListener,
    ctx: BrokerContext,
    token: String,
    item: u64,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let smtp = TcpListener::bind("127.0.0.1:0").unwrap();
        smtp.set_nonblocking(true).unwrap();
        let mut vault = Vault::create(&dir.path().join("vault.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        let item = vault
            .add(account(smtp.local_addr().unwrap().port()))
            .unwrap()
            .id;
        let (agent, token) = vault.register_agent("Synthetic mail agent").unwrap();
        vault.set_agent_sees_all(agent.id, true).unwrap();
        Self {
            dir,
            smtp,
            item,
            token: token.expose().into(),
            ctx: BrokerContext {
                vault: Arc::new(Mutex::new(Some(vault))),
                tls: apassy::broker::http::TlsClient::platform().unwrap(),
                approvals: Arc::new(ApprovalQueue::new()),
                approval_timeout: Duration::from_secs(3),
                run_timeout: Duration::from_secs(1),
                bouncer: None,
                model_gate: None,
                prompts: Arc::new(PromptStore::new(vec![])),
            },
        }
    }

    fn cwd(&self) -> String {
        self.dir.path().to_str().unwrap().into()
    }

    fn request(&self, action: Action) -> WireRequest {
        WireRequest {
            v: action.wire_version(),
            token: self.token.clone(),
            host_session: Some(SESSION.into()),
            action,
        }
    }

    fn prepare(&self) -> MailTaskSnapshot {
        self.prepare_recipients(&[RECIPIENT])
    }

    fn prepare_recipients(&self, recipients: &[&str]) -> MailTaskSnapshot {
        let response = handle(&self.ctx, &self.request(self.proposal(recipients)));
        assert!(response.ok, "{response:?}");
        let result = response.result.unwrap();
        assert_eq!(result["state"], "pending");
        let guard = self.ctx.vault.lock().unwrap();
        let epoch = guard.as_ref().unwrap().epoch();
        let task = self
            .ctx
            .approvals
            .mail_tasks()
            .list_for_owner(&epoch)
            .unwrap()
            .into_iter()
            .find(|task| task.id == result["task_id"].as_str().unwrap())
            .unwrap();
        assert_eq!(task.state, MailTaskState::Pending);
        self.assert_no_contact();
        task
    }

    fn proposal(&self, recipients: &[&str]) -> Action {
        Action::PrepareMailTask {
            item_id: self.item,
            recipients: recipients
                .iter()
                .map(|recipient| (*recipient).into())
                .collect(),
            subject: "Synthetic project update".into(),
            body: "The synthetic project is ready for review.\n".into(),
            ttl_minutes: 5,
            purpose: PURPOSE.into(),
            cwd: self.cwd(),
        }
    }

    fn activate(&self, task: &MailTaskSnapshot) {
        // Exercise the existing real owner gate against this temporary vault.
        // There is no test-only or production authorization bypass here.
        let proof = OwnerGate::new(self.ctx.vault.clone(), None)
            .authorize(
                task.owner_action(),
                OwnerCheck::Passphrase(Zeroizing::new(PASS.into())),
            )
            .unwrap();
        let guard = self.ctx.vault.lock().unwrap();
        self.ctx
            .approvals
            .mail_tasks()
            .activate(&task.id, &guard.as_ref().unwrap().epoch(), proof)
            .unwrap();
    }

    fn send(&self, task: &MailTaskSnapshot) -> WireRequest {
        self.send_recipient(task, RECIPIENT)
    }

    fn send_recipient(&self, task: &MailTaskSnapshot, recipient: &str) -> WireRequest {
        self.request(Action::SendTaskMail {
            task_id: task.id.clone(),
            recipient: recipient.into(),
            cwd: self.cwd(),
            user_request: PURPOSE.into(),
        })
    }

    fn status(&self, task: &MailTaskSnapshot) -> WireRequest {
        self.request(Action::MailTaskStatus {
            task_id: task.id.clone(),
            cwd: self.cwd(),
        })
    }

    fn assert_status(&self, task: &MailTaskSnapshot, state: &str) {
        let response = handle(&self.ctx, &self.status(task));
        assert!(response.ok, "{response:?}");
        let result = response.result.unwrap();
        assert_eq!(result["state"], state);
        let mut keys: Vec<_> = result
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "expires_in_seconds",
                "in_flight",
                "not_submitted",
                "remaining",
                "sent",
                "state",
                "task_id",
                "total",
                "unknown"
            ]
        );
    }

    fn assert_no_contact(&self) {
        match self.smtp.accept() {
            Err(error) if error.kind() == ErrorKind::WouldBlock => {}
            other => panic!("SMTP was contacted before authorization: {other:?}"),
        }
    }

    fn assert_scope_refused(&self, request: &WireRequest) {
        let response = handle(&self.ctx, request);
        assert!(!response.ok, "{response:?}");
        assert_eq!(response.error.unwrap().code, "mail_task_unavailable");
        assert!(
            self.ctx.approvals.pending().is_empty(),
            "scope denial must precede per-send approval"
        );
        self.assert_no_contact();
    }

    fn assert_context_refused(&self, task: &MailTaskSnapshot, request: &WireRequest) {
        self.assert_scope_refused(request);
        let Action::SendTaskMail { cwd, .. } = &request.action else {
            panic!("expected a send request");
        };
        let action = Action::MailTaskStatus {
            task_id: task.id.clone(),
            cwd: cwd.clone(),
        };
        self.assert_scope_refused(&WireRequest {
            v: action.wire_version(),
            token: request.token.clone(),
            host_session: request.host_session.clone(),
            action,
        });
    }

    fn refuse_smtp_greeting(&self, task: &MailTaskSnapshot, recipient: &str) {
        let ctx = self.ctx.clone();
        let request = self.send_recipient(task, recipient);
        let sending = std::thread::spawn(move || handle(&ctx, &request));
        let started = Instant::now();
        let mut connection = loop {
            match self.smtp.accept() {
                Ok((mut stream, _)) => {
                    // Deliberately stop before TLS, AUTH, envelope or DATA.
                    stream
                        .write_all(b"554 Synthetic submission disabled\r\n")
                        .unwrap();
                    break Some(stream);
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    if sending.is_finished() || started.elapsed() >= Duration::from_secs(3) {
                        break None;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("synthetic SMTP accept: {error}"),
            }
        };
        let response = sending.join().unwrap();
        assert!(
            connection.is_some(),
            "approved recipient never reached SMTP: {response:?}"
        );
        assert_eq!(response.error.unwrap().code, "mail_not_submitted");
        let stream = connection.as_mut().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        assert_eq!(
            stream.read(&mut [0]).unwrap(),
            0,
            "a refused greeting must not receive credentials or message data"
        );
    }
}

fn account(port: u16) -> ItemDraft {
    let field = |name: &str, value: &str, secret| Field {
        name: name.into(),
        value: SecretValue::new(value.into()),
        secret,
    };
    let detail = |label: &str, value: &str| {
        let name = format!(
            "x_{}",
            label
                .bytes()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        field(&name, value, false)
    };
    ItemDraft {
        title: "Synthetic SMTP account".into(),
        kind: CredentialKind::Login,
        notes: String::new(),
        tags: vec![],
        fields: vec![
            field("username", "synthetic-user", false),
            field("password", "SYNTHETIC-SMTP-SECRET-ONLY", true),
            detail("SMTP host", "127.0.0.1"),
            detail("SMTP port", &port.to_string()),
            detail("SMTP sender", "sender@example.invalid"),
        ],
    }
}

#[test]
fn preparing_and_activating_a_task_do_not_preapprove_a_message() {
    let f = Fixture::new();
    let task = f.prepare();
    f.assert_status(&task, "pending");
    f.assert_scope_refused(&f.send(&task));
    f.activate(&task);
    f.assert_status(&task, "active");
    f.assert_no_contact();

    let ctx = f.ctx.clone();
    let request = f.send(&task);
    let sending = std::thread::spawn(move || handle(&ctx, &request));
    let started = Instant::now();
    let pending = loop {
        if let Some(pending) = f.ctx.approvals.pending().first().cloned() {
            break pending;
        }
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "active task did not ask for this send"
        );
        std::thread::sleep(Duration::from_millis(5));
    };
    let duplicate = handle(&f.ctx, &f.send(&task));
    assert_eq!(duplicate.error.unwrap().code, "mail_task_in_flight");
    assert_eq!(f.ctx.approvals.pending().len(), 1);
    f.assert_no_contact();
    assert!(f.ctx.approvals.deny(pending.id));
    let response: WireResponse = sending.join().unwrap();
    assert!(!response.ok, "{response:?}");
    assert_eq!(response.error.unwrap().code, "approval_denied");
    let retry = handle(&f.ctx, &f.send(&task));
    assert_eq!(retry.error.unwrap().code, "mail_not_submitted");
    assert!(f.ctx.approvals.pending().is_empty());
    f.assert_no_contact();
}

#[test]
fn active_task_rejects_foreign_context_recipient_and_changed_item_before_policy() {
    let f = Fixture::new();
    let task = f.prepare();
    f.activate(&task);

    let mut wrong_session = f.send(&task);
    wrong_session.host_session = Some("other-host-session".into());
    f.assert_context_refused(&task, &wrong_session);
    let mut missing_session = f.send(&task);
    missing_session.host_session = None;
    f.assert_context_refused(&task, &missing_session);
    let mut wrong_recipient = f.send(&task);
    if let Action::SendTaskMail { recipient, .. } = &mut wrong_recipient.action {
        *recipient = "unapproved@example.invalid".into();
    }
    f.assert_scope_refused(&wrong_recipient);
    let other_project = tempfile::tempdir().unwrap();
    let mut wrong_project = f.send(&task);
    if let Action::SendTaskMail { cwd, .. } = &mut wrong_project.action {
        *cwd = other_project.path().to_str().unwrap().into();
    }
    f.assert_context_refused(&task, &wrong_project);
    let other_token = {
        let mut guard = f.ctx.vault.lock().unwrap();
        let vault = guard.as_mut().unwrap();
        let (agent, token) = vault.register_agent("Other synthetic mail agent").unwrap();
        vault.set_agent_sees_all(agent.id, true).unwrap();
        token.expose().to_owned()
    };
    let mut wrong_agent = f.send(&task);
    wrong_agent.token = other_token;
    f.assert_context_refused(&task, &wrong_agent);

    {
        let mut changed = account(f.smtp.local_addr().unwrap().port());
        changed.title = "Changed synthetic SMTP account".into();
        f.ctx
            .vault
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .update(f.item, task.binding.item_revision, changed)
            .unwrap();
    }
    f.assert_context_refused(&task, &f.send(&task));
}

#[test]
fn approved_production_task_evaluates_three_recipients_and_blocks_a_fourth_before_model_or_smtp() {
    let mut f = Fixture::new();
    let bouncer = crate::common::fake_bouncer(&[
        ("task_match", 0.999),
        ("writes", 0.999),
        ("remote", 0.999),
        ("leak", 0.001),
        ("destroy", 0.001),
        ("rule_break", 0.001),
    ]);
    f.ctx.bouncer = Some(BouncerClient::new(&bouncer.url).unwrap());
    f.ctx
        .vault
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .set_declaration(
            f.item,
            &Declaration {
                project: f.cwd(),
                environment: Environment::Production,
                risk: RiskLevel::High,
                scope: Scope::Admin,
                reversibility: Reversibility::Irreversible,
            },
        )
        .unwrap();
    let recipients = [
        "one@example.invalid",
        "two@example.invalid",
        "three@example.invalid",
    ];
    let task = f.prepare_recipients(&recipients);
    f.assert_scope_refused(&f.send_recipient(&task, recipients[0]));
    assert!(bouncer.bodies.lock().unwrap().is_empty());
    f.activate(&task);

    for recipient in recipients {
        f.refuse_smtp_greeting(&task, recipient);
    }
    let bodies = bouncer.bodies.lock().unwrap().clone();
    assert_eq!(bodies.len(), 3);
    for (body, recipient) in bodies.iter().zip(recipients) {
        assert!(
            body.contains(recipient),
            "each recipient needs its own local evaluation"
        );
        assert!(!body.contains("SYNTHETIC-SMTP-SECRET-ONLY"));
    }
    f.assert_scope_refused(&f.send_recipient(&task, "four@example.invalid"));
    assert_eq!(bouncer.bodies.lock().unwrap().len(), 3);
    let retry = handle(&f.ctx, &f.send_recipient(&task, recipients[0]));
    assert_eq!(retry.error.unwrap().code, "mail_not_submitted");
    assert_eq!(bouncer.bodies.lock().unwrap().len(), 3);
    f.assert_no_contact();
    assert!(f.ctx.approvals.pending().is_empty());
    let status = handle(&f.ctx, &f.status(&task)).result.unwrap();
    assert_eq!(status["not_submitted"], 3);
    assert_eq!(status["remaining"], 0);
    assert_eq!(status["sent"], 0);
    let guard = f.ctx.vault.lock().unwrap();
    let activity = guard.as_ref().unwrap().recent_activity(50).unwrap();
    let refused: Vec<_> = activity
        .iter()
        .filter(|row| row.operation == "mail task access")
        .collect();
    assert_eq!(refused.len(), 2, "inactive task and fourth recipient");
    assert!(
        refused
            .iter()
            .all(|row| row.decision == apassy::vault::ActivityDecision::Deny)
    );
    assert!(!format!("{activity:?}").contains("example.invalid"));
}
