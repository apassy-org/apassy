//! Local SMTP task orchestration. No password, recipient or message enters a
//! returned receipt or the activity log. Account settings are owner vault fields:
//! visible custom details `SMTP host`, `SMTP port` (465: TLS; others: STARTTLS), `SMTP username`,
//! and `SMTP sender`. A Login may use its ordinary `username` instead. Exactly one
//! hidden field is required: `password` or a custom detail named `SMTP password`.
//! Both Login and Custom items are supported through the existing detail editor.

use std::path::PathBuf;

use serde_json::json;
use zeroize::Zeroizing;

use super::decide::{self, BrokerContext};
use super::mail_tasks::{
    MailTaskAccount, MailTaskBinding, MailTaskDraft, MailTaskOutcome, MailTaskRecipientState,
    MailTaskReservationResult, MailTaskSnapshot, MailTaskState,
};
use super::project::{Project, project_of};
use crate::agent::wire::{Action, WireRequest, WireResponse};
use crate::contracts::CredentialKind;
use crate::vault::exceptions::Standing;
use crate::vault::{ActivityDecision, AgentSummary, NewActivity, Vault, custom_detail_label};

fn unavailable() -> WireResponse {
    WireResponse::failure(
        "mail_task_unavailable",
        "This mail task is unavailable in the current context.",
    )
}

struct Caller {
    agent: AgentSummary,
    cwd: PathBuf,
    project: Project,
    context_id: String,
    verified_task: bool,
}

struct Checked {
    caller: Caller,
    binding: MailTaskBinding,
    account: MailTaskAccount,
    password_field: String,
    always_ask: bool,
}

/// Host session is mandatory even when there is no verified hook. In that case
/// the unpredictable scope ID and exact owner-approved purpose form the task;
/// untrusted caller prose cannot silently replace that purpose on a later send.
fn caller(
    ctx: &BrokerContext,
    vault: &mut Vault,
    request: &WireRequest,
    cwd: &str,
) -> Result<Caller, WireResponse> {
    let agent = decide::authenticate(vault, &request.token, "mail task")?;
    let session = request
        .host_session
        .as_deref()
        .filter(|value| {
            !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
        })
        .ok_or_else(unavailable)?;
    if super::operations::cancelled() {
        return Err(super::operations::cancelled_response());
    }
    let cwd = std::fs::canonicalize(cwd)
        .ok()
        .filter(|p| p.is_dir())
        .ok_or_else(unavailable)?;
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let project = project_of(&cwd, home.as_deref()).ok_or_else(unavailable)?;
    // An MCP adapter without a native host session supplies only a process-local
    // random binding. It is not hook evidence: resolving it by directory could
    // accidentally borrow a different host's task. The exact owner-approved
    // purpose is the sole task context for this process-scoped path.
    let prompt = (!crate::agent::wire::is_mail_process_session(session)).then(|| {
        ctx.prompts
            .resolve(agent.id, &vault.epoch(), Some(session), &cwd, "")
    });
    if prompt.as_ref().is_some_and(|prompt| {
        !prompt.flags.is_empty() || prompt.source.contains("another host session")
    }) {
        return Err(unavailable());
    }
    let verified_task = prompt
        .as_ref()
        .is_some_and(|prompt| prompt.source.contains("verified in the host transcript"));
    let mut bytes = b"apassy-mail-task-context-v1\0".to_vec();
    for value in [
        session,
        if verified_task {
            prompt.as_ref().map_or("", |prompt| prompt.text.as_str())
        } else {
            ""
        },
    ] {
        bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    let context_id = ring::digest::digest(&ring::digest::SHA256, &bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(Caller {
        agent,
        cwd,
        project,
        context_id,
        verified_task,
    })
}

fn account(vault: &Vault, item: u64) -> Result<(MailTaskAccount, String, u64), WireResponse> {
    let details = vault.details(item).map_err(|_| unavailable())?;
    if !matches!(
        details.summary.kind,
        CredentialKind::Login | CredentialKind::Custom
    ) {
        return Err(unavailable());
    }
    let hidden = details
        .fields
        .iter()
        .filter(|field| field.secret)
        .collect::<Vec<_>>();
    let [password] = hidden.as_slice() else {
        return Err(unavailable());
    };
    if password.name != "password"
        && custom_detail_label(&password.name).as_deref() != Some("SMTP password")
    {
        return Err(unavailable());
    }
    let read = |label: &str, ordinary: Option<&str>| -> Result<String, WireResponse> {
        let mut fields = details
            .fields
            .iter()
            .filter(|field| {
                !field.secret && custom_detail_label(&field.name).as_deref() == Some(label)
            })
            .collect::<Vec<_>>();
        if fields.is_empty() {
            fields = details
                .fields
                .iter()
                .filter(|field| !field.secret && ordinary == Some(field.name.as_str()))
                .collect();
        }
        let [field] = fields.as_slice() else {
            return Err(unavailable());
        };
        let value = vault.reveal(item, &field.name).map_err(|_| unavailable())?;
        Ok(value.expose().to_owned())
    };
    let host = read("SMTP host", None)?;
    let port = read("SMTP port", None)?
        .parse::<u16>()
        .map_err(|_| unavailable())?;
    let user = read(
        "SMTP username",
        (details.summary.kind == CredentialKind::Login).then_some("username"),
    )?;
    let sender = read("SMTP sender", None)?;
    if port == 0
        || host.len() > 253
        || !host.contains('.')
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        || user.is_empty()
        || user.len() > 512
        || user.chars().any(char::is_control)
        || !super::mail_tasks::valid_mail_recipient(&sender)
    {
        return Err(unavailable());
    }
    Ok((
        MailTaskAccount {
            host,
            port,
            user,
            sender,
        },
        password.name.clone(),
        details.summary.revision,
    ))
}

fn check(
    ctx: &BrokerContext,
    vault: &mut Vault,
    request: &WireRequest,
    cwd: &str,
    item: u64,
) -> Result<Checked, WireResponse> {
    let caller = caller(ctx, vault, request, cwd)?;
    let view = vault
        .agent_view(caller.agent.id)
        .map_err(|_| unavailable())?;
    if view.standing(item) == Standing::Never
        || vault.needs_review(item).unwrap_or(true)
        || vault.is_archived(item).unwrap_or(true)
        || vault
            .cloud_agent_ids()
            .map_or(true, |ids| ids.contains(&caller.agent.id))
    {
        return Err(unavailable());
    }
    let always_ask = vault.always_ask(item).map_err(|_| unavailable())?
        || view.standing(item) == Standing::AlwaysAsk;
    let declaration = vault.declaration(item).map_err(|_| unavailable())?;
    if declaration.as_ref().is_some_and(|value| {
        super::run::foreign_project(&value.project, Some(&caller.project)).is_some()
    }) {
        return Err(unavailable());
    }
    let (account, password_field, item_revision) = account(vault, item)?;
    let policy_digest = vault
        .access_policy_digest(
            caller.agent.id,
            item,
            &caller.cwd.to_string_lossy(),
            &caller.project.key,
        )
        .map_err(|_| unavailable())?;
    let binding = MailTaskBinding {
        agent_id: caller.agent.id,
        project_key: caller.project.key.clone(),
        vault_epoch: vault.epoch(),
        item_revision,
        context_id: caller.context_id.clone(),
        policy_digest,
    };
    Ok(Checked {
        caller,
        binding,
        account,
        password_field,
        always_ask,
    })
}

fn check_snapshot(
    ctx: &BrokerContext,
    vault: &mut Vault,
    request: &WireRequest,
    cwd: &str,
    scope: &MailTaskSnapshot,
) -> Result<Checked, WireResponse> {
    let current = check(ctx, vault, request, cwd, scope.draft.item_id)?;
    if current.binding != scope.binding || current.account != scope.account {
        return Err(unavailable());
    }
    Ok(current)
}

pub(super) fn handle(ctx: &BrokerContext, request: &WireRequest) -> WireResponse {
    let response = match &request.action {
        Action::PrepareMailTask {
            item_id,
            recipients,
            subject,
            body,
            ttl_minutes,
            purpose,
            cwd,
        } => prepare(
            ctx,
            request,
            cwd,
            MailTaskDraft {
                item_id: *item_id,
                recipients: recipients.clone(),
                subject: subject.clone(),
                body: body.clone(),
                ttl_minutes: *ttl_minutes,
                purpose: purpose.clone(),
            },
        ),
        Action::SendTaskMail {
            task_id,
            recipient,
            cwd,
            user_request,
        } => send(ctx, request, task_id, recipient, cwd, user_request),
        Action::MailTaskStatus { task_id, cwd } => status(ctx, request, task_id, cwd),
        _ => WireResponse::failure("invalid_request", "This is not a mail task request."),
    };
    if let Some(error) = &response.error {
        record_request_failure(ctx, &request.token, &error.code);
    }
    response
}

/// Approval outcomes have their own decision. Record independent scope and transport
/// failures without turning a timeout or an in-flight retry into another refusal.
fn record_request_failure(ctx: &BrokerContext, token: &str, code: &str) {
    let (decision, operation, reason) = match code {
        "mail_task_unavailable" => (
            ActivityDecision::Deny,
            "mail task access",
            "An approved mail task matching this request is unavailable.",
        ),
        "invalid_mail_task" => (
            ActivityDecision::Deny,
            "mail task access",
            "The proposed mail task has invalid scope or message fields.",
        ),
        "mail_not_submitted" => (
            ActivityDecision::Error,
            "mail task",
            "The message was not submitted. A new attempt requires another reviewed task.",
        ),
        "mail_submission_unknown" => (
            ActivityDecision::Error,
            "mail task",
            "The SMTP server may have accepted the message. This task cannot send it again.",
        ),
        "mail_content_unavailable" | "mail_audit_unavailable" => (
            ActivityDecision::Error,
            "mail task",
            "Apassy could not complete the authorization checks for this send.",
        ),
        _ => return,
    };
    let mut guard = decide::lock(&ctx.vault);
    let Some(vault) = guard.as_mut().filter(|v| !v.is_locked()) else {
        return;
    };
    let Ok(agent) = vault.authenticate_agent(token) else {
        return;
    };
    let _ = vault.record_activity(&NewActivity {
        agent_id: Some(agent.id),
        agent_name: agent.name,
        item_id: None,
        operation: operation.into(),
        decision,
        reason: reason.into(),
    });
    if decision == ActivityDecision::Deny && crate::decision_log::enabled() {
        crate::decision_log::append(&crate::decision_log::Line {
            at: super::learning::now(),
            request: "mail_task_access".into(),
            agent: agent.id.to_string(),
            route: "Refused".into(),
            reason: "AccessCheck".into(),
            outcome: "refused".into(),
            code: code.into(),
            ..Default::default()
        });
    }
}

fn status(ctx: &BrokerContext, request: &WireRequest, task_id: &str, cwd: &str) -> WireResponse {
    let mut guard = decide::lock(&ctx.vault);
    let Some(vault) = guard.as_mut().filter(|v| !v.is_locked()) else {
        return decide::locked_response();
    };
    let caller = match caller(ctx, vault, request, cwd) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let scope = match ctx.approvals.mail_tasks().snapshot_for_context(
        task_id,
        caller.agent.id,
        &caller.project.key,
        &vault.epoch(),
        &caller.context_id,
    ) {
        Ok(s) => s,
        Err(_) => return unavailable(),
    };
    if let Err(response) = check_snapshot(ctx, vault, request, cwd, &scope) {
        return response;
    }
    let count = |state| {
        scope
            .recipient_states
            .iter()
            .filter(|(_, value)| *value == state)
            .count()
    };
    WireResponse::success(json!({"task_id": task_id,
        "state": match scope.state { MailTaskState::Pending => "pending", MailTaskState::Active => "active",
            MailTaskState::Denied => "denied", MailTaskState::Revoked => "revoked", MailTaskState::Expired => "expired" },
        "expires_in_seconds": scope.remaining_seconds, "total": scope.recipient_states.len(),
        "remaining": count(MailTaskRecipientState::Ready), "in_flight": count(MailTaskRecipientState::InFlight),
        "sent": count(MailTaskRecipientState::Finished(MailTaskOutcome::Success)),
        "unknown": count(MailTaskRecipientState::Finished(MailTaskOutcome::Unknown)),
        "not_submitted": count(MailTaskRecipientState::Finished(MailTaskOutcome::PreSendFailure))}))
}

fn prepare(
    ctx: &BrokerContext,
    request: &WireRequest,
    cwd: &str,
    draft: MailTaskDraft,
) -> WireResponse {
    let mut guard = decide::lock(&ctx.vault);
    let Some(vault) = guard.as_mut().filter(|v| !v.is_locked()) else {
        return decide::locked_response();
    };
    let checked = match check(ctx, vault, request, cwd, draft.item_id) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let snapshot = match ctx
        .approvals
        .mail_tasks()
        .propose(draft, checked.binding, checked.account)
    {
        Ok(scope) => scope,
        Err(super::mail_tasks::MailTaskError::Capacity) => {
            return WireResponse::failure("busy", "The mail task table is full.");
        }
        Err(_) => {
            return WireResponse::failure(
                "invalid_mail_task",
                "The mail task could not be prepared.",
            );
        }
    };
    if super::operations::bind_mail_task(
        ctx.approvals.mail_tasks(),
        checked.caller.agent.id,
        vault.epoch(),
        &snapshot.id,
    ) {
        return super::operations::cancelled_response();
    }
    drop(guard);
    ctx.approvals.notify_owner();
    WireResponse::success(
        json!({"task_id": snapshot.id, "state": "pending", "expires_in_seconds": snapshot.remaining_seconds}),
    )
}

fn outcome(task_id: &str, result: MailTaskOutcome, replayed: bool) -> WireResponse {
    match result {
        MailTaskOutcome::Success => {
            if replayed {
                super::operations::observed_effect();
            }
            WireResponse::success(
                json!({"task_id": task_id, "status": "sent", "replayed": replayed}),
            )
        }
        MailTaskOutcome::Unknown => {
            super::operations::observed_effect();
            WireResponse::failure(
                "mail_submission_unknown",
                "The server may have accepted this message. Do not retry; its recipient slot is permanently consumed.",
            )
        }
        MailTaskOutcome::PreSendFailure => WireResponse::failure(
            "mail_not_submitted",
            "The message was not submitted. This recipient slot is consumed; another attempt requires a new task and owner approval.",
        ),
    }
}

fn send(
    ctx: &BrokerContext,
    request: &WireRequest,
    task_id: &str,
    recipient: &str,
    cwd: &str,
    intent: &str,
) -> WireResponse {
    send_with(
        ctx,
        request,
        task_id,
        recipient,
        cwd,
        intent,
        |scope, recipient, password, before_auth, before_data| {
            super::task_smtp::submit_checked(
                &scope.account.host,
                scope.account.port,
                &scope.account.user,
                password,
                &scope.account.sender,
                recipient,
                &scope.draft.subject,
                &scope.draft.body,
                before_auth,
                before_data,
            )
        },
    )
}

/// Private transport dependency: tests exercise broker admission and the real
/// per-message approval queue without opening a socket or sending credentials.
fn send_with(
    ctx: &BrokerContext,
    request: &WireRequest,
    task_id: &str,
    recipient: &str,
    cwd: &str,
    intent: &str,
    submit: impl FnOnce(
        &MailTaskSnapshot,
        &str,
        &str,
        &dyn Fn() -> bool,
        &dyn Fn() -> bool,
    ) -> Result<(), super::task_smtp::SubmissionError>,
) -> WireResponse {
    let registry = ctx.approvals.mail_tasks();
    let (scope, checked, reservation) = {
        let mut guard = decide::lock(&ctx.vault);
        let Some(vault) = guard.as_mut().filter(|v| !v.is_locked()) else {
            return decide::locked_response();
        };
        let caller = match caller(ctx, vault, request, cwd) {
            Ok(c) => c,
            Err(e) => return e,
        };
        let scope = match registry.snapshot_for_context(
            task_id,
            caller.agent.id,
            &caller.project.key,
            &vault.epoch(),
            &caller.context_id,
        ) {
            Ok(scope) => scope,
            Err(_) => return unavailable(),
        };
        let checked = match check_snapshot(ctx, vault, request, cwd, &scope) {
            Ok(c) => c,
            Err(e) => return e,
        };
        if !checked.caller.verified_task && intent.trim() != scope.draft.purpose.trim() {
            return unavailable();
        }
        if !scope.draft.recipients.iter().any(|r| r == recipient) {
            return unavailable();
        }
        // Reserving before the policy wait prevents concurrent duplicate prompts
        // and makes an owner/model denial terminal for this recipient.
        let reservation =
            match registry.reserve(task_id, &checked.binding, &checked.account, recipient) {
                Ok(MailTaskReservationResult::Reserved(reservation)) => reservation,
                Ok(MailTaskReservationResult::Previous(previous)) => {
                    return outcome(task_id, previous, true);
                }
                Ok(MailTaskReservationResult::InFlight) => {
                    return WireResponse::failure(
                        "mail_task_in_flight",
                        "This recipient already has a pending send.",
                    );
                }
                Err(_) => return unavailable(),
            };
        (scope, checked, reservation)
    };
    let live = || {
        let mut guard = decide::lock(&ctx.vault);
        guard
            .as_mut()
            .filter(|v| !v.is_locked())
            .is_some_and(|vault| {
                check_snapshot(ctx, vault, request, cwd, &scope).is_ok()
                    && registry.reservation_valid(&reservation).unwrap_or(false)
            })
    };
    let authorization = match super::mail_policy::authorize(
        ctx,
        &scope,
        recipient,
        &checked.caller.agent,
        &checked.caller.cwd,
        request.host_session.as_deref(),
        intent,
        !checked.caller.verified_task,
        checked.always_ask,
        live,
    ) {
        Ok(auth) => auth,
        Err(response) => {
            let _ = registry.finish(reservation, MailTaskOutcome::PreSendFailure);
            return response;
        }
    };
    let password = {
        let mut guard = decide::lock(&ctx.vault);
        let Some(vault) = guard.as_mut().filter(|v| !v.is_locked()) else {
            let _ = registry.finish(reservation, MailTaskOutcome::PreSendFailure);
            return decide::locked_response();
        };
        if check_snapshot(ctx, vault, request, cwd, &scope).is_err()
            || !registry.reservation_valid(&reservation).unwrap_or(false)
        {
            let _ = registry.finish(reservation, MailTaskOutcome::PreSendFailure);
            return unavailable();
        }
        match vault.reveal(scope.draft.item_id, &checked.password_field) {
            Ok(value) => Zeroizing::new(value.expose().to_owned()),
            Err(_) => {
                let _ = registry.finish(reservation, MailTaskOutcome::PreSendFailure);
                return unavailable();
            }
        }
    };
    let before_auth = || {
        let mut guard = decide::lock(&ctx.vault);
        guard
            .as_mut()
            .filter(|v| !v.is_locked())
            .is_some_and(|vault| {
                check_snapshot(ctx, vault, request, cwd, &scope).is_ok()
                    && registry.reservation_valid(&reservation).unwrap_or(false)
                    && super::operations::start_effect()
            })
    };
    let result = submit(&scope, recipient, &password, &before_auth, &live);
    drop(password);
    let disposition = match result {
        Ok(()) => MailTaskOutcome::Success,
        Err(error) if error.outcome == super::task_smtp::SubmissionOutcome::Unknown => {
            MailTaskOutcome::Unknown
        }
        Err(_) => MailTaskOutcome::PreSendFailure,
    };
    // If finishing is unavailable, the still in-flight capability also forbids a
    // retry. Never turn an SMTP ambiguity into a safe-to-retry result.
    let _ = registry.finish(reservation, disposition);
    let mut guard = decide::lock(&ctx.vault);
    if let Some(vault) = guard
        .as_mut()
        .filter(|v| !v.is_locked() && v.epoch() == scope.binding.vault_epoch)
    {
        let _ = vault.record_item_use(&crate::vault::usage::NewItemUse {
            item_id: scope.draft.item_id,
            agent_id: Some(checked.caller.agent.id),
            agent_name: checked.caller.agent.name,
            project_key: checked.caller.project.key,
            project_label: checked.caller.project.label,
            action: super::action_kind::ActionKind::Change,
            command_summary: match disposition {
                MailTaskOutcome::Success => "SMTP task accepted",
                MailTaskOutcome::Unknown => "SMTP task disposition unknown",
                MailTaskOutcome::PreSendFailure => "SMTP task not submitted",
            }
            .into(),
            hosts: vec![],
            // This row records the authorization. SMTP delivery disposition is
            // separate: a failed/unknown transport cannot turn an allowance into
            // a fabricated owner or model denial.
            outcome: crate::vault::usage::UseOutcome::Allowed,
            decided_by: authorization.decided_by,
            answered_on: authorization.answered_on,
            decision_log_id: authorization.decision_log_id,
        });
    }
    outcome(task_id, disposition, false)
}

#[cfg(test)]
mod tests {
    use super::super::approvals::{ApprovalQueue, OwnerAction, OwnerProof};
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    #[test]
    fn terminal_results_and_late_revocation_never_submit_twice() {
        for expected in [
            MailTaskOutcome::Success,
            MailTaskOutcome::Unknown,
            MailTaskOutcome::PreSendFailure,
        ] {
            let temp = tempfile::tempdir().unwrap();
            let mut vault = Vault::create(&temp.path().join("vault.db"), "synthetic-mail").unwrap();
            vault.unlock("synthetic-mail").unwrap();
            let item = vault
                .add(crate::vault::ItemDraft {
                    title: "Synthetic SMTP".into(),
                    kind: CredentialKind::Custom,
                    notes: String::new(),
                    tags: vec![],
                    fields: vec![
                        field("SMTP host", "smtp.example.test", false),
                        field("SMTP port", "587", false),
                        field("SMTP username", "test-user", false),
                        field("SMTP sender", "sender@example.test", false),
                        field("SMTP password", "synthetic-password", true),
                    ],
                })
                .unwrap()
                .id;
            let (agent, token) = vault.register_agent("Synthetic mail agent").unwrap();
            vault.set_agent_sees_all(agent.id, true).unwrap();
            let ctx = BrokerContext {
                vault: Arc::new(Mutex::new(Some(vault))),
                tls: super::super::http::TlsClient::platform().unwrap(),
                approvals: Arc::new(ApprovalQueue::new()),
                approval_timeout: Duration::from_secs(5),
                run_timeout: Duration::from_secs(1),
                bouncer: None,
                model_gate: None,
                prompts: Arc::new(super::super::prompts::PromptStore::new(vec![
                    temp.path().to_path_buf(),
                ])),
            };
            let cwd = temp.path().display().to_string();
            let action = Action::PrepareMailTask {
                item_id: item,
                recipients: vec!["recipient@example.test".into()],
                subject: "Private subject".into(),
                body: "Private body".into(),
                ttl_minutes: 5,
                purpose: "Send the approved update".into(),
                cwd: cwd.clone(),
            };
            let mut request = WireRequest {
                v: action.wire_version(),
                token: token.expose().into(),
                host_session: Some(if expected == MailTaskOutcome::Unknown {
                    crate::agent::wire::mail_process_session("00112233445566778899aabbccddeeff")
                        .unwrap()
                } else {
                    "synthetic-host-session".into()
                }),
                action,
            };
            if expected == MailTaskOutcome::Unknown {
                let transcript = temp.path().join("another-host-session.jsonl");
                std::fs::write(&transcript, serde_json::to_string(&json!({
                    "type": "user", "message": {"role":"user", "content":"Unrelated verified host task"}
                })).unwrap()).unwrap();
                assert!(
                    super::super::prompts::submit(
                        &ctx,
                        &request.token,
                        &super::super::prompts::Submission {
                            host: "claude-code",
                            host_session: Some("another-host-session"),
                            cwd: &cwd,
                            prompt: "Unrelated verified host task",
                            transcript_path: transcript.to_str(),
                            truncated: false,
                            source: Some("user")
                        }
                    )
                    .ok
                );
                let mut guard = decide::lock(&ctx.vault);
                let vault = guard.as_mut().unwrap();
                let resolved = ctx.prompts.resolve(
                    agent.id,
                    &vault.epoch(),
                    Some("another-host-session"),
                    std::path::Path::new(&cwd),
                    "",
                );
                assert!(resolved.source.contains("verified in the host transcript"));
                assert!(
                    !caller(&ctx, vault, &request, &cwd).unwrap().verified_task,
                    "MCP process binding must not borrow a different session's verified task"
                );
            }
            let prepared = handle(&ctx, &request);
            assert!(prepared.ok, "{prepared:?}");
            let id = prepared.result.unwrap()["task_id"]
                .as_str()
                .unwrap()
                .to_owned();
            let epoch = decide::lock(&ctx.vault).as_ref().unwrap().epoch();
            let scope = ctx
                .approvals
                .mail_tasks()
                .list_for_owner(&epoch)
                .unwrap()
                .remove(0);
            ctx.approvals
                .mail_tasks()
                .activate(
                    &id,
                    &epoch,
                    OwnerProof::issue_for_test(scope.owner_action(), epoch, Instant::now()),
                )
                .unwrap();
            request.action = Action::SendTaskMail {
                task_id: id.clone(),
                recipient: "recipient@example.test".into(),
                cwd: cwd.clone(),
                user_request: "Send the approved update".into(),
            };
            if expected == MailTaskOutcome::Unknown {
                let refused = send_with(
                    &ctx,
                    &request,
                    &id,
                    "recipient@example.test",
                    &cwd,
                    "Unrelated verified host task",
                    |_, _, _, _, _| panic!("task drift reached transport"),
                );
                assert_eq!(refused.error.unwrap().code, "mail_task_unavailable");
                let mut other_process = request.clone();
                other_process.host_session =
                    crate::agent::wire::mail_process_session("ffeeddccbbaa99887766554433221100");
                assert_eq!(
                    status(&ctx, &other_process, &id, &cwd).error.unwrap().code,
                    "mail_task_unavailable"
                );
                assert!(ctx.approvals.pending().is_empty());
            }
            let response = std::thread::scope(|threads| {
                let sending = threads.spawn(|| {
                    send_with(
                        &ctx,
                        &request,
                        &id,
                        "recipient@example.test",
                        &cwd,
                        "Send the approved update",
                        |scope, recipient, password, before_auth, before_data| {
                            assert_eq!(recipient, "recipient@example.test");
                            assert_eq!(password, "synthetic-password");
                            assert!(before_auth());
                            if expected == MailTaskOutcome::PreSendFailure {
                                ctx.approvals
                                    .mail_tasks()
                                    .revoke(&scope.id, &epoch)
                                    .unwrap();
                                assert!(!before_data());
                                return Err(super::super::task_smtp::SubmissionError {
                                    outcome:
                                        super::super::task_smtp::SubmissionOutcome::NotSubmitted,
                                    step: "authorization",
                                    reply: None,
                                });
                            }
                            assert!(before_data());
                            if expected == MailTaskOutcome::Unknown {
                                Err(super::super::task_smtp::SubmissionError {
                                    outcome: super::super::task_smtp::SubmissionOutcome::Unknown,
                                    step: "message",
                                    reply: None,
                                })
                            } else {
                                Ok(())
                            }
                        },
                    )
                });
                let started = Instant::now();
                let pending = loop {
                    if let Some(pending) = ctx.approvals.pending().first().cloned() {
                        break pending;
                    }
                    assert!(
                        started.elapsed() < Duration::from_secs(5),
                        "send did not ask the owner"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                };
                ctx.approvals
                    .approve(OwnerProof::issue_for_test(
                        OwnerAction::ApproveRun(pending),
                        epoch,
                        Instant::now(),
                    ))
                    .unwrap();
                sending.join().unwrap()
            });
            assert_eq!(response.ok, expected == MailTaskOutcome::Success);
            let replay = send_with(
                &ctx,
                &request,
                &id,
                "recipient@example.test",
                &cwd,
                "Send the approved update",
                |_, _, _, _, _| panic!("terminal recipient was submitted again"),
            );
            assert_eq!(replay.ok, response.ok);
            assert_eq!(
                replay.error.as_ref().map(|e| &e.code),
                response.error.as_ref().map(|e| &e.code)
            );
            let status = status(&ctx, &request, &id, &cwd).result.unwrap();
            let count = match expected {
                MailTaskOutcome::Success => "sent",
                MailTaskOutcome::Unknown => "unknown",
                MailTaskOutcome::PreSendFailure => "not_submitted",
            };
            assert_eq!(status[count], 1);
            let output = serde_json::to_string(&replay).unwrap();
            for sensitive in [
                "synthetic-password",
                "recipient@example.test",
                "Private subject",
                "Private body",
            ] {
                assert!(!output.contains(sensitive));
            }
        }
    }

    fn field(label: &str, value: &str, secret: bool) -> crate::vault::Field {
        crate::vault::Field {
            name: format!(
                "x_{}",
                label
                    .as_bytes()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            ),
            value: crate::vault::SecretValue::new(value.into()),
            secret,
        }
    }

    #[test]
    fn account_accepts_only_one_explicit_secret_and_owner_smtp_fields() {
        let temp = tempfile::tempdir().unwrap();
        let mut vault = Vault::create(&temp.path().join("vault.db"), "synthetic-mail").unwrap();
        vault.unlock("synthetic-mail").unwrap();
        let draft = crate::vault::ItemDraft {
            title: "Synthetic SMTP".into(),
            kind: CredentialKind::Custom,
            notes: String::new(),
            tags: vec![],
            fields: vec![
                field("SMTP host", "smtp.example.test", false),
                field("SMTP port", "587", false),
                field("SMTP username", "test-user", false),
                field("SMTP sender", "sender@example.test", false),
                field("SMTP password", "synthetic-password", true),
            ],
        };
        let item = vault.add(draft.clone()).unwrap();
        let (settings, _, _) = account(&vault, item.id).unwrap();
        assert_eq!(settings.port, 587);
        let mut duplicate = draft.clone();
        duplicate
            .fields
            .push(field("Other secret", "not-mail", true));
        let item = vault.add(duplicate).unwrap();
        assert!(account(&vault, item.id).is_err());
        let mut spoof = draft.clone();
        spoof.fields[0] = field("SMTP host", "smtp.example.test\r\nAUTH", false);
        let item = vault.add(spoof).unwrap();
        assert!(account(&vault, item.id).is_err());
    }
}
