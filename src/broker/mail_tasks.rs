//! Bounded, process-local owner consent for one immutable SMTP task.
//!
//! Inputs in `MailTaskBinding` and `MailTaskAccount` come from the authenticated
//! broker and freshly read vault, never from the agent's proposed draft. Callers
//! hold the vault lock while checking the current epoch/revision/account and while
//! activating or reserving. The registry mutex is always acquired after that lock.
//! A reservation is made at the last pre-send boundary, after any policy wait.
//! Neither an SMTP ambiguity nor a dropped reservation permits another send.
//! Restart loses grants: no task can be resumed without a new owner approval.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use zeroize::Zeroize;

use super::approvals::{CheckMethod, OwnerAction, OwnerProof};

pub const MAX_MAIL_TASKS: usize = 64;
pub const MAX_MAIL_RECIPIENTS: usize = 100;
pub const MAX_MAIL_TASK_MINUTES: u16 = 30;
pub const MAX_MAIL_BODY_BYTES: usize = 16 * 1024;

/// The only fields an agent may propose. Text is literal plain text; there is no
/// template interpreter, HTML, attachment, CC, BCC, custom header, or URL fetch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailTaskDraft {
    pub item_id: u64,
    pub recipients: Vec<String>,
    pub subject: String,
    pub body: String,
    pub ttl_minutes: u16,
    pub purpose: String,
}

/// Authenticated broker facts. `context_id` binds the host/session/task context;
/// `project_key` is the broker-resolved canonical project, not an agent label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailTaskBinding {
    pub agent_id: u64,
    pub project_key: String,
    pub vault_epoch: [u8; 32],
    pub item_revision: u64,
    pub context_id: String,
    /// Broker-computed digest of item policy, agent/token and rule generations.
    pub policy_digest: String,
}

/// Non-secret snapshot from separately validated owner-controlled SMTP settings.
/// No credential is stored here. The dispatcher must revalidate these settings
/// and the item revision immediately before reserving and using the credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailTaskAccount {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub sender: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailTaskState {
    Pending,
    Active,
    Denied,
    Revoked,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailTaskOutcome {
    Success,
    /// Delivery may have happened. Retrying is prohibited.
    Unknown,
    /// No message was sent. This reservation is nevertheless terminal; a new
    /// task and owner approval are needed for another attempt.
    PreSendFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailTaskRecipientState {
    Ready,
    InFlight,
    Finished(MailTaskOutcome),
}

/// A detached display copy; modifying it cannot modify the stored grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailTaskSnapshot {
    pub id: String,
    pub digest: String,
    pub draft: MailTaskDraft,
    pub binding: MailTaskBinding,
    pub account: MailTaskAccount,
    pub state: MailTaskState,
    pub recipient_states: Vec<(String, MailTaskRecipientState)>,
    pub remaining_seconds: u64,
}

impl MailTaskSnapshot {
    pub fn owner_action(&self) -> OwnerAction {
        OwnerAction::ActivateMailTask {
            scope_id: self.id.clone(),
            scope_digest: self.digest.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailTaskError {
    InvalidDraft,
    InvalidBinding,
    InvalidAccount,
    Capacity,
    RandomUnavailable,
    Unavailable,
    NotPending,
    NotActive,
    RecipientOutsideScope,
    OwnerProof,
    InvalidReservation,
    Poisoned,
}

impl fmt::Display for MailTaskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidDraft => {
                "Invalid mail task: use bounded plain text and distinct exact recipients."
            }
            Self::InvalidBinding => "The authenticated mail task context is invalid.",
            Self::InvalidAccount => "The owner-controlled SMTP account settings are invalid.",
            Self::Capacity => {
                "The mail task limit is reached. Wait for an existing task to expire."
            }
            Self::RandomUnavailable => "A secure mail task identifier could not be generated.",
            Self::Unavailable => "This mail task is unavailable in the current context.",
            Self::NotPending => "This mail task is no longer waiting for owner approval.",
            Self::NotActive => "This mail task is not active.",
            Self::RecipientOutsideScope => "This recipient is outside the approved mail task.",
            Self::OwnerProof => "Fresh local owner approval for this exact mail task is required.",
            Self::InvalidReservation => "This mail reservation cannot be completed.",
            Self::Poisoned => "The mail task registry is unavailable.",
        })
    }
}
impl std::error::Error for MailTaskError {}

/// A single-use capability returned only by the atomic reservation operation.
/// It intentionally has no Clone and no public constructor or mutable fields.
#[derive(Debug)]
pub struct MailTaskReservation {
    task_id: String,
    recipient: String,
    account: MailTaskAccount,
    subject: String,
    body: String,
    nonce: String,
}
impl MailTaskReservation {
    pub fn task_id(&self) -> &str {
        &self.task_id
    }
    pub fn recipient(&self) -> &str {
        &self.recipient
    }
    pub fn account(&self) -> &MailTaskAccount {
        &self.account
    }
    pub fn subject(&self) -> &str {
        &self.subject
    }
    pub fn body(&self) -> &str {
        &self.body
    }
}
impl Drop for MailTaskReservation {
    fn drop(&mut self) {
        self.task_id.zeroize();
        self.recipient.zeroize();
        self.subject.zeroize();
        self.body.zeroize();
        self.account.host.zeroize();
        self.account.user.zeroize();
        self.account.sender.zeroize();
        self.nonce.zeroize();
    }
}

#[derive(Debug)]
pub enum MailTaskReservationResult {
    Reserved(MailTaskReservation),
    InFlight,
    Previous(MailTaskOutcome),
}

struct Recipient {
    state: MailTaskRecipientState,
    nonce: Option<String>,
}
struct Task {
    snapshot: MailTaskSnapshot,
    deadline: Instant,
    recipients: BTreeMap<String, Recipient>,
    operation_cancelled: bool,
}
impl Task {
    fn view(&self, now: Instant) -> MailTaskSnapshot {
        let mut snapshot = self.snapshot.clone();
        if now >= self.deadline
            && matches!(
                snapshot.state,
                MailTaskState::Pending | MailTaskState::Active
            )
        {
            snapshot.state = MailTaskState::Expired;
        }
        snapshot.remaining_seconds = self.deadline.saturating_duration_since(now).as_secs();
        snapshot.recipient_states = self
            .recipients
            .iter()
            .map(|(address, recipient)| (address.clone(), recipient.state))
            .collect();
        snapshot
    }
    fn live(&self, now: Instant) -> bool {
        now < self.deadline
    }

    fn cancel_pending(&mut self, now: Instant) -> Result<(), MailTaskError> {
        // A retry of this cancellation remains idempotent even after the original
        // deadline. A denial or an unrelated owner revocation is not cancellation.
        if self.operation_cancelled {
            return Ok(());
        }
        if !self.live(now) || self.snapshot.state != MailTaskState::Pending {
            return Err(MailTaskError::NotPending);
        }
        self.snapshot.state = MailTaskState::Revoked;
        self.operation_cancelled = true;
        Ok(())
    }
}

impl Drop for Task {
    fn drop(&mut self) {
        // Remove registry-owned plaintext as well as logical access on session
        // end. Detached UI/transport snapshots remain owned by their callers.
        self.snapshot.draft.subject.zeroize();
        self.snapshot.draft.body.zeroize();
        self.snapshot.draft.purpose.zeroize();
        self.snapshot.draft.recipients.zeroize();
        self.snapshot.binding.project_key.zeroize();
        self.snapshot.binding.context_id.zeroize();
        self.snapshot.binding.policy_digest.zeroize();
        self.snapshot.account.host.zeroize();
        self.snapshot.account.user.zeroize();
        self.snapshot.account.sender.zeroize();
        for (mut address, mut recipient) in std::mem::take(&mut self.recipients) {
            address.zeroize();
            recipient.nonce.zeroize();
        }
    }
}

#[derive(Default)]
pub struct MailTaskRegistry {
    tasks: Mutex<BTreeMap<String, Task>>,
}
impl MailTaskRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> Result<MutexGuard<'_, BTreeMap<String, Task>>, MailTaskError> {
        // A panic may have interrupted a state transition. Never recover consent
        // from a poisoned lock by assuming the transition was atomic.
        self.tasks.lock().map_err(|_| MailTaskError::Poisoned)
    }

    pub fn propose(
        &self,
        draft: MailTaskDraft,
        binding: MailTaskBinding,
        account: MailTaskAccount,
    ) -> Result<MailTaskSnapshot, MailTaskError> {
        self.propose_at(draft, binding, account, Instant::now())
    }

    fn propose_at(
        &self,
        draft: MailTaskDraft,
        binding: MailTaskBinding,
        account: MailTaskAccount,
        now: Instant,
    ) -> Result<MailTaskSnapshot, MailTaskError> {
        validate(&draft, &binding, &account)?;
        let mut tasks = self.lock()?;
        // Never evict an unexpired scope, including denied/revoked scopes and all
        // their reservation results. This makes pressure unable to reset sends.
        tasks.retain(|_, task| task.live(now));
        if tasks.len() >= MAX_MAIL_TASKS {
            return Err(MailTaskError::Capacity);
        }
        let mut id = random_id()?;
        while tasks.contains_key(&id) {
            id = random_id()?;
        }
        let digest = scope_digest(&id, &draft, &binding, &account);
        let deadline = now + Duration::from_secs(u64::from(draft.ttl_minutes) * 60);
        let recipients = draft
            .recipients
            .iter()
            .map(|address| {
                (
                    address.clone(),
                    Recipient {
                        state: MailTaskRecipientState::Ready,
                        nonce: None,
                    },
                )
            })
            .collect();
        let task = Task {
            snapshot: MailTaskSnapshot {
                id: id.clone(),
                digest,
                draft,
                binding,
                account,
                state: MailTaskState::Pending,
                recipient_states: Vec::new(),
                remaining_seconds: 0,
            },
            deadline,
            recipients,
            operation_cancelled: false,
        };
        let snapshot = task.view(now);
        tasks.insert(id, task);
        Ok(snapshot)
    }

    /// Agent lookup checks every binding field, with the same refusal for missing
    /// IDs and foreign scopes. A task ID alone is never a read capability.
    pub fn snapshot(
        &self,
        id: &str,
        binding: &MailTaskBinding,
    ) -> Result<MailTaskSnapshot, MailTaskError> {
        let tasks = self.lock()?;
        let task = tasks
            .get(id)
            .filter(|t| &t.snapshot.binding == binding)
            .ok_or(MailTaskError::Unavailable)?;
        Ok(task.view(Instant::now()))
    }

    /// Resolve the item only after checking all authenticated request identity.
    /// The dispatcher must then fetch the live revision and policy digest before
    /// reserving; this lookup itself conveys no permission to send.
    pub fn snapshot_for_context(
        &self,
        id: &str,
        agent_id: u64,
        project_key: &str,
        vault_epoch: &[u8; 32],
        context_id: &str,
    ) -> Result<MailTaskSnapshot, MailTaskError> {
        let tasks = self.lock()?;
        let task = tasks
            .get(id)
            .filter(|task| {
                let binding = &task.snapshot.binding;
                binding.agent_id == agent_id
                    && binding.project_key == project_key
                    && &binding.vault_epoch == vault_epoch
                    && binding.context_id == context_id
            })
            .ok_or(MailTaskError::Unavailable)?;
        Ok(task.view(Instant::now()))
    }

    /// Owner-only UI path. Caller supplies the currently unlocked vault's epoch.
    pub fn list_for_owner(&self, epoch: &[u8; 32]) -> Result<Vec<MailTaskSnapshot>, MailTaskError> {
        let now = Instant::now();
        Ok(self
            .lock()?
            .values()
            .filter(|t| &t.snapshot.binding.vault_epoch == epoch)
            .map(|t| t.view(now))
            .collect())
    }

    /// Badge count only; does not clone any recipient, message or account data.
    pub fn pending_count(&self, epoch: &[u8; 32]) -> Result<usize, MailTaskError> {
        let tasks = self.lock()?;
        let now = Instant::now();
        Ok(tasks
            .values()
            .filter(|task| {
                &task.snapshot.binding.vault_epoch == epoch
                    && task.snapshot.state == MailTaskState::Pending
                    && task.live(now)
            })
            .count())
    }

    /// Destructively end an already-ended vault session (lock, close or switch).
    /// The vault's session-end hook calls this even when no future proposal arrives.
    /// Missing grants fence every reservation and replay; ordinary revoke must
    /// instead retain its grants/results until expiry. Callers must also discard
    /// detached display/transport copies when their vault-session fence fails.
    pub fn clear_session(&self, epoch: &[u8; 32]) {
        // Destruction is safe even after a panic; keep the mutex poisoned so all
        // subsequent consent operations still fail closed.
        let mut tasks = self
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tasks.retain(|_, task| &task.snapshot.binding.vault_epoch != epoch);
    }

    /// Caller holds the current unlocked vault while consuming this proof. The
    /// OwnerGate's action policy must require a fresh local check, never a window.
    pub fn activate(
        &self,
        id: &str,
        epoch: &[u8; 32],
        proof: OwnerProof,
    ) -> Result<(), MailTaskError> {
        self.activate_at(id, epoch, proof, Instant::now())
    }
    fn activate_at(
        &self,
        id: &str,
        epoch: &[u8; 32],
        proof: OwnerProof,
        now: Instant,
    ) -> Result<(), MailTaskError> {
        let mut tasks = self.lock()?;
        let task = tasks
            .get_mut(id)
            .filter(|t| &t.snapshot.binding.vault_epoch == epoch)
            .ok_or(MailTaskError::Unavailable)?;
        if !task.live(now)
            || !task.live(Instant::now())
            || task.snapshot.state != MailTaskState::Pending
        {
            return Err(MailTaskError::NotPending);
        }
        if !matches!(
            proof.method(),
            CheckMethod::TouchId | CheckMethod::Passphrase | CheckMethod::Polkit
        ) || proof.check(&task.snapshot.owner_action(), epoch).is_err()
        {
            return Err(MailTaskError::OwnerProof);
        }
        task.snapshot.state = MailTaskState::Active;
        Ok(())
    }

    pub fn deny(&self, id: &str, epoch: &[u8; 32]) -> Result<(), MailTaskError> {
        self.end(id, epoch, MailTaskState::Denied)
    }
    pub fn revoke(&self, id: &str, epoch: &[u8; 32]) -> Result<(), MailTaskError> {
        self.end(id, epoch, MailTaskState::Revoked)
    }
    /// Explicit authenticated cancellation can withdraw a pending proposal. It
    /// cannot activate a grant or operate on another request's task.
    pub fn cancel_pending(&self, id: &str, binding: &MailTaskBinding) -> Result<(), MailTaskError> {
        let mut tasks = self.lock()?;
        let task = tasks
            .get_mut(id)
            .filter(|t| &t.snapshot.binding == binding)
            .ok_or(MailTaskError::Unavailable)?;
        task.cancel_pending(Instant::now())
    }
    /// Operation receipts already bind the exact opaque proposal ID. They need
    /// only agent/session identity to withdraw that pending proposal; active
    /// scopes cannot be cancelled through this weaker lookup.
    pub(super) fn cancel_pending_operation(
        &self,
        id: &str,
        agent_id: u64,
        epoch: &[u8; 32],
    ) -> Result<(), MailTaskError> {
        let mut tasks = self.lock()?;
        let task = tasks
            .get_mut(id)
            .filter(|task| {
                task.snapshot.binding.agent_id == agent_id
                    && &task.snapshot.binding.vault_epoch == epoch
            })
            .ok_or(MailTaskError::Unavailable)?;
        task.cancel_pending(Instant::now())
    }
    fn end(&self, id: &str, epoch: &[u8; 32], state: MailTaskState) -> Result<(), MailTaskError> {
        let mut tasks = self.lock()?;
        let task = tasks
            .get_mut(id)
            .filter(|t| &t.snapshot.binding.vault_epoch == epoch)
            .ok_or(MailTaskError::Unavailable)?;
        if !task.live(Instant::now()) {
            return Err(MailTaskError::Unavailable);
        }
        match (task.snapshot.state, state) {
            (MailTaskState::Pending, MailTaskState::Denied)
            | (MailTaskState::Pending | MailTaskState::Active, MailTaskState::Revoked) => {
                task.snapshot.state = state;
                Ok(())
            }
            _ => Err(MailTaskError::NotActive),
        }
    }

    /// Disconnect or authenticated-context changes fence all new reservations.
    /// An already admitted send can finish and retains its result. Actual vault
    /// session end uses `clear_session` to also remove stored plaintext.
    pub fn invalidate_all(&self) -> Result<(), MailTaskError> {
        for task in self.lock()?.values_mut() {
            if matches!(
                task.snapshot.state,
                MailTaskState::Pending | MailTaskState::Active
            ) {
                task.snapshot.state = MailTaskState::Revoked;
            }
        }
        Ok(())
    }

    pub fn reserve(
        &self,
        id: &str,
        binding: &MailTaskBinding,
        account: &MailTaskAccount,
        recipient: &str,
    ) -> Result<MailTaskReservationResult, MailTaskError> {
        self.reserve_at(id, binding, account, recipient, Instant::now())
    }
    fn reserve_at(
        &self,
        id: &str,
        binding: &MailTaskBinding,
        account: &MailTaskAccount,
        recipient: &str,
        now: Instant,
    ) -> Result<MailTaskReservationResult, MailTaskError> {
        let mut tasks = self.lock()?;
        let task = tasks
            .get_mut(id)
            .filter(|t| &t.snapshot.binding == binding && &t.snapshot.account == account)
            .ok_or(MailTaskError::Unavailable)?;
        let recipient_state = task
            .recipients
            .get(recipient)
            .ok_or(MailTaskError::RecipientOutsideScope)?;
        match recipient_state.state {
            MailTaskRecipientState::InFlight => return Ok(MailTaskReservationResult::InFlight),
            MailTaskRecipientState::Finished(outcome) => {
                return Ok(MailTaskReservationResult::Previous(outcome));
            }
            MailTaskRecipientState::Ready => {}
        }
        // Replay returns the recorded result even after revocation/expiry. Only
        // a new admission needs live consent. Re-read the clock under the mutex,
        // so waiting for this lock cannot extend a grant beyond its deadline.
        if !task.live(now)
            || !task.live(Instant::now())
            || task.snapshot.state != MailTaskState::Active
        {
            return Err(MailTaskError::NotActive);
        }
        let nonce = random_id()?;
        let recipient_state = task
            .recipients
            .get_mut(recipient)
            .ok_or(MailTaskError::RecipientOutsideScope)?;
        recipient_state.state = MailTaskRecipientState::InFlight;
        recipient_state.nonce = Some(nonce.clone());
        Ok(MailTaskReservationResult::Reserved(MailTaskReservation {
            task_id: id.to_owned(),
            recipient: recipient.to_owned(),
            nonce,
            account: task.snapshot.account.clone(),
            subject: task.snapshot.draft.subject.clone(),
            body: task.snapshot.draft.body.clone(),
        }))
    }

    /// Settlement may follow expiry/revocation; it never revives consent. Unknown
    /// and pre-send failures are terminal just like success. A dropped capability
    /// leaves InFlight forever (until expiry), which also prohibits a second send.
    pub fn finish(
        &self,
        reservation: MailTaskReservation,
        outcome: MailTaskOutcome,
    ) -> Result<(), MailTaskError> {
        let mut tasks = self.lock()?;
        let recipient = tasks
            .get_mut(&reservation.task_id)
            .and_then(|t| t.recipients.get_mut(&reservation.recipient))
            .filter(|r| {
                r.state == MailTaskRecipientState::InFlight
                    && r.nonce.as_deref() == Some(reservation.nonce.as_str())
            })
            .ok_or(MailTaskError::InvalidReservation)?;
        recipient.state = MailTaskRecipientState::Finished(outcome);
        recipient.nonce = None;
        Ok(())
    }

    /// Final pre-DATA fence, after the dispatcher rechecks the current vault
    /// identity/settings under the vault lock. A revocation after this boundary
    /// cannot recall a message already admitted to the SMTP transport.
    pub fn reservation_valid(
        &self,
        reservation: &MailTaskReservation,
    ) -> Result<bool, MailTaskError> {
        self.reservation_valid_at(reservation, Instant::now())
    }
    fn reservation_valid_at(
        &self,
        reservation: &MailTaskReservation,
        now: Instant,
    ) -> Result<bool, MailTaskError> {
        let tasks = self.lock()?;
        Ok(tasks.get(&reservation.task_id).is_some_and(|task| {
            task.live(now)
                && task.live(Instant::now())
                && task.snapshot.state == MailTaskState::Active
                && task
                    .recipients
                    .get(&reservation.recipient)
                    .is_some_and(|recipient| {
                        recipient.state == MailTaskRecipientState::InFlight
                            && recipient.nonce.as_deref() == Some(reservation.nonce.as_str())
                    })
        }))
    }
}

fn short_text(value: &str, max: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}
fn dns_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
}
/// Conservative, unambiguous SMTP mailbox subset; no display names or lists.
/// Exact bytes are retained. Case-insensitive duplicates are rejected to avoid
/// accidental duplicate delivery to ordinary case-insensitive mail providers.
pub fn valid_mail_recipient(value: &str) -> bool {
    if value.len() > 254 {
        return false;
    }
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && local.len() <= 64
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && local
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._+-".contains(&c))
        && dns_name(domain)
        && domain.contains('.')
}
fn validate(
    draft: &MailTaskDraft,
    binding: &MailTaskBinding,
    account: &MailTaskAccount,
) -> Result<(), MailTaskError> {
    let mut seen = BTreeSet::new();
    if draft.item_id == 0
        || draft.recipients.is_empty()
        || draft.recipients.len() > MAX_MAIL_RECIPIENTS
        || draft
            .recipients
            .iter()
            .any(|r| !valid_mail_recipient(r) || !seen.insert(r.to_ascii_lowercase()))
        || !short_text(&draft.subject, 200)
        || draft.body.len() > MAX_MAIL_BODY_BYTES
        || draft.body.trim().is_empty()
        || draft
            .body
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t')
        || !short_text(&draft.purpose, 512)
        || !(1..=MAX_MAIL_TASK_MINUTES).contains(&draft.ttl_minutes)
    {
        return Err(MailTaskError::InvalidDraft);
    }
    if binding.agent_id == 0
        || !short_text(&binding.project_key, 4096)
        || !short_text(&binding.context_id, 512)
        || !short_text(&binding.policy_digest, 512)
    {
        return Err(MailTaskError::InvalidBinding);
    }
    if !dns_name(&account.host)
        || account.port == 0
        || !short_text(&account.user, 320)
        || !valid_mail_recipient(&account.sender)
    {
        return Err(MailTaskError::InvalidAccount);
    }
    Ok(())
}
fn random_id() -> Result<String, MailTaskError> {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).map_err(|_| MailTaskError::RandomUnavailable)?;
    Ok(hex(&bytes))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn scope_digest(
    id: &str,
    draft: &MailTaskDraft,
    binding: &MailTaskBinding,
    account: &MailTaskAccount,
) -> String {
    let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
    // Length prefixes prevent concatenation ambiguities. Order and all immutable
    // fields, including account, recipient count, lifetime and purpose, are signed.
    let mut field = |bytes: &[u8]| {
        digest.update(&(bytes.len() as u64).to_be_bytes());
        digest.update(bytes);
    };
    field(b"apassy-mail-task-v1");
    field(id.as_bytes());
    field(&draft.item_id.to_be_bytes());
    field(&(draft.recipients.len() as u64).to_be_bytes());
    for recipient in &draft.recipients {
        field(recipient.as_bytes());
    }
    field(draft.subject.as_bytes());
    field(draft.body.as_bytes());
    field(&draft.ttl_minutes.to_be_bytes());
    field(draft.purpose.as_bytes());
    field(&binding.agent_id.to_be_bytes());
    field(binding.project_key.as_bytes());
    field(&binding.vault_epoch);
    field(&binding.item_revision.to_be_bytes());
    field(binding.context_id.as_bytes());
    field(binding.policy_digest.as_bytes());
    field(account.host.as_bytes());
    field(&account.port.to_be_bytes());
    field(account.user.as_bytes());
    field(account.sender.as_bytes());
    hex(digest.finish().as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    fn draft() -> MailTaskDraft {
        MailTaskDraft {
            item_id: 7,
            recipients: vec!["one@example.org".into(), "two@example.org".into()],
            subject: "Meeting notes".into(),
            body: "Hello,\nThese are the exact notes. {{literal}}".into(),
            ttl_minutes: 10,
            purpose: "Send the agreed meeting notes".into(),
        }
    }
    fn binding() -> MailTaskBinding {
        MailTaskBinding {
            agent_id: 3,
            project_key: "/project/.git".into(),
            vault_epoch: [9; 32],
            item_revision: 12,
            context_id: "host-session/task-42".into(),
            policy_digest: "policy-generation-1".into(),
        }
    }
    fn account() -> MailTaskAccount {
        MailTaskAccount {
            host: "smtp.example.org".into(),
            port: 587,
            user: "owner@example.org".into(),
            sender: "owner@example.org".into(),
        }
    }
    fn proposal(registry: &MailTaskRegistry, now: Instant) -> MailTaskSnapshot {
        registry
            .propose_at(draft(), binding(), account(), now)
            .unwrap()
    }
    fn activate(registry: &MailTaskRegistry, task: &MailTaskSnapshot, now: Instant) {
        let proof = OwnerProof::issue_for_test(
            task.owner_action(),
            task.binding.vault_epoch,
            Instant::now(),
        );
        registry
            .activate_at(&task.id, &task.binding.vault_epoch, proof, now)
            .unwrap();
    }
    fn reserve(
        registry: &MailTaskRegistry,
        task: &MailTaskSnapshot,
        now: Instant,
    ) -> MailTaskReservation {
        let result = registry
            .reserve_at(
                &task.id,
                &task.binding,
                &task.account,
                &task.draft.recipients[0],
                now,
            )
            .unwrap();
        let MailTaskReservationResult::Reserved(reservation) = result else {
            panic!("expected first reservation")
        };
        reservation
    }

    #[test]
    fn proposal_is_inert_and_only_fresh_exact_proof_activates_it() {
        let registry = MailTaskRegistry::new();
        let now = Instant::now();
        let task = proposal(&registry, now);
        assert_eq!(task.state, MailTaskState::Pending);
        assert!(matches!(
            registry.reserve_at(
                &task.id,
                &task.binding,
                &task.account,
                &task.draft.recipients[0],
                now
            ),
            Err(MailTaskError::NotActive)
        ));
        let mut altered = task.clone();
        altered.digest.push('0');
        let proof = OwnerProof::issue_for_test(
            altered.owner_action(),
            task.binding.vault_epoch,
            Instant::now(),
        );
        assert_eq!(
            registry.activate_at(&task.id, &task.binding.vault_epoch, proof, now),
            Err(MailTaskError::OwnerProof)
        );
        let proof = OwnerProof::issue_for_test(task.owner_action(), [1; 32], Instant::now());
        assert_eq!(
            registry.activate_at(&task.id, &task.binding.vault_epoch, proof, now),
            Err(MailTaskError::OwnerProof)
        );
        let proof = OwnerProof::issue_for_test(
            task.owner_action(),
            task.binding.vault_epoch,
            Instant::now() - Duration::from_secs(61),
        );
        assert_eq!(
            registry.activate_at(&task.id, &task.binding.vault_epoch, proof, now),
            Err(MailTaskError::OwnerProof)
        );
        activate(&registry, &task, now);
        let proof = OwnerProof::issue_for_test(
            task.owner_action(),
            task.binding.vault_epoch,
            Instant::now(),
        );
        assert_eq!(
            registry.activate_at(&task.id, &task.binding.vault_epoch, proof, now),
            Err(MailTaskError::NotPending)
        );
    }

    #[test]
    fn every_authenticated_binding_and_account_field_is_required_for_send() {
        let registry = MailTaskRegistry::new();
        let now = Instant::now();
        let task = proposal(&registry, now);
        activate(&registry, &task, now);
        let original = task.binding.clone();
        let mut mutations = vec![original.clone(); 6];
        mutations[0].agent_id += 1;
        mutations[1].project_key.push('x');
        mutations[2].vault_epoch[0] ^= 1;
        mutations[3].item_revision += 1;
        mutations[4].context_id.push('x');
        mutations[5].policy_digest.push('x');
        for changed in mutations {
            assert_eq!(
                registry.snapshot(&task.id, &changed),
                Err(MailTaskError::Unavailable)
            );
            assert!(matches!(
                registry.reserve_at(&task.id, &changed, &task.account, "one@example.org", now),
                Err(MailTaskError::Unavailable)
            ));
        }
        let mut accounts = vec![task.account.clone(); 4];
        accounts[0].host.push('x');
        accounts[1].port += 1;
        accounts[2].user.push('x');
        accounts[3].sender.push('x');
        for changed in accounts {
            assert!(matches!(
                registry.reserve_at(&task.id, &task.binding, &changed, "one@example.org", now),
                Err(MailTaskError::Unavailable)
            ));
        }
        assert!(matches!(
            registry.reserve_at(
                &task.id,
                &task.binding,
                &task.account,
                "other@example.org",
                now
            ),
            Err(MailTaskError::RecipientOutsideScope)
        ));
        assert!(registry.list_for_owner(&[0; 32]).unwrap().is_empty());
        assert_eq!(
            registry.snapshot_for_context(
                &task.id,
                original.agent_id + 1,
                &original.project_key,
                &original.vault_epoch,
                &original.context_id
            ),
            Err(MailTaskError::Unavailable)
        );
        assert_eq!(
            registry.snapshot_for_context(
                &task.id,
                original.agent_id,
                "/other",
                &original.vault_epoch,
                &original.context_id
            ),
            Err(MailTaskError::Unavailable)
        );
        assert_eq!(
            registry.snapshot_for_context(
                &task.id,
                original.agent_id,
                &original.project_key,
                &[0; 32],
                &original.context_id
            ),
            Err(MailTaskError::Unavailable)
        );
        assert_eq!(
            registry.snapshot_for_context(
                &task.id,
                original.agent_id,
                &original.project_key,
                &original.vault_epoch,
                "other-task"
            ),
            Err(MailTaskError::Unavailable)
        );
        assert_eq!(
            registry
                .snapshot_for_context(
                    &task.id,
                    original.agent_id,
                    &original.project_key,
                    &original.vault_epoch,
                    &original.context_id
                )
                .unwrap()
                .draft
                .item_id,
            7
        );
    }

    #[test]
    fn reservation_freezes_literal_content_and_all_outcomes_are_terminal() {
        for outcome in [
            MailTaskOutcome::Success,
            MailTaskOutcome::Unknown,
            MailTaskOutcome::PreSendFailure,
        ] {
            let registry = MailTaskRegistry::new();
            let now = Instant::now();
            let task = proposal(&registry, now);
            activate(&registry, &task, now);
            let reservation = reserve(&registry, &task, now);
            assert_eq!(reservation.subject(), task.draft.subject);
            assert_eq!(reservation.body(), task.draft.body);
            assert_eq!(reservation.account(), &task.account);
            assert!(matches!(
                registry.reserve_at(
                    &task.id,
                    &task.binding,
                    &task.account,
                    reservation.recipient(),
                    now
                ),
                Ok(MailTaskReservationResult::InFlight)
            ));
            registry.finish(reservation, outcome).unwrap();
            assert!(
                matches!(registry.reserve_at(&task.id, &task.binding, &task.account, "one@example.org", now), Ok(MailTaskReservationResult::Previous(previous)) if previous == outcome)
            );
            assert!(matches!(
                registry.reserve_at(
                    &task.id,
                    &task.binding,
                    &task.account,
                    "two@example.org",
                    now
                ),
                Ok(MailTaskReservationResult::Reserved(_))
            ));
        }
    }

    #[test]
    fn concurrent_calls_can_reserve_a_recipient_only_once() {
        let registry = Arc::new(MailTaskRegistry::new());
        let now = Instant::now();
        let task = proposal(&registry, now);
        activate(&registry, &task, now);
        let barrier = Arc::new(Barrier::new(8));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let registry = Arc::clone(&registry);
                let barrier = Arc::clone(&barrier);
                let task = task.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    registry
                        .reserve_at(
                            &task.id,
                            &task.binding,
                            &task.account,
                            "one@example.org",
                            now,
                        )
                        .unwrap()
                })
            })
            .collect();
        let mut reserved = 0;
        let mut inflight = 0;
        for handle in handles {
            match handle.join().unwrap() {
                MailTaskReservationResult::Reserved(_) => reserved += 1,
                MailTaskReservationResult::InFlight => inflight += 1,
                MailTaskReservationResult::Previous(_) => panic!("nothing has completed"),
            }
        }
        assert_eq!((reserved, inflight), (1, 7));
    }

    #[test]
    fn expiry_revocation_and_global_invalidation_fence_inflight_sends() {
        let registry = MailTaskRegistry::new();
        let now = Instant::now();
        let task = proposal(&registry, now);
        activate(&registry, &task, now);
        let reservation = reserve(&registry, &task, now);
        assert!(registry.reservation_valid_at(&reservation, now).unwrap());
        let deadline = now + Duration::from_secs(600);
        assert!(
            !registry
                .reservation_valid_at(&reservation, deadline)
                .unwrap()
        );
        assert!(matches!(
            registry.reserve_at(
                &task.id,
                &task.binding,
                &task.account,
                "two@example.org",
                deadline
            ),
            Err(MailTaskError::NotActive)
        ));
        registry
            .revoke(&task.id, &task.binding.vault_epoch)
            .unwrap();
        assert!(!registry.reservation_valid_at(&reservation, now).unwrap());
        registry
            .finish(reservation, MailTaskOutcome::PreSendFailure)
            .unwrap();
        let pending = proposal(&registry, now);
        let active = proposal(&registry, now);
        activate(&registry, &active, now);
        registry.invalidate_all().unwrap();
        assert_eq!(
            registry
                .snapshot(&pending.id, &pending.binding)
                .unwrap()
                .state,
            MailTaskState::Revoked
        );
        assert_eq!(
            registry
                .snapshot(&active.id, &active.binding)
                .unwrap()
                .state,
            MailTaskState::Revoked
        );
    }

    #[test]
    fn denial_and_receipt_cancellation_never_activate_or_revoke_an_active_task() {
        let registry = MailTaskRegistry::new();
        let now = Instant::now();
        let task = proposal(&registry, now);
        assert_eq!(
            registry.cancel_pending_operation(&task.id, 4, &task.binding.vault_epoch),
            Err(MailTaskError::Unavailable)
        );
        assert_eq!(
            registry.cancel_pending_operation(&task.id, 3, &[0; 32]),
            Err(MailTaskError::Unavailable)
        );
        registry
            .cancel_pending_operation(&task.id, 3, &task.binding.vault_epoch)
            .unwrap();
        assert_eq!(
            registry.snapshot(&task.id, &task.binding).unwrap().state,
            MailTaskState::Revoked
        );
        registry
            .cancel_pending_operation(&task.id, 3, &task.binding.vault_epoch)
            .unwrap();
        let proof = OwnerProof::issue_for_test(
            task.owner_action(),
            task.binding.vault_epoch,
            Instant::now(),
        );
        assert_eq!(
            registry.activate_at(&task.id, &task.binding.vault_epoch, proof, now),
            Err(MailTaskError::NotPending)
        );
        let active = proposal(&registry, now);
        activate(&registry, &active, now);
        assert_eq!(
            registry.cancel_pending_operation(&active.id, 3, &active.binding.vault_epoch),
            Err(MailTaskError::NotPending)
        );
        assert_eq!(
            registry.deny(&active.id, &active.binding.vault_epoch),
            Err(MailTaskError::NotActive)
        );
        registry
            .revoke(&active.id, &active.binding.vault_epoch)
            .unwrap();
        assert_eq!(
            registry.cancel_pending_operation(&active.id, 3, &active.binding.vault_epoch),
            Err(MailTaskError::NotPending)
        );
        let expired = proposal(&registry, now);
        let proof = OwnerProof::issue_for_test(
            expired.owner_action(),
            expired.binding.vault_epoch,
            Instant::now(),
        );
        assert_eq!(
            registry.activate_at(
                &expired.id,
                &expired.binding.vault_epoch,
                proof,
                now + Duration::from_secs(600)
            ),
            Err(MailTaskError::NotPending)
        );
    }

    #[test]
    fn historical_decisions_survive_the_deadline_and_cancel_retries_are_exact() {
        let registry = MailTaskRegistry::new();
        let now = Instant::now();
        let denied = proposal(&registry, now);
        let revoked = proposal(&registry, now);
        let cancelled = proposal(&registry, now);
        let pending = proposal(&registry, now);
        let active = proposal(&registry, now);
        registry
            .deny(&denied.id, &denied.binding.vault_epoch)
            .unwrap();
        registry
            .revoke(&revoked.id, &revoked.binding.vault_epoch)
            .unwrap();
        registry
            .cancel_pending_operation(&cancelled.id, 3, &cancelled.binding.vault_epoch)
            .unwrap();
        activate(&registry, &active, now);
        let after_deadline = now + Duration::from_secs(601);
        let mut tasks = registry.lock().unwrap();
        for (snapshot, expected) in [
            (&denied, MailTaskState::Denied),
            (&revoked, MailTaskState::Revoked),
            (&cancelled, MailTaskState::Revoked),
            (&pending, MailTaskState::Expired),
            (&active, MailTaskState::Expired),
        ] {
            let view = tasks[&snapshot.id].view(after_deadline);
            assert_eq!(view.state, expected);
            assert_eq!(view.remaining_seconds, 0);
        }
        assert_eq!(
            tasks
                .get_mut(&cancelled.id)
                .unwrap()
                .cancel_pending(after_deadline),
            Ok(())
        );
        assert_eq!(
            tasks.get_mut(&denied.id).unwrap().cancel_pending(now),
            Err(MailTaskError::NotPending)
        );
        assert_eq!(
            tasks.get_mut(&revoked.id).unwrap().cancel_pending(now),
            Err(MailTaskError::NotPending)
        );
    }

    #[test]
    fn pending_count_checks_epoch_state_and_expiry_without_message_snapshots() {
        let registry = MailTaskRegistry::new();
        let now = Instant::now();
        let pending = proposal(&registry, now);
        let expired = proposal(&registry, now);
        let active = proposal(&registry, now);
        let denied = proposal(&registry, now);
        activate(&registry, &active, now);
        registry
            .deny(&denied.id, &denied.binding.vault_epoch)
            .unwrap();
        let mut foreign_binding = binding();
        foreign_binding.vault_epoch = [8; 32];
        registry
            .propose(draft(), foreign_binding, account())
            .unwrap();
        registry
            .lock()
            .unwrap()
            .get_mut(&expired.id)
            .unwrap()
            .deadline = now;
        assert_eq!(
            registry
                .pending_count(&pending.binding.vault_epoch)
                .unwrap(),
            1
        );
        assert_eq!(registry.pending_count(&[8; 32]).unwrap(), 1);
        assert_eq!(registry.pending_count(&[7; 32]).unwrap(), 0);
    }

    #[test]
    fn ending_one_session_removes_its_content_and_fences_inflight_and_replay() {
        let registry = MailTaskRegistry::new();
        let now = Instant::now();
        let pending = proposal(&registry, now);
        let active = proposal(&registry, now);
        activate(&registry, &active, now);
        let reservation = reserve(&registry, &active, now);
        let mut other_binding = binding();
        other_binding.vault_epoch = [8; 32];
        let other = registry.propose(draft(), other_binding, account()).unwrap();
        registry.clear_session(&pending.binding.vault_epoch);
        registry.clear_session(&pending.binding.vault_epoch);
        assert!(
            registry
                .list_for_owner(&pending.binding.vault_epoch)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            registry.snapshot(&pending.id, &pending.binding),
            Err(MailTaskError::Unavailable)
        );
        assert_eq!(
            registry.snapshot(&active.id, &active.binding),
            Err(MailTaskError::Unavailable)
        );
        assert!(!registry.reservation_valid(&reservation).unwrap());
        assert_eq!(
            registry.finish(reservation, MailTaskOutcome::Unknown),
            Err(MailTaskError::InvalidReservation)
        );
        assert!(matches!(
            registry.reserve(
                &active.id,
                &active.binding,
                &active.account,
                "one@example.org"
            ),
            Err(MailTaskError::Unavailable)
        ));
        assert_eq!(
            registry.pending_count(&other.binding.vault_epoch).unwrap(),
            1
        );
        assert_eq!(registry.lock().unwrap().len(), 1);
    }

    #[test]
    fn capacity_never_evicts_unexpired_scopes_or_reservation_results() {
        let registry = MailTaskRegistry::new();
        let now = Instant::now();
        let first = proposal(&registry, now);
        activate(&registry, &first, now);
        let reservation = reserve(&registry, &first, now);
        registry
            .finish(reservation, MailTaskOutcome::Unknown)
            .unwrap();
        for _ in 1..MAX_MAIL_TASKS {
            proposal(&registry, now);
        }
        assert_eq!(
            registry.propose_at(draft(), binding(), account(), now),
            Err(MailTaskError::Capacity)
        );
        assert!(matches!(
            registry.reserve_at(
                &first.id,
                &first.binding,
                &first.account,
                "one@example.org",
                now
            ),
            Ok(MailTaskReservationResult::Previous(
                MailTaskOutcome::Unknown
            ))
        ));
        assert!(
            registry
                .propose_at(
                    draft(),
                    binding(),
                    account(),
                    now + Duration::from_secs(600)
                )
                .is_ok()
        );
        assert_eq!(
            registry.snapshot(&first.id, &first.binding),
            Err(MailTaskError::Unavailable)
        );
    }

    #[test]
    fn dropped_or_forged_reservations_cannot_release_the_recipient() {
        let registry = MailTaskRegistry::new();
        let now = Instant::now();
        let task = proposal(&registry, now);
        activate(&registry, &task, now);
        let mut reservation = reserve(&registry, &task, now);
        reservation.nonce.push('x');
        assert!(!registry.reservation_valid(&reservation).unwrap());
        assert_eq!(
            registry.finish(reservation, MailTaskOutcome::Success),
            Err(MailTaskError::InvalidReservation)
        );
        assert!(matches!(
            registry.reserve_at(
                &task.id,
                &task.binding,
                &task.account,
                "one@example.org",
                now
            ),
            Ok(MailTaskReservationResult::InFlight)
        ));
        registry
            .revoke(&task.id, &task.binding.vault_epoch)
            .unwrap();
        assert!(matches!(
            registry.reserve_at(
                &task.id,
                &task.binding,
                &task.account,
                "one@example.org",
                now
            ),
            Ok(MailTaskReservationResult::InFlight)
        ));
        assert!(matches!(
            registry.reserve_at(
                &task.id,
                &task.binding,
                &task.account,
                "two@example.org",
                now
            ),
            Err(MailTaskError::NotActive)
        ));
    }

    #[test]
    fn poisoning_the_registry_refuses_all_access() {
        let registry = MailTaskRegistry::new();
        let now = Instant::now();
        let task = proposal(&registry, now);
        let _ = std::panic::catch_unwind(|| {
            let _guard = registry.tasks.lock().unwrap();
            panic!("synthetic interrupted transition");
        });
        assert_eq!(
            registry.snapshot(&task.id, &task.binding),
            Err(MailTaskError::Poisoned)
        );
        assert_eq!(
            registry.list_for_owner(&task.binding.vault_epoch),
            Err(MailTaskError::Poisoned)
        );
        assert_eq!(registry.invalidate_all(), Err(MailTaskError::Poisoned));
        assert_eq!(
            registry.propose(draft(), binding(), account()),
            Err(MailTaskError::Poisoned)
        );
        registry.clear_session(&task.binding.vault_epoch);
        assert!(
            registry
                .tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty()
        );
        assert_eq!(
            registry.snapshot(&task.id, &task.binding),
            Err(MailTaskError::Poisoned)
        );
    }

    #[test]
    fn rejects_header_injection_duplicate_recipients_and_unbounded_content() {
        for recipient in [
            "A <a@example.org>",
            "a@example.org,b@example.org",
            "a@example.org\r\nBcc: x@y.org",
            "a@b",
            "a..b@example.org",
            "a@-example.org",
            "a@example..org",
        ] {
            assert!(!valid_mail_recipient(recipient), "{recipient:?}");
        }
        let mut drafts = vec![draft(); 10];
        drafts[0].recipients.clear();
        drafts[1].recipients = vec!["a@example.org".into(), "A@example.org".into()];
        drafts[2].subject.push_str("\r\nBcc: a@example.org");
        drafts[3].body.push('\0');
        drafts[4].body = "x".repeat(MAX_MAIL_BODY_BYTES + 1);
        drafts[5].ttl_minutes = 31;
        drafts[6].ttl_minutes = 0;
        drafts[7].recipients = (0..=MAX_MAIL_RECIPIENTS)
            .map(|i| format!("{i}@example.org"))
            .collect();
        drafts[8].purpose.clear();
        drafts[9].subject = "x".repeat(201);
        for invalid in drafts {
            assert_eq!(
                validate(&invalid, &binding(), &account()),
                Err(MailTaskError::InvalidDraft)
            );
        }
        assert!(validate(&draft(), &binding(), &account()).is_ok());
    }

    #[test]
    fn digest_covers_all_immutable_scope_fields_without_concatenation_aliases() {
        let original = scope_digest("id", &draft(), &binding(), &account());
        let mut drafts = vec![draft(); 7];
        drafts[0].item_id += 1;
        drafts[1].recipients.reverse();
        drafts[2].recipients.pop();
        drafts[3].subject.push('x');
        drafts[4].body.push('x');
        drafts[5].ttl_minutes += 1;
        drafts[6].purpose.push('x');
        for changed in drafts {
            assert_ne!(
                scope_digest("id", &changed, &binding(), &account()),
                original
            );
        }
        let mut bindings = vec![binding(); 6];
        bindings[0].agent_id += 1;
        bindings[1].project_key.push('x');
        bindings[2].vault_epoch[0] ^= 1;
        bindings[3].item_revision += 1;
        bindings[4].context_id.push('x');
        bindings[5].policy_digest.push('x');
        for changed in bindings {
            assert_ne!(scope_digest("id", &draft(), &changed, &account()), original);
        }
        let mut accounts = vec![account(); 4];
        accounts[0].host.push('x');
        accounts[1].port += 1;
        accounts[2].user.push('x');
        accounts[3].sender.push('x');
        for changed in accounts {
            assert_ne!(scope_digest("id", &draft(), &binding(), &changed), original);
        }
        assert_ne!(
            scope_digest("other-id", &draft(), &binding(), &account()),
            original
        );
        let mut a = draft();
        let mut b = draft();
        a.subject = "ab".into();
        a.body = "c".into();
        b.subject = "a".into();
        b.body = "bc".into();
        assert_ne!(
            scope_digest("id", &a, &binding(), &account()),
            scope_digest("id", &b, &binding(), &account())
        );
    }
}
