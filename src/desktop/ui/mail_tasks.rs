//! Local owner review of immutable, short-lived SMTP tasks. A proposal never
//! becomes active merely by appearing here or by opening its details.

use eframe::egui;

use super::kit::{self, Font, Style, Tone};
use crate::broker::approvals::OwnerProof;
use crate::broker::mail_tasks::{MailTaskSnapshot, MailTaskState};
use crate::desktop::DesktopApp;
use crate::desktop::owner_check::OwnerRequest;

pub(super) fn pending_count(app: &DesktopApp) -> usize {
    let Some(approvals) = app.approvals() else {
        return 0;
    };
    let Some(epoch) = app.owner_ui.session.epoch() else {
        return 0;
    };
    approvals.mail_tasks().pending_count(&epoch).unwrap_or(0)
}

pub(super) fn show(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let Some(approvals) = app.approvals() else {
        return;
    };
    let Some(epoch) = app.owner_ui.session.epoch() else {
        return;
    };
    let tasks = match approvals.mail_tasks().list_for_owner(&epoch) {
        Ok(tasks) => tasks,
        Err(err) => {
            kit::tone_note(ui, &err.to_string(), Tone::Warning);
            return;
        }
    };
    let tasks: Vec<_> = tasks
        .into_iter()
        .filter(|task| matches!(task.state, MailTaskState::Pending | MailTaskState::Active))
        .collect();
    if tasks.is_empty() {
        return;
    }
    ui.label(kit::text("Mail tasks", Font::Headline));
    kit::paragraph(
        ui,
        "Review a task locally before Bouncer can decide its sends. A task never approves a send by itself.",
        Font::Body,
        kit::palette().label,
    );
    let mut choice = None;
    egui::ScrollArea::vertical()
        .id_salt("mail-task-proposals")
        .max_height((ui.available_height() * 0.45).clamp(100.0, 320.0))
        .auto_shrink([false, true])
        .show(ui, |ui| {
            for task in tasks {
                ui.push_id(&task.id, |ui| {
                    ui.group(|ui| {
                        let pending = task.state == MailTaskState::Pending;
                        ui.label(kit::text(
                            if pending {
                                "Waiting for your review"
                            } else {
                                "Active mail task"
                            },
                            Font::Headline,
                        ));
                        ui.label(format!(
                            "Agent #{} · item #{} · {} recipients · {}s left",
                            task.binding.agent_id,
                            task.draft.item_id,
                            task.draft.recipients.len(),
                            task.remaining_seconds
                        ));
                        egui::CollapsingHeader::new("Exact task details")
                            .show(ui, |ui| details(ui, &task));
                        ui.horizontal_wrapped(|ui| {
                            if pending {
                                if kit::button(
                                    ui,
                                    "Let Bouncer decide for this task",
                                    Style::Prominent,
                                )
                                .clicked()
                                {
                                    choice = Some(Choice::Review(task.clone()));
                                }
                                if kit::button(ui, "Deny task", Style::Bordered).clicked() {
                                    choice = Some(Choice::Deny(task.id.clone()));
                                }
                            } else if kit::button(ui, "Revoke task now", Style::Bordered).clicked()
                            {
                                choice = Some(Choice::Revoke(task.id.clone()));
                            }
                        });
                    });
                });
            }
        });
    match choice {
        Some(Choice::Review(task)) => {
            app.ask_owner(OwnerRequest::ActivateMailTask { task }, Some(ui.ctx()))
        }
        Some(Choice::Deny(id)) => app.end_mail_task(&id, false, ui.ctx()),
        Some(Choice::Revoke(id)) => app.end_mail_task(&id, true, ui.ctx()),
        None => {}
    }
    // Countdown and expiry remain visible without another user input.
    ui.ctx()
        .request_repaint_after(std::time::Duration::from_secs(1));
}

enum Choice {
    Review(MailTaskSnapshot),
    Deny(String),
    Revoke(String),
}

/// No markdown, linkification, truncation or recipient preview: every byte that
/// affects sending has a visible representation, also in the final owner prompt.
pub(super) fn details(ui: &mut egui::Ui, task: &MailTaskSnapshot) {
    for (label, value) in detail_lines(task) {
        ui.label(kit::text(label, Font::Headline));
        ui.add(egui::Label::new(visible(&value)).wrap().selectable(true));
    }
}

fn detail_lines(task: &MailTaskSnapshot) -> Vec<(&'static str, String)> {
    vec![
        ("Task", task.id.clone()),
        ("Agent", format!("Agent #{}", task.binding.agent_id)),
        ("Project", task.binding.project_key.clone()),
        (
            "Credential",
            format!(
                "Item #{} · revision {}",
                task.draft.item_id, task.binding.item_revision
            ),
        ),
        ("Task context", task.binding.context_id.clone()),
        (
            "SMTP endpoint",
            format!("{}:{}", task.account.host, task.account.port),
        ),
        ("Account", task.account.user.clone()),
        ("Sender", task.account.sender.clone()),
        ("All recipients", task.draft.recipients.join("\n")),
        ("Subject (literal)", task.draft.subject.clone()),
        ("Body (literal)", task.draft.body.clone()),
        ("Purpose", task.draft.purpose.clone()),
        (
            "Limit",
            format!(
                "At most one send attempt per recipient; {} recipient(s). An unknown result is not retried.",
                task.draft.recipients.len()
            ),
        ),
        (
            "Lifetime",
            format!(
                "{} minutes from proposal; {} seconds remaining when this review was prepared. Locking or changing this vault session ends the task.",
                task.draft.ttl_minutes, task.remaining_seconds
            ),
        ),
        ("Attachments", "None. Attachments are not permitted.".into()),
    ]
}

fn visible(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if crate::browser::wire::hides_text(ch) && ch != '\n' && ch != '\t' {
                format!("\\u{{{:04x}}}", ch as u32)
            } else {
                ch.to_string()
            }
        })
        .collect()
}

impl DesktopApp {
    pub(crate) fn complete_mail_task(&mut self, task: MailTaskSnapshot, proof: OwnerProof) {
        let Some(approvals) = self.approvals() else {
            self.set_err("The broker is not running.");
            return;
        };
        let result = self
            .owner_ui
            .session
            .with_vault(|vault| {
                // Keep the current vault locked while the registry checks the proof's
                // exact task digest and epoch and activates the pending proposal.
                if vault.is_locked() {
                    return None;
                }
                if !vault
                    .details(task.draft.item_id)
                    .is_ok_and(|details| details.summary.revision == task.binding.item_revision)
                {
                    return Some(Err("The mail task credential changed. Review a new task.".to_owned()));
                }
                if let Err(err) = approvals.mail_tasks().activate(&task.id, &vault.epoch(), proof) {
                    return Some(Err(err.to_string()));
                }
                // No sender can reserve while this vault lock is held. Audit must
                // succeed before releasing it; failed audit removes the authority.
                if let Err(err) = crate::broker::decide::record_mail_task_review(vault, &task, true) {
                    let revoked = approvals.mail_tasks().revoke(&task.id, &vault.epoch());
                    return Some(Err(match revoked {
                        Ok(()) => format!("Mail task revoked because its review could not be recorded: {err}"),
                        Err(revoke_err) => format!("The mail task review could not be recorded ({err}); revocation also failed ({revoke_err}). No send was started by this review."),
                    }));
                }
                Some(Ok(()))
            })
            .flatten();
        self.ui.bouncer.clear();
        match result {
            Some(Ok(())) => self.set_ok("Task active. Bouncer still decides each send."),
            Some(Err(err)) => self.set_err(err.to_string()),
            None => self.set_err("Unlock the vault and review the task again."),
        }
    }

    fn end_mail_task(&mut self, id: &str, revoke: bool, ctx: &egui::Context) {
        // Denying/revoking narrows authority immediately and cancels an open
        // authentication dialog for the same proposal before it can complete.
        if self.owner.check.as_ref().is_some_and(|dialog| {
            matches!(&dialog.request,
            OwnerRequest::ActivateMailTask { task } if task.id == id)
        }) {
            self.close_owner_check(Some(ctx));
        }
        let Some(approvals) = self.approvals() else {
            return;
        };
        let result = self.owner_ui.session.with_vault(|vault| {
            if revoke {
                approvals
                    .mail_tasks()
                    .revoke(id, &vault.epoch())
                    .map_err(|err| err.to_string())
            } else {
                let task = approvals
                    .mail_tasks()
                    .list_for_owner(&vault.epoch())
                    .map_err(|err| err.to_string())?
                    .into_iter()
                    .find(|task| task.id == id && task.state == MailTaskState::Pending)
                    .ok_or_else(|| "The mail task is no longer waiting.".to_owned())?;
                approvals
                    .mail_tasks()
                    .deny(id, &vault.epoch())
                    .map_err(|err| err.to_string())?;
                crate::broker::decide::record_mail_task_review(vault, &task, false).map_err(|err| {
                    format!("Mail task denied, but its decision could not be recorded: {err}")
                })
            }
        });
        self.ui.bouncer.clear();
        match result {
            Some(Ok(())) => self.set_ok(if revoke {
                "Mail task revoked."
            } else {
                "Mail task denied."
            }),
            Some(Err(err)) => self.set_err(err.to_string()),
            None => self.set_err("The vault session changed."),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::mail_tasks::{MailTaskAccount, MailTaskBinding, MailTaskDraft};

    fn task() -> MailTaskSnapshot {
        MailTaskSnapshot {
            id: "synthetic-task".into(),
            digest: "a".repeat(64),
            draft: MailTaskDraft {
                item_id: 17,
                recipients: (0..100).map(|n| format!("person{n}@example.com")).collect(),
                subject: "Literal subject".into(),
                body: "A long literal body\n".repeat(100),
                ttl_minutes: 30,
                purpose: "Requested owner-reviewed mail".into(),
            },
            binding: MailTaskBinding {
                agent_id: 9,
                project_key: "/synthetic/project".into(),
                vault_epoch: [1; 32],
                item_revision: 3,
                context_id: "authenticated-task".into(),
                policy_digest: "b".repeat(64),
            },
            account: MailTaskAccount {
                host: "smtp.example.com".into(),
                port: 465,
                user: "owner@example.com".into(),
                sender: "sender@example.com".into(),
            },
            state: MailTaskState::Pending,
            recipient_states: Vec::new(),
            remaining_seconds: 1799,
        }
    }

    #[test]
    fn review_includes_all_recipients_literal_content_and_scope_bounds() {
        let task = task();
        let lines = detail_lines(&task);
        let value = |name| &lines.iter().find(|(label, _)| *label == name).unwrap().1;
        assert_eq!(value("All recipients"), &task.draft.recipients.join("\n"));
        assert_eq!(value("Body (literal)"), &task.draft.body);
        assert_eq!(value("Subject (literal)"), &task.draft.subject);
        assert_eq!(value("Agent"), "Agent #9");
        assert_eq!(value("Project"), "/synthetic/project");
        assert_eq!(value("SMTP endpoint"), "smtp.example.com:465");
        assert_eq!(value("Account"), "owner@example.com");
        assert_eq!(value("Sender"), "sender@example.com");
        assert!(value("Credential").contains("revision 3"));
        assert!(value("Limit").contains("one send attempt per recipient"));
        assert!(value("Lifetime").contains("30 minutes from proposal"));
        assert!(value("Attachments").contains("not permitted"));
        let request = OwnerRequest::ActivateMailTask { task: task.clone() };
        assert_eq!(request.action(), task.owner_action());
        assert!(request.action().needs_fresh_local_check());
        assert!(request.describe().contains("does not approve sending"));
    }

    #[test]
    fn literal_review_does_not_hide_or_shorten_text() {
        let text = format!("{}\n<b>literal</b>\u{202e}tail", "x".repeat(800));
        let shown = super::visible(&text);
        assert!(shown.starts_with(&"x".repeat(800)));
        assert!(shown.ends_with("\n<b>literal</b>\\u{202e}tail"));
    }
}
