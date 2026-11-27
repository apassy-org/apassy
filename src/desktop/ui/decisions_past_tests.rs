//! Tests of the detail of a past decision (ADR 0046): one reason, "Next time", and
//! "Details" on demand. Synthetic values only.

use super::*;
use crate::broker::action_kind::ActionKind;
use crate::broker::approvals::OwnerCheck;
use crate::contracts::CredentialKind;
use crate::desktop::ui::owner_tests::{PASS, unlocked_app_with_item};
use crate::vault::usage::{NewItemUse, UseDecidedBy, UseOutcome};
use crate::vault::{
    Declaration, Environment, Field, ItemDraft, RequestSource, Reversibility, RiskLevel, Scope,
    SecretValue,
};
use tempfile::TempDir;

const KEY: &str = "/synthetic/apassy/.git";

struct Fixture {
    _dir: TempDir,
    app: DesktopApp,
    item: u64,
    agent: u64,
}

fn fixture() -> Fixture {
    let dir = TempDir::new().expect("temp dir");
    let (app, item) = unlocked_app_with_item(&dir);
    let agent = app
        .owner_ui
        .session
        .with_vault(|vault| {
            vault
                .save_declaration(
                    item,
                    &Declaration {
                        project: "apassy".to_owned(),
                        environment: Environment::Staging,
                        risk: RiskLevel::Medium,
                        scope: Scope::ReadWrite,
                        reversibility: Reversibility::Reversible,
                    },
                    Some("sentry"),
                    None,
                )
                .expect("declaration");
            let agent = vault.register_agent("Claude Code").expect("agent").0.id;
            vault.set_agent_sees_all(agent, true).expect("see all");
            agent
        })
        .expect("open");
    Fixture {
        _dir: dir,
        app,
        item,
        agent,
    }
}

/// One decision and the uses of its credentials, as the broker writes them.
struct Decision<'a> {
    items: Vec<u64>,
    asked: bool,
    decided_by: DecidedBy,
    decision: LoggedDecision,
    why: DecisionWhy,
    flags: &'a [&'a str],
    note: &'a str,
    /// The generalized command of a run that a remembered pattern allowed.
    pattern: &'a str,
    /// The variables of the run.
    env_names: Vec<String>,
}

impl Decision<'_> {
    /// A question about the credential that nobody answered, and that offered "Allow
    /// changes in apassy".
    fn unanswered(item: u64) -> Self {
        Self {
            items: vec![item],
            asked: true,
            decided_by: DecidedBy::NoAnswer,
            decision: LoggedDecision::Deny,
            why: DecisionWhy {
                reason: "ForeignProject".to_owned(),
                offered: "in_project:change".to_owned(),
                ..DecisionWhy::default()
            },
            flags: &[],
            note: "\"Guarded key\" is declared for the project \"platform\", not for \"apassy\".",
            pattern: "",
            env_names: vec!["SYNTH_SENTRY_KEY".to_owned()],
        }
    }
}

fn record(fx: &mut Fixture, decision: Decision<'_>) -> u64 {
    let outcome = match (decision.decision, decision.decided_by) {
        (LoggedDecision::Allow, _) => UseOutcome::Allowed,
        (_, DecidedBy::Owner) => UseOutcome::Denied,
        (_, DecidedBy::NoAnswer) if decision.why.code == "approval_invalidated" => {
            UseOutcome::Refused
        }
        (_, DecidedBy::NoAnswer) => UseOutcome::TimedOut,
        _ => UseOutcome::Refused,
    };
    let by = if outcome == UseOutcome::Refused {
        UseDecidedBy::Rule
    } else {
        match decision.decided_by {
            DecidedBy::Owner | DecidedBy::NoAnswer => UseDecidedBy::Owner,
            DecidedBy::Answer => UseDecidedBy::Answer,
            DecidedBy::Pattern => UseDecidedBy::Pattern,
            DecidedBy::Rule => UseDecidedBy::Rule,
            DecidedBy::Model => UseDecidedBy::Bouncer,
        }
    };
    record_with_use(fx, decision, Some((outcome, by)))
}

fn record_with_use(
    fx: &mut Fixture,
    decision: Decision<'_>,
    use_result: Option<(UseOutcome, UseDecidedBy)>,
) -> u64 {
    let agent = fx.agent;
    fx.app
        .owner_ui
        .session
        .with_vault(|vault| {
            let entry = DecisionEntry {
                at: crate::broker::learning::now(),
                agent_id: agent,
                agent_name: "Claude Code".to_owned(),
                project_dir: "/synthetic/apassy".to_owned(),
                cwd_rel: ".".to_owned(),
                items: decision.items.clone(),
                user_request: "Check the Sentry releases.".to_owned(),
                user_request_source: RequestSource::Host,
                command: vec!["sentry-cli".to_owned(), "releases".to_owned()],
                purpose: "Check the releases.".to_owned(),
                env_names: decision.env_names.clone(),
                declarations: Vec::new(),
                rule_flags: decision.flags.iter().map(|f| (*f).to_owned()).collect(),
                known_safe: false,
                model_facts: Vec::new(),
                pattern: decision.pattern.to_owned(),
                grant_asks: false,
                asked: decision.asked,
                decision: decision.decision,
                decided_by: decision.decided_by,
                remembered: false,
                policy: "apassy-bouncer-v9".to_owned(),
                note: decision.note.to_owned(),
                instruction: String::new(),
            }
            .with_why(&decision.why);
            let id = vault.record_decision(&entry).expect("decision");
            if let Some((outcome, decided_by)) = use_result {
                for item in &decision.items {
                    vault
                        .record_item_use(&NewItemUse {
                            item_id: *item,
                            agent_id: Some(agent),
                            agent_name: "Claude Code".to_owned(),
                            project_key: KEY.to_owned(),
                            project_label: "apassy".to_owned(),
                            action: ActionKind::Change,
                            command_summary: "run sentry-cli releases".to_owned(),
                            hosts: vec!["sentry.io".to_owned()],
                            outcome,
                            decided_by,
                            answered_on: String::new(),
                            decision_log_id: Some(id),
                        })
                        .expect("use");
                }
            }
            id
        })
        .expect("open")
}

fn past(fx: &Fixture, id: u64) -> Past {
    read(&fx.app, id).expect("the detail")
}

fn labels(past: &Past) -> Vec<&'static str> {
    past.next
        .iter()
        .flat_map(|row| row.buttons.iter().map(|button| button.label))
        .collect()
}

fn row<'a>(past: &'a Past, text: &str) -> &'a NextRow {
    past.next
        .iter()
        .find(|row| row.text == text)
        .unwrap_or_else(|| panic!("no row {text}: {:?}", past.next))
}

fn press(fx: &mut Fixture, act: &Act) {
    let ctx = egui::Context::default();
    super::act(&mut fx.app, &ctx, act.clone());
}

/// The words of one frame of `draw`.
fn painted(draw: impl FnMut(&mut Ui)) -> String {
    fn collect(shape: &egui::Shape, out: &mut String) {
        match shape {
            egui::Shape::Text(text) => {
                out.push_str(text.galley.text());
                out.push('\n');
            }
            egui::Shape::Vec(shapes) => shapes.iter().for_each(|shape| collect(shape, out)),
            _ => {}
        }
    }
    let ctx = egui::Context::default();
    let input = egui::RawInput {
        screen_rect: Some(egui::Rect::from_min_size(
            egui::Pos2::ZERO,
            egui::vec2(600.0, 900.0),
        )),
        ..Default::default()
    };
    let mut draw = draw;
    let mut output = ctx.run_ui(input, |ui| draw(ui));
    output.textures_delta.clear();
    let mut text = String::new();
    for clipped in &output.shapes {
        collect(&clipped.shape, &mut text);
    }
    output.drop_without_applying_deltas();
    text
}

#[test]
fn a_past_decision_shows_one_reason_and_details_on_demand() {
    let mut fx = fixture();
    let item = fx.item;
    let id = record(&mut fx, Decision::unanswered(item));
    let detail = past(&fx, id);
    assert_eq!(detail.reason, "This credential belongs to another project.");
    assert!(detail.note.contains("is declared for the project"));
    assert_eq!(detail.command, "run sentry-cli releases");
    assert!(
        detail
            .details
            .contains(&("Asked you".to_owned(), "Yes".to_owned()))
    );
    let closed = painted(|ui| {
        draw_top(ui, &detail);
        draw_details(ui, &detail, &mut false, |_| {});
    });
    for expected in ["Why", detail.reason.as_str(), "Next time", "Details"] {
        assert!(closed.contains(expected), "{expected}: {closed}");
    }
    for hidden in ["Asked you", "is declared for the project", "run sentry-cli"] {
        assert!(!closed.contains(hidden), "{hidden}: {closed}");
    }
    let open = painted(|ui| draw_details(ui, &detail, &mut true, |_| {}));
    for expected in [
        "Asked you",
        "is declared for the project",
        "Command",
        "run sentry-cli releases",
    ] {
        assert!(open.contains(expected), "{expected}: {open}");
    }
}

#[test]
fn a_timed_out_question_offers_allow_and_saves_after_the_owner_check() {
    let mut fx = fixture();
    let item = fx.item;
    let id = record(&mut fx, Decision::unanswered(item));
    let detail = past(&fx, id);
    let allow = row(&detail, "Allow changes in apassy without asking");
    assert_eq!(
        allow.detail.as_deref(),
        Some("For every agent, with Guarded key. Safety rules still ask.")
    );
    assert_eq!(allow.buttons[0].label, "Allow…");
    assert_eq!(
        allow.buttons[0].spoken,
        "Allow changes in apassy without asking"
    );
    press(&mut fx, &allow.buttons[0].act);
    let check = fx.app.owner.check.as_ref().expect("the owner check opens");
    assert!(
        matches!(&check.request, OwnerRequest::RememberAnswer { item_id, .. } if *item_id == fx.item),
        "{:?}",
        check.request
    );
    let stored = |fx: &Fixture| {
        fx.app
            .owner_ui
            .session
            .with_vault(|vault| {
                vault.answer_for(fx.item, KEY, ActionKind::Change, AnswerScope::Project)
            })
            .expect("open")
            .expect("read")
    };
    assert!(stored(&fx).is_none(), "nothing before the check");
    fx.app
        .confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    assert!(stored(&fx).is_some());
    assert_eq!(fx.app.status_text, "Saved. Safety rules can still ask.");
    let detail = past(&fx, id);
    assert_eq!(
        row(&detail, "Rule: Allow changes in apassy").buttons[0].label,
        "Remove"
    );
    assert!(!labels(&detail).contains(&"Allow…"));
}

#[test]
fn always_ask_and_never_act_at_once_and_remove_asks_for_the_check() {
    let mut fx = fixture();
    let item = fx.item;
    let id = record(&mut fx, Decision::unanswered(item));
    let detail = past(&fx, id);
    let standing = row(&detail, "Next uses by Claude Code");
    let spoken: Vec<&str> = standing
        .buttons
        .iter()
        .map(|button| button.spoken.as_str())
        .collect();
    assert_eq!(
        spoken,
        [
            "Always ask Claude Code for Guarded key",
            "Never give Guarded key to Claude Code"
        ]
    );
    assert_eq!(standing.buttons[1].style, Style::DestructiveBordered);
    press(&mut fx, &standing.buttons[0].act);
    assert!(fx.app.owner.check.is_none(), "stricter: no check");
    assert_eq!(
        fx.app.status_text,
        "Each use of Guarded key by Claude Code now asks you."
    );
    let detail = past(&fx, id);
    let exception = row(&detail, "Always asks for Claude Code");
    assert_eq!(exception.buttons[0].label, "Remove…");
    assert_eq!(
        exception.buttons[0].spoken,
        "Remove Always ask for Claude Code"
    );
    press(&mut fx, &exception.buttons[0].act);
    let check = fx
        .app
        .owner
        .check
        .as_ref()
        .expect("removal needs the check");
    assert!(matches!(
        check.request,
        OwnerRequest::RemoveAgentException {
            kind: ExceptionKind::AlwaysAsk,
            ..
        }
    ));
    fx.app.close_owner_check(None);
    let still = fx
        .app
        .owner_ui
        .session
        .with_vault(|vault| vault.agent_view(fx.agent))
        .expect("open")
        .expect("view");
    assert!(still.always_ask.contains(&fx.item));
    // "Never" acts at once too, in a fresh detail.
    let mut fx = fixture();
    let item = fx.item;
    let id = record(&mut fx, Decision::unanswered(item));
    let detail = past(&fx, id);
    press(
        &mut fx,
        &row(&detail, "Next uses by Claude Code").buttons[1].act,
    );
    assert_eq!(fx.app.status_text, "Claude Code never gets Guarded key.");
    assert!(fx.app.owner.check.is_none());
}

#[test]
fn a_flagged_decision_has_no_button_that_loosens() {
    let mut fx = fixture();
    let item = fx.item;
    let id = record(
        &mut fx,
        Decision {
            why: DecisionWhy {
                reason: "HookFlags".to_owned(),
                ..DecisionWhy::default()
            },
            flags: &["injection_phrase", "secret_output"],
            ..Decision::unanswered(item)
        },
    );
    let detail = past(&fx, id);
    assert_eq!(detail.reason, "The command could print the secret.");
    let buttons = labels(&detail);
    for loosening in ["Allow…", "Turn Off…", "Remove…"] {
        assert!(!buttons.contains(&loosening), "{buttons:?}");
    }
    assert!(
        row(&detail, "A command like this asks every time.")
            .buttons
            .is_empty()
    );
}

#[test]
fn a_refused_or_denied_decision_has_no_button_that_loosens() {
    let mut fx = fixture();
    let (agent, item) = (fx.agent, fx.item);
    fx.app
        .owner_ui
        .session
        .with_vault(|vault| vault.add_agent_exception(agent, item, ExceptionKind::Never))
        .expect("open")
        .expect("never");
    let refused = record(
        &mut fx,
        Decision {
            asked: false,
            decided_by: DecidedBy::Rule,
            why: DecisionWhy {
                reason: "AccessCheck".to_owned(),
                code: "not_granted".to_owned(),
                ..DecisionWhy::default()
            },
            note: "The owner did not let this agent use item 1.",
            ..Decision::unanswered(item)
        },
    );
    let denied = record(
        &mut fx,
        Decision {
            decided_by: DecidedBy::Owner,
            ..Decision::unanswered(item)
        },
    );
    for id in [refused, denied] {
        let detail = past(&fx, id);
        let buttons = labels(&detail);
        for loosening in ["Allow…", "Turn Off…", "Remove…"] {
            assert!(!buttons.contains(&loosening), "{id}: {buttons:?}");
        }
        let never = row(&detail, "Never for Claude Code.");
        assert_eq!(never.buttons[0].act, Act::OpenCredential(item));
    }
    assert_eq!(
        past(&fx, refused).reason,
        "This agent may not use this credential."
    );
}

#[test]
fn a_remembered_answer_is_removed_from_its_decision() {
    let mut fx = fixture();
    let item = fx.item;
    fx.app
        .owner_ui
        .session
        .with_vault(|vault| {
            vault.remember_answer(
                item,
                &crate::vault::answers::ProjectRef {
                    key: KEY.to_owned(),
                    label: "apassy".to_owned(),
                },
                ActionKind::Change,
                "iPhone",
                &[],
            )
        })
        .expect("open")
        .expect("answer");
    let id = record(
        &mut fx,
        Decision {
            asked: false,
            decided_by: DecidedBy::Answer,
            decision: LoggedDecision::Allow,
            why: DecisionWhy {
                reason: "RememberedAnswer".to_owned(),
                ..DecisionWhy::default()
            },
            ..Decision::unanswered(item)
        },
    );
    let detail = past(&fx, id);
    assert_eq!(detail.reason, "Your rule covers this run.");
    let rule = row(&detail, "Rule: Allow changes in apassy");
    assert_eq!(
        rule.buttons[0].spoken,
        "Remove the rule: Allow changes in apassy"
    );
    press(&mut fx, &rule.buttons[0].act);
    assert_eq!(
        fx.app.status_text,
        "\u{201c}Allow changes in apassy\u{201d} is removed. The bouncer asks again."
    );
    let answers = fx
        .app
        .owner_ui
        .session
        .with_vault(|vault| vault.answers_for_item(item))
        .expect("open")
        .expect("answers");
    assert!(answers.is_empty());
}

#[test]
fn a_decision_with_two_credentials_has_no_action() {
    let mut fx = fixture();
    let item = fx.item;
    let second = fx
        .app
        .owner_ui
        .session
        .with_vault(|vault| {
            vault
                .add(ItemDraft {
                    title: "Second key".to_owned(),
                    kind: CredentialKind::ApiKey,
                    notes: String::new(),
                    tags: Vec::new(),
                    fields: vec![Field {
                        name: "token".to_owned(),
                        value: SecretValue::new("SYNTH-second-value".to_owned()),
                        secret: true,
                    }],
                })
                .expect("add")
                .id
        })
        .expect("open");
    let id = record(
        &mut fx,
        Decision {
            items: vec![item, second],
            ..Decision::unanswered(item)
        },
    );
    let detail = past(&fx, id);
    assert_eq!(detail.next.len(), 1, "{:?}", detail.next);
    assert_eq!(
        detail.next[0].text,
        "This run used 2 credentials. Change their rules in each credential."
    );
    assert!(detail.next[0].buttons.is_empty());
}

#[test]
fn the_phrase_comes_from_the_stored_word() {
    let mut fx = fixture();
    let item = fx.item;
    let (index, _) =
        crate::broker::shell_risk::injection_match("Ask the bouncer.").expect("a phrase");
    let flagged = |inject: String| Decision {
        why: DecisionWhy {
            reason: "HookFlags".to_owned(),
            inject,
            ..DecisionWhy::default()
        },
        flags: &["injection_phrase"],
        ..Decision::unanswered(item)
    };
    let id = record(&mut fx, flagged(format!("prompt:{index}")));
    let detail = past(&fx, id);
    assert_eq!(
        detail.reason,
        "Your prompt mentions \u{201c}the bouncer\u{201d}."
    );
    assert!(
        !detail.details.iter().any(|(label, _)| label == "Phrase"),
        "{:?}",
        detail.details
    );
    // Without a word that reads, the Why line is the sentence of the flag.
    for word in ["elsewhere:1", "prompt:99999", "prompt:x", ""] {
        let id = record(&mut fx, flagged(word.to_owned()));
        assert_eq!(
            past(&fx, id).reason,
            "The request text mentions the bouncer or an approval.",
            "{word}"
        );
    }
    // With another flag first, the Why line is that flag's sentence.
    let id = record(
        &mut fx,
        Decision {
            flags: &["injection_phrase", "secret_output"],
            ..flagged(format!("prompt:{index}"))
        },
    );
    assert_eq!(past(&fx, id).reason, "The command could print the secret.");
}

/// The texts of all buttons of the rows, and what each does.
fn acts(past: &Past) -> Vec<(&'static str, &Act)> {
    past.next
        .iter()
        .flat_map(|row| row.buttons.iter().map(|button| (button.label, &button.act)))
        .collect()
}

/// A button that gives authority back: it opens an owner check that loosens.
fn loosens(act: &Act) -> bool {
    matches!(
        act,
        Act::Ask(request) if matches!(
            **request,
            OwnerRequest::RememberAnswer { .. }
                | OwnerRequest::AlwaysAskOff { .. }
                | OwnerRequest::RemoveAgentException { .. }
        )
    )
}

fn pattern_key(agent: u64, project: &str, item: u64, template: &str) -> crate::vault::PatternKey {
    crate::vault::PatternKey {
        agent_id: agent,
        project_dir: project.to_owned(),
        items: vec![item],
        policy: String::new(),
        cwd_rel: ".".to_owned(),
        template: template.to_owned(),
    }
}

/// F1: a remembered pattern keeps the project key (the `.git` folder of a git project),
/// not the project folder. "Forget" removes exactly the pattern of this command; a
/// blocked one, and those of another project or agent, stay. A pattern blocked after the
/// detail was drawn stays too.
#[test]
fn forget_removes_the_pattern_of_this_command_only() {
    let mut fx = fixture();
    let (agent, item) = (fx.agent, fx.item);
    let display = "sentry-cli releases";
    let now = crate::broker::learning::now();
    let ids = fx
        .app
        .owner_ui
        .session
        .with_vault(|vault| {
            let other_agent = vault.register_agent("Codex").expect("agent").0.id;
            let mut ids = Vec::new();
            for key in [
                pattern_key(agent, KEY, item, "this"),
                pattern_key(agent, "/synthetic/other/.git", item, "this"),
                pattern_key(other_agent, KEY, item, "this"),
            ] {
                for at in 0..3 {
                    vault
                        .remember_approval(&key, display, now + at)
                        .expect("approval");
                }
                ids.push(vault.pattern(&key).expect("read").expect("pattern").id);
            }
            let blocked = pattern_key(agent, KEY, item, "blocked");
            vault.block_pattern(&blocked, display, now).expect("block");
            ids.push(vault.pattern(&blocked).expect("read").expect("pattern").id);
            ids
        })
        .expect("open");
    let id = record(
        &mut fx,
        Decision {
            asked: false,
            decided_by: DecidedBy::Pattern,
            decision: LoggedDecision::Allow,
            why: DecisionWhy {
                reason: "RememberedPattern".to_owned(),
                ..DecisionWhy::default()
            },
            pattern: display,
            ..Decision::unanswered(item)
        },
    );
    let detail = past(&fx, id);
    let forget = row(&detail, "Remembered command");
    assert_eq!(forget.buttons[0].act, Act::Forget(vec![ids[0]]));
    press(&mut fx, &forget.buttons[0].act);
    assert_eq!(
        fx.app.status_text,
        "Forgotten. Matching runs ask you again."
    );
    let left: Vec<u64> = fx
        .app
        .owner_ui
        .session
        .patterns()
        .expect("patterns")
        .into_iter()
        .map(|pattern| pattern.id)
        .collect();
    assert!(!left.contains(&ids[0]));
    for kept in &ids[1..] {
        assert!(left.contains(kept), "{kept}: {left:?}");
    }
    // S2: a pattern that is blocked between the drawing and the click stays.
    let key = pattern_key(agent, KEY, item, "this");
    let again = fx
        .app
        .owner_ui
        .session
        .with_vault(|vault| {
            for at in 0..3 {
                vault
                    .remember_approval(&key, display, now + 10 + at)
                    .expect("approval");
            }
            vault.pattern(&key).expect("read").expect("pattern").id
        })
        .expect("open");
    let detail = past(&fx, id);
    let forget = row(&detail, "Remembered command").buttons[0].act.clone();
    fx.app
        .owner_ui
        .session
        .with_vault(|vault| vault.block_pattern(&key, display, now + 20))
        .expect("open")
        .expect("block");
    press(&mut fx, &forget);
    let blocked = fx
        .app
        .owner_ui
        .session
        .patterns()
        .expect("patterns")
        .into_iter()
        .find(|pattern| pattern.id == again)
        .expect("the blocked pattern stays");
    assert!(blocked.blocked);
}

/// F19: the checks that no button loosens can fail. A flagged question with an offer
/// word in its row shows no "Allow…"; an "Always ask" exception shows "Remove…" on an
/// unanswered decision and only "Open Credential" on a refused one.
#[test]
fn a_flagged_or_refused_decision_shows_no_button_that_loosens_but_an_unanswered_one_can() {
    let mut fx = fixture();
    let (agent, item) = (fx.agent, fx.item);
    let flagged = record(
        &mut fx,
        Decision {
            why: DecisionWhy {
                reason: "HookFlags".to_owned(),
                offered: "in_project:change".to_owned(),
                ..DecisionWhy::default()
            },
            flags: &["secret_output"],
            ..Decision::unanswered(item)
        },
    );
    let detail = past(&fx, flagged);
    assert!(
        !acts(&detail).iter().any(|(_, act)| loosens(act)),
        "{:?}",
        detail.next
    );
    fx.app
        .owner_ui
        .session
        .with_vault(|vault| vault.add_agent_exception(agent, item, ExceptionKind::AlwaysAsk))
        .expect("open")
        .expect("always ask");
    let unanswered = record(&mut fx, Decision::unanswered(item));
    let detail = past(&fx, unanswered);
    assert!(
        acts(&detail)
            .iter()
            .any(|(label, act)| *label == "Remove…" && loosens(act)),
        "{:?}",
        detail.next
    );
    // F10: with the exception, the rule would not change what the agent sees.
    assert!(!acts(&detail).iter().any(|(label, _)| *label == "Allow…"));
    let refused = record(
        &mut fx,
        Decision {
            asked: false,
            decided_by: DecidedBy::Rule,
            why: DecisionWhy {
                reason: "AccessCheck".to_owned(),
                code: "invalid_request".to_owned(),
                ..DecisionWhy::default()
            },
            ..Decision::unanswered(item)
        },
    );
    let detail = past(&fx, refused);
    assert!(
        !acts(&detail).iter().any(|(_, act)| loosens(act)),
        "{:?}",
        detail.next
    );
    assert_eq!(
        row(&detail, "Always asks for Claude Code.").buttons[0].act,
        Act::OpenCredential(item)
    );
}

/// S5: a denied decision with "Always ask me" on shows the label with Open Credential,
/// never Turn Off…; an unanswered one shows Turn Off….
#[test]
fn always_ask_me_turns_off_only_from_a_decision_that_was_not_denied() {
    let mut fx = fixture();
    let item = fx.item;
    fx.app
        .owner_ui
        .session
        .with_vault(|vault| vault.set_always_ask(item, true))
        .expect("open")
        .expect("always ask");
    let asked = |decided_by, decision| Decision {
        decided_by,
        decision,
        why: DecisionWhy {
            reason: "AlwaysAsk".to_owned(),
            ..DecisionWhy::default()
        },
        ..Decision::unanswered(item)
    };
    let unanswered = record(&mut fx, asked(DecidedBy::NoAnswer, LoggedDecision::Deny));
    let detail = past(&fx, unanswered);
    assert_eq!(detail.reason, "This credential is marked Always ask.");
    let turn_off = row(&detail, "Always ask me");
    assert_eq!(turn_off.buttons[0].label, "Turn Off…");
    assert!(loosens(&turn_off.buttons[0].act));
    let denied = record(&mut fx, asked(DecidedBy::Owner, LoggedDecision::Deny));
    let detail = past(&fx, denied);
    assert_eq!(
        row(&detail, "Always ask me").buttons[0].act,
        Act::OpenCredential(item)
    );
    assert!(!acts(&detail).iter().any(|(label, _)| *label == "Turn Off…"));
}

/// F22: one-time codes, rows from before the reason words, and the sentences of why
/// nothing is remembered.
#[test]
fn codes_old_rows_and_why_nothing_is_remembered_read_in_plain_words() {
    let mut fx = fixture();
    let item = fx.item;
    let code = crate::vault::mfa::code_env_name(item);
    let codes = record(
        &mut fx,
        Decision {
            why: DecisionWhy {
                reason: "OneTimeCode".to_owned(),
                offered: "in_project:change".to_owned(),
                codes: "with_value".to_owned(),
                ..DecisionWhy::default()
            },
            env_names: vec!["SYNTH_SENTRY_KEY".to_owned(), code],
            ..Decision::unanswered(item)
        },
    );
    let detail = past(&fx, codes);
    assert_eq!(detail.reason, "This run needs a one-time code.");
    let allow = row(
        &detail,
        "Allow changes with one-time codes in apassy without asking",
    );
    assert!(matches!(
        &allow.buttons[0].act,
        Act::Ask(request) if matches!(**request, OwnerRequest::RememberAnswer { codes: true, .. })
    ));
    // Rows from before the words: the kind comes from the columns.
    let old_flagged = record(
        &mut fx,
        Decision {
            decided_by: DecidedBy::Owner,
            decision: LoggedDecision::Allow,
            why: DecisionWhy::default(),
            flags: &["secret_output"],
            note: "Rule flags: secret_output.",
            ..Decision::unanswered(item)
        },
    );
    let detail = past(&fx, old_flagged);
    assert_eq!(detail.reason, "The command could print the secret.");
    assert!(
        row(&detail, "A command like this asks every time.")
            .buttons
            .is_empty()
    );
    let old_plain = record(
        &mut fx,
        Decision {
            why: DecisionWhy::default(),
            note: "The owner did not answer this run.",
            ..Decision::unanswered(item)
        },
    );
    let detail = past(&fx, old_plain);
    assert_eq!(detail.reason, "The owner did not answer this run.");
    assert!(detail.note.is_empty(), "the hover would say the same");
    assert!(!acts(&detail).iter().any(|(label, _)| *label == "Allow…"));
    // Why nothing is remembered.
    let nothing = |word: &str| Decision {
        why: DecisionWhy {
            reason: "LowTaskMatch".to_owned(),
            noremember: word.to_owned(),
            ..DecisionWhy::default()
        },
        ..Decision::unanswered(item)
    };
    for (word, text) in [
        (
            "uncertain",
            "Apassy could not tell what this command changes, so it asks each time.",
        ),
        (
            "brain",
            "Nothing is remembered while the bouncer brain is off.",
        ),
    ] {
        let id = record(&mut fx, nothing(word));
        assert!(row(&past(&fx, id), text).buttons.is_empty(), "{word}");
    }
    // `production`: an environment that is not set opens the credential; a confirmed
    // production credential says that it asks every time.
    let unset = record(&mut fx, nothing("production"));
    fx.app
        .owner_ui
        .session
        .with_vault(|vault| {
            vault.save_declaration(
                item,
                &Declaration {
                    project: "apassy".to_owned(),
                    environment: crate::vault::providers::DEFAULT_ENVIRONMENT,
                    risk: RiskLevel::High,
                    scope: Scope::Admin,
                    reversibility: Reversibility::Irreversible,
                },
                None,
                None,
            )?;
            // Production only by default: the environment's source is the default value.
            vault.set_declaration_sources(
                item,
                &crate::vault::DeclarationSources {
                    environment: crate::vault::DeclarationSource::Default,
                    ..crate::vault::DeclarationSources::default()
                },
            )
        })
        .expect("open")
        .expect("unset");
    let detail = past(&fx, unset);
    assert_eq!(
        row(&detail, "Environment not set").buttons[0].act,
        Act::OpenCredential(item)
    );
    fx.app
        .owner_ui
        .session
        .with_vault(|vault| {
            vault.set_declaration_sources(
                item,
                &crate::vault::DeclarationSources {
                    environment: crate::vault::DeclarationSource::Owner,
                    ..crate::vault::DeclarationSources::default()
                },
            )
        })
        .expect("open")
        .expect("owner");
    let detail = past(&fx, unset);
    assert!(
        row(&detail, "This production credential asks every time.")
            .buttons
            .is_empty()
    );
}

/// S5: "Always ask me" turned on between the drawing of "Allow…" and the owner check:
/// the check passes, nothing is saved, and the message says why.
#[test]
fn a_change_between_the_row_and_the_check_saves_nothing() {
    let mut fx = fixture();
    let item = fx.item;
    let id = record(&mut fx, Decision::unanswered(item));
    let detail = past(&fx, id);
    press(
        &mut fx,
        &row(&detail, "Allow changes in apassy without asking").buttons[0].act,
    );
    assert!(fx.app.owner.check.is_some());
    fx.app
        .owner_ui
        .session
        .with_vault(|vault| vault.set_always_ask(item, true))
        .expect("open")
        .expect("always ask");
    fx.app
        .confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    assert_eq!(
        fx.app.status_text,
        "This answer is no longer offered. Answer the next question."
    );
    let answers = fx
        .app
        .owner_ui
        .session
        .with_vault(|vault| vault.answers_for_item(item))
        .expect("open")
        .expect("answers");
    assert!(answers.is_empty());
}

/// S5: with the "How often to ask" window open, an answer that tightens nothing still
/// completes at once, but "Allow…" opens the owner check every time.
#[test]
fn allow_opens_the_owner_check_while_the_owner_window_is_open() {
    use crate::broker::approvals::OwnerFrequency;
    let mut fx = fixture();
    let item = fx.item;
    let window = fx.app.owner_ui.session.owner_window.clone();
    window.configure(OwnerFrequency::OneMinute);
    window.observe(true);
    fx.app.owner_ui.session.lock().expect("lock");
    fx.app.owner_ui.session.unlock(PASS).expect("unlock");
    window.observe(true);
    let ctx = egui::Context::default();
    // The window covers an ordinary rule change of the credential: no dialog.
    fx.app
        .owner_ui
        .session
        .with_vault(|vault| vault.set_always_ask(item, true))
        .expect("open")
        .expect("always ask");
    fx.app.ask_owner(
        OwnerRequest::AlwaysAskOff {
            item_id: item,
            name: "Guarded key".to_owned(),
        },
        Some(&ctx),
    );
    assert!(fx.app.owner.check.is_none(), "the window covers it");
    let always_ask = fx
        .app
        .owner_ui
        .session
        .with_vault(|vault| vault.always_ask(item))
        .expect("open")
        .expect("read");
    assert!(!always_ask, "the window completed it");
    let id = record(&mut fx, Decision::unanswered(item));
    let detail = past(&fx, id);
    press(
        &mut fx,
        &row(&detail, "Allow changes in apassy without asking").buttons[0].act,
    );
    let check = fx.app.owner.check.as_ref().expect("the owner check opens");
    assert!(matches!(check.request, OwnerRequest::RememberAnswer { .. }));
    fx.app.close_owner_check(None);
}

#[test]
fn logs_and_history_keep_rejections_distinct_from_unanswered_questions() {
    use crate::desktop::ui::bouncer::{ActivityScope, LogFilter, LogKindFilter, LogSource};
    use crate::desktop::ui::decisions_bouncer::{HistoryFilter, State, history_events};
    use crate::desktop::ui::{bouncer_load, logs};

    let mut fx = fixture();
    let item = fx.item;
    let mut ids = Vec::new();
    for (by, code, words) in [
        (DecidedBy::Owner, "approval_denied", "Denied by you"),
        (DecidedBy::Rule, "not_visible", "Refused by policy"),
        (DecidedBy::NoAnswer, "approval_timeout", "Timed out"),
        (
            DecidedBy::NoAnswer,
            "approval_invalidated",
            "Request invalidated",
        ),
        (DecidedBy::NoAnswer, "", "No answer"),
    ] {
        let mut decision = Decision::unanswered(item);
        decision.decided_by = by;
        decision.asked = by != DecidedBy::Rule;
        decision.why.code = code.to_owned();
        let id = if code.is_empty() {
            // A legacy no-answer record without a linked concrete use cannot tell
            // us whether it timed out or was invalidated.
            record_with_use(&mut fx, decision, None)
        } else {
            record(&mut fx, decision)
        };
        ids.push((id, words));
    }
    // A final access check may refuse an earlier allowed decision. Preserve the
    // production binding to that actual use; changing precedence would hide it.
    let mut allowed = Decision::unanswered(item);
    allowed.decision = LoggedDecision::Allow;
    allowed.decided_by = DecidedBy::Model;
    allowed.asked = false;
    allowed.why = DecisionWhy {
        reason: "ModelAllowed".to_owned(),
        ..DecisionWhy::default()
    };
    let final_refusal = record_with_use(
        &mut fx,
        allowed,
        Some((UseOutcome::Refused, UseDecidedBy::Rule)),
    );
    ids.push((final_refusal, "Refused by policy"));
    fx.app
        .owner_ui
        .session
        .with_vault(|vault| {
            use crate::decision_log::DecisionOutcome;
            let rows = vault.bouncer_log(None, 200, None).unwrap();
            let expected = [
                DecisionOutcome::Denied,
                DecisionOutcome::Refused,
                DecisionOutcome::TimedOut,
                DecisionOutcome::Invalidated,
                DecisionOutcome::Unanswered,
                DecisionOutcome::Refused,
            ];
            for ((id, _), expected) in ids.iter().zip(expected) {
                let row = rows.iter().find(|row| row.decision_log_id == *id).unwrap();
                assert_eq!(
                    row.outcome_kind(),
                    expected,
                    "stored decision/use binding for {id}"
                );
            }
            let final_row = rows
                .iter()
                .find(|row| row.decision_log_id == final_refusal)
                .unwrap();
            assert!(
                final_row.allowed,
                "the earlier bouncer decision remains allowed"
            );
            assert_eq!(final_row.use_outcome, Some(DecisionOutcome::Refused));
            assert!(
                rows.iter()
                    .find(|row| row.decision_log_id == ids[4].0)
                    .unwrap()
                    .use_outcome
                    .is_none()
            );
        })
        .unwrap();
    let data = bouncer_load::load(&fx.app, &[], None, 1);
    for (id, words) in &ids {
        let event = data
            .events
            .iter()
            .find(|event| event.source == LogSource::Decision(*id))
            .unwrap();
        assert_eq!(event.outcome.text(), *words);
    }
    let scope = ActivityScope::default();
    let denied = history_events(
        &data,
        &scope,
        &State {
            filter: HistoryFilter::Denied,
            ..State::default()
        },
    );
    assert_eq!(denied.len(), 3);
    assert!(denied.iter().all(|event| matches!(&event.source, LogSource::Decision(id) if *id == ids[0].0 || *id == ids[1].0 || *id == final_refusal)));
    let logs = logs::LogsView::of(
        &data,
        &scope,
        &LogFilter {
            kind: LogKindFilter::Denied,
            ..LogFilter::default()
        },
        crate::broker::learning::now(),
        0,
    );
    assert_eq!(
        logs.groups
            .iter()
            .map(|(_, rows)| rows.len())
            .sum::<usize>(),
        3
    );
    assert_eq!(
        history_events(
            &data,
            &scope,
            &State {
                filter: HistoryFilter::AskedYou,
                ..State::default()
            }
        )
        .len(),
        4
    );
}

#[test]
fn logs_and_history_show_activity_only_refusals_without_duplicate_run_rows() {
    use crate::desktop::ui::bouncer::{ActivityScope, LogFilter, LogKind, LogSource};
    use crate::desktop::ui::decisions_bouncer::{State, history_events};
    use crate::desktop::ui::{bouncer_load, logs};
    use crate::vault::{ActivityDecision, NewActivity};

    let mut fx = fixture();
    let item = fx.item;
    let mut decision = Decision::unanswered(item);
    decision.decided_by = DecidedBy::Owner;
    decision.why.code = "approval_denied".to_owned();
    record(&mut fx, decision);
    fx.app.owner_ui.session.with_vault(|vault| {
        for (operation, reason) in [
            ("run sentry-cli releases", "The owner denied this run."),
            ("run sentry-cli releases", "The token is not valid or the agent is revoked."),
            ("request access", "The owner did not let this agent see this credential, or it is archived or gone."),
            ("mail task access", "An approved mail task matching this request is unavailable."),
        ] {
            vault.record_activity(&NewActivity {
                agent_id: Some(fx.agent), agent_name: "Claude Code".to_owned(), item_id: Some(item),
                operation: operation.to_owned(), decision: ActivityDecision::Deny, reason: reason.to_owned(),
            }).expect("synthetic activity");
        }
    }).expect("open");
    let data = bouncer_load::load(&fx.app, &[], None, 1);
    let scope = ActivityScope::default();
    let history = history_events(&data, &scope, &State::default());
    assert_eq!(
        history.len(),
        4,
        "one decision, three independent request refusals"
    );
    assert_eq!(
        history
            .iter()
            .filter(|event| event.kind == LogKind::Request)
            .count(),
        3
    );
    assert!(
        history
            .iter()
            .filter(|event| matches!(event.source, LogSource::Activity(_)))
            .all(|event| event.expandable() && event.command.contains('\n'))
    );
    let request = history
        .iter()
        .find(|event| event.kind == LogKind::Request)
        .unwrap();
    let detail = painted(|ui| {
        crate::desktop::ui::decisions_bouncer::history_detail(
            ui,
            request,
            crate::broker::learning::now(),
            false,
            |_| {},
            |_| {},
        )
    });
    assert!(detail.contains("Request"));
    assert!(detail.contains("Refused by policy"));
    assert!(detail.contains(request.command.lines().next().unwrap()));
    let logs = logs::LogsView::of(
        &data,
        &scope,
        &LogFilter::default(),
        crate::broker::learning::now(),
        0,
    );
    assert_eq!(
        logs.groups
            .iter()
            .map(|(_, rows)| rows.len())
            .sum::<usize>(),
        4
    );
    // A notification may still select an old, unstructured activity row. It cannot
    // turn that row into a policy decision or a second entry in History.
    let activity = fx
        .app
        .owner_ui
        .session
        .activity(10)
        .expect("activity")
        .into_iter()
        .find(|row| row.reason == "The owner denied this run.")
        .unwrap();
    crate::desktop::ui::logs::open_activity(&mut fx.app, activity.id);
    let selected = bouncer_load::load(&fx.app, &[], None, 1);
    let fallback = selected
        .events
        .iter()
        .find(|event| event.source == LogSource::Activity(activity.id))
        .unwrap();
    assert_eq!(fallback.outcome.text(), "Not allowed");
    assert!(!fallback.outcome.denied());
    assert_eq!(
        history_events(&selected, &scope, &State::default()).len(),
        4
    );
}

#[test]
fn stored_legacy_access_denial_appears_once_without_activity_or_decision_rows() {
    use crate::desktop::ui::bouncer::{
        ActivityScope, LogFilter, LogKind, LogKindFilter, LogSource,
    };
    use crate::desktop::ui::decisions_bouncer::{HistoryFilter, State, history_events};
    use crate::desktop::ui::{bouncer_load, logs};
    let mut fx = fixture();
    let id = fx
        .app
        .owner_ui
        .session
        .with_vault(|vault| {
            vault
                .set_env_binding(fx.item, "SYNTH_SENTRY_KEY", "token")
                .unwrap();
            vault
                .request_access(
                    fx.agent,
                    fx.item,
                    "SENSITIVE-ACCESS-REASON",
                    "/sensitive/cwd",
                )
                .unwrap()
                .0
        })
        .unwrap();
    fx.app
        .owner_ui
        .session
        .deny_access_request(id)
        .expect("real legacy Deny entry point");
    let at = fx
        .app
        .owner_ui
        .session
        .with_vault(|vault| {
            assert!(vault.bouncer_log(None, 200, None).unwrap().is_empty());
            assert!(vault.recent_activity(200).unwrap().is_empty());
            vault.denied_access_requests(None, 200).unwrap()[0].at
        })
        .unwrap();
    fx.app.owner_ui.session.lock().unwrap();
    fx.app.owner_ui.session.unlock(PASS).unwrap();
    let data = bouncer_load::load(&fx.app, &[], None, 1);
    let scope = ActivityScope::default();
    let events = history_events(
        &data,
        &scope,
        &State {
            filter: HistoryFilter::Denied,
            ..State::default()
        },
    );
    assert_eq!(events.len(), 1);
    let event = events[0];
    assert_eq!(event.source, LogSource::AccessRequest(id));
    assert_eq!(event.kind, LogKind::Request);
    assert_eq!(event.at, at);
    assert_eq!(
        event.outcome.text(),
        "Denied",
        "legacy unsigned state cannot establish its actor"
    );
    assert_eq!(event.agent.as_deref(), Some("Claude Code"));
    assert_eq!(event.credential.as_deref(), Some("Guarded key"));
    assert!(!event.command.contains("SENSITIVE-ACCESS-REASON"));
    assert!(!event.command.contains("/sensitive/cwd"));
    let view = logs::LogsView::of(
        &data,
        &scope,
        &LogFilter {
            kind: LogKindFilter::Denied,
            ..LogFilter::default()
        },
        crate::broker::learning::now(),
        0,
    );
    assert_eq!(
        view.groups
            .iter()
            .map(|(_, rows)| rows.len())
            .sum::<usize>(),
        1
    );
    let loaded_again = bouncer_load::load(&fx.app, &[], None, 1);
    assert_eq!(
        history_events(&loaded_again, &scope, &State::default()).len(),
        1
    );
}

#[test]
fn scoped_local_and_signed_iphone_access_denials_load_once_with_their_receipt_actor() {
    use crate::desktop::ui::bouncer::{ActivityScope, LogFilter, LogKindFilter, LogSource};
    use crate::desktop::ui::decisions_bouncer::{HistoryFilter, State, history_events};
    use crate::desktop::ui::{bouncer_load, logs};
    use crate::questions::access_request::{self as wire, Choice};
    use crate::sync::{DeviceKey, encode_b64u};
    use crate::vault::{RelayDevice, TrustedDeviceKind};
    const TEAM: &str = "t_7k2m5q4x3c";
    for remote in [false, true] {
        let mut fx = fixture();
        std::fs::create_dir(fx._dir.path().join(".git")).unwrap();
        let sign = DeviceKey::generate().unwrap();
        let answer = DeviceKey::generate().unwrap();
        let iphone = crate::relay::membership::new_device_uuid().unwrap();
        let id = fx
            .app
            .owner_ui
            .session
            .with_vault(|vault| {
                vault
                    .set_env_binding(fx.item, "SYNTH_SENTRY_KEY", "token")
                    .unwrap();
                if remote {
                    let mac = DeviceKey::generate().unwrap();
                    vault
                        .set_relay_device(&RelayDevice {
                            relay_url: "https://relay.example.test".to_owned(),
                            team_id: TEAM.to_owned(),
                            device_id: 2,
                            public_key: mac.public_key().to_vec(),
                            key_pkcs8: mac.pkcs8().unwrap().clone(),
                            created_at: 0,
                            account_key: false,
                        })
                        .unwrap();
                    crate::relay::membership::enable_questions(vault, "Synthetic Mac").unwrap();
                    vault
                        .register_trusted_device(
                            &iphone,
                            "Synthetic iPhone",
                            TrustedDeviceKind::Iphone,
                            sign.public_key(),
                            Some(answer.public_key()),
                        )
                        .unwrap();
                    vault.set_trusted_device_relay_id(&iphone, TEAM, 7).unwrap();
                }
                let agent = vault
                    .list_agents()
                    .unwrap()
                    .into_iter()
                    .find(|agent| agent.id == fx.agent)
                    .unwrap();
                let response = crate::broker::access_once::create(
                    vault,
                    &agent,
                    fx.item,
                    "SENSITIVE-SCOPED-REASON",
                    fx._dir.path().to_str(),
                    &wire::Scope {
                        action: wire::Action::Read,
                        hosts: vec!["api.example.test".to_owned()],
                    },
                );
                assert!(response.ok, "{response:?}");
                response.result.unwrap()["request_id"].as_u64().unwrap()
            })
            .unwrap();
        let project = fx
            .app
            .owner_ui
            .session
            .with_vault(|vault| {
                vault
                    .scoped_access_request(id)
                    .unwrap()
                    .card
                    .card
                    .project
                    .unwrap()
                    .label
            })
            .unwrap();
        if remote {
            fx.app
                .owner_ui
                .session
                .with_vault(|vault| {
                    let card = vault.scoped_access_request(id).unwrap().card;
                    let mut denied = wire::Answer::prepare(
                        &card,
                        &iphone,
                        Choice::Deny,
                        crate::vault::access_once::now(),
                    )
                    .unwrap();
                    denied.signature =
                        encode_b64u(&sign.sign(&denied.message(&card).unwrap()).unwrap());
                    crate::broker::access_once::RemoteAccessAnswer::verify(vault, id, denied, 7)
                        .unwrap()
                        .commit(vault)
                        .unwrap();
                })
                .unwrap();
        } else {
            fx.app
                .owner_ui
                .session
                .deny_access_request(id)
                .expect("real local scoped Deny entry point");
        }
        fx.app.owner_ui.session.lock().unwrap();
        fx.app.owner_ui.session.unlock(PASS).unwrap();
        let data = bouncer_load::load(&fx.app, &[], None, 1);
        let scope = ActivityScope::default();
        let denied = history_events(
            &data,
            &scope,
            &State {
                filter: HistoryFilter::Denied,
                ..State::default()
            },
        );
        assert_eq!(denied.len(), 1);
        assert_eq!(denied[0].source, LogSource::AccessRequest(id));
        assert_eq!(denied[0].project, project);
        assert_eq!(
            denied[0].outcome.text(),
            if remote {
                "Denied on Synthetic iPhone"
            } else {
                "Denied by you"
            }
        );
        assert!(!denied[0].command.contains("SENSITIVE-SCOPED-REASON"));
        assert_eq!(
            history_events(
                &data,
                &scope,
                &State {
                    filter: HistoryFilter::AskedYou,
                    ..State::default()
                }
            )
            .len(),
            1
        );
        let shown = logs::LogsView::of(
            &data,
            &scope,
            &LogFilter {
                kind: LogKindFilter::Denied,
                ..LogFilter::default()
            },
            crate::broker::learning::now(),
            0,
        );
        assert_eq!(
            shown
                .groups
                .iter()
                .map(|(_, rows)| rows.len())
                .sum::<usize>(),
            1
        );
    }
}
