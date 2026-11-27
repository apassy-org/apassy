//! The code mail of public links (connect-share-v1 section 10, docs/SPEC.md section 38.7):
//! the `relay-mail` thread hands each mail of the outbox in `links.db` to the operator's
//! SMTP submission server, and a small submission client on the relay's rustls stack.
//!
//! The client speaks only what one plain-text mail needs (RFC 5321, RFC 6409, RFC 8314):
//! TLS from the first byte on port 465, else a required STARTTLS; EHLO; AUTH PLAIN or
//! LOGIN, only over TLS; one `MAIL FROM`, one `RCPT TO`, `DATA`, and `QUIT`. The
//! certificate of the server is checked with the system roots (rustls-platform-verifier)
//! for the configured host name. Every address it sends is in the normal form of section
//! 6 (ASCII, no space, no angle bracket), so no command can carry another one.
//!
//! No log line holds an address, a code, the text of a mail, or a reply of the server
//! (a reply may quote the address): a failure names its step and its reply code only.
//!
//! The thread checks its session at start and then every `probe_secs` (`Mailer::probe`:
//! connect, TLS, EHLO, AUTH, `MAIL FROM`, `RSET`, `QUIT`; no mail). While the check fails,
//! and after a mail fails at AUTH or `MAIL FROM`, the mail is off (`Links::mail_on`).

use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use base64::prelude::{BASE64_STANDARD, Engine as _};
use rustls::ClientConfig;
use rustls::pki_types::{CertificateDer, ServerName};
use zeroize::Zeroizing;

use crate::config::MailSettings;
use crate::error::{RelayError, RelayResult};
use crate::server::hub::Hub;
use crate::server::links::{MAIL_SUBJECT, TEST_SUBJECT, TEST_TEXT};

/// The whole of one SMTP session, from the connection to `QUIT`.
pub const SESSION_SECS: u64 = 60;
/// Mails the thread hands over in one round.
const BATCH: u32 = 10;
/// The first wait after a failure; it doubles up to `MAX_RETRY_SECS`.
const FIRST_RETRY_SECS: u64 = 30;
const MAX_RETRY_SECS: u64 = 600;

#[path = "smtp_transport.rs"]
mod smtp_transport;
pub use smtp_transport::MailError;
use smtp_transport::Session;

/// A submission client for the settings of the relay. One per relay.
pub struct Mailer {
    settings: MailSettings,
    tls: Arc<ClientConfig>,
}

impl Mailer {
    /// The client of `settings`: the system roots, plus `extra_roots_der` (tests).
    pub fn new(settings: &MailSettings) -> RelayResult<Self> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = if settings.extra_roots_der.is_empty() {
            rustls_platform_verifier::Verifier::new(Arc::clone(&provider))
        } else {
            let roots: Vec<CertificateDer<'static>> = settings
                .extra_roots_der
                .iter()
                .map(|der| CertificateDer::from(der.clone()))
                .collect();
            rustls_platform_verifier::Verifier::new_with_extra_roots(roots, Arc::clone(&provider))
        }
        .map_err(|_| RelayError::internal("The system certificate roots cannot be loaded."))?;
        let tls = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| RelayError::internal("The TLS protocol versions cannot be set."))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        ServerName::try_from(settings.host.clone())
            .map_err(|_| RelayError::invalid("APASSY_CONNECT_SMTP_HOST is not a host name."))?;
        Ok(Self {
            settings: settings.clone(),
            tls: Arc::new(tls),
        })
    }

    /// Hands one code mail to `to` with `text` (CRLF lines) to the submission server.
    pub fn send(&self, to: &str, text: &str, now: u64) -> Result<(), MailError> {
        self.submit(to, MAIL_SUBJECT, text, now)
    }

    /// Hands one test mail to `to` with the configured settings (`apassy-relay
    /// mail-test`): the same session as a code mail, another subject and text, no code.
    pub fn send_test(&self, to: &str, now: u64) -> Result<(), MailError> {
        self.submit(to, TEST_SUBJECT, TEST_TEXT, now)
    }

    /// Checks the session without a mail: connect, TLS, EHLO, AUTH, `MAIL FROM` with the
    /// sender, then `RSET` and `QUIT`. No recipient is named and nothing is sent.
    pub fn probe(&self) -> Result<(), MailError> {
        let mut session = self.open().map_err(MailError::in_setup)?;
        session
            .command(&format!("MAIL FROM:<{}>", self.settings.from))
            .and_then(|()| session.expect("mail from", &[250]).map(drop))
            .map_err(MailError::in_setup)?;
        session.command("RSET")?;
        session.expect("rset", &[250])?;
        let _ = session.command("QUIT");
        Ok(())
    }

    /// One mail with `subject` and `text`. Every failure before `RCPT TO` is marked
    /// `setup` (`MailError::setup`).
    fn submit(&self, to: &str, subject: &str, text: &str, now: u64) -> Result<(), MailError> {
        let from = &self.settings.from;
        if !plain_address(to) || !plain_address(from) {
            return Err(MailError::at("address"));
        }
        let message = Zeroizing::new(message(from, to, subject, text, now)?);
        let mut session = self.open().map_err(MailError::in_setup)?;
        session
            .command(&format!("MAIL FROM:<{from}>"))
            .and_then(|()| session.expect("mail from", &[250]).map(drop))
            .map_err(MailError::in_setup)?;
        session.command(&format!("RCPT TO:<{to}>"))?;
        session.expect("rcpt to", &[250, 251])?;
        session.command("DATA")?;
        session.expect("data", &[354])?;
        session.write_data(&message)?;
        session.expect("message", &[250])?;
        // The mail is taken: a failed QUIT changes nothing.
        let _ = session.command("QUIT");
        Ok(())
    }

    /// The session up to the sender: the greeting, EHLO, STARTTLS (unless TLS from the
    /// first byte) and EHLO again, and AUTH when the relay has an account.
    fn open(&self) -> Result<Session, MailError> {
        let from = &self.settings.from;
        let mut session = self.connect()?;
        session.expect("greeting", &[220])?;
        let helo = from.rsplit('@').next().unwrap_or("localhost").to_string();
        let mut extensions = session.ehlo(&helo)?;
        if !self.settings.implicit_tls() {
            if !extensions.iter().any(|line| keyword(line) == "STARTTLS") {
                return Err(MailError::at("starttls offered"));
            }
            session.command("STARTTLS")?;
            session.expect("starttls", &[220])?;
            session = session.start_tls(&self.tls, &self.settings.host)?;
            extensions = session.ehlo(&helo)?;
        }
        if let Some((user, password)) = &self.settings.auth {
            let mechanisms: Vec<String> = extensions
                .iter()
                .filter(|line| keyword(line) == "AUTH")
                .flat_map(|line| {
                    line.split_whitespace()
                        .skip(1)
                        .map(str::to_ascii_uppercase)
                        .collect::<Vec<_>>()
                })
                .collect();
            if mechanisms.iter().any(|m| m == "PLAIN") {
                let mut token = Zeroizing::new(Vec::new());
                token.push(0);
                token.extend_from_slice(user.as_bytes());
                token.push(0);
                token.extend_from_slice(password.expose().as_bytes());
                let line =
                    Zeroizing::new(format!("AUTH PLAIN {}", BASE64_STANDARD.encode(&*token)));
                session.command(&line)?;
                session.expect("auth", &[235])?;
            } else if mechanisms.iter().any(|m| m == "LOGIN") {
                session.command("AUTH LOGIN")?;
                session.expect("auth", &[334])?;
                session.command(&BASE64_STANDARD.encode(user.as_bytes()))?;
                session.expect("auth", &[334])?;
                let secret = Zeroizing::new(BASE64_STANDARD.encode(password.expose().as_bytes()));
                session.command(&secret)?;
                session.expect("auth", &[235])?;
            } else {
                return Err(MailError::at("auth offered"));
            }
        }
        Ok(session)
    }

    /// TCP to the server (a fixed address in tests), and TLS at once on port 465.
    fn connect(&self) -> Result<Session, MailError> {
        let addresses: Vec<SocketAddr> = match self.settings.connect_to {
            Some(addr) => vec![addr],
            None => (self.settings.host.as_str(), self.settings.port)
                .to_socket_addrs()
                .map_err(|_| MailError::at("resolve"))?
                .collect(),
        };
        let tcp = addresses
            .iter()
            .find_map(|addr| TcpStream::connect_timeout(addr, self.settings.connect_timeout).ok())
            .ok_or_else(|| MailError::at("connect"))?;
        tcp.set_read_timeout(Some(self.settings.io_timeout))
            .and_then(|()| tcp.set_write_timeout(Some(self.settings.io_timeout)))
            .map_err(|_| MailError::at("connect"))?;
        let session = Session::new(
            tcp,
            std::time::Instant::now() + Duration::from_secs(SESSION_SECS),
            self.settings.io_timeout,
        );
        if self.settings.implicit_tls() {
            session.start_tls(&self.tls, &self.settings.host)
        } else {
            Ok(session)
        }
    }
}

/// The first word of an EHLO line, in capitals.
fn keyword(line: &str) -> String {
    line.split_whitespace()
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase()
}

/// An address that may go into a command: printable ASCII without space or angle bracket.
fn plain_address(address: &str) -> bool {
    !address.is_empty()
        && address.len() <= 254
        && address
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'<' && byte != b'>')
}

/// The date of a header (RFC 5322 section 3.3), in UTC.
pub fn rfc5322_date(now: u64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    // `fmt_time` gives `YYYY-MM-DD HH:MM:SSZ`.
    let text = crate::cli::commands::fmt_time(now);
    let year = &text[0..4];
    let month: usize = text[5..7].parse().unwrap_or(1);
    let day = &text[8..10];
    let clock = &text[11..19];
    let weekday = DAYS[((now / 86_400) % 7) as usize];
    let month = MONTHS[month.clamp(1, 12) - 1];
    format!("{weekday}, {day} {month} {year} {clock} +0000")
}

/// The whole message: the headers and `text`, every line ending in CRLF.
fn message(from: &str, to: &str, subject: &str, text: &str, now: u64) -> Result<String, MailError> {
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).map_err(|_| MailError::at("message id"))?;
    let id: String = id.iter().map(|byte| format!("{byte:02x}")).collect();
    let domain = from.rsplit('@').next().unwrap_or("localhost");
    Ok(format!(
        "Date: {date}\r\nFrom: Apassy <{from}>\r\nTo: <{to}>\r\nSubject: {subject}\r\nMessage-ID: <{id}@{domain}>\r\n\
         MIME-Version: 1.0\r\nContent-Type: text/plain; charset=us-ascii\r\nContent-Transfer-Encoding: 7bit\r\n\
         Auto-Submitted: auto-generated\r\n\r\n{text}",
        date = rfc5322_date(now),
    ))
}

/// The wait after the `tries`-th failure: 30 seconds, doubling, at most 10 minutes.
fn retry_after(tries: i64) -> u64 {
    let shift = u32::try_from(tries.clamp(0, 10)).unwrap_or(10);
    FIRST_RETRY_SECS
        .saturating_mul(1 << shift)
        .min(MAX_RETRY_SECS)
}

/// Turns the mail off when the thread ends, however it ends (a stop, or a panic): the
/// waiting code requests go with their address keys (`Links::mail_stopped`).
struct MailOff(Arc<crate::server::links::Links>);

impl Drop for MailOff {
    fn drop(&mut self) {
        self.0.mail_stopped();
    }
}

/// True for a reply that no later try changes (5xx, RFC 5321 section 4.2.1).
fn permanent(error: &MailError) -> bool {
    error.reply.is_some_and(|code| (500..600).contains(&code))
}

/// `apassy-relay mail-test <address>`: one test mail (`TEST_SUBJECT`, no code, no link)
/// to `address` with the mail settings of `config`, over the same session as a code mail.
/// It reads no `links.db` and runs beside a running relay. Answers the normal form of the
/// address that the server took; a failure names its step and reply code only.
pub fn mail_test(config: &crate::config::RelayConfig, address: &str) -> RelayResult<String> {
    let settings = config.connect.mail.as_ref().ok_or_else(|| {
        RelayError::invalid(
            "No mail sender is set: set APASSY_CONNECT_SMTP_HOST and APASSY_CONNECT_SMTP_FROM (docs/OPERATIONS.md 30.2).",
        )
    })?;
    let normal = crate::server::links::normal_address(address)
        .ok_or_else(|| RelayError::invalid("The address is not an e-mail address."))?;
    let mailer = Mailer::new(settings)?;
    mailer
        .send_test(&normal, crate::now_unix())
        .map_err(|error| {
            RelayError::internal(format!(
                "The SMTP server did not take the test mail: step {error}{}.",
                if error.setup {
                    " (before the recipient: the host, its certificate, the account, or the sender)"
                } else {
                    ""
                }
            ))
        })?;
    Ok(normal)
}

/// The `relay-mail` thread: it checks its SMTP session at start and then every
/// `probe_secs` (`Mailer::probe`, `Links::probed`); it turns the waiting code requests
/// into mails (`Links::process_jobs`), also between two mails, so a slow server delays
/// them by a check and a session at most (`SESSION_SECS` each); it hands each due mail to
/// the server (only one with time left in its hour for the round) and
/// deletes it once the server took it; a 5xx reply drops the mail at once; any other
/// failure waits longer each time; a mail that is not taken within an hour is deleted
/// (`Links::mail_failed`, the maintenance pass). A mail lost before its recipient was
/// named (`MailError::setup`) gives its counts back (`Links::mail_dropped`).
pub fn run(hub: Arc<Hub>, stop: Arc<AtomicBool>) {
    let Some(links) = hub.links().cloned() else {
        return;
    };
    let _off = MailOff(links.clone());
    let Some(mailer) = links.mailer() else {
        return;
    };
    let jobs = || {
        if links.process_jobs().is_err() {
            eprintln!("apassy-relay: a code request could not be made into a mail");
        }
    };
    let probe_every = links.probe_secs().map(Duration::from_secs);
    let mut next_probe = std::time::Instant::now();
    while !stop.load(Ordering::Relaxed) {
        if let Some(every) = probe_every
            && std::time::Instant::now() >= next_probe
        {
            links.probed(mailer.probe().err().as_ref());
            next_probe = std::time::Instant::now() + every;
        }
        jobs();
        let now = crate::now_unix();
        // A round of `BATCH` sessions of `SESSION_SECS` each, and a minute to spare.
        let ahead = u64::from(BATCH) * SESSION_SECS + 60;
        let due = match links.due_mail(now, BATCH, ahead) {
            Ok(due) => due,
            Err(_) => {
                eprintln!("apassy-relay: the mail outbox cannot be read");
                Vec::new()
            }
        };
        for (id, recipient, text, tries) in &due {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            jobs();
            let now = crate::now_unix();
            let stored = match mailer.send(recipient, text, now) {
                Ok(()) => links.mail_sent(*id),
                Err(error) => {
                    if error.refused_sender() {
                        links.sender_refused(&error);
                    }
                    if permanent(&error) {
                        eprintln!(
                            "apassy-relay: a code mail was refused by the SMTP server at step {error}: it is dropped"
                        );
                        links.mail_dropped(*id, error.setup)
                    } else {
                        eprintln!(
                            "apassy-relay: a code mail was not taken by the SMTP server at step {error} (try {})",
                            tries + 1
                        );
                        links.mail_failed(*id, now, retry_after(*tries), error.setup)
                    }
                }
            };
            if stored.is_err() {
                eprintln!("apassy-relay: the mail outbox cannot be written");
            }
        }
        if due.len() < BATCH as usize {
            links.wait_for_mail(Duration::from_secs(1));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_date_is_rfc_5322() {
        assert_eq!(rfc5322_date(0), "Thu, 01 Jan 1970 00:00:00 +0000");
        assert_eq!(
            rfc5322_date(1_764_331_200),
            "Fri, 28 Nov 2025 12:00:00 +0000"
        );
    }

    #[test]
    fn only_a_failure_before_the_recipient_is_the_relays_own() {
        let refused_auth = MailError {
            step: "auth",
            reply: Some(535),
            setup: false,
        }
        .in_setup();
        assert!(refused_auth.setup && refused_auth.refused_sender());
        let refused_sender = MailError {
            step: "mail from",
            reply: Some(553),
            setup: true,
        };
        assert!(refused_sender.refused_sender());
        // A 4xx there (a rate limit of the server) or a timeout leaves the mail on.
        for busy in [
            MailError {
                step: "mail from",
                reply: Some(450),
                setup: true,
            },
            MailError::at("auth").in_setup(),
        ] {
            assert!(!busy.refused_sender(), "{busy}");
        }
        assert!(MailError::at("auth offered").in_setup().refused_sender());
        // A failed connection or TLS is the relay's own, but does not stop the mail: the
        // next check of the session does that.
        let tls = MailError::at("tls").in_setup();
        assert!(tls.setup && !tls.refused_sender());
        // A refused recipient counts.
        let recipient = MailError {
            step: "rcpt to",
            reply: Some(550),
            setup: false,
        };
        assert!(!recipient.setup && !recipient.refused_sender());
    }

    #[test]
    fn retries_wait_longer_up_to_ten_minutes() {
        assert_eq!(retry_after(0), 30);
        assert_eq!(retry_after(1), 60);
        assert_eq!(retry_after(5), 600);
        assert_eq!(retry_after(100), 600);
    }

    #[test]
    fn a_command_takes_no_address_with_a_line_break_or_a_bracket() {
        assert!(plain_address("ada@example.com"));
        for bad in [
            "",
            "a b@example.com",
            "a>@example.com",
            "a@example.com\r\nRSET",
        ] {
            assert!(!plain_address(bad), "{bad:?}");
        }
    }

    #[test]
    fn the_message_has_the_contract_text_and_no_link() {
        let text = "Your code to open a shared Apassy item: 12345678\r\n\r\nIt works for 15 minutes. If you did not ask for it, ignore this mail.\r\n";
        let message = message(
            "connect@apassy.example",
            "ada@example.com",
            MAIL_SUBJECT,
            text,
            0,
        )
        .unwrap();
        assert!(message.contains("\r\nSubject: Your Apassy code\r\n"));
        assert!(message.ends_with(&format!("\r\n\r\n{text}")));
        assert!(!message.contains("http"));
    }
}
