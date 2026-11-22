//! One typed SMTP submission. No raw commands, caller headers, extra recipients or retry.
//! Credentials are used only after verifying TLS. Errors expose no server reply text.
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::prelude::{BASE64_STANDARD, Engine as _};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use zeroize::Zeroizing;

#[path = "../../crates/apassy-relay/src/server/smtp_transport.rs"]
#[allow(dead_code)] // The relay additionally uses setup/refused_sender.
mod transport;
use transport::{MailError, Session};

const SESSION_TIMEOUT: Duration = Duration::from_secs(60);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_BODY_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SubmissionOutcome {
    /// No DATA was sent, or the server explicitly rejected the DATA transaction.
    NotSubmitted,
    /// DATA may have reached the server, but its acceptance could not be confirmed.
    /// A caller must not retry this transaction automatically.
    Unknown,
}

/// All fields are bounded, static metadata. Never contains credentials or reply text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SubmissionError {
    pub outcome: SubmissionOutcome,
    pub step: &'static str,
    pub reply: Option<u16>,
}

impl From<MailError> for SubmissionError {
    fn from(error: MailError) -> Self {
        Self {
            outcome: SubmissionOutcome::NotSubmitted,
            step: error.step,
            reply: error.reply,
        }
    }
}
impl std::fmt::Display for SubmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SMTP {} ({:?})", self.step, self.outcome)
    }
}
impl std::error::Error for SubmissionError {}

/// Share the consent registry's conservative single-mailbox grammar so the
/// transport cannot silently broaden the address that the owner authorized.
fn valid_mailbox(address: &str) -> bool {
    super::mail_tasks::valid_mail_recipient(address)
}

/// Submit one message to one recipient, with no retry. Success means that the
/// submission server accepted DATA, not that the inbox received the message.
/// Revalidate consent immediately before credential transmission and before DATA.
/// Returning false aborts without sending the corresponding external effect.
#[allow(clippy::too_many_arguments)]
pub(super) fn submit_checked(
    host: &str,
    port: u16,
    username: &str,
    password: &str,
    from: &str,
    recipient: &str,
    subject: &str,
    body: &str,
    before_auth: impl FnOnce() -> bool,
    before_data: impl FnOnce() -> bool,
) -> Result<(), SubmissionError> {
    let message = prepare(
        host, port, username, password, from, recipient, subject, body,
    )?;
    let deadline = Instant::now() + SESSION_TIMEOUT;
    let tls = tls_config()?;
    // System DNS has no deadline API. Keep only this bounded resolution result; the
    // resolver thread has no credentials or message and can never submit anything.
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let host_owned = host.to_owned();
    std::thread::Builder::new()
        .name("task-smtp-resolve".into())
        .spawn(move || {
            let result = (host_owned.as_str(), port)
                .to_socket_addrs()
                .map(|addresses| addresses.take(16).collect::<Vec<_>>());
            let _ = sender.send(result);
        })
        .map_err(|_| MailError::at("resolve"))?;
    let addresses = receiver
        .recv_timeout(CONNECT_TIMEOUT)
        .map_err(|_| MailError::at("resolve"))?
        .map_err(|_| MailError::at("resolve"))?;
    let tcp = connect(&addresses, deadline)?;
    transact(
        tcp,
        &tls,
        host,
        port == 465,
        username,
        password,
        from,
        recipient,
        &message,
        deadline,
        before_auth,
        before_data,
    )
}

fn tls_config() -> Result<Arc<ClientConfig>, MailError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls_platform_verifier::Verifier::new(Arc::clone(&provider))
        .map_err(|_| MailError::at("certificate roots"))?;
    Ok(Arc::new(
        ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| MailError::at("tls"))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth(),
    ))
}

fn connect(addresses: &[SocketAddr], deadline: Instant) -> Result<TcpStream, MailError> {
    for address in addresses {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(MailError::at("connect"));
        }
        if let Ok(tcp) = TcpStream::connect_timeout(address, left.min(CONNECT_TIMEOUT)) {
            return Ok(tcp);
        }
    }
    Err(MailError::at("connect"))
}

#[allow(clippy::too_many_arguments)]
fn prepare(
    host: &str,
    port: u16,
    username: &str,
    password: &str,
    from: &str,
    recipient: &str,
    subject: &str,
    body: &str,
) -> Result<Zeroizing<String>, MailError> {
    if host.is_empty() || host.len() > 253 || port == 0 || ServerName::try_from(host).is_err() {
        return Err(MailError::at("host"));
    }
    if username.is_empty()
        || password.is_empty()
        || username.len() > 4096
        || password.len() > 4096
        || username.contains('\0')
        || password.contains('\0')
    {
        return Err(MailError::at("credentials"));
    }
    if !valid_mailbox(from) || !valid_mailbox(recipient) {
        return Err(MailError::at("address"));
    }
    if subject.len() > 4096 || subject.chars().any(char::is_control) {
        return Err(MailError::at("subject"));
    }
    if body.len() > MAX_BODY_BYTES || body.contains('\0') {
        return Err(MailError::at("body"));
    }
    message(from, recipient, subject, body)
}

/// RFC 2047 words are split on UTF-8 boundaries and folded between words. Each is
/// <= 68 bytes, below the 75-byte encoded-word limit, including the charset markers.
fn encoded_subject(subject: &str) -> String {
    let mut words = Vec::new();
    let mut chunk = String::new();
    for character in subject.chars() {
        if chunk.len() + character.len_utf8() > 42 {
            words.push(format!(
                "=?UTF-8?B?{}?=",
                BASE64_STANDARD.encode(chunk.as_bytes())
            ));
            chunk.clear();
        }
        chunk.push(character);
    }
    if !chunk.is_empty() {
        words.push(format!(
            "=?UTF-8?B?{}?=",
            BASE64_STANDARD.encode(chunk.as_bytes())
        ));
    }
    words.join("\r\n ")
}

fn message(
    from: &str,
    recipient: &str,
    subject: &str,
    body: &str,
) -> Result<Zeroizing<String>, MailError> {
    let now = time::OffsetDateTime::now_utc();
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let date = format!(
        "{:02} {} {} {:02}:{:02}:{:02} +0000",
        now.day(),
        MONTHS[usize::from(u8::from(now.month())) - 1],
        now.year(),
        now.hour(),
        now.minute(),
        now.second()
    );
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).map_err(|_| MailError::at("message id"))?;
    let id = id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let domain = from
        .split_once('@')
        .ok_or_else(|| MailError::at("address"))?
        .1;
    let mut result = Zeroizing::new(format!(
        "Date: {date}\r\nFrom: <{from}>\r\nTo: <{recipient}>\r\nSubject: {}\r\nMessage-ID: <{id}@{domain}>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n",
        encoded_subject(subject)
    ));
    // Canonical MIME text has CRLF. Base64 supports Unicode and arbitrarily long
    // logical lines without SMTPUTF8 or 8BITMIME; wire lines are at most 76 bytes.
    let canonical = Zeroizing::new(
        body.replace("\r\n", "\n")
            .replace('\r', "\n")
            .replace('\n', "\r\n"),
    );
    let encoded = Zeroizing::new(BASE64_STANDARD.encode(canonical.as_bytes()));
    for line in encoded.as_bytes().chunks(76) {
        result.push_str(std::str::from_utf8(line).map_err(|_| MailError::at("body"))?);
        result.push_str("\r\n");
    }
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
fn transact(
    tcp: TcpStream,
    tls: &Arc<ClientConfig>,
    host: &str,
    implicit: bool,
    username: &str,
    password: &str,
    from: &str,
    recipient: &str,
    message: &str,
    deadline: Instant,
    before_auth: impl FnOnce() -> bool,
    before_data: impl FnOnce() -> bool,
) -> Result<(), SubmissionError> {
    let mut session = Session::new(tcp, deadline, IO_TIMEOUT);
    if implicit {
        session = session.start_tls(tls, host)?;
    }
    session.expect("greeting", &[220])?;
    let mut extensions = session.ehlo("localhost")?;
    if !implicit {
        if !extensions.iter().any(|line| {
            line.split_whitespace()
                .next()
                .is_some_and(|word| word.eq_ignore_ascii_case("STARTTLS"))
        }) {
            return Err(MailError::at("starttls offered").into());
        }
        session.command("STARTTLS")?;
        session.expect("starttls", &[220])?;
        session = session.start_tls(tls, host)?;
        extensions = session.ehlo("localhost")?;
    }
    let mechanisms = extensions
        .iter()
        .filter(|line| {
            line.split_whitespace()
                .next()
                .is_some_and(|word| word.eq_ignore_ascii_case("AUTH"))
        })
        .flat_map(|line| line.split_whitespace().skip(1))
        .collect::<Vec<_>>();
    if !before_auth() {
        return Err(MailError::at("authorization").into());
    }
    if mechanisms
        .iter()
        .any(|word| word.eq_ignore_ascii_case("PLAIN"))
    {
        let token = Zeroizing::new(format!("\0{username}\0{password}"));
        let encoded = Zeroizing::new(BASE64_STANDARD.encode(token.as_bytes()));
        let command = Zeroizing::new(format!("AUTH PLAIN {}", encoded.as_str()));
        session.command(&command)?;
        session.expect("auth", &[235])?;
    } else if mechanisms
        .iter()
        .any(|word| word.eq_ignore_ascii_case("LOGIN"))
    {
        session.command("AUTH LOGIN")?;
        session.expect("auth", &[334])?;
        let user = Zeroizing::new(BASE64_STANDARD.encode(username.as_bytes()));
        session.command(&user)?;
        session.expect("auth", &[334])?;
        let secret = Zeroizing::new(BASE64_STANDARD.encode(password.as_bytes()));
        session.command(&secret)?;
        session.expect("auth", &[235])?;
    } else {
        return Err(MailError::at("auth offered").into());
    }
    session.command(&format!("MAIL FROM:<{from}>"))?;
    session.expect("mail from", &[250])?;
    session.command(&format!("RCPT TO:<{recipient}>"))?;
    session.expect("rcpt to", &[250, 251])?;
    session.command("DATA")?;
    session.expect("data", &[354])?;
    if !before_data() {
        return Err(MailError::at("authorization").into());
    }
    // Conservatively mark every write failure unknown, even if it might have failed
    // before the final dot. Only an explicit negative DATA reply proves rejection.
    session
        .write_data(message)
        .map_err(|error| SubmissionError {
            outcome: SubmissionOutcome::Unknown,
            step: error.step,
            reply: error.reply,
        })?;
    session
        .expect("message", &[250])
        .map_err(|error| SubmissionError {
            outcome: if error.reply.is_some_and(|code| (400..600).contains(&code)) {
                SubmissionOutcome::NotSubmitted
            } else {
                SubmissionOutcome::Unknown
            },
            step: error.step,
            reply: error.reply,
        })?;
    // Submission is confirmed even if the peer fails before answering QUIT.
    let _ = session.command("QUIT");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::Mutex;

    const HOST: &str = "smtp.apassy.test";
    const FROM: &str = "sender@apassy.test";
    const TO: &str = "recipient@example.test";
    const USER: &str = "synthetic-user";
    const PASSWORD: &str = "synthetic-password";

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Mode {
        Accept,
        LostAck,
        RejectData,
        RejectRecipient,
        NoTls,
        Login,
    }
    #[derive(Default)]
    struct Seen {
        commands: Vec<String>,
        messages: Vec<String>,
    }
    struct Fake {
        addr: SocketAddr,
        tls: Arc<ClientConfig>,
        seen: Arc<Mutex<Seen>>,
        thread: std::thread::JoinHandle<()>,
    }

    fn reply<S: Write>(reader: &mut BufReader<S>, text: &str) -> std::io::Result<()> {
        reader.get_mut().write_all(text.as_bytes())?;
        reader.get_mut().flush()
    }
    fn command<S: Read>(
        reader: &mut BufReader<S>,
        seen: &Mutex<Seen>,
        secure: bool,
    ) -> std::io::Result<String> {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if !line.is_empty() {
            seen.lock().unwrap().commands.push(format!(
                "{}:{}",
                if secure { "tls" } else { "plain" },
                line.trim_end()
            ));
        }
        Ok(line)
    }
    fn serve<S: Read + Write>(
        stream: S,
        seen: &Mutex<Seen>,
        mode: Mode,
        greeting: bool,
    ) -> std::io::Result<()> {
        let mut reader = BufReader::new(stream);
        if greeting {
            reply(&mut reader, "220 fake\r\n")?;
        }
        loop {
            let line = command(&mut reader, seen, true)?;
            if line.is_empty() {
                return Ok(());
            }
            if line.starts_with("EHLO ") {
                reply(
                    &mut reader,
                    if mode == Mode::Login {
                        "250-fake\r\n250 AUTH LOGIN\r\n"
                    } else {
                        "250-fake\r\n250 AUTH PLAIN\r\n"
                    },
                )?;
            } else if line.starts_with("AUTH PLAIN ") {
                let token = line.trim_end().strip_prefix("AUTH PLAIN ").unwrap();
                assert_eq!(
                    BASE64_STANDARD.decode(token).unwrap(),
                    format!("\0{USER}\0{PASSWORD}").as_bytes()
                );
                reply(&mut reader, "235 authenticated\r\n")?;
            } else if line == "AUTH LOGIN\r\n" {
                reply(&mut reader, "334 user\r\n")?;
                let user = command(&mut reader, seen, true)?;
                assert_eq!(
                    BASE64_STANDARD.decode(user.trim_end()).unwrap(),
                    USER.as_bytes()
                );
                reply(&mut reader, "334 password\r\n")?;
                let password = command(&mut reader, seen, true)?;
                assert_eq!(
                    BASE64_STANDARD.decode(password.trim_end()).unwrap(),
                    PASSWORD.as_bytes()
                );
                reply(&mut reader, "235 authenticated\r\n")?;
            } else if line.starts_with("MAIL FROM:") {
                reply(&mut reader, "250 sender\r\n")?;
            } else if line.starts_with("RCPT TO:") {
                reply(
                    &mut reader,
                    if mode == Mode::RejectRecipient {
                        "550 recipient rejected private text\r\n"
                    } else {
                        "250 recipient\r\n"
                    },
                )?;
            } else if line == "DATA\r\n" {
                reply(&mut reader, "354 continue\r\n")?;
                let mut data = String::new();
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line)? == 0 {
                        return Ok(());
                    }
                    if line == ".\r\n" {
                        break;
                    }
                    data.push_str(line.strip_prefix('.').unwrap_or(&line));
                }
                seen.lock().unwrap().messages.push(data);
                if mode == Mode::LostAck {
                    return Ok(());
                }
                reply(
                    &mut reader,
                    if mode == Mode::RejectData {
                        "554 rejected private text\r\n"
                    } else {
                        "250 accepted\r\n"
                    },
                )?;
            } else if line == "QUIT\r\n" {
                return Ok(());
            } else {
                return Err(std::io::Error::other("unexpected test command"));
            }
        }
    }

    fn fake(mode: Mode, implicit: bool) -> Fake {
        let certified = rcgen::generate_simple_self_signed(vec![HOST.into()]).unwrap();
        let certificate = certified.cert.der().clone();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server = Arc::new(
            ServerConfig::builder_with_provider(Arc::clone(&provider))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![certificate.clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                        certified.signing_key.serialize_der(),
                    )),
                )
                .unwrap(),
        );
        let mut roots = RootCertStore::empty();
        roots.add(certificate).unwrap();
        let tls = Arc::new(
            ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Seen::default()));
        let thread_seen = Arc::clone(&seen);
        let thread = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            tcp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            tcp.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
            let tcp = if implicit {
                tcp
            } else {
                let mut reader = BufReader::new(tcp);
                reply(&mut reader, "220 fake\r\n").unwrap();
                assert!(
                    command(&mut reader, &thread_seen, false)
                        .unwrap()
                        .starts_with("EHLO ")
                );
                if mode == Mode::NoTls {
                    reply(&mut reader, "250-fake\r\n250 AUTH PLAIN\r\n").unwrap();
                    // Client must stop without transmitting AUTH in cleartext.
                    let _ = command(&mut reader, &thread_seen, false);
                    return;
                }
                reply(&mut reader, "250-fake\r\n250 STARTTLS\r\n").unwrap();
                assert_eq!(
                    command(&mut reader, &thread_seen, false).unwrap(),
                    "STARTTLS\r\n"
                );
                reply(&mut reader, "220 go\r\n").unwrap();
                reader.into_inner()
            };
            let stream = StreamOwned::new(ServerConnection::new(server).unwrap(), tcp);
            let _ = serve(stream, &thread_seen, mode, implicit);
        });
        Fake {
            addr,
            tls,
            seen,
            thread,
        }
    }

    fn send_fake(
        fake: &Fake,
        implicit: bool,
        host: &str,
        auth: bool,
        data: bool,
        text: &str,
    ) -> Result<(), SubmissionError> {
        let tcp = TcpStream::connect(fake.addr).unwrap();
        transact(
            tcp,
            &fake.tls,
            host,
            implicit,
            USER,
            PASSWORD,
            FROM,
            TO,
            text,
            Instant::now() + Duration::from_secs(3),
            || auth,
            || data,
        )
    }

    #[test]
    fn typed_envelope_tls_headers_and_unicode_are_preserved_once() {
        for (mode, implicit) in [
            (Mode::Accept, false),
            (Mode::Accept, true),
            (Mode::Login, false),
        ] {
            let fake = fake(mode, implicit);
            let body = format!("Zażółć gęślą\n.\n{}", "😀".repeat(2000));
            let subject = "Zażółć gęślą 😀 ".repeat(20);
            let text = prepare(HOST, 587, USER, PASSWORD, FROM, TO, &subject, &body).unwrap();
            send_fake(&fake, implicit, HOST, true, true, &text).unwrap();
            fake.thread.join().unwrap();
            let seen = fake.seen.lock().unwrap();
            assert_eq!(seen.messages.len(), 1);
            assert_eq!(
                seen.commands
                    .iter()
                    .filter(|line| line.starts_with("tls:MAIL FROM:"))
                    .collect::<Vec<_>>(),
                vec![&format!("tls:MAIL FROM:<{FROM}>")]
            );
            assert_eq!(
                seen.commands
                    .iter()
                    .filter(|line| line.starts_with("tls:RCPT TO:"))
                    .collect::<Vec<_>>(),
                vec![&format!("tls:RCPT TO:<{TO}>")]
            );
            assert_eq!(
                seen.commands
                    .iter()
                    .filter(|line| line.as_str() == "tls:DATA")
                    .count(),
                1
            );
            assert!(
                !seen
                    .commands
                    .iter()
                    .any(|line| line.starts_with("plain:AUTH"))
            );
            let (headers, data) = seen.messages[0].split_once("\r\n\r\n").unwrap();
            let names = headers
                .split("\r\n")
                .filter(|line| !line.starts_with(' '))
                .map(|line| line.split_once(':').unwrap().0)
                .collect::<Vec<_>>();
            assert_eq!(
                names,
                [
                    "Date",
                    "From",
                    "To",
                    "Subject",
                    "Message-ID",
                    "MIME-Version",
                    "Content-Type",
                    "Content-Transfer-Encoding"
                ]
            );
            assert!(headers.contains(&format!("\r\nTo: <{TO}>\r\n")));
            let encoded = headers
                .split_once("Subject: ")
                .unwrap()
                .1
                .split("\r\nMessage-ID:")
                .next()
                .unwrap();
            let decoded = encoded
                .split_whitespace()
                .flat_map(|word| {
                    assert!(word.len() <= 75);
                    BASE64_STANDARD
                        .decode(
                            word.strip_prefix("=?UTF-8?B?")
                                .unwrap()
                                .strip_suffix("?=")
                                .unwrap(),
                        )
                        .unwrap()
                })
                .collect::<Vec<_>>();
            assert_eq!(String::from_utf8(decoded).unwrap(), subject);
            assert!(data.split("\r\n").all(|line| line.len() <= 76));
            assert_eq!(
                BASE64_STANDARD.decode(data.replace("\r\n", "")).unwrap(),
                body.replace('\n', "\r\n").as_bytes()
            );
        }
    }

    #[test]
    fn lost_acceptance_is_unknown_and_never_retried() {
        for (mode, outcome, messages) in [
            (Mode::LostAck, SubmissionOutcome::Unknown, 1),
            (Mode::RejectData, SubmissionOutcome::NotSubmitted, 1),
            (Mode::RejectRecipient, SubmissionOutcome::NotSubmitted, 0),
        ] {
            let fake = fake(mode, false);
            let message = prepare(HOST, 587, USER, PASSWORD, FROM, TO, "Subject", "Body").unwrap();
            let error = send_fake(&fake, false, HOST, true, true, &message).unwrap_err();
            assert_eq!(error.outcome, outcome);
            assert!(!format!("{error:?}").contains("private text"));
            fake.thread.join().unwrap();
            let seen = fake.seen.lock().unwrap();
            assert_eq!(seen.messages.len(), messages);
            assert_eq!(
                seen.commands
                    .iter()
                    .filter(|line| line.starts_with("tls:MAIL FROM:"))
                    .count(),
                1
            );
        }
    }

    #[test]
    fn no_tls_bad_certificate_and_revocation_stop_external_effects() {
        for (mode, host, auth, data, expect_auth) in [
            (Mode::NoTls, HOST, true, true, false),
            (Mode::Accept, "wrong.apassy.test", true, true, false),
            (Mode::Accept, HOST, false, true, false),
            (Mode::Accept, HOST, true, false, true),
        ] {
            let fake = fake(mode, false);
            let message = prepare(HOST, 587, USER, PASSWORD, FROM, TO, "Subject", "Body").unwrap();
            let error = send_fake(&fake, false, host, auth, data, &message).unwrap_err();
            assert_eq!(error.outcome, SubmissionOutcome::NotSubmitted);
            fake.thread.join().unwrap();
            let seen = fake.seen.lock().unwrap();
            assert!(seen.messages.is_empty());
            assert_eq!(
                seen.commands
                    .iter()
                    .any(|line| line.starts_with("tls:AUTH")),
                expect_auth
            );
            assert!(
                !seen
                    .commands
                    .iter()
                    .any(|line| line.starts_with("plain:AUTH"))
            );
        }
    }

    #[test]
    fn dot_stuffing_cannot_end_data_or_add_an_envelope() {
        let fake = fake(Mode::Accept, false);
        let text =
            "From: <sender@apassy.test>\r\n\r\n.\r\n..two\r\nMAIL FROM:<other@example.test>\r\n";
        send_fake(&fake, false, HOST, true, true, text).unwrap();
        fake.thread.join().unwrap();
        let seen = fake.seen.lock().unwrap();
        assert_eq!(seen.messages, [text]);
        assert_eq!(
            seen.commands
                .iter()
                .filter(|line| line.starts_with("tls:MAIL FROM:"))
                .count(),
            1
        );
    }

    #[test]
    fn validation_rejects_multiple_mailboxes_header_injection_and_auth_nuls() {
        for address in [
            "a@example.test,b@example.test",
            "a@example.test;",
            "a@example.test\r\nRCPT TO:<b@example.test>",
            "A <a@example.test>",
            "a(comment)@example.test",
            "a@@example.test",
            ".a@example.test",
            "a..b@example.test",
            "a@example..test",
            "a@-example.test",
            "a@[127.0.0.1]",
            "a@exämple.test",
        ] {
            assert!(!valid_mailbox(address), "{address:?}");
            assert!(prepare(HOST, 587, USER, PASSWORD, FROM, address, "Subject", "Body").is_err());
        }
        for subject in [
            "Subject\r\nBcc: victim@example.test",
            "Subject\nCc: victim@example.test",
            "bad\0",
            "bad\t",
        ] {
            assert!(prepare(HOST, 587, USER, PASSWORD, FROM, TO, subject, "Body").is_err());
        }
        assert!(
            prepare(
                HOST,
                587,
                "user\0other",
                PASSWORD,
                FROM,
                TO,
                "Subject",
                "Body"
            )
            .is_err()
        );
        assert!(
            prepare(
                HOST,
                587,
                USER,
                "password\0other",
                FROM,
                TO,
                "Subject",
                "Body"
            )
            .is_err()
        );
        assert!(valid_mailbox("first.last+tag@example.test"));
    }
}
