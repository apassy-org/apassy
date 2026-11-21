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

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use base64::prelude::{BASE64_STANDARD, Engine as _};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use zeroize::Zeroizing;

use crate::config::MailSettings;
use crate::error::{RelayError, RelayResult};
use crate::server::hub::Hub;
use crate::server::links::MAIL_SUBJECT;

/// The longest reply line the client reads (RFC 5321 allows 512 bytes).
const MAX_LINE: u64 = 2048;
/// The most lines of one reply.
const MAX_REPLY_LINES: usize = 100;
/// The whole of one SMTP session, from the connection to `QUIT`.
pub const SESSION_SECS: u64 = 60;
/// Mails the thread hands over in one round.
const BATCH: u32 = 10;
/// The first wait after a failure; it doubles up to `MAX_RETRY_SECS`.
const FIRST_RETRY_SECS: u64 = 30;
const MAX_RETRY_SECS: u64 = 600;

/// Why a submission failed: its step and the server's reply code, never the reply text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailError {
    pub step: &'static str,
    pub reply: Option<u16>,
}

impl MailError {
    fn at(step: &'static str) -> Self {
        Self { step, reply: None }
    }
}

impl std::fmt::Display for MailError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.reply {
            Some(code) => write!(f, "{} ({code})", self.step),
            None => f.write_str(self.step),
        }
    }
}

/// The TCP or the TLS connection of a session.
enum Wire {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl Wire {
    /// The timeouts of the socket under the session.
    fn set_timeouts(&self, timeout: Duration) -> std::io::Result<()> {
        let tcp = match self {
            Self::Plain(stream) => stream,
            Self::Tls(stream) => &stream.sock,
        };
        tcp.set_read_timeout(Some(timeout))?;
        tcp.set_write_timeout(Some(timeout))
    }
}

impl Read for Wire {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buf),
            Self::Tls(stream) => stream.read(buf),
        }
    }
}

impl Write for Wire {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(buf),
            Self::Tls(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::Tls(stream) => stream.flush(),
        }
    }
}

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

    /// Hands one mail to `to` with the subject of the code mail and `text` (CRLF lines) to
    /// the submission server.
    pub fn send(&self, to: &str, text: &str, now: u64) -> Result<(), MailError> {
        let from = &self.settings.from;
        if !plain_address(to) || !plain_address(from) {
            return Err(MailError::at("address"));
        }
        let message = Zeroizing::new(message(from, to, text, now)?);
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
        session.command(&format!("MAIL FROM:<{from}>"))?;
        session.expect("mail from", &[250])?;
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
        let session = Session {
            reader: BufReader::new(Wire::Plain(tcp)),
            deadline: std::time::Instant::now() + Duration::from_secs(SESSION_SECS),
            io_timeout: self.settings.io_timeout,
        };
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

/// One SMTP session, with one deadline for all of it.
struct Session {
    reader: BufReader<Wire>,
    deadline: std::time::Instant,
    io_timeout: Duration,
}

impl Session {
    /// The time left for the next read or write: at most the I/O timeout, never past the
    /// deadline of the session.
    fn arm(&mut self) -> Result<(), MailError> {
        let left = self
            .deadline
            .saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Err(MailError::at("deadline"));
        }
        self.reader
            .get_ref()
            .set_timeouts(left.min(self.io_timeout))
            .map_err(|_| MailError::at("deadline"))
    }

    fn command(&mut self, line: &str) -> Result<(), MailError> {
        self.arm()?;
        let wire = self.reader.get_mut();
        wire.write_all(line.as_bytes())
            .and_then(|()| wire.write_all(b"\r\n"))
            .and_then(|()| wire.flush())
            .map_err(|_| MailError::at("write"))
    }

    /// One reply: its code and the text of each line.
    fn reply(&mut self, step: &'static str) -> Result<(u16, Vec<String>), MailError> {
        let mut lines = Vec::new();
        loop {
            self.arm()?;
            let mut line = Vec::new();
            (&mut self.reader)
                .take(MAX_LINE)
                .read_until(b'\n', &mut line)
                .map_err(|_| MailError::at(step))?;
            if !line.ends_with(b"\n") {
                return Err(MailError::at(step));
            }
            while matches!(line.last(), Some(b'\n' | b'\r')) {
                line.pop();
            }
            let code = line
                .get(..3)
                .filter(|digits| digits.iter().all(u8::is_ascii_digit))
                .and_then(|digits| std::str::from_utf8(digits).ok())
                .and_then(|digits| digits.parse::<u16>().ok())
                .ok_or_else(|| MailError::at(step))?;
            let separator = line.get(3).copied().unwrap_or(b' ');
            lines.push(String::from_utf8_lossy(line.get(4..).unwrap_or_default()).into_owned());
            match separator {
                b' ' => return Ok((code, lines)),
                b'-' if lines.len() < MAX_REPLY_LINES => {}
                _ => return Err(MailError::at(step)),
            }
        }
    }

    fn expect(&mut self, step: &'static str, ok: &[u16]) -> Result<Vec<String>, MailError> {
        let (code, lines) = self.reply(step)?;
        if ok.contains(&code) {
            Ok(lines)
        } else {
            Err(MailError {
                step,
                reply: Some(code),
            })
        }
    }

    /// EHLO, and the extension lines of the answer (without the greeting line).
    fn ehlo(&mut self, name: &str) -> Result<Vec<String>, MailError> {
        self.command(&format!("EHLO {name}"))?;
        let lines = self.expect("ehlo", &[250])?;
        Ok(lines.into_iter().skip(1).collect())
    }

    /// TLS over the TCP connection, with the server's certificate checked for `host`.
    /// Bytes that came before the handshake are refused: a server, or a machine on the
    /// way, could put commands in front of it.
    fn start_tls(self, config: &Arc<ClientConfig>, host: &str) -> Result<Self, MailError> {
        if !self.reader.buffer().is_empty() {
            return Err(MailError::at("starttls"));
        }
        let Wire::Plain(tcp) = self.reader.into_inner() else {
            return Err(MailError::at("starttls"));
        };
        let left = self
            .deadline
            .saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Err(MailError::at("deadline"));
        }
        let timeout = left.min(self.io_timeout);
        tcp.set_read_timeout(Some(timeout))
            .and_then(|()| tcp.set_write_timeout(Some(timeout)))
            .map_err(|_| MailError::at("tls"))?;
        let name = ServerName::try_from(host.to_string()).map_err(|_| MailError::at("tls"))?;
        let connection =
            ClientConnection::new(Arc::clone(config), name).map_err(|_| MailError::at("tls"))?;
        let mut stream = StreamOwned::new(connection, tcp);
        // The handshake is finished, and the certificate checked, before any command.
        while stream.conn.is_handshaking() {
            if std::time::Instant::now() >= self.deadline {
                return Err(MailError::at("deadline"));
            }
            stream
                .conn
                .complete_io(&mut stream.sock)
                .map_err(|_| MailError::at("tls"))?;
        }
        Ok(Self {
            reader: BufReader::new(Wire::Tls(Box::new(stream))),
            deadline: self.deadline,
            io_timeout: self.io_timeout,
        })
    }

    /// The message, each line that starts with `.` doubled, then `CRLF . CRLF`.
    fn write_data(&mut self, message: &str) -> Result<(), MailError> {
        let mut data = Zeroizing::new(String::with_capacity(message.len() + 8));
        for line in message.split("\r\n") {
            if line.starts_with('.') {
                data.push('.');
            }
            data.push_str(line);
            data.push_str("\r\n");
        }
        // `split` gives one empty part after the last CRLF.
        if message.ends_with("\r\n") {
            let len = data.len() - 2;
            data.truncate(len);
        }
        data.push_str(".\r\n");
        self.arm()?;
        let wire = self.reader.get_mut();
        wire.write_all(data.as_bytes())
            .and_then(|()| wire.flush())
            .map_err(|_| MailError::at("write"))
    }
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
fn message(from: &str, to: &str, text: &str, now: u64) -> Result<String, MailError> {
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).map_err(|_| MailError::at("message id"))?;
    let id: String = id.iter().map(|byte| format!("{byte:02x}")).collect();
    let domain = from.rsplit('@').next().unwrap_or("localhost");
    Ok(format!(
        "Date: {date}\r\nFrom: Apassy <{from}>\r\nTo: <{to}>\r\nSubject: {MAIL_SUBJECT}\r\nMessage-ID: <{id}@{domain}>\r\n\
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

/// The `relay-mail` thread: it turns the waiting code requests into mails
/// (`Links::process_jobs`), also between two mails, so a slow server delays them by one
/// session at most (`SESSION_SECS`); it hands each due mail to the server and deletes it
/// once the server took it; a 5xx reply drops the mail at once; any other failure waits
/// longer each time; a mail that is not taken within an hour is deleted
/// (`Links::mail_failed`, the maintenance pass).
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
    while !stop.load(Ordering::Relaxed) {
        jobs();
        let now = crate::now_unix();
        let due = match links.due_mail(now, BATCH) {
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
                Err(error) if permanent(&error) => {
                    eprintln!(
                        "apassy-relay: a code mail was refused by the SMTP server at step {error}: it is dropped"
                    );
                    links.mail_sent(*id)
                }
                Err(error) => {
                    eprintln!(
                        "apassy-relay: a code mail was not taken by the SMTP server at step {error} (try {})",
                        tries + 1
                    );
                    links.mail_failed(*id, now, retry_after(*tries))
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
        let message = message("connect@apassy.example", "ada@example.com", text, 0).unwrap();
        assert!(message.contains("\r\nSubject: Your Apassy code\r\n"));
        assert!(message.ends_with(&format!("\r\n\r\n{text}")));
        assert!(!message.contains("http"));
    }
}
