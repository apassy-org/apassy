//! Shared SMTP wire protocol. Used by the relay and typed broker submission.
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;
const MAX_LINE: u64 = 2048;
const MAX_REPLY_LINES: usize = 100;
/// Why a submission failed: its step and the server's reply code, never the reply text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailError {
    pub step: &'static str,
    pub reply: Option<u16>,
    /// The failure came before the recipient was named: the connection, TLS, EHLO, AUTH,
    /// or `MAIL FROM`. That is the relay's own settings or its way to the server, never
    /// the recipient, so the mail does not count against the caps of the address, the
    /// recipient, or the account (`Links::mail_dropped`).
    pub setup: bool,
}

impl MailError {
    pub(super) fn at(step: &'static str) -> Self {
        Self {
            step,
            reply: None,
            setup: false,
        }
    }

    /// The same failure, marked as one before the recipient.
    pub(super) fn in_setup(self) -> Self {
        Self {
            setup: true,
            ..self
        }
    }

    /// True for a 5xx at AUTH or `MAIL FROM`, or a server that offers no AUTH: the server
    /// refuses the account or the sender of the relay for good, so no mail can go until
    /// the check of the session passes again. A 4xx (a rate limit of the server) or a
    /// timeout there leaves the mail on.
    pub fn refused_sender(&self) -> bool {
        let permanent = self.reply.is_some_and(|code| (500..600).contains(&code));
        self.setup
            && (self.step == "auth offered"
                || (matches!(self.step, "auth" | "mail from") && permanent))
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

/// Re-arm each actual socket operation, including rustls handshake internals, so a
/// peer sending one byte at a time cannot extend the overall session deadline.
struct DeadlineTcp {
    stream: TcpStream,
    deadline: std::time::Instant,
    io_timeout: Duration,
}
impl DeadlineTcp {
    fn arm(&self) -> std::io::Result<()> {
        let left = self
            .deadline
            .saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "SMTP deadline",
            ));
        }
        let timeout = Some(left.min(self.io_timeout));
        self.stream.set_read_timeout(timeout)?;
        self.stream.set_write_timeout(timeout)
    }
}
impl Read for DeadlineTcp {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.arm()?;
        self.stream.read(buf)
    }
}
impl Write for DeadlineTcp {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.arm()?;
        self.stream.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.arm()?;
        self.stream.flush()
    }
}

/// The TCP or the TLS connection of a session.
enum Wire {
    Plain(DeadlineTcp),
    Tls(Box<StreamOwned<ClientConnection, DeadlineTcp>>),
}

impl Wire {
    /// The timeouts of the socket under the session.
    fn set_timeouts(&self, timeout: Duration) -> std::io::Result<()> {
        let tcp = match self {
            Self::Plain(stream) => stream,
            Self::Tls(stream) => &stream.sock,
        };
        tcp.stream.set_read_timeout(Some(timeout))?;
        tcp.stream.set_write_timeout(Some(timeout))
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

/// One SMTP session, with one deadline for all of it.
pub(super) struct Session {
    reader: BufReader<Wire>,
    deadline: std::time::Instant,
    io_timeout: Duration,
}

impl Session {
    pub(super) fn new(tcp: TcpStream, deadline: std::time::Instant, io_timeout: Duration) -> Self {
        Self {
            reader: BufReader::new(Wire::Plain(DeadlineTcp {
                stream: tcp,
                deadline,
                io_timeout,
            })),
            deadline,
            io_timeout,
        }
    }

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

    pub(super) fn command(&mut self, line: &str) -> Result<(), MailError> {
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
        let mut first_code = None;
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
            if first_code.is_some_and(|first| first != code) {
                return Err(MailError::at(step));
            }
            first_code = Some(code);
            let separator = line.get(3).copied().unwrap_or(b' ');
            lines.push(String::from_utf8_lossy(line.get(4..).unwrap_or_default()).into_owned());
            match separator {
                b' ' => return Ok((code, lines)),
                b'-' if lines.len() < MAX_REPLY_LINES => {}
                _ => return Err(MailError::at(step)),
            }
        }
    }

    pub(super) fn expect(
        &mut self,
        step: &'static str,
        ok: &[u16],
    ) -> Result<Vec<String>, MailError> {
        let (code, lines) = self.reply(step)?;
        if ok.contains(&code) {
            Ok(lines)
        } else {
            Err(MailError {
                step,
                reply: Some(code),
                setup: false,
            })
        }
    }

    /// EHLO, and the extension lines of the answer (without the greeting line).
    pub(super) fn ehlo(&mut self, name: &str) -> Result<Vec<String>, MailError> {
        self.command(&format!("EHLO {name}"))?;
        let lines = self.expect("ehlo", &[250])?;
        Ok(lines.into_iter().skip(1).collect())
    }

    /// TLS over the TCP connection, with the server's certificate checked for `host`.
    /// Bytes that came before the handshake are refused: a server, or a machine on the
    /// way, could put commands in front of it.
    pub(super) fn start_tls(
        self,
        config: &Arc<ClientConfig>,
        host: &str,
    ) -> Result<Self, MailError> {
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
        tcp.stream
            .set_read_timeout(Some(timeout))
            .and_then(|()| tcp.stream.set_write_timeout(Some(timeout)))
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
    pub(super) fn write_data(&mut self, message: &str) -> Result<(), MailError> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (TcpStream, TcpStream) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    #[test]
    fn every_socket_operation_checks_the_session_deadline() {
        let (stream, _peer) = pair();
        let mut tcp = DeadlineTcp {
            stream,
            deadline: std::time::Instant::now() - Duration::from_secs(1),
            io_timeout: Duration::from_secs(10),
        };
        assert_eq!(
            tcp.read(&mut [0]).unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
        assert_eq!(
            tcp.write(b"secret").unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
        assert_eq!(
            tcp.flush().unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn multiline_replies_cannot_change_the_status_code() {
        let (client, mut peer) = pair();
        peer.write_all(b"550-rejected\r\n250 accepted\r\n").unwrap();
        let mut session = Session::new(
            client,
            std::time::Instant::now() + Duration::from_secs(1),
            Duration::from_secs(1),
        );
        let error = session.expect("message", &[250]).unwrap_err();
        assert_eq!(error.step, "message");
        assert_eq!(error.reply, None);
    }
}
