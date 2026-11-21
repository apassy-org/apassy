//! A fake SMTP submission server for the tests of the code mail (docs/SPEC.md section
//! 38.7): on a free loopback port, with its own test certificate authority, STARTTLS (or
//! TLS from the first byte), AUTH PLAIN and LOGIN, and one mail per session. It records
//! each mail it takes, and the commands it saw before TLS. Synthetic values only.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use apassy_relay::config::MailSettings;
use apassy_relay::secret::SecretString;
use base64::prelude::{BASE64_STANDARD, Engine as _};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

/// The host name in the server's certificate. The relay connects to the fixed address.
pub const HOST: &str = "smtp.apassy.test";
pub const USER: &str = "connect@apassy.test";
pub const PASSWORD: &str = "synthetic-smtp-password-0123456789";
pub const FROM: &str = "connect@apassy.test";

/// One mail that the server took.
#[derive(Debug, Clone)]
pub struct Mail {
    pub from: String,
    pub to: String,
    /// The message as it arrived, without the final `.` line and with dots unstuffed.
    pub data: String,
    /// The user of the AUTH, if any.
    pub user: Option<String>,
    pub tls: bool,
}

impl Mail {
    /// The eight digits of the code in the text.
    pub fn code(&self) -> String {
        let marker = "Apassy item: ";
        let at = self.data.find(marker).expect("code line") + marker.len();
        self.data[at..at + 8].to_string()
    }
}

pub struct FakeSmtp {
    pub addr: SocketAddr,
    pub ca_der: Vec<u8>,
    mails: Arc<Mutex<Vec<Mail>>>,
    /// While true, every `RCPT TO` is refused with 451 (a server that fails for now).
    pub refuse: Arc<AtomicBool>,
    pub sessions: Arc<AtomicUsize>,
    implicit: bool,
}

fn this_year() -> i32 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    1970 + i32::try_from(secs / 31_556_952).unwrap_or(56)
}

fn validity(params: &mut CertificateParams) {
    let year = this_year();
    params.not_before = rcgen::date_time_ymd(year - 1, 12, 1);
    params.not_after = rcgen::date_time_ymd(year + 1, 1, 5);
}

/// A server with STARTTLS on a free port (`implicit`: TLS from the first byte instead).
pub fn start(implicit: bool) -> FakeSmtp {
    let mut root = CertificateParams::default();
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "Apassy relay SMTP test root");
    root.distinguished_name = name;
    root.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    validity(&mut root);
    let root_key = KeyPair::generate().expect("root key");
    let root_cert = root.self_signed(&root_key).expect("root");
    let issuer = Issuer::new(root, root_key);
    let mut leaf = CertificateParams::new(vec![HOST.to_string()]).expect("leaf");
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf.use_authority_key_identifier_extension = true;
    validity(&mut leaf);
    let leaf_key = KeyPair::generate().expect("leaf key");
    let leaf_cert = leaf.signed_by(&leaf_key, &issuer).expect("leaf cert");
    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf_cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
            )
            .expect("server config");
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let mails = Arc::new(Mutex::new(Vec::new()));
    let refuse = Arc::new(AtomicBool::new(false));
    let sessions = Arc::new(AtomicUsize::new(0));
    let (thread_mails, thread_refuse, thread_sessions) =
        (mails.clone(), refuse.clone(), sessions.clone());
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            thread_sessions.fetch_add(1, Ordering::SeqCst);
            let (config, mails, refuse) =
                (config.clone(), thread_mails.clone(), thread_refuse.clone());
            thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(20)));
                let _ = session(stream, &config, implicit, &mails, &refuse);
            });
        }
    });
    FakeSmtp {
        addr,
        ca_der: root_cert.der().to_vec(),
        mails,
        refuse,
        sessions,
        implicit,
    }
}

impl FakeSmtp {
    /// The relay's mail settings for this server, with the test account.
    pub fn settings(&self) -> MailSettings {
        let port = if self.implicit { 465 } else { 587 };
        let mut settings = MailSettings::new(HOST, port, FROM);
        settings.auth = Some((USER.to_string(), SecretString::new(PASSWORD.to_string())));
        settings.extra_roots_der = vec![self.ca_der.clone()];
        settings.connect_to = Some(self.addr);
        settings.io_timeout = Duration::from_secs(10);
        settings
    }

    /// Every mail taken so far.
    pub fn mails(&self) -> Vec<Mail> {
        self.mails.lock().unwrap().clone()
    }

    /// Waits until `count` mails were taken (at most 15 s), and answers them.
    pub fn wait_for(&self, count: usize) -> Vec<Mail> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let mails = self.mails();
            if mails.len() >= count || Instant::now() > deadline {
                return mails;
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
}

enum Wire {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ServerConnection, TcpStream>>),
}

impl Read for Wire {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(s) => s.read(buf),
            Self::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Wire {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(s) => s.write(buf),
            Self::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(s) => s.flush(),
            Self::Tls(s) => s.flush(),
        }
    }
}

fn tls(tcp: TcpStream, config: &Arc<ServerConfig>) -> std::io::Result<Wire> {
    let conn = ServerConnection::new(config.clone()).map_err(std::io::Error::other)?;
    let mut stream = StreamOwned::new(conn, tcp);
    while stream.conn.is_handshaking() {
        stream.conn.complete_io(&mut stream.sock)?;
    }
    Ok(Wire::Tls(Box::new(stream)))
}

fn session(
    tcp: TcpStream,
    config: &Arc<ServerConfig>,
    implicit: bool,
    mails: &Mutex<Vec<Mail>>,
    refuse: &AtomicBool,
) -> std::io::Result<()> {
    let wire = if implicit {
        tls(tcp, config)?
    } else {
        Wire::Plain(tcp)
    };
    let mut reader = BufReader::new(wire);
    let mut secure = implicit;
    let send = |reader: &mut BufReader<Wire>, line: &str| -> std::io::Result<()> {
        let wire = reader.get_mut();
        wire.write_all(line.as_bytes())?;
        wire.write_all(b"\r\n")?;
        wire.flush()
    };
    send(&mut reader, "220 smtp.apassy.test ESMTP fake")?;
    let (mut from, mut to, mut user) = (None, None, None);
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Ok(());
        }
        let line = line.trim_end().to_string();
        let upper = line.to_ascii_uppercase();
        if upper.starts_with("EHLO") {
            let wire = reader.get_mut();
            wire.write_all(b"250-smtp.apassy.test\r\n")?;
            if !secure {
                wire.write_all(b"250-STARTTLS\r\n")?;
            } else {
                wire.write_all(b"250-AUTH PLAIN LOGIN\r\n")?;
            }
            wire.write_all(b"250 8BITMIME\r\n")?;
            wire.flush()?;
        } else if upper == "STARTTLS" && !secure {
            send(&mut reader, "220 go ahead")?;
            let Wire::Plain(tcp) = reader.into_inner() else {
                return Ok(());
            };
            reader = BufReader::new(tls(tcp, config)?);
            secure = true;
        } else if let Some(token) = line.strip_prefix("AUTH PLAIN ") {
            if !secure {
                send(&mut reader, "538 encryption required")?;
                continue;
            }
            let decoded = BASE64_STANDARD.decode(token).unwrap_or_default();
            let parts: Vec<&[u8]> = decoded.split(|byte| *byte == 0).collect();
            if parts.len() == 3 && parts[1] == USER.as_bytes() && parts[2] == PASSWORD.as_bytes() {
                user = Some(USER.to_string());
                send(&mut reader, "235 ok")?;
            } else {
                send(&mut reader, "535 bad credentials")?;
            }
        } else if let Some(address) = line.strip_prefix("MAIL FROM:") {
            if user.is_none() {
                send(&mut reader, "530 authentication required")?;
                continue;
            }
            from = Some(address.trim_matches(['<', '>']).to_string());
            send(&mut reader, "250 ok")?;
        } else if let Some(address) = line.strip_prefix("RCPT TO:") {
            if refuse.load(Ordering::SeqCst) {
                send(&mut reader, "451 try later")?;
                continue;
            }
            to = Some(address.trim_matches(['<', '>']).to_string());
            send(&mut reader, "250 ok")?;
        } else if upper == "DATA" {
            send(&mut reader, "354 go")?;
            let mut data = String::new();
            loop {
                let mut part = String::new();
                if reader.read_line(&mut part)? == 0 {
                    return Ok(());
                }
                if part == ".\r\n" {
                    break;
                }
                let part = part.strip_prefix('.').map_or(part.clone(), str::to_string);
                data.push_str(&part);
            }
            mails.lock().unwrap().push(Mail {
                from: from.take().unwrap_or_default(),
                to: to.take().unwrap_or_default(),
                data,
                user: user.clone(),
                tls: secure,
            });
            send(&mut reader, "250 queued")?;
        } else if upper == "QUIT" {
            send(&mut reader, "221 bye")?;
            return Ok(());
        } else {
            send(&mut reader, "502 not implemented")?;
        }
    }
}
