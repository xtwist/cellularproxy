use crate::tcp::{tcp_connect_via_interface, tcp_connect_with_fingerprint, OsFingerprint};
use crate::username::parse_username;
use derive_builder::Builder;
use slog::{error, Logger};
use socks5_proto::{
    handshake::{
        password::{Request as PasswordRequest, Response as PasswordResponse},
        Method as HandshakeMethod, Request as HandshakeRequest, Response as HandshakeResponse,
    },
    Address, Command, Reply, Request, Response,
};
use std::{
    collections::HashMap,
    io,
    net::{AddrParseError, SocketAddr},
    result,
    string::FromUtf8Error,
};
use std::sync::Arc;
use thiserror::Error;
use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream},
};

#[derive(Debug, Error)]
pub enum Socks5Error {
    #[error("failed to bind to address: {0}")]
    Listen(#[source] io::Error),

    #[error("failed to accept connection: {0}")]
    Accept(#[source] io::Error),

    #[error("handshake failed: {0}")]
    Handshake(#[source] socks5_proto::Error),

    #[error("no supported auth method")]
    UnsupportedMethod,

    #[error("password request failed: {0}")]
    PasswordRequest(#[source] socks5_proto::handshake::password::Error),

    #[error("authentication failed for user `{0}`")]
    AuthenticationFailed(String),

    #[error("password response write failed: {0}")]
    PasswordResponseWrite(#[source] io::Error),

    #[error("request read failed: {0}")]
    RequestRead(#[source] socks5_proto::Error),

    #[error("invalid address: {0}")]
    InvalidAddress(#[source] AddrParseError),

    #[error("tcp connect via interface failed: {0}")]
    Connect(#[source] io::Error),

    #[error("response write failed: {0}")]
    ResponseWrite(#[source] io::Error),

    #[error("command not supported: {0:?}")]
    UnsupportedCommand(Command),

    #[error("command not allowed: {0:?}")]
    CommandNotAllowed(Command),

    #[error("utf8 decoding failed: {0}")]
    Utf8(#[from] FromUtf8Error),
}

#[derive(Builder, Clone)]
#[builder(pattern = "owned")]
pub struct Socks5 {
    fingerprint: OsFingerprint,
    listen_addr: SocketAddr,
    iface_map: HashMap<String, String>,
    logger: Logger,
}

pub type Result<T> = result::Result<T, Socks5Error>;

impl Socks5 {
    /// Consume the builder and start serving forever.
    pub async fn run(self) -> Result<Socks5Error> {
        let listener = TcpListener::bind(self.listen_addr)
            .await
            .map_err(Socks5Error::Listen)?;

        let logger = self.logger.clone();
        let iface_map = self.iface_map.clone();
        let server = Arc::new(self);

        loop {
            let (stream, peer) = listener.accept().await.map_err(Socks5Error::Accept)?;
            let server = Arc::clone(&server);               // cheap clone of the Arc
            let iface_map = server.iface_map.clone();
            let logger    = server.logger.clone();
            
            tokio::spawn(async move {
                if let Err(err) = server.handle_client(stream, iface_map).await {
                    error!(logger, "client {} error: {}", peer, err);
                }
            });
        }
    }

    /// Per‐connection handler: does the SOCKS5 handshake, auth, CONNECT, proxying.
    async fn handle_client(
        &self,
        mut client: TcpStream,
        iface_map: HashMap<String, String>,
    ) -> Result<()> {
        // 1) handshake
        let hs_req = HandshakeRequest::read_from(&mut client)
            .await
            .map_err(Socks5Error::Handshake)?;

        // 2) check USER/PASS support
        if !hs_req
            .methods
            .iter()
            .any(|&m| m == HandshakeMethod::PASSWORD)
        {
            HandshakeResponse::new(HandshakeMethod::UNACCEPTABLE)
                .write_to(&mut client)
                .await
                .map_err(Socks5Error::ResponseWrite)?;
            return Err(Socks5Error::UnsupportedMethod);
        }

        // 3) ack USER/PASS
        HandshakeResponse::new(HandshakeMethod::PASSWORD)
            .write_to(&mut client)
            .await
            .map_err(Socks5Error::ResponseWrite)?;

        // 4) read credentials
        let pwd_req = PasswordRequest::read_from(&mut client)
            .await
            .map_err(Socks5Error::PasswordRequest)?;
        let username = String::from_utf8(pwd_req.username)?;
        let password = String::from_utf8(pwd_req.password)?;

        // 5) validate
        let (username, fingerprint) = parse_username(username.as_str(), self.fingerprint)
            .map_err(|_| Socks5Error::AuthenticationFailed(username.clone()))?;

        let auth_ok = username == "modem" && iface_map.contains_key(&password);

        PasswordResponse::new(auth_ok)
            .write_to(&mut client)
            .await
            .map_err(Socks5Error::PasswordResponseWrite)?;
        if !auth_ok {
            return Err(Socks5Error::AuthenticationFailed(username));
        }

        // 6) read SOCKS5 request
        let req = Request::read_from(&mut client)
            .await
            .map_err(Socks5Error::RequestRead)?;

        // 7) lookup interface name
        let ifname = iface_map.get(&password).unwrap(); // safe—just checked

        // 8) dispatch
        match req.command {
            Command::Connect => {
                let (_sent, _recv) =
                    Self::server_socks5_connect(ifname, req.address, fingerprint, client).await?;
                Ok(())
            }
            cmd @ Command::Associate => {
                Response::new(Reply::ConnectionNotAllowed, req.address)
                    .write_to(&mut client)
                    .await
                    .map_err(Socks5Error::ResponseWrite)?;
                Err(Socks5Error::CommandNotAllowed(cmd))
            }
            cmd => {
                Response::new(Reply::CommandNotSupported, req.address)
                    .write_to(&mut client)
                    .await
                    .map_err(Socks5Error::ResponseWrite)?;
                Err(Socks5Error::UnsupportedCommand(cmd))
            }
        }
    }

    async fn server_socks5_connect(
        ifname: &str,
        requested_addr: Address,
        fingerprint: OsFingerprint,
        mut client: TcpStream,
    ) -> Result<(u64, u64)> {
        let sock_addr: SocketAddr = requested_addr
            .to_string()
            .parse()
            .map_err(Socks5Error::InvalidAddress)?;

        let mut outbound = tcp_connect_with_fingerprint(sock_addr, ifname, fingerprint)
            .await
            .map_err(Socks5Error::Connect)?;

        Response::new(Reply::Succeeded, requested_addr)
            .write_to(&mut client)
            .await
            .map_err(Socks5Error::ResponseWrite)?;

        copy_bidirectional(&mut client, &mut outbound)
            .await
            .map_err(Socks5Error::Connect)
    }
}
