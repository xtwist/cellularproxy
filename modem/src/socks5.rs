use anyhow::{Result};
use std::{collections::HashMap, io, net::{SocketAddr}};
use std::net::AddrParseError;
use std::string::FromUtf8Error;
use tokio::{
    io::{copy_bidirectional},
    net::{TcpStream},
};
use socks5_proto::handshake::password::{Request as PasswordRequest, Response as PasswordResponse};
use socks5_proto::{
    Address, Command, Reply, Request, Response,
    handshake::{
        Method as HandshakeMethod, Request as HandshakeRequest, Response as HandshakeResponse,
    },
};
use thiserror::Error;
use crate::tcp::tcp_connect_via_interface;

#[derive(Debug, Error)]
pub enum Socks5Error {
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

pub async fn handle_socks5(
    mut client: TcpStream,
    iface_map: HashMap<String, String>,
) -> Result<(), Socks5Error> {
    // 1) Read and parse the SOCKS5 handshake
    let hs_req = HandshakeRequest::read_from(&mut client)
        .await
        .map_err(Socks5Error::Handshake)?;

    // 2) Check for USERNAME/PASSWORD method
    if !hs_req
        .methods
        .iter()
        .any(|&m| m == HandshakeMethod::PASSWORD)
    {
        // Tell the client no acceptable methods, then error out
        HandshakeResponse::new(HandshakeMethod::UNACCEPTABLE)
            .write_to(&mut client)
            .await
            .map_err(Socks5Error::ResponseWrite)?;
        return Err(Socks5Error::UnsupportedMethod);
    }

    // 3) Acknowledge USERNAME/PASSWORD
    HandshakeResponse::new(HandshakeMethod::PASSWORD)
        .write_to(&mut client)
        .await
        .map_err(Socks5Error::ResponseWrite)?;

    // 4) Read the password request
    let pwd_req = PasswordRequest::read_from(&mut client)
        .await
        .map_err(Socks5Error::PasswordRequest)?;

    // 5) Decode credentials
    let username = String::from_utf8(pwd_req.username)?;
    let password = String::from_utf8(pwd_req.password)?;

    // 6) Validate
    let auth_ok = username == "modem" && iface_map.contains_key(&password);
    PasswordResponse::new(auth_ok)
        .write_to(&mut client)
        .await
        .map_err(Socks5Error::PasswordResponseWrite)?;
    if !auth_ok {
        return Err(Socks5Error::AuthenticationFailed(username));
    }

    // 7) Read the actual SOCKS5 request
    let req = Request::read_from(&mut client)
        .await
        .map_err(Socks5Error::RequestRead)?;

    let ifname = match iface_map
        .get(&password) {
        Some(ifname) => ifname,
        None => {
            Response::new(Reply::GeneralFailure, req.address)
                .write_to(&mut client)
                .await
                .map_err(Socks5Error::ResponseWrite)?;
            return Err(Socks5Error::AuthenticationFailed(username));
        }
    };

    // 8) Dispatch on command
    match req.command {
        Command::Connect => {
            server_socks5_connect(ifname, req.address, client).await?;
        }
        cmd @ Command::Associate => {
            // only CONNECT is allowed in this implementation
            Response::new(Reply::ConnectionNotAllowed, req.address)
                .write_to(&mut client)
                .await
                .map_err(Socks5Error::ResponseWrite)?;
            return Err(Socks5Error::CommandNotAllowed(cmd));
        }
        cmd => {
            Response::new(Reply::CommandNotSupported, req.address)
                .write_to(&mut client)
                .await
                .map_err(Socks5Error::ResponseWrite)?;
            return Err(Socks5Error::UnsupportedCommand(cmd));
        }
    }

    Ok(())
}

async fn server_socks5_connect(
    ifname: &str,
    requested_addr: Address,
    mut client: TcpStream,
) -> Result<(), Socks5Error> {
    // Parse the target socket address
    let sock_addr: SocketAddr = requested_addr
        .to_string()
        .parse()
        .map_err(Socks5Error::InvalidAddress)?;

    // Open the outbound connection via the specified interface
    let mut outbound = tcp_connect_via_interface(sock_addr, ifname)
        .await
        .map_err(Socks5Error::Connect)?;

    // Tell the client the CONNECT succeeded
    Response::new(Reply::Succeeded, requested_addr)
        .write_to(&mut client)
        .await
        .map_err(Socks5Error::ResponseWrite)?;

    // Pipe data both ways
    copy_bidirectional(&mut client, &mut outbound)
        .await
        .map_err(Socks5Error::Connect)?;

    Ok(())
}