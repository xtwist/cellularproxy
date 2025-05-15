use anyhow::{anyhow, Context, Result};
use get_if_addrs::get_if_addrs;
use socket2::{Socket, Type};
use socks5_protocol::{
    Address, AuthMethod, AuthRequest, AuthResponse, CommandRequest, CommandResponse,
    Version,
};
use socks5_proto::{
    Response,
    handshake::{
        Method as HandshakeMethod, Request as HandshakeRequest, Response as HandshakeResponse,
    },
};
use std::{collections::HashMap, net::SocketAddr};
use std::ffi::CString;
use std::net::IpAddr;
use std::os::fd::{AsRawFd};
use axum::{Json, Router};
use axum::response::{Response as AxumResponse};
use axum::response::IntoResponse;
use axum::routing::get;
use clap::Parser;
use http::StatusCode;
use serde::Serialize;
use serde_json::json;
use slog::{info, o, Drain, FnValue, Logger, PushFnValue, Record};
use tokio::{
    io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio::net::TcpSocket;
use uuid::Uuid;
use libc::{c_void, setsockopt, SOL_SOCKET, SO_BINDTODEVICE};
use serde::ser::SerializeStruct;
use tikv_jemallocator::Jemalloc;

#[derive(Clone, Debug)]
pub struct Device {
    id: Uuid,
    name: String, // interface name, e.g. "eth0", "ppp0"
    ip: String,   // IP address of the interface
}

impl Serialize for Device {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("Device", 3)?;
        state.serialize_field("id", &self.id.to_string())?;
        state.serialize_field("name", &self.name)?;
        state.serialize_field("ip", &self.ip)?;
        state.end()
    }
}

/// Helper: read /proc/net/route and return the iface whose Destination is 0.0.0.0
fn get_default_interface() -> Result<String> {
    let data = std::fs::read_to_string("/proc/net/route")?;
    for line in data.lines().skip(1) {
        let cols: Vec<_> = line.split_whitespace().collect();
        if cols.get(1) == Some(&"00000000") {
            return Ok(cols[0].to_string());
        }
    }
    Err(anyhow::anyhow!("no default route interface found"))
}