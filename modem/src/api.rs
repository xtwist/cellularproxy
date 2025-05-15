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

use crate::device::Device;

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, msg: impl Into<String>) -> Self {
        ApiError { status, message: msg.into() }
    }
    fn not_found(msg: impl Into<String>) -> Self {
        ApiError::new(StatusCode::NOT_FOUND, msg)
    }
    fn internal(msg: impl Into<String>) -> Self {
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, msg)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> AxumResponse {
        let body = Json(json!({ "error": self.message }));
        (self.status, body).into_response()
    }
}
pub async fn list_interfaces() -> Result<Json<Vec<Device>>, ApiError> {
    // 1) figure out your "main" interface
    let main = get_default_interface()
        .map_err(|e| ApiError::internal(format!("detect default iface: {}", e)))?;

    // 2) enumerate all IP‐up interfaces
    let all_ifs = get_if_addrs().map_err(|e| ApiError::internal(e.to_string()))?;
    let devices: Vec<Device> = all_ifs
        .into_iter()
        // keep only the default iface + any ppp*/wwan* (Huawei)
        .filter(|iface| {
            iface.name == main
                || iface.name.starts_with("ppp")
                || iface.name.starts_with("wwan")
                || iface.name.starts_with("enx")
        })
        .map(|iface| {
            let id = Uuid::new_v5(&Uuid::NAMESPACE_URL, iface.name.as_bytes());
            Device {
                id,
                name: iface.name,
                ip: iface.addr.ip().to_string(),
            }
        })
        .collect();

    Ok(Json(devices))
}