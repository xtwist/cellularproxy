use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response as AxumResponse},
    routing::{get, post},
    Json, Router,
};
use derive_builder::Builder;
use get_if_addrs::get_if_addrs;
use serde::{Deserialize, Serialize};
use serde_json::json;
use slog::{error, info, Logger};
use tokio::{net::TcpListener, sync::Mutex};
use uuid::Uuid;

use crate::{
    device::{get_default_interface, Device},
    modem::Modem,
    modem_huaweie337::HuaweiE337,
};

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, msg: impl Into<String>) -> Self {
        ApiError {
            status,
            message: msg.into(),
        }
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

#[derive(Debug, Serialize, Deserialize)]
pub struct SmsMessage {
    recipient: String,
    content: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SmsResponse {
    id: String,
    status: String,
}

#[derive(Builder)]
#[builder(pattern = "mutable")]
pub struct API {
    addr: SocketAddr,
    modem: Arc<Mutex<dyn Modem + Send + Sync>>,
    #[builder(default)]
    logger: Option<Logger>,
}

pub struct AppState {
    modem: Arc<Mutex<dyn Modem + Send + Sync>>,
    logger: Logger,
}

impl API {
    pub fn builder() -> APIBuilder {
        APIBuilder::default()
    }

    pub async fn run(self) -> Result<(), anyhow::Error> {
        if !self.logger.is_some() {
            return Err(anyhow::anyhow!("Logger is not set"));
        }

        let logger = self.logger.unwrap();

        let state = Arc::new(AppState {
            modem: self.modem,
            logger: logger.clone(),
        });

        let app = Router::new()
            .route("/api/v1/devices", get(handle_list_devices))
            .route("/api/v1/devices/{id}/reboot", post(handle_reboot_interface))
            .with_state(state);

        let api_listener = TcpListener::bind(self.addr)
            .await
            .context("Failed to bind API listener")?;

        // Use axum::Server for graceful shutdown
        axum::serve(api_listener, app)
            .with_graceful_shutdown(async {
                tokio::signal::ctrl_c()
                    .await
                    .expect("install Ctrl+C handler");
            })
            .await?;

        Ok(())
    }
}

pub fn list_interfaces() -> HashMap<String, String> {
    let mut ifaces = HashMap::new();
    for iface in get_if_addrs().context("list interfaces").unwrap() {
        if iface.name.starts_with("enx") {
            let id = Uuid::new_v5(&Uuid::NAMESPACE_URL, iface.name.as_bytes()).to_string();
            ifaces.insert(id, iface.name);
        }
    }

    ifaces
}

async fn handle_list_devices(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<Device>>, ApiError> {
    info!(state.logger, "Listing interfaces");

    // 1) figure out your "main" interface
    let main = get_default_interface()
        .map_err(|e| ApiError::internal(format!("detect default iface: {}", e)))?;

    // 2) enumerate all IP‐up interfaces
    let all_ifs = get_if_addrs().map_err(|e| ApiError::internal(e.to_string()))?;
    let devices: Vec<Device> = all_ifs
        .into_iter()
        // keep only the default iface + any ppp*/wwan* (Huawei)
        .filter(|iface| iface.name.starts_with("enx"))
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

async fn handle_reboot_interface(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    info!(state.logger, "Restarting interface"; "id" => &id);

    // Find the interface by ID
    let interfaces = list_interfaces();
    let interface_name = interfaces
        .get(&id)
        .ok_or_else(|| ApiError::not_found(format!("Interface with ID {} not found", id)))?;

    // Implement the actual restart logic here
    // For now, we'll just return a success message

    state
        .modem
        .lock()
        .await
        .reboot()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(Json(json!({
        "status": "success",
        "message": format!("Interface {} restarted successfully", interface_name)
    })))
}
