use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::{
    Router,
    extract::Request,
    http::{HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use base64::{Engine as _, engine::general_purpose};
use prometheus::{Encoder, TextEncoder};
use slog::{Logger, debug};
use tokio::sync::oneshot;
use crate::jemalloc::spawn_allocator_metrics_loop;

async fn metrics_handler() -> impl IntoResponse {
    let metric_families = prometheus::gather();
    let encoder = TextEncoder::new();
    let mut buffer = Vec::new();

    if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
        return Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from(format!("Error encoding metrics: {}", e)))
            .unwrap();
    }

    Response::builder()
        .status(StatusCode::OK)
        .header(
            "Content-Type",
            HeaderValue::from_static("text/plain; version=0.0.4"),
        )
        .body(buffer.into())
        .unwrap()
}

// Basic auth middleware
async fn basic_auth(
    req: Request,
    next: Next,
    credentials: Arc<(String, String)>,
) -> Result<Response, StatusCode> {
    // Get authorization header
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok());

    // Check if authorization header is present and valid
    match auth_header {
        Some(auth) if auth.starts_with("Basic ") => {
            // Extract credentials from header
            let encoded = auth.trim_start_matches("Basic ");
            let decoded = general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| StatusCode::UNAUTHORIZED)?;

            let decoded_str = String::from_utf8(decoded).map_err(|_| StatusCode::UNAUTHORIZED)?;

            // Check credentials
            if decoded_str == format!("{}:{}", credentials.0, credentials.1) {
                // Authentication successful, proceed with request
                let response = next.run(req).await;
                Ok(response)
            } else {
                // Invalid credentials
                Err(StatusCode::UNAUTHORIZED)
            }
        }
        _ => {
            // No or invalid authorization header
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

async fn handler_404() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, "Not found")
}

/// Start a metrics server with basic authentication
///
/// Returns a shutdown signal sender that can be used to stop the server
pub async fn start_metrics_server(
    addr: SocketAddr,
    username: String,
    password: String,
    logger: Logger,
) -> oneshot::Sender<()> {
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    

    tokio::spawn(async move {
        let mut app = Router::new()
            .route("/metrics", get(metrics_handler))
            .fallback(handler_404);

        // Only add auth middleware if both username and password are provided
        if !username.is_empty() && !password.is_empty() {
            // Store credentials in Arc for sharing across async tasks
            let credentials = Arc::new((username, password));

            let auth_middleware = move |req: Request, next: Next| {
                let creds = credentials.clone();
                async move { basic_auth(req, next, creds).await }
            };

            app = app.layer(middleware::from_fn(auth_middleware));
            debug!(logger, "Metrics server started with authentication";);
        } else {
            debug!(logger, "Metrics server started without authentication");
        }

        debug!(
            logger,
            "Metrics server listening on http://{}/metrics", addr
        );

        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .unwrap_or_else(|e| panic!("could not bind to {}: {}", addr, e));

        // Use Axum's serve with graceful shutdown
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                shutdown_rx.await.ok();
            })
            .await
            .unwrap_or_else(|e| panic!("could not server app {}", e));
    });

    shutdown_tx
}
