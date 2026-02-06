use std::{net::SocketAddr, str::FromStr};

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use inactu_verifier::{
    enforce_capability_ceiling, parse_manifest_json, parse_policy_document, parse_receipt_json,
    sha256_prefixed, verify_receipt_hash,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::info;

#[derive(Clone, Debug)]
struct AppState {
    service_name: &'static str,
    service_version: &'static str,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
    version: &'static str,
}

#[derive(Debug, Deserialize)]
struct VerifyManifestRequest {
    manifest: Value,
    policy: Option<Value>,
}

#[derive(Debug, Serialize)]
struct VerifyManifestResponse {
    name: String,
    version: String,
    artifact: String,
    capability_ceiling_ok: bool,
}

#[derive(Debug, Deserialize)]
struct VerifyReceiptRequest {
    receipt: Value,
}

#[derive(Debug, Serialize)]
struct VerifyReceiptResponse {
    artifact: String,
    receipt_hash: String,
    valid: bool,
}

#[derive(Debug, Deserialize)]
struct HashRequest {
    payload: String,
}

#[derive(Debug, Serialize)]
struct HashResponse {
    digest: String,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(serde_json::json!({
            "error": self.message,
        }));
        (self.status, body).into_response()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();

    let state = AppState {
        service_name: "inactu-control",
        service_version: env!("CARGO_PKG_VERSION"),
    };
    let app = router(state.clone());
    let bind_addr = bind_address()?;
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;

    info!(%bind_addr, "starting service");
    axum::serve(listener, app).await?;
    Ok(())
}

fn init_tracing() {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();
}

fn bind_address() -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let value = std::env::var("INACTU_CONTROL_BIND").unwrap_or_else(|_| "127.0.0.1:8080".into());
    SocketAddr::from_str(&value).map_err(|err| format!("invalid INACTU_CONTROL_BIND: {err}").into())
}

fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/verify/manifest", post(verify_manifest))
        .route("/v1/verify/receipt", post(verify_receipt))
        .route("/v1/hash/sha256", post(hash_sha256))
        .with_state(state)
}

async fn healthz(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: state.service_name,
        version: state.service_version,
    })
}

async fn verify_manifest(
    Json(request): Json<VerifyManifestRequest>,
) -> Result<Json<VerifyManifestResponse>, ApiError> {
    let manifest_bytes = serde_json::to_vec(&request.manifest)
        .map_err(|err| ApiError::bad_request(format!("manifest serialization failed: {err}")))?;
    let manifest = parse_manifest_json(&manifest_bytes)
        .map_err(|err| ApiError::bad_request(format!("invalid manifest: {err}")))?;

    let capability_ceiling_ok = if let Some(policy_value) = request.policy {
        let policy_bytes = serde_json::to_vec(&policy_value)
            .map_err(|err| ApiError::bad_request(format!("policy serialization failed: {err}")))?;
        let policy = parse_policy_document(&policy_bytes)
            .map_err(|err| ApiError::bad_request(format!("invalid policy: {err}")))?;
        enforce_capability_ceiling(&manifest.capabilities, &policy)
            .map_err(|err| ApiError::bad_request(format!("capability check failed: {err}")))?;
        true
    } else {
        false
    };

    Ok(Json(VerifyManifestResponse {
        name: manifest.name,
        version: manifest.version,
        artifact: manifest.artifact,
        capability_ceiling_ok,
    }))
}

async fn verify_receipt(
    Json(request): Json<VerifyReceiptRequest>,
) -> Result<Json<VerifyReceiptResponse>, ApiError> {
    let receipt_bytes = serde_json::to_vec(&request.receipt)
        .map_err(|err| ApiError::bad_request(format!("receipt serialization failed: {err}")))?;
    let receipt = parse_receipt_json(&receipt_bytes)
        .map_err(|err| ApiError::bad_request(format!("invalid receipt: {err}")))?;
    verify_receipt_hash(&receipt)
        .map_err(|err| ApiError::bad_request(format!("receipt verification failed: {err}")))?;

    Ok(Json(VerifyReceiptResponse {
        artifact: receipt.artifact,
        receipt_hash: receipt.receipt_hash,
        valid: true,
    }))
}

async fn hash_sha256(Json(request): Json<HashRequest>) -> Json<HashResponse> {
    Json(HashResponse {
        digest: sha256_prefixed(request.payload.as_bytes()),
    })
}
