use crate::{routes, state, token_auth};
use axum::{extract::DefaultBodyLimit, routing::get, Router};
use std::sync::Arc;

pub async fn health() -> &'static str {
    "ok"
}

/// Build the main Axum router.
///
/// - `/health` is always unprotected.
/// - All `/v1/acip/*` routes are placed behind token auth (if enabled) and a body limit.
pub fn build_router(
    state: Arc<state::AppState>,
    token: Option<String>,
    extra_protected: Router<Arc<state::AppState>>,
) -> Router {
    // Apply token auth and body size limits to protected routes.
    let protected = token_auth::with_token_auth(
        Router::new()
            .route("/v1/acip/schema", get(routes::get_schema))
            .route("/v1/acip/policies", get(routes::list_policies))
            .route("/v1/acip/policy", get(routes::get_policy))
            .merge(extra_protected)
            // Limit request bodies (JSON + base64) to reduce DoS risk.
            .layer(DefaultBodyLimit::max(1_500_000)),
        token,
    );

    Router::new()
        .route("/health", get(health))
        .merge(protected)
        .with_state(state)
}
