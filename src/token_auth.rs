use crate::introspection;
use axum::{
    http::{HeaderMap, StatusCode},
    middleware::{from_fn_with_state, Next},
    response::IntoResponse,
    extract::State,
    Router,
};

/// Apply X-ACIP-Token authentication to a router.
///
/// If `token` is None, authentication is disabled and all requests are allowed.
pub fn with_token_auth<S>(router: Router<S>, token: Option<String>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router.layer(from_fn_with_state(token, token_auth_middleware))
}

async fn token_auth_middleware(
    State(token): State<Option<String>>,
    headers: HeaderMap,
    req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> axum::response::Response {
    let Some(expected) = token else {
        return next.run(req).await;
    };

    let got = headers.get("x-acip-token").and_then(|v| v.to_str().ok());
    let Some(got) = got else {
        return introspection::json_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            serde_json::json!({"missing": true}),
        )
        .into_response();
    };

    if got != expected {
        return introspection::json_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            serde_json::json!({"invalid": true}),
        )
        .into_response();
    }

    next.run(req).await
}
