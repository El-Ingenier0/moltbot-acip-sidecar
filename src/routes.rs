use crate::introspection;
use crate::state::AppState;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde_json::json;
use std::sync::Arc;

pub fn policy_name_from_headers(headers: &HeaderMap) -> String {
    headers
        .get("x-acip-policy")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "default".to_string())
}

pub async fn list_policies(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut names = state.policies.list();
    names.sort();
    (StatusCode::OK, Json(json!({ "policies": names })))
}

pub async fn get_policy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let name = policy_name_from_headers(&headers);
    let Some(p) = state.policies.get(&name) else {
        let mut names = state.policies.list();
        names.sort();
        return introspection::json_error(
            StatusCode::BAD_REQUEST,
            "unknown policy",
            json!({ "requested": name, "available": names }),
        )
        .into_response();
    };

    (StatusCode::OK, Json(json!({ "name": name, "policy": p }))).into_response()
}

pub async fn get_schema() -> impl IntoResponse {
    (StatusCode::OK, Json(introspection::decision_schema()))
}
