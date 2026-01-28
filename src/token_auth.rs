use crate::introspection;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    middleware::{from_fn_with_state, Next},
    response::IntoResponse,
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

    let mut values = headers.get_all("x-acip-token").iter();
    let Some(value) = values.next() else {
        return introspection::json_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            serde_json::json!({"missing": true}),
        )
        .into_response();
    };

    if values.next().is_some() {
        return introspection::json_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            serde_json::json!({"invalid": true}),
        )
        .into_response();
    }

    let got = match value.to_str() {
        Ok(value) => value.trim(),
        Err(_) => {
            return introspection::json_error(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                serde_json::json!({"invalid": true}),
            )
            .into_response();
        }
    };

    if !constant_time_eq(got, &expected) {
        return introspection::json_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            serde_json::json!({"invalid": true}),
        )
        .into_response();
    }

    next.run(req).await
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let mut diff = a_bytes.len() ^ b_bytes.len();
    let max = a_bytes.len().max(b_bytes.len());
    for i in 0..max {
        let av = *a_bytes.get(i).unwrap_or(&0);
        let bv = *b_bytes.get(i).unwrap_or(&0);
        diff |= (av ^ bv) as usize;
    }
    diff == 0
}
