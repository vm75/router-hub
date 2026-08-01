use crate::{models::ApiMessage, state::AppState};
use axum::{
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub async fn require_auth(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let supplied = bearer_token(&request);
    if supplied
        .as_deref()
        .is_some_and(|token| token_matches(token, &state.config.server.auth_token))
    {
        next.run(request).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            axum::Json(ApiMessage::new("missing or invalid API token")),
        )
            .into_response()
    }
}

fn bearer_token(request: &Request) -> Option<String> {
    request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(ToOwned::to_owned)
}

pub(crate) fn token_matches(candidate: &str, expected: &str) -> bool {
    let candidate_hash = Sha256::digest(candidate.as_bytes());
    let expected_hash = Sha256::digest(expected.as_bytes());
    candidate_hash.ct_eq(&expected_hash).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request as HttpRequest;

    #[test]
    fn test_token_matches() {
        assert!(token_matches("secret123", "secret123"));
        assert!(!token_matches("secret123", "wrongsecret"));
        assert!(!token_matches("secret123", "secret1234"));
    }

    #[test]
    fn test_bearer_token_extraction() {
        let req = HttpRequest::builder()
            .header("authorization", "Bearer my-token-abc")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(bearer_token(&req), Some("my-token-abc".to_string()));

        let req_invalid = HttpRequest::builder()
            .header("authorization", "Basic my-token-abc")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(bearer_token(&req_invalid), None);
    }
}
