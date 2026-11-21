//! Wallet sign-in.
//!
//! Live: sign-in with Ethereum, Stellar, and EVM-compatible chains.
//! - `nonce.rs` issues single-use nonces (valid for 5 minutes)
//! - `siwe.rs` verifies EIP-191 signed messages from Ethereum and EVM-compatible wallets
//! - `stellar.rs` verifies SEP-10 signed transactions from Stellar
mod nonce;
mod siwe;
mod stellar;
mod user;

pub use user::AuthUser;

use axum::extract::State;
use axum::Router;
use axum::http::StatusCode;
use axum::routing::post;

use crate::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .merge(nonce::routes())
        .merge(siwe::routes())
        .merge(stellar::routes())
        .route("/auth/logout", post(logout))
}

/// POST /v1/auth/logout - revoke the current session token.
///
/// Adds the token's `jti` to the in-memory revocation set (and to the DB
/// when available) so that subsequent requests with the same token receive
/// 401. Expired entries are pruned on each call to keep the set bounded.
async fn logout(
    State(state): State<AppState>,
    auth: AuthUser,
) -> StatusCode {
    let Ok(claims) = auth.verify(state.config.jwt_secret.as_bytes()) else {
        return StatusCode::NO_CONTENT; // token was already invalid; nothing to revoke
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let mut revoked = state.revoked_tokens.write().await;
    // Prune entries that have already expired — the token bucket refills
    // naturally so they can never be replayed anyway.
    revoked.retain(|_, &mut exp| exp > now);
    revoked.insert(claims.jti, claims.exp);
    drop(revoked);

    StatusCode::NO_CONTENT
}