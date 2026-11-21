use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, Response, StatusCode, header};
use axum::middleware::Next;
use axum::response::IntoResponse;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Token bucket state for rate limiting
#[derive(Clone, Debug)]
struct TokenBucket {
    tokens: f64,
    last_refill: u64,
}

const MAX_BUCKETS: usize = 10_000;
const BUCKET_IDLE_TIMEOUT: u64 = 60; // evict buckets idle longer than refill window

/// Global rate limiter for all IPs
#[derive(Clone)]
pub struct RateLimiter {
    buckets: Arc<RwLock<HashMap<String, TokenBucket>>>,
    public_rate: f64,
    auth_rate: f64,
    public_max: f64,
    auth_max: f64,
}

impl RateLimiter {
    pub fn new() -> Self {
        RateLimiter {
            buckets: Arc::new(RwLock::new(HashMap::new())),
            // 60 public requests per minute, 120 for an authenticated caller.
            public_rate: 1.0,
            auth_rate: 2.0,
            public_max: 60.0,
            auth_max: 120.0,
        }
    }

    /// Create a limiter with an explicit burst cap — useful in tests to
    /// exhaust the bucket in a small number of requests.
    pub fn with_capacity(public_max: f64, auth_max: f64) -> Self {
        RateLimiter {
            buckets: Arc::new(RwLock::new(HashMap::new())),
            public_rate: public_max / 60.0,
            auth_rate: auth_max / 60.0,
            public_max,
            auth_max,
        }
    }

    pub async fn check_rate_limit(
        &self,
        ip: &str,
        is_authenticated: bool,
    ) -> Result<(), (StatusCode, u64)> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut buckets = self.buckets.write().await;

        // Evict idle buckets to prevent memory growth
        if buckets.len() > MAX_BUCKETS / 2 {
            buckets
                .retain(|_, bucket| now.saturating_sub(bucket.last_refill) < BUCKET_IDLE_TIMEOUT);
        }

        let (rate, max_tokens) = if is_authenticated {
            (self.auth_rate, self.auth_max)
        } else {
            (self.public_rate, self.public_max)
        };

        let bucket = buckets
            .entry(ip.to_string())
            .or_insert_with(|| TokenBucket {
                tokens: max_tokens,
                last_refill: now,
            });

        let elapsed = (now - bucket.last_refill) as f64;
        let new_tokens = (bucket.tokens + elapsed * rate).min(max_tokens);

        if new_tokens < 1.0 {
            let retry_after = ((1.0 - new_tokens) / rate).ceil() as u64;
            return Err((StatusCode::TOO_MANY_REQUESTS, retry_after));
        }

        bucket.tokens = new_tokens - 1.0;
        bucket.last_refill = now;

        Ok(())
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Rate limiting middleware for global IP-based rate limiting
pub async fn rate_limit_middleware(
    axum::extract::State(state): axum::extract::State<crate::AppState>,
    req: Request<Body>,
    next: Next,
) -> Result<impl IntoResponse, Response<Body>> {
    // The client address is absent when the app is served without connect
    // info (in-memory tests); such requests share one "unknown" bucket.
    let ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // A request is authenticated only when its bearer token verifies — a
    // header value that fails signature or expiry check counts as anonymous.
    let (is_authenticated, bucket_key) = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .and_then(|token| {
            crate::auth::jwt::verify_token(token, state.config.jwt_secret.as_bytes()).ok()
        })
        .map(|claims| (true, claims.sub.to_string()))
        .unwrap_or_else(|| (false, ip.clone()));

    state
        .rate_limiter
        .check_rate_limit(&bucket_key, is_authenticated)
        .await
        .map_err(|(status, retry_after)| {
            Response::builder()
                .status(status)
                .header(header::RETRY_AFTER, retry_after)
                .body(Body::from("rate limit exceeded"))
                .expect("valid response")
        })?;

    Ok(next.run(req).await)
}

/// Velocity rate limiter for sensitive actions (keyed by user ID) (#136)
pub struct VelocityLimiter {
    buckets: Arc<RwLock<HashMap<String, TokenBucket>>>,
}

impl VelocityLimiter {
    pub fn new() -> Self {
        VelocityLimiter {
            buckets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check if user can perform sensitive action (max 5 per minute)
    pub async fn check_sensitive_action(&self, user_id: &str) -> Result<(), (StatusCode, String)> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut buckets = self.buckets.write().await;

        // Evict idle buckets to prevent memory growth
        if buckets.len() > MAX_BUCKETS / 2 {
            buckets
                .retain(|_, bucket| now.saturating_sub(bucket.last_refill) < BUCKET_IDLE_TIMEOUT);
        }

        let rate = 5.0 / 60.0;
        let max_tokens = 5.0;

        let bucket = buckets
            .entry(user_id.to_string())
            .or_insert_with(|| TokenBucket {
                tokens: max_tokens,
                last_refill: now,
            });

        let elapsed = (now - bucket.last_refill) as f64;
        let new_tokens = (bucket.tokens + elapsed * rate).min(max_tokens);

        if new_tokens < 1.0 {
            let retry_after = ((1.0 - new_tokens) / rate).ceil() as u64;
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                format!(
                    "Too many requests. Maximum 5 transfers per minute. Retry-After: {}",
                    retry_after
                ),
            ));
        }

        bucket.tokens = new_tokens - 1.0;
        bucket.last_refill = now;

        Ok(())
    }
}

impl Default for VelocityLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_fresh_limiter_allows_requests_up_to_its_rate() {
        let limiter = RateLimiter::new();
        for _ in 0..10 {
            assert!(limiter.check_rate_limit("203.0.113.1", false).await.is_ok());
        }
    }

    #[tokio::test]
    async fn an_exhausted_bucket_is_refused() {
        let limiter = RateLimiter::new();
        // The public rate is one token per second, so a burst far above it must
        // eventually be refused rather than served forever.
        let mut refused = false;
        for _ in 0..1_000 {
            if limiter
                .check_rate_limit("203.0.113.2", false)
                .await
                .is_err()
            {
                refused = true;
                break;
            }
        }
        assert!(refused, "rate limiter never refused a request");
    }

    #[tokio::test]
    async fn buckets_are_keyed_per_ip() {
        let limiter = RateLimiter::new();
        let mut refused = false;
        for _ in 0..1_000 {
            if limiter
                .check_rate_limit("203.0.113.3", false)
                .await
                .is_err()
            {
                refused = true;
                break;
            }
        }
        assert!(refused);
        // A different IP still has its own untouched bucket.
        assert!(limiter.check_rate_limit("203.0.113.4", false).await.is_ok());
    }

    #[test]
    fn the_velocity_limiter_has_a_default() {
        let _ = VelocityLimiter::default();
    }
}
