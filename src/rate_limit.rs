//! Per-identity rate limiting (Phase 6.1).
//!
//! ## Why two keys
//!
//! Each tool call is checked against two independent token buckets:
//!
//! 1. `sha256(bearer)[..16]` — protects the homeserver/MAS from a leaked
//!    token: even if the same `sub` has multiple active tokens, a
//!    compromised one can only burn its own bucket before being denied.
//! 2. MAS `sub` (ULID) — protects against the same user spinning up many
//!    tokens (e.g. claude.ai issuing a fresh one per session) and using
//!    the union of their per-token allowances to flood Synapse.
//!
//! Either bucket exceeded → request denied. Both must allow.
//!
//! When `sub` is unavailable (the `/setup` browser flow doesn't go
//! through MAS introspection), only the bearer-hash bucket applies.
//!
//! ## Why two quotas
//!
//! Reads (`list_joined_rooms`, `read_recent_messages`, `whoami`,
//! `verify_status`) are cheap and idempotent — high default quota.
//! Writes (`send_text_message` + future write tools) are more expensive
//! and side-effectful; tighter default.
//!
//! ## Memory bound
//!
//! Each bucket map is hard-capped with least-recently-seen eviction. This
//! keeps valid-token rotation or a growing tenant population from turning
//! authentication churn into permanent process-memory growth.
//!
//! ## Quota knobs
//!
//! Configured at startup; no per-request override. Read from env in
//! `config.rs`:
//!
//! - `JMAP_MCP_RATE_LIMIT_READS_PER_MIN` (default 60)
//! - `JMAP_MCP_RATE_LIMIT_WRITES_PER_MIN` (default 30)

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};

/// Maximum number of fresh MCP sessions a single bearer token or Logto
/// subject may open in a short burst, before the refill in
/// [`INITIALIZE_REFILL_INTERVAL`] paces them.
///
/// Sized from observed client behaviour, not from an ideal: Cursor opens
/// **two** sessions within one second of a single connect, and every client
/// re-initializes after any transport-level failure. At the old burst of 8
/// (refilling once per 30-minute session TTL) four ordinary connects
/// exhausted the bucket and the fifth got a 30-minute lockout — surfacing to
/// the user as a dead connector on their *first* tool call, which is exactly
/// the failure this limiter must not cause.
///
/// The global [`crate::session::MAX_SESSIONS`] cap (256) remains the real
/// bound on the session pool; this limiter only paces one identity.
pub const MAX_INITIALIZES_PER_IDENTITY: u32 = 32;

/// Refill rate for the initialize bucket: one slot per minute.
///
/// Decoupled from `session::SESSION_KEEP_ALIVE`. Tying refill to the session
/// TTL sounded principled but meant a client that legitimately churned
/// sessions waited half an hour for a single retry. At 1/min a flooding
/// identity sustains ~30 concurrent sessions against a 30-minute idle TTL —
/// comfortably inside the 256-session cap — while a real user's reconnect
/// storm clears in seconds.
#[allow(unknown_lints, clippy::duration_suboptimal_units)] // `from_hours`/`from_mins` unstable on 1.93
pub const INITIALIZE_REFILL_INTERVAL: Duration = Duration::from_secs(60);

/// Limiter type alias — `governor`'s direct (non-keyed) variant; we
/// build one per identity and hand it out keyed by bearer-hash or sub.
type Bucket = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// Hard memory bound for each rate-limit key map. This is deliberately much
/// larger than the expected tenant population while preventing valid-token
/// churn from growing the process forever.
const LIMITER_KEY_CAP: usize = 4096;

#[derive(Debug)]
struct BucketEntry {
    bucket: Arc<Bucket>,
    last_seen: Instant,
}

type BucketMap = RwLock<HashMap<String, BucketEntry>>;

/// What kind of MCP tool this call is. Drives which quota applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Read,
    Write,
}

/// Returned when a request would exceed the configured quota.
#[derive(Debug, Clone, Copy)]
pub struct RateLimited;

#[derive(Debug)]
pub struct Limiter {
    reads_per_min: NonZeroU32,
    writes_per_min: NonZeroU32,
    bearer_read: BucketMap,
    bearer_write: BucketMap,
    sub_read: BucketMap,
    sub_write: BucketMap,
}

impl Limiter {
    /// New limiter with the given per-minute quotas. `0` quotas are
    /// rejected (`None`) — use a large quota to "effectively disable",
    /// don't pass `0`.
    #[must_use]
    pub fn new(reads_per_min: u32, writes_per_min: u32) -> Option<Self> {
        Some(Self {
            reads_per_min: NonZeroU32::new(reads_per_min)?,
            writes_per_min: NonZeroU32::new(writes_per_min)?,
            bearer_read: RwLock::new(HashMap::new()),
            bearer_write: RwLock::new(HashMap::new()),
            sub_read: RwLock::new(HashMap::new()),
            sub_write: RwLock::new(HashMap::new()),
        })
    }

    /// Check both per-bearer-hash and per-sub buckets. Returns `Ok(())`
    /// if both allow, `Err(RateLimited)` if either denies.
    pub fn check(
        &self,
        bearer_hash: &str,
        sub: Option<&str>,
        category: Category,
    ) -> Result<(), RateLimited> {
        let (bearer_map, sub_map, quota) = match category {
            Category::Read => (&self.bearer_read, &self.sub_read, self.reads_per_min),
            Category::Write => (&self.bearer_write, &self.sub_write, self.writes_per_min),
        };
        let bearer_bucket = get_or_insert(bearer_map, bearer_hash, quota);
        if bearer_bucket.check().is_err() {
            return Err(RateLimited);
        }
        if let Some(s) = sub {
            let sub_bucket = get_or_insert(sub_map, s, quota);
            if sub_bucket.check().is_err() {
                return Err(RateLimited);
            }
        }
        Ok(())
    }
}

fn get_or_insert(map: &BucketMap, key: &str, quota: NonZeroU32) -> Arc<Bucket> {
    // `governor::Quota::per_minute(n)` translates to one token every
    // (60/n) seconds with a burst of `n`.
    get_or_insert_with_quota(map, key, Quota::per_minute(quota))
}

fn get_or_insert_with_quota(map: &BucketMap, key: &str, quota: Quota) -> Arc<Bucket> {
    let mut guard = match map.write() {
        Ok(g) => g,
        // RwLock poisoning is unrecoverable here. A poisoned lock means a
        // panic happened while holding the lock — the safe thing is to
        // fall through to "no rate-limiting for this caller right now"
        // rather than panic again and tear down the server. Logged
        // upstream via tracing in the call site if it ever fires.
        Err(p) => p.into_inner(),
    };
    let now = Instant::now();
    if let Some(entry) = guard.get_mut(key) {
        entry.last_seen = now;
        return Arc::clone(&entry.bucket);
    }
    if guard.len() >= LIMITER_KEY_CAP
        && let Some(oldest) = guard
            .iter()
            .min_by_key(|(_, entry)| entry.last_seen)
            .map(|(key, _)| key.clone())
    {
        guard.remove(&oldest);
    }
    let bucket = Arc::new(RateLimiter::direct(quota));
    guard.insert(
        key.to_owned(),
        BucketEntry {
            bucket: Arc::clone(&bucket),
            last_seen: now,
        },
    );
    bucket
}

/// Rate limiter dedicated to fresh MCP session creation (the
/// `initialize` request without an `mcp-session-id` header). Tool-call
/// rate limits do not protect this path because rmcp allocates the
/// session before any tool handler runs, so the per-bucket charge
/// inside [`Limiter::check`] never fires for the initialize request.
///
/// Keyed by bearer-hash AND MAS subject the same way [`Limiter`] is:
/// a stolen token can't fan out more sessions than the bucket allows,
/// and the same `sub` can't accumulate sessions across rotated tokens
/// either.
#[derive(Debug)]
pub struct InitializeLimiter {
    quota: Quota,
    bearer: BucketMap,
    sub: BucketMap,
}

impl InitializeLimiter {
    /// New limiter that allows up to `burst` initialize calls back-to-back
    /// and then refills one token every `replenish_1_per`.
    ///
    /// Callers pass [`INITIALIZE_REFILL_INTERVAL`]; see
    /// [`MAX_INITIALIZES_PER_IDENTITY`] for why the burst and refill are
    /// sized to real client reconnect behaviour rather than to the session
    /// TTL. The global session cap, not this limiter, bounds the pool.
    #[must_use]
    pub fn new(replenish_1_per: Duration, burst: u32) -> Self {
        let burst = NonZeroU32::new(burst).unwrap_or(NonZeroU32::MIN);
        let quota = Quota::with_period(replenish_1_per)
            .unwrap_or_else(|| Quota::per_minute(NonZeroU32::MIN))
            .allow_burst(burst);
        Self {
            quota,
            bearer: RwLock::new(HashMap::new()),
            sub: RwLock::new(HashMap::new()),
        }
    }

    /// Check both per-bearer-hash and per-sub initialize buckets.
    pub fn check(&self, bearer_hash: &str, sub: Option<&str>) -> Result<(), RateLimited> {
        let bearer_bucket = get_or_insert_with_quota(&self.bearer, bearer_hash, self.quota);
        if bearer_bucket.check().is_err() {
            return Err(RateLimited);
        }
        if let Some(s) = sub {
            let sub_bucket = get_or_insert_with_quota(&self.sub, s, self.quota);
            if sub_bucket.check().is_err() {
                return Err(RateLimited);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(unknown_lints, clippy::unwrap_used, clippy::duration_suboptimal_units)]
mod tests {
    use super::*;

    #[test]
    fn zero_quota_rejected() {
        assert!(Limiter::new(0, 1).is_none());
        assert!(Limiter::new(1, 0).is_none());
    }

    #[test]
    fn reads_and_writes_have_independent_buckets() {
        let l = Limiter::new(2, 2).unwrap();
        // Burn the read bucket.
        l.check("h", Some("s"), Category::Read).unwrap();
        l.check("h", Some("s"), Category::Read).unwrap();
        assert!(l.check("h", Some("s"), Category::Read).is_err());
        // Writes are unaffected.
        l.check("h", Some("s"), Category::Write).unwrap();
        l.check("h", Some("s"), Category::Write).unwrap();
        assert!(l.check("h", Some("s"), Category::Write).is_err());
    }

    #[test]
    fn distinct_bearers_dont_share_a_bucket() {
        let l = Limiter::new(1, 1).unwrap();
        l.check("h1", None, Category::Read).unwrap();
        // Same identity at the bearer-hash level → denied.
        assert!(l.check("h1", None, Category::Read).is_err());
        // Different bearer → fresh bucket.
        l.check("h2", None, Category::Read).unwrap();
    }

    #[test]
    fn sub_bucket_denies_across_bearers_for_same_user() {
        let l = Limiter::new(1, 1).unwrap();
        l.check("h1", Some("user-A"), Category::Read).unwrap();
        // Different bearer, same sub → sub bucket exhausted.
        assert!(l.check("h2", Some("user-A"), Category::Read).is_err());
    }

    #[test]
    fn no_sub_means_bearer_only() {
        let l = Limiter::new(1, 1).unwrap();
        // Without sub, the sub bucket is skipped; only bearer-hash
        // applies.
        l.check("h1", None, Category::Read).unwrap();
        assert!(l.check("h1", None, Category::Read).is_err());
        l.check("h2", None, Category::Read).unwrap();
    }

    #[test]
    fn initialize_limiter_denies_after_burst_on_bearer() {
        let l = InitializeLimiter::new(Duration::from_secs(60), 2);
        l.check("h", Some("s")).unwrap();
        l.check("h", Some("s")).unwrap();
        assert!(l.check("h", Some("s")).is_err());
    }

    #[test]
    fn initialize_limiter_denies_across_bearers_for_same_sub() {
        let l = InitializeLimiter::new(Duration::from_secs(60), 1);
        l.check("h1", Some("s")).unwrap();
        // Different bearer, same sub → sub bucket exhausted.
        assert!(l.check("h2", Some("s")).is_err());
    }

    #[test]
    fn initialize_limiter_no_sub_uses_bearer_only() {
        let l = InitializeLimiter::new(Duration::from_secs(60), 1);
        l.check("h", None).unwrap();
        assert!(l.check("h", None).is_err());
        // Different bearer → fresh bucket.
        l.check("h2", None).unwrap();
    }

    #[test]
    fn limiter_key_maps_are_hard_capped() {
        let l = Limiter::new(100_000, 100_000).unwrap();
        for i in 0..=LIMITER_KEY_CAP {
            l.check(&format!("bearer-{i}"), None, Category::Read)
                .unwrap();
        }
        assert_eq!(l.bearer_read.read().unwrap().len(), LIMITER_KEY_CAP);

        let initialize = InitializeLimiter::new(Duration::from_secs(60), 1);
        for i in 0..=LIMITER_KEY_CAP {
            initialize.check(&format!("bearer-{i}"), None).unwrap();
        }
        assert_eq!(initialize.bearer.read().unwrap().len(), LIMITER_KEY_CAP);
    }
}
