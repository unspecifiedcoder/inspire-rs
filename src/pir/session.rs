//! ClientSession cache (Raven-local fork addition).
//!
//! ## What it fixes
//!
//! Upstream `query` / `query_seeded` at `pir/query.rs:197-272` call
//! `maybe_generate_packing_keys` on every invocation. That helper in
//! turn calls:
//!
//! - `PackParams::new(&crs.params, crs.inspiring_num_columns)` at
//!   `inspiring/inspiring2.rs:107-182`, which internally runs
//!   `generate_automorph_tables` at `inspiring/inspiring2.rs:200-263`.
//!   The tables are constructed via a brute-force O(n³) search for
//!   each odd automorphism index. At n=2048 that is roughly
//!   8.6 × 10^9 u64 comparisons per call.
//! - `ClientPackingKeys::generate(rlwe_sk, &pack_params, ...)` which
//!   emits `y_body` + up to ~2047 `y_all` rotations of the client's
//!   packing-key polynomial.
//!
//! None of that work depends on the query index, the shard, the
//! global_index, or the sampler's random output. It depends only on
//! `crs.params`, `rlwe_sk`, `crs.inspiring_num_columns`, and
//! `crs.inspiring_w_seed` - all stable across every query a client
//! sends to the same server-session CRS.
//!
//! Split-timing measurements showed client query-gen at ~3836 ms
//! (vs the server at ~4210 ms), and profiling points at the above
//! two calls as the dominant cost. Caching them across queries is
//! the structural fix.
//!
//! ## Shape
//!
//! ```text
//! let session = ClientSession::new(crs, rlwe_sk, &mut sampler)?;
//! // ... many times ...
//! let (state, seeded_query) = session.query_seeded(idx, &shard_config, &mut sampler)?;
//! ```
//!
//! The session clones its cached `ClientPackingKeys` into each emitted
//! query. The clone cost is bounded by the pre-computed polynomial
//! payload (O(d × num_rotations) memory copy) and does not re-run the
//! O(d³) automorphism-table search. Cloning is orders of magnitude
//! cheaper than regeneration.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::inspiring::{ClientPackingKeys, PackParams};
use crate::lwe::LweSecretKey;
use crate::math::{GaussianSampler, NttContext};
use crate::params::ShardConfig;
use crate::rgsw::{RgswCiphertext, SeededRgswCiphertext};
use crate::rlwe::RlweSecretKey;

use super::encode_db::inverse_monomial;
use super::error::{pir_err, Result};
use super::query::{ClientQuery, ClientState, PackingMode, SeededClientQuery, ServerSessionHandle};
use super::setup::ServerCrs;

/// Long-lived client-side state that captures everything a client
/// needs to emit many queries against one server-session CRS.
///
/// Construct once per server session; call
/// [`query`](Self::query) / [`query_seeded`](Self::query_seeded) for
/// each retrieval. The InspiRING packing keys (the expensive part) are
/// computed inside [`new`](Self::new) and cloned into each emitted
/// query.
///
/// ## Packing-key handshake (optional compression)
///
/// Per-query wire size is dominated (~48 KiB of ~148 KiB at
/// d=2048, 3 gadget digits) by the inlined `inspiring_packing_keys`
/// payload. These keys are deterministic per
/// `(CRS x rlwe_sk x inspiring_w_seed)` and stable across every
/// query in the same session. The session may call
/// [`register_with`](Self::register_with) once to upload the keys
/// to a [`ServerSessionStore`], receive an opaque
/// [`ServerSessionHandle`], and cache it. Subsequent
/// `query_seeded` calls emit the handle in place of the inlined
/// keys, dropping wire-side query size by roughly a third.
///
/// Fallback: if the handshake is not used, `query_seeded` emits
/// with keys inlined, preserving byte-for-byte the pre-handshake
/// wire format + behavior.
#[derive(Debug)]
pub struct ClientSession {
    /// Caller-supplied CRS. Held by value so the session owns a
    /// consistent snapshot; callers who need to rotate CRSes (e.g.
    /// server reload) should build a new `ClientSession`.
    crs: ServerCrs,
    /// Caller-supplied RLWE secret key.
    rlwe_sk: RlweSecretKey,
    /// Derived LWE secret key (coefficient vector of the RLWE key).
    /// Cached because `rlwe_to_lwe_key` is O(d) per call but upstream
    /// re-computes it on every query anyway.
    lwe_sk: LweSecretKey,
    /// Precomputed InspiRING packing params (owns the O(d³)
    /// automorph tables). `None` if the CRS doesn't carry InspiRING
    /// machinery (i.e. Tree-packing-only server).
    pack_params: Option<PackParams>,
    /// Precomputed client packing keys (y_body + y_all rotations).
    /// `None` for Tree-packing-only servers.
    packing_keys: Option<ClientPackingKeys>,
    /// Handshake handle populated by [`register_with`](Self::register_with).
    /// `None` = fallback path (inline keys in every query).
    /// `Some(h)` = compact path (reference the handle; keys are resolved
    /// server-side from [`ServerSessionStore`]).
    session_handle: Option<ServerSessionHandle>,
}

impl ClientSession {
    /// Build a session. Runs the heavy one-time work:
    /// `PackParams::new` + `ClientPackingKeys::generate` if the CRS
    /// carries InspiRING machinery.
    pub fn new(
        crs: ServerCrs,
        rlwe_sk: RlweSecretKey,
        sampler: &mut GaussianSampler,
    ) -> Result<Self> {
        let lwe_sk = rlwe_to_lwe_key(&rlwe_sk);

        let (pack_params, packing_keys) = if crs.packing_k_g.is_some()
            && crs.inspiring_num_columns > 0
        {
            let pp = PackParams::new(&crs.params, crs.inspiring_num_columns);
            let keys = ClientPackingKeys::generate(&rlwe_sk, &pp, crs.inspiring_w_seed, sampler);
            (Some(pp), Some(keys))
        } else {
            (None, None)
        };

        Ok(Self {
            crs,
            rlwe_sk,
            lwe_sk,
            pack_params,
            packing_keys,
            session_handle: None,
        })
    }

    /// Upload cached packing keys to the server's
    /// [`ServerSessionStore`], store the returned handle, and
    /// switch this session to the compact wire format.
    ///
    /// After this call, [`query`](Self::query) and
    /// [`query_seeded`](Self::query_seeded) emit queries with
    /// `inspiring_packing_keys: None` + `session_handle: Some(...)`.
    /// The server's `respond_inspiring_cached_with_session` entry
    /// point resolves the handle back to the stored keys. The wire
    /// payload shrinks by the size of the inlined `ClientPackingKeys`
    /// payload (measured ~48 KiB at d=2048 production params).
    ///
    /// Returns `Ok(None)` if the session has no packing keys to
    /// upload (Tree-packing-only server); no handshake is required.
    /// Returns `Ok(Some(handle))` on success. Returns `Err` if the
    /// underlying store is poisoned.
    pub fn register_with(
        &mut self,
        store: &ServerSessionStore,
    ) -> Result<Option<ServerSessionHandle>> {
        match &self.packing_keys {
            None => Ok(None),
            Some(keys) => {
                let handle = store.register(keys.clone())?;
                self.session_handle = Some(handle);
                Ok(Some(handle))
            }
        }
    }

    /// Current handshake handle, or `None` if
    /// [`register_with`](Self::register_with) has not been called
    /// (or this session has no InspiRING packing keys to register).
    pub fn session_handle(&self) -> Option<ServerSessionHandle> {
        self.session_handle
    }

    /// Register with the server store via the server-side derivation
    /// path.
    ///
    /// Clones the session's `y_body` (and other metadata) but drops
    /// the derived `y_all` + `y_all_ntt` fields before registering —
    /// matching what a server receives when the query was transported
    /// across the wire (the derived fields are `#[serde(skip)]`). The
    /// server then re-derives them once via
    /// [`ServerSessionStore::register_server_side`], which caches the
    /// populated keys under the returned handle. Subsequent queries
    /// against that handle dispatch to `packing_online_fully_ntt` in
    /// the respond path (not the slower coefficient-form
    /// `packing_online` fallback the wire case otherwise hits).
    ///
    /// This is the hook that closes the measured ~1.58× server
    /// slowdown + ~36% throughput drop for wire-format deployments.
    /// For pure in-process use, prefer [`register_with`](Self::register_with)
    /// — it skips the redundant derivation.
    pub fn register_with_server_derivation(
        &mut self,
        store: &ServerSessionStore,
    ) -> Result<Option<ServerSessionHandle>> {
        let (pp, ctx, wire_keys) = match (&self.pack_params, &self.packing_keys) {
            (Some(pp), Some(keys)) => {
                let ctx = self.crs.params.ntt_context();
                let wire_keys = ClientPackingKeys {
                    y_body: keys.y_body.clone(),
                    z_body: keys.z_body.clone(),
                    y_all: Vec::new(),
                    y_all_ntt: Vec::new(),
                    y_bar_all: Vec::new(),
                    y_bar_all_ntt: Vec::new(),
                    full_key: keys.full_key,
                    num_to_pack: keys.num_to_pack,
                };
                (pp, ctx, wire_keys)
            }
            _ => return Ok(None),
        };
        let handle = store.register_server_side(wire_keys, pp, &ctx)?;
        self.session_handle = Some(handle);
        Ok(Some(handle))
    }

    /// Borrow the captured CRS. Useful when callers also need to hand
    /// the CRS to the response-side API alongside the session.
    pub fn crs(&self) -> &ServerCrs {
        &self.crs
    }

    /// Borrow the captured RLWE secret key. Session owns it; callers
    /// who need the key for extract/decrypt should re-use this.
    pub fn rlwe_secret_key(&self) -> &RlweSecretKey {
        &self.rlwe_sk
    }

    /// Hot-path query: emits a full `ClientQuery`. Per-query work only
    /// (inverse monomial + RGSW encrypt + clone the cached packing
    /// keys into the emitted query).
    pub fn query(
        &self,
        global_index: u64,
        shard_config: &ShardConfig,
        sampler: &mut GaussianSampler,
    ) -> Result<(ClientState, ClientQuery)> {
        let d = self.crs.ring_dim();
        let q = self.crs.modulus();
        let ctx = self.crs.params.ntt_context();

        let (shard_id, local_index) = shard_config.index_to_shard(global_index);

        let inv_mono = inverse_monomial(local_index as usize, d, q, self.crs.params.moduli());
        let rgsw_ciphertext = RgswCiphertext::encrypt(
            &self.rlwe_sk,
            &inv_mono,
            &self.crs.rgsw_gadget,
            sampler,
            &ctx,
        );

        let state = ClientState {
            secret_key: self.lwe_sk.clone(),
            rlwe_secret_key: self.rlwe_sk.clone(),
            index: global_index,
            shard_id,
            local_index,
        };

        // Handshake-aware wire shape: when a session handle is
        // attached, emit `inspiring_packing_keys: None` and carry
        // the handle instead. Otherwise inline the keys as before.
        let (inspiring_packing_keys, session_handle) = match self.session_handle {
            Some(h) => (None, Some(h)),
            None => (self.packing_keys.clone(), None),
        };
        let packing_mode = if self.packing_keys.is_some() {
            PackingMode::Inspiring
        } else {
            PackingMode::Tree
        };

        Ok((
            state,
            ClientQuery {
                shard_id,
                rgsw_ciphertext,
                packing_mode,
                inspiring_packing_keys,
                session_handle,
            },
        ))
    }

    /// Hot-path seeded query (InsPIRe^2). Same shape as
    /// [`query`](Self::query) but returns a `SeededClientQuery` for
    /// ~50% bandwidth reduction.
    pub fn query_seeded(
        &self,
        global_index: u64,
        shard_config: &ShardConfig,
        sampler: &mut GaussianSampler,
    ) -> Result<(ClientState, SeededClientQuery)> {
        let d = self.crs.ring_dim();
        let q = self.crs.modulus();
        let ctx = self.crs.params.ntt_context();

        let (shard_id, local_index) = shard_config.index_to_shard(global_index);

        let inv_mono = inverse_monomial(local_index as usize, d, q, self.crs.params.moduli());
        let rgsw_ciphertext = SeededRgswCiphertext::encrypt(
            &self.rlwe_sk,
            &inv_mono,
            &self.crs.rgsw_gadget,
            sampler,
            &ctx,
        );

        let state = ClientState {
            secret_key: self.lwe_sk.clone(),
            rlwe_secret_key: self.rlwe_sk.clone(),
            index: global_index,
            shard_id,
            local_index,
        };

        let (inspiring_packing_keys, session_handle) = match self.session_handle {
            Some(h) => (None, Some(h)),
            None => (self.packing_keys.clone(), None),
        };
        let packing_mode = if self.packing_keys.is_some() {
            PackingMode::Inspiring
        } else {
            PackingMode::Tree
        };

        Ok((
            state,
            SeededClientQuery {
                shard_id,
                rgsw_ciphertext,
                packing_mode,
                inspiring_packing_keys,
                session_handle,
            },
        ))
    }

    /// Whether this session has InspiRING packing machinery cached.
    /// Useful for callers that want to branch on server capability
    /// at setup time rather than per-query.
    pub fn has_inspiring_packing(&self) -> bool {
        self.packing_keys.is_some()
    }

    /// Borrow the cached `PackParams` for advanced callers (e.g. those
    /// reconstructing intermediate state for debugging or tests).
    pub fn pack_params(&self) -> Option<&PackParams> {
        self.pack_params.as_ref()
    }
}

/// Copy of `query::rlwe_to_lwe_key`. The upstream function is
/// non-pub; duplicating it is cheaper than reorganising the module.
fn rlwe_to_lwe_key(rlwe_sk: &RlweSecretKey) -> LweSecretKey {
    let d = rlwe_sk.ring_dim();
    let mut coeffs = Vec::with_capacity(d);
    for i in 0..d {
        coeffs.push(rlwe_sk.poly.coeff(i));
    }
    let q = rlwe_sk.modulus();
    LweSecretKey::from_coeffs(coeffs, q)
}

/// Server-side session map for the packing-key handshake.
///
/// One store per server instance. Callers register a client's
/// `ClientPackingKeys` via [`register`](Self::register), receive an
/// opaque [`ServerSessionHandle`], and send the handle back to the
/// client. Subsequent queries reference the handle and the server
/// resolves the keys via [`get`](Self::get).
///
/// The store is `Send + Sync` so it can be shared across rayon
/// workers + async request handlers. Internally an `RwLock<HashMap>`
/// because reads dominate writes: every query reads, registration
/// happens once per client session.
///
/// ## Capacity + eviction
///
/// There is no eviction. Callers concerned about memory pressure
/// should build a longer-lived store outside of this crate (e.g.
/// an LRU wrapper) and call into this store's `register` / `get`
/// accordingly. The B1 bench adapter uses a single session so
/// capacity is bounded at 1.
///
/// ## Security
///
/// The handle is an unauthenticated u64. A malicious client that
/// guesses another client's handle could route queries to be
/// processed under that client's packing keys — which (per the
/// `ClientPackingKeys` structure) produce a response the malicious
/// client cannot decrypt. That is a denial-of-useful-response
/// against the other client, not a confidentiality leak. Production
/// deployments should pair the handle with a session token or
/// transport-level authentication; none of that lives in this
/// store.
#[derive(Debug, Default)]
pub struct ServerSessionStore {
    /// Interior mutability for read-heavy access. Arc<ClientPackingKeys>
    /// avoids cloning the ~48 KiB payload on every lookup.
    inner: RwLock<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    by_handle: HashMap<u64, Arc<ClientPackingKeys>>,
    next_handle: u64,
}

impl ServerSessionStore {
    /// Build an empty store. Call [`register`](Self::register) to
    /// allocate handles.
    pub fn new() -> Self {
        Self::default()
    }

    /// Store `keys` under a freshly allocated handle and return it.
    /// Handles are monotonically increasing; collisions are impossible
    /// within the lifetime of a single store.
    pub fn register(&self, keys: ClientPackingKeys) -> Result<ServerSessionHandle> {
        let mut inner = self
            .inner
            .write()
            .map_err(|_| pir_err!("ServerSessionStore: lock poisoned on register"))?;
        let h = inner.next_handle;
        inner.next_handle = inner.next_handle.checked_add(1).unwrap_or(0);
        inner.by_handle.insert(h, Arc::new(keys));
        Ok(ServerSessionHandle(h))
    }

    /// Server-side register path.
    ///
    /// Accepts `ClientPackingKeys` as delivered over the wire (where
    /// `y_all` + `y_all_ntt` are `#[serde(skip)]` and therefore empty
    /// after deserialize), derives both from `y_body` using the
    /// provided `pack_params` + NTT context, and caches the fully-
    /// populated keys under a fresh handle.
    ///
    /// Subsequent `respond_inspiring_cached_with_session` calls against
    /// the returned handle dispatch to `packing_online_fully_ntt`
    /// (rather than the coefficient-form `packing_online` fallback),
    /// closing the wire-format gap measured at ~1.58× server
    /// slowdown and ~36% throughput drop.
    ///
    /// No-op derivation when the input keys already carry `y_all_ntt`
    /// (in-process case): the ensure_server_derivatives helper is
    /// length-checked and returns immediately when the fields are
    /// populated.
    pub fn register_server_side(
        &self,
        mut keys: ClientPackingKeys,
        pack_params: &PackParams,
        ctx: &NttContext,
    ) -> Result<ServerSessionHandle> {
        keys.ensure_server_derivatives(pack_params, ctx);
        self.register(keys)
    }

    /// Look up the packing keys stored under `handle`. Returns `None`
    /// if no such handle exists.
    pub fn get(&self, handle: ServerSessionHandle) -> Result<Option<Arc<ClientPackingKeys>>> {
        let inner = self
            .inner
            .read()
            .map_err(|_| pir_err!("ServerSessionStore: lock poisoned on get"))?;
        Ok(inner.by_handle.get(&handle.0).cloned())
    }

    /// Number of currently registered sessions.
    pub fn len(&self) -> usize {
        self.inner
            .read()
            .map(|inner| inner.by_handle.len())
            .unwrap_or(0)
    }

    /// Whether the store holds no sessions.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
