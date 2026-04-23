//! InsPIRe: Communication-Efficient PIR with Server-side Preprocessing
//!
//! This crate implements the InsPIRe PIR protocol from the paper:
//! "InsPIRe: Communication-Efficient PIR with Server-side Preprocessing"
//!
//! Key components:
//! - InspiRING: Novel ring packing algorithm (LWE → RLWE) using only 2 key-switching matrices
//! - Homomorphic polynomial evaluation for reduced response size
//! - CRS model for server-side preprocessing

pub mod cost;
pub mod inspiring;
pub mod ks;
pub mod lwe;
pub mod math;
pub mod params;
pub mod pir;
pub mod rgsw;
pub mod rlwe;

pub use pir::{
    encode_column, encode_database, encode_direct, extract, extract_inspiring, extract_two_packing,
    extract_with_variant, inverse_monomial, query, query_seeded, respond, respond_inspiring,
    respond_inspiring_cached, respond_inspiring_cached_with_session, respond_one_packing,
    respond_seeded, respond_seeded_inspiring, respond_seeded_inspiring_cached,
    respond_seeded_inspiring_cached_with_session, respond_seeded_packed,
    respond_seeded_with_variant, respond_with_variant, setup, ClientQuery, ClientSession,
    ClientState, EncodedDatabase, InspireCrs, PackingMode, SeededClientQuery, ServerCrs,
    ServerInspiringCache, ServerResponse, ServerSessionHandle, ServerSessionStore, ShardData,
};

pub use params::{InspireParams, InspireVariant, SecurityLevel};
