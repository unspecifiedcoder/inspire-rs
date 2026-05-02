//! Spiral-style server-side response mod-switching.
//!
//! Switches the response RLWE ciphertext from the encoding modulus
//! `q` (typically the 2-CRT product `q ≈ 2^60`) down to a smaller
//! single-prime modulus `q'`, producing a wire-byte reduction
//! proportional to the CRT-limb count drop. Cited inspiration:
//! Spiral's `values.h:71` parameter triple `(q1, q2, t)` for response
//! mod-switching.
//!
//! # Algorithm
//!
//! For each coefficient `c ∈ Z_q` in the RLWE ciphertext (both the
//! `a` and `b` polynomials):
//!
//!   c' = round(c · q' / q) mod q'
//!
//! After the switch the noise grows by approximately
//! `d · |s|_max / 2` (worst-case rounding noise) plus the original
//! noise scaled by `q'/q`. Decryption succeeds iff the post-switch
//! noise stays under `q'/(2p)` (the mod-switched delta-half budget).
//!
//! # Wire-bytes win
//!
//! A 2-CRT polynomial serialized via bincode encodes
//! `dim * crt_count = 2 * dim` u64 elements per Poly. A 1-CRT
//! polynomial encodes `dim` u64 elements. The Inspiring response
//! holds one `(a, b)` ciphertext pair, so the dominant wire payload
//! halves when the response is mod-switched from 2-CRT down to a
//! single 1-CRT polynomial pair.
//!
//! # Noise-budget gate
//!
//! [`check_mod_switch_noise_budget`] enforces a conservative bound
//! before any switch is applied. The shipping production cell at
//! `d=2048`, `p=65537`, source `q ≈ 2^60` (two 30-bit primes) and
//! target `q' = DEFAULT_Q ≈ 2^60` (single 60-bit prime) preserves the
//! modulus magnitude exactly (`q == q'` numerically), so the rounding
//! noise term is zero and the budget is trivially satisfied. Operators
//! that select a smaller `q'` for additional shrink (deferred to V2 +
//! bit-packed serialization work) MUST verify the budget at the
//! deployed parameter triple.
//!
//! # Sound vs. unsound switches
//!
//! A switch with `q' < q · (2 * p) / (d · |s|_max + 2 * old_noise)`
//! breaks decryption silently. The gate fires on numerical violation;
//! the [`mod_switch_response_checked`] entrypoint returns an error
//! rather than producing a corrupted ciphertext.

use serde::{Deserialize, Serialize};

use crate::math::{NttContext, Poly};
use crate::params::InspireParams;
use crate::rlwe::{RlweCiphertext, RlweSecretKey};

use super::error::{pir_err, Result};
use super::query::{ClientState, PackingMode};
use super::respond::ServerResponse;
use super::setup::InspireCrs;

/// Conservative tail-bound multiplier on the secret-key infinity norm.
///
/// For a discrete Gaussian with `sigma <= 6.4`, taking `|s|_inf <= 7 * sigma`
/// gives ~2^-32 tail probability per coefficient. The bound is
/// intentionally tighter than statistical-average to keep the
/// noise-budget gate worst-case sound under the `d` independent
/// rounding samples that mod-switch introduces.
const SECRET_KEY_TAIL_MULT: f64 = 7.0;

/// Half-tail rounding error per coefficient under integer division.
///
/// The Spiral mod-switch round-to-nearest emits at most 0.5 per
/// coefficient before being multiplied through by the secret. Each
/// of `d` coefficient samples contributes at most this magnitude.
const ROUND_HALF: f64 = 0.5;

/// NTT-friendly 45-bit prime suitable as a mod-switch target for
/// `secure_128_d2048` (single-CRT q ≈ 2^60). Verified prime via
/// Miller-Rabin with witnesses `{2,3,5,7,11,13,17,19,23,29,31,37}`
/// (deterministic for n < 3.3e14). Satisfies `p ≡ 1 (mod 4096)` so
/// admits length-2048 negacyclic NTT for client-side decryption.
///
/// Wire-byte profile vs unswitched 60-bit single-CRT response:
/// `45 bits = 6 bytes_per_coeff` vs `60 bits = 8 bytes_per_coeff`,
/// yielding a 25% per-coefficient wire reduction when paired with
/// the [`encode_response_packed`] tight serializer. The bincode
/// `Vec<u64>` baseline pads every coefficient to 8 bytes regardless
/// of the actual modulus width, so the win materializes only with
/// the packed encoder.
pub const MOD_SWITCH_TARGET_45BIT: u64 = 35_184_372_060_161;

/// NTT-friendly 33-bit prime offering a more aggressive wire
/// reduction (5 bytes_per_coeff = 37.5% per-coefficient shrink) at
/// a tighter post-switch noise margin. Operators MUST verify the
/// noise budget against their concrete cell shape via
/// [`check_mod_switch_noise_budget`] before deploying this target.
pub const MOD_SWITCH_TARGET_33BIT: u64 = 8_589_905_921;

/// Mod-switch parameter triple equivalent to Spiral's `(q1, q2, t)`
/// shape at `values.h:71` adapted for InsPIRe's `(q, q', p)` naming.
///
/// # Fields
///
/// * `source_modulus` - Original ciphertext modulus `q` (CRT product).
/// * `target_modulus` - Post-switch modulus `q'`. Must satisfy
///   `target_modulus <= source_modulus` and `target_modulus ≡ 1 (mod 2 * dim)`
///   for the switched ciphertext to remain compatible with NTT-based
///   client decryption.
/// * `plaintext_modulus` - Plaintext modulus `p` reused from the
///   source parameters; mod-switch does not change `p`.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct ModSwitchParams {
    pub source_modulus: u64,
    pub target_modulus: u64,
    pub plaintext_modulus: u64,
}

impl ModSwitchParams {
    /// Build a parameter triple from source `InspireParams` and a
    /// requested `target_modulus`. Validates basic sanity (target <=
    /// source, both > p, target NTT-friendly mod 2 * dim).
    pub fn new(source_params: &InspireParams, target_modulus: u64) -> Result<Self> {
        if target_modulus == 0 {
            return Err(pir_err!("mod-switch target_modulus must be positive"));
        }
        if target_modulus > source_params.q {
            return Err(pir_err!(
                "mod-switch target_modulus {} exceeds source modulus {}; widening is not a mod-switch",
                target_modulus,
                source_params.q
            ));
        }
        if target_modulus < source_params.p {
            return Err(pir_err!(
                "mod-switch target_modulus {} < plaintext modulus p={}; decryption impossible",
                target_modulus,
                source_params.p
            ));
        }
        let two_n = 2u64 * source_params.ring_dim as u64;
        if target_modulus % two_n != 1 {
            return Err(pir_err!(
                "mod-switch target_modulus {} is not NTT-friendly: must satisfy q' ≡ 1 (mod 2*d) where d={}",
                target_modulus,
                source_params.ring_dim
            ));
        }
        Ok(Self {
            source_modulus: source_params.q,
            target_modulus,
            plaintext_modulus: source_params.p,
        })
    }
}

/// Verify that a mod-switch from `source_modulus` to `target_modulus`
/// keeps the decryption noise under the post-switch budget
/// `q'/(2p)`.
///
/// The bound combines:
/// - Worst-case round-to-nearest noise: `d/2 * |s|_max`, where
///   `|s|_max <= SECRET_KEY_TAIL_MULT * sigma` (tail-bounded
///   Gaussian).
/// - Scaled prior noise: `(q'/q) * old_noise_bound`. We bound
///   `old_noise_bound` by `q/(4p)` (half the available pre-switch
///   delta-budget) since shipping configs always have at least 1 bit
///   of decryption slack.
///
/// Returns `Err` if the conservative bound exceeds `q'/(2p)`.
pub fn check_mod_switch_noise_budget(params: &InspireParams, target_modulus: u64) -> Result<()> {
    let _triple = ModSwitchParams::new(params, target_modulus)?;
    let d = params.ring_dim as f64;
    let p = params.p as f64;
    let q_old = params.q as f64;
    let q_new = target_modulus as f64;
    let sigma = params.sigma;

    let s_max = SECRET_KEY_TAIL_MULT * sigma;
    let round_noise = ROUND_HALF + d * 0.5 * s_max;
    let scaled_old_noise = (q_new / q_old) * (q_old / (4.0 * p));
    let total_noise = round_noise + scaled_old_noise;

    let budget = q_new / (2.0 * p);

    if total_noise >= budget {
        return Err(pir_err!(
            "mod-switch noise-budget violation: total_noise={:.0} >= budget={:.0} \
             (round={:.0}, scaled_old={:.0}, q'={}, q={}, p={}, d={}, sigma={})",
            total_noise,
            budget,
            round_noise,
            scaled_old_noise,
            target_modulus,
            params.q,
            params.p,
            params.ring_dim,
            params.sigma,
        ));
    }
    Ok(())
}

/// Mod-switch a single RLWE polynomial.
///
/// For each coefficient `c` of `poly` (recomposed from any CRT
/// representation), produces `c' = round(c * q' / q) mod q'` in a
/// fresh single-modulus polynomial.
///
/// When `target_modulus == poly.modulus()`, the operation degenerates
/// to a CRT-representation collapse with no arithmetic noise added.
///
/// # Errors
/// Returns `Err` if `poly` is in NTT domain (must be in coefficient
/// domain to recompose values cross-CRT).
fn mod_switch_poly(poly: &Poly, target_modulus: u64) -> Result<Poly> {
    if poly.is_ntt() {
        return Err(pir_err!(
            "mod_switch_poly requires coefficient-domain input; got NTT-domain Poly"
        ));
    }
    let dim = poly.dimension();
    let q_old = poly.modulus();
    let mut out = vec![0u64; dim];

    if target_modulus == q_old && poly.crt_count() == 1 {
        out.copy_from_slice(poly.coeffs());
        return Ok(Poly::from_coeffs(out, target_modulus));
    }

    let q_old_u128 = q_old as u128;
    let q_new_u128 = target_modulus as u128;
    let half_q_old = q_old_u128 / 2;

    for (i, slot) in out.iter_mut().enumerate() {
        let c_old = poly.coeff(i) as u128;
        let scaled = c_old * q_new_u128 + half_q_old;
        let c_new = (scaled / q_old_u128) % q_new_u128;
        *slot = c_new as u64;
    }

    Ok(Poly::from_coeffs(out, target_modulus))
}

/// Mod-switch every RLWE ciphertext inside a `ServerResponse`.
///
/// Applies [`mod_switch_poly`] to the `a` and `b` polys of every
/// ciphertext (the primary `ciphertext` plus any `column_ciphertexts`
/// in non-Inspiring variants). The returned `ServerResponse` carries
/// the same `packing_mode` discriminant so client extract dispatches
/// correctly; the only structural difference is the smaller modulus
/// on every internal `Poly`.
///
/// # Errors
/// Returns `Err` if any internal poly is in NTT domain, or if the
/// noise-budget gate fails for the requested switch.
pub fn mod_switch_response_checked(
    params: &InspireParams,
    response: &ServerResponse,
    target_modulus: u64,
) -> Result<ServerResponse> {
    check_mod_switch_noise_budget(params, target_modulus)?;
    mod_switch_response_inner(response, target_modulus)
}

/// Same as [`mod_switch_response_checked`] but skips the noise-budget
/// gate. For benchmark + KAT use only; production callers must use
/// the checked variant.
pub fn mod_switch_response_unchecked(
    response: &ServerResponse,
    target_modulus: u64,
) -> Result<ServerResponse> {
    mod_switch_response_inner(response, target_modulus)
}

fn mod_switch_response_inner(
    response: &ServerResponse,
    target_modulus: u64,
) -> Result<ServerResponse> {
    let new_main = mod_switch_ciphertext(&response.ciphertext, target_modulus)?;
    let new_columns = response
        .column_ciphertexts
        .iter()
        .map(|ct| mod_switch_ciphertext(ct, target_modulus))
        .collect::<Result<Vec<_>>>()?;
    Ok(ServerResponse {
        ciphertext: new_main,
        column_ciphertexts: new_columns,
        packing_mode: response.packing_mode,
    })
}

fn mod_switch_ciphertext(ct: &RlweCiphertext, target_modulus: u64) -> Result<RlweCiphertext> {
    let new_a = mod_switch_poly(&ct.a, target_modulus)?;
    let new_b = mod_switch_poly(&ct.b, target_modulus)?;
    Ok(RlweCiphertext::from_parts(new_a, new_b))
}

/// Mod-switch a secret key polynomial into the target modulus space.
///
/// Secrets are sampled small (Gaussian `sigma`) so their integer
/// values are unchanged when re-interpreted under a different
/// modulus, modulo the standard signed-vs-unsigned representation
/// flip. Recomposes from CRT, then re-decomposes against
/// `target_modulus`.
///
/// # Errors
/// Returns `Err` if the secret-key polynomial is in NTT domain.
fn mod_switch_secret_key(
    sk: &RlweSecretKey,
    target_modulus: u64,
    source_modulus: u64,
) -> Result<RlweSecretKey> {
    if sk.poly.is_ntt() {
        return Err(pir_err!(
            "mod_switch_secret_key requires coefficient-domain input"
        ));
    }
    let dim = sk.poly.dimension();
    let half_q_old = source_modulus / 2;
    let mut new_coeffs = vec![0u64; dim];
    for (i, slot) in new_coeffs.iter_mut().enumerate() {
        let c = sk.poly.coeff(i);
        let signed_value = if c > half_q_old {
            (c as i128) - (source_modulus as i128)
        } else {
            c as i128
        };
        let mapped = signed_value.rem_euclid(target_modulus as i128) as u64;
        *slot = mapped;
    }
    Ok(RlweSecretKey::from_poly(Poly::from_coeffs(
        new_coeffs,
        target_modulus,
    )))
}

/// Tight wire-encoding of a mod-switched [`ServerResponse`].
///
/// The Spiral wire-byte win materializes only when the post-switch
/// modulus is paired with a coefficient-tight serialization that
/// drops the per-coefficient `u64` padding bincode emits. This
/// encoder packs each coefficient into the minimum whole-byte width
/// `bytes_per_coeff = ceil(log2(target_modulus) / 8)`.
///
/// # Layout
///
/// ```text
///   magic          : 4 bytes  ("RIMS")
///   version        : 1 byte   (currently 1)
///   target_modulus : 8 bytes  (LE u64)
///   ring_dim       : 4 bytes  (LE u32)
///   bytes_per_coeff: 1 byte
///   packing_mode   : 1 byte   (0 None / 1 Inspiring / 2 Tree)
///   num_columns    : 4 bytes  (LE u32; column_ciphertexts.len())
///   payload        : (2 + 2 * num_columns) * ring_dim * bytes_per_coeff
/// ```
///
/// The payload concatenates every Poly in the response (`a`, `b`,
/// then each column ciphertext's `a`, `b`) coefficient-major in
/// little-endian order, padded to `bytes_per_coeff` bytes.
///
/// # Errors
/// Returns `Err` when any contained polynomial sits in NTT domain or
/// has a multi-CRT representation (mod-switch must be applied before
/// encoding so that every poly is single-CRT).
pub fn encode_response_packed(response: &ServerResponse) -> Result<Vec<u8>> {
    let main_dim = response.ciphertext.ring_dim();
    let target_modulus = response.ciphertext.modulus();
    if target_modulus == 0 {
        return Err(pir_err!(
            "encode_response_packed: target_modulus must be > 0"
        ));
    }
    if response.ciphertext.a.crt_count() != 1 || response.ciphertext.b.crt_count() != 1 {
        return Err(pir_err!(
            "encode_response_packed: ciphertext must be single-CRT after mod-switch"
        ));
    }

    let bits = (64u32 - (target_modulus.saturating_sub(1)).leading_zeros()).max(1);
    let bytes_per_coeff = ((bits + 7) / 8) as u8;

    let pack_mode_byte: u8 = match response.packing_mode {
        None => 0,
        Some(PackingMode::Inspiring) => 1,
        Some(PackingMode::Tree) => 2,
    };

    let num_columns = u32::try_from(response.column_ciphertexts.len())
        .map_err(|_| pir_err!("encode_response_packed: too many column ciphertexts"))?;
    let ring_dim_u32 = u32::try_from(main_dim)
        .map_err(|_| pir_err!("encode_response_packed: ring_dim does not fit in u32"))?;

    let payload_polys = 2usize + 2 * (num_columns as usize);
    let payload_len = payload_polys
        .checked_mul(main_dim)
        .and_then(|n| n.checked_mul(bytes_per_coeff as usize))
        .ok_or_else(|| pir_err!("encode_response_packed: payload size overflow"))?;
    let header_len = 4 + 1 + 8 + 4 + 1 + 1 + 4;
    let mut out = Vec::with_capacity(header_len + payload_len);
    out.extend_from_slice(b"RIMS");
    out.push(1u8);
    out.extend_from_slice(&target_modulus.to_le_bytes());
    out.extend_from_slice(&ring_dim_u32.to_le_bytes());
    out.push(bytes_per_coeff);
    out.push(pack_mode_byte);
    out.extend_from_slice(&num_columns.to_le_bytes());

    write_poly_packed(&response.ciphertext.a, bytes_per_coeff, &mut out)?;
    write_poly_packed(&response.ciphertext.b, bytes_per_coeff, &mut out)?;
    for col_ct in &response.column_ciphertexts {
        if col_ct.a.crt_count() != 1 || col_ct.b.crt_count() != 1 {
            return Err(pir_err!(
                "encode_response_packed: column ciphertext must be single-CRT"
            ));
        }
        if col_ct.ring_dim() != main_dim {
            return Err(pir_err!(
                "encode_response_packed: column ciphertext ring_dim mismatch"
            ));
        }
        write_poly_packed(&col_ct.a, bytes_per_coeff, &mut out)?;
        write_poly_packed(&col_ct.b, bytes_per_coeff, &mut out)?;
    }
    Ok(out)
}

/// Inverse of [`encode_response_packed`]. Reconstructs a
/// [`ServerResponse`] whose Polys are single-CRT under the encoded
/// `target_modulus`.
pub fn decode_response_packed(bytes: &[u8]) -> Result<ServerResponse> {
    if bytes.len() < 23 || &bytes[..4] != b"RIMS" {
        return Err(pir_err!(
            "decode_response_packed: bad magic / truncated header"
        ));
    }
    let version = bytes[4];
    if version != 1 {
        return Err(pir_err!(
            "decode_response_packed: unsupported version {}",
            version
        ));
    }
    let target_modulus = u64::from_le_bytes(
        bytes[5..13]
            .try_into()
            .map_err(|_| pir_err!("decode_response_packed: target_modulus header truncated"))?,
    );
    let ring_dim = u32::from_le_bytes(
        bytes[13..17]
            .try_into()
            .map_err(|_| pir_err!("decode_response_packed: ring_dim header truncated"))?,
    ) as usize;
    let bytes_per_coeff = bytes[17];
    let pack_mode_byte = bytes[18];
    let num_columns = u32::from_le_bytes(
        bytes[19..23]
            .try_into()
            .map_err(|_| pir_err!("decode_response_packed: num_columns header truncated"))?,
    ) as usize;

    let packing_mode = match pack_mode_byte {
        0 => None,
        1 => Some(PackingMode::Inspiring),
        2 => Some(PackingMode::Tree),
        other => {
            return Err(pir_err!(
                "decode_response_packed: unknown packing_mode byte {}",
                other
            ))
        }
    };

    let payload_polys = 2usize + 2 * num_columns;
    let payload_len = payload_polys
        .checked_mul(ring_dim)
        .and_then(|n| n.checked_mul(bytes_per_coeff as usize))
        .ok_or_else(|| pir_err!("decode_response_packed: payload length overflow"))?;
    let payload_start = 23usize;
    if bytes.len() != payload_start + payload_len {
        return Err(pir_err!(
            "decode_response_packed: payload length mismatch (expected {}, got {})",
            payload_start + payload_len,
            bytes.len()
        ));
    }

    let mut cursor = payload_start;
    let read_poly = |cursor: &mut usize, src: &[u8]| -> Result<Poly> {
        let chunk_len = ring_dim * bytes_per_coeff as usize;
        let chunk = &src[*cursor..*cursor + chunk_len];
        *cursor += chunk_len;
        let mut coeffs = vec![0u64; ring_dim];
        for (i, slot) in coeffs.iter_mut().enumerate() {
            let mut buf = [0u8; 8];
            let off = i * bytes_per_coeff as usize;
            for j in 0..bytes_per_coeff as usize {
                buf[j] = chunk[off + j];
            }
            *slot = u64::from_le_bytes(buf);
        }
        Ok(Poly::from_coeffs(coeffs, target_modulus))
    };

    let main_a = read_poly(&mut cursor, bytes)?;
    let main_b = read_poly(&mut cursor, bytes)?;
    let main_ct = RlweCiphertext::from_parts(main_a, main_b);
    let mut column_ciphertexts = Vec::with_capacity(num_columns);
    for _ in 0..num_columns {
        let col_a = read_poly(&mut cursor, bytes)?;
        let col_b = read_poly(&mut cursor, bytes)?;
        column_ciphertexts.push(RlweCiphertext::from_parts(col_a, col_b));
    }

    Ok(ServerResponse {
        ciphertext: main_ct,
        column_ciphertexts,
        packing_mode,
    })
}

fn write_poly_packed(poly: &Poly, bytes_per_coeff: u8, out: &mut Vec<u8>) -> Result<()> {
    if poly.is_ntt() {
        return Err(pir_err!("write_poly_packed: refuses NTT-domain Poly"));
    }
    let dim = poly.dimension();
    for i in 0..dim {
        let value = poly.coeff(i);
        let bytes = value.to_le_bytes();
        out.extend_from_slice(&bytes[..bytes_per_coeff as usize]);
    }
    Ok(())
}

/// Decrypt + extract bytes from a mod-switched Inspiring response.
///
/// Mirrors [`crate::pir::extract_inspiring`] but reads `delta'` and
/// the NTT context from the mod-switched modulus carried on the
/// response polynomials, and rewrites the secret key into the
/// target-modulus space before decryption.
pub fn extract_inspiring_mod_switched(
    crs: &InspireCrs,
    state: &ClientState,
    response: &ServerResponse,
    entry_size: usize,
) -> Result<Vec<u8>> {
    use super::encode_db::reconstruct_entry;

    if !matches!(response.packing_mode, Some(PackingMode::Inspiring)) {
        return Err(pir_err!(
            "extract_inspiring_mod_switched expected packing_mode=Inspiring; got {:?}",
            response.packing_mode
        ));
    }

    let target_modulus = response.ciphertext.modulus();
    let p = crs.params.p;
    let delta_prime = target_modulus / p;
    if delta_prime == 0 {
        return Err(pir_err!(
            "post-switch delta = q'/p = 0 (q'={}, p={}); cannot decrypt",
            target_modulus,
            p
        ));
    }

    let target_ctx = NttContext::with_moduli(crs.params.ring_dim, &[target_modulus]);
    let switched_sk = mod_switch_secret_key(&state.rlwe_secret_key, target_modulus, crs.params.q)?;

    let num_columns = (entry_size * 8).div_ceil(16);
    let decrypted = response
        .ciphertext
        .decrypt(&switched_sk, delta_prime, p, &target_ctx);

    let mut column_values = Vec::with_capacity(num_columns);
    for col in 0..num_columns {
        column_values.push(decrypted.coeff(col));
    }

    Ok(reconstruct_entry(&column_values, entry_size))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::math::GaussianSampler;
    use crate::params::InspireParams;
    use crate::pir::query::query_seeded;
    use crate::pir::respond::respond_seeded_inspiring;
    use crate::pir::setup::setup;

    fn small_inspiring_params() -> InspireParams {
        InspireParams {
            ring_dim: 256,
            q: crate::math::mod_q::DEFAULT_Q,
            crt_moduli: vec![crate::math::mod_q::DEFAULT_Q],
            p: 65537,
            sigma: 6.4,
            gadget_base: 1 << 20,
            gadget_len: 3,
            security_level: crate::params::SecurityLevel::Bits128,
        }
    }

    fn production_params() -> InspireParams {
        InspireParams::secure_128_d2048()
    }

    #[test]
    fn mod_switch_noise_budget_accepts_identity_switch() {
        let params = small_inspiring_params();
        check_mod_switch_noise_budget(&params, params.q)
            .expect("identity switch must satisfy noise budget");
    }

    #[test]
    fn mod_switch_noise_budget_rejects_too_small_target() {
        let params = small_inspiring_params();
        let undersized = params.p * 4;
        let two_n = 2 * params.ring_dim as u64;
        let mut candidate = (undersized / two_n) * two_n + 1;
        if candidate < params.p {
            candidate += two_n;
        }
        let result = check_mod_switch_noise_budget(&params, candidate);
        assert!(
            result.is_err(),
            "tiny q' must trigger noise-budget rejection (candidate={candidate}): {result:?}"
        );
    }

    #[test]
    fn mod_switch_params_rejects_non_ntt_friendly_target() {
        let params = small_inspiring_params();
        let bad = params.q - 7;
        let result = ModSwitchParams::new(&params, bad);
        assert!(result.is_err(), "non NTT-friendly target must reject");
    }

    #[test]
    fn mod_switch_params_rejects_widening() {
        let params = small_inspiring_params();
        let too_big = params.q.saturating_add(2 * params.ring_dim as u64);
        let result = ModSwitchParams::new(&params, too_big);
        assert!(result.is_err(), "widening target must reject");
    }

    #[test]
    fn poly_mod_switch_identity_preserves_coefficients() {
        let dim = 16;
        let coeffs: Vec<u64> = (0..dim as u64).map(|i| i * 1_234_567).collect();
        let poly = Poly::from_coeffs(coeffs.clone(), crate::math::mod_q::DEFAULT_Q);
        let switched = mod_switch_poly(&poly, crate::math::mod_q::DEFAULT_Q).unwrap();
        for (i, expected) in coeffs.iter().enumerate() {
            assert_eq!(switched.coeff(i), expected % crate::math::mod_q::DEFAULT_Q);
        }
    }

    #[test]
    fn inspiring_mod_switch_identity_roundtrip_recovers_entry() {
        let params = small_inspiring_params();
        let mut sampler = GaussianSampler::new(params.sigma);

        let entry_size = 32;
        let num_entries = params.ring_dim;
        let database: Vec<u8> = (0..(num_entries * entry_size))
            .map(|i| (i % 256) as u8)
            .collect();

        let (crs, encoded_db, rlwe_sk) =
            setup(&params, &database, entry_size, &mut sampler).unwrap();

        let target_index = 7u64;
        let (state, query) = query_seeded(
            &crs,
            target_index,
            &encoded_db.config,
            &rlwe_sk,
            &mut sampler,
        )
        .unwrap();

        let response = respond_seeded_inspiring(&crs, &encoded_db, &query).unwrap();

        let switched = mod_switch_response_checked(&crs.params, &response, params.q).unwrap();

        let extracted =
            extract_inspiring_mod_switched(&crs, &state, &switched, entry_size).unwrap();

        let expected_start = (target_index as usize) * entry_size;
        let expected = &database[expected_start..expected_start + entry_size];
        assert_eq!(
            extracted.as_slice(),
            expected,
            "identity mod-switch must round-trip the entry byte-for-byte"
        );
    }

    #[test]
    fn encode_decode_packed_roundtrip_single_crt() {
        let dim = 16;
        let modulus = crate::math::mod_q::DEFAULT_Q;
        let coeffs_a: Vec<u64> = (0..dim as u64).map(|i| (i * 7) % modulus).collect();
        let coeffs_b: Vec<u64> = (0..dim as u64).map(|i| (i * 11 + 3) % modulus).collect();
        let a = Poly::from_coeffs(coeffs_a.clone(), modulus);
        let b = Poly::from_coeffs(coeffs_b.clone(), modulus);
        let ct = RlweCiphertext::from_parts(a, b);
        let response = ServerResponse {
            ciphertext: ct,
            column_ciphertexts: vec![],
            packing_mode: Some(PackingMode::Inspiring),
        };
        let encoded = encode_response_packed(&response).unwrap();
        let decoded = decode_response_packed(&encoded).unwrap();
        assert_eq!(decoded.packing_mode, Some(PackingMode::Inspiring));
        assert_eq!(decoded.ciphertext.modulus(), modulus);
        for i in 0..dim {
            assert_eq!(decoded.ciphertext.a.coeff(i), coeffs_a[i]);
            assert_eq!(decoded.ciphertext.b.coeff(i), coeffs_b[i]);
        }
    }

    #[test]
    fn encode_packed_rejects_multi_crt_response() {
        let dim = 16;
        let a = Poly::zero_moduli(dim, &crate::params::DEFAULT_Q_2CRT_30BIT);
        let b = Poly::zero_moduli(dim, &crate::params::DEFAULT_Q_2CRT_30BIT);
        let ct = RlweCiphertext::from_parts(a, b);
        let response = ServerResponse {
            ciphertext: ct,
            column_ciphertexts: vec![],
            packing_mode: None,
        };
        let result = encode_response_packed(&response);
        assert!(
            result.is_err(),
            "encode_response_packed must reject multi-CRT input"
        );
    }

    #[test]
    fn decode_packed_rejects_bad_magic() {
        let bytes = vec![0u8; 32];
        let result = decode_response_packed(&bytes);
        assert!(result.is_err(), "decoder must reject bad magic");
    }

    #[test]
    #[ignore = "production-cell mod-switch roundtrip is the bench's job; gated to keep unit-test wall time bounded"]
    fn production_45bit_mod_switch_roundtrip() {
        let params = production_params();
        let mut sampler = GaussianSampler::new(params.sigma);
        let entry_size = 32;
        let num_entries = params.ring_dim;
        let database: Vec<u8> = (0..(num_entries * entry_size))
            .map(|i| ((i * 37 + 11) % 256) as u8)
            .collect();

        let (crs, encoded_db, rlwe_sk) =
            setup(&params, &database, entry_size, &mut sampler).unwrap();

        let target_index = 17u64;
        let (state, query) = query_seeded(
            &crs,
            target_index,
            &encoded_db.config,
            &rlwe_sk,
            &mut sampler,
        )
        .unwrap();

        let response = respond_seeded_inspiring(&crs, &encoded_db, &query).unwrap();
        let switched =
            mod_switch_response_checked(&crs.params, &response, MOD_SWITCH_TARGET_45BIT).unwrap();
        let extracted =
            extract_inspiring_mod_switched(&crs, &state, &switched, entry_size).unwrap();

        let expected_start = (target_index as usize) * entry_size;
        let expected = &database[expected_start..expected_start + entry_size];
        assert_eq!(extracted.as_slice(), expected);
    }

    #[test]
    fn production_45bit_target_passes_noise_gate() {
        let params = production_params();
        check_mod_switch_noise_budget(&params, MOD_SWITCH_TARGET_45BIT)
            .expect("45-bit target must pass noise budget at production cell");
    }

    #[test]
    fn production_33bit_target_rejected_under_conservative_gate() {
        let params = production_params();
        let result = check_mod_switch_noise_budget(&params, MOD_SWITCH_TARGET_33BIT);
        assert!(
            result.is_err(),
            "33-bit target sits on the conservative-gate boundary; the gate MUST reject \
             it under the 7-sigma tail bound to preserve the M015 noise-budget floor. \
             Operators that want this target must opt out of the gate explicitly via \
             `mod_switch_response_unchecked` and accept the tighter noise margin: {result:?}"
        );
    }

    #[test]
    fn forged_undersized_target_triggers_noise_gate() {
        let params = production_params();
        let forged = 65537u64 * 2 * 4096 + 1;
        let real_forged =
            (forged / (2 * params.ring_dim as u64)) * (2 * params.ring_dim as u64) + 1;
        let result = check_mod_switch_noise_budget(&params, real_forged);
        assert!(
            result.is_err(),
            "forged tiny target ({real_forged}) MUST trigger noise-budget rejection: {result:?}"
        );
    }

    #[test]
    fn mod_switch_response_inner_preserves_packing_mode() {
        let params = small_inspiring_params();
        let zero_a = Poly::zero_default(params.ring_dim);
        let zero_b = Poly::zero_default(params.ring_dim);
        let ct = RlweCiphertext::from_parts(zero_a, zero_b);
        let response = ServerResponse {
            ciphertext: ct,
            column_ciphertexts: vec![],
            packing_mode: Some(PackingMode::Inspiring),
        };
        let out = mod_switch_response_inner(&response, params.q).unwrap();
        assert_eq!(out.packing_mode, Some(PackingMode::Inspiring));
    }
}
