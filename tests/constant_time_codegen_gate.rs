//! Correctness for `from_signed`, plus a disabled probe for the remaining
//! variable-latency divide.
//!
//! NO WORKING CONSTANT-TIME REGRESSION GATE EXISTS. Reverting the branch-free
//! sign fold to `if val >= 0` leaves this file green, because the compiler
//! emits `cmov` for both forms and the only conditional jump is a
//! divide-by-zero guard on the public modulus. Catching that regression needs a
//! dudect-style timing test, not codegen inspection.

#![allow(
    clippy::expect_used,
    reason = "test-target harness; an abort here is the failure report"
)]

use std::process::Command;

use raven_inspire::math::ModQ;

/// `from_signed` is inlined, so it has no symbol of its own. This shim pins its
/// body into one that objdump can find.
#[no_mangle]
#[inline(never)]
pub extern "C" fn raven_ct_probe_from_signed(val: i64, q: u64) -> u64 {
    std::hint::black_box(ModQ::from_signed(
        std::hint::black_box(val),
        std::hint::black_box(q),
    ))
}

fn probe_disassembly() -> Option<String> {
    if !cfg!(target_arch = "x86_64") {
        return None;
    }
    let exe = std::env::current_exe().ok()?;
    let out = Command::new("objdump")
        .args(["-d", "--demangle", exe.to_str()?])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let start = text.find("<raven_ct_probe_from_signed>:")?;
    let body = &text[start..];
    let end = body[1..].find("\n\n").map_or(body.len(), |i| i + 1);
    Some(body[..end].to_owned())
}

/// A hardware divide with a secret dividend is variable-latency on most
/// x86-64 parts, so `from_signed` must reduce without one.
#[test]
#[ignore = "reduce_by_public_modulus still divides on the secret magnitude; \
un-ignore when it uses Barrett or Shoup reduction"]
fn from_signed_emits_no_hardware_divide() {
    let body = probe_disassembly().expect("x86_64 plus objdump are required to gate this");
    let offenders: Vec<&str> = body
        .lines()
        .filter(|l| {
            let ops = l.split('\t').nth(2).unwrap_or("");
            ops.trim_start().starts_with("div") || ops.trim_start().starts_with("idiv")
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "from_signed must not divide on a secret magnitude; found:\n{}",
        offenders.join("\n")
    );
}

/// Correctness, so the branch-free form cannot drift from the arithmetic it
/// replaced. Covers both signs, zero, the modulus boundary, and saturation.
#[test]
fn from_signed_agrees_with_the_reference_reduction() {
    let q = 1_152_921_504_606_830_593u64;
    let cases = [
        0i64,
        1,
        -1,
        6,
        -6,
        i64::MAX,
        i64::MIN + 1,
        (q - 1) as i64,
        -((q - 1) as i64),
    ];
    for v in cases {
        // through the shim, so the symbol survives dead-code elimination
        let got = raven_ct_probe_from_signed(v, q);
        assert_eq!(got, ModQ::from_signed(v, q));
        let want = if v >= 0 {
            (v as u64) % q
        } else {
            let abs = v.unsigned_abs();
            let r = abs % q;
            if r == 0 {
                0
            } else {
                q - r
            }
        };
        assert_eq!(got, want, "from_signed({v}, {q})");
        assert!(got < q, "from_signed({v}) returned {got}, not reduced");
    }
}
