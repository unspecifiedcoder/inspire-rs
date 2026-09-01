//! Structural check that `ModQ::from_signed` is built from the constant-time
//! primitives its doc comment claims, rather than branching on the secret.
//!
//! # Why a source check rather than a codegen or IR check
//!
//! `from_signed`'s two arms are cheap integer arithmetic, so LLVM if-converts
//! a `if val >= 0 { .. } else { .. }` form into a `select` — at the IR level,
//! before codegen runs. Both the branch-free construction and the branchy one
//! therefore compile to the same `cmov`-based machine code, and neither
//! disassembly nor LLVM-IR inspection can tell them apart. Reproduce with:
//!
//! ```text
//! rustc --edition 2021 -O --crate-type=lib --emit=llvm-ir <branchy form>
//! # the `if` lowers to `select i1 %_81, i64 %spec.select, i64 %r`
//! ```
//!
//! That is the compiler behaving correctly — machine code that branchlessly
//! selects is not a constant-time regression merely because the source spelled
//! it with an `if`. But it does mean the property "this function is built out
//! of the designated constant-time primitives" exists only in the source, so
//! the source is where it has to be checked.
//!
//! # What this test claims, and what it does not
//!
//! It claims exactly one thing: `from_signed` is *constructed* from
//! `ct_is_negative` and `conditional_select`, and contains no control flow.
//! That is a reviewable structural invariant, and it is what regresses when
//! someone "simplifies" this function back to an `if`.
//!
//! It does NOT claim the compiled code executes in constant time on any
//! particular CPU. No source-level test can establish that.
//!
//! # Why the AST and not the source text
//!
//! An earlier draft grepped the function body for `"if "`. That was wrong in
//! both directions: it fired on the word "if" appearing in an ordinary comment,
//! and it missed `match val < 0 { .. }` and `if(val >= 0)` entirely. Parsing
//! sidesteps both — comments are not in the AST, and every control-flow form is
//! a distinct node regardless of spelling.

#![allow(
    clippy::panic,
    clippy::expect_used,
    reason = "test harness; panic with a clear message is the failure report"
)]

use std::fs;
use std::path::Path;

use syn::visit::Visit;

/// Locates `fn from_signed` inside `impl ModQ` in `src/math/modular.rs`.
///
/// Matches on the item structure rather than a signature string, so adding an
/// attribute, renaming a parameter, or letting rustfmt wrap the signature does
/// not turn this into a spurious failure.
fn parse_from_signed() -> syn::ImplItemFn {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/math/modular.rs");
    let source =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    let file = syn::parse_file(&source)
        .unwrap_or_else(|e| panic!("parsing {} as Rust: {e}", path.display()));

    for item in &file.items {
        let syn::Item::Impl(item_impl) = item else {
            continue;
        };
        let syn::Type::Path(self_ty) = &*item_impl.self_ty else {
            continue;
        };
        if !self_ty.path.is_ident("ModQ") {
            continue;
        }
        for impl_item in &item_impl.items {
            if let syn::ImplItem::Fn(f) = impl_item {
                if f.sig.ident == "from_signed" {
                    return f.clone();
                }
            }
        }
    }
    panic!(
        "could not find `fn from_signed` in `impl ModQ` in {}; if it moved or was \
         renamed, update this test to follow it",
        path.display()
    )
}

/// Records every control-flow construct reached, so the failure message can
/// name what was found instead of just asserting a count.
#[derive(Default)]
struct ControlFlowFinder {
    found: Vec<&'static str>,
}

impl<'ast> Visit<'ast> for ControlFlowFinder {
    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        self.found.push("if");
        syn::visit::visit_expr_if(self, node);
    }
    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        self.found.push("match");
        syn::visit::visit_expr_match(self, node);
    }
    fn visit_expr_loop(&mut self, node: &'ast syn::ExprLoop) {
        self.found.push("loop");
        syn::visit::visit_expr_loop(self, node);
    }
    fn visit_expr_while(&mut self, node: &'ast syn::ExprWhile) {
        self.found.push("while");
        syn::visit::visit_expr_while(self, node);
    }
    fn visit_expr_for_loop(&mut self, node: &'ast syn::ExprForLoop) {
        self.found.push("for");
        syn::visit::visit_expr_for_loop(self, node);
    }
    fn visit_expr_try(&mut self, node: &'ast syn::ExprTry) {
        self.found.push("?");
        syn::visit::visit_expr_try(self, node);
    }
}

/// Collects the final path segment of every *called* function, so the test can
/// require the primitives be invoked rather than merely mentioned.
#[derive(Default)]
struct CallFinder {
    called: Vec<String>,
}

impl<'ast> Visit<'ast> for CallFinder {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(p) = &*node.func {
            if let Some(seg) = p.path.segments.last() {
                self.called.push(seg.ident.to_string());
            }
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        self.called.push(node.method.to_string());
        syn::visit::visit_expr_method_call(self, node);
    }
}

/// Name of the function called in tail position, if the body ends in a call.
fn tail_call_name(f: &syn::ImplItemFn) -> Option<String> {
    let syn::Stmt::Expr(expr, None) = f.block.stmts.last()? else {
        return None;
    };
    match expr {
        syn::Expr::Call(call) => match &*call.func {
            syn::Expr::Path(p) => Some(p.path.segments.last()?.ident.to_string()),
            _ => None,
        },
        syn::Expr::MethodCall(call) => Some(call.method.to_string()),
        _ => None,
    }
}

/// No control flow at all in `from_signed`.
///
/// Catches the exact historical regression (reverting the branch-free sign fold
/// to `if val >= 0`) and every equivalent spelling of it — `match val < 0`,
/// `if(val >= 0)`, or a loop. A helper this function *calls* may branch on
/// PUBLIC values (`reduce_by_public_modulus`'s divide-by-zero guard on `q`, for
/// instance); that is fine and lives outside this body.
#[test]
fn from_signed_contains_no_control_flow() {
    let f = parse_from_signed();
    let mut finder = ControlFlowFinder::default();
    finder.visit_block(&f.block);

    assert!(
        finder.found.is_empty(),
        "from_signed contains control flow ({}), but it must read `val`'s sign as \
         a mask and select its result without branching. If this is a deliberate \
         redesign, the constant-time argument for this function needs revisiting, \
         not this test relaxing.",
        finder.found.join(", ")
    );
}

/// The constant-time primitives must be *called*, not merely referenced.
///
/// Checking for a call rather than the identifier's presence is what stops a
/// dead `let _ = ct_is_negative(val);` from satisfying the invariant while the
/// real work happens in a branch.
#[test]
fn from_signed_calls_the_constant_time_primitives() {
    let f = parse_from_signed();
    let mut finder = CallFinder::default();
    finder.visit_block(&f.block);

    assert!(
        finder.called.iter().any(|c| c == "ct_is_negative"),
        "from_signed does not call ct_is_negative; the sign of the secret must be \
         read as a mask. Calls found: {:?}",
        finder.called
    );
    assert!(
        finder.called.iter().any(|c| c == "conditional_select"),
        "from_signed does not call conditional_select; the result must be chosen \
         by constant-time selection. Calls found: {:?}",
        finder.called
    );
}

/// The returned value must come *from* the constant-time select.
///
/// The two checks above are satisfiable by a body that calls both primitives and
/// then returns something else entirely. Pinning the tail expression is what
/// makes the selection load-bearing rather than decorative.
#[test]
fn from_signed_returns_the_result_of_a_constant_time_select() {
    let f = parse_from_signed();
    let tail = tail_call_name(&f);

    assert_eq!(
        tail.as_deref(),
        Some("conditional_select"),
        "from_signed must end in a conditional_select call so the returned value \
         is the selected one; found tail expression {tail:?}. A body that calls \
         the primitives and then returns some other expression would satisfy the \
         other two tests while still leaking."
    );
}
