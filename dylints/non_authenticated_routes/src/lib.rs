#![feature(rustc_private)]
#![feature(let_chains)]

extern crate rustc_arena;
extern crate rustc_ast;
extern crate rustc_ast_pretty;
extern crate rustc_attr;
extern crate rustc_data_structures;
extern crate rustc_errors;
extern crate rustc_hir;
extern crate rustc_hir_pretty;
extern crate rustc_index;
extern crate rustc_infer;
extern crate rustc_lexer;
extern crate rustc_middle;
extern crate rustc_mir_dataflow;
extern crate rustc_parse;
extern crate rustc_span;
extern crate rustc_target;
extern crate rustc_trait_selection;

use clippy_utils::diagnostics::span_lint;
use rustc_hir::{def_id::DefId, Item, ItemKind, QPath, TyKind};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::{symbol::Ident, Span, Symbol};

dylint_linting::impl_late_lint! {
    /// ### What it does
    ///
    /// ### Why is this bad?
    ///
    /// ### Known problems
    /// Remove if none.
    ///
    /// ### Example
    /// ```rust
    /// // example code where a warning is issued
    /// ```
    /// Use instead:
    /// ```rust
    /// // example code that does not raise a warning
    /// ```
    pub NON_AUTHENTICATED_ROUTES,
    Warn,
    "description goes here",
    NonAuthenticatedRoutes::default()
}

#[derive(Default)]
pub struct NonAuthenticatedRoutes {
    last_function_item: Option<(Ident, Span, bool)>,
}

// Collect all the attribute macros that are applied to the given span
fn attr_def_ids(mut span: rustc_span::Span) -> Vec<(DefId, Symbol, Option<DefId>)> {
    use rustc_span::hygiene::{walk_chain, ExpnKind, MacroKind};
    use rustc_span::{ExpnData, SyntaxContext};

    let mut def_ids = Vec::new();
    while span.ctxt() != SyntaxContext::root() {
        if let ExpnData {
            kind: ExpnKind::Macro(MacroKind::Attr, macro_symbol),
            macro_def_id: Some(def_id),
            parent_module,
            ..
        } = span.ctxt().outer_expn_data()
        {
            def_ids.push((def_id, macro_symbol, parent_module));
        }
        span = walk_chain(span, SyntaxContext::root());
    }
    def_ids
}

const ROCKET_MACRO_EXCEPTIONS: [(&str, &str); 1] = [("rocket::catch", "catch")];

const VALID_AUTH_HEADERS: [&str; 6] = [
    "auth::Headers",
    "auth::OrgHeaders",
    "auth::AdminHeaders",
    "auth::ManagerHeaders",
    "auth::ManagerHeadersLoose",
    "auth::OwnerHeaders",
];

impl<'tcx> LateLintPass<'tcx> for NonAuthenticatedRoutes {
    fn check_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx Item) {
        if let ItemKind::Fn(sig, ..) = item.kind {
            let mut has_auth_headers = false;

            for input in sig.decl.inputs {
                let TyKind::Path(QPath::Resolved(_, path)) = input.kind else {
                    continue;
                };

                for seg in path.segments {
                    if let Some(def_id) = seg.res.opt_def_id() {
                        let def = cx.tcx.def_path_str(def_id);
                        if VALID_AUTH_HEADERS.contains(&def.as_str()) {
                            has_auth_headers = true;
                        }
                    }
                }
            }

            self.last_function_item = Some((item.ident, sig.span, has_auth_headers));
            return;
        }

        let ItemKind::Struct(_data, _generics) = item.kind else {
            return;
        };

        let def_ids = attr_def_ids(item.span);

        let mut is_rocket_route = false;

        for (def_id, sym, parent) in &def_ids {
            let def_id = cx.tcx.def_path_str(*def_id);
            let sym = sym.as_str();
            let parent = parent.map(|parent| cx.tcx.def_path_str(parent));

            if ROCKET_MACRO_EXCEPTIONS.contains(&(&def_id, sym)) {
                is_rocket_route = false;
                break;
            }

            if def_id.starts_with("rocket::") || parent.as_deref() == Some("rocket_codegen") {
                is_rocket_route = true;
                break;
            }
        }

        if !is_rocket_route {
            return;
        }

        let Some((func_ident, func_span, has_auth_headers)) = self.last_function_item.take() else {
            span_lint(cx, NON_AUTHENTICATED_ROUTES, item.span, "No function found before the expanded route");
            return;
        };

        if func_ident != item.ident {
            span_lint(
                cx,
                NON_AUTHENTICATED_ROUTES,
                item.span,
                "The function before the expanded route does not match the route",
            );
            return;
        }

        if !has_auth_headers {
            span_lint(
                cx,
                NON_AUTHENTICATED_ROUTES,
                func_span,
                "This Rocket route does not have any authentication headers",
            );
        }
    }
}

#[test]
fn ui() {
    dylint_testing::ui_test(env!("CARGO_PKG_NAME"), "ui");
}
