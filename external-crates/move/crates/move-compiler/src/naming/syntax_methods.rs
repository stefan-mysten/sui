// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    diag,
    editions::FeatureGate,
    expansion::ast::ModuleIdent,
    ice,
    naming::{
        ast::{
            self as N, SyntaxMethod, SyntaxMethodKind, SyntaxMethodKind_, SyntaxMethods, TypeName,
        },
        translate::Context,
    },
    parser::ast::FunctionName,
    shared::known_attributes::{AttributeKind_, KnownAttribute, SyntaxAttribute},
};
use move_ir_types::location::*;

#[derive(PartialEq, Eq, Ord, PartialOrd)]
enum SyntaxMethodPrekind_ {
    For,
    Index,
    Assign,
}

type SyntaxMethodPrekind = Spanned<SyntaxMethodPrekind_>;

//-------------------------------------------------------------------------------------------------
// Resolution and recording
//-------------------------------------------------------------------------------------------------

/// validate and record syntax methods
pub(super) fn resolve_syntax_attributes(
    context: &mut Context,
    syntax_methods: &mut SyntaxMethods,
    module_name: &ModuleIdent,
    function_name: &FunctionName,
    function: &N::Function,
) -> Option<()> {
    let attr = function.attributes.get_(&AttributeKind_::Syntax)?;
    let sp!(attr_loc, attr_value) = attr;

    let KnownAttribute::Syntax(SyntaxAttribute { kind }) = attr_value else {
        context.add_diag(ice!((
            *attr_loc,
            "Expected 'syntax' attributed based on kind"
        )));
        return None;
    };
    let Some(prekind) = attr_param_from_str(kind.loc, kind.value.as_str()) else {
        let msg = format!("Invalid syntax method identifier '{}'", kind);
        context.add_diag(diag!(Declarations::InvalidAttribute, (kind.loc, msg)));
        return None;
    };

    if !context.check_feature(
        context.current_package,
        FeatureGate::SyntaxMethods,
        *attr_loc,
    ) {
        return None;
    }

    let param_ty = get_first_type(context, attr_loc, &function.signature)?;
    let Some(type_name) = determine_subject_type_name(context, module_name, attr_loc, &param_ty)
    else {
        assert!(context.env.has_errors());
        return None;
    };

    // For loops may need to change this, but for now we disallow this.
    if let Some(macro_loc) = function.macro_ {
        let msg = "Syntax attributes may not appear on macro definitions";
        let fn_msg = "This function is a macro";
        context.add_diag(diag!(
            Declarations::InvalidSyntaxMethod,
            (*attr_loc, msg),
            (macro_loc, fn_msg)
        ));
        return None;
    }

    let method_entry = syntax_methods.entry(type_name).or_default();

    let Some(kind) = determine_valid_kind(context, prekind, &param_ty) else {
        assert!(context.env.has_errors());
        return None;
    };
    if !valid_return_type(
        context,
        &kind,
        param_ty.loc,
        &function.signature.return_type,
    ) {
        assert!(context.env.has_errors());
        return None;
    }

    let new_syntax_method = SyntaxMethod {
        loc: function_name.0.loc,
        visibility: function.visibility,
        kind,
        tname: type_name,
        target_function: (*module_name, *function_name),
    };
    let method_opt: &mut Option<Box<SyntaxMethod>> = method_entry.lookup_kind_entry(&kind);
    if let Some(previous) = method_opt {
        prev_syntax_defn_error(context, previous, kind, &type_name)
    } else {
        *method_opt = Some(Box::new(new_syntax_method));
    }
    Some(())
}

fn prev_syntax_defn_error(
    context: &mut Context,
    prev: &SyntaxMethod,
    sp!(sloc, method_kind): SyntaxMethodKind,
    sp!(_, type_name): &TypeName,
) {
    let kind_string = match method_kind {
        SyntaxMethodKind_::Index => format!("'{}'", SyntaxAttribute::INDEX),
        SyntaxMethodKind_::IndexMut => format!("mutable '{}'", SyntaxAttribute::INDEX),
    };
    let msg = format!(
        "Redefined {} 'syntax' method for '{}'",
        kind_string, type_name
    );
    let prev_msg = "This syntax method was previously defined here.";
    context.add_diag(diag!(
        Declarations::InvalidAttribute,
        (sloc, msg),
        (prev.loc, prev_msg)
    ));
}

//-------------------------------------------------------------------------------------------------
// Syntax method attribute and kind handling
//-------------------------------------------------------------------------------------------------

fn attr_param_from_str(loc: Loc, name_str: &str) -> Option<SyntaxMethodPrekind> {
    match name_str {
        SyntaxAttribute::FOR => Some(sp(loc, SyntaxMethodPrekind_::For)),
        SyntaxAttribute::INDEX => Some(sp(loc, SyntaxMethodPrekind_::Index)),
        SyntaxAttribute::ASSIGN => Some(sp(loc, SyntaxMethodPrekind_::Assign)),
        _ => None,
    }
}

fn determine_valid_kind(
    context: &mut Context,
    sp!(sloc, kind): SyntaxMethodPrekind,
    subject_type: &N::Type,
) -> Option<SyntaxMethodKind> {
    use SyntaxMethodKind_ as SK;
    let sk = match kind {
        SyntaxMethodPrekind_::Index => {
            if valid_imm_ref(subject_type) {
                SK::Index
            } else if valid_mut_ref(subject_type) {
                SK::IndexMut
            } else {
                let msg = format!(
                    "'{}' is only valid if the first parameter's type is a reference as '&' or '&mut'",
                    SyntaxAttribute::INDEX,
                );
                let ty_msg = "This type is not a reference";
                context.add_diag(diag!(
                    Declarations::InvalidAttribute,
                    (sloc, msg),
                    (subject_type.loc, ty_msg)
                ));
                return None;
            }
        }
        SyntaxMethodPrekind_::For => {
            let msg = "'for' syntax attributes are not currently supported";
            context.add_diag(diag!(Declarations::InvalidAttribute, (sloc, msg),));
            return None;
        }
        // SyntaxMethodPrekind_::For => match mut_opt {
        //     Some((loc, true)) => SK::ForMut,
        //     Some((loc, false)) => SK::ForImm,
        //     None => SK::ForVal,
        // },
        SyntaxMethodPrekind_::Assign => {
            let msg = "'assign' syntax attributes are not currently supported";
            context.add_diag(diag!(Declarations::InvalidAttribute, (sloc, msg),));
            return None;
        } // SyntaxMethodPrekind_::Assign => match mut_opt {
          //     Some((loc, true)) => SK::Assign,
          //     _ => {
          //         let msg = format!(
          //         "'{}' is only valid if the first parameter's type is a mutable reference as '&mut'",
          //         SyntaxAttribute::INDEX,
          //     );
          //         let ty_msg = "This type is not a reference";
          //         context.add_diag(diag!(
          //             Declarations::InvalidAttribute,
          //             (sloc, msg),
          //             (*ty_loc, msg)
          //         ));
          //         return None;
          //     }
          // },
    };
    Some(sp(sloc, sk))
}

//-------------------------------------------------------------------------------------------------
// Types
//-------------------------------------------------------------------------------------------------

const INVALID_MODULE_MSG: &str = "Invalid 'syntax' definition";
const INVALID_MODULE_TYPE_MSG: &str = "This type is defined in a different module";

fn determine_subject_type_name(
    context: &mut Context,
    cur_module: &ModuleIdent,
    ann_loc: &Loc,
    sp!(loc, ty_): &N::Type,
) -> Option<TypeName> {
    match ty_ {
        N::Type_::Apply(_, type_name, _) => {
            let defining_module = match &type_name.value {
                N::TypeName_::Multiple(_) => {
                    let msg = "Invalid type for syntax method definition";
                    let mut diag = diag!(Declarations::InvalidSyntaxMethod, (*loc, msg));
                    diag.add_note("Syntax methods may only be defined for single base types");
                    context.add_diag(diag);
                    return None;
                }
                N::TypeName_::Builtin(sp!(_, bt_)) => context.env.primitive_definer(*bt_),
                N::TypeName_::ModuleType(m, _) => Some(m),
            };
            if Some(cur_module) == defining_module {
                Some(*type_name)
            } else {
                context.add_diag(diag!(
                    Declarations::InvalidSyntaxMethod,
                    (*ann_loc, INVALID_MODULE_MSG),
                    (*loc, INVALID_MODULE_TYPE_MSG)
                ));
                None
            }
        }
        N::Type_::Ref(_, inner) => determine_subject_type_name(context, cur_module, ann_loc, inner),
        N::Type_::Param(param) => {
            let msg = format!(
                "Invalid {} annotation. Cannot associate a syntax method with a type parameter",
                SyntaxAttribute::SYNTAX
            );
            let tmsg = format!(
                "But '{}' was declared as a type parameter here",
                param.user_specified_name
            );
            context.add_diag(diag!(
                Declarations::InvalidSyntaxMethod,
                (*ann_loc, msg),
                (*loc, tmsg)
            ));
            None
        }
        N::Type_::Var(_) | N::Type_::Anything | N::Type_::UnresolvedError => {
            assert!(context.env.has_errors());
            None
        }
        N::Type_::Unit | N::Type_::Fun(_, _) | N::Type_::Void => {
            let msg = "Invalid type for syntax method definition";
            let mut diag = diag!(Declarations::InvalidSyntaxMethod, (*loc, msg));
            diag.add_note("Syntax methods may only be defined for single base types");
            context.add_diag(diag);
            None
        }
    }
}

fn valid_return_type(
    context: &mut Context,
    sp!(loc, kind_): &SyntaxMethodKind,
    subject_loc: Loc,
    ty: &N::Type,
) -> bool {
    match kind_ {
        SyntaxMethodKind_::Index => {
            if valid_imm_ref(ty) {
                valid_index_return_type(context, loc, ty)
            } else if valid_mut_ref(ty) {
                let msg = format!("Invalid {} annotation", SyntaxAttribute::SYNTAX);
                let tmsg = "This syntax method must return an immutable reference to match its subject type";
                context.add_diag(diag!(
                    Declarations::InvalidSyntaxMethod,
                    (*loc, msg),
                    (ty.loc, tmsg),
                    (subject_loc, "Immutable subject type defined here")
                ));
                false
            } else {
                let msg = format!(
                    "Invalid {} annotation. This syntax method must return an immutable reference",
                    SyntaxAttribute::SYNTAX
                );
                let tmsg = "This is not an immutable reference";
                context.add_diag(diag!(
                    Declarations::InvalidSyntaxMethod,
                    (*loc, msg),
                    (ty.loc, tmsg),
                    (subject_loc, "Immutable subject type defined here")
                ));
                false
            }
        }

        SyntaxMethodKind_::IndexMut => {
            if valid_mut_ref(ty) {
                valid_index_return_type(context, loc, ty)
            } else if valid_imm_ref(ty) {
                let msg = format!("Invalid {} annotation", SyntaxAttribute::SYNTAX);
                let tmsg =
                    "This syntax method must return a mutable reference to match its subject type";
                context.add_diag(diag!(
                    Declarations::InvalidSyntaxMethod,
                    (*loc, msg),
                    (ty.loc, tmsg),
                    (subject_loc, "Mutable subject type defined here")
                ));
                false
            } else {
                let msg = format!(
                    "Invalid {} annotation. This syntax method must return a mutable reference",
                    SyntaxAttribute::SYNTAX
                );
                let tmsg = "This is not a mutable reference";
                context.add_diag(diag!(
                    Declarations::InvalidSyntaxMethod,
                    (*loc, msg),
                    (ty.loc, tmsg),
                    (subject_loc, "Mutable subject type defined here")
                ));
                false
            }
        }
    }
}

fn valid_imm_ref(sp!(_, type_): &N::Type) -> bool {
    matches!(type_.is_ref(), Some(false))
}

fn valid_mut_ref(sp!(_, type_): &N::Type) -> bool {
    matches!(type_.is_ref(), Some(true))
}

fn valid_index_return_type(
    context: &mut Context,
    kind_loc: &Loc,
    sp!(tloc, type_): &N::Type,
) -> bool {
    match type_ {
        N::Type_::Apply(_, _, _) | N::Type_::Param(_) => true,
        N::Type_::Ref(_, inner) => valid_index_return_type(context, kind_loc, inner),
        N::Type_::Unit => {
            let msg = format!(
                "Invalid {} annotation. This syntax method cannot return a unit type",
                SyntaxAttribute::SYNTAX
            );
            let tmsg = "Unit type occurs as the return type for this function";
            context.add_diag(diag!(
                Declarations::InvalidSyntaxMethod,
                (*kind_loc, msg),
                (*tloc, tmsg)
            ));
            false
        }
        N::Type_::Fun(_, _) => {
            let msg = format!(
                "Invalid {} annotation. A syntax method cannot return a function",
                SyntaxAttribute::SYNTAX
            );
            let tmsg = "But a function type appears in this return type";
            context.add_diag(diag!(
                Declarations::InvalidSyntaxMethod,
                (*kind_loc, msg),
                (*tloc, tmsg)
            ));
            false
        }
        N::Type_::Var(_) | N::Type_::Anything | N::Type_::Void | N::Type_::UnresolvedError => {
            // Already an error state, so pass
            assert!(context.env.has_errors());
            false
        }
    }
}

fn get_first_type(
    context: &mut Context,
    attr_loc: &Loc,
    fn_signature: &N::FunctionSignature,
) -> Option<N::Type> {
    if let Some((_, _, ty)) = fn_signature.parameters.first() {
        Some(ty.clone())
    } else {
        let msg = format!(
            "Invalid attribute. {} is only valid if the function takes at least one parameter",
            SyntaxAttribute::SYNTAX
        );
        context.add_diag(diag!(Declarations::InvalidAttribute, (*attr_loc, msg)));
        None
    }
}
