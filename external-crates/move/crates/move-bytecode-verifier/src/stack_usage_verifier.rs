// Copyright (c) The Diem Core Contributors
// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

//! This module implements a checker for verifying that basic blocks in the bytecode instruction
//! sequence of a function use the evaluation stack in a balanced manner. Every basic block,
//! except those that end in Ret (return to caller) opcode, must leave the stack height the
//! same as at the beginning of the block. A basic block that ends in Ret opcode must increase
//! the stack height by the number of values returned by the function as indicated in its
//! signature. Additionally, the stack height must not dip below that at the beginning of the
//! block for any basic block.
use crate::absint::{FunctionContext, VMControlFlowGraph};
use move_abstract_interpreter::control_flow_graph::ControlFlowGraph;
use move_binary_format::{
    CompiledModule,
    errors::{PartialVMError, PartialVMResult},
    file_format::{
        Bytecode, CodeOffset, CodeUnit, FunctionDefinitionIndex, Signature, StructFieldInformation,
    },
};
use move_bytecode_verifier_meter::Meter;
use move_core_types::vm_status::StatusCode;
use move_vm_config::verifier::VerifierConfig;

type BlockId = CodeOffset;

pub(crate) struct StackUsageVerifier<'a> {
    module: &'a CompiledModule,
    current_function: Option<FunctionDefinitionIndex>,
    code: &'a CodeUnit,
    return_: &'a Signature,
}

impl<'a> StackUsageVerifier<'a> {
    pub(crate) fn verify(
        config: &VerifierConfig,
        module: &'a CompiledModule,
        function_context: &'a FunctionContext,
        _meter: &mut (impl Meter + ?Sized), // TODO: metering
    ) -> PartialVMResult<()> {
        let verifier = Self {
            module,
            current_function: function_context.index(),
            code: function_context.code(),
            return_: function_context.return_(),
        };

        for block_id in function_context.cfg().blocks() {
            verifier.verify_block(config, block_id, function_context.cfg())?
        }
        Ok(())
    }

    fn verify_block(
        &self,
        config: &VerifierConfig,
        block_id: BlockId,
        cfg: &VMControlFlowGraph,
    ) -> PartialVMResult<()> {
        let code = &self.code.code;
        let mut stack_size_increment = 0;
        let block_start = cfg.block_start(block_id);
        let mut overall_push = 0;
        for i in block_start..=cfg.block_end(block_id) {
            let (num_pops, num_pushes) = self.instruction_effect(&code[i as usize])?;
            if let Some(new_pushes) = u64::checked_add(overall_push, num_pushes) {
                overall_push = new_pushes
            };

            // Check that the accumulated pushes does not exceed a pre-defined max size
            if let Some(max_push_size) = config.max_push_size {
                if overall_push > max_push_size as u64 {
                    return Err(PartialVMError::new(StatusCode::VALUE_STACK_PUSH_OVERFLOW)
                        .at_code_offset(self.current_function(), block_start));
                }
            }

            // Check that the stack height is sufficient to accommodate the number
            // of pops this instruction does
            if stack_size_increment < num_pops {
                return Err(
                    PartialVMError::new(StatusCode::NEGATIVE_STACK_SIZE_WITHIN_BLOCK)
                        .at_code_offset(self.current_function(), block_start),
                );
            }
            if let Some(new_incr) = u64::checked_sub(stack_size_increment, num_pops) {
                stack_size_increment = new_incr
            } else {
                return Err(
                    PartialVMError::new(StatusCode::NEGATIVE_STACK_SIZE_WITHIN_BLOCK)
                        .at_code_offset(self.current_function(), block_start),
                );
            };
            if let Some(new_incr) = u64::checked_add(stack_size_increment, num_pushes) {
                stack_size_increment = new_incr
            } else {
                return Err(
                    PartialVMError::new(StatusCode::POSITIVE_STACK_SIZE_AT_BLOCK_END)
                        .at_code_offset(self.current_function(), block_start),
                );
            };

            if stack_size_increment > config.max_value_stack_size as u64 {
                return Err(PartialVMError::new(StatusCode::VALUE_STACK_OVERFLOW)
                    .at_code_offset(self.current_function(), block_start));
            }
        }

        if stack_size_increment == 0 {
            Ok(())
        } else {
            Err(
                PartialVMError::new(StatusCode::POSITIVE_STACK_SIZE_AT_BLOCK_END)
                    .at_code_offset(self.current_function(), block_start),
            )
        }
    }

    /// The effect of an instruction is a tuple where the first element
    /// is the number of pops it does, and the second element is the number
    /// of pushes it does
    fn instruction_effect(&self, instruction: &Bytecode) -> PartialVMResult<(u64, u64)> {
        Ok(match instruction {
            // Instructions that pop, but don't push
            Bytecode::Pop
            | Bytecode::BrTrue(_)
            | Bytecode::BrFalse(_)
            | Bytecode::StLoc(_)
            | Bytecode::Abort
            | Bytecode::VariantSwitch(_) => (1, 0),

            // Instructions that push, but don't pop
            Bytecode::LdU8(_)
            | Bytecode::LdU16(_)
            | Bytecode::LdU32(_)
            | Bytecode::LdU64(_)
            | Bytecode::LdU128(_)
            | Bytecode::LdU256(_)
            | Bytecode::LdTrue
            | Bytecode::LdFalse
            | Bytecode::LdConst(_)
            | Bytecode::CopyLoc(_)
            | Bytecode::MoveLoc(_)
            | Bytecode::MutBorrowLoc(_)
            | Bytecode::ImmBorrowLoc(_) => (0, 1),

            // Instructions that pop and push once
            Bytecode::Not
            | Bytecode::FreezeRef
            | Bytecode::ReadRef
            | Bytecode::ExistsDeprecated(_)
            | Bytecode::ExistsGenericDeprecated(_)
            | Bytecode::MutBorrowGlobalDeprecated(_)
            | Bytecode::MutBorrowGlobalGenericDeprecated(_)
            | Bytecode::ImmBorrowGlobalDeprecated(_)
            | Bytecode::ImmBorrowGlobalGenericDeprecated(_)
            | Bytecode::MutBorrowField(_)
            | Bytecode::MutBorrowFieldGeneric(_)
            | Bytecode::ImmBorrowField(_)
            | Bytecode::ImmBorrowFieldGeneric(_)
            | Bytecode::MoveFromDeprecated(_)
            | Bytecode::MoveFromGenericDeprecated(_)
            | Bytecode::CastU8
            | Bytecode::CastU16
            | Bytecode::CastU32
            | Bytecode::CastU64
            | Bytecode::CastU128
            | Bytecode::CastU256
            | Bytecode::VecLen(_)
            | Bytecode::VecPopBack(_) => (1, 1),

            // Binary operations (pop twice and push once)
            Bytecode::Add
            | Bytecode::Sub
            | Bytecode::Mul
            | Bytecode::Mod
            | Bytecode::Div
            | Bytecode::BitOr
            | Bytecode::BitAnd
            | Bytecode::Xor
            | Bytecode::Shl
            | Bytecode::Shr
            | Bytecode::Or
            | Bytecode::And
            | Bytecode::Eq
            | Bytecode::Neq
            | Bytecode::Lt
            | Bytecode::Gt
            | Bytecode::Le
            | Bytecode::Ge => (2, 1),

            // Vector packing and unpacking
            Bytecode::VecPack(_, num) => (*num, 1),
            Bytecode::VecUnpack(_, num) => (1, *num),

            // Vector indexing operations (pop twice and push once)
            Bytecode::VecImmBorrow(_) | Bytecode::VecMutBorrow(_) => (2, 1),

            // MoveTo, WriteRef, and VecPushBack pop twice but do not push
            Bytecode::MoveToDeprecated(_)
            | Bytecode::MoveToGenericDeprecated(_)
            | Bytecode::WriteRef
            | Bytecode::VecPushBack(_) => (2, 0),

            // VecSwap pops three times but does not push
            Bytecode::VecSwap(_) => (3, 0),

            // Branch and Nop neither pops nor pushes
            Bytecode::Branch(_) | Bytecode::Nop => (0, 0),

            // Return performs `return_count` pops
            Bytecode::Ret => {
                let return_count = self.return_.len();
                (return_count as u64, 0)
            }

            // Call performs `arg_count` pops and `return_count` pushes
            Bytecode::Call(idx) => {
                let function_handle = self.module.function_handle_at(*idx);
                let arg_count = self.module.signature_at(function_handle.parameters).len() as u64;
                let return_count = self.module.signature_at(function_handle.return_).len() as u64;
                (arg_count, return_count)
            }
            Bytecode::CallGeneric(idx) => {
                let func_inst = self.module.function_instantiation_at(*idx);
                let function_handle = self.module.function_handle_at(func_inst.handle);
                let arg_count = self.module.signature_at(function_handle.parameters).len() as u64;
                let return_count = self.module.signature_at(function_handle.return_).len() as u64;
                (arg_count, return_count)
            }

            // Pack performs `num_fields` pops and one push
            Bytecode::Pack(idx) => {
                let struct_definition = self.module.struct_def_at(*idx);
                let field_count = match &struct_definition.field_information {
                    // 'Native' here is an error that will be caught by the bytecode verifier later
                    StructFieldInformation::Native => 0,
                    StructFieldInformation::Declared(fields) => fields.len(),
                };
                (field_count as u64, 1)
            }
            Bytecode::PackGeneric(idx) => {
                let struct_inst = self.module.struct_instantiation_at(*idx);
                let struct_definition = self.module.struct_def_at(struct_inst.def);
                let field_count = match &struct_definition.field_information {
                    // 'Native' here is an error that will be caught by the bytecode verifier later
                    StructFieldInformation::Native => 0,
                    StructFieldInformation::Declared(fields) => fields.len(),
                };
                (field_count as u64, 1)
            }

            // Unpack performs one pop and `num_fields` pushes
            Bytecode::Unpack(idx) => {
                let struct_definition = self.module.struct_def_at(*idx);
                let field_count = match &struct_definition.field_information {
                    // 'Native' here is an error that will be caught by the bytecode verifier later
                    StructFieldInformation::Native => 0,
                    StructFieldInformation::Declared(fields) => fields.len(),
                };
                (1, field_count as u64)
            }
            Bytecode::UnpackGeneric(idx) => {
                let struct_inst = self.module.struct_instantiation_at(*idx);
                let struct_definition = self.module.struct_def_at(struct_inst.def);
                let field_count = match &struct_definition.field_information {
                    // 'Native' here is an error that will be caught by the bytecode verifier later
                    StructFieldInformation::Native => 0,
                    StructFieldInformation::Declared(fields) => fields.len(),
                };
                (1, field_count as u64)
            }

            // Pack performs `num_fields` pops and one push
            Bytecode::PackVariant(vidx) => {
                let handle = self.module.variant_handle_at(*vidx);
                let variant_definition =
                    self.module.variant_def_at(handle.enum_def, handle.variant);
                let field_count = variant_definition.fields.len();
                (field_count as u64, 1)
            }
            Bytecode::PackVariantGeneric(vidx) => {
                let handle = self.module.variant_instantiation_handle_at(*vidx);
                let enum_def_instantiation = self.module.enum_instantiation_at(handle.enum_def);
                let variant_definition = self
                    .module
                    .variant_def_at(enum_def_instantiation.def, handle.variant);
                let field_count = variant_definition.fields.len();
                (field_count as u64, 1)
            }

            // Unpack performs one pop and `num_fields` pushes
            Bytecode::UnpackVariant(vidx)
            | Bytecode::UnpackVariantImmRef(vidx)
            | Bytecode::UnpackVariantMutRef(vidx) => {
                let handle = self.module.variant_handle_at(*vidx);
                let variant_definition =
                    self.module.variant_def_at(handle.enum_def, handle.variant);
                let field_count = variant_definition.fields.len();
                (1, field_count as u64)
            }
            Bytecode::UnpackVariantGeneric(vidx)
            | Bytecode::UnpackVariantGenericImmRef(vidx)
            | Bytecode::UnpackVariantGenericMutRef(vidx) => {
                let handle = self.module.variant_instantiation_handle_at(*vidx);
                let enum_def_instantiation = self.module.enum_instantiation_at(handle.enum_def);
                let variant_definition = self
                    .module
                    .variant_def_at(enum_def_instantiation.def, handle.variant);
                let field_count = variant_definition.fields.len();
                (1, field_count as u64)
            }
        })
    }

    fn current_function(&self) -> FunctionDefinitionIndex {
        self.current_function.unwrap_or(FunctionDefinitionIndex(0))
    }
}
