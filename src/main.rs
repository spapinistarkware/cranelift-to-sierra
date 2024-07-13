#![allow(unused)]

use std::{
    collections::{HashMap, HashSet},
    fs,
};

use cairo_lang_sierra::{
    ids::{ConcreteLibfuncId, ConcreteTypeId, FunctionId, GenericLibfuncId, GenericTypeId, VarId},
    program::{
        ConcreteLibfuncLongId, ConcreteTypeLongId, DeclaredTypeInfo, GenBranchInfo,
        GenBranchTarget, GenFunction, GenInvocation, GenStatement, GenericArg, LibfuncDeclaration,
        Param, Program, StatementIdx, TypeDeclaration,
    },
};
use cranelift_codegen::ir::{self, condcodes::IntCC, Type, Value};
use cranelift_frontend::Variable;
// use cranelift::prelude::*;
// use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext};
use cranelift_reader::parse_functions;
use itertools::Itertools;
use num_bigint::BigInt;
// use isa::CallConv;

const SIZES: [u32; 5] = [8, 16, 32, 64, 128];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Label(u32);
struct SierraBuilder {
    const_libfuncs: HashSet<(usize, u128)>,
    cmp_funcs: HashSet<(usize, IntCC)>,
    binary_funcs: HashSet<(usize, ir::Opcode)>,
    program: Program,
    statements: Vec<GenStatement<Label>>,
    block_remapping: HashMap<Label, StatementIdx>,
    next_var: u32,
}
impl SierraBuilder {
    fn new() -> Self {
        // Initialize basic types.
        // type u128 = u128 [storable: true, drop: true, dup: true, zero_sized: false];

        let type_declarations = SIZES
            .iter()
            .map(|n| TypeDeclaration {
                id: ConcreteTypeId::from_string(format!("u{n}")),
                long_id: ConcreteTypeLongId {
                    generic_id: GenericTypeId::from_string(format!("u{n}")),
                    generic_args: vec![],
                },
                declared_type_info: Some(DeclaredTypeInfo {
                    storable: true,
                    droppable: true,
                    duplicatable: true,
                    zero_sized: false,
                }),
            })
            .collect();
        let mut libfunc_declarations = SIZES
            .iter()
            .map(|n| LibfuncDeclaration {
                id: ConcreteLibfuncId::from_string(format!("store_temp<{n}>")),
                long_id: ConcreteLibfuncLongId {
                    generic_id: cairo_lang_sierra::ids::GenericLibfuncId::from_string("store_temp"),
                    generic_args: vec![GenericArg::Type(ConcreteTypeId::from_string(format!(
                        "u{n}"
                    )))],
                },
            })
            .collect_vec();
        libfunc_declarations.push(LibfuncDeclaration {
            id: ConcreteLibfuncId::from_string("match_bool"),
            long_id: ConcreteLibfuncLongId {
                generic_id: GenericLibfuncId::from_string("match_enum"),
                generic_args: vec![GenericArg::Type(ConcreteTypeId::from_string("bool"))],
            },
        });

        Self {
            const_libfuncs: Default::default(),
            cmp_funcs: Default::default(),
            binary_funcs: Default::default(),
            program: Program {
                type_declarations,
                libfunc_declarations,
                statements: vec![],
                funcs: vec![],
            },
            statements: vec![],
            block_remapping: Default::default(),
            next_var: 0,
        }
    }
    fn const_libfunc(&mut self, n_bits: usize, val: u128) -> ConcreteLibfuncId {
        if !self.const_libfuncs.contains(&(n_bits, val)) {
            self.const_libfuncs.insert((n_bits, val));
            self.program.libfunc_declarations.push(LibfuncDeclaration {
                id: ConcreteLibfuncId::from_string(format!(
                    "const_as_immediate<u{},{}>",
                    n_bits, val
                )),
                long_id: ConcreteLibfuncLongId {
                    generic_id: GenericLibfuncId::from_string("const"),
                    generic_args: vec![
                        GenericArg::Type(ConcreteTypeId::from_string(format!("u{}", n_bits))),
                        GenericArg::Value(BigInt::from(val)),
                    ],
                },
            });
        }
        ConcreteLibfuncId::from_string(format!("const_as_immediate<u{},{}>", n_bits, val))
    }
    fn gen_type(&self, n_bits: usize) -> ConcreteTypeId {
        ConcreteTypeId::from_string(format!("u{}", n_bits))
    }
    fn add_simple_statement(
        &mut self,
        libfunc_id: ConcreteLibfuncId,
        args: &[Value],
        results: &[Value],
    ) {
        let args = args
            .iter()
            .map(|v| VarId::from_string(format!("v{}", v.as_u32())))
            .collect_vec();
        let results = results
            .iter()
            .map(|v| VarId::from_string(format!("v{}", v.as_u32())))
            .collect_vec();
        self.statements
            .push(simple_basic_statement(libfunc_id, &args, &results));
    }
    fn add_function(&mut self, func: GenFunction<StatementIdx>) {
        self.program.libfunc_declarations.push(LibfuncDeclaration {
            id: ConcreteLibfuncId::from_string(format!(
                "user_func@{}",
                func.id.clone().debug_name.unwrap()
            )),
            long_id: ConcreteLibfuncLongId {
                generic_id: GenericLibfuncId::from_string("function_call"),
                generic_args: vec![GenericArg::UserFunc(func.id.clone())],
            },
        });
        self.program.funcs.push(func);
    }
    fn build(mut self) -> Program {
        for s in self.statements {
            let s = match s {
                GenStatement::Invocation(inv) => GenStatement::Invocation(GenInvocation {
                    libfunc_id: inv.libfunc_id,
                    args: inv.args,
                    branches: inv
                        .branches
                        .into_iter()
                        .map(|b| GenBranchInfo {
                            target: match b.target {
                                GenBranchTarget::Fallthrough => GenBranchTarget::Fallthrough,
                                GenBranchTarget::Statement(l) => {
                                    GenBranchTarget::Statement(self.block_remapping[&l])
                                }
                            },
                            results: b.results,
                        })
                        .collect(),
                }),
                GenStatement::Return(vars) => GenStatement::Return(vars),
            };
            self.program.statements.push(s);
        }
        self.program
    }

    fn start_block(&mut self, block_lbl: Label) {
        self.block_remapping
            .insert(block_lbl, StatementIdx(self.statements.len()));
    }

    fn comparison_function_id(&mut self, n_bits: usize, cond: IntCC) -> ConcreteLibfuncId {
        // Assume runtime user function library.
        let name = format!("cmp_{}_{}", n_bits, cond);
        if !self.cmp_funcs.contains(&(n_bits, cond)) {
            self.cmp_funcs.insert((n_bits, cond));
            self.program.libfunc_declarations.push(LibfuncDeclaration {
                id: ConcreteLibfuncId::from_string(name.clone()),
                long_id: ConcreteLibfuncLongId {
                    generic_id: GenericLibfuncId::from_string("function_call"),
                    generic_args: vec![GenericArg::UserFunc(FunctionId::from_string(name.clone()))],
                },
            });
        }
        ConcreteLibfuncId::from_string(name)
    }

    fn binary_function_id(&mut self, n_bits: usize, opcode: ir::Opcode) -> ConcreteLibfuncId {
        let name = format!("bin_{}_{}", n_bits, opcode);
        if !self.binary_funcs.contains(&(n_bits, opcode)) {
            self.program.libfunc_declarations.push(LibfuncDeclaration {
                id: ConcreteLibfuncId::from_string(name.clone()),
                long_id: ConcreteLibfuncLongId {
                    generic_id: GenericLibfuncId::from_string("function_call"),
                    generic_args: vec![GenericArg::UserFunc(FunctionId::from_string(name.clone()))],
                },
            });
        }
        ConcreteLibfuncId::from_string(name)
    }

    fn store_temp(&mut self, n_bits: usize, v: Value) -> VarId {
        let res = VarId::from_string(format!("s{}", v.as_u32()));
        let args = [VarId::from_string(format!("v{}", v.as_u32()))];
        self.statements.push(simple_basic_statement(
            ConcreteLibfuncId::from_string(format!("store_temp<{n_bits}>")),
            &args,
            &[res.clone()],
        ));
        res
    }

    fn alloc_var(&mut self) -> VarId {
        let next_var = self.next_var;
        self.next_var += 1;
        VarId::from_string(format!("v{}", next_var))
    }
}

pub fn simple_basic_statement(
    libfunc_id: ConcreteLibfuncId,
    args: &[cairo_lang_sierra::ids::VarId],
    results: &[cairo_lang_sierra::ids::VarId],
) -> GenStatement<Label> {
    GenStatement::Invocation(GenInvocation {
        libfunc_id,
        args: args.into(),
        branches: vec![GenBranchInfo {
            target: GenBranchTarget::Fallthrough,
            results: results.into(),
        }],
    })
}

pub fn n_bits_of_type(ty: ir::types::Type) -> usize {
    if ty == ir::types::I8 {
        8
    } else if ty == ir::types::I16 {
        16
    } else if ty == ir::types::I32 {
        32
    } else if ty == ir::types::I64 {
        64
    } else if ty == ir::types::I128 {
        128
    } else {
        panic!("Unsupported type")
    }
}

#[allow(unused_variables)]
fn main() {
    // Read the CLIF IR from a file.
    // let path = "sample/target/x86_64-unknown-none/release/deps/sample-50f25e90c7988e68.clif/_ZN6sample3fib17h04a57acab04d56feE.opt.clif";
    let path = "example.clif";
    let source = fs::read_to_string(path).unwrap();
    let parsed = parse_functions(&source).unwrap();

    for func in &parsed {
        println!("CLIF function {}", func.name);
        println!("{}", func.display());
    }

    let mut builder = SierraBuilder::new();

    for func in &parsed {
        let n_bits_of = |v: Value| {
            let ty = func.dfg.value_type(v);
            n_bits_of_type(ty)
        };
        let ret_types = func
            .signature
            .returns
            .iter()
            .map(|p| builder.gen_type(n_bits_of_type(p.value_type)))
            .collect_vec();

        // Emit function.
        builder.add_function(GenFunction::new(
            FunctionId::from_string(func.name.to_string()),
            func.signature
                .params
                .iter()
                .map(|p| Param {
                    id: VarId::from_string(p.to_string()),
                    ty: builder.gen_type(n_bits_of_type(p.value_type)),
                })
                .collect(),
            ret_types,
            StatementIdx(builder.statements.len()),
        ));

        for block in func.layout.blocks() {
            builder.start_block(Label(block.as_u32()));
            for inst in func.layout.block_insts(block) {
                let inst_data = func.dfg.insts[inst];
                let results = func.dfg.inst_results(inst);
                match inst_data {
                    ir::InstructionData::AtomicCas {
                        opcode,
                        args,
                        flags,
                    } => {}
                    ir::InstructionData::AtomicRmw {
                        opcode,
                        args,
                        flags,
                        op,
                    } => {}
                    ir::InstructionData::Binary { opcode, args } => {
                        let n_bits = n_bits_of_type(func.dfg.value_type(args[0]));
                        let libfunc_id = builder.binary_function_id(n_bits, opcode);
                        builder.add_simple_statement(libfunc_id, &args[..], results)
                    }
                    ir::InstructionData::BinaryImm64 { opcode, arg, imm } => {}
                    ir::InstructionData::BinaryImm8 { opcode, arg, imm } => {}
                    ir::InstructionData::BranchTable { opcode, arg, table } => {}
                    ir::InstructionData::Brif {
                        opcode,
                        arg,
                        blocks,
                    } => {
                        let v0 = builder.alloc_var();
                        let v1 = builder.alloc_var();

                        builder
                            .statements
                            .push(GenStatement::Invocation(GenInvocation {
                                libfunc_id: ConcreteLibfuncId::from_string("match_bool"),
                                args: vec![VarId::from_string(format!("v{}", arg.as_u32()))],
                                branches: vec![
                                    GenBranchInfo {
                                        target: GenBranchTarget::Fallthrough,
                                        results: vec![v0],
                                    },
                                    GenBranchInfo {
                                        target: GenBranchTarget::Statement(Label(
                                            blocks[1].block(&func.dfg.value_lists).as_u32(),
                                        )),
                                        results: vec![v1],
                                    },
                                ],
                            }));
                    }
                    ir::InstructionData::Call {
                        opcode,
                        args,
                        func_ref,
                    } => {
                        let args = (0..args.len(&func.dfg.value_lists))
                            .map(|i| args.get(i, &func.dfg.value_lists).unwrap());
                        let args = args
                            .map(|v| builder.store_temp(n_bits_of(v), v))
                            .collect_vec();
                        let callee = parsed[func_ref.as_u32() as usize].name.to_string();
                        builder
                            .statements
                            .push(GenStatement::Invocation(GenInvocation {
                                libfunc_id: ConcreteLibfuncId::from_string(format!(
                                    "user_func@{callee}"
                                )),
                                args,
                                branches: vec![GenBranchInfo {
                                    target: GenBranchTarget::Fallthrough,
                                    results: results
                                        .iter()
                                        .map(|v| VarId::from_string(format!("v{}", v.as_u32())))
                                        .collect(),
                                }],
                            }));
                    }
                    ir::InstructionData::CallIndirect {
                        opcode,
                        args,
                        sig_ref,
                    } => {}
                    ir::InstructionData::CondTrap { opcode, arg, code } => {}
                    ir::InstructionData::DynamicStackLoad {
                        opcode,
                        dynamic_stack_slot,
                    } => {}
                    ir::InstructionData::DynamicStackStore {
                        opcode,
                        arg,
                        dynamic_stack_slot,
                    } => {}
                    ir::InstructionData::FloatCompare { opcode, args, cond } => {}
                    ir::InstructionData::FuncAddr { opcode, func_ref } => {}
                    ir::InstructionData::IntAddTrap { opcode, args, code } => {}
                    ir::InstructionData::IntCompare { opcode, args, cond } => {
                        let n_bits = n_bits_of_type(func.dfg.value_type(args[0]));
                        let libfunc_id = builder.comparison_function_id(n_bits, cond);
                        builder.add_simple_statement(libfunc_id, &args[..], results)
                    }
                    ir::InstructionData::IntCompareImm {
                        opcode,
                        arg,
                        cond,
                        imm,
                    } => {}
                    ir::InstructionData::Jump {
                        opcode,
                        destination,
                    } => {
                        // TODO: Fix destinations in a second pass.
                        // TODO: variable mappings.
                        let block = destination.block(&func.dfg.value_lists);

                        builder
                            .statements
                            .push(GenStatement::Invocation(GenInvocation {
                                libfunc_id: ConcreteLibfuncId::from_string("jump"),
                                args: vec![],
                                branches: vec![GenBranchInfo {
                                    target: GenBranchTarget::Statement(Label(block.as_u32())),
                                    results: vec![],
                                }],
                            }));
                    }
                    ir::InstructionData::Load {
                        opcode,
                        arg,
                        flags,
                        offset,
                    } => {}
                    ir::InstructionData::LoadNoOffset { opcode, arg, flags } => {}
                    ir::InstructionData::MultiAry { opcode, args } => {
                        assert_eq!(opcode, ir::Opcode::Return);
                        // TODO: Only push if necessary.
                        let args = (0..args.len(&func.dfg.value_lists))
                            .map(|i| args.get(i, &func.dfg.value_lists).unwrap());
                        let args = args
                            .map(|v| builder.store_temp(n_bits_of(v), v))
                            .collect_vec();
                        builder.statements.push(GenStatement::Return(args));
                    }
                    ir::InstructionData::NullAry { opcode } => {}
                    ir::InstructionData::Shuffle { opcode, args, imm } => {}
                    ir::InstructionData::StackLoad {
                        opcode,
                        stack_slot,
                        offset,
                    } => {}
                    ir::InstructionData::StackStore {
                        opcode,
                        arg,
                        stack_slot,
                        offset,
                    } => {}
                    ir::InstructionData::Store {
                        opcode,
                        args,
                        flags,
                        offset,
                    } => {}
                    ir::InstructionData::StoreNoOffset {
                        opcode,
                        args,
                        flags,
                    } => {}
                    ir::InstructionData::Ternary { opcode, args } => {}
                    ir::InstructionData::TernaryImm8 { opcode, args, imm } => {}
                    ir::InstructionData::Trap { opcode, code } => {}
                    ir::InstructionData::Unary { opcode, arg } => {}
                    ir::InstructionData::UnaryConst {
                        opcode,
                        constant_handle,
                    } => {}
                    ir::InstructionData::UnaryGlobalValue {
                        opcode,
                        global_value,
                    } => {}
                    ir::InstructionData::UnaryIeee32 { opcode, imm } => {}
                    ir::InstructionData::UnaryIeee64 { opcode, imm } => {}
                    ir::InstructionData::UnaryImm { opcode, imm } => {
                        let n_bits = n_bits_of_type(func.dfg.value_type(results[0]));
                        let libfunc_id = builder.const_libfunc(n_bits, imm.bits() as u128);
                        builder.add_simple_statement(libfunc_id, &[], results);
                    }
                };
                println!("{:?}", inst_data);
            }
        }
    }

    let program = builder.build();
    println!();
    println!("Program:");
    println!("{}", program);
}
