use std::backtrace::Backtrace;

use ds_rom::rom::{Arm9, Autoload, raw::RawBuildInfoError};
use snafu::Snafu;
use unarm::{BlxTarget, Ins};

use super::functions::{Function, FunctionAnalysisError, FunctionParseOptions, ParseFunctionError};
use crate::{analysis::functions::IntoFunctionError, config::module::ModuleKind};

#[derive(Debug)]
pub struct CtorRange {
    pub start: u32,
    pub end: u32,
}

#[derive(Debug, Snafu)]
pub enum CtorRangeError {
    #[snafu(transparent)]
    RawBuildInfo { source: RawBuildInfoError },
    #[snafu(transparent)]
    FunctionAnalysis { source: FunctionAnalysisError },
    #[snafu(display("failed to analyze entrypoint function: {parse_result}\n{backtrace}"))]
    EntryAnalysisFailed { parse_result: ParseFunctionError, backtrace: Backtrace },
    #[snafu(display("no function calls in entrypoint:\n{backtrace}"))]
    NoEntryFunctionCalls { backtrace: Backtrace },
    #[snafu(display("failed to parse static initializer function: {parse_result}\n{backtrace}"))]
    InitFunctionAnalysisFailed { parse_result: ParseFunctionError, backtrace: Backtrace },
    #[snafu(display("no pool constants found in static initializer function:\n{backtrace}"))]
    NoInitPoolConstants { backtrace: Backtrace },
    #[snafu(display(
        ".ctor runner at {address:#010x} not in range of module '{module_kind}:\n{backtrace}'"
    ))]
    CtorRunnerNotInRange { address: u32, module_kind: ModuleKind, backtrace: Backtrace },
}

impl CtorRange {
    fn find_function_calls(function: &Function, module_code: &[u8], base_address: u32) -> Vec<u32> {
        let mut called_functions = vec![];
        for ins in function.parser(module_code, base_address) {
            match &ins {
                Ins::Bl { target, .. } | Ins::Blx { target: BlxTarget::Direct(target), .. } => {
                    called_functions.push(target.addr);
                }
                _ => {}
            }
        }
        called_functions
    }

    pub fn find_in_arm9(
        arm9: &Arm9,
        unknown_autoloads: &[&Autoload],
    ) -> Result<Self, CtorRangeError> {
        let code = arm9.code()?;

        let entry_addr = arm9.entry_function();
        let entry_code = &code[(entry_addr - arm9.base_address()) as usize..];
        let parse_result = Function::parse_function(FunctionParseOptions {
            name: "entry".to_string(),
            start_address: entry_addr,
            base_address: entry_addr,
            module_code: entry_code,
            known_end_address: None,
            module_start_address: arm9.base_address(),
            module_end_address: arm9.end_address()?,
            existing_functions: None,
            dsprot_encrypted_ranges: &[],
            check_defs_uses: false,
            parse_options: Default::default(),
        });
        let entry_func = match parse_result {
            Ok(function) => function,
            Err(FunctionAnalysisError::IntoFunction {
                source: IntoFunctionError::ParseFunction { source },
            }) => {
                return EntryAnalysisFailedSnafu { parse_result: source }.fail();
            }
            Err(e) => return Err(e.into()),
        };

        // The .ctor runner is normally the last function called by the entrypoint, but TWL-SDK entrypoints call other
        // functions after it. Try the calls from last to first until one reads a .ctor list in the ARM9 program.
        let called_functions = Self::find_function_calls(&entry_func, entry_code, entry_addr);
        if called_functions.is_empty() {
            return NoEntryFunctionCallsSnafu.fail();
        }
        let mut first_error = None;
        for &run_inits_addr in called_functions.iter().rev() {
            match Self::parse_ctor_runner(arm9, code, unknown_autoloads, run_inits_addr) {
                Ok(Some(ctor_range)) => return Ok(ctor_range),
                Ok(None) => {}
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        Err(first_error.unwrap_or_else(|| NoInitPoolConstantsSnafu.build()))
    }

    /// Parses a candidate .ctor runner. Returns `None` if its first pool constant is not a null-terminated list within the
    /// ARM9 program.
    fn parse_ctor_runner(
        arm9: &Arm9,
        code: &[u8],
        unknown_autoloads: &[&Autoload],
        run_inits_addr: u32,
    ) -> Result<Option<Self>, CtorRangeError> {
        let run_inits_offset = run_inits_addr.wrapping_sub(arm9.base_address()) as usize;
        let (run_inits_module_start, run_inits_module_end, run_inits_code) =
            if run_inits_offset < code.len() {
                (arm9.base_address(), arm9.end_address()?, &code[run_inits_offset..])
            } else {
                // .ctor is in one of the unknown autoloads
                let run_inits_autoload = unknown_autoloads.iter().find(|autoload| {
                    let run_inits_offset =
                        run_inits_addr.wrapping_sub(autoload.base_address()) as usize;
                    run_inits_offset < autoload.code().len()
                });
                let Some(run_inits_autoload) = run_inits_autoload else {
                    return CtorRunnerNotInRangeSnafu {
                        address: run_inits_addr,
                        module_kind: ModuleKind::Arm9,
                    }
                    .fail();
                };

                let base_address = run_inits_autoload.base_address();
                let run_inits_offset = (run_inits_addr - base_address) as usize;
                let code = &run_inits_autoload.code()[run_inits_offset..];
                (
                    base_address,
                    base_address
                        + run_inits_autoload.code().len() as u32
                        + run_inits_autoload.bss_size(),
                    code,
                )
            };
        let parse_result = Function::parse_function(FunctionParseOptions {
            name: "run_inits".to_string(),
            start_address: run_inits_addr,
            base_address: run_inits_addr,
            module_code: run_inits_code,
            known_end_address: None,
            module_start_address: run_inits_module_start,
            module_end_address: run_inits_module_end,
            existing_functions: None,
            dsprot_encrypted_ranges: &[],
            check_defs_uses: false,
            parse_options: Default::default(),
        });
        let run_inits_func = match parse_result {
            Ok(function) => function,
            Err(FunctionAnalysisError::IntoFunction {
                source: IntoFunctionError::ParseFunction { source },
            }) => {
                return InitFunctionAnalysisFailedSnafu { parse_result: source }.fail();
            }
            Err(e) => return Err(e.into()),
        };

        let (p_ctor_start, _) = run_inits_func
            .pool_constants()
            .first_key_value()
            .ok_or_else(|| NoInitPoolConstantsSnafu.build())?;
        let ctor_start_data = &run_inits_code[(p_ctor_start - run_inits_addr) as usize..];
        let ctor_start = u32::from_le_bytes([
            ctor_start_data[0],
            ctor_start_data[1],
            ctor_start_data[2],
            ctor_start_data[3],
        ]);

        let Some(ctor_offset) =
            ctor_start.checked_sub(arm9.base_address()).filter(|&o| (o as usize) < code.len())
        else {
            return Ok(None);
        };
        let Some(num_ctors) = code[ctor_offset as usize..]
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .position(|ctor| ctor == 0)
        else {
            return Ok(None);
        };

        let ctor_end = ctor_start + num_ctors as u32 * 4 + 4;

        Ok(Some(Self { start: ctor_start, end: ctor_end }))
    }
}
