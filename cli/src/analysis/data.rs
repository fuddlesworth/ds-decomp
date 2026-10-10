use ds_decomp::{
    analysis::functions::{CalledFunction, Function},
    config::{
        module::{Module, ModuleKind},
        relocations::{Relocation, RelocationFromModulesError, RelocationModule},
        section::{SectionCodeError, SectionIndex, SectionKind},
        symbol::{
            InstructionMode, SymFunction, SymLabel, Symbol, SymbolKind, SymbolMapError, SymbolMaps,
        },
    },
};
use snafu::Snafu;
use unarm::Ins;

pub struct AnalyzeExternalReferencesOptions<'a> {
    pub modules: &'a [Module],
    pub module_index: usize,
    pub symbol_maps: &'a mut SymbolMaps,
    /// Adds symbols for calls into other modules that lead to no known function, see [`insert_external_call_target`].
    pub allow_unknown_function_calls: bool,
}

#[derive(Debug, Snafu)]
pub enum AnalyzeExternalReferencesError {
    #[snafu(display(
        "Failed to add relocation for local function call from {from:#010x} in {module_kind} to {to:#010x} as it leads to no function"
    ))]
    LocalFunctionNotFound { from: u32, to: u32, module_kind: ModuleKind },
    #[snafu(display(
        "Failed to add relocation for function call from {from:#010x} in {from_module} to {to:#010x} in {to_module} as it leads to a non-function symbol: {symbol}"
    ))]
    InvalidCallDestinationSymbol {
        from: u32,
        to: u32,
        from_module: ModuleKind,
        to_module: ModuleKind,
        symbol: Box<Symbol>,
    },
    #[snafu(transparent)]
    SymbolMap { source: SymbolMapError },
    #[snafu(transparent)]
    SectionCode { source: SectionCodeError },
    #[snafu(transparent)]
    RelocationFromModules { source: RelocationFromModulesError },
}

pub fn analyze_external_references(
    options: &mut AnalyzeExternalReferencesOptions,
) -> Result<RelocationResult, AnalyzeExternalReferencesError> {
    let mut result = RelocationResult::new();
    find_relocations_in_functions(&mut result, options)?;
    find_external_references_in_sections(options, &mut result)?;
    add_dsprot_external_relocations(options, &mut result)?;
    Ok(result)
}

fn add_dsprot_external_relocations(
    options: &mut AnalyzeExternalReferencesOptions,
    result: &mut RelocationResult,
) -> Result<(), AnalyzeExternalReferencesError> {
    let dsprot_relocations =
        options.modules[options.module_index].dsprot_external_relocations().to_vec();
    for relocation in dsprot_relocations {
        let candidates = find_symbol_candidates(options, relocation.to_address);
        if candidates.is_empty() {
            log::warn!(
                "DS Protect relocation from {:#010x} in {} to {:#010x} leads to no module",
                relocation.from_address,
                options.modules[options.module_index].kind(),
                relocation.to_address
            );
            continue;
        }
        let candidate_modules = candidates.iter().map(|c| &options.modules[c.module_index]);
        let module = RelocationModule::from_modules(candidate_modules)?;
        // The pool scan reads the encoded pointer as-is, so replace its relocation with the decoded one
        result.relocations.retain(|r| r.from_address() != relocation.from_address);
        result.relocations.push(Relocation::new_load(
            relocation.from_address,
            relocation.to_address,
            relocation.addend as i64,
            module,
        ));
        result.external_symbols.push(ExternalSymbol { candidates, address: relocation.to_address });
    }
    Ok(())
}

fn find_external_references_in_sections(
    options: &mut AnalyzeExternalReferencesOptions,
    result: &mut RelocationResult,
) -> Result<(), AnalyzeExternalReferencesError> {
    let o = options;
    for section in o.modules[o.module_index].sections().iter() {
        match section.kind() {
            SectionKind::Data | SectionKind::Rodata => {}
            SectionKind::Code | SectionKind::Bss => continue,
        }

        let code = section
            .code(o.modules[o.module_index].code(), o.modules[o.module_index].base_address())?
            .unwrap();
        let byte_arrays = o
            .symbol_maps
            .get(o.modules[o.module_index].kind())
            .map(|symbol_map| symbol_map.byte_array_ranges(section.address_range()))
            .unwrap_or_default();
        for word in section.iter_words(code, None) {
            if byte_arrays.iter().any(|byte_array| byte_array.contains(&word.address)) {
                continue;
            }
            find_external_data(o, word.address, word.value, result)?;
        }
    }
    Ok(())
}

fn find_relocations_in_functions(
    result: &mut RelocationResult,
    options: &mut AnalyzeExternalReferencesOptions,
) -> Result<(), AnalyzeExternalReferencesError> {
    for section in options.modules[options.module_index].sections().iter() {
        for function in section.functions().values() {
            add_function_calls_as_relocations(function, result, options)?;
            find_external_data_from_pools(options, function, result)?;
        }
    }
    Ok(())
}

fn iter_function_calls(function: &Function) -> impl Iterator<Item = (&u32, &CalledFunction)> {
    function
        .function_calls()
        .iter()
        // TODO: Condition code resets to AL for relocated call instructions
        .filter(|(_, called_function)| !called_function.ins.is_conditional())
}

fn add_function_calls_as_relocations(
    function: &Function,
    result: &mut RelocationResult,
    options: &mut AnalyzeExternalReferencesOptions,
) -> Result<(), AnalyzeExternalReferencesError> {
    let AnalyzeExternalReferencesOptions {
        modules,
        module_index,
        symbol_maps,
        allow_unknown_function_calls,
    } = options;

    for (&address, called_function) in iter_function_calls(function) {
        let local_module = &modules[*module_index];
        let is_local =
            local_module.sections().get_by_contained_address(called_function.address).is_some();

        let module: RelocationModule = if is_local {
            let module_kind = local_module.kind();
            let symbol_map = symbol_maps.get_mut(module_kind);
            let symbol = match symbol_map.by_address(called_function.address)? {
                Some((_, symbol)) => symbol,
                None => {
                    let error = LocalFunctionNotFoundSnafu {
                        from: address,
                        to: called_function.address,
                        module_kind,
                    }
                    .build();
                    log::error!("{error}");
                    return Err(error);
                }
            };
            match &symbol.kind {
                SymbolKind::Function(_) | SymbolKind::Label(SymLabel { external: true, .. }) => {}

                SymbolKind::Label(SymLabel { external: false, .. })
                | SymbolKind::Undefined
                | SymbolKind::PoolConstant
                | SymbolKind::JumpTable(_)
                | SymbolKind::Data(_)
                | SymbolKind::Bss(_) => {
                    return InvalidCallDestinationSymbolSnafu {
                        from: address,
                        to: called_function.address,
                        from_module: module_kind,
                        to_module: module_kind,
                        symbol: symbol.clone(),
                    }
                    .fail();
                }
            }

            module_kind.into()
        } else {
            let candidates = modules.iter().filter(|&module| {
                let symbol_map = symbol_maps.get(module.kind()).unwrap();
                let Some((_, symbol)) = symbol_map.by_address(called_function.address).unwrap()
                else {
                    return false;
                };

                let mode = match &symbol.kind {
                    SymbolKind::Function(SymFunction { mode, .. })
                    | SymbolKind::Label(SymLabel { external: true, mode }) => mode,

                    SymbolKind::Label(SymLabel { external: false, .. })
                    | SymbolKind::Undefined
                    | SymbolKind::PoolConstant
                    | SymbolKind::JumpTable(_)
                    | SymbolKind::Data(_)
                    | SymbolKind::Bss(_) => return false,
                };

                mode.into_thumb() == Some(called_function.thumb)
            });
            let module = RelocationModule::from_modules(candidates)?;
            if module == RelocationModule::None && *allow_unknown_function_calls {
                insert_external_call_target(
                    modules,
                    *module_index,
                    symbol_maps,
                    address,
                    called_function,
                )?
                .map_or(module, |target| target.kind().into())
            } else {
                module
            }
        };

        if module == RelocationModule::None {
            log::warn!(
                "No functions from {address:#010x} in {} to {:#010x}:",
                modules[*module_index].kind(),
                called_function.address
            );
        }

        if matches!(called_function.ins, Ins::B { .. }) {
            result.relocations.push(Relocation::new_branch(
                address,
                called_function.address,
                module,
            ));
        } else {
            result.relocations.push(Relocation::new_call(
                address,
                called_function.address,
                module,
                function.is_thumb(),
                called_function.thumb,
            ));
        }
    }
    Ok(())
}

/// Adds a symbol for a call into another module which leads to no known function: an external label if the destination
/// is inside a function, otherwise an unknown function. Returns the destination module, or `None` if no other module or
/// several overlays contain the destination.
fn insert_external_call_target<'a>(
    modules: &'a [Module],
    module_index: usize,
    symbol_maps: &mut SymbolMaps,
    from: u32,
    called_function: &CalledFunction,
) -> Result<Option<&'a Module>, AnalyzeExternalReferencesError> {
    let mut containing = modules.iter().enumerate().filter(|&(index, module)| {
        index != module_index
            && module.sections().get_by_contained_address(called_function.address).is_some()
    });
    let Some((_, target)) = containing.next() else { return Ok(None) };
    if containing.next().is_some() {
        return Ok(None);
    }

    let from_kind = modules[module_index].kind();
    let symbol_map = symbol_maps.get_mut(target.kind());
    let containing_function = symbol_map
        .get_function_containing(called_function.address)
        .map(|(_, symbol)| (symbol.name.clone(), symbol.addr));
    if let Some((name, addr)) = containing_function {
        log::warn!(
            "Function call from {from:#010x} in {from_kind} to {:#010x} goes to middle of function '{name}' at {addr:#010x} in {}, adding an external label symbol",
            called_function.address,
            target.kind()
        );
        symbol_map.add_external_label(called_function.address, called_function.thumb)?;
    } else if symbol_map.get_label(called_function.address)?.is_some() {
        symbol_map.add_external_label(called_function.address, called_function.thumb)?;
    } else {
        log::warn!(
            "Function call from {from:#010x} in {from_kind} to {:#010x} in {} leads to no function, inserting an unknown function symbol",
            called_function.address,
            target.kind()
        );
        let function_address = called_function.address | called_function.thumb as u32;
        let name = format!("{}{:08x}_unk", target.default_func_prefix, function_address);
        symbol_map.add_unknown_function(name, function_address, called_function.thumb);
    }
    Ok(Some(target))
}

fn find_external_data_from_pools(
    options: &mut AnalyzeExternalReferencesOptions,
    function: &Function,
    result: &mut RelocationResult,
) -> Result<(), AnalyzeExternalReferencesError> {
    for pool_constant in function.iter_pool_constants() {
        find_external_data(options, pool_constant.address, pool_constant.value, result)?;
    }
    Ok(())
}

fn find_external_data(
    options: &mut AnalyzeExternalReferencesOptions,
    address: u32,
    pointer: u32,
    result: &mut RelocationResult,
) -> Result<(), AnalyzeExternalReferencesError> {
    let o = options;

    let local_module = &o.modules[o.module_index];
    let is_local = local_module.sections().get_by_contained_address(pointer).is_some();
    if is_local {
        return Ok(());
    }

    let candidates = find_symbol_candidates(o, pointer);
    if candidates.is_empty() {
        // Probably not a pointer
        return Ok(());
    }

    let candidate_modules = candidates.iter().map(|c| &o.modules[c.module_index]);
    let module = RelocationModule::from_modules(candidate_modules)?;

    result.relocations.push(Relocation::new_load(address, pointer, 0, module));
    result.external_symbols.push(ExternalSymbol { candidates, address: pointer });
    Ok(())
}

fn find_symbol_candidates(
    options: &mut AnalyzeExternalReferencesOptions,
    pointer: u32,
) -> Vec<SymbolCandidate> {
    options
        .modules
        .iter()
        .enumerate()
        .filter_map(|(index, module)| {
            if index == options.module_index {
                return None;
            }
            let (section_index, section) = module.sections().get_by_contained_address(pointer)?;
            let symbol_map = options.symbol_maps.get(module.kind()).unwrap();
            // Only the start of an embedded binary is referred to, so a value inside one is no pointer
            let inside_byte_array = symbol_map
                .byte_array_ranges(section.address_range())
                .iter()
                .any(|byte_array| pointer > byte_array.start && byte_array.contains(&pointer));
            if inside_byte_array {
                return None;
            }
            // Functions can also end up outside code sections, such as unknown functions called from other modules
            let points_to_function = symbol_map.get_function(pointer).ok().flatten().is_some();
            if section.kind() == SectionKind::Code || points_to_function {
                let (_, symbol) = symbol_map.by_address(pointer & !1).unwrap()?;
                let symbol_is_thumb = match &symbol.kind {
                    SymbolKind::Function(function) => function.mode == InstructionMode::Thumb,
                    SymbolKind::Label(SymLabel { external: true, mode }) => {
                        *mode == InstructionMode::Thumb
                    }
                    SymbolKind::Label(SymLabel { external: false, .. })
                    | SymbolKind::Undefined
                    | SymbolKind::PoolConstant
                    | SymbolKind::JumpTable(_)
                    | SymbolKind::Data(_)
                    | SymbolKind::Bss(_) => return None,
                };

                let thumb = (pointer & 1) != 0;
                if symbol_is_thumb != thumb {
                    return None;
                }
            }
            if let Some((_, symbol)) = symbol_map.by_address(pointer).unwrap()
                && symbol.scope.is_local()
            {
                // Existing symbol is local, so it can't be referred to by a relocation
                None
            } else {
                Some(SymbolCandidate { module_index: index, section_index })
            }
        })
        .collect::<Vec<_>>()
}

pub struct RelocationResult {
    pub relocations: Vec<Relocation>,
    pub external_symbols: Vec<ExternalSymbol>,
}

impl RelocationResult {
    fn new() -> Self {
        Self { relocations: vec![], external_symbols: vec![] }
    }
}

pub struct ExternalSymbol {
    pub candidates: Vec<SymbolCandidate>,
    pub address: u32,
}

pub struct SymbolCandidate {
    pub module_index: usize,
    pub section_index: SectionIndex,
}
