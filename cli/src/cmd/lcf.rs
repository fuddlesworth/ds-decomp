use std::{
    collections::{HashMap, hash_map},
    fmt::Display,
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::Args;
use ds_decomp::config::{
    config::Config,
    delinks::{DelinkFile, Delinks},
    link_time_const::LinkTimeConst,
    module::ModuleKind,
    section::MigrateSection,
};
use ds_rom::rom::{Autoload, Rom, raw::AutoloadKind};
use serde::Serialize;
use strum::IntoEnumIterator as _;
use tinytemplate::TinyTemplate;

use crate::{
    analysis::overlay_groups::{OverlayGroupLocation, OverlayGroups},
    config::{
        delinks::{DelinksMap, DelinksMapOptions},
        link_names::LinkNames,
        section::SectionExt,
    },
    util::{
        io::{create_dir_all, create_file_and_dirs},
        path::PathExt,
    },
};

/// Generates linker scripts for all modules in a dsd config.
#[derive(Args)]
pub struct Lcf {
    /// Path to config.yaml.
    #[arg(long, short = 'c')]
    pub config_path: PathBuf,

    /// File of absolute symbols to define in the linker script, as NitroSDK's linker script template defines its
    /// stack sizes: one `NAME = VALUE` per line, with `#` comments.
    #[arg(long)]
    pub symbols: Option<PathBuf>,
}

static ARM9_LCF_TEMPLATE: &str = include_str!("../../../assets/arm9.lcf.template");

pub const ARM9_LCF_FILE_NAME: &str = "arm9.lcf";
pub const ARM9_OBJECTS_FILE_NAME: &str = "objects.txt";

#[derive(Serialize, Clone)]
struct LcfModule {
    name: String,
    origin: String,
    end_address: u32,
    output_file: String,
    link_section: String,
    object: String,
    sections: Vec<LcfSection>,
    in_tcm: bool,
    #[serde(skip)]
    kind: ModuleKind,
}

#[derive(Serialize, Clone)]
struct LcfSection {
    name: String,
    alignment: u32,
    end_alignment: u32,
    start_symbol: String,
    end_symbol: String,
    append_zero: bool,
    exceptix: bool,
    files: Vec<LcfFile>,
    #[serde(skip)]
    initialized: bool,
}

#[derive(Serialize, Clone)]
struct LcfFile {
    name: String,
    /// May be the original section name or a different source name if migrated
    section_name: String,
}

#[derive(Serialize)]
struct Arm9LcfContext {
    modules: Vec<LcfModule>,
    overlays: Vec<Arm9LcfOverlay>,
    variables: Vec<LcfVariable>,
    /// Symbols of the module parameters, defined after the modules from their sections' symbols
    module_params: Vec<LcfVariable>,
}

/// What the module parameters' symbols take from the ROM rather than from the link: the sizes of the autoload lists,
/// which the ROM build writes after each module's autoload blocks, and the place of the LTD module's autoload blocks.
struct ModuleParamsLayout {
    /// Size of the static module's autoload list
    autoload_list_size: u32,
    /// The LTD module's layout, if the ROM has one
    ltd: Option<LtdParamsLayout>,
}

struct LtdParamsLayout {
    /// Where the LTD module's autoload blocks start: the ARM9i program's base address plus the size of its static part,
    /// which isn't linked
    autoload_start: u32,
    /// Size of the LTD module's autoload list
    autoload_list_size: u32,
}

#[derive(Serialize)]
struct Arm9LcfOverlay {
    id_symbol: String,
    id: u16,
}

#[derive(Serialize)]
pub struct LcfVariable {
    symbol: String,
    value: String,
}

impl LcfVariable {
    fn new(symbol: impl Display, value: impl Display) -> Self {
        Self { symbol: symbol.to_string(), value: value.to_string() }
    }
}

impl Lcf {
    pub fn run(&self) -> Result<()> {
        let config = Config::from_file(&self.config_path)?;
        let config_dir = self.config_path.parent().unwrap();

        let delinks_map = DelinksMap::from_config(&config, config_dir, DelinksMapOptions {
            // We want migrated sections to be linked in the module it belongs to
            migrate_sections: true,
            generate_gap_files: true,
        })?;
        let link_names = LinkNames::new(&delinks_map);
        Self::validate_all_file_names(&delinks_map, &link_names)?;

        let rom = config.load_rom(config_dir)?;

        let build_path = config_dir.join(&config.build_path).clean();

        let link_modules = LinkModules::new(&rom, &config, &delinks_map, &link_names)?;

        let mut tt = TinyTemplate::new();
        tt.add_template("arm9", ARM9_LCF_TEMPLATE)?;

        let mut variables = Self::generate_lcf_variables(&config);
        if let Some(symbols) = &self.symbols {
            variables.extend(Self::read_symbols(symbols)?);
        }
        let module_params =
            Self::module_param_variables(&link_modules.modules, &ModuleParamsLayout::new(&rom)?);
        let arm9_context = Arm9LcfContext {
            modules: link_modules.modules,
            overlays: config
                .overlays
                .iter()
                .map(|overlay| Arm9LcfOverlay {
                    id_symbol: Self::overlay_id_symbol_name(overlay.id),
                    id: overlay.id,
                })
                .collect(),
            variables,
            module_params,
        };
        Self::write_arm9_lcf(&arm9_context, &tt, &build_path)?;
        self.write_arm9_objects(&config, &build_path, &delinks_map, &link_names)?;

        // mwldarm doesn't create the build directory for the modules
        create_dir_all(build_path.join("build"))?;

        Ok(())
    }

    fn generate_lcf_variables(config: &Config) -> Vec<LcfVariable> {
        let overlay_count = config.overlays.len();
        LinkTimeConst::iter()
            .filter_map(|var| {
                let value = match var {
                    LinkTimeConst::DtcmLo => "ADDR(DTCM)".to_string(),
                    LinkTimeConst::ItcmHi => "ADDR(ITCM) + SIZEOF(ITCM)".to_string(),
                    LinkTimeConst::CodeHi => "ADDR(SPACE)".to_string(),
                    LinkTimeConst::OverlayCount => overlay_count.to_string(),
                    LinkTimeConst::Arm9CtorStart => return None, // ARM9_CTOR_START already exists
                    LinkTimeConst::ExceptionTableStart => return None, // __exception_table_start__
                    LinkTimeConst::ExceptionTableEnd => return None, // __exception_table_end__
                    // Defined after the modules, see module_param_variables
                    LinkTimeConst::SdkAutoloadList
                    | LinkTimeConst::SdkAutoloadListEnd
                    | LinkTimeConst::SdkAutoloadStart
                    | LinkTimeConst::SdkStaticBssStart
                    | LinkTimeConst::SdkStaticBssEnd
                    | LinkTimeConst::SdkLtdautoloadList
                    | LinkTimeConst::SdkLtdautoloadListEnd
                    | LinkTimeConst::SdkLtdautoloadStart => return None,
                };
                Some(LcfVariable::new(var.to_string(), value))
            })
            .collect()
    }

    /// The symbols of the module parameters that NitroSDK's crt0 keeps for the ROM's startup (`_start_ModuleParams`,
    /// and TwlSDK's `_start_LtdModuleParams`), placed as NitroSDK's linker script template places them: the static
    /// module's autoload blocks start at the end of its initialized data, its autoload list follows the blocks, and the
    /// LTD module's list follows its own blocks. The modules' sizes come from their sections' symbols, so the
    /// symbols follow the code, and the lists' sizes and the start of the LTD module's blocks come from the ROM. The ROM
    /// build writes the same values again when it puts the modules together, and the compressed ends too.
    fn module_param_variables(
        modules: &[LcfModule],
        layout: &ModuleParamsLayout,
    ) -> Vec<LcfVariable> {
        let mut variables = vec![];
        let Some(arm9) = modules.iter().find(|module| module.kind == ModuleKind::Arm9) else {
            return variables;
        };
        let autoload_start = arm9.initialized_end().unwrap_or_else(|| arm9.origin.clone());
        let (bss_start, bss_end) =
            arm9.bss_bounds().unwrap_or_else(|| (autoload_start.clone(), autoload_start.clone()));
        variables.push(LcfVariable::new(LinkTimeConst::SdkAutoloadStart, &autoload_start));
        variables.push(LcfVariable::new(LinkTimeConst::SdkStaticBssStart, bss_start));
        variables.push(LcfVariable::new(LinkTimeConst::SdkStaticBssEnd, bss_end));

        let is_ltd =
            |module: &&LcfModule| matches!(module.kind, ModuleKind::Autoload(AutoloadKind::Ltd(_)));
        let blocks_end = |start: String, ltd: bool| {
            modules
                .iter()
                .filter(|module| matches!(module.kind, ModuleKind::Autoload(_)))
                .filter(|module| is_ltd(module) == ltd)
                .filter_map(LcfModule::initialized_size)
                .fold(start, |end, size| format!("{end} + {size}"))
        };
        let list = LinkTimeConst::SdkAutoloadList;
        variables.push(LcfVariable::new(
            list,
            blocks_end(LinkTimeConst::SdkAutoloadStart.to_string(), false),
        ));
        variables.push(LcfVariable::new(
            LinkTimeConst::SdkAutoloadListEnd,
            format!("{list} + {:#x}", layout.autoload_list_size),
        ));

        if let Some(ltd) = &layout.ltd {
            let list = LinkTimeConst::SdkLtdautoloadList;
            variables.push(LcfVariable::new(
                LinkTimeConst::SdkLtdautoloadStart,
                format!("{:#010x}", ltd.autoload_start),
            ));
            variables.push(LcfVariable::new(
                list,
                blocks_end(LinkTimeConst::SdkLtdautoloadStart.to_string(), true),
            ));
            variables.push(LcfVariable::new(
                LinkTimeConst::SdkLtdautoloadListEnd,
                format!("{list} + {:#x}", ltd.autoload_list_size),
            ));
        }
        variables
    }

    fn read_symbols(path: &Path) -> Result<Vec<LcfVariable>> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read symbols from {}", path.display()))?;
        let mut symbols = vec![];
        for (number, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap().trim();
            if line.is_empty() {
                continue;
            }
            let Some((symbol, value)) = line.split_once('=') else {
                bail!("{}:{}: expected NAME = VALUE", path.display(), number + 1);
            };
            let (symbol, value) = (symbol.trim(), value.trim());
            if symbol.is_empty() || value.is_empty() || symbol.contains(char::is_whitespace) {
                bail!("{}:{}: expected NAME = VALUE", path.display(), number + 1);
            }
            symbols.push(LcfVariable::new(symbol, value));
        }
        Ok(symbols)
    }

    fn write_arm9_lcf(context: &Arm9LcfContext, tt: &TinyTemplate, lcf_path: &Path) -> Result<()> {
        let lcf_file_path = lcf_path.join("arm9.lcf");
        let lcf_string = tt.render("arm9", &context)?;

        let file = create_file_and_dirs(lcf_file_path)?;
        let mut writer = BufWriter::new(file);
        writer.write_all(lcf_string.as_bytes())?;

        Ok(())
    }

    fn write_arm9_objects(
        &self,
        config: &Config,
        lcf_path: &Path,
        delinks_map: &DelinksMap,
        link_names: &LinkNames,
    ) -> Result<()> {
        let config_dir = self.config_path.parent().unwrap();
        let objects_file_path = lcf_path.join(ARM9_OBJECTS_FILE_NAME);
        let mut writer = BufWriter::new(create_file_and_dirs(objects_file_path)?);

        let build_path = config_dir.join(&config.build_path);
        let delinks_path = config_dir.join(&config.delinks_path);
        for line in Self::arm9_object_lines(&build_path, &delinks_path, delinks_map, link_names) {
            writeln!(writer, "{line}")?;
        }
        Ok(())
    }

    /// The lines of the ARM9 program's object list: complete files' objects from `build_path`, the others' from
    /// `delinks_path`, and the copies of objects of a shared file name from `build_path` (see [`LinkNames`]).
    fn arm9_object_lines(
        build_path: &Path,
        delinks_path: &Path,
        delinks_map: &DelinksMap,
        link_names: &LinkNames,
    ) -> Vec<String> {
        let mut lines = vec![];

        // Each overlay's objects follow an -overlaygroup and -overlay option of their own, as the SDK's response
        // file has them. mwldarm then gives every call out of range in an overlay its own long-branch veneer,
        // placed after the calling function, instead of sharing one per target. A file listed after these options
        // belongs to the last overlay, so the other modules' files come first.
        let (overlays, others): (Vec<&Delinks>, Vec<&Delinks>) = delinks_map
            .iter()
            .partition(|delinks| matches!(delinks.module_kind(), ModuleKind::Overlay(_)));
        for delinks in others.into_iter().chain(overlays) {
            if let ModuleKind::Overlay(id) = delinks.module_kind() {
                let name = format!("OV{id:03}");
                lines.push(format!("-overlaygroup {name},0"));
                lines.push(format!("-overlay {name}"));
            }
            for file in &delinks.files {
                if Self::links_in_ltd(file, delinks.module_kind()) {
                    // Listed by its migrated part, in the LTD autoload's files
                    continue;
                }
                let object = link_names.link_object(file, build_path, delinks_path);
                lines.push(format!("\"{}\"", object.display()));
            }
        }
        lines
    }

    /// Whether a file of `module_kind` has sections migrated to the DSi LTD autoload. TwlSDK's response file lists such
    /// an object once, where its LTD part belongs: mwldarm makes the long-branch veneers of the LTD code object by
    /// object, in the list's order, so listing it in its own module's place changes the LTD autoload.
    fn links_in_ltd(file: &DelinkFile, module_kind: ModuleKind) -> bool {
        file.migrated_sections.iter().any(|section| {
            matches!(MigrateSection::parse(section.name(), module_kind), Ok(Some(migration)) if migration.is_ltd())
        })
    }

    pub fn overlay_id_symbol_name(id: u16) -> String {
        format!("OVERLAY_{id}_ID")
    }

    pub fn module_lcf_file_name(kind: ModuleKind) -> String {
        match kind {
            ModuleKind::Arm9 => "main.lcf".to_string(),
            ModuleKind::Autoload(autoload) => match autoload {
                AutoloadKind::Itcm => "itcm.lcf".to_string(),
                AutoloadKind::Dtcm => "dtcm.lcf".to_string(),
                AutoloadKind::Unknown(autoload_index) => {
                    format!("autoload_{autoload_index:03}.lcf")
                }
                AutoloadKind::Ltd(autoload_index) => {
                    format!("ltd_autoload_{autoload_index:03}.lcf")
                }
            },
            ModuleKind::Overlay(overlay_id) => format!("overlay_{overlay_id:03}.lcf"),
        }
    }

    /// Checks that the linker can tell the objects apart. Files of one name in different modules are linked under names
    /// of their paths (see [`LinkNames`]), but a module may not have two files of one name, and no two files may have
    /// one object name in the link, as a file listed in two modules or a path name that another file has would.
    fn validate_all_file_names(delinks_map: &DelinksMap, link_names: &LinkNames) -> Result<()> {
        let mut object_names: HashMap<String, (String, ModuleKind)> = HashMap::new();
        let mut success = true;
        for delinks in delinks_map.iter() {
            success &= Self::validate_file_names(delinks, link_names, &mut object_names);
        }
        if !success {
            bail!("Duplicate file names found, see logs above");
        }
        Ok(())
    }

    fn validate_file_names(
        delinks: &Delinks,
        link_names: &LinkNames,
        object_names: &mut HashMap<String, (String, ModuleKind)>,
    ) -> bool {
        let module_kind = delinks.module_kind();
        let mut success = true;
        let mut module_names: HashMap<String, String> = HashMap::new();
        for file in &delinks.files {
            if file.migrated() {
                // Migrated files will have the same name as the original, that is intentional
                continue;
            }
            let name = file.unique_name();
            let (path, _) = file.split_file_ext();
            let base_name = path.rsplit_once(['/', '\\']).map_or(path.as_str(), |(_, base)| base);
            let object_file_name = format!("{base_name}.o");
            if let Some(other) = module_names.insert(object_file_name.clone(), name.clone()) {
                log::error!(
                    "Delink file name '{object_file_name}' of {name} already used by {other} in {module_kind}"
                );
                success = false;
                continue;
            }
            match object_names.entry(link_names.object_name(file)) {
                hash_map::Entry::Occupied(occupied_entry) => {
                    let (other, other_kind) = occupied_entry.get();
                    log::error!(
                        "Object name '{}' of {name} in {module_kind} already used by {other} in {other_kind}",
                        occupied_entry.key()
                    );
                    success = false;
                }
                hash_map::Entry::Vacant(vacant_entry) => {
                    vacant_entry.insert((name, module_kind));
                }
            }
        }
        success
    }
}

impl LcfModule {
    fn new(
        kind: ModuleKind,
        origin: String,
        config: &Config,
        delinks_map: &DelinksMap,
        link_names: &LinkNames,
    ) -> Result<Self> {
        let module_config = match kind {
            ModuleKind::Arm9 => &config.main_module,
            ModuleKind::Autoload(autoload) => {
                &config.autoloads.iter().find(|a| a.kind == autoload).unwrap().module
            }
            ModuleKind::Overlay(overlay_id) => {
                &config.overlays.iter().find(|o| o.id == overlay_id).unwrap().module
            }
        };

        let output_file =
            format!("build/{}", module_config.object.file_name().unwrap().to_string_lossy());
        let module_name = match kind {
            ModuleKind::Arm9 => "ARM9".to_string(),
            ModuleKind::Autoload(autoload) => match autoload {
                AutoloadKind::Itcm => "ITCM".to_string(),
                AutoloadKind::Dtcm => "DTCM".to_string(),
                AutoloadKind::Unknown(autoload_index) => format!("AUTOLOAD_{autoload_index}"),
                AutoloadKind::Ltd(autoload_index) => format!("LTD_AUTOLOAD_{autoload_index}"),
            },
            ModuleKind::Overlay(overlay_id) => format!("OV{overlay_id:03}"),
        };
        let link_section = format!(".{}", module_name.to_lowercase());

        let object = format!("{}.o", module_config.name);

        let delinks = delinks_map.get(kind).context("Failed to find delinks")?;

        let sections = delinks
            .sections
            .sorted_by_address()
            .iter()
            .map(|section| {
                let name = section.name().to_string();
                let alignment = section.alignment();
                let append_zero = section.name() == ".ctor";
                let exceptix = section.name() == ".exceptix";
                let end_address = section.end_address() + if append_zero { 4 } else { 0 };
                let end_alignment = if end_address % 32 == 0 { 32 } else { 4 };
                let (start_symbol, end_symbol) = if exceptix {
                    ("__exception_table_start__".to_string(), "__exception_table_end__".to_string())
                } else {
                    let boundary_name = section.boundary_name();
                    (
                        format!("{module_name}_{boundary_name}_START"),
                        format!("{module_name}_{boundary_name}_END"),
                    )
                };
                let files = if exceptix {
                    Vec::new()
                } else {
                    delinks
                        .files
                        .iter()
                        .filter_map(|file| {
                            file.sections
                                .by_name(&name)
                                .map(|(_, section)| (file, section.source_name().to_string()))
                        })
                        .map(|(file, section_name)| LcfFile {
                            name: link_names.object_name(file),
                            section_name,
                        })
                        .collect::<Vec<_>>()
                };
                LcfSection {
                    name,
                    alignment,
                    end_alignment,
                    start_symbol,
                    end_symbol,
                    append_zero,
                    exceptix,
                    files,
                    initialized: section.kind().is_initialized(),
                }
            })
            .collect::<Vec<_>>();

        let end_address = delinks.sections.end_address().unwrap();

        let in_tcm = matches!(kind, ModuleKind::Autoload(AutoloadKind::Itcm | AutoloadKind::Dtcm));

        Ok(Self {
            name: module_name,
            origin,
            end_address,
            output_file,
            link_section,
            object,
            sections,
            in_tcm,
            kind,
        })
    }

    /// The size of the module's initialized data in the ROM, as an expression of its sections' symbols: from the start
    /// of its first initialized section to the end of its last, rounded up to the alignment of its .text section, as
    /// `rom config` gives an autoload's code size. `None` if the module has no initialized section.
    fn initialized_size(&self) -> Option<String> {
        let mut initialized = self.sections.iter().filter(|section| section.initialized);
        let first = initialized.next()?;
        let last = initialized.next_back().unwrap_or(first);
        let size = format!("{} - {}", last.end_symbol, first.start_symbol);
        let alignment = self
            .sections
            .iter()
            .find(|section| section.name == ".text")
            .map_or(1, |section| section.alignment);
        Some(if alignment > 1 {
            format!("({size} + {:#x}) / {alignment:#x} * {alignment:#x}", alignment - 1)
        } else {
            format!("({size})")
        })
    }

    /// The end of the module's initialized data, see [`Self::initialized_size`].
    fn initialized_end(&self) -> Option<String> {
        let first = self.sections.iter().find(|section| section.initialized)?;
        Some(format!("{} + {}", first.start_symbol, self.initialized_size()?))
    }

    /// The start and end of the module's .bss, from its first uninitialized section to its last.
    fn bss_bounds(&self) -> Option<(String, String)> {
        let mut bss = self.sections.iter().filter(|section| !section.initialized);
        let first = bss.next()?;
        let last = bss.next_back().unwrap_or(first);
        Some((first.start_symbol.clone(), last.end_symbol.clone()))
    }
}

impl ModuleParamsLayout {
    fn new(rom: &Rom<'_>) -> Result<Self> {
        let list_size = |autoloads: &[Autoload]| {
            autoloads.iter().map(|autoload| autoload.info().entry_bytes().len() as u32).sum()
        };
        let ltd = rom.dsi().and_then(|dsi| {
            dsi.ltd().map(|ltd| LtdParamsLayout {
                autoload_start: dsi.config().arm9i.base_address + ltd.static_data().len() as u32,
                autoload_list_size: list_size(ltd.autoloads()),
            })
        });
        Ok(Self { autoload_list_size: list_size(&rom.arm9().autoloads()?), ltd })
    }
}

struct LinkModules {
    modules: Vec<LcfModule>,
    last_static_index: usize,
}

impl LinkModules {
    pub fn new(
        rom: &Rom<'_>,
        config: &Config,
        delinks_map: &DelinksMap,
        link_names: &LinkNames,
    ) -> Result<Self> {
        let mut link_modules = Self::find_static(rom, config, delinks_map, link_names)?;
        let static_end_address = link_modules.last_static_module().end_address;
        log::debug!("Static end address: {static_end_address:#010x}");
        let overlay_groups = OverlayGroups::analyze(static_end_address, rom.arm9_overlays())?;
        for group in overlay_groups.iter() {
            let origin = match &group.location {
                OverlayGroupLocation::AfterStatic => {
                    let last_static_module = link_modules.last_static_module();
                    format!("AFTER({})", last_static_module.name)
                }
                OverlayGroupLocation::After(ids) => {
                    format!(
                        "AFTER({})",
                        ids.iter().map(|id| format!("OV{id:03}")).collect::<Vec<_>>().join(", ")
                    )
                }
                OverlayGroupLocation::Static => {
                    format!("{:#010x}", group.start_address)
                }
            };

            for &overlay_id in &group.overlays {
                let kind = ModuleKind::Overlay(overlay_id);
                link_modules.modules.push(LcfModule::new(
                    kind,
                    origin.clone(),
                    config,
                    delinks_map,
                    link_names,
                )?);
            }
        }
        Ok(link_modules)
    }

    fn find_static(
        rom: &Rom<'_>,
        config: &Config,
        delinks_map: &DelinksMap,
        link_names: &LinkNames,
    ) -> Result<Self> {
        let arm9 = rom.arm9();
        let mut modules = vec![];
        modules.push(LcfModule::new(
            ModuleKind::Arm9,
            format!("{:#010x}", arm9.base_address()),
            config,
            delinks_map,
            link_names,
        )?);
        let mut prev_static_index = 0;

        // Find contiguous autoloads after the main program
        let mut sorted_autoloads = rom.arm9().autoloads()?;
        sorted_autoloads.sort_unstable_by_key(Autoload::base_address);
        for autoload in sorted_autoloads {
            let prev_module = &modules[prev_static_index];
            let origin = if autoload.base_address() == prev_module.end_address {
                prev_static_index = modules.len();
                format!("AFTER({})", prev_module.name)
            } else {
                format!("{:#010x}", autoload.base_address())
            };
            modules.push(LcfModule::new(
                ModuleKind::Autoload(autoload.kind()),
                origin,
                config,
                delinks_map,
                link_names,
            )?);
        }

        // The ARM9i program's LTD autoloads are linked at their own addresses
        if let Some(ltd) = rom.dsi().and_then(|dsi| dsi.ltd()) {
            for autoload in ltd.autoloads() {
                modules.push(LcfModule::new(
                    ModuleKind::Autoload(autoload.kind()),
                    format!("{:#010x}", autoload.base_address()),
                    config,
                    delinks_map,
                    link_names,
                )?);
            }
        }
        Ok(Self { modules, last_static_index: prev_static_index })
    }

    fn last_static_module(&self) -> &LcfModule {
        &self.modules[self.last_static_index]
    }
}

#[cfg(test)]
mod tests {
    use ds_decomp::config::section::LTD_MAIN_AUTOLOAD_INDEX;

    use super::*;
    use crate::config::link_names::object_to_link;

    const LTD_MAIN: ModuleKind = ModuleKind::Autoload(AutoloadKind::Ltd(LTD_MAIN_AUTOLOAD_INDEX));

    // An object with functions and statics in ARM9 main and in the LTD autoload, as TwlSDK's card_rom.o has
    const MAIN_DELINKS: &str = "
    .text       start:0x02000000 end:0x02000100 kind:code align:32
    .bss        start:0x02100000 end:0x02100100 kind:bss align:32

main_a.c:
    complete
    .text       start:0x02000000 end:0x02000040
    .bss        start:0x02100000 end:0x02100010
    .ltdmain.bss start:0x02780020 end:0x02780030

card_rom.c:
    complete
    .text       start:0x02000040 end:0x02000080
    .bss        start:0x02100010 end:0x02100020
    .ltdmain    start:0x02700040 end:0x02700070
    .ltdmain.bss start:0x02780010 end:0x02780020

main_b.c:
    .text       start:0x02000080 end:0x02000100
    .bss        start:0x02100020 end:0x02100100
";

    const LTD_DELINKS: &str = "
    .ltdmain    start:0x02700000 end:0x02700100 kind:code align:32
    .bss        start:0x02780000 end:0x02780100 kind:bss align:32

ltd_a.c:
    complete
    .ltdmain    start:0x02700000 end:0x02700040
    .bss        start:0x02780000 end:0x02780010

ltd_b.c:
    complete
    .ltdmain    start:0x02700080 end:0x02700100
    .bss        start:0x02780030 end:0x02780100
";

    fn delinks_map(name: &str, migrate_sections: bool) -> DelinksMap {
        delinks_map_of(
            name,
            &[(ModuleKind::Arm9, MAIN_DELINKS), (LTD_MAIN, LTD_DELINKS)],
            migrate_sections,
        )
    }

    /// The delinks of each module from its delinks.txt
    fn delinks_map_of(
        name: &str,
        modules: &[(ModuleKind, &str)],
        migrate_sections: bool,
    ) -> DelinksMap {
        let dir = std::env::temp_dir().join(format!("dsd-test-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let delinks = modules
            .iter()
            .enumerate()
            .map(|(index, &(kind, text))| {
                let path = dir.join(format!("delinks_{index}.txt"));
                std::fs::write(&path, text).unwrap();
                Delinks::from_file(&path, kind).unwrap()
            })
            .collect();
        std::fs::remove_dir_all(&dir).unwrap();
        DelinksMap::new(delinks, DelinksMapOptions { migrate_sections, generate_gap_files: true })
            .unwrap()
    }

    fn files_named<'a>(delinks: &'a Delinks, name: &str) -> Vec<&'a DelinkFile> {
        delinks.files.iter().filter(|file| file.name == name).collect()
    }

    fn section_names(file: &DelinkFile) -> Vec<(String, String)> {
        file.sections
            .iter()
            .map(|section| (section.name().to_string(), section.source_name().to_string()))
            .collect()
    }

    #[test]
    fn test_ltd_part_migrates_as_one_file() {
        let map = delinks_map("migrate", true);

        let main = map.get(ModuleKind::Arm9).unwrap();
        let [card_rom] = files_named(main, "card_rom.c")[..] else { panic!() };
        assert_eq!(section_names(card_rom), [
            (".text".to_string(), ".text".to_string()),
            (".bss".to_string(), ".bss".to_string())
        ]);
        let migrated =
            card_rom.migrated_sections.iter().map(|section| section.name()).collect::<Vec<_>>();
        assert_eq!(migrated, [".ltdmain", ".ltdmain.bss"]);
        assert!(Lcf::links_in_ltd(card_rom, ModuleKind::Arm9));

        // The LTD autoload gets one file with both parts, placed from the object's own section names, and its own
        // .ltdmain files are not migrations
        let ltd = map.get(LTD_MAIN).unwrap();
        let [card_rom] = files_named(ltd, "card_rom.c")[..] else { panic!() };
        assert!(card_rom.migrated());
        assert_eq!(section_names(card_rom), [
            (".ltdmain".to_string(), ".ltdmain".to_string()),
            (".bss".to_string(), ".ltdmain.bss".to_string())
        ]);
        for name in ["ltd_a.c", "ltd_b.c"] {
            let [file] = files_named(ltd, name)[..] else { panic!("{name}") };
            assert!(!file.migrated());
            assert_eq!(file.migrated_sections.len(), 0);
            assert!(!Lcf::links_in_ltd(file, LTD_MAIN));
        }
        // main_a.c's statics come after card_rom.c's in the LTD autoload, though its code is first in main
        let order = ltd
            .files
            .iter()
            .filter(|file| !file.gap())
            .map(|file| file.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(order, ["ltd_a.c", "card_rom.c", "main_a.c", "ltd_b.c"]);
    }

    /// A gap file's name and its sections' names and ranges
    type Gap = (String, Vec<(String, u32, u32)>);

    fn gaps(delinks: &Delinks) -> Vec<Gap> {
        delinks
            .files
            .iter()
            .filter(|file| file.gap())
            .map(|file| {
                let sections = file
                    .sections
                    .iter()
                    .map(|s| (s.name().to_string(), s.start_address(), s.end_address()))
                    .collect();
                (file.unique_name(), sections)
            })
            .collect()
    }

    #[test]
    fn test_ltd_part_object_listed_in_ltd_place() {
        let map = delinks_map("objects", true);
        let build = Path::new("build");
        let delinks = Path::new("delinks");
        let lines = Lcf::arm9_object_lines(build, delinks, &map, &LinkNames::new(&map))
            .into_iter()
            .filter(|line| !line.contains("_dsd_gap@"))
            .collect::<Vec<_>>();
        let object = |base: &Path, name: &str| format!("\"{}\"", base.join(name).display());
        // Each object with an LTD part is listed once, in the LTD autoload's order
        assert_eq!(lines, [
            object(delinks, "main_b.o"),
            object(build, "ltd_a.o"),
            object(build, "card_rom.o"),
            object(build, "main_a.o"),
            object(build, "ltd_b.o"),
        ]);
    }

    #[test]
    fn test_ltd_part_unmigrated() {
        // Without migration, as objdiff and the disassembler read the delinks, the file keeps its LTD part. The LTD
        // parts' order, opposite to main's for main_a.c and card_rom.c, is no link order cycle of main
        let map = delinks_map("unmigrated", false);
        let main = map.get(ModuleKind::Arm9).unwrap();
        let [card_rom] = files_named(main, "card_rom.c")[..] else { panic!() };
        let names = section_names(card_rom).into_iter().map(|(name, _)| name).collect::<Vec<_>>();
        assert_eq!(names, [".text", ".bss", ".ltdmain", ".ltdmain.bss"]);
        assert!(files_named(map.get(LTD_MAIN).unwrap(), "card_rom.c").is_empty());

        // Its gap files are still those that `dsd delink` writes from the migrated delinks: the LTD part is no gap
        let migrated = delinks_map("unmigrated-gaps", true);
        for kind in [ModuleKind::Arm9, LTD_MAIN] {
            assert_eq!(gaps(map.get(kind).unwrap()), gaps(migrated.get(kind).unwrap()));
        }
        assert_eq!(gaps(map.get(LTD_MAIN).unwrap()), [(
            "_dsd_gap@ltd_autoload_0_0".to_string(),
            vec![(".ltdmain".to_string(), 0x02700070, 0x02700080)]
        )]);
    }

    // A game's heap.c and main.c in ARM9 main, and a library's files of the same names in an overlay
    const SHARED_MAIN_DELINKS: &str = "
    .text       start:0x02000000 end:0x02000100 kind:code align:32

src/main.c:
    complete
    .text       start:0x02000000 end:0x02000040

src/heap.c:
    .text       start:0x02000040 end:0x02000080

src/other.c:
    complete
    .text       start:0x02000080 end:0x02000100
";

    const SHARED_OVERLAY_DELINKS: &str = "
    .text       start:0x02200000 end:0x02200100 kind:code align:32

lib/util/src/main.c:
    complete
    .text       start:0x02200000 end:0x02200040

lib/util/src/heap.c:
    complete
    .text       start:0x02200040 end:0x02200100
";

    const OVERLAY_1: ModuleKind = ModuleKind::Overlay(1);
    const OVERLAY_2: ModuleKind = ModuleKind::Overlay(2);

    fn file<'a>(map: &'a DelinksMap, kind: ModuleKind, name: &str) -> &'a DelinkFile {
        let [file] = files_named(map.get(kind).unwrap(), name)[..] else { panic!("{name}") };
        file
    }

    #[test]
    fn test_shared_file_names_link_under_path_names() {
        let map = delinks_map_of(
            "shared",
            &[(ModuleKind::Arm9, SHARED_MAIN_DELINKS), (OVERLAY_1, SHARED_OVERLAY_DELINKS)],
            true,
        );
        let link_names = LinkNames::new(&map);
        assert!(Lcf::validate_all_file_names(&map, &link_names).is_ok());

        // Each object of a shared file name has a name of its path in the linker script, the others their file name
        let names = [
            (ModuleKind::Arm9, "src/main.c", "src_main.o"),
            (ModuleKind::Arm9, "src/heap.c", "src_heap.o"),
            (ModuleKind::Arm9, "src/other.c", "other.o"),
            (OVERLAY_1, "lib/util/src/main.c", "lib_util_src_main.o"),
            (OVERLAY_1, "lib/util/src/heap.c", "lib_util_src_heap.o"),
        ];
        for (kind, name, object_name) in names {
            assert_eq!(link_names.object_name(file(&map, kind, name)), object_name);
        }

        // The object list gives their copies, made from the compiled or the delinked object, under link/
        let build = Path::new("build");
        let delinks = Path::new("build/delinks");
        let heap = file(&map, ModuleKind::Arm9, "src/heap.c");
        assert_eq!(object_to_link(heap, build, delinks), Path::new("build/delinks/src/heap.o"));
        let lines = Lcf::arm9_object_lines(build, delinks, &map, &link_names)
            .into_iter()
            .filter(|line| !line.contains("_dsd_gap@"))
            .collect::<Vec<_>>();
        assert_eq!(lines, [
            "\"build/link/src/src_main.o\"",
            "\"build/link/src/src_heap.o\"",
            "\"build/src/other.o\"",
            "-overlaygroup OV001,0",
            "-overlay OV001",
            "\"build/link/lib/util/src/lib_util_src_main.o\"",
            "\"build/link/lib/util/src/lib_util_src_heap.o\"",
        ]);
    }

    #[test]
    fn test_file_names_the_linker_cant_tell_apart() {
        let clashes = [
            // Two files of one name in one module
            (
                "module",
                SHARED_MAIN_DELINKS.replace("src/other.c", "lib/heap.c"),
                SHARED_OVERLAY_DELINKS.to_string(),
            ),
            // One file in two modules
            (
                "twice",
                SHARED_MAIN_DELINKS.to_string(),
                SHARED_OVERLAY_DELINKS.replace("lib/util/src/", "src/"),
            ),
            // A file named as another's object is linked
            (
                "path",
                SHARED_MAIN_DELINKS.replace("src/other.c", "src_heap.c"),
                SHARED_OVERLAY_DELINKS.to_string(),
            ),
        ];
        for (name, main, overlay) in clashes {
            let map =
                delinks_map_of(name, &[(ModuleKind::Arm9, &main), (OVERLAY_2, &overlay)], true);
            let link_names = LinkNames::new(&map);
            assert!(Lcf::validate_all_file_names(&map, &link_names).is_err(), "{name}");
        }
    }

    /// A module of the given sections, each a name, an alignment and whether it is initialized
    fn param_module(kind: ModuleKind, name: &str, sections: &[(&str, u32, bool)]) -> LcfModule {
        let sections = sections
            .iter()
            .map(|&(section_name, alignment, initialized)| {
                let boundary = section_name.trim_start_matches('.').to_uppercase();
                LcfSection {
                    name: section_name.to_string(),
                    alignment,
                    end_alignment: 4,
                    start_symbol: format!("{name}_{boundary}_START"),
                    end_symbol: format!("{name}_{boundary}_END"),
                    append_zero: false,
                    exceptix: false,
                    files: vec![],
                    initialized,
                }
            })
            .collect();
        LcfModule {
            name: name.to_string(),
            origin: "0x02000000".to_string(),
            end_address: 0,
            output_file: String::new(),
            link_section: String::new(),
            object: String::new(),
            sections,
            in_tcm: false,
            kind,
        }
    }

    fn param_modules() -> Vec<LcfModule> {
        vec![
            param_module(ModuleKind::Arm9, "ARM9", &[
                (".text", 32, true),
                (".data", 4, true),
                (".sbss", 4, false),
                (".bss", 32, false),
            ]),
            param_module(ModuleKind::Autoload(AutoloadKind::Itcm), "ITCM", &[
                (".text", 32, true),
                (".bss", 32, false),
            ]),
            // No .text to round the size to, and no initialized data at all
            param_module(ModuleKind::Autoload(AutoloadKind::Dtcm), "DTCM", &[
                (".data", 4, true),
                (".bss", 4, false),
            ]),
            param_module(ModuleKind::Autoload(AutoloadKind::Unknown(2)), "AUTOLOAD_2", &[(
                ".bss", 4, false,
            )]),
            param_module(LTD_MAIN, "LTD_AUTOLOAD_0", &[
                (".text", 32, true),
                (".ltdmain", 4, true),
                (".bss", 32, false),
            ]),
            param_module(ModuleKind::Overlay(0), "OV000", &[(".text", 32, true)]),
        ]
    }

    fn param_text(variables: &[LcfVariable]) -> Vec<String> {
        variables.iter().map(|v| format!("{} = {};", v.symbol, v.value)).collect()
    }

    #[test]
    fn test_module_params_follow_the_modules() {
        let layout = ModuleParamsLayout {
            autoload_list_size: 0x40,
            ltd: Some(LtdParamsLayout { autoload_start: 0x02400004, autoload_list_size: 0x10 }),
        };
        let variables = Lcf::module_param_variables(&param_modules(), &layout);
        assert_eq!(param_text(&variables), [
            "SDK_AUTOLOAD_START = ARM9_TEXT_START + (ARM9_DATA_END - ARM9_TEXT_START + 0x1f) / 0x20 * 0x20;",
            "SDK_STATIC_BSS_START = ARM9_SBSS_START;",
            "SDK_STATIC_BSS_END = ARM9_BSS_END;",
            "SDK_AUTOLOAD_LIST = SDK_AUTOLOAD_START + (ITCM_TEXT_END - ITCM_TEXT_START + 0x1f) / 0x20 * 0x20 + \
             (DTCM_DATA_END - DTCM_DATA_START);",
            "SDK_AUTOLOAD_LIST_END = SDK_AUTOLOAD_LIST + 0x40;",
            "SDK_LTDAUTOLOAD_START = 0x02400004;",
            "SDK_LTDAUTOLOAD_LIST = SDK_LTDAUTOLOAD_START + (LTD_AUTOLOAD_0_LTDMAIN_END - LTD_AUTOLOAD_0_TEXT_START + \
             0x1f) / 0x20 * 0x20;",
            "SDK_LTDAUTOLOAD_LIST_END = SDK_LTDAUTOLOAD_LIST + 0x10;",
        ]);
        // Every name is one that a relocation can point at
        for variable in &variables {
            assert!(
                LinkTimeConst::iter().any(|c| c.name() == variable.symbol),
                "{}",
                variable.symbol
            );
        }
    }

    #[test]
    fn test_module_params_without_ltd() {
        let layout = ModuleParamsLayout { autoload_list_size: 0x18, ltd: None };
        let modules = param_modules()
            .into_iter()
            .filter(|module| !matches!(module.kind, ModuleKind::Autoload(AutoloadKind::Ltd(_))))
            .collect::<Vec<_>>();
        let text = param_text(&Lcf::module_param_variables(&modules, &layout));
        assert_eq!(text.len(), 5);
        assert_eq!(text[4], "SDK_AUTOLOAD_LIST_END = SDK_AUTOLOAD_LIST + 0x18;");
    }

    #[test]
    fn test_module_params_rendered_after_the_modules() {
        let mut tt = TinyTemplate::new();
        tt.add_template("arm9", ARM9_LCF_TEMPLATE).unwrap();
        let layout = ModuleParamsLayout { autoload_list_size: 0x40, ltd: None };
        let modules = param_modules();
        let context = Arm9LcfContext {
            module_params: Lcf::module_param_variables(&modules, &layout),
            modules,
            overlays: vec![],
            variables: vec![LcfVariable::new("SDK_IRQ_STACKSIZE", "0x800")],
        };
        let lcf = tt.render("arm9", &context).unwrap();
        let last_module = lcf.find("} > OV000").unwrap();
        let list = lcf.find("SDK_AUTOLOAD_LIST = SDK_AUTOLOAD_START + (ITCM_TEXT_END").unwrap();
        assert!(last_module < list);
        assert!(lcf.find("SDK_IRQ_STACKSIZE = 0x800;").unwrap() < lcf.find("} > ARM9").unwrap());
        assert!(lcf.contains("/ 0x20 * 0x20"), "the expressions are not escaped");
    }
}
