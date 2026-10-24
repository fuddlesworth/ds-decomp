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
        Self::validate_all_file_names(&delinks_map)?;

        let rom = config.load_rom(config_dir)?;

        let build_path = config_dir.join(&config.build_path).clean();

        let link_modules = LinkModules::new(&rom, &config, &delinks_map)?;

        let mut tt = TinyTemplate::new();
        tt.add_template("arm9", ARM9_LCF_TEMPLATE)?;

        let mut variables = Self::generate_lcf_variables(&config);
        if let Some(symbols) = &self.symbols {
            variables.extend(Self::read_symbols(symbols)?);
        }
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
        };
        Self::write_arm9_lcf(&arm9_context, &tt, &build_path)?;
        self.write_arm9_objects(&config, &build_path, &delinks_map)?;

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
                };
                Some(LcfVariable::new(var.to_string(), value))
            })
            .collect()
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
    ) -> Result<()> {
        let config_dir = self.config_path.parent().unwrap();
        let objects_file_path = lcf_path.join(ARM9_OBJECTS_FILE_NAME);
        let mut writer = BufWriter::new(create_file_and_dirs(objects_file_path)?);

        let build_path = config_dir.join(&config.build_path);
        let delinks_path = config_dir.join(&config.delinks_path);
        for line in Self::arm9_object_lines(&build_path, &delinks_path, delinks_map) {
            writeln!(writer, "{line}")?;
        }
        Ok(())
    }

    /// The lines of the ARM9 program's object list: complete files' objects from `build_path`, the others' from
    /// `delinks_path`.
    fn arm9_object_lines(
        build_path: &Path,
        delinks_path: &Path,
        delinks_map: &DelinksMap,
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
                let (file_path, _) = file.split_file_ext();
                let base_path = if file.complete { build_path } else { delinks_path };
                let file = base_path.join(file_path).with_extension("o").clean();
                lines.push(format!("\"{}\"", file.display()));
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

    fn validate_all_file_names(delinks_map: &DelinksMap) -> Result<()> {
        let mut delink_files: HashMap<String, ModuleKind> = HashMap::new();
        let mut success = true;
        for delinks in delinks_map.iter() {
            success &= Self::validate_file_names(delinks, &mut delink_files);
        }
        if !success {
            bail!("Duplicate file names found, see logs above");
        }
        Ok(())
    }

    fn validate_file_names(
        delinks: &Delinks,
        delink_files: &mut HashMap<String, ModuleKind>,
    ) -> bool {
        let mut success = true;
        for file in &delinks.files {
            if file.migrated() {
                // Migrated files will have the same name as the original, that is intentional
                continue;
            }
            let name = file.unique_name();
            let filename = name.rsplit_once(['/', '\\']).map_or(name.as_str(), |(_, base)| base);
            match delink_files.entry(filename.to_string()) {
                hash_map::Entry::Occupied(occupied_entry) => {
                    log::error!(
                        "Delink file name '{}' in {} already used in {}",
                        filename,
                        delinks.module_kind(),
                        occupied_entry.get()
                    );
                    success = false;
                }
                hash_map::Entry::Vacant(vacant_entry) => {
                    vacant_entry.insert(delinks.module_kind());
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
                        .map(|(file, section_name)| {
                            let (file, _) = file.split_file_ext();
                            let name = file
                                .rsplit_once(['/', '\\'])
                                .map_or(file.as_str(), |(_, basefile)| basefile);
                            LcfFile { name: format!("{name}.o"), section_name }
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
        })
    }
}

struct LinkModules {
    modules: Vec<LcfModule>,
    last_static_index: usize,
}

impl LinkModules {
    pub fn new(rom: &Rom<'_>, config: &Config, delinks_map: &DelinksMap) -> Result<Self> {
        let mut link_modules = Self::find_static(rom, config, delinks_map)?;
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
                )?);
            }
        }
        Ok(link_modules)
    }

    fn find_static(rom: &Rom<'_>, config: &Config, delinks_map: &DelinksMap) -> Result<Self> {
        let arm9 = rom.arm9();
        let mut modules = vec![];
        modules.push(LcfModule::new(
            ModuleKind::Arm9,
            format!("{:#010x}", arm9.base_address()),
            config,
            delinks_map,
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
        let dir = std::env::temp_dir().join(format!("dsd-test-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let main_path = dir.join("main_delinks.txt");
        let ltd_path = dir.join("ltd_delinks.txt");
        std::fs::write(&main_path, MAIN_DELINKS).unwrap();
        std::fs::write(&ltd_path, LTD_DELINKS).unwrap();
        let delinks = vec![
            Delinks::from_file(&main_path, ModuleKind::Arm9).unwrap(),
            Delinks::from_file(&ltd_path, LTD_MAIN).unwrap(),
        ];
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
        let lines = Lcf::arm9_object_lines(build, delinks, &map)
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
}
