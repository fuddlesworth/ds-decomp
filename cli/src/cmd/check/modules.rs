use std::{
    fmt::Display,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::Args;
use ds_decomp::config::{
    config::{Config, ConfigModule},
    module::ModuleKind,
};
use ds_rom::rom::{Arm9BuildConfig, RomConfig};

use crate::{
    cmd::ModuleFilterArgs,
    util::io::{FileError, open_file, read_file},
};

/// The size of an HMAC-SHA1 overlay digest
const OVERLAY_DIGEST_SIZE: usize = 20;

/// Verifies that built modules are matching the base ROM.
#[derive(Args)]
pub struct CheckModules {
    /// Path to config.yaml.
    #[arg(long, short = 'c')]
    pub config_path: PathBuf,

    /// Return failing exit code if a module doesn't pass the checks.
    #[arg(long, short = 'f')]
    pub fail: bool,

    #[command(flatten)]
    pub module_filter: ModuleFilterArgs,
}

#[derive(PartialEq, Eq)]
enum CheckResult {
    ChecksumFailed,
    Ok, // OK
}

impl CheckModules {
    pub fn run(&self) -> Result<()> {
        let config = Config::from_file(&self.config_path)?;
        let config_path = self.config_path.parent().unwrap();

        let mut success = true;

        if self.module_filter.has(ModuleKind::Arm9) {
            success &= Self::print_check_module(
                &config.main_module,
                ModuleKind::Arm9,
                Some(&config),
                config_path,
            )?;
        }
        for autoload in &config.autoloads {
            if self.module_filter.has(ModuleKind::Autoload(autoload.kind)) {
                success &= Self::print_check_module(
                    &autoload.module,
                    ModuleKind::Autoload(autoload.kind),
                    None,
                    config_path,
                )?;
            }
        }
        for overlay in &config.overlays {
            if self.module_filter.has(ModuleKind::Overlay(overlay.id)) {
                success &= Self::print_check_module(
                    &overlay.module,
                    ModuleKind::Overlay(overlay.id),
                    None,
                    config_path,
                )?;
            }
        }

        if self.fail && !success {
            bail!("Some module(s) didn't pass the checks.");
        }

        Ok(())
    }

    fn print_check_module(
        module: &ConfigModule,
        module_kind: ModuleKind,
        arm9_config: Option<&Config>,
        config_path: &Path,
    ) -> Result<bool> {
        let result = Self::check_module(module, arm9_config, config_path)?;
        log::info!("Check {module_kind}: {result}");
        Ok(result == CheckResult::Ok)
    }

    fn check_module(
        module: &ConfigModule,
        arm9_config: Option<&Config>,
        config_path: &Path,
    ) -> Result<CheckResult> {
        let base_hash = u64::from_str_radix(&module.hash, 16)
            .with_context(|| format!("Invalid hash '{}'", module.hash))?;

        let mut code = match read_file(config_path.join(&module.object)) {
            Ok(code) => code,
            Err(FileError::FileNotFound { .. }) => vec![],
            Err(e) => return Err(e.into()),
        };
        if let Some(config) = arm9_config {
            Self::take_overlay_digests(&mut code, config, config_path)?;
        }
        let code_hash = fxhash::hash64(&code);

        if code_hash == base_hash {
            Ok(CheckResult::Ok)
        } else {
            Ok(CheckResult::ChecksumFailed)
        }
    }
}

impl CheckModules {
    /// The linked ARM9 program leaves the room of the overlay digest table, which `rom build` fills in from the built
    /// overlays as NitroSDK's tools do after the link, so its bytes are taken from the extracted ARM9 program: the
    /// overlay table's digest just before the table and one digest per overlay. The ROM's own check covers them.
    fn take_overlay_digests(code: &mut [u8], config: &Config, config_path: &Path) -> Result<()> {
        let object_path = config_path.join(&config.main_module.object);
        let Some(build_dir) = object_path.parent() else {
            return Ok(());
        };
        let arm9_yaml = build_dir.join("arm9.yaml");
        if !arm9_yaml.exists() {
            return Ok(());
        }
        let build_config: Arm9BuildConfig = serde_saphyr::from_reader(open_file(&arm9_yaml)?)?;
        let offset = build_config.offsets.overlay_signatures as usize;
        if offset < OVERLAY_DIGEST_SIZE {
            return Ok(());
        }
        let start = offset - OVERLAY_DIGEST_SIZE;
        let end = offset + OVERLAY_DIGEST_SIZE * config.overlays.len();

        let rom_config_path = config_path.join(&config.rom_config);
        let rom_paths: RomConfig = serde_saphyr::from_reader(open_file(&rom_config_path)?)?;
        let extract_dir = rom_config_path.parent().unwrap();
        let original = read_file(extract_dir.join(&rom_paths.arm9_bin))?;
        if end <= code.len() && end <= original.len() {
            code[start..end].copy_from_slice(&original[start..end]);
        }
        Ok(())
    }
}

impl Display for CheckResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckResult::ChecksumFailed => write!(f, "checksum failed"),
            CheckResult::Ok => write!(f, "OK"),
        }
    }
}
