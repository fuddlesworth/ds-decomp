use std::borrow::Cow;

use ds_rom::rom::{
    Arm9AutoloadError, Rom,
    raw::{AutoloadKind, RawBuildInfoError},
};
use snafu::Snafu;

use crate::config::module::ModuleKind;

#[derive(Debug, Snafu)]
pub enum RomGetCodeError {
    #[snafu(display("Module {} not found", module_kind))]
    ModuleNotFound { module_kind: ModuleKind },
    #[snafu(transparent)]
    RawBuildInfo { source: RawBuildInfoError },
    #[snafu(transparent)]
    Arm9Autoload { source: Arm9AutoloadError },
}

pub trait RomExt {
    /// Returns the full binary code of the given module.
    ///
    /// # Errors
    ///
    /// This function will return an error if the given module does not exist in the ROM or if
    /// [`ds_rom::rom::Arm9::code`] or [`ds_rom::rom::Arm9::autoloads`] fail.
    fn get_code(&self, kind: ModuleKind) -> Result<Cow<'_, [u8]>, RomGetCodeError>;
}

impl RomExt for Rom<'_> {
    fn get_code(&self, kind: ModuleKind) -> Result<Cow<'_, [u8]>, RomGetCodeError> {
        match kind {
            ModuleKind::Arm9 => Ok(self.arm9().code()?.into()),
            ModuleKind::Overlay(id) => Ok(self
                .arm9_overlays()
                .get(id as usize)
                .ok_or_else(|| RomGetCodeError::ModuleNotFound { module_kind: kind })?
                .code()
                .into()),
            ModuleKind::Autoload(AutoloadKind::Ltd(_)) => {
                let autoload = self
                    .dsi()
                    .and_then(|dsi| dsi.ltd())
                    .and_then(|ltd| ltd.autoloads().iter().find(|a| ModuleKind::Autoload(a.kind()) == kind))
                    .ok_or_else(|| RomGetCodeError::ModuleNotFound { module_kind: kind })?;
                Ok(autoload.code().to_owned().into())
            }
            ModuleKind::Autoload(autoload_kind) => {
                let autoloads = self.arm9().autoloads()?;
                let autoload = autoloads
                    .iter()
                    .find(|a| a.kind() == autoload_kind)
                    .ok_or_else(|| RomGetCodeError::ModuleNotFound { module_kind: kind })?;
                Ok(autoload.code().to_owned().into())
            }
        }
    }
}
