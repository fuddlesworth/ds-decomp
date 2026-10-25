use std::{backtrace::Backtrace, fmt::Display};

use serde::{Deserialize, Serialize};
use snafu::Snafu;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use crate::config::ParseContext;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, EnumIter, Debug)]
pub enum LinkTimeConst {
    DtcmLo,
    ItcmHi,
    CodeHi,
    OverlayCount,
    Arm9CtorStart,
    ExceptionTableStart,
    ExceptionTableEnd,
    /// The static module's autoload list, which the ROM build writes after the module's autoload blocks. NitroSDK's crt0
    /// keeps it in the module parameters (`_start_ModuleParams`), as the next four.
    SdkAutoloadList,
    /// The end of the static module's autoload list.
    SdkAutoloadListEnd,
    /// Where the static module's autoload blocks start, at the end of its initialized data.
    SdkAutoloadStart,
    /// The start of the static module's .bss.
    SdkStaticBssStart,
    /// The end of the static module's .bss.
    SdkStaticBssEnd,
    /// The LTD module's autoload list, which the ROM build writes after the LTD module's autoload blocks. TwlSDK's crt0
    /// keeps it in the LTD module's parameters (`_start_LtdModuleParams`), as the next two.
    SdkLtdautoloadList,
    /// The end of the LTD module's autoload list.
    SdkLtdautoloadListEnd,
    /// Where the LTD module's autoload blocks start, after the static part of the ARM9i program.
    SdkLtdautoloadStart,
}

#[derive(Debug, Snafu)]
pub enum LinkTimeConstParseError {
    #[snafu(display(
        "{context}: unknown link-time constant '{value}', must be one of:
        {}:
        {backtrace}",
        LinkTimeConst::iter().map(LinkTimeConst::name).collect::<Vec<_>>().join(", ")
    ))]
    UnknownKind { context: ParseContext, value: String, backtrace: Backtrace },
}

impl LinkTimeConst {
    pub(crate) fn parse(
        value: &str,
        context: &ParseContext,
    ) -> Result<Self, LinkTimeConstParseError> {
        match Self::iter().find(|link_time_const| link_time_const.name() == value) {
            Some(link_time_const) => Ok(link_time_const),
            None => UnknownKindSnafu { context, value }.fail(),
        }
    }

    /// Returns the name of the symbol that the linker script defines.
    pub fn name(self) -> &'static str {
        match self {
            LinkTimeConst::DtcmLo => "__DTCM_LO",
            LinkTimeConst::ItcmHi => "__ITCM_HI",
            LinkTimeConst::CodeHi => "__CODE_HI",
            LinkTimeConst::OverlayCount => "__OVERLAY_COUNT",
            LinkTimeConst::Arm9CtorStart => "ARM9_CTOR_START",
            LinkTimeConst::ExceptionTableStart => "__exception_table_start__",
            LinkTimeConst::ExceptionTableEnd => "__exception_table_end__",
            LinkTimeConst::SdkAutoloadList => "SDK_AUTOLOAD_LIST",
            LinkTimeConst::SdkAutoloadListEnd => "SDK_AUTOLOAD_LIST_END",
            LinkTimeConst::SdkAutoloadStart => "SDK_AUTOLOAD_START",
            LinkTimeConst::SdkStaticBssStart => "SDK_STATIC_BSS_START",
            LinkTimeConst::SdkStaticBssEnd => "SDK_STATIC_BSS_END",
            LinkTimeConst::SdkLtdautoloadList => "SDK_LTDAUTOLOAD_LIST",
            LinkTimeConst::SdkLtdautoloadListEnd => "SDK_LTDAUTOLOAD_LIST_END",
            LinkTimeConst::SdkLtdautoloadStart => "SDK_LTDAUTOLOAD_START",
        }
    }
}

impl Display for LinkTimeConst {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_names_parse_back() {
        let context = ParseContext { file_path: "relocs.txt".to_string(), row: 1 };
        for link_time_const in LinkTimeConst::iter() {
            let parsed = LinkTimeConst::parse(&link_time_const.to_string(), &context).unwrap();
            assert_eq!(parsed, link_time_const);
        }
        assert_eq!(
            LinkTimeConst::parse("SDK_LTDAUTOLOAD_LIST_END", &context).unwrap(),
            LinkTimeConst::SdkLtdautoloadListEnd
        );
        assert!(LinkTimeConst::parse("SDK_AUTOLOAD_SIZE", &context).is_err());
    }
}
