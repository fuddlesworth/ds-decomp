# `relocs.txt`
This document describes how a `relocs.txt` file is structured.

## Format
Each line in `relocs.txt` is one relocation, and has the following format:
```
from:FROM kind:KIND to:TO add:ADD module:MODULE
```
- `FROM`: Any 32-bit address in this module.
- [`KIND`](#relocation-kinds)
- `TO`: Any 32-bit address in the game's code.
- (optional) `ADD`: Explicit addend to add to the `TO` address.
- [`MODULE`](#destination-module)

### Relocation kinds
- `arm_call`: ARM call to ARM.
- `thumb_call`: Thumb call to Thumb.
- `arm_call_thumb`: ARM call to Thumb.
- `thumb_call_arm`: Thumb call to ARM. 
- `arm_branch`: ARM branch to ARM.
- `load`: 32-bit absolute pointer.
- `overlay_id`: Overlay ID.
    - Special case of `load` that resolves to an overlay ID.
    - The relocation must also have `module:none`.
- `link_time_const(CONST)`: Link-time variable. `CONST` must be one of:
    - `__DTCM_LO`: Base address of the DTCM module.
    - `__ITCM_HI`: End address of the ITCM module.
    - `__CODE_HI`: End address of static memory in main RAM.
    - `__OVERLAY_COUNT`: Number of overlays.
    - `ARM9_CTOR_START`: Base address of .ctor in main ARM9 program.
    - `__exception_table_start__`: Base address of .exceptix in main ARM9 program.
    - `__exception_table_end__`: End address of .exceptix in main ARM9 program.
    - The module parameters' symbols, which NitroSDK's crt0 keeps in `_start_ModuleParams` and TwlSDK's in
      `_start_LtdModuleParams`. `dsd lcf` defines them after the modules, from the modules' section symbols, as
      NitroSDK's linker script template does, and `rom build` writes the same values again:
        - `SDK_AUTOLOAD_START`: End of the main ARM9 program's initialized data, where its autoload blocks start.
        - `SDK_AUTOLOAD_LIST`, `SDK_AUTOLOAD_LIST_END`: The autoload list, after the autoload blocks.
        - `SDK_STATIC_BSS_START`, `SDK_STATIC_BSS_END`: The main ARM9 program's .bss.
        - `SDK_LTDAUTOLOAD_START`: Where the DSi LTD module's autoload blocks start, after the ARM9i program's static
          part. Defined only for a ROM with an LTD module, as the next two.
        - `SDK_LTDAUTOLOAD_LIST`, `SDK_LTDAUTOLOAD_LIST_END`: The LTD module's autoload list, after its blocks.

### Destination module
- `none`: No destination symbol found due to poor analysis by `dsd init`. Many `dsd` subcommands will fail.
- `overlay(X)`: Destination module is in overlay X.
- `overlays(X,Y,Z,...)`: Destination module is in one of many overlays. `dsd delink` will choose the first one in this list.
- `main`: Destination symbol is in the main module.
- `itcm`: Destination symbol is in ITCM.
- `dtcm`: Destination symbol is in DTCM.
