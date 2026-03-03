# Switch Native Port (Bootstrap)

This directory is an initial native C++ bootstrap for parsing `global-metadata.dat`.

Current scope:
- Validates metadata magic and supported version range.
- Parses core header fields needed for classes.
- Parses image/type/method/field/parameter tables.
- Resolves metadata strings.
- Writes a metadata-only `dump.cs` with class stubs.
- Loads IL2CPP ELF64 `PT_LOAD` segments natively (foundation for binary-backed dump parity).
- Finds `CodeRegistration` and `MetadataRegistration` natively from ELF data/symbols.
- Loads runtime `types[]` from `MetadataRegistration` and uses them for primitive/class type-name resolution.

Not implemented yet:
- Executable parsing (`main`, `NSO`, `ELF`) and metadata registration linkage.
- Method pointer recovery, field offsets, and script generation parity.
- Custom attributes, generics, and full version-specific edge handling.
- NRO packaging glue (`libnx`, `elf2nro`, romfs assets).

## Build (desktop smoke test)

```bash
cmake -S Switch -B Switch/build
cmake --build Switch/build -j
./Switch/build/switch_il2cpp_metadata /path/to/global-metadata.dat /path/to/dump.cs
./Switch/build/switch_il2cpp_metadata /path/to/main.elf /path/to/global-metadata.dat /path/to/dump.cs
```

## Build direction for Nintendo Switch homebrew

Use `devkitPro` (`devkitA64` + `libnx`) and add a Switch-target build script that compiles this parser into an ELF, then package with `elf2nro`.

This bootstrap keeps parser logic platform-agnostic so it can be reused in both desktop test binaries and eventual `.nro` builds.

## Build `.nro` (Switch homebrew)

Prerequisites:
- `devkitPro` installed with `devkitA64` and `libnx`
- `DEVKITPRO` and `DEVKITARM`/toolchain env vars set by your devkitPro shell

From repository root:

```bash
make.exe -C Switch
```

Artifacts:
- `Switch/switch_il2cpp_metadata.elf`
- `Switch/switch_il2cpp_metadata.nro`

Optional:
- Put assets in `Switch/romfs` and they will be packaged into the `.nro`.
- Clean with:

```bash
make.exe -C Switch clean
```
