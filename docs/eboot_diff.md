# EBOOT Diff Tool

`eboot_diff` is a dual-pane PPC64 disassembly diff viewer for PS3 `EBOOT.BIN` and `EBOOT.ELF` files.

## Features

- Open `EBOOT.BIN` (auto-decrypt) or `EBOOT.ELF` on left and right panes
- Capstone-powered PPC64 big-endian disassembly
- WinDiff-style aligned rows with insert/delete/change highlighting
- Synchronized scrolling in a single view
- Copy instruction bytes between sides
- Keystone-based inline assembly edits (4-byte PPC instructions)
- Export patched output as `EBOOT.ELF` or re-signed `EBOOT.BIN`

## Dependencies

- **Capstone**, **fmt**, **Catch2**, **GLFW**, **Dear ImGui** — fetched via CPM (`cmake/Dependencies.cmake`)
- **Keystone** — system library (`libkeystone-dev`, `pkg-config keystone`)

Valgrind QA requires `libc6-dbg` on Debian/Ubuntu systems.

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Runtime crypto assets are staged to `build/bin/data/`. Run tools from `build/bin/` or set the `PS3` environment variable to a directory containing `keys`, `ldr_curves`, `vsh_curves`, and `idps`.

## Usage

GUI:

```bash
./build/bin/eboot_diff
```

Headless self-test (for CI/valgrind):

```bash
./build/bin/eboot_diff --self-test
```

Headless diff report:

```bash
./build/bin/eboot_diff --diff left.elf right.elf --report diff.txt
```

## QA

```bash
cmake --build build --target check
./scripts/qa_valgrind.sh
./scripts/qa_strace.sh
```

Debug with GDB:

```bash
cd build/bin
gdb --args ./eboot_diff --self-test
```

## Architecture

- `eboot_diff_lib` — domain models and services (loader, disassembler, diff, patch, assembler, export)
- `resigner_core` — shared decrypt/resign settings via `SceOperations`
- `eboot_diff` — ImGui front-end

NPDRM `EBOOT.BIN` decryption may require a matching RAP in `raps/` or a manual klicensee in the Settings dialog.
