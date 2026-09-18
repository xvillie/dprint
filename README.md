# dprint

Auto Updating / Live Dumping External Printsploit
# admin privileges aren't required but better for stability.

## Layout

```
dprint.sln
dprint/
    ├── dprint.vcxproj
    ├── include/
    │   ├── process.hpp        # process enum, PEB, PE sections, RPM/WPM
    │   ├── dumper.hpp         # anchor scan → xref → CALL target
    │   └── injector.hpp       # SeDebug, shellcode, IoCompletion dispatch
    ├── src/
    │   ├── process.cpp
    │   ├── dumper.cpp
    │   ├── injector.cpp
    │   └── main.cpp           # CLI: `dump` and `print` subcommands
    └── external/
        └── hde64/             # small x86-64 length disassembler (vendored)
```

#

## Clone

```bash
git clone https://github.com/f1en444/dprint.git
cd dprint
```

## Build

### Requirements

* Windows 10/11
* Visual Studio 2022
* MSBuild
* C++ Desktop Development workload

### Using Visual Studio

Open `dprint.sln` in Visual Studio 2022.

Select:

* **Configuration:** `Release`
* **Platform:** `x64`

Then build the solution with **Build → Build Solution**.

### Using MSBuild

From a Visual Studio Developer Command Prompt:

```cmd
msbuild dprint.sln /p:Configuration=Release /p:Platform=x64
```

The compiled executable will be located in:

```text
x64\Release\dprint.exe
```

## Usage

Dump only — find the print-function RVA:

```
dprint dump
```

Print a message (auto-dumps the offset for you):

```
dprint print "hello from rbx_console"
dprint print "network warning"   -l warning
dprint print "you died"          -l error
dprint print "cached"            --offset 0x92C340
```

Optional flags on either subcommand:

- `--process EXE` — target executable name (default `RobloxPlayerBeta.exe`)
- `--anchor STRING` — anchor string used by the dumper

## How it works

- **`dump`** — reads the target's `.rdata`, finds the anchor string, scans
  `.text` for rip-relative references, disassembles the first ~64 bytes past
  each reference with `hde64`, extracts the near-CALL target, votes across
  every reference, prints candidates ranked by vote count.
- **`print`** — enables `SeDebugPrivilege`, allocates `PAGE_EXECUTE_READWRITE`
  memory in the target, writes ~50 bytes of shellcode that calls
  `(GetModuleHandleA(nullptr) + rva)(level, "msg")`, then dispatches execution
  through the target's own threadpool by writing a `TP_DIRECT` into a zero-
  filled RW codecave and calling `NtSetIoCompletion`.

## Notes

- `--offset` in `print` avoids re-running the dumper each call — useful for
  scripting. Cache the value you get out of `dump`.
- Shellcode is left resident in the target (frees would race the async
  callback). Each `print` invocation leaks ~50 bytes.
- If `dump` returns no candidates: the anchor string moved or the compiler
  changed how it emits the load. Pass `--anchor "some other string in Roblox"`
  and try again.
