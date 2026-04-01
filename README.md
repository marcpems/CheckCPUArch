# CheckCPUArch

A Windows command-line tool that scans a directory for `.exe` and `.dll` files and reports the CPU architecture of each file by reading its PE (Portable Executable) header.

Detected architectures include **x86**, **x64**, **Arm64**, **Arm64EC**, **Arm64X**, **ARM**, and **IA-64**.

## Download

Pre-built binaries from the latest successful CI build are available on the [Latest Build](../../releases/tag/latest) release page:

- **CheckCPUArch-x64.zip** — for x64 Windows
- **CheckCPUArch-ARM64.zip** — for Arm64 Windows

Each zip contains `CheckCPUArch.exe` and `CheckCPUArch.pdb`. Download the zip for your architecture, extract, and run.

## Usage

```
CheckCPUArch.exe [-s] [-v] [path]
```

| Option | Description |
|--------|-------------|
| `-s` or `/s` | Recursively scan all sub-folders |
| `-v` or `/v` | Enable verbose trace output |
| `path` | Directory to scan (defaults to the current directory) |

Flags are case-insensitive and can use either `-` or `/` as a prefix.

## Examples

Scan the current directory:
```
CheckCPUArch.exe
```

Scan `C:\Windows\System32` including all sub-folders:
```
CheckCPUArch.exe -s C:\Windows\System32
```

Scan with verbose output:
```
CheckCPUArch.exe -v -s C:\MyApp
```

## Output

Results are displayed as a table showing each file's path (relative to the scan directory) and its architecture:

```
File                              Architecture
--------------------------------------------------
myapp.exe                         x64
plugins\helper.dll                Arm64EC
legacy\old.dll                    x86
```

## Building

Open `CheckCPUArch.slnx` in Visual Studio 2022 (v145 toolset) and build for the desired platform (x64, ARM64, or x86).

Or build from the command line with MSBuild:
```
msbuild CheckCPUArch.vcxproj /p:Configuration=Release /p:Platform=ARM64
```
