# Binary Ninja Zydis
A plugin for binary ninja, that uses the [zydis](https://github.com/zyantific/zydis) disassembler.
The zydis disassembler currently supports way more instructions than the x86/x64 backend of binary ninja supports.

For example, Binary Ninja can't disassemble `vcmpps k2 {k7}, zmm2, dword ptr ds:[rax+rbx*4+0x100] {1to16}, 0x0F`
(opcodes `62 F1 6C 5F C2 54 98 40 0F`) yet (from the AVX 512 instruction set extension). Many many more instructions
from that or similar extensions are not supported by binary ninja.

## Current Limitations
Currently we fall back to binary ninjas IL lifting (which isn't a bad thing).

### Mach-O 64 bit binaries
Mach-O 64 bit binaries are currently not supported, since I couldn't find the correct value to override.

# Installation

## Building on Linux
```bash
git clone https://github.com/th0rex/binaryninja_zydis
cd binaryninja_zydis

mkdir build
cd build

cmake .. -DBINARYNINJA_CORE_PATH=<path to libbinaryninjacore.so.1> -DCMAKE_BUILD_TYPE=RelWithDebInfo -G Ninja
ninja
```

## Building on Windows
Note: Currently binary ninja doesn't ship with the .lib file for the core API. You can create it yourself by dumping the exports
and then using the `lib` tool in a Visual Studio Developer Command Prompt.

It is assumed that the file is located at `C:\\Program Files\\Vector35\\BinaryNinja\\binaryninjacore.lib`

```bash
git clone https://github.com/th0rex/binaryninja_zydis
cd binaryninja_zydis

mkdir build
cd build

cmake.exe .. -DCMAKE_BUILD_TYPE=RelWithDebInfo

# Build the solution with Visual Studio
```

## Usage
Either copy the resulting `binaryninja_zydis.dll` or `libbinaryninja_zydis.so` file to your binary ninja plugins directory, or
symlink it there so that you don't have to copy it on updates.

After doing that you have to open any binary (or create a new one) and choose `Zydis x86` or `Zydis x64` from the 
`Tools` menu to use the zydis backend for x86 or x64 files, respectively. Note that in the current view the backend will NOT change,
this only affects newly opened files.

Once this backend gets better, it will be set as the default.
