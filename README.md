# LazyImporter RE Resolver

## How LazyImporter hides imports

Instead of a normal import (a name string + an IAT entry), every `LI_FN(name)`
call site stores only a hash. For each call site the compiler generates:

- a per-call-site **offset** (a random 32-bit seed derived from
  `__TIME__/__DATE__/__LINE__/__COUNTER__`), and
- the **hash** `= FNV1a(name, offset)` with `hash_single(v,c) = (v ^ c) * 0x1000193`.

At runtime LazyImporter walks the PEB loader list and every module's export table,
hashing each export name with that offset and comparing to the stored hash. No
name strings, no IAT entries nothing to grep for.

## How the resolver recovers them

Both constants survive `/O2` as immediates with recognisable opcodes (confirmed by
disassembly of a LazyImporter build):

```asm
41 B9 17 3E 3F C2     mov   r9d, 0C23F3E17h     ; OFFSET  (seed / accumulator init)
...                   imul  r9d, ecx, 1000193h  ; the FNV loop
41 81 F9 BE 75 64 99  cmp   r9d, 996475BEh      ; HASH    (compare constant)
```

So the resolver:

1. **Builds a dictionary** of export names from the System32 DLLs (`ntdll`,
   `kernel32`, `kernelbase`, `user32`, `advapi32`, …) those are the strings
   LazyImporter hashes.
2. **Harvests immediates** from executable sections, split by opcode:
   `mov r32, imm32` offset candidates; `cmp r32, imm32` (`81 /7` or `3D`) hash
   candidates, each with its byte position.
3. **Matches**: for every offset `O` and every dictionary name `N`, checks whether
   `FNV1a(N, O)` is a harvested hash immediate.
4. **Confirms by locality**: the hash's `cmp` must sit just after the offset's
   `mov` (within a small byte window). The opcode + FNV + locality combination
   makes HIGH-confidence hits essentially free of false positives.

The FNV implementation in [`resolver/fnv.hpp`](resolver/fnv.hpp) mirrors
[`lazy_importer.hpp`](lazy_importer-master/include/lazy_importer.hpp) bit-for-bit.
`LI_MODULE` hashes (module names like `kernel32.dll`) are recovered the same way.

## Usage

```bash
build\resolver.exe <target.exe> [options]
```

The only argument you normally need is the target path the rest are optional.

| option | meaning |
| --- | --- |
| `--dll <name>` | add an extra DLL to the dictionary, e.g. `--dll wininet.dll` (repeatable) |
| `--ci` | case-insensitive hashing (`LAZY_IMPORTER_CASE_INSENSITIVE`) |
| `--dlls-dir <path>` | export-dictionary source (default `C:\Windows\System32`) |
| `--names-only` | print one recovered name per line (for scripting/diffing) |
| `--json` | machine-readable output (if you wanted to make for example IDA script) |

Example output:

```
Target      : build\target_app.exe (x64)
Dictionary  : 10985 names from 14 modules (C:\Windows\System32)
Immediates  : 461 mov (seed) / 165 cmp (hash) candidates in exec sections
Hash mode   : case-sensitive

Recovered imports (22)
  NAME                 MODULE                       OFFSET      HASH        SITES
  VirtualAlloc         kernel32.dll,kernelbase.dll  0x5C0F3DAD  0x4B223E99  2
  MessageBoxA          user32.dll                   0xAA989ABB  0xE210515A  1
  ...
Summary: 22 hidden imports recovered.
```

`SITES` is the number of distinct call sites that resolved that function. Every
result is opcode + locality confirmed, so false positives are practically nil.
