# HvShield

Hypervisor-based memory integrity monitor using Intel VT-x and EPT (Extended Page Tables).

Monitors and enforces page-level read/write/execute permissions on physical memory regions from outside the OS kernel. Intended for detecting rootkits, code injection, and unauthorized memory modifications on protected pages.

## How it works

1. Enables VMX operation and launches the host OS as a guest in VMX non-root mode
2. Builds an identity-mapped EPT structure (using 2MB large pages by default, splitting to 4K where fine-grained control is needed)
3. Marks protected physical pages with restricted EPT permissions
4. EPT violations on protected pages trap into the VMM, which logs the violation and optionally injects an exception back into the guest

## Current status

Early development. VMX bootstrap and EPT core are functional. VMCS setup covers the minimum fields needed to launch. No guest state save/restore yet, no multi-processor support.

## Build

Requirements:
- Visual Studio 2022
- Windows Driver Kit (WDK) 10.0.22621.0 or later
- x64 target only (no x86, no ARM)

Build from VS developer command prompt:

```
msbuild HvShield.sln /p:Configuration=Release /p:Platform=x64
```

Or open `HvShield.sln` in Visual Studio and build the driver project.

## License

None yet. Do not redistribute.
