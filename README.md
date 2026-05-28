# HvShield

HvShield is a defensive security research prototype for hypervisor-based memory
integrity monitoring on Windows x64. It explores how Intel VT-x and Extended
Page Tables can be used to observe and restrict access to protected kernel
memory pages from below the operating system.

The project is intentionally scoped as research code. It is useful for studying
VMX setup, VMCS state, EPT construction, and EPT-violation based detection. It is
not a production driver and it is not intended to be used outside an authorized
lab environment.

## What is implemented

- VMX support checks through CPUID and VMX capability MSRs
- VMXON region allocation and VMX entry bootstrap helpers
- VMCS field definitions and minimum VMCS setup scaffolding
- Identity-mapped EPT construction with 2 MB pages
- MTRR-aware EPT memory type selection for variable MTRR ranges
- EPT structure definitions for PML4, PDPT, PD, and PT entries
- Protected-page metadata and EPT permission control primitives

## Defensive research goals

HvShield is designed around defensive memory integrity use cases:

- detecting writes to protected kernel code pages
- experimenting with EPT-backed monitoring of sensitive memory regions
- studying rootkit-style memory modification from a hypervisor perspective
- validating VMCS and EPT behavior in a controlled Windows lab

## Current status

This repository is an early source snapshot. The VMX and EPT core are present,
but several pieces required for a stable production VMM are intentionally called
out as unfinished in the source:

- full guest state save and restore is not complete
- multi-processor launch and scheduling are not implemented
- INVEPT after EPT changes is not implemented
- fixed-range MTRR handling is incomplete
- no hardened policy engine, telemetry pipeline, or installer is included

## Build notes

Requirements for integrating the code into a local driver project:

- Visual Studio 2022
- Windows Driver Kit 10.0.22621.0 or later
- x64 target
- test-signing enabled in a lab VM

This public repository currently contains the core source files, not a complete
WDK solution. To build it, import `src/vmx.c`, `src/ept.c`, and
`src/hvshield.h` into a WDM/KMDF driver project and compile for x64.

## Responsible use

This project is for defensive security research, education, and authorized lab
testing only. It does not include exploitation, persistence, evasion, or
deployment tooling.

## Related writeups

- [VMCS by Practice](https://iwishi808.github.io/2026/05/20/vmcs-by-practice/)
- [EPT Internals](https://iwishi808.github.io/2026/05/18/ept-internals/)

## License

MIT
