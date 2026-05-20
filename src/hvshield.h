#pragma once

#include <ntddk.h>

/*
 * hvshield.h - Core definitions for HvShield hypervisor memory integrity monitor.
 *
 * References:
 *   Intel SDM Vol. 3C, Chapter 24 (VMX) and Chapter 28 (EPT)
 *   See specifically Table 28-1 through 28-6 for EPT structure formats.
 */

/* --------------------------------------------------------------------------
 * EPT Structures
 * --------------------------------------------------------------------------
 * Identity mapped. We use 2MB large pages for the bulk of physical memory
 * and split down to 4K pages only for regions needing per-page permission
 * control (protected pages).
 */

typedef union _EPT_PML4E {
    ULONG64 Value;
    struct {
        ULONG64 Read            : 1;    /* [0]  */
        ULONG64 Write           : 1;    /* [1]  */
        ULONG64 Execute         : 1;    /* [2]  */
        ULONG64 Reserved0       : 5;    /* [3:7]  MBZ */
        ULONG64 Accessed        : 1;    /* [8]  */
        ULONG64 Ignored0        : 1;    /* [9]  */
        ULONG64 ExecuteForUserMode : 1; /* [10] */
        ULONG64 Ignored1        : 1;    /* [11] */
        ULONG64 PhysAddr        : 40;   /* [12:51] PFN of PDPT */
        ULONG64 Ignored2        : 12;   /* [52:63] */
    };
} EPT_PML4E, *PEPT_PML4E;

typedef union _EPT_PDPTE {
    ULONG64 Value;
    struct {
        ULONG64 Read            : 1;
        ULONG64 Write           : 1;
        ULONG64 Execute         : 1;
        ULONG64 Reserved0       : 5;
        ULONG64 Accessed        : 1;
        ULONG64 Ignored0        : 1;
        ULONG64 ExecuteForUserMode : 1;
        ULONG64 Ignored1        : 1;
        ULONG64 PhysAddr        : 40;   /* PFN of PD */
        ULONG64 Ignored2        : 12;
    };
} EPT_PDPTE, *PEPT_PDPTE;

/* Page Directory Entry - can be either 2MB large page or pointer to PT */
typedef union _EPT_PDE {
    ULONG64 Value;
    struct {
        ULONG64 Read            : 1;
        ULONG64 Write           : 1;
        ULONG64 Execute         : 1;
        ULONG64 MemoryType      : 3;    /* [3:5] for large pages only */
        ULONG64 IgnorePAT       : 1;    /* [6] for large pages only */
        ULONG64 LargePage       : 1;    /* [7] 1 = maps 2MB page */
        ULONG64 Accessed        : 1;
        ULONG64 Dirty           : 1;    /* [9] for large pages only */
        ULONG64 ExecuteForUserMode : 1;
        ULONG64 Ignored0        : 1;
        ULONG64 Reserved0       : 9;    /* [12:20] MBZ for large pages */
        ULONG64 PhysAddr        : 31;   /* [21:51] PFN of 2MB page */
        ULONG64 Ignored1        : 12;
    } LargePageFormat;
    struct {
        ULONG64 Read            : 1;
        ULONG64 Write           : 1;
        ULONG64 Execute         : 1;
        ULONG64 Reserved0       : 4;
        ULONG64 LargePage       : 1;    /* [7] 0 = pointer to PT */
        ULONG64 Accessed        : 1;
        ULONG64 Ignored0        : 1;
        ULONG64 ExecuteForUserMode : 1;
        ULONG64 Ignored1        : 1;
        ULONG64 PhysAddr        : 40;   /* [12:51] PFN of PT */
        ULONG64 Ignored2        : 12;
    } PageTableFormat;
} EPT_PDE, *PEPT_PDE;

typedef union _EPT_PTE {
    ULONG64 Value;
    struct {
        ULONG64 Read            : 1;
        ULONG64 Write           : 1;
        ULONG64 Execute         : 1;
        ULONG64 MemoryType      : 3;    /* [3:5] EPT memory type */
        ULONG64 IgnorePAT       : 1;    /* [6] */
        ULONG64 Ignored0        : 1;    /* [7] */
        ULONG64 Accessed        : 1;
        ULONG64 Dirty           : 1;
        ULONG64 ExecuteForUserMode : 1;
        ULONG64 Ignored1        : 1;
        ULONG64 PhysAddr        : 40;   /* [12:51] PFN of 4K page */
        ULONG64 Ignored2        : 5;    /* [52:56] */
        ULONG64 VerifyGuestPaging : 1;  /* [57] */
        ULONG64 PagingWriteAccess : 1;  /* [58] */
        ULONG64 Ignored3        : 1;    /* [59] */
        ULONG64 SupervisorShadowStack : 1; /* [60] */
        ULONG64 SubPageWritePerm : 1;   /* [61] */
        ULONG64 Ignored4        : 1;    /* [62] */
        ULONG64 SuppressVE      : 1;    /* [63] */
    };
} EPT_PTE, *PEPT_PTE;

/* EPT pointer (written to VMCS) */
typedef union _EPT_POINTER {
    ULONG64 Value;
    struct {
        ULONG64 MemoryType      : 3;    /* 0 = UC, 6 = WB */
        ULONG64 PageWalkLength  : 3;    /* Must be 3 (4-level walk - 1) */
        ULONG64 DirtyAndAccessEnabled : 1;
        ULONG64 EnforcementOfAccessRights : 1;
        ULONG64 Reserved0       : 4;
        ULONG64 PML4PhysAddr    : 40;   /* PFN of PML4 table */
        ULONG64 Reserved1       : 12;
    };
} EPT_POINTER, *PEPT_POINTER;

/* --------------------------------------------------------------------------
 * VMCS Field Encodings (subset we actually use)
 * --------------------------------------------------------------------------
 * Intel SDM Vol. 3C, Appendix B
 */

/* 16-bit control fields */
#define VMCS_CTRL_VPID                      0x00000000

/* 64-bit control fields */
#define VMCS_CTRL_EPT_POINTER               0x0000201A
#define VMCS_CTRL_IO_BITMAP_A               0x00002000
#define VMCS_CTRL_IO_BITMAP_B               0x00002002
#define VMCS_CTRL_MSR_BITMAP                0x00002004

/* 32-bit control fields */
#define VMCS_CTRL_PIN_BASED_EXEC            0x00004000
#define VMCS_CTRL_PRIMARY_PROC_BASED_EXEC   0x00004002
#define VMCS_CTRL_EXCEPTION_BITMAP          0x00004004
#define VMCS_CTRL_VMEXIT_CONTROLS           0x0000400C
#define VMCS_CTRL_VMEXIT_MSR_STORE_COUNT    0x0000400E
#define VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT     0x00004010
#define VMCS_CTRL_VMENTRY_CONTROLS          0x00004012
#define VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT    0x00004014
#define VMCS_CTRL_VMENTRY_INTERRUPT_INFO     0x00004016
#define VMCS_CTRL_SECONDARY_PROC_BASED_EXEC 0x0000401E

/* 64-bit read-only fields */
#define VMCS_EXIT_GUEST_PHYSICAL_ADDR       0x00002400

/* 32-bit read-only fields */
#define VMCS_EXIT_REASON                    0x00004402
#define VMCS_EXIT_QUALIFICATION             0x00006400
#define VMCS_EXIT_INTERRUPT_INFO            0x00004404
#define VMCS_EXIT_INTERRUPT_ERROR_CODE      0x00004406
#define VMCS_EXIT_INSTRUCTION_LENGTH        0x0000440C

/* Natural-width guest state */
#define VMCS_GUEST_CR0                      0x00006800
#define VMCS_GUEST_CR3                      0x00006802
#define VMCS_GUEST_CR4                      0x00006804
#define VMCS_GUEST_RSP                      0x0000681C
#define VMCS_GUEST_RIP                      0x0000681E
#define VMCS_GUEST_RFLAGS                   0x00006820

/* Natural-width host state */
#define VMCS_HOST_CR0                       0x00006C00
#define VMCS_HOST_CR3                       0x00006C02
#define VMCS_HOST_CR4                       0x00006C04
#define VMCS_HOST_RSP                       0x00006C14
#define VMCS_HOST_RIP                       0x00006C16

/* Guest segment selectors */
#define VMCS_GUEST_CS_SELECTOR              0x00000802
#define VMCS_GUEST_SS_SELECTOR              0x00000804
#define VMCS_GUEST_DS_SELECTOR              0x00000806
#define VMCS_GUEST_ES_SELECTOR              0x00000808
#define VMCS_GUEST_FS_SELECTOR              0x0000080A
#define VMCS_GUEST_GS_SELECTOR              0x0000080C
#define VMCS_GUEST_TR_SELECTOR              0x0000080E
#define VMCS_GUEST_LDTR_SELECTOR            0x00000810

/* Host segment selectors */
#define VMCS_HOST_CS_SELECTOR               0x00000C02
#define VMCS_HOST_SS_SELECTOR               0x00000C04
#define VMCS_HOST_DS_SELECTOR               0x00000C06
#define VMCS_HOST_ES_SELECTOR               0x00000C08
#define VMCS_HOST_FS_SELECTOR               0x00000C0A
#define VMCS_HOST_GS_SELECTOR              0x00000C0C
#define VMCS_HOST_TR_SELECTOR               0x00000C0E

/* --------------------------------------------------------------------------
 * VM-Exit Reasons
 * -------------------------------------------------------------------------- */

#define EXIT_REASON_EXCEPTION_NMI           0
#define EXIT_REASON_EXTERNAL_INTERRUPT      1
#define EXIT_REASON_TRIPLE_FAULT            2
#define EXIT_REASON_CPUID                   10
#define EXIT_REASON_HLT                     12
#define EXIT_REASON_INVD                    13
#define EXIT_REASON_VMCALL                  18
#define EXIT_REASON_CR_ACCESS               28
#define EXIT_REASON_MSR_READ                31
#define EXIT_REASON_MSR_WRITE               32
#define EXIT_REASON_EPT_VIOLATION           48
#define EXIT_REASON_EPT_MISCONFIG           49
#define EXIT_REASON_XSETBV                  55

/* --------------------------------------------------------------------------
 * EPT Violation Exit Qualification Bits
 * --------------------------------------------------------------------------
 * Intel SDM Vol. 3C, Table 27-7
 */

#define EPT_VIOLATION_READ                  (1ULL << 0)
#define EPT_VIOLATION_WRITE                 (1ULL << 1)
#define EPT_VIOLATION_EXECUTE               (1ULL << 2)
#define EPT_VIOLATION_GPA_READABLE          (1ULL << 3)
#define EPT_VIOLATION_GPA_WRITEABLE         (1ULL << 4)
#define EPT_VIOLATION_GPA_EXECUTABLE        (1ULL << 5)
#define EPT_VIOLATION_GPA_USER_EXECUTABLE   (1ULL << 6)
#define EPT_VIOLATION_GUEST_LINEAR_VALID    (1ULL << 7)
#define EPT_VIOLATION_CAUSED_BY_TRANSLATION (1ULL << 8)
#define EPT_VIOLATION_USER_MODE_LINEAR      (1ULL << 9)
#define EPT_VIOLATION_RW_PAGE               (1ULL << 10)
#define EPT_VIOLATION_EXECUTE_DISABLED_PAGE (1ULL << 11)
#define EPT_VIOLATION_NMI_UNBLOCKING        (1ULL << 12)

/* --------------------------------------------------------------------------
 * MSR Definitions
 * -------------------------------------------------------------------------- */

#define MSR_IA32_VMX_BASIC                  0x00000480
#define MSR_IA32_VMX_PINBASED_CTLS         0x00000481
#define MSR_IA32_VMX_PROCBASED_CTLS        0x00000482
#define MSR_IA32_VMX_EXIT_CTLS             0x00000483
#define MSR_IA32_VMX_ENTRY_CTLS            0x00000484
#define MSR_IA32_VMX_CR0_FIXED0            0x00000486
#define MSR_IA32_VMX_CR0_FIXED1            0x00000487
#define MSR_IA32_VMX_CR4_FIXED0            0x00000488
#define MSR_IA32_VMX_CR4_FIXED1            0x00000489
#define MSR_IA32_VMX_PROCBASED_CTLS2       0x0000048B
#define MSR_IA32_VMX_EPT_VPID_CAP         0x0000048C
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS    0x0000048D
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS   0x0000048E
#define MSR_IA32_VMX_TRUE_EXIT_CTLS        0x0000048F
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS       0x00000490
#define MSR_IA32_FEATURE_CONTROL           0x0000003A
#define MSR_IA32_MTRR_DEF_TYPE             0x000002FF
#define MSR_IA32_MTRR_PHYSBASE0            0x00000200
#define MSR_IA32_MTRR_PHYSMASK0            0x00000201
#define MSR_IA32_MTRRCAP                   0x000000FE

/* --------------------------------------------------------------------------
 * Processor Control Bits
 * -------------------------------------------------------------------------- */

/* Primary Processor-Based VM-Execution Controls */
#define CPU_BASED_ACTIVATE_SECONDARY_CONTROLS   (1UL << 31)

/* Secondary Processor-Based VM-Execution Controls */
#define CPU_BASED_2ND_EXEC_ENABLE_EPT           (1UL << 1)
#define CPU_BASED_2ND_EXEC_UNRESTRICTED_GUEST   (1UL << 7)
#define CPU_BASED_2ND_EXEC_ENABLE_VPID          (1UL << 5)

/* CR4 bits */
#define CR4_VMXE                                (1UL << 13)

/* IA32_FEATURE_CONTROL bits */
#define FEATURE_CONTROL_LOCKED                  (1ULL << 0)
#define FEATURE_CONTROL_VMXON_OUTSIDE_SMX       (1ULL << 2)

/* EPT memory types */
#define EPT_MEMORY_TYPE_UC                      0
#define EPT_MEMORY_TYPE_WC                      1
#define EPT_MEMORY_TYPE_WT                      4
#define EPT_MEMORY_TYPE_WP                      5
#define EPT_MEMORY_TYPE_WB                      6

/* --------------------------------------------------------------------------
 * HvShield Internal Structures
 * -------------------------------------------------------------------------- */

#define HVSHIELD_MAX_PROTECTED_PAGES    256
#define HVSHIELD_POOL_TAG               ((ULONG)0x53685664)  /* SHvd */

typedef struct _PROTECTED_PAGE_ENTRY {
    ULONG64         GuestPhysicalAddress;   /* GPA of the 4K page */
    BOOLEAN         Active;
    BOOLEAN         AllowRead;
    BOOLEAN         AllowWrite;
    BOOLEAN         AllowExecute;
    ULONG           ViolationCount;
} PROTECTED_PAGE_ENTRY, *PPROTECTED_PAGE_ENTRY;

typedef struct _VMX_CONTEXT {
    PVOID           VmxonRegion;            /* VMXON region VA */
    PHYSICAL_ADDRESS VmxonRegionPhys;
    PVOID           VmcsRegion;             /* VMCS region VA */
    PHYSICAL_ADDRESS VmcsRegionPhys;
    BOOLEAN         VmxEnabled;
} VMX_CONTEXT, *PVMX_CONTEXT;

typedef struct _EPT_STATE {
    EPT_POINTER     EptPointer;
    PEPT_PML4E      PML4;                  /* VA of PML4 table */
    PHYSICAL_ADDRESS PML4Phys;

    /* Protected page tracking */
    PROTECTED_PAGE_ENTRY ProtectedPages[HVSHIELD_MAX_PROTECTED_PAGES];
    ULONG           ProtectedPageCount;
    KSPIN_LOCK      ProtectedPagesLock;
} EPT_STATE, *PEPT_STATE;

/* --------------------------------------------------------------------------
 * MTRR State (for EPT memory type selection)
 * -------------------------------------------------------------------------- */

#define MTRR_MAX_VARIABLE_RANGES    16

typedef struct _MTRR_RANGE {
    ULONG64     Base;
    ULONG64     Mask;
    UCHAR       Type;
    BOOLEAN     Valid;
} MTRR_RANGE, *PMTRR_RANGE;

typedef struct _MTRR_STATE {
    UCHAR       DefaultType;
    BOOLEAN     Enabled;
    BOOLEAN     FixedEnabled;
    ULONG       VariableRangeCount;
    MTRR_RANGE  VariableRanges[MTRR_MAX_VARIABLE_RANGES];
} MTRR_STATE, *PMTRR_STATE;

/* --------------------------------------------------------------------------
 * Function Declarations
 * -------------------------------------------------------------------------- */

/* vmx.c */
NTSTATUS    vmx_check_support(VOID);
NTSTATUS    vmx_init(_Out_ PVMX_CONTEXT VmxCtx);
NTSTATUS    vmcs_setup(_Inout_ PVMX_CONTEXT VmxCtx, _In_ PEPT_STATE EptState);
VOID        vmx_teardown(_Inout_ PVMX_CONTEXT VmxCtx);

/* ept.c */
NTSTATUS    ept_initialize(_Out_ PEPT_STATE EptState);
NTSTATUS    ept_build_identity_map(_Inout_ PEPT_STATE EptState);
NTSTATUS    ept_set_page_permission(
                _Inout_ PEPT_STATE EptState,
                _In_ ULONG64 GuestPhysicalAddress,
                _In_ BOOLEAN AllowRead,
                _In_ BOOLEAN AllowWrite,
                _In_ BOOLEAN AllowExecute
            );
BOOLEAN     ept_handle_violation(
                _Inout_ PEPT_STATE EptState,
                _In_ ULONG64 ExitQualification,
                _In_ ULONG64 GuestPhysicalAddress
            );
VOID        ept_teardown(_Inout_ PEPT_STATE EptState);

/* MTRR helpers (ept.c) */
VOID        mtrr_initialize(_Out_ PMTRR_STATE MtrrState);
UCHAR       mtrr_get_memory_type(_In_ PMTRR_STATE MtrrState, _In_ ULONG64 PhysicalAddress);
