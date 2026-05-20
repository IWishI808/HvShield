/*
 * vmx.c - VMX bootstrap and VM-exit handling for HvShield.
 *
 * Handles VMXON, VMCS setup, and basic VM-exit dispatch.
 * This is the minimum needed to get a hypervisor running; many VMCS fields
 * are stubbed or set to defaults.
 *
 * TODO: Full guest state save/restore (currently missing segment limits,
 *       access rights, GDTR, IDTR, etc.)
 * TODO: Multi-processor support (run vmx_init on each logical processor)
 * TODO: NMI windowing for safe NMI re-injection
 * TODO: MSR bitmap allocation (currently not filtering MSR exits)
 */

#include "hvshield.h"

/* Intrinsics for VMX instructions - MSVC-specific */
extern unsigned char __vmx_on(unsigned long long *);
extern unsigned char __vmx_vmptrld(unsigned long long *);
extern unsigned char __vmx_vmclear(unsigned long long *);
extern unsigned char __vmx_vmread(size_t, size_t *);
extern unsigned char __vmx_vmwrite(size_t, size_t);
extern void __vmx_off(void);

/* --------------------------------------------------------------------------
 * Helpers
 * -------------------------------------------------------------------------- */

static ULONG
vmx_adjust_controls(
    _In_ ULONG RequestedControls,
    _In_ ULONG MsrAddress
)
{
    /*
     * Intel SDM Vol. 3C, 31.5.1 - Algorithms for determining VMX capabilities.
     * For each control bit:
     *   - If bit is 1 in the allowed-1 (high 32 bits), it CAN be 1
     *   - If bit is 1 in the allowed-0 (low 32 bits), it MUST be 1
     * Result = (requested | must_be_1) & can_be_1
     */
    LARGE_INTEGER msr;

    msr.QuadPart = __readmsr(MsrAddress);

    RequestedControls |= msr.LowPart;      /* must-be-1 bits */
    RequestedControls &= msr.HighPart;     /* can-be-1 bits */

    return RequestedControls;
}

static PVOID
vmx_alloc_contiguous_page(
    _Out_ PPHYSICAL_ADDRESS PhysAddr
)
{
    PHYSICAL_ADDRESS low, high, boundary;
    PVOID va;

    low.QuadPart = 0;
    high.QuadPart = ~0ULL;
    boundary.QuadPart = 0;

    va = MmAllocateContiguousMemorySpecifyCache(
        PAGE_SIZE,
        low,
        high,
        boundary,
        MmCached
    );

    if (!va)
        return NULL;

    RtlZeroMemory(va, PAGE_SIZE);
    *PhysAddr = MmGetPhysicalAddress(va);
    return va;
}

/* --------------------------------------------------------------------------
 * VMX Support Check
 * -------------------------------------------------------------------------- */

NTSTATUS
vmx_check_support(VOID)
{
    int cpuInfo[4];
    ULONG64 featureControl;
    ULONG64 vmxBasic;
    ULONG vmcsSize;
    ULONG64 procBased2;
    ULONG64 eptVpidCap;

    /* Check CPUID.1:ECX.VMX[bit 5] */
    __cpuid(cpuInfo, 1);
    if (!(cpuInfo[2] & (1 << 5))) {
        DbgPrint("[HvShield] VMX not supported by processor\n");
        return STATUS_NOT_SUPPORTED;
    }

    /* Check IA32_FEATURE_CONTROL MSR */
    featureControl = __readmsr(MSR_IA32_FEATURE_CONTROL);

    if (!(featureControl & FEATURE_CONTROL_LOCKED)) {
        /*
         * BIOS did not lock the feature control MSR. We could lock it
         * ourselves but that is risky on production systems.
         */
        DbgPrint("[HvShield] IA32_FEATURE_CONTROL not locked by BIOS\n");
        return STATUS_NOT_SUPPORTED;
    }

    if (!(featureControl & FEATURE_CONTROL_VMXON_OUTSIDE_SMX)) {
        DbgPrint("[HvShield] VMXON outside SMX not enabled in BIOS\n");
        return STATUS_NOT_SUPPORTED;
    }

    /* Read VMX basic capabilities */
    vmxBasic = __readmsr(MSR_IA32_VMX_BASIC);

    /* Check VMCS revision ID and region size (bits 44:32 = VMCS size) */
    vmcsSize = (ULONG)((vmxBasic >> 32) & 0x1FFF);
    if (vmcsSize > PAGE_SIZE) {
        DbgPrint("[HvShield] VMCS region size %u exceeds PAGE_SIZE\n", vmcsSize);
        return STATUS_NOT_SUPPORTED;
    }

    /* Check for EPT and VPID support */
    procBased2 = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS2);
    if (!((procBased2 >> 32) & CPU_BASED_2ND_EXEC_ENABLE_EPT)) {
        DbgPrint("[HvShield] EPT not supported\n");
        return STATUS_NOT_SUPPORTED;
    }

    /* Check EPT capabilities */
    eptVpidCap = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);

    /* Bit 6: page-walk length 4, bit 14: WB memory type for EPT */
    if (!(eptVpidCap & (1ULL << 6))) {
        DbgPrint("[HvShield] EPT 4-level page walk not supported\n");
        return STATUS_NOT_SUPPORTED;
    }
    if (!(eptVpidCap & (1ULL << 14))) {
        DbgPrint("[HvShield] EPT WB memory type not supported\n");
        return STATUS_NOT_SUPPORTED;
    }
    /* Bit 16: 2MB pages */
    if (!(eptVpidCap & (1ULL << 16))) {
        DbgPrint("[HvShield] EPT 2MB large pages not supported\n");
        return STATUS_NOT_SUPPORTED;
    }

    DbgPrint("[HvShield] VMX support verified, VMCS revision = 0x%X\n",
             (ULONG)(vmxBasic & 0x7FFFFFFF));

    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * VMX Initialization (VMXON)
 * -------------------------------------------------------------------------- */

NTSTATUS
vmx_init(
    _Out_ PVMX_CONTEXT VmxCtx
)
{
    ULONG64 vmxBasic;
    ULONG revisionId;
    ULONG64 cr4;
    unsigned char vmxResult;

    RtlZeroMemory(VmxCtx, sizeof(VMX_CONTEXT));

    /* Read revision ID from IA32_VMX_BASIC */
    vmxBasic = __readmsr(MSR_IA32_VMX_BASIC);
    revisionId = (ULONG)(vmxBasic & 0x7FFFFFFF);

    /* Allocate VMXON region - must be 4K aligned, in contiguous physical memory */
    VmxCtx->VmxonRegion = vmx_alloc_contiguous_page(&VmxCtx->VmxonRegionPhys);
    if (!VmxCtx->VmxonRegion) {
        DbgPrint("[HvShield] Failed to allocate VMXON region\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Write VMCS revision ID to first 4 bytes of VMXON region */
    *(PULONG)VmxCtx->VmxonRegion = revisionId;

    /*
     * Set CR4.VMXE before executing VMXON.
     * We also need to ensure CR0 and CR4 satisfy the fixed bits
     * from IA32_VMX_CR0_FIXED0/1 and IA32_VMX_CR4_FIXED0/1.
     */
    cr4 = __readcr4();
    __writecr4(cr4 | CR4_VMXE);

    /*
     * TODO: Adjust CR0 per IA32_VMX_CR0_FIXED0/1.
     * In practice, the kernel already has the right bits set, but we
     * should verify to be safe.
     */

    /* Execute VMXON */
    vmxResult = __vmx_on(&VmxCtx->VmxonRegionPhys.QuadPart);
    if (vmxResult != 0) {
        DbgPrint("[HvShield] VMXON failed with result %u\n", vmxResult);
        __writecr4(cr4); /* restore CR4 */
        MmFreeContiguousMemory(VmxCtx->VmxonRegion);
        VmxCtx->VmxonRegion = NULL;
        return STATUS_UNSUCCESSFUL;
    }

    VmxCtx->VmxEnabled = TRUE;
    DbgPrint("[HvShield] VMXON successful, revision ID = 0x%X\n", revisionId);

    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * VMCS Setup
 * --------------------------------------------------------------------------
 * Allocate VMCS, write revision ID, VMPTRLD, then populate fields.
 *
 * This is intentionally minimal - just enough to not #GP on VMLAUNCH.
 * Many fields are set to 0 or default values. A real implementation needs
 * full guest/host state setup matching the current CPU state.
 */

NTSTATUS
vmcs_setup(
    _Inout_ PVMX_CONTEXT VmxCtx,
    _In_ PEPT_STATE EptState
)
{
    ULONG64 vmxBasic;
    ULONG revisionId;
    unsigned char result;
    ULONG pinBased, primaryProcBased, secondaryProcBased;
    ULONG exitControls, entryControls;

    if (!VmxCtx->VmxEnabled)
        return STATUS_INVALID_DEVICE_STATE;

    vmxBasic = __readmsr(MSR_IA32_VMX_BASIC);
    revisionId = (ULONG)(vmxBasic & 0x7FFFFFFF);

    /* Allocate VMCS region */
    VmxCtx->VmcsRegion = vmx_alloc_contiguous_page(&VmxCtx->VmcsRegionPhys);
    if (!VmxCtx->VmcsRegion) {
        DbgPrint("[HvShield] Failed to allocate VMCS region\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Write revision ID */
    *(PULONG)VmxCtx->VmcsRegion = revisionId;

    /* VMCLEAR first (required before VMPTRLD on a new VMCS) */
    result = __vmx_vmclear(&VmxCtx->VmcsRegionPhys.QuadPart);
    if (result != 0) {
        DbgPrint("[HvShield] VMCLEAR failed: %u\n", result);
        return STATUS_UNSUCCESSFUL;
    }

    /* VMPTRLD - make this the current VMCS */
    result = __vmx_vmptrld(&VmxCtx->VmcsRegionPhys.QuadPart);
    if (result != 0) {
        DbgPrint("[HvShield] VMPTRLD failed: %u\n", result);
        return STATUS_UNSUCCESSFUL;
    }

    /* --- Control fields --- */

    /* Pin-based controls: nothing special needed */
    pinBased = vmx_adjust_controls(0, MSR_IA32_VMX_PINBASED_CTLS);
    __vmx_vmwrite(VMCS_CTRL_PIN_BASED_EXEC, pinBased);

    /* Primary processor-based: enable secondary controls */
    primaryProcBased = vmx_adjust_controls(
        CPU_BASED_ACTIVATE_SECONDARY_CONTROLS,
        MSR_IA32_VMX_PROCBASED_CTLS
    );
    __vmx_vmwrite(VMCS_CTRL_PRIMARY_PROC_BASED_EXEC, primaryProcBased);

    /* Secondary processor-based: enable EPT */
    secondaryProcBased = vmx_adjust_controls(
        CPU_BASED_2ND_EXEC_ENABLE_EPT,
        MSR_IA32_VMX_PROCBASED_CTLS2
    );
    __vmx_vmwrite(VMCS_CTRL_SECONDARY_PROC_BASED_EXEC, secondaryProcBased);

    /*
     * VM-exit controls: host address-space size (bit 9) for 64-bit host.
     * VM-entry controls: IA-32e mode guest (bit 9) for 64-bit guest.
     */
    exitControls = vmx_adjust_controls(
        (1UL << 9),    /* Host address-space size */
        MSR_IA32_VMX_EXIT_CTLS
    );
    __vmx_vmwrite(VMCS_CTRL_VMEXIT_CONTROLS, exitControls);

    entryControls = vmx_adjust_controls(
        (1UL << 9),    /* IA-32e mode guest */
        MSR_IA32_VMX_ENTRY_CTLS
    );
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_CONTROLS, entryControls);

    /* EPT pointer */
    __vmx_vmwrite(VMCS_CTRL_EPT_POINTER, EptState->EptPointer.Value);

    /* Exception bitmap: 0 = do not intercept any exceptions */
    __vmx_vmwrite(VMCS_CTRL_EXCEPTION_BITMAP, 0);

    /* MSR load/store counts = 0 */
    __vmx_vmwrite(VMCS_CTRL_VMEXIT_MSR_STORE_COUNT, 0);
    __vmx_vmwrite(VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT, 0);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT, 0);

    /*
     * TODO: Set up host state fields (CR0, CR3, CR4, segment selectors,
     *       RSP, RIP, GDTR, IDTR, TR, etc.)
     *
     * TODO: Set up guest state fields to match current CPU state
     *       (this is the tricky part - need to read current state and
     *       mirror it so the guest starts executing where we left off)
     *
     * TODO: Allocate and set MSR bitmap to reduce MSR-access exits
     *
     * For now, we just set the control fields and EPT. The caller is
     * responsible for filling in guest/host state before VMLAUNCH.
     */

    /* Minimal host state that we can set here */
    __vmx_vmwrite(VMCS_HOST_CR0, __readcr0());
    __vmx_vmwrite(VMCS_HOST_CR3, __readcr3());
    __vmx_vmwrite(VMCS_HOST_CR4, __readcr4());

    /*
     * Host RIP = our vmexit handler entry point.
     * Host RSP = needs a dedicated host stack.
     * Both are set to 0 here as placeholders.
     *
     * TODO: allocate host stack, set Host RSP
     * TODO: set Host RIP to vmexit_handler_asm (assembly entry point that
     *       saves registers and calls vmexit_handler)
     */
    __vmx_vmwrite(VMCS_HOST_RIP, 0);  /* MUST be set before VMLAUNCH */
    __vmx_vmwrite(VMCS_HOST_RSP, 0);  /* MUST be set before VMLAUNCH */

    /*
     * Host segment selectors - read from current state.
     * Must be loaded with valid selectors (RPL=0, TI=0 for most).
     */
    {
        USHORT cs, ss, ds, es, fs, gs, tr;

        cs = __readcs();
        ss = __readss();
        ds = __readds();
        es = __reades();
        fs = __readfs();
        gs = __readgs();
        tr = __readtr();

        __vmx_vmwrite(VMCS_HOST_CS_SELECTOR, cs & 0xFFF8);
        __vmx_vmwrite(VMCS_HOST_SS_SELECTOR, ss & 0xFFF8);
        __vmx_vmwrite(VMCS_HOST_DS_SELECTOR, ds & 0xFFF8);
        __vmx_vmwrite(VMCS_HOST_ES_SELECTOR, es & 0xFFF8);
        __vmx_vmwrite(VMCS_HOST_FS_SELECTOR, fs & 0xFFF8);
        __vmx_vmwrite(VMCS_HOST_GS_SELECTOR, gs & 0xFFF8);
        __vmx_vmwrite(VMCS_HOST_TR_SELECTOR, tr & 0xFFF8);
    }

    DbgPrint("[HvShield] VMCS setup complete (minimal - see TODOs)\n");

    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * VM-Exit Handler (C dispatch)
 * --------------------------------------------------------------------------
 * In a real implementation, the assembly entry point saves all GPRs to a
 * struct and passes it here. We would also need to handle resume (VMRESUME)
 * after processing the exit.
 *
 * TODO: This needs an assembly stub (vmexit_entry.asm) that:
 *   1. Pushes all GPRs
 *   2. Calls this function
 *   3. Pops all GPRs
 *   4. Executes VMRESUME
 *   5. Handles VMRESUME failure
 */

VOID
vmexit_handler(
    VOID  /* TODO: pass saved guest register state */
)
{
    size_t exitReason = 0;
    size_t exitQualification = 0;
    size_t guestPhysAddr = 0;

    __vmx_vmread(VMCS_EXIT_REASON, &exitReason);
    exitReason &= 0xFFFF;  /* Low 16 bits are the basic exit reason */

    switch (exitReason) {
    case EXIT_REASON_EPT_VIOLATION:
        __vmx_vmread(VMCS_EXIT_QUALIFICATION, &exitQualification);
        __vmx_vmread((size_t)VMCS_EXIT_GUEST_PHYSICAL_ADDR, &guestPhysAddr);

        /*
         * TODO: Need access to the global EPT state here.
         * In practice this would be stored in a per-processor context
         * accessible via a known GS-relative address or similar mechanism.
         */

        /* ept_handle_violation(&g_EptState, exitQualification, guestPhysAddr); */
        DbgPrint("[HvShield] EPT violation: reason=%llu qual=0x%llX gpa=0x%llX\n",
                 (ULONG64)exitReason, (ULONG64)exitQualification, (ULONG64)guestPhysAddr);
        break;

    case EXIT_REASON_EPT_MISCONFIG:
        /*
         * EPT misconfiguration = our EPT tables have invalid entries.
         * This is always a bug in our code. Log and halt.
         */
        __vmx_vmread((size_t)VMCS_EXIT_GUEST_PHYSICAL_ADDR, &guestPhysAddr);
        DbgPrint("[HvShield] FATAL: EPT misconfiguration at GPA 0x%llX\n",
                 (ULONG64)guestPhysAddr);

        /* TODO: graceful shutdown instead of letting guest hang */
        break;

    case EXIT_REASON_CPUID:
        /*
         * TODO: Emulate CPUID. For a transparent hypervisor, we would execute
         * CPUID natively and filter certain leaves (e.g., hide hypervisor
         * present bit, mask VMX capability bits).
         */
        DbgPrint("[HvShield] CPUID exit (not handled)\n");
        break;

    case EXIT_REASON_VMCALL:
        /*
         * Hypercall interface. Could be used for:
         *   - Usermode monitor requesting page protection changes
         *   - Guest driver communicating with the hypervisor
         *
         * TODO: Define hypercall ABI and dispatch table.
         */
        DbgPrint("[HvShield] VMCALL (hypercall not implemented)\n");
        break;

    case EXIT_REASON_CR_ACCESS:
        /*
         * TODO: Handle CR0/CR3/CR4 accesses if we intercept them.
         * Needed for shadowing CR3 changes or enforcing CR0.WP.
         */
        DbgPrint("[HvShield] CR access exit (not handled)\n");
        break;

    case EXIT_REASON_MSR_READ:
    case EXIT_REASON_MSR_WRITE:
        /*
         * TODO: Handle MSR reads/writes. Should at minimum handle
         * IA32_EFER for long mode transitions and IA32_FEATURE_CONTROL
         * to hide VMX capability from the guest.
         */
        DbgPrint("[HvShield] MSR %s exit (not handled)\n",
                 exitReason == EXIT_REASON_MSR_READ ? "read" : "write");
        break;

    case EXIT_REASON_TRIPLE_FAULT:
        DbgPrint("[HvShield] FATAL: Triple fault in guest\n");
        /* TODO: Dump guest state for debugging */
        break;

    case EXIT_REASON_XSETBV:
        /*
         * TODO: Execute XSETBV on behalf of the guest.
         * Pass through XCR0 writes after validation.
         */
        break;

    default:
        DbgPrint("[HvShield] Unhandled VM-exit reason: %llu\n", (ULONG64)exitReason);
        break;
    }

    /*
     * After handling the exit, we would normally:
     *   1. Advance guest RIP past the faulting instruction (for some exits)
     *   2. VMRESUME to re-enter the guest
     *
     * This is handled in the assembly stub, not here.
     */
}

/* --------------------------------------------------------------------------
 * VMX Teardown
 * -------------------------------------------------------------------------- */

VOID
vmx_teardown(
    _Inout_ PVMX_CONTEXT VmxCtx
)
{
    if (!VmxCtx->VmxEnabled)
        return;

    /* VMXOFF */
    __vmx_off();
    VmxCtx->VmxEnabled = FALSE;

    /* Restore CR4.VMXE = 0 */
    __writecr4(__readcr4() & ~CR4_VMXE);

    if (VmxCtx->VmcsRegion) {
        MmFreeContiguousMemory(VmxCtx->VmcsRegion);
        VmxCtx->VmcsRegion = NULL;
    }

    if (VmxCtx->VmxonRegion) {
        MmFreeContiguousMemory(VmxCtx->VmxonRegion);
        VmxCtx->VmxonRegion = NULL;
    }

    DbgPrint("[HvShield] VMX teardown complete\n");
}
