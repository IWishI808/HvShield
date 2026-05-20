/*
 * ept.c - Extended Page Table implementation for HvShield.
 *
 * Builds an identity-mapped EPT using 2MB large pages. Protected pages
 * are split down to 4K granularity so we can set per-page RWX permissions.
 *
 * TODO: INVEPT after EPT modifications (currently relying on VMFUNC or
 *       manual invalidation which is not implemented)
 * TODO: Handle MTRR fixed ranges (currently only variable ranges)
 * TODO: Support splitting 1GB pages if the processor supports them
 */

#include "hvshield.h"

/* We assume max 512GB physical address space for now.
 * That is 1 PML4 entry -> 512 PDPT entries -> 512 PD entries each.
 * Adjust HVSHIELD_MAX_PHYS_MEMORY_GB if you need more. */
#define HVSHIELD_MAX_PHYS_MEMORY_GB     512

static MTRR_STATE g_MtrrState = { 0 };

/* --------------------------------------------------------------------------
 * MTRR Handling
 * -------------------------------------------------------------------------- */

VOID
mtrr_initialize(
    _Out_ PMTRR_STATE MtrrState
)
{
    ULONG64 mtrrCap;
    ULONG64 mtrrDefType;
    ULONG   i;

    RtlZeroMemory(MtrrState, sizeof(MTRR_STATE));

    mtrrCap = __readmsr(MSR_IA32_MTRRCAP);
    MtrrState->VariableRangeCount = (ULONG)(mtrrCap & 0xFF);
    if (MtrrState->VariableRangeCount > MTRR_MAX_VARIABLE_RANGES)
        MtrrState->VariableRangeCount = MTRR_MAX_VARIABLE_RANGES;

    mtrrDefType = __readmsr(MSR_IA32_MTRR_DEF_TYPE);
    MtrrState->DefaultType = (UCHAR)(mtrrDefType & 0xFF);
    MtrrState->Enabled = (mtrrDefType & (1ULL << 11)) != 0;
    MtrrState->FixedEnabled = (mtrrDefType & (1ULL << 10)) != 0;

    for (i = 0; i < MtrrState->VariableRangeCount; i++) {
        ULONG64 base = __readmsr(MSR_IA32_MTRR_PHYSBASE0 + (i * 2));
        ULONG64 mask = __readmsr(MSR_IA32_MTRR_PHYSMASK0 + (i * 2));

        MtrrState->VariableRanges[i].Base = base & ~0xFFFULL;
        MtrrState->VariableRanges[i].Type = (UCHAR)(base & 0xFF);
        MtrrState->VariableRanges[i].Mask = mask & ~0xFFFULL;
        MtrrState->VariableRanges[i].Valid = (mask & (1ULL << 11)) != 0;
    }
}

/*
 * Determine the MTRR memory type for a given physical address.
 * If multiple variable ranges overlap, UC wins over anything,
 * and WT wins over WB (Intel SDM Vol 3A, 11.11.4.1).
 *
 * TODO: handle fixed-range MTRRs for addresses below 1MB
 */
UCHAR
mtrr_get_memory_type(
    _In_ PMTRR_STATE MtrrState,
    _In_ ULONG64 PhysicalAddress
)
{
    ULONG i;
    UCHAR resultType = 0xFF;   /* sentinel: no match found */

    if (!MtrrState->Enabled)
        return EPT_MEMORY_TYPE_UC;

    for (i = 0; i < MtrrState->VariableRangeCount; i++) {
        PMTRR_RANGE range = &MtrrState->VariableRanges[i];

        if (!range->Valid)
            continue;

        if ((PhysicalAddress & range->Mask) == (range->Base & range->Mask)) {
            /* Address falls within this MTRR range */
            if (range->Type == EPT_MEMORY_TYPE_UC) {
                /* UC always wins */
                return EPT_MEMORY_TYPE_UC;
            }

            if (resultType == 0xFF) {
                resultType = range->Type;
            } else if (resultType == EPT_MEMORY_TYPE_WT || range->Type == EPT_MEMORY_TYPE_WT) {
                /* WT wins over WB in overlap scenarios */
                resultType = EPT_MEMORY_TYPE_WT;
            }
            /* else keep existing type (same type overlap) */
        }
    }

    if (resultType == 0xFF)
        return MtrrState->DefaultType;

    return resultType;
}

/* --------------------------------------------------------------------------
 * EPT Table Allocation Helpers
 * -------------------------------------------------------------------------- */

static PVOID
ept_alloc_page(
    _Out_ PPHYSICAL_ADDRESS PhysAddr
)
{
    PVOID va;

    va = ExAllocatePoolWithTag(
        NonPagedPool,
        PAGE_SIZE,
        HVSHIELD_POOL_TAG
    );

    if (!va)
        return NULL;

    RtlZeroMemory(va, PAGE_SIZE);
    *PhysAddr = MmGetPhysicalAddress(va);
    return va;
}

static VOID
ept_free_page(
    _In_ PVOID Va
)
{
    if (Va)
        ExFreePoolWithTag(Va, HVSHIELD_POOL_TAG);
}

/* --------------------------------------------------------------------------
 * EPT Initialization
 * -------------------------------------------------------------------------- */

NTSTATUS
ept_initialize(
    _Out_ PEPT_STATE EptState
)
{
    RtlZeroMemory(EptState, sizeof(EPT_STATE));
    KeInitializeSpinLock(&EptState->ProtectedPagesLock);

    mtrr_initialize(&g_MtrrState);

    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * Identity Map Construction
 * --------------------------------------------------------------------------
 * Build a full identity map: GPA == HPA.
 * Uses 2MB large pages. Each PML4 entry covers 512GB, each PDPTE covers
 * 1GB, each PDE covers 2MB.
 *
 * We only populate the first HVSHIELD_MAX_PHYS_MEMORY_GB of address space.
 */

NTSTATUS
ept_build_identity_map(
    _Inout_ PEPT_STATE EptState
)
{
    PHYSICAL_ADDRESS pml4Phys;
    PEPT_PML4E pml4;
    ULONG pdptIdx, pdIdx;
    ULONG64 currentPhysAddr;
    PHYSICAL_ADDRESS pdptPhys;
    PEPT_PDPTE pdpt;

    /* Allocate PML4 */
    pml4 = (PEPT_PML4E)ept_alloc_page(&pml4Phys);
    if (!pml4)
        return STATUS_INSUFFICIENT_RESOURCES;

    EptState->PML4 = pml4;
    EptState->PML4Phys = pml4Phys;

    /*
     * We need 1 PML4 entry for up to 512GB.
     * Under that, we need (HVSHIELD_MAX_PHYS_MEMORY_GB) PDPT entries,
     * each pointing to a PD with 512 2MB entries.
     */

    /* Allocate single PDPT (covers 512GB) */
    pdpt = (PEPT_PDPTE)ept_alloc_page(&pdptPhys);
    if (!pdpt) {
        ept_free_page(pml4);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* PML4[0] -> PDPT */
    pml4[0].Value = 0;
    pml4[0].Read = 1;
    pml4[0].Write = 1;
    pml4[0].Execute = 1;
    pml4[0].PhysAddr = pdptPhys.QuadPart >> 12;

    currentPhysAddr = 0;

    for (pdptIdx = 0; pdptIdx < HVSHIELD_MAX_PHYS_MEMORY_GB && pdptIdx < 512; pdptIdx++) {
        PHYSICAL_ADDRESS pdPhys;
        PEPT_PDE pd;

        pd = (PEPT_PDE)ept_alloc_page(&pdPhys);
        if (!pd) {
            /* TODO: proper cleanup of already allocated tables */
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        /* PDPT[i] -> PD */
        pdpt[pdptIdx].Value = 0;
        pdpt[pdptIdx].Read = 1;
        pdpt[pdptIdx].Write = 1;
        pdpt[pdptIdx].Execute = 1;
        pdpt[pdptIdx].PhysAddr = pdPhys.QuadPart >> 12;

        /* Fill PD with 512 x 2MB large page entries */
        for (pdIdx = 0; pdIdx < 512; pdIdx++) {
            UCHAR memType = mtrr_get_memory_type(&g_MtrrState, currentPhysAddr);

            pd[pdIdx].Value = 0;
            pd[pdIdx].LargePageFormat.Read = 1;
            pd[pdIdx].LargePageFormat.Write = 1;
            pd[pdIdx].LargePageFormat.Execute = 1;
            pd[pdIdx].LargePageFormat.LargePage = 1;
            pd[pdIdx].LargePageFormat.MemoryType = memType;
            pd[pdIdx].LargePageFormat.PhysAddr = currentPhysAddr >> 21;

            currentPhysAddr += (2 * 1024 * 1024); /* 2MB */
        }
    }

    /* Build the EPT pointer */
    EptState->EptPointer.Value = 0;
    EptState->EptPointer.MemoryType = EPT_MEMORY_TYPE_WB;  /* Page-walk memory type */
    EptState->EptPointer.PageWalkLength = 3;                 /* 4-level walk minus 1 */
    EptState->EptPointer.DirtyAndAccessEnabled = 0;          /* TODO: enable if supported */
    EptState->EptPointer.PML4PhysAddr = pml4Phys.QuadPart >> 12;

    DbgPrint("[HvShield] EPT identity map built: %u GB mapped, EPTP = 0x%llX\n",
             pdptIdx, EptState->EptPointer.Value);

    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * Split 2MB Page to 4K Pages
 * --------------------------------------------------------------------------
 * When we need fine-grained control over a specific 4K page that is inside
 * a 2MB large page, we have to split the large page into 512 4K PTEs.
 *
 * TODO: track split PDs for proper teardown
 */

static NTSTATUS
ept_split_large_page(
    _Inout_ PEPT_STATE EptState,
    _In_ ULONG64 GuestPhysicalAddress
)
{
    ULONG64 largePageBase;
    ULONG pml4Idx, pdptIdx, pdIdx, ptIdx;
    PEPT_PML4E pml4;
    PEPT_PDPTE pdpt;
    PEPT_PDE pd;
    PEPT_PTE pt;
    PHYSICAL_ADDRESS ptPhys, pdptPhysAddr, pdPhysAddr;
    UCHAR memType;

    largePageBase = GuestPhysicalAddress & ~(ULONG64)(0x1FFFFF); /* 2MB align */

    pml4Idx = (ULONG)((GuestPhysicalAddress >> 39) & 0x1FF);
    pdptIdx = (ULONG)((GuestPhysicalAddress >> 30) & 0x1FF);
    pdIdx   = (ULONG)((GuestPhysicalAddress >> 21) & 0x1FF);

    /* Only PML4[0] is populated */
    if (pml4Idx != 0)
        return STATUS_INVALID_PARAMETER;

    pml4 = EptState->PML4;
    if (!pml4[0].Read)
        return STATUS_INVALID_PARAMETER;

    /* Walk to PDPT */
    pdptPhysAddr.QuadPart = pml4[0].PhysAddr << 12;
    pdpt = (PEPT_PDPTE)MmGetVirtualForPhysical(pdptPhysAddr);
    if (!pdpt)
        return STATUS_INVALID_PARAMETER;

    /* Walk to PD */
    pdPhysAddr.QuadPart = pdpt[pdptIdx].PhysAddr << 12;
    pd = (PEPT_PDE)MmGetVirtualForPhysical(pdPhysAddr);
    if (!pd)
        return STATUS_INVALID_PARAMETER;

    /* Check if already split */
    if (!pd[pdIdx].LargePageFormat.LargePage) {
        /* Already 4K pages, nothing to do */
        return STATUS_SUCCESS;
    }

    /* Allocate PT */
    pt = (PEPT_PTE)ept_alloc_page(&ptPhys);
    if (!pt)
        return STATUS_INSUFFICIENT_RESOURCES;

    /* Fill 512 x 4K entries that cover the same 2MB region */
    for (ptIdx = 0; ptIdx < 512; ptIdx++) {
        ULONG64 pageAddr = largePageBase + ((ULONG64)ptIdx * PAGE_SIZE);
        memType = mtrr_get_memory_type(&g_MtrrState, pageAddr);

        pt[ptIdx].Value = 0;
        pt[ptIdx].Read = 1;
        pt[ptIdx].Write = 1;
        pt[ptIdx].Execute = 1;
        pt[ptIdx].MemoryType = memType;
        pt[ptIdx].PhysAddr = pageAddr >> 12;
    }

    /* Replace the large page PDE with a pointer to the new PT */
    pd[pdIdx].Value = 0;
    pd[pdIdx].PageTableFormat.Read = 1;
    pd[pdIdx].PageTableFormat.Write = 1;
    pd[pdIdx].PageTableFormat.Execute = 1;
    pd[pdIdx].PageTableFormat.LargePage = 0;
    pd[pdIdx].PageTableFormat.PhysAddr = ptPhys.QuadPart >> 12;

    /*
     * TODO: INVEPT here to flush stale TLB entries for this region.
     * Without this, the processor may still use a cached 2MB translation.
     */

    DbgPrint("[HvShield] Split 2MB page at GPA 0x%llX into 4K pages\n", largePageBase);

    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * Find the PTE for a given GPA (must be in a 4K-mapped region)
 * -------------------------------------------------------------------------- */

static PEPT_PTE
ept_find_pte(
    _In_ PEPT_STATE EptState,
    _In_ ULONG64 GuestPhysicalAddress
)
{
    ULONG pml4Idx, pdptIdx, pdIdx, ptIdx;
    PEPT_PML4E pml4;
    PEPT_PDPTE pdpt;
    PEPT_PDE pd;
    PEPT_PTE pt;
    PHYSICAL_ADDRESS addr;

    pml4Idx = (ULONG)((GuestPhysicalAddress >> 39) & 0x1FF);
    pdptIdx = (ULONG)((GuestPhysicalAddress >> 30) & 0x1FF);
    pdIdx   = (ULONG)((GuestPhysicalAddress >> 21) & 0x1FF);
    ptIdx   = (ULONG)((GuestPhysicalAddress >> 12) & 0x1FF);

    if (pml4Idx != 0)
        return NULL;

    pml4 = EptState->PML4;

    addr.QuadPart = pml4[0].PhysAddr << 12;
    pdpt = (PEPT_PDPTE)MmGetVirtualForPhysical(addr);
    if (!pdpt || !pdpt[pdptIdx].Read)
        return NULL;

    addr.QuadPart = pdpt[pdptIdx].PhysAddr << 12;
    pd = (PEPT_PDE)MmGetVirtualForPhysical(addr);
    if (!pd)
        return NULL;

    /* If still a large page, cannot return a PTE */
    if (pd[pdIdx].LargePageFormat.LargePage)
        return NULL;

    addr.QuadPart = pd[pdIdx].PageTableFormat.PhysAddr << 12;
    pt = (PEPT_PTE)MmGetVirtualForPhysical(addr);
    if (!pt)
        return NULL;

    return &pt[ptIdx];
}

/* --------------------------------------------------------------------------
 * Set Page Permissions
 * --------------------------------------------------------------------------
 * Modifies RWX permissions on a specific 4K GPA. Splits the containing
 * 2MB large page if necessary.
 */

NTSTATUS
ept_set_page_permission(
    _Inout_ PEPT_STATE EptState,
    _In_ ULONG64 GuestPhysicalAddress,
    _In_ BOOLEAN AllowRead,
    _In_ BOOLEAN AllowWrite,
    _In_ BOOLEAN AllowExecute
)
{
    NTSTATUS status;
    PEPT_PTE pte;
    KIRQL oldIrql;
    ULONG64 alignedGpa;
    ULONG i;

    alignedGpa = GuestPhysicalAddress & ~(ULONG64)(PAGE_SIZE - 1);

    /* Split the 2MB page containing this GPA if needed */
    status = ept_split_large_page(EptState, alignedGpa);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[HvShield] Failed to split large page for GPA 0x%llX: 0x%X\n",
                 alignedGpa, status);
        return status;
    }

    /* Find and modify the PTE */
    pte = ept_find_pte(EptState, alignedGpa);
    if (!pte) {
        DbgPrint("[HvShield] PTE not found for GPA 0x%llX\n", alignedGpa);
        return STATUS_NOT_FOUND;
    }

    pte->Read = AllowRead ? 1 : 0;
    pte->Write = AllowWrite ? 1 : 0;
    pte->Execute = AllowExecute ? 1 : 0;

    /*
     * Note: setting all three to 0 causes EPT misconfiguration, not violation.
     * Intel SDM says at least one permission bit must be set, or entry is
     * considered "not present". We allow this for now; the caller should know
     * what they are doing.
     *
     * TODO: INVEPT single-context invalidation here
     */

    /* Track this page in our protected pages list */
    KeAcquireSpinLock(&EptState->ProtectedPagesLock, &oldIrql);

    /* Check if already tracked */
    for (i = 0; i < EptState->ProtectedPageCount; i++) {
        if (EptState->ProtectedPages[i].GuestPhysicalAddress == alignedGpa) {
            EptState->ProtectedPages[i].AllowRead = AllowRead;
            EptState->ProtectedPages[i].AllowWrite = AllowWrite;
            EptState->ProtectedPages[i].AllowExecute = AllowExecute;
            KeReleaseSpinLock(&EptState->ProtectedPagesLock, oldIrql);
            goto done;
        }
    }

    /* Add new entry */
    if (EptState->ProtectedPageCount < HVSHIELD_MAX_PROTECTED_PAGES) {
        PPROTECTED_PAGE_ENTRY entry = &EptState->ProtectedPages[EptState->ProtectedPageCount];
        entry->GuestPhysicalAddress = alignedGpa;
        entry->Active = TRUE;
        entry->AllowRead = AllowRead;
        entry->AllowWrite = AllowWrite;
        entry->AllowExecute = AllowExecute;
        entry->ViolationCount = 0;
        EptState->ProtectedPageCount++;
    } else {
        KeReleaseSpinLock(&EptState->ProtectedPagesLock, oldIrql);
        DbgPrint("[HvShield] Protected page table full, cannot track GPA 0x%llX\n", alignedGpa);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeReleaseSpinLock(&EptState->ProtectedPagesLock, oldIrql);

done:
    DbgPrint("[HvShield] Set permissions on GPA 0x%llX: R=%d W=%d X=%d\n",
             alignedGpa, AllowRead, AllowWrite, AllowExecute);

    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * EPT Violation Handler
 * --------------------------------------------------------------------------
 * Called from the VM-exit handler when exit reason == EPT_VIOLATION.
 *
 * Returns TRUE if the violation was on a protected page (handled),
 * FALSE if it was unexpected (caller should inject #PF or bug check).
 */

BOOLEAN
ept_handle_violation(
    _Inout_ PEPT_STATE EptState,
    _In_ ULONG64 ExitQualification,
    _In_ ULONG64 GuestPhysicalAddress
)
{
    ULONG64 alignedGpa;
    KIRQL oldIrql;
    ULONG i;
    BOOLEAN found = FALSE;
    BOOLEAN wasRead, wasWrite, wasExec;

    alignedGpa = GuestPhysicalAddress & ~(ULONG64)(PAGE_SIZE - 1);

    /* Decode what the guest was trying to do */
    wasRead  = (ExitQualification & EPT_VIOLATION_READ) != 0;
    wasWrite = (ExitQualification & EPT_VIOLATION_WRITE) != 0;
    wasExec  = (ExitQualification & EPT_VIOLATION_EXECUTE) != 0;

    DbgPrint("[HvShield] EPT violation: GPA=0x%llX Qual=0x%llX (R=%d W=%d X=%d)\n",
             GuestPhysicalAddress, ExitQualification,
             wasRead, wasWrite, wasExec);

    /* Check against our protected pages */
    KeAcquireSpinLock(&EptState->ProtectedPagesLock, &oldIrql);

    for (i = 0; i < EptState->ProtectedPageCount; i++) {
        if (EptState->ProtectedPages[i].Active &&
            EptState->ProtectedPages[i].GuestPhysicalAddress == alignedGpa)
        {
            EptState->ProtectedPages[i].ViolationCount++;
            found = TRUE;

            DbgPrint("[HvShield] PROTECTED PAGE VIOLATION #%u on GPA 0x%llX\n",
                     EptState->ProtectedPages[i].ViolationCount, alignedGpa);

            /*
             * TODO: This is where we would take action:
             *   - Log the guest RIP (read from VMCS_GUEST_RIP)
             *   - Optionally inject #GP into the guest
             *   - Optionally single-step past the instruction:
             *     temporarily allow access, set monitor trap flag,
             *     on MTF exit re-restrict the page
             *   - Send notification to usermode monitor via shared memory
             *
             * For now we just log and skip the instruction, which is wrong
             * but lets us test without crashing the guest immediately.
             */

            break;
        }
    }

    KeReleaseSpinLock(&EptState->ProtectedPagesLock, oldIrql);

    if (!found) {
        /*
         * EPT violation on a page we do not track. This should not happen
         * with a correct identity map. Likely a bug in our EPT setup or
         * a MMIO region we did not account for.
         */
        DbgPrint("[HvShield] WARNING: Unexpected EPT violation at GPA 0x%llX\n",
                 GuestPhysicalAddress);
    }

    return found;
}

/* --------------------------------------------------------------------------
 * EPT Teardown
 * --------------------------------------------------------------------------
 * TODO: Walk the entire EPT hierarchy and free all allocated pages.
 *       Currently this is a stub that just frees the PML4.
 */

VOID
ept_teardown(
    _Inout_ PEPT_STATE EptState
)
{
    /*
     * WARNING: This leaks all PDPT, PD, and PT allocations.
     * Proper implementation needs to walk the tree and free every level.
     * Good enough for development/testing where we unload and reboot.
     */
    if (EptState->PML4) {
        ept_free_page(EptState->PML4);
        EptState->PML4 = NULL;
    }

    DbgPrint("[HvShield] EPT teardown (partial - see TODO)\n");
}
