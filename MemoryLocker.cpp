#include "MemoryLocker.h"

//! Locks read-only pages in memory and creates an additional read-write mapping
MemoryLocker::MemoryLocker(void* pData, ULONG size)
{
    m_pMdl = IoAllocateMdl(pData, size, FALSE, FALSE, NULL);
    ASSERT(m_pMdl);
    MmProbeAndLockPages(m_pMdl, KernelMode, IoReadAccess);
    m_pPointer = MmMapLockedPagesSpecifyCache(m_pMdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    NTSTATUS status = MmProtectMdlSystemAddress(m_pMdl, PAGE_EXECUTE_READWRITE);
    (void)status;
    ASSERT(NT_SUCCESS(status));
}

//! Destroys the additional read-write mapping
MemoryLocker::~MemoryLocker()
{
    MmUnmapLockedPages(m_pPointer, m_pMdl);
    MmUnlockPages(m_pMdl);
    IoFreeMdl(m_pMdl);
}

//! Returns a write-enabled pointer to a read-only memory block
void* MemoryLocker::GetPointer()
{
    return m_pPointer;
}
