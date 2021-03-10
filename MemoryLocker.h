#pragma once

#include <wdm.h>
#include "Utils.h"

/*
    Nice little class to be able to write in read-only memory. Taken from VirtualKD-redux.
*/
class MemoryLocker
{
private:
    PMDL m_pMdl;
    PVOID m_pPointer;

public:
    //! Locks read-only pages in memory and creates an additional read-write mapping
    MemoryLocker(void* pData, ULONG size);

    //! Destroys the additional read-write mapping
    ~MemoryLocker();

    //! Returns a write-enabled pointer to a read-only memory block
    void* GetPointer();
};