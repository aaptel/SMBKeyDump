#include <ntddk.h>
#include "MemoryLocker.h"
#include "Utils.h"

VOID DriverUnload(IN PDRIVER_OBJECT DriverObject);

#define KEY_GEN_IAT_OFFSET     0x418d0
#define KEY_INSERT_IAT_OFFSET  0x418c8

static bool KeyGenHooked = false;
static bool KeyInsertHooked = false;

static void DumpKey(const PCHAR Name, PUINT8 k)
{
    P("%s = "
        "%02x %02x %02x %02x "
        "%02x %02x %02x %02x "
        "%02x %02x %02x %02x "
        "%02x %02x %02x %02x "
        , Name
        , k[0], k[1], k[2], k[3]
        , k[4], k[5], k[6], k[7]
        , k[8], k[9], k[10], k[11]
        , k[12], k[13], k[14], k[15]
    );
}

// Pointer to store address of the original srvnet!SmbCryptoKeyTableInsert
__int64(__fastcall* real_SmbCryptoKeyTableInsert)(__int64, __int64, __int64, PVOID*);

// Our wrapper around it that will get called instead
__int64 __fastcall my_SmbCryptoKeyTableInsert(__int64 a1, __int64 a2, __int64 sessId, PVOID* keyhandle)
{
    P("srvnet!SmbCryptoKeyTableInsert: SessionId=%llx", sessId);
    return real_SmbCryptoKeyTableInsert(a1, a2, sessId, keyhandle);
}

// Pointer to store address of the original srvnet!SmbCryptoCreateServerCipherKeys
__int64(__fastcall* real_SmbCryptoCreateServerCipherKeys)(int, __int64, __int64, __int64, int, PUINT8*, PUINT8*);

// Our wrapper around it that will be called instead
__int64 __fastcall my_SmbCryptoCreateServerCipherKeys(int a1, __int64 a2, __int64 a3, __int64 a4, int a5, PUINT8* a6, PUINT8* a7)
{
    P("srvnet!SmbCryptoCreateServerCipherKeys(%x, %llx, %llx, %llx, %x, %p, %p)", a1, a2, a3, a4, a5, a6, a7);
    __int64 ret = real_SmbCryptoCreateServerCipherKeys(a1, a2, a3, a4, a5, a6, a7);
    P("=> RET=%llx", ret);

    if (ret == 0) {
        PUINT8 k;

        k = (PUINT8)(*(PUINT64)(*a6)) + 92;
        DumpKey("ServerOut Key", k);

        k = (PUINT8)(*(PUINT64)(*a7)) + 92;
        DumpKey("ServerIn Key", k);
    }
    return ret;
}


extern "C"
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT     DriverObject,
    _In_ PUNICODE_STRING    RegistryPath
)
{
    P("Loading module...");

    (void)RegistryPath;
    DriverObject->DriverUnload = DriverUnload;    

    PVOID pModuleBase = KernelGetModuleBase("srv2.sys");
    if (!pModuleBase) {
        P("Cannot find srv2.sys in loaded modules");
        return 0;
    }

    P("Module srv2.sys loaded at %p", pModuleBase);

    {
        PVOID pIATEntry = ((PUINT8)pModuleBase + KEY_GEN_IAT_OFFSET);
        MemoryLocker ml(pIATEntry, sizeof(PVOID));
        PVOID p = ml.GetPointer();
        PVOID newFunc = &my_SmbCryptoCreateServerCipherKeys;
        memcpy(&real_SmbCryptoCreateServerCipherKeys, p, sizeof(PVOID));
        P("Hooking srv2 import address for srvnet!SmbCryptoCreateServerCipherKeys %p", real_SmbCryptoCreateServerCipherKeys);
        P("With our func %p", newFunc);
        memcpy(p, &newFunc, sizeof(PVOID));
        KeyGenHooked = true;
    }

    {
        PVOID pIATEntry = ((PUINT8)pModuleBase + KEY_INSERT_IAT_OFFSET);
        MemoryLocker ml(pIATEntry, sizeof(PVOID));
        PVOID p = ml.GetPointer();
        PVOID newFunc = &my_SmbCryptoKeyTableInsert;
        memcpy(&real_SmbCryptoKeyTableInsert, p, sizeof(PVOID));
        P("Hooking srv2 import address for srvnet!SmbCryptoKeyTableInsert %p", real_SmbCryptoKeyTableInsert);
        P("With our func %p", newFunc);
        memcpy(p, &newFunc, sizeof(PVOID));
        KeyInsertHooked = true;
    }

    P("Module loaded");
    return 0;
}

VOID DriverUnload(IN PDRIVER_OBJECT DriverObject)
{
    (void)DriverObject;

    P("Unloading module...");

    PVOID pModuleBase = KernelGetModuleBase("srv2.sys");
    if (!pModuleBase) {
        P("Cannot find srv2.sys in loaded modules");
        return;
    }

    if (KeyGenHooked)
    {
        P("Restoring srv2 import address for srvnet!SmbCryptoCreateServerCipherKeys");
        PVOID pIATEntry = ((PUINT8)pModuleBase + KEY_GEN_IAT_OFFSET);
        MemoryLocker ml(pIATEntry, sizeof(PVOID));
        PVOID p = ml.GetPointer();
        memcpy(p, &real_SmbCryptoCreateServerCipherKeys, sizeof(PVOID));
    }

    if (KeyInsertHooked)
    {
        P("Restoring srv2 import address for srvnet!SmbCryptoKeyTableInsert");
        PVOID pIATEntry = ((PUINT8)pModuleBase + KEY_INSERT_IAT_OFFSET);
        MemoryLocker ml(pIATEntry, sizeof(PVOID));
        PVOID p = ml.GetPointer();
        memcpy(p, &real_SmbCryptoKeyTableInsert, sizeof(PVOID));
    }

    P("Module unloaded");
}
