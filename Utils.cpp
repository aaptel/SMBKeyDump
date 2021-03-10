#include <ntddk.h>
#include <stdarg.h>
#include <ntstrsafe.h>
#include "Undoc.h"
#include "Utils.h"

//! Kernel-mode equivalent of GetModuleHandle()
/*! This function returns the base address of a module loaded into kernel address space (can be a driver
    or a kernel-mode DLL).
    \param pModuleName Specifies the module name as an ANSI null-terminated string.
    \return The function returns the base address of a module, or NULL if it was not found among the loaded modules.
    \remarks The function body was downloaded from <a href="http://alter.org.ua/docs/nt_kernel/procaddr/">here</a>.
*/
PVOID
KernelGetModuleBase(
    PCHAR  pModuleName
)
{
    PVOID pModuleBase = NULL;
    PULONG pSystemInfoBuffer = NULL;

    __try
    {
        NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
        ULONG    SystemInfoBufferSize = 0;

        status = ZwQuerySystemInformation(SystemModuleInformation,
            &SystemInfoBufferSize,
            0,
            &SystemInfoBufferSize);

        if (!SystemInfoBufferSize)
            return NULL;

        pSystemInfoBuffer = (PULONG)ExAllocatePoolZero(NonPagedPool, SIZE_T(SystemInfoBufferSize) * 2, 'BMSK');

        if (!pSystemInfoBuffer)
            return NULL;

        memset(pSystemInfoBuffer, 0, SIZE_T(SystemInfoBufferSize) * 2);

        status = ZwQuerySystemInformation(SystemModuleInformation,
            pSystemInfoBuffer,
            SystemInfoBufferSize * 2,
            &SystemInfoBufferSize);

        if (NT_SUCCESS(status))
        {
            PSYSTEM_MODULE_ENTRY pSysModuleEntry =
                ((PSYSTEM_MODULE_INFORMATION)(pSystemInfoBuffer))->Modules;
            ULONG i;

            for (i = 0; i < ((PSYSTEM_MODULE_INFORMATION)(pSystemInfoBuffer))->ModulesCount; i++)
            {
                if (_stricmp((char*)pSysModuleEntry[i].Name +
                    pSysModuleEntry[i].NameOffset, pModuleName) == 0)
                {
                    pModuleBase = pSysModuleEntry[i].ImageBaseAddress;
                    break;
                }
            }
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        pModuleBase = NULL;
    }
    if (pSystemInfoBuffer) {
        ExFreePool(pSystemInfoBuffer);
    }

    return pModuleBase;
} // end KernelGetModuleBase()

//! Kernel-mode equivalent of GetProcAddress()
/*! This function returns the address of a function exported by a module loaded into kernel address space.
    \param ModuleBase Specifies the module base address (can be determined by calling KernelGetModuleBase()).
    \param pFunctionName Specifies the function name as an ANSI null-terminated string.
    \return The function returns the address of an exported function, or NULL if it was not found.
    \remarks The function body was downloaded from <a href="http://alter.org.ua/docs/nt_kernel/procaddr/">here</a>.
*/
PVOID
KernelGetProcAddress(
    PVOID ModuleBase,
    PCHAR pFunctionName
)
{
    ASSERT(ModuleBase && pFunctionName);
    PVOID pFunctionAddress = NULL;

    ULONG size = 0;
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)
        RtlImageDirectoryEntryToData(ModuleBase, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size);

    if (!exports)
        return NULL;

#pragma warning(push)
#pragma warning(disable: 4311)
#pragma warning(disable: 4302)
#pragma warning(disable: 4312)
    ULONG_PTR addr = (ULONG_PTR)(PUCHAR)((ULONG)exports - (ULONG)ModuleBase);
#pragma warning(pop)

    PULONG functions = (PULONG)((ULONG_PTR)ModuleBase + exports->AddressOfFunctions);
    PSHORT ordinals = (PSHORT)((ULONG_PTR)ModuleBase + exports->AddressOfNameOrdinals);
    PULONG names = (PULONG)((ULONG_PTR)ModuleBase + exports->AddressOfNames);
    ULONG  max_name = exports->NumberOfNames;
    ULONG  max_func = exports->NumberOfFunctions;
    ULONG i;

    for (i = 0; i < max_name; i++)
    {
        ULONG ord = ordinals[i];
        if (i >= max_name || ord >= max_func) {
            return NULL;
        }
        if (functions[ord] < addr || functions[ord] >= addr + size)
        {
            if (strcmp((PCHAR)ModuleBase + names[i], pFunctionName) == 0)
            {
                pFunctionAddress = (PVOID)((PCHAR)ModuleBase + functions[ord]);
                break;
            }
        }
    }
    return pFunctionAddress;
}


NTSTATUS
LogToFile(LPCSTR formatstring, ...)
{
    NTSTATUS Status;
    char Buffer[512];
    memset(Buffer, 0, sizeof(Buffer));
    va_list args;
    va_start(args, formatstring);
    RtlStringCbVPrintfA(Buffer, sizeof(Buffer), formatstring, args);
    va_end(args);

    ULONG bufferSize = (ULONG)strnlen(Buffer, sizeof(Buffer));
    UNICODE_STRING      filePath;   //  Must be with DOS prefix: \??\C:\MyFolder\logs.txt
    HANDLE              hFile;
    OBJECT_ATTRIBUTES   ObjectAttributes;
    IO_STATUS_BLOCK     IoStatusBlock;

    RtlInitUnicodeString(&filePath, L"\\??\\C:\\logs.txt");
    InitializeObjectAttributes(&ObjectAttributes, &filePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    Status = ZwCreateFile(&hFile, FILE_APPEND_DATA|SYNCHRONIZE, &ObjectAttributes,
        &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF,
        FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

    if (!NT_SUCCESS(Status))
    {
        DBGP("Creating file error");
        return Status;
    }

    Status = ZwWriteFile(hFile, NULL, NULL, NULL, &IoStatusBlock, (PVOID)Buffer, bufferSize, NULL, NULL);

    if (!NT_SUCCESS(Status))
    {
        DBGP("Writing file error");
        goto out;
    }

out:
    ZwClose(hFile);
    return Status;
}

int FindImportByNameMapped(void* PEBuffer, const char* ImportName, MappedImportDescriptor* ImportDesc)
{
    if (!PEBuffer)
        return -1;
    if (!ImportName)
        return -1;
    if (!ImportDesc)
        return -1;

    memset(ImportDesc, 0, sizeof(MappedImportDescriptor));

    IMAGE_DOS_HEADER* DosHeader;
    IMAGE_NT_HEADERS* NTHeaders;
    IMAGE_OPTIONAL_HEADER* OptionalHeader;
    IMAGE_IMPORT_DESCRIPTOR* ImportDescriptor;

    DosHeader = (IMAGE_DOS_HEADER*)PEBuffer;
    NTHeaders = (IMAGE_NT_HEADERS*)((char*)PEBuffer + DosHeader->e_lfanew);
    OptionalHeader = &NTHeaders->OptionalHeader;

    if (!OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
        return -1;

    ImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)((char*)PEBuffer + OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    while (ImportDescriptor->Name)
    {
        void** OriginalFirstThunk = (void**)((char*)PEBuffer + ImportDescriptor->OriginalFirstThunk);
        void** FirstThunk = (void**)((char*)PEBuffer + ImportDescriptor->FirstThunk);

        if (!OriginalFirstThunk)
            OriginalFirstThunk = FirstThunk;

        for (; *OriginalFirstThunk; OriginalFirstThunk++, FirstThunk++)
        {
            if (!IMAGE_SNAP_BY_ORDINAL((unsigned long long) * OriginalFirstThunk))
            {
                IMAGE_IMPORT_BY_NAME* ImportByName = (IMAGE_IMPORT_BY_NAME*)((char*)PEBuffer + (unsigned long long) * OriginalFirstThunk);
                if (!_stricmp(ImportByName->Name, ImportName))
                {
                    ImportDesc->OriginalFirstThunk = OriginalFirstThunk;
                    ImportDesc->FirstThunk = FirstThunk;
                    ImportDesc->ImportDescriptor = ImportDescriptor;
                    return STATUS_SUCCESS;
                }
            }
        }
        ImportDescriptor++;
    }
    return -1;
}