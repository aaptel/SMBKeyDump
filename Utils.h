#pragma once
#include <ntddk.h>

NTSTATUS LogToFile(LPCSTR formatstring, ...);

PVOID
KernelGetModuleBase(
	PCHAR  pModuleName
);

PVOID
KernelGetProcAddress(
	PVOID ModuleBase,
	PCHAR pFunctionName
);

#define DBGP(x, ...) DbgPrint("[SMBKeyDump] " x "\n", ##__VA_ARGS__)
#define P(x, ...) \
	do { \
		DbgPrint("[SMBKeyDump] " x "\n", ##__VA_ARGS__); \
		LogToFile(x "\n", ##__VA_ARGS__); \
	} while (0)

#include <ntimage.h>
typedef struct _MappedImportDescriptor
{
	void** OriginalFirstThunk;
	void** FirstThunk;
	IMAGE_IMPORT_DESCRIPTOR* ImportDescriptor;
} MappedImportDescriptor, * PMappedImportDescriptor;

int FindImportByNameMapped(void* PEBuffer, const char* ImportName, MappedImportDescriptor* ImportDesc);
