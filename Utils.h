#pragma once

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
