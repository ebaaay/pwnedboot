#include "Global.h"

#define INFINITE_LOOP() while (true) {}

enum AppContext
{
    ApplicationContext,
    FirmwareContext
};

typedef void(__stdcall* BlpArchSwitchContext_t)(int target);
BlpArchSwitchContext_t BlpArchSwitchContext;

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

EXTERN_C NTKERNELAPI PVOID NTAPI RtlFindExportedRoutineByName(PVOID imageBase, PCCH routineName);

EXTERN_C NTSTATUS EntryPoint()
{
    // If this freezes the PC, the DLL LOADED successfully.
    // If it still reboots to recovery, the DLL is NOT loading (DSE/Secure Boot blocking).
    while (true) { __halt(); }
    return STATUS_SUCCESS;
}