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
    /*
     * The entry point will be first executed from winload.efi
     * and then 2 times from the ntoskrnl.exe if the boot continues.
     */

    ULONG64 returnAddress = reinterpret_cast<ULONG64>(_ReturnAddress());

    // Search for MZ signature (0x5A4D) in 4KB increments (page aligned)
    // This is more robust than looking for DOS prompt strings.
    ULONG64 searchBase = returnAddress & ~0xFFF;
    int limit = 0;
    while (*reinterpret_cast<USHORT*>(searchBase) != 0x5A4D && limit < 0x1000) {
        searchBase -= 0x1000;
        limit++;
    }

    if (limit >= 0x1000) {
        // Fallback: search byte by byte if page-aligned search fails (unlikely)
        searchBase = returnAddress;
        while (*reinterpret_cast<USHORT*>(searchBase) != 0x5A4D)
            searchBase--;
    }

    const ULONG64 moduleBase = searchBase;

    // Search for SystemTable and ImageHandle
    // Patterns for Windows 10/11
    ULONG64 systemTableScan = Utils::FindPatternImage(reinterpret_cast<PVOID>(moduleBase), "48 8B 05 ? ? ? ? 33 FF 4C 8B E9 48 8B 68 18 48 85 ED 75 0A");
    if (!systemTableScan) systemTableScan = Utils::FindPatternImage(reinterpret_cast<PVOID>(moduleBase), "48 8B 05 ? ? ? ? 48 8B 40 18 48 8B 50 20");
    if (!systemTableScan) systemTableScan = Utils::FindPatternImage(reinterpret_cast<PVOID>(moduleBase), "48 8B 05 ? ? ? ? 33 FF 48 8B E9");

    if (!systemTableScan)
        return STATUS_INVALID_PARAMETER_1;

    const ULONG64 ptrAddress = (systemTableScan + 7) + *reinterpret_cast<int*>(systemTableScan + 3);
    const ULONG64 resolvedSystemTable = *reinterpret_cast<ULONG64*>(ptrAddress);
    const ULONG64 resolvedImageHandle = *reinterpret_cast<ULONG64*>(ptrAddress + 8);

    EFI::Stage0(reinterpret_cast<PVOID>(resolvedImageHandle), reinterpret_cast<PVOID>(resolvedSystemTable));

    // Find BlpArchSwitchContext
    BlpArchSwitchContext = reinterpret_cast<BlpArchSwitchContext_t>(Utils::FindPatternImage(reinterpret_cast<PVOID>(moduleBase), "40 53 48 83 EC 20 48 8B 15"));
    if (!BlpArchSwitchContext) BlpArchSwitchContext = reinterpret_cast<BlpArchSwitchContext_t>(Utils::FindPatternImage(reinterpret_cast<PVOID>(moduleBase), "48 8B C4 48 89 58 08 4c 89 48 20 40 56 48 83 ec 30"));
    if (!BlpArchSwitchContext) BlpArchSwitchContext = reinterpret_cast<BlpArchSwitchContext_t>(Utils::FindPatternImage(reinterpret_cast<PVOID>(moduleBase), "48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 41 54 41 56 41 57 48 83 EC 30"));

    if (!BlpArchSwitchContext)
        return STATUS_INVALID_PARAMETER_2;

    PIMAGE_DOS_HEADER dosHeader = &__ImageBase;
    PIMAGE_NT_HEADERS64 ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<ULONG64>(dosHeader) + dosHeader->e_lfanew);

    PVOID targetBase = reinterpret_cast<PVOID>(moduleBase);
    memcpy(targetBase, dosHeader, ntHeaders->OptionalHeader.SizeOfImage);

    PVOID entry = RtlFindExportedRoutineByName(targetBase, "RemappedEntry");
    if (!entry)
        return STATUS_INVALID_PARAMETER_3;

    memset(targetBase, 0, ntHeaders->OptionalHeader.SizeOfHeaders);
    return reinterpret_cast<NTSTATUS(*)()>(entry)();
}

EXTERN_C __declspec(dllexport) NTSTATUS RemappedEntry()
{
    BlpArchSwitchContext(FirmwareContext);

    EFI::Stage1();

    // Menu and Boot
    EFI::SplashScreen();
    EFI::Exec();

    INFINITE_LOOP();
}