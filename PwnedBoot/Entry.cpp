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
    ULONG64 searchBase = returnAddress & ~0xFFF;
    while (*reinterpret_cast<USHORT*>(searchBase) != 0x5A4D)
        searchBase -= 0x1000;

    const ULONG64 moduleBase = searchBase;

    // Try primary pattern (Win 11 / Newer Win 10)
    ULONG64 systemTableScan = Utils::FindPatternImage(reinterpret_cast<PVOID>(moduleBase), "48 8B 05 ? ? ? ? 33 FF 4C 8B E9 48 8B 68 18 48 85 ED 75 0A");
    
    // If failed, try secondary pattern (Older Win 10)
    if (!systemTableScan) {
        systemTableScan = Utils::FindPatternImage(reinterpret_cast<PVOID>(moduleBase), "48 8B 05 ? ? ? ? 48 8B 40 18 48 8B 50 20");
    }

    if (!systemTableScan)
        return STATUS_INVALID_PARAMETER_1;

    const ULONG64 ptrAddress = (systemTableScan + 7) + *reinterpret_cast<int*>(systemTableScan + 3);
    const ULONG64 resolvedSystemTable = *reinterpret_cast<ULONG64*>(ptrAddress);
    const ULONG64 resolvedImageHandle = *reinterpret_cast<ULONG64*>(ptrAddress + 8);

    EFI::Stage0(reinterpret_cast<PVOID>(resolvedImageHandle), reinterpret_cast<PVOID>(resolvedSystemTable));

    BlpArchSwitchContext = reinterpret_cast<BlpArchSwitchContext_t>(Utils::FindPatternImage(reinterpret_cast<PVOID>(moduleBase), "40 53 48 83 EC 20 48 8B 15"));
    
    // Fallback for BlpArchSwitchContext on some Win 10 builds
    if (!BlpArchSwitchContext) {
        BlpArchSwitchContext = reinterpret_cast<BlpArchSwitchContext_t>(Utils::FindPatternImage(reinterpret_cast<PVOID>(moduleBase), "48 8B C4 48 89 58 08 4c 89 48 20 40 56 48 83 ec 30"));
    }

    if (!BlpArchSwitchContext)
        return STATUS_INVALID_PARAMETER_2;

    /*
     * We obviously cannot switch the context here, since that would
     * instantly crash the system. This module is NOT mapped in the firmware
     * context. Instead, we will remap ourselves over winload.efi which is
     * so we can then switch to it.
     */

    PIMAGE_DOS_HEADER dosHeader = &__ImageBase;
    PIMAGE_NT_HEADERS64 ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<ULONG64>(dosHeader) + dosHeader->e_lfanew);

    /*
     * This is the most fun part, now we have to pick a location that will not fuck up
     * the BlpArchSwitchContext functionality or the context save data. This looks really
     * scary until you realize that winload.efi is quite large (image size 0x304000) and that
     * its sections start with .text, then page and the data is last. Might change with
     * different Windows versions.
     */
    PVOID targetBase = reinterpret_cast<PVOID>(moduleBase);
    memcpy(targetBase, dosHeader, ntHeaders->OptionalHeader.SizeOfImage);

    PVOID entry = RtlFindExportedRoutineByName(targetBase, "RemappedEntry");
    if (!entry)
        return STATUS_INVALID_PARAMETER_3;

    /*
     * Remove the headers so the image is not reallocated by the firmware
     * or some crap like that which could mess things up.
     */
    memset(targetBase, 0, ntHeaders->OptionalHeader.SizeOfHeaders);

    return reinterpret_cast<NTSTATUS(*)()>(entry)();
}

EXTERN_C __declspec(dllexport) NTSTATUS RemappedEntry()
{
    /*
     * This entry is now located in the region where winload.efi was originally
     * (or still is but just the rest of it...). Now lets switch the context to
     * firmware and lets pray that we have not overwritten anything related to the
     * context switching.
     */
    BlpArchSwitchContext(FirmwareContext);

    EFI::Stage1();

    //EFI::ChangeResolution();
    EFI::SplashScreen();
    EFI::Exec();

    INFINITE_LOOP();
}