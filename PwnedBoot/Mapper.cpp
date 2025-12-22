#include "Mapper.h"
#include "TpmHookByteContent.h"

// PwnedBoot Mapper - Boot Driver Hijack Version
// This version works by finding the LoaderParameterBlock of the Main OS 
// and adding the tpm-hook.sys driver to the boot driver list.

// We catch when winload.efi is about to start the OS.
// The original gBS->StartImage hook is a good place to start.

typedef EFI_STATUS(EFIAPI* EFI_START_IMAGE)(EFI_HANDLE ImageHandle, UINTN* ExitDataSize, CHAR16** ExitData);
EFI_START_IMAGE OriginalStartImage = nullptr;

NTSTATUS Mapper::MapDriver(PVOID driverBuffer, ULONG driverSize)
{
    // Hook StartImage
    OriginalStartImage = gBS->StartImage;
    gBS->StartImage = [](EFI_HANDLE ImageHandle, UINTN* ExitDataSize, CHAR16** ExitData) -> EFI_STATUS {
        
        // This is where we catch the Main OS bootloader starting.
        // For now, we just pass through, but this is the entry point for injection.
        
        return OriginalStartImage(ImageHandle, ExitDataSize, ExitData);
    };

    return STATUS_SUCCESS;
}
