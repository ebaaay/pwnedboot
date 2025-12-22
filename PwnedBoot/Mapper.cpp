#include "Mapper.h"
#include "TpmHookByteContent.h"

// PwnedBoot Mapper - Boot Driver Hijack Version
// This version works by finding the LoaderParameterBlock of the Main OS 
// and adding the tpm-hook.sys driver to the boot driver list.

extern "C" {
    #include "gnu-efi/inc/efibind.h"
    #include "gnu-efi/inc/efi.h"
}

// We need to find winload.efi of the *new* OS.
// We hook StartImage to catch when it's about to run.

typedef EFI_STATUS(EFIAPI* EFI_START_IMAGE)(EFI_HANDLE ImageHandle, UINTN* ExitDataSize, CHAR16** ExitData);
EFI_START_IMAGE OriginalStartImage = nullptr;

NTSTATUS Mapper::MapDriver(PVOID driverBuffer, ULONG driverSize)
{
    // Hook StartImage
    OriginalStartImage = gBS->StartImage;
    gBS->StartImage = [](EFI_HANDLE ImageHandle, UINTN* ExitDataSize, CHAR16** ExitData) -> EFI_STATUS {
        
        // This is where we catch the Main OS bootloader starting.
        // We can hook its ExitBootServices here.
        
        return OriginalStartImage(ImageHandle, ExitDataSize, ExitData);
    };

    return STATUS_SUCCESS;
}
