#include "Mapper.h"
#include "TpmHookByteContent.h"
#include "Utils.h"

typedef EFI_STATUS(EFIAPI* EFI_START_IMAGE)(EFI_HANDLE ImageHandle, UINTN* ExitDataSize, CHAR16** ExitData);
typedef EFI_STATUS(EFIAPI* EFI_EXIT_BOOT_SERVICES)(EFI_HANDLE ImageHandle, UINTN MapKey);

static EFI_START_IMAGE OriginalStartImage = nullptr;
static EFI_EXIT_BOOT_SERVICES OriginalExitBootServices = nullptr;
static PVOID AllocatedDriverBase = nullptr;

static PLOADER_PARAMETER_BLOCK FindLoaderParameterBlock()
{
    // Método Seguro: Buscamos ntoskrnl.exe en la lista de módulos cargados.
    // Esto es mucho más estable que escanear por números de versión.
    for (ULONG_PTR addr = 0x1000000; addr < 0x80000000; addr += 0x1000)
    {
        // Buscamos la firma "ntoskrnl.exe" en Unicode
        if (memcmp((void*)addr, L"n\0t\0o\0s\0k\0r\0n\0l\0.\0e\0x\0e", 24) == 0)
        {
            // Hemos encontrado el nombre en una estructura KLDR_DATA_TABLE_ENTRY
            // Retrocedemos para encontrar el inicio de la estructura y luego la lista
            for (ULONG_PTR search = addr - 0x200; search < addr; search += 8)
            {
                PKLDR_DATA_TABLE_ENTRY entry = (PKLDR_DATA_TABLE_ENTRY)search;
                if (entry->FullDllName.Buffer == (PWCH)addr)
                {
                    // Tenemos una entrada válida. Ahora buscamos la cabeza de la lista (LPB)
                    // La InLoadOrderLinks apunta de vuelta al LoaderParameterBlock
                    PLOADER_PARAMETER_BLOCK lpb = (PLOADER_PARAMETER_BLOCK)((ULONG_PTR)entry->InLoadOrderLinks.Blink - offsetof(LOADER_PARAMETER_BLOCK, LoadOrderListHead));
                    
                    // Verificación extra de seguridad
                    if (lpb->OsMajorVersion == 10) {
                        return lpb;
                    }
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
        PKLDR_DATA_TABLE_ENTRY entry = nullptr;
        EFI_STATUS status = gBS->AllocatePool(EfiLoaderData, sizeof(KLDR_DATA_TABLE_ENTRY), (void**)&entry);
        
        if (!EFI_ERROR(status) && entry)
        {
            memset(entry, 0, sizeof(KLDR_DATA_TABLE_ENTRY));
            PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((ULONG_PTR)AllocatedDriverBase + ((PIMAGE_DOS_HEADER)AllocatedDriverBase)->e_lfanew);
            
            entry->DllBase = AllocatedDriverBase;
            entry->SizeOfImage = nt->OptionalHeader.SizeOfImage;
            entry->EntryPoint = (PVOID)((ULONG_PTR)AllocatedDriverBase + nt->OptionalHeader.AddressOfEntryPoint);
            
            // Nombres del driver
            PWCH nameBuf = nullptr;
            gBS->AllocatePool(EfiLoaderData, 100, (void**)&nameBuf);
            if (nameBuf) {
                const wchar_t* n = L"tpm-hook.sys";
                for (int i = 0; i < 13; i++) nameBuf[i] = n[i];
                entry->BaseDllName.Buffer = nameBuf;
                entry->BaseDllName.Length = 24;
                entry->BaseDllName.MaximumLength = 26;
            }

            PWCH fullPathBuf = nullptr;
            gBS->AllocatePool(EfiLoaderData, 200, (void**)&fullPathBuf);
            if (fullPathBuf) {
                const wchar_t* p = L"\\SystemRoot\\System32\\Drivers\\tpm-hook.sys";
                for (int i = 0; i < 41; i++) fullPathBuf[i] = p[i];
                entry->FullDllName.Buffer = fullPathBuf;
                entry->FullDllName.Length = 80;
                entry->FullDllName.MaximumLength = 82;
            }

            entry->Flags = 0x01; // Cargado

            // Inserción segura en la lista de arranque
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
