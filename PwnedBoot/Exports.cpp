#include "Global.h"

EXTERN_C __declspec(dllexport) ULONG64 McImageInfo = 0x3800000001;

EXTERN_C __declspec(dllexport) NTSTATUS McMicrocodeOperation(void)
{
    return STATUS_SUCCESS;
}