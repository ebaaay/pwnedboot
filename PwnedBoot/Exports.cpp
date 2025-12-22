#include "Global.h"

EXTERN_C ULONG64 McImageInfo = 0x3800000001;

EXTERN_C NTSTATUS McMicrocodeOperation(void)
{
    return STATUS_SUCCESS;
}