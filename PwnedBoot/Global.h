#pragma once

#include <intrin.h>

// Use basic definitions instead of ntifs.h to avoid WDK dependency on CI
typedef long NTSTATUS;
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)
#define STATUS_INVALID_PARAMETER_1      ((NTSTATUS)0xC00000EFL)
#define STATUS_INVALID_PARAMETER_2      ((NTSTATUS)0xC00000F0L)
#define STATUS_INVALID_PARAMETER_3      ((NTSTATUS)0xC00000F1L)

typedef unsigned long ULONG;
typedef unsigned char UCHAR;
typedef unsigned short USHORT;
typedef void* PVOID;
typedef unsigned __int64 ULONG64;
typedef __int64 LONG64;
typedef ULONG64* PULONG64;
typedef const char* PCCH;

#include <ntimage.h>
#include <stddef.h>

#include "Utils.h"
#include "Defines.h"
#include "EFI.h"