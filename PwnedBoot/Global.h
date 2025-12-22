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
typedef unsigned __int64 ULONGLONG;
typedef char CHAR;

typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY* Flink;
    struct _LIST_ENTRY* Blink;
} LIST_ENTRY, *PLIST_ENTRY;

typedef ULONG64* PULONG64;
typedef const char* PCCH;
typedef long LONG;
typedef __int64 LONG64;

#ifndef IMAGE_DOS_SIGNATURE
#define IMAGE_DOS_SIGNATURE                 0x5A4D      // MZ
#endif

typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    USHORT e_magic;                     // Magic number
    USHORT e_cblp;                      // Bytes on last page of file
    USHORT e_cp;                        // Pages in file
    USHORT e_crlc;                      // Relocations
    USHORT e_cparhdr;                   // Size of header in paragraphs
    USHORT e_minalloc;                  // Minimum extra paragraphs needed
    USHORT e_maxalloc;                  // Maximum extra paragraphs needed
    USHORT e_ss;                        // Initial (relative) SS value
    USHORT e_sp;                        // Initial SP value
    USHORT e_csum;                      // Checksum
    USHORT e_ip;                        // Initial IP value
    USHORT e_cs;                        // Initial (relative) CS value
    USHORT e_lfarlc;                    // File address of relocation table
    USHORT e_ovno;                      // Overlay number
    USHORT e_res[4];                    // Reserved words
    USHORT e_oemid;                     // OEM identifier (for e_oeminfo)
    USHORT e_oeminfo;                   // OEM info; e_oemid specific
    USHORT e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    USHORT  Machine;
    USHORT  NumberOfSections;
    ULONG   TimeDateStamp;
    ULONG   PointerToSymbolTable;
    ULONG   NumberOfSymbols;
    USHORT  SizeOfOptionalHeader;
    USHORT  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    ULONG   VirtualAddress;
    ULONG   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    USHORT      Magic;
    UCHAR       MajorLinkerVersion;
    UCHAR       MinorLinkerVersion;
    ULONG       SizeOfCode;
    ULONG       SizeOfInitializedData;
    ULONG       SizeOfUninitializedData;
    ULONG       AddressOfEntryPoint;
    ULONG       BaseOfCode;
    ULONG64     ImageBase;
    ULONG       SectionAlignment;
    ULONG       FileAlignment;
    USHORT      MajorOperatingSystemVersion;
    USHORT      MinorOperatingSystemVersion;
    USHORT      MajorImageVersion;
    USHORT      MinorImageVersion;
    USHORT      MajorSubsystemVersion;
    USHORT      MinorSubsystemVersion;
    ULONG       Win32VersionValue;
    ULONG       SizeOfImage;
    ULONG       SizeOfHeaders;
    ULONG       CheckSum;
    USHORT      Subsystem;
    USHORT      DllCharacteristics;
    ULONG64     SizeOfStackReserve;
    ULONG64     SizeOfStackCommit;
    ULONG64     SizeOfHeapReserve;
    ULONG64     SizeOfHeapCommit;
    ULONG       LoaderFlags;
    ULONG       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
    ULONG Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

#include <stddef.h>

#include "Utils.h"
#include "Defines.h"
#include "EFI.h"