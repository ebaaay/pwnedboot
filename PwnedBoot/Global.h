#pragma once

#include <intrin.h>
#include <string.h>

// Basic types
typedef unsigned long ULONG;
typedef unsigned short USHORT;
typedef unsigned char UCHAR;
typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned long DWORD;
typedef unsigned int DWORD32;
typedef unsigned __int64 ULONG64;
typedef unsigned __int64 ULONGLONG;
typedef __int64 LONG64;
typedef long LONG;
typedef void* PVOID;
typedef const char* PCCH;
typedef char CHAR;
typedef char* PCH;
typedef USHORT* PWCH;
typedef DWORD* PDWORD;
typedef USHORT* PUSHORT;

#if defined(_M_AMD64)
typedef unsigned __int64 ULONG_PTR;
#else
typedef unsigned long ULONG_PTR;
#endif

// Forward declarations for bootloader types
struct _CONFIGURATION_COMPONENT_DATA;
struct _NLS_DATA_BLOCK;
struct _ARC_DISK_INFORMATION;
struct _LOADER_PARAMETER_EXTENSION;
struct _RTL_BALANCED_NODE;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWCH   Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

// include EFI headers to get LIST_ENTRY and EFI types
#include "EFIGlobal.h"

// NT types and macros
typedef long NTSTATUS;
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)
#define STATUS_INVALID_PARAMETER_1      ((NTSTATUS)0xC00000EFL)
#define STATUS_INVALID_PARAMETER_2      ((NTSTATUS)0xC00000F0L)
#define STATUS_INVALID_PARAMETER_3      ((NTSTATUS)0xC00000F1L)

#define NTAPI __stdcall
#define NTKERNELAPI
#ifndef EXTERN_C
#define EXTERN_C extern "C"
#endif

#ifndef FIELD_OFFSET
#define FIELD_OFFSET(type, field)    ((LONG)(ULONG_PTR)&(((type *)0)->field))
#endif

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

#define IMAGE_DIRECTORY_ENTRY_EXPORT          0

typedef struct _IMAGE_EXPORT_DIRECTORY {
    ULONG   Characteristics;
    ULONG   TimeDateStamp;
    USHORT  MajorVersion;
    USHORT  MinorVersion;
    ULONG   Name;
    ULONG   Base;
    ULONG   NumberOfFunctions;
    ULONG   NumberOfNames;
    ULONG   AddressOfFunctions;     // RVA from base of image
    ULONG   AddressOfNames;         // RVA from base of image
    ULONG   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

typedef struct _IMAGE_SECTION_HEADER {
    BYTE    Name[8];
    union {
            ULONG   PhysicalAddress;
            ULONG   VirtualSize;
    } Misc;
    ULONG   VirtualAddress;
    ULONG   SizeOfRawData;
    ULONG   PointerToRawData;
    ULONG   PointerToRelocations;
    ULONG   PointerToLinenumbers;
    USHORT  NumberOfRelocations;
    USHORT  NumberOfLinenumbers;
    ULONG   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

#ifndef IMAGE_FIRST_SECTION
#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)(ntheader) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS64, OptionalHeader ) +               \
     ((ntheader))->FileHeader.SizeOfOptionalHeader                      \
    ))
#endif

#include <stddef.h>

#include "Utils.h"
#include "Defines.h"
#include "EFI.h"