# exports.py

import ctypes
from ctypes import wintypes

class StartupInfoEx(ctypes.Structure):
    _fields_ = [
        ("StartupInfo", wintypes.STARTUPINFO),
        ("AttributeList", ctypes.POINTER(ctypes.c_void_p))  # PROC_THREAD_ATTRIBUTE_LIST
    ]

class ProcessInformation(ctypes.Structure):
    _fields_ = [
        ("Process", wintypes.HANDLE),
        ("Thread", wintypes.HANDLE),
        ("ProcessId", wintypes.DWORD),
        ("ThreadId", wintypes.DWORD)
    ]

class PROC_THREAD_ATTRIBUTE_LIST(ctypes.Structure):
    _fields_ = [
        ("dwFlags", wintypes.DWORD),
        ("size", ctypes.c_uint64),
        ("count", ctypes.c_uint64),
        ("reserved", ctypes.c_uint64),
        ("unknown", ctypes.POINTER(ctypes.c_uint64)),
        ("entries", ctypes.POINTER(ctypes.c_void_p))  # PROC_THREAD_ATTRIBUTE_ENTRY
    ]

class PROC_THREAD_ATTRIBUTE_ENTRY(ctypes.Structure):
    _fields_ = [
        ("attribute", ctypes.POINTER(wintypes.DWORD)),
        ("cbSize", ctypes.c_size_t),
        ("lpValue", ctypes.c_void_p)
    ]

class ExportDirectory(ctypes.Structure):
    _fields_ = [
        ("ExportFlags", wintypes.DWORD),
        ("TimeDateStamp", wintypes.DWORD),
        ("MajorVersion", wintypes.WORD),
        ("MinorVersion", wintypes.WORD),
        ("NameRVA", wintypes.DWORD),
        ("OrdinalBase", wintypes.DWORD),
        ("NumberOfFunctions", wintypes.DWORD),
        ("NumberOfNames", wintypes.DWORD),
        ("AddressTableAddr", wintypes.DWORD),
        ("NameTableAddr", wintypes.DWORD),
        ("OrdinalTableAddr", wintypes.DWORD),
        ("DllName", ctypes.c_char_p)
    ]

class Export(ctypes.Structure):
    _fields_ = [
        ("Ordinal", wintypes.DWORD),
        ("Name", ctypes.c_char_p),
        ("VirtualAddress", wintypes.DWORD),
        ("Forward", ctypes.c_char_p)
    ]

class SString(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.WORD),
        ("MaxLength", wintypes.WORD),
        ("PWstr", ctypes.POINTER(wintypes.WCHAR))
    ]

    def __str__(self):
        return ctypes.wstring_at(self.PWstr)

class IMAGE_OPTIONAL_HEADER(ctypes.Structure):
    _fields_ = [
        ("Magic", wintypes.WORD),
        ("MajorLinkerVersion", wintypes.BYTE),
        ("MinorLinkerVersion", wintypes.BYTE),
        ("SizeOfCode", wintypes.DWORD),
        ("SizeOfInitializedData", wintypes.DWORD),
        ("SizeOfUninitializedData", wintypes.DWORD),
        ("AddressOfEntryPoint", wintypes.DWORD),
        ("BaseOfCode", wintypes.DWORD),
        ("ImageBase", ctypes.c_uint64),
        ("SectionAlignment", wintypes.DWORD),
        ("FileAlignment", wintypes.DWORD),
        ("MajorOperatingSystemVersion", wintypes.WORD),
        ("MinorOperatingSystemVersion", wintypes.WORD),
        ("MajorImageVersion", wintypes.WORD),
        ("MinorImageVersion", wintypes.WORD),
        ("MajorSubsystemVersion", wintypes.WORD),
        ("MinorSubsystemVersion", wintypes.WORD),
        ("Win32VersionValue", wintypes.DWORD),
        ("SizeOfImage", wintypes.DWORD),
        ("SizeOfHeaders", wintypes.DWORD),
        ("CheckSum", wintypes.DWORD),
        ("Subsystem", wintypes.WORD),
        ("DllCharacteristics", wintypes.WORD),
        ("SizeOfStackReserve", ctypes.c_uint64),
        ("SizeOfStackCommit", ctypes.c_uint64),
        ("SizeOfHeapReserve", ctypes.c_uint64),
        ("SizeOfHeapCommit", ctypes.c_uint64),
        ("LoaderFlags", wintypes.DWORD),
        ("NumberOfRvaAndSizes", wintypes.DWORD),
        ("DataDirectory", wintypes.DWORD * 16)  # IMAGE_DATA_DIRECTORY
    ]

class IMAGE_OPTIONAL_HEADER32(ctypes.Structure):
    _fields_ = [
        ("Magic", wintypes.WORD),
        ("MajorLinkerVersion", wintypes.BYTE),
        ("MinorLinkerVersion", wintypes.BYTE),
        ("SizeOfCode", wintypes.DWORD),
        ("SizeOfInitializedData", wintypes.DWORD),
        ("SizeOfUninitializedData", wintypes.DWORD),
        ("AddressOfEntryPoint", wintypes.DWORD),
        ("BaseOfCode", wintypes.DWORD),
        ("BaseOfData", wintypes.DWORD),
        ("ImageBase", ctypes.c_uint64),
        ("SectionAlignment", wintypes.DWORD),
        ("FileAlignment", wintypes.DWORD),
        ("MajorOperatingSystemVersion", wintypes.WORD),
        ("MinorOperatingSystemVersion", wintypes.WORD),
        ("MajorImageVersion", wintypes.WORD),
        ("MinorImageVersion", wintypes.WORD),
        ("MajorSubsystemVersion", wintypes.WORD),
        ("MinorSubsystemVersion", wintypes.WORD),
        ("Win32VersionValue", wintypes.DWORD),
        ("SizeOfImage", wintypes.DWORD),
        ("SizeOfHeaders", wintypes.DWORD),
        ("CheckSum", wintypes.DWORD),
        ("Subsystem", wintypes.WORD),
        ("DllCharacteristics", wintypes.WORD),
        ("SizeOfStackReserve", ctypes.c_uint64),
        ("SizeOfStackCommit", ctypes.c_uint64),
        ("SizeOfHeapReserve", ctypes.c_uint64),
        ("SizeOfHeapCommit", ctypes.c_uint64),
        ("LoaderFlags", wintypes.DWORD),
        ("NumberOfRvaAndSizes", wintypes.DWORD),
        ("DataDirectory", ctypes.c_void_p)  # IMAGE_DATA_DIRECTORY
    ]

class IMAGE_DATA_DIRECTORY(ctypes.Structure):
    _fields_ = [
        ("VirtualAddress", wintypes.DWORD),
        ("Size", wintypes.DWORD)
    ]

class IMAGE_FILE_HEADER(ctypes.Structure):
    _fields_ = [
        ("Machine", wintypes.WORD),
        ("NumberOfSections", wintypes.WORD),
        ("TimeDateStamp", wintypes.DWORD),
        ("PointerToSymbolTable", wintypes.DWORD),
        ("NumberOfSymbols", wintypes.DWORD),
        ("SizeOfOptionalHeader", wintypes.WORD),
        ("Characteristics", wintypes.WORD)
    ]

class IMAGE_NT_HEADER(ctypes.Structure):
    _fields_ = [
        ("Signature", wintypes.DWORD),
        ("FileHeader", IMAGE_FILE_HEADER),
        ("OptionalHeader", IMAGE_OPTIONAL_HEADER)
    ]

class IMAGE_DOS_HEADER(ctypes.Structure):
    _fields_ = [
        ("E_magic", wintypes.WORD),
        ("E_cblp", wintypes.WORD),
        ("E_cp", wintypes.WORD),
        ("E_crlc", wintypes.WORD),
        ("E_cparhdr", wintypes.WORD),
        ("E_minalloc", wintypes.WORD),
        ("E_maxalloc", wintypes.WORD),
        ("E_ss", wintypes.WORD),
        ("E_sp", wintypes.WORD),
        ("E_csum", wintypes.WORD),
        ("E_ip", wintypes.WORD),
        ("E_cs", wintypes.WORD),
        ("E_lfarlc", wintypes.WORD),
        ("E_ovno", wintypes.WORD),
        ("E_res", wintypes.WORD * 4),
        ("E_oemid", wintypes.WORD),
        ("E_oeminfo", wintypes.WORD),
        ("E_res2", wintypes.WORD * 10),
        ("E_lfanew", wintypes.WORD)
    ]

class MemStatusEx(ctypes.Structure):
    _fields_ = [
        ("dwLength", wintypes.DWORD),
        ("dwMemoryLoad", wintypes.DWORD),
        ("ullTotalPhys", ctypes.c_uint64),
        ("ullAvailPhys", ctypes.c_uint64),
        ("unused", ctypes.c_uint64 * 5)
    ]

class PTHREAD_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("exitStatus", wintypes.LONG),
        ("pTebBaseAddress", ctypes.c_void_p),
        ("clientId", ctypes.c_void_p),  # CLIENT_ID
        ("AffinityMask", ctypes.c_void_p),
        ("Priority", wintypes.LONG),
        ("BasePriority", wintypes.LONG),
        ("v", wintypes.LONG)
    ]

class SC_SERVICE_TAG_QUERY(ctypes.Structure):
    _fields_ = [
        ("processId", wintypes.DWORD),
        ("serviceTag", wintypes.DWORD),
        ("reserved", wintypes.DWORD),
        ("pBuffer", ctypes.c_void_p)
    ]

class CLIENT_ID(ctypes.Structure):
    _fields_ = [
        ("UniqueProcess", ctypes.c_void_p),
        ("UniqueThread", ctypes.c_void_p)
    ]
