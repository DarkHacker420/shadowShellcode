import ctypes
import ctypes.wintypes as wintypes

# Constants
PAGE_EXECUTE_READWRITE = 0x40
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

# Load kernel32 DLL for necessary functions
kernel32 = ctypes.WinDLL("kernel32.dll")
ntdll = ctypes.WinDLL("ntdll.dll")

# Define the structure for PEB (Process Environment Block)
class LIST_ENTRY(ctypes.Structure):
    _fields_ = [
        ("Flink", wintypes.LPVOID),
        ("Blink", wintypes.LPVOID),
    ]

class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", wintypes.LPWSTR),
    ]

class LDR_DATA_TABLE_ENTRY(ctypes.Structure):
    _fields_ = [
        ("Reserved1", ctypes.c_byte * 2),
        ("InMemoryOrderLinks", LIST_ENTRY),
        ("DllBase", wintypes.LPVOID),
        ("FullDllName", UNICODE_STRING),
        ("BaseDllName", UNICODE_STRING),
    ]

class PEB_LDR_DATA(ctypes.Structure):
    _fields_ = [
        ("Reserved1", ctypes.c_byte * 8),
        ("InMemoryOrderModuleList", LIST_ENTRY),
    ]

class PEB(ctypes.Structure):
    _fields_ = [
        ("Reserved1", ctypes.c_byte * 2),
        ("Reserved2", ctypes.c_byte * 4),
        ("Ldr", ctypes.POINTER(PEB_LDR_DATA)),
    ]

class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Reserved1", wintypes.LPVOID),
        ("PebBaseAddress", ctypes.POINTER(PEB)),
        ("Reserved2", wintypes.LPVOID * 2),
        ("UniqueProcessId", wintypes.HANDLE),
        ("Reserved3", wintypes.LPVOID),
    ]

# Function to get PEB
def get_peb():
    process = kernel32.GetCurrentProcess()
    basic_info = PROCESS_BASIC_INFORMATION()
    size_returned = wintypes.ULONG()

    # Call NtQueryInformationProcess to retrieve PEB
    result = ntdll.NtQueryInformationProcess(
        process,
        0,  # ProcessBasicInformation
        ctypes.byref(basic_info),
        ctypes.sizeof(basic_info),
        ctypes.byref(size_returned),
    )
    if result != 0:
        raise ctypes.WinError()

    return basic_info.PebBaseAddress

# Function to iterate loaded modules
def list_modules():
    peb = get_peb()
    ldr = peb.contents.Ldr.contents
    module_list = ldr.InMemoryOrderModuleList

    current_entry = module_list.Flink
    modules = []

    while current_entry != ctypes.addressof(module_list):
        entry = ctypes.cast(current_entry, ctypes.POINTER(LDR_DATA_TABLE_ENTRY)).contents
        modules.append(entry.BaseDllName.Buffer)
        current_entry = entry.InMemoryOrderLinks.Flink

    return modules

# Example usage
if __name__ == "__main__":
    try:
        modules = list_modules()
        print("Loaded modules:")
        for module in modules:
            print(module)
    except Exception as e:
        print(f"Error: {e}")
