import ctypes
import ctypes.wintypes as wintypes
from ctypes import POINTER, Structure, sizeof, byref

# Define constants
PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = 0x100000000000

# Define structures
class STARTUPINFOEX(Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPVOID),
        ("lpDesktop", wintypes.LPVOID),
        ("lpTitle", wintypes.LPVOID),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", wintypes.LPBYTE),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
        ("lpAttributeList", wintypes.LPVOID),
    ]

class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]

# Load required functions
kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)

InitializeProcThreadAttributeList = kernel32.InitializeProcThreadAttributeList
InitializeProcThreadAttributeList.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, POINTER(ctypes.c_size_t)]
InitializeProcThreadAttributeList.restype = wintypes.BOOL

UpdateProcThreadAttribute = kernel32.UpdateProcThreadAttribute
UpdateProcThreadAttribute.argtypes = [
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.SIZE_T,
    wintypes.LPVOID,
    wintypes.SIZE_T,
    wintypes.LPVOID,
    wintypes.LPVOID,
]
UpdateProcThreadAttribute.restype = wintypes.BOOL

CreateProcessW = kernel32.CreateProcessW
CreateProcessW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.LPWSTR,
    wintypes.LPVOID,
    wintypes.LPVOID,
    wintypes.BOOL,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.LPCWSTR,
    POINTER(STARTUPINFOEX),
    POINTER(PROCESS_INFORMATION),
]
CreateProcessW.restype = wintypes.BOOL

# Main function to launch process with DLL-blocking enabled
def create_process_with_blockdlls(command):
    attr_list_size = ctypes.c_size_t(0)
    InitializeProcThreadAttributeList(None, 1, 0, byref(attr_list_size))

    attribute_list = ctypes.create_string_buffer(attr_list_size.value)
    if not InitializeProcThreadAttributeList(attribute_list, 1, 0, byref(attr_list_size)):
        raise ctypes.WinError(ctypes.get_last_error())

    mitigation_policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
    if not UpdateProcThreadAttribute(
        attribute_list, 0, 0x20007, byref(ctypes.c_size_t(mitigation_policy)), sizeof(ctypes.c_size_t), None, None
    ):
        raise ctypes.WinError(ctypes.get_last_error())

    startup_info = STARTUPINFOEX()
    startup_info.cb = sizeof(STARTUPINFOEX)
    startup_info.lpAttributeList = attribute_list

    process_info = PROCESS_INFORMATION()
    if not CreateProcessW(
        None,
        command,
        None,
        None,
        False,
        0x00080000,  # EXTENDED_STARTUPINFO_PRESENT
        None,
        None,
        byref(startup_info),
        byref(process_info),
    ):
        raise ctypes.WinError(ctypes.get_last_error())

    print(f"Process launched with PID: {process_info.dwProcessId}")

# Example usage
if __name__ == "__main__":
    try:
        create_process_with_blockdlls("C:\\Windows\\System32\\notepad.exe")
    except Exception as e:
        print(f"Error: {e}")
