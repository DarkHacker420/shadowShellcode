import ctypes
from ctypes import wintypes, byref
import struct

# Define PROCESS_MITIGATION_DYNAMIC_CODE_POLICY structure
class PROCESS_MITIGATION_DYNAMIC_CODE_POLICY(ctypes.Structure):
    _fields_ = [
        ("Flags", wintypes.DWORD),
    ]

    def __init__(self):
        self.Flags = 0
        self.ProhibitDynamicCode = 1

    @property
    def ProhibitDynamicCode(self):
        return bool(self.Flags & 0x1)

    @ProhibitDynamicCode.setter
    def ProhibitDynamicCode(self, value):
        if value:
            self.Flags |= 0x1
        else:
            self.Flags &= ~0x1

# Wrapper for SetProcessMitigationPolicy
def enable_acg():
    kernel32 = ctypes.WinDLL("kernel32.dll")
    SetProcessMitigationPolicy = kernel32.SetProcessMitigationPolicy
    SetProcessMitigationPolicy.argtypes = [
        wintypes.DWORD,  # Policy type
        wintypes.LPVOID,  # Policy structure
        wintypes.SIZE_T,  # Policy size
    ]
    SetProcessMitigationPolicy.restype = wintypes.BOOL

    ProcessDynamicCodePolicy = 2  # Policy type for dynamic code
    dcp = PROCESS_MITIGATION_DYNAMIC_CODE_POLICY()
    dcp.ProhibitDynamicCode = 1  # Enable dynamic code prohibition

    result = SetProcessMitigationPolicy(
        ProcessDynamicCodePolicy,
        byref(dcp),
        ctypes.sizeof(dcp)
    )

    if not result:
        error_code = ctypes.GetLastError()
        raise OSError(f"SetProcessMitigationPolicy failed with error code: {error_code}")
    else:
        print("ACG protection enabled successfully.")

# Test function (can be removed in production)
if __name__ == "__main__":
    try:
        enable_acg()
    except Exception as e:
        print(f"Error: {e}")
