# evasion.py

import os
import psutil
import platform
import ctypes
import requests
from ctypes import wintypes, Structure, byref
import time

# Constants
MEMORY_THRESHOLD = 4174967296  # 4GB
DISK_THRESHOLD = 68719476736  # 64GB
CPU_THRESHOLD = 2
PROCESS_THRESHOLD = 15
INTERNET_TIMEOUT = 3  # seconds

# Lists of known sandbox indicators
drivers = [
    "C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
    "C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
    # Add other drivers as needed
]

processes = [
    "vboxservice.exe",
    "vboxtray.exe",
    # Add other process names as needed
]

hostnames_list = [
    "Sandbox",
    "SANDBOX",
    # Add other hostnames as needed
]

usernames_list = [
    "sandbox",
    "virus",
    # Add other usernames as needed
]

class MEMORYSTATUSEX(Structure):
    _fields_ = [
        ("dwLength", wintypes.DWORD),
        ("dwMemoryLoad", wintypes.DWORD),
        ("ullTotalPhys", ctypes.c_uint64),
        ("ullAvailPhys", ctypes.c_uint64),
        ("ullTotalPageFile", ctypes.c_uint64),
        ("ullAvailPageFile", ctypes.c_uint64),
        ("ullTotalVirtual", ctypes.c_uint64),
        ("ullAvailVirtual", ctypes.c_uint64),
        ("sullAvailExtendedVirtual", ctypes.c_uint64),
    ]

def auto_check():
    if check_memory():
        return True
    if check_drivers():
        return True
    if check_process():
        return True
    if check_disk():
        return True
    if check_internet():
        return True
    if check_hostname():
        return True
    if check_username():
        return True
    if check_cpu():
        return True
    return False

def check_memory():
    kernel32 = ctypes.WinDLL('kernel32.dll')
    memory_status = MEMORYSTATUSEX()
    memory_status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    kernel32.GlobalMemoryStatusEx(byref(memory_status))
    return memory_status.ullTotalPhys < MEMORY_THRESHOLD

def check_disk():
    total_bytes = ctypes.c_ulonglong(0)
    kernel32 = ctypes.WinDLL('kernel32.dll')
    kernel32.GetDiskFreeSpaceExW(ctypes.c_wchar_p("C:\\"), None, byref(total_bytes), None)
    return total_bytes.value < DISK_THRESHOLD

def check_internet():
    try:
        requests.get("https://google.com", timeout=INTERNET_TIMEOUT)
        return False
    except requests.RequestException:
        return True

def check_hostname():
    hostname = platform.node()
    return hostname in hostnames_list

def check_username():
    username = os.getlogin()
    return username in usernames_list

def check_cpu():
    return os.cpu_count() <= CPU_THRESHOLD

def check_drivers():
    for driver in drivers:
        if os.path.exists(driver):
            return True
    return False

def check_process():
    process_list = [p.name() for p in psutil.process_iter()]
    if len(process_list) <= PROCESS_THRESHOLD:
        return True
    for proc in process_list:
        if proc in processes:
            return True
    return False

# Example usage
if __name__ == '__main__':
    if auto_check():
        print("Sandbox detected")
    else:
        print("No sandbox detected")
