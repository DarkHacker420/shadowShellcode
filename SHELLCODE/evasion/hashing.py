# evasion.py

import ctypes
import pefile
import os
import struct

class MayBeHookedError(Exception):
    def __init__(self, found_bytes):
        self.found_bytes = found_bytes
        super().__init__(f"Function may be hooked, found bytes: {found_bytes}")

def in_mem_loads(dll_name):
    # This function should return the base address and size of the loaded DLL in memory
    # Placeholder implementation
    return 0x10000000, 0x1000

def rva_to_offset(pe, rva):
    # Convert RVA to file offset
    return pe.get_offset_from_rva(rva)

def check_bytes(buff):
    # Placeholder implementation for checking bytes
    # This function should return the syscall ID if the bytes are valid
    # Raise MayBeHookedError if the function seems to be hooked
    if buff.startswith(b'\x4C'):
        return struct.unpack('<H', buff[4:6])[0], None
    else:
        raise MayBeHookedError(buff)

def get_ntdll_start():
    # This function should return the start address and size of ntdll in memory
    # Placeholder implementation
    return 0x10000000, 0x1000

def get_func_ptr(hash, dll, hashing_function):
    try:
        pe_file = pefile.PE(dll)
    except FileNotFoundError:
        return None, "", FileNotFoundError(f"File {dll} not found")

    for exp in pe_file.DIRECTORY_ENTRY_EXPORT.symbols:
        if hash == hashing_function(exp.name.decode()):
            return ctypes.windll.LoadLibrary(dll).get_proc_address(exp.name.decode()), exp.name.decode(), None

    return None, "", Exception("Function not found")

def get_sys_id_hash(hash, dll, hashing_func):
    try:
        dll_pe = pefile.PE(dll)
    except FileNotFoundError:
        return 0, "", FileNotFoundError(f"File {dll} not found")

    for exp in dll_pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if hashing_func(exp.name.decode()) == hash:
            offset = rva_to_offset(dll_pe, exp.address)
            b_bytes = dll_pe.get_memory_mapped_image()
            buff = b_bytes[offset:offset+10]
            if not buff.startswith(b'\x4C'):
                raise MayBeHookedError(buff)

            sys_id = struct.unpack('<H', buff[4:6])[0]
            return sys_id, exp.name.decode(), None

    return 0, "", Exception("Syscall ID not found")

def get_sys_id_hash_halos(hash, hashing_func):
    s, si = in_mem_loads('ntdll')
    ntdll_pe = pefile.PE(data=ctypes.string_at(s, si))

    for exp in ntdll_pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if hashing_func(exp.name.decode()) == hash:
            offset = rva_to_offset(ntdll_pe, exp.address)
            b_bytes = ntdll_pe.get_memory_mapped_image()
            buff = b_bytes[offset:offset+10]
            try:
                sys_id, _ = check_bytes(buff)
                return sys_id, exp.name.decode(), None
            except MayBeHookedError as hook_err:
                start, size = get_ntdll_start()

                # Search forward
                distance_neighbor = 0
                for i in range(offset, start + size):
                    if b_bytes[i:i+3] == b'\x0f\x05\xc3':
                        distance_neighbor += 1
                        try:
                            sys_id, _ = check_bytes(b_bytes[i+14:i+22])
                            return sys_id - distance_neighbor, "", None
                        except MayBeHookedError:
                            continue

                # Search backward
                distance_neighbor = 1
                for i in range(offset - 1, 0, -1):
                    if b_bytes[i:i+3] == b'\x0f\x05\xc3':
                        distance_neighbor += 1
                        try:
                            sys_id, _ = check_bytes(b_bytes[i+14:i+22])
                            return sys_id + distance_neighbor - 1, "", None
                        except MayBeHookedError:
                            continue

    return 0, "", Exception("Syscall ID not found")
