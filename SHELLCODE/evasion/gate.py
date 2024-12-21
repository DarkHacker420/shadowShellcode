# gate.py

import ctypes
import pefile
import os

class MayBeHookedError(Exception):
    pass

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
    if buff[0] == 0x4C:
        return int.from_bytes(buff[1:3], 'little'), None
    else:
        raise MayBeHookedError("Function may be hooked")

def get_ntdll_start():
    # This function should return the start address and size of ntdll in memory
    # Placeholder implementation
    return 0x10000000, 0x1000

def get_sys_id(funcname):
    s, si = in_mem_loads('ntdll')
    ntdll_pe = pefile.PE(data=ctypes.string_at(s, si))

    for exp in ntdll_pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if funcname.lower() == exp.name.decode().lower():
            offset = rva_to_offset(ntdll_pe, exp.address)
            b_bytes = ntdll_pe.get_memory_mapped_image()
            buff = b_bytes[offset:offset+10]
            try:
                sys_id, _ = check_bytes(buff)
                return sys_id
            except MayBeHookedError:
                start, size = get_ntdll_start()
                distance_neighbor = 0

                # Search forward
                for i in range(offset, start + size):
                    if b_bytes[i:i+3] == b'\x0f\x05\xc3':
                        distance_neighbor += 1
                        try:
                            sys_id, _ = check_bytes(b_bytes[i+14:i+22])
                            return sys_id - distance_neighbor
                        except MayBeHookedError:
                            continue

                # Search backward
                distance_neighbor = 1
                for i in range(offset - 1, 0, -1):
                    if b_bytes[i:i+3] == b'\x0f\x05\xc3':
                        distance_neighbor += 1
                        try:
                            sys_id, _ = check_bytes(b_bytes[i+14:i+22])
                            return sys_id + distance_neighbor - 1
                        except MayBeHookedError:
                            continue

    return get_disk_sys_id(funcname)

def get_disk_sys_id(funcname):
    ntdll_path = os.path.join(os.environ['SYSTEMROOT'], 'System32', 'ntdll.dll')
    ntdll_pe = pefile.PE(ntdll_path)

    for exp in ntdll_pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if funcname.lower() == exp.name.decode().lower():
            offset = rva_to_offset(ntdll_pe, exp.address)
            b_bytes = ntdll_pe.get_memory_mapped_image()
            buff = b_bytes[offset:offset+10]
            try:
                sys_id, _ = check_bytes(buff)
                return sys_id
            except MayBeHookedError:
                start, size = get_ntdll_start()
                distance_neighbor = 0

                # Search forward
                for i in range(offset, start + size):
                    if b_bytes[i:i+3] == b'\x0f\x05\xc3':
                        distance_neighbor += 1
                        try:
                            sys_id, _ = check_bytes(b_bytes[i+14:i+22])
                            return sys_id - distance_neighbor
                        except MayBeHookedError:
                            continue

                # Search backward
                distance_neighbor = 1
                for i in range(offset - 1, 0, -1):
                    if b_bytes[i:i+3] == b'\x0f\x05\xc3':
                        distance_neighbor += 1
                        try:
                            sys_id, _ = check_bytes(b_bytes[i+14:i+22])
                            return sys_id + distance_neighbor - 1
                        except MayBeHookedError:
                            continue

    raise Exception("syscall ID not found")
