# evasion.py

import pefile
import os

class HookCheckError(Exception):
    pass

def detect_hooks():
    hooked_functions = []

    ntdll_path = os.path.join(os.environ['SYSTEMROOT'], 'System32', 'ntdll.dll')
    try:
        dll_pe = pefile.PE(ntdll_path)
    except FileNotFoundError:
        return hooked_functions, FileNotFoundError(f"File {ntdll_path} not found")

    for exp in dll_pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name is not None:
            func_name = exp.name.decode()
            if len(func_name) > 3 and (func_name.startswith("Nt") or func_name.startswith("Zw")):
                offset = dll_pe.get_offset_from_rva(exp.address)
                b_bytes = dll_pe.get_memory_mapped_image()
                buff = b_bytes[offset:offset+10]

                if not buff.startswith(b'\x4C'):  # Assuming HookCheck is a specific byte pattern
                    hooked_functions.append(func_name)

    return hooked_functions, None

def is_hooked(funcname):
    try:
        all_hooks, err = detect_hooks()
        if err:
            return False, err

        for h in all_hooks:
            if funcname.lower() == h.lower():
                return True, None

        return False, None
    except Exception as e:
        return False, e

# Example usage
if __name__ == '__main__':
    hooked_funcs, error = detect_hooks()
    if error:
        print(f"Error detecting hooks: {error}")
    else:
        print("Hooked functions:", hooked_funcs)

    func_name = "NtCreateFile"
    hooked, error = is_hooked(func_name)
    if error:
        print(f"Error checking if {func_name} is hooked: {error}")
    else:
        print(f"Is {func_name} hooked? {hooked}")
