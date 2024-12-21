# Advanced Shellcode Loader Tool

## Description

This project is an advanced shellcode loader tool designed to implement multiple evasion and injection techniques, support various encryption methods, and enhance security bypass mechanisms. It includes features such as sandbox detection, AMSI/ETW patching, and metadata generation for shellcode.

## Features

- **Shellcode Injection Techniques**: Supports SuspendedProcess and Process Hollowing techniques.
- **Encryption Methods**: Provides options for AES, 3DES, and RC4 encryption.
- **Security Bypass**: Includes AMSI and ETW patching to bypass security mechanisms.
- **Sandbox Detection**: Detects sandbox environments to prevent execution in virtualized or monitored environments.
- **Metadata Generation**: Computes MD5, SHA1, and SHA256 hashes for shellcode integrity verification.

## Installation

1. Clone the repository:
   ```bash
   https://github.com/DarkHacker420/shadowShellcode.git
   cd shadowShellcode
## Usage
pip install -r requirements.txt
python shellcodemain.py --shellcode <path_to_shellcode> --output <EXE_or_DLL> [options]

## Options
--shellcode: Path to the shellcode file.
--output: Output format, either EXE or DLL.
--encrypt: Encryption method (AES, 3DES, RC4).
--key: Encryption key (optional).
--detect-sandbox: Enable sandbox detection.
--patch: Enable AMSI and ETW patching.
--inject: Injection technique (SuspendedProcess, ProcessHollowing).

## Example
python shellcodemain.py --shellcode shellcode.bin --output EXE --encrypt AES --key mysecretkey --detect-sandbox --patch --inject SuspendedProcess

## Disclaimer
This tool is intended for educational and research purposes only. The authors are not responsible for any misuse or damage caused by this tool.

