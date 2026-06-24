# Lab 1 — Symmetric Encryption with Crypto++

## Tool
`aestool` — AES encryption/decryption CLI using Crypto++.

## Environment
- Windows: MSYS2 UCRT64
- Linux: Ubuntu 26.04 LTS
- Language: C++17
- Build system: CMake + Ninja
- Crypto library: Crypto++

## Planned Features
- AES modes: ECB, CBC, OFB, CFB, CTR, XTS, CCM, GCM
- Key input from file or hex
- File and text input
- Hex/Base64/raw output
- Sidecar JSON metadata
- KAT runner
- Negative tests
- Benchmark

## Build on Windows MSYS2 UCRT64

Run inside MSYS2 UCRT64:

    cmake -S . -B build-windows-ucrt64 -G Ninja -DCMAKE_BUILD_TYPE=Release
    cmake --build build-windows-ucrt64

## Run

    ./build-windows-ucrt64/aestool.exe --help
    ./build-windows-ucrt64/aestool.exe selftest
