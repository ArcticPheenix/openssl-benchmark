# OpenSSL Benchmarking Tool

This project provides a simple benchmarking tool for measuring the performance of OpenSSL cryptographic operations, specifically focusing on RSA operations.

## Features
- Benchmarks RSA cryptographic operations using OpenSSL
- Simple command-line interface
- Customizable via source code

## Prerequisites
- GCC or compatible C compiler
- OpenSSL development libraries (tested with OpenSSL 3.5.1)

## Building

```
make
```

This will build the benchmarking tool using the provided `Makefile`.

## Usage

After building, run the benchmark executable:

```
./openssl-benchmark
```

Or, if the output binary has a different name, adjust accordingly.

## Files
- `main.c`: Entry point for the benchmarking tool
- `rsa_bench.c` / `rsa_bench.h`: RSA benchmarking implementation and interface
- `Makefile`: Build instructions

## Configuration
- The tool is configured to use OpenSSL headers from `/opt/openssl-3.5.1/include/` (see `.vscode/c_cpp_properties.json`). Adjust as needed for your system.

## License
This project is provided as-is for benchmarking and educational purposes.
