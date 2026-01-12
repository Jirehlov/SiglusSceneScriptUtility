#!/usr/bin/env python3
"""Performance benchmark comparing Python and Rust implementations."""

import time
import os

# Force Python implementation first
from siglus_scene_script_utility import native_ops
native_ops._USE_NATIVE = False

from siglus_scene_script_utility.native_ops import (  # noqa: E402
    _py_lzss_pack, _py_lzss_unpack, _py_md5_digest, _py_xor_cycle_inplace,
)

# Load native implementations separately
try:
    from siglus_scene_script_utility.native_accel import (
        lzss_pack as native_lzss_pack,
        lzss_unpack as native_lzss_unpack,
        md5_digest as native_md5_digest,
        xor_cycle_inplace as native_xor_cycle_inplace,
    )
    NATIVE_AVAILABLE = True
except ImportError:
    NATIVE_AVAILABLE = False
    print("Native module not available!")
    exit(1)

# Test data - use a portion of Scene.pck if available, otherwise generate data
test_file = "Scene.pck"
if os.path.exists(test_file):
    with open(test_file, "rb") as f:
        # Read first 100KB for benchmarking
        test_data = f.read(100_000)
    print(f"Using {len(test_data)} bytes from Scene.pck for benchmarking")
else:
    # Generate test data with some repetition (good for LZSS)
    test_data = (b"Hello, World! " * 1000 + b"x" * 50000)[:100_000]
    print(f"Using {len(test_data)} bytes of generated data for benchmarking")

print("\n" + "=" * 60)
print("PERFORMANCE BENCHMARK: Python vs Rust")
print("=" * 60)

# LZSS Pack benchmark
print("\n--- LZSS Compression ---")
iterations = 3

# Python
start = time.time()
for _ in range(iterations):
    py_packed = _py_lzss_pack(test_data)
py_time = (time.time() - start) / iterations
print(f"Python: {py_time:.4f}s per iteration")

# Rust
start = time.time()
for _ in range(iterations):
    rust_packed = native_lzss_pack(test_data)
rust_time = (time.time() - start) / iterations
print(f"Rust:   {rust_time:.4f}s per iteration")

if rust_time > 0:
    print(f">>> Speedup: {py_time / rust_time:.1f}x faster with Rust")

# LZSS Unpack benchmark
print("\n--- LZSS Decompression ---")
iterations = 50

# Python
start = time.time()
for _ in range(iterations):
    _py_lzss_unpack(py_packed)
py_time = (time.time() - start) / iterations
print(f"Python: {py_time * 1000:.4f}ms per iteration")

# Rust
start = time.time()
for _ in range(iterations):
    native_lzss_unpack(rust_packed)
rust_time = (time.time() - start) / iterations
print(f"Rust:   {rust_time * 1000:.4f}ms per iteration")

if rust_time > 0:
    print(f">>> Speedup: {py_time / rust_time:.1f}x faster with Rust")

# MD5 benchmark
print("\n--- MD5 Digest ---")
iterations = 100

# Python
start = time.time()
for _ in range(iterations):
    _py_md5_digest(test_data)
py_time = (time.time() - start) / iterations
print(f"Python: {py_time * 1000:.4f}ms per iteration")

# Rust  
start = time.time()
for _ in range(iterations):
    native_md5_digest(test_data)
rust_time = (time.time() - start) / iterations
print(f"Rust:   {rust_time * 1000:.4f}ms per iteration")

if rust_time > 0:
    print(f">>> Speedup: {py_time / rust_time:.1f}x faster with Rust")

# XOR cycle benchmark
print("\n--- XOR Cycle ---")
iterations = 1000
code = bytes([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0])

# Python
data_py = bytearray(test_data)
start = time.time()
for _ in range(iterations):
    _py_xor_cycle_inplace(data_py, code, 0)
py_time = (time.time() - start) / iterations
print(f"Python: {py_time * 1000:.4f}ms per iteration")

# Rust
data_rust = bytearray(test_data)
start = time.time()
for _ in range(iterations):
    native_xor_cycle_inplace(data_rust, code, 0)
rust_time = (time.time() - start) / iterations
print(f"Rust:   {rust_time * 1000:.4f}ms per iteration")

if rust_time > 0:
    print(f">>> Speedup: {py_time / rust_time:.1f}x faster with Rust")

print("\n" + "=" * 60)
print("Benchmark complete!")
print("=" * 60)
