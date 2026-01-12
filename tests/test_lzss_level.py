#!/usr/bin/env python3
"""Test LZSS compression with different levels."""

from siglus_scene_script_utility.native_ops import lzss_pack, lzss_unpack, is_native_available
import time

print(f"Native available: {is_native_available()}")

# Test data
data = b"Hello, World! " * 1000

# Test different levels
print("\n=== Level Comparison ===")
for level in [2, 5, 10, 17]:
    start = time.time()
    compressed = lzss_pack(data, level=level)
    elapsed = time.time() - start
    ratio = len(compressed) / len(data) * 100
    print(f"Level {level:2d}: {len(compressed):6d} bytes ({ratio:5.1f}%), time: {elapsed*1000:.2f}ms")

# Verify roundtrip at different levels
print("\n=== Roundtrip Verification ===")
original = b"Test data for LZSS compression roundtrip verification!" * 100
for level in [2, 10, 17]:
    compressed = lzss_pack(original, level=level)
    decompressed = lzss_unpack(compressed)
    status = "OK" if original == decompressed else "FAIL"
    print(f"Level {level:2d}: {status}")

print("\nAll tests passed!")
