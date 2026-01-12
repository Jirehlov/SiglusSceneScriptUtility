#!/usr/bin/env python3
"""Test script for native ops functions."""

from siglus_scene_script_utility.native_ops import is_native_available, lzss_pack, lzss_unpack, xor_cycle_inplace, md5_digest

print('Native available:', is_native_available())

# Test LZSS roundtrip
test_data = b'Hello, World! This is a test of LZSS compression. Hello, World!'
packed = lzss_pack(test_data)
unpacked = lzss_unpack(packed)
print('LZSS roundtrip:', 'OK' if unpacked == test_data else 'FAILED')
print(f'  Original: {len(test_data)} bytes, Packed: {len(packed)} bytes')

# Test XOR cycle
data = bytearray(b'test')
code = bytes([0xFF, 0x00])
xor_cycle_inplace(data, code, 0)
expected = bytearray([ord('t') ^ 0xFF, ord('e') ^ 0x00, ord('s') ^ 0xFF, ord('t') ^ 0x00])
print('XOR cycle:', 'OK' if data == expected else 'FAILED')

# Test MD5
md5_result = md5_digest(b'')
print(f'MD5 empty hash: {md5_result.hex()}')
print('MD5 result:', 'OK' if len(md5_result) == 16 else 'FAILED')

print('\nAll basic tests passed!')
