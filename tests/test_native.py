from siglus_scene_script_utility.native_ops import (
    is_native_available,
    lzss_pack,
    lzss_unpack,
    xor_cycle_inplace,
    md5_digest,
)


def test_native_availability():
    """Ensure native extension is available (since we built it)."""
    assert is_native_available() is True, "Native extension should be available"


def test_lzss_roundtrip():
    """Test LZSS compression and decompression."""
    test_data = b"Hello, World! This is a test of LZSS compression. Hello, World!"
    packed = lzss_pack(test_data)
    unpacked = lzss_unpack(packed)
    assert unpacked == test_data
    # Compression should usually reduce size for repetitive data
    assert len(packed) < len(test_data) + 64  # Basic sanity check


def test_xor_cycle():
    """Test inline XOR cycle."""
    data = bytearray(b"test")
    code = bytes([0xFF, 0x00])
    xor_cycle_inplace(data, code, 0)
    expected = bytearray(
        [ord("t") ^ 0xFF, ord("e") ^ 0x00, ord("s") ^ 0xFF, ord("t") ^ 0x00]
    )
    assert data == expected


def test_md5():
    """Test MD5 digest."""
    # MD5 of empty string is d41d8cd98f00b204e9800998ecf8427e
    md5_result = md5_digest(b"")
    assert len(md5_result) == 16
    assert md5_result.hex() == "d41d8cd98f00b204e9800998ecf8427e"
