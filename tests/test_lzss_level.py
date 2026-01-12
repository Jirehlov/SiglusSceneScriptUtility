import pytest
from siglus_scene_script_utility.native_ops import (
    lzss_pack,
    lzss_unpack,
)


@pytest.mark.parametrize("level", [2, 5, 10, 17])
def test_lzss_level_compression(level):
    """Test LZSS compression with different levels."""
    data = b"Hello, World! " * 1000
    compressed = lzss_pack(data, level=level)

    # Basic sanity checks
    assert len(compressed) > 0
    # Higher levels generally should compact better (though not strictly guaranteed for short/simple data)
    # This test just ensures valid output at each level

    # Verify roundtrip
    decompressed = lzss_unpack(compressed)
    assert decompressed == data


def test_lzss_level_impact():
    """Verify that level 2 (fastest) is indeed generally larger/same size as level 17 (best)."""
    data = b"Hello, World! " * 5000 + b"x" * 5000  # Mixed data pattern
    c_low = lzss_pack(data, level=2)
    c_high = lzss_pack(data, level=17)

    # Level 2 (min match=2) has less chance to compress than Level 17 (max match=17)
    # However, since the look ahead is always 17 in implementation, level controls max match length
    # A smaller max match length means less compression for long repetitions
    assert len(c_low) >= len(c_high)
