_LEGACY_COMPILE = False
_LEGACY_FULL = False
_SCENE_STRING_XOR_MULTIPLIER = 0x7087

const = None
try:
    from ._const_manager import get_const_module

    const = get_const_module()
except Exception:
    const = None
