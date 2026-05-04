__version__ = "0.3.0"
const = None
try:
    from ._const_manager import get_const_module

    const = get_const_module()
except Exception:
    const = None
