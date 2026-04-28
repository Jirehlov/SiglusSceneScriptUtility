__version__ = "0.2.8"
const = None
try:
    from ._const_manager import get_const_module

    const = get_const_module()
except Exception:
    const = None
