__version__ = "0.2.1"

try:
    from ._const_manager import get_const_module

    const = get_const_module()
except Exception:
    pass
