__version__ = "0.2.1"

try:
    from ._const_manager import const_exists, load_const_module

    if const_exists():
        load_const_module()
except Exception:
    pass
