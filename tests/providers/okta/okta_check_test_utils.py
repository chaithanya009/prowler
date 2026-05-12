import importlib
import sys
from contextlib import contextmanager
from types import ModuleType


@contextmanager
def load_check_with_clients(check_module: str, clients: dict[str, dict[str, object]]):
    old_check = sys.modules.pop(check_module, None)
    old_clients = {name: sys.modules.get(name) for name in clients}
    missing_clients = {name for name in clients if name not in sys.modules}

    for module_name, attributes in clients.items():
        module = ModuleType(module_name)
        for name, value in attributes.items():
            setattr(module, name, value)
        sys.modules[module_name] = module

    try:
        yield importlib.import_module(check_module)
    finally:
        sys.modules.pop(check_module, None)
        if old_check is not None:
            sys.modules[check_module] = old_check

        for module_name, module in old_clients.items():
            if module_name in missing_clients:
                sys.modules.pop(module_name, None)
            else:
                sys.modules[module_name] = module
