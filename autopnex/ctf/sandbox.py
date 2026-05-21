"""CTF 沙箱模块 — 隔离执行环境管理。

提供基于 Docker 容器或子进程的隔离执行环境，
支持 web/pwn/crypto/misc/reverse 五种 CTF 题型。

当 Docker 不可用时，自动降级为基于临时目录的子进程隔离模式。
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Dict, Optional


# ---------------------------------------------------------------------------
# CTFSandbox
# ---------------------------------------------------------------------------


class CTFSandbox:
    """Docker container lifecycle manager for CTF sandboxing.

    支持五种 CTF 题型的隔离执行环境：
    - web: Web 漏洞利用（requests, beautifulsoup4, sqlmap）
    - pwn: 二进制漏洞利用（pwntools, gdb, pwndbg, ROPgadget）
    - crypto: 密码学（pycryptodome, gmpy2, z3-solver）
    - misc: 杂项（binwalk, steghide, exiftool, wireshark）
    - reverse: 逆向工程（binutils, ltrace, strace, radare2）

    当 Docker 不可用时，自动降级为基于临时目录的子进程隔离模式。

    Args:
        challenge_type: 题目类型，支持 web|pwn|crypto|misc|reverse，默认 "web"。
        timeout: 默认超时时间（秒），默认 300。
    """

    # Docker 镜像映射
    _DOCKER_IMAGES: Dict[str, str] = {
        "web": "ctf-sandbox-web:latest",
        "pwn": "ctf-sandbox-pwn:latest",
        "crypto": "ctf-sandbox-crypto:latest",
        "misc": "ctf-sandbox-misc:latest",
        "reverse": "ctf-sandbox-reverse:latest",
    }

    # 脚本语言解释器映射
    _INTERPRETERS: Dict[str, str] = {
        "python": sys.executable,
        "python3": sys.executable,
        "bash": "bash",
        "sh": "sh",
        "ruby": "ruby",
        "perl": "perl",
        "node": "node",
        "nodejs": "node",
    }

    def __init__(
        self,
        challenge_type: str = "web",
        timeout: int = 300,
    ) -> None:
        """初始化 CTF 沙箱。

        Args:
            challenge_type: 题目类型，支持 web|pwn|crypto|misc|reverse。
            timeout: 默认超时时间（秒）。
        """
        self.challenge_type = challenge_type.lower()
        self.timeout = timeout
        self._docker_available = self._check_docker()
        self._sessions: Dict[str, dict] = {}

    # ------------------------------------------------------------------
    # 公开接口
    # ------------------------------------------------------------------

    def create_session(self, session_id: Optional[str] = None) -> str:
        """创建隔离执行会话。

        如果 Docker 可用，启动一个 Docker 容器作为会话；
        否则创建一个临时目录作为会话工作区。

        Args:
            session_id: 可选的会话 ID，不提供时自动生成 UUID。

        Returns:
            会话 ID 字符串。
        """
        if session_id is None:
            session_id = str(uuid.uuid4())

        if self._docker_available:
            success = self._create_docker_container(session_id)
            if success:
                self._sessions[session_id] = {
                    "type": "docker",
                    "container_id": session_id,
                    "workspace": None,
                }
                return session_id
            # Docker 创建失败，降级到子进程模式
        
        # 子进程隔离模式：创建临时目录
        workspace = tempfile.mkdtemp(prefix=f"ctf_sandbox_{session_id[:8]}_")
        self._sessions[session_id] = {
            "type": "subprocess",
            "container_id": None,
            "workspace": workspace,
        }
        return session_id

    def execute_in_sandbox(
        self,
        session_id: str,
        command: str,
        timeout: int = 30,
    ) -> dict:
        """在沙箱中执行命令。

        Args:
            session_id: 会话 ID，必须已通过 create_session() 创建。
            command: 要执行的 shell 命令。
            timeout: 命令超时时间（秒），默认 30。

        Returns:
            包含 stdout、stderr、returncode 的字典：
            {
                "stdout": str,
                "stderr": str,
                "returncode": int,
            }

        Raises:
            KeyError: 当 session_id 不存在时。
        """
        if session_id not in self._sessions:
            raise KeyError(f"会话不存在: {session_id}")

        session = self._sessions[session_id]

        if session["type"] == "docker":
            return self._docker_exec(session_id, command, timeout)
        else:
            return self._subprocess_exec(command, session["workspace"], timeout)

    def execute_script(
        self,
        session_id: str,
        script: str,
        language: str = "python",
    ) -> dict:
        """在沙箱中执行脚本。

        将脚本写入会话工作区的临时文件，然后用对应解释器执行。

        Args:
            session_id: 会话 ID，必须已通过 create_session() 创建。
            script: 脚本内容字符串。
            language: 脚本语言，支持 python/python3/bash/sh/ruby/perl/node，默认 "python"。

        Returns:
            包含 stdout、stderr、returncode 的字典：
            {
                "stdout": str,
                "stderr": str,
                "returncode": int,
            }

        Raises:
            KeyError: 当 session_id 不存在时。
            ValueError: 当 language 不受支持时。
        """
        if session_id not in self._sessions:
            raise KeyError(f"会话不存在: {session_id}")

        lang = language.lower()
        if lang not in self._INTERPRETERS:
            raise ValueError(
                f"不支持的脚本语言: {language}。"
                f"支持的语言: {', '.join(self._INTERPRETERS.keys())}"
            )

        session = self._sessions[session_id]

        # 确定脚本文件扩展名
        ext_map = {
            "python": ".py",
            "python3": ".py",
            "bash": ".sh",
            "sh": ".sh",
            "ruby": ".rb",
            "perl": ".pl",
            "node": ".js",
            "nodejs": ".js",
        }
        ext = ext_map.get(lang, ".txt")

        # 写入脚本到临时文件
        if session["type"] == "docker":
            # Docker 模式：先写到本地临时文件，再复制到容器
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=ext,
                delete=False,
                encoding="utf-8",
            ) as f:
                f.write(script)
                local_script_path = f.name

            try:
                # 复制脚本到容器
                container_script = f"/tmp/script_{uuid.uuid4().hex[:8]}{ext}"
                copy_result = subprocess.run(
                    ["docker", "cp", local_script_path, f"{session_id}:{container_script}"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if copy_result.returncode != 0:
                    return {
                        "stdout": "",
                        "stderr": f"Failed to copy script to container: {copy_result.stderr}",
                        "returncode": 1,
                    }

                # 在容器中执行脚本
                interpreter = self._get_docker_interpreter(lang)
                return self._docker_exec(
                    session_id,
                    f"{interpreter} {container_script}",
                    self.timeout,
                )
            finally:
                os.unlink(local_script_path)
        else:
            # 子进程模式：写入工作区
            workspace = session["workspace"]
            script_path = os.path.join(workspace, f"script_{uuid.uuid4().hex[:8]}{ext}")
            with open(script_path, "w", encoding="utf-8") as f:
                f.write(script)

            interpreter = self._INTERPRETERS[lang]
            command = f'"{interpreter}" "{script_path}"'
            return self._subprocess_exec(command, workspace, self.timeout)

    def destroy_session(self, session_id: str) -> bool:
        """销毁会话，释放资源。

        Args:
            session_id: 要销毁的会话 ID。

        Returns:
            True 表示成功销毁，False 表示会话不存在或销毁失败。
        """
        if session_id not in self._sessions:
            return False

        session = self._sessions[session_id]

        if session["type"] == "docker":
            try:
                subprocess.run(
                    ["docker", "rm", "-f", session_id],
                    capture_output=True,
                    timeout=15,
                )
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                pass
        else:
            workspace = session.get("workspace")
            if workspace and os.path.exists(workspace):
                try:
                    shutil.rmtree(workspace, ignore_errors=True)
                except OSError:
                    pass

        del self._sessions[session_id]
        return True

    def destroy_all_sessions(self) -> int:
        """销毁所有活跃会话。

        Returns:
            成功销毁的会话数量。
        """
        session_ids = list(self._sessions.keys())
        count = 0
        for sid in session_ids:
            if self.destroy_session(sid):
                count += 1
        return count

    def list_sessions(self) -> list:
        """列出所有活跃会话 ID。

        Returns:
            会话 ID 列表。
        """
        return list(self._sessions.keys())

    # ------------------------------------------------------------------
    # Docker 相关内部方法
    # ------------------------------------------------------------------

    def _check_docker(self) -> bool:
        """检查 Docker 是否可用。

        Returns:
            True 表示 Docker 可用，False 表示不可用。
        """
        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return False

    def _create_docker_container(self, session_id: str) -> bool:
        """创建带网络隔离和资源限制的 Docker 容器。

        容器配置：
        - --network none: 无网络访问（网络隔离）
        - --memory 512m: 内存限制 512MB
        - --cpus 1: CPU 限制 1 核
        - --read-only: 只读文件系统（/tmp 除外）
        - --tmpfs /tmp: 可写的 /tmp 目录

        Args:
            session_id: 容器名称/ID。

        Returns:
            True 表示容器创建成功，False 表示失败。
        """
        image = self._DOCKER_IMAGES.get(self.challenge_type, self._DOCKER_IMAGES["web"])

        cmd = [
            "docker", "run",
            "-d",                          # 后台运行
            "--name", session_id,          # 容器名称
            "--network", "none",           # 网络隔离
            "--memory", "512m",            # 内存限制
            "--cpus", "1",                 # CPU 限制
            "--read-only",                 # 只读文件系统
            "--tmpfs", "/tmp:rw,size=256m",  # 可写的 /tmp
            "--rm",                        # 退出后自动删除（但我们用 -d 所以需要手动 rm）
            image,
            "sleep", str(self.timeout),   # 保持容器运行
        ]

        # 移除 --rm（与 -d 配合时行为不一致，改为手动 rm）
        cmd = [
            "docker", "run",
            "-d",
            "--name", session_id,
            "--network", "none",
            "--memory", "512m",
            "--cpus", "1",
            "--read-only",
            "--tmpfs", "/tmp:rw,size=256m",
            image,
            "sleep", str(self.timeout),
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False

    def _docker_exec(
        self,
        session_id: str,
        command: str,
        timeout: int,
    ) -> dict:
        """在 Docker 容器中执行命令。

        Args:
            session_id: 容器名称/ID。
            command: 要执行的命令。
            timeout: 超时时间（秒）。

        Returns:
            {stdout, stderr, returncode} 字典。
        """
        cmd = ["docker", "exec", session_id, "sh", "-c", command]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
            }
        except subprocess.TimeoutExpired:
            return {
                "stdout": "",
                "stderr": f"命令执行超时（{timeout}秒）",
                "returncode": -1,
            }
        except (FileNotFoundError, OSError) as e:
            return {
                "stdout": "",
                "stderr": f"Docker 执行失败: {e}",
                "returncode": -1,
            }

    def _get_docker_interpreter(self, language: str) -> str:
        """获取 Docker 容器内的解释器路径。

        Args:
            language: 脚本语言名称。

        Returns:
            解释器命令字符串。
        """
        docker_interpreters = {
            "python": "python3",
            "python3": "python3",
            "bash": "bash",
            "sh": "sh",
            "ruby": "ruby",
            "perl": "perl",
            "node": "node",
            "nodejs": "node",
        }
        return docker_interpreters.get(language.lower(), "python3")

    # ------------------------------------------------------------------
    # 子进程隔离内部方法
    # ------------------------------------------------------------------

    def _subprocess_exec(
        self,
        command: str,
        workspace: Optional[str],
        timeout: int,
    ) -> dict:
        """在子进程中执行命令（降级模式）。

        Args:
            command: 要执行的命令。
            workspace: 工作目录路径。
            timeout: 超时时间（秒）。

        Returns:
            {stdout, stderr, returncode} 字典。
        """
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=workspace,
            )
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
            }
        except subprocess.TimeoutExpired:
            return {
                "stdout": "",
                "stderr": f"命令执行超时（{timeout}秒）",
                "returncode": -1,
            }
        except (OSError, ValueError) as e:
            return {
                "stdout": "",
                "stderr": f"命令执行失败: {e}",
                "returncode": -1,
            }
