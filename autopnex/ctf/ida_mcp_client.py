"""IDA Pro MCP 客户端 — 通过 MCP 协议连接 IDA Pro 进行二进制分析。

提供反编译、反汇编、交叉引用、字符串搜索、重命名等功能，
集成到 CTF 解题流程中辅助 Reverse 和 Pwn 题型分析。
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

log = logging.getLogger("autopnex.ctf.ida_mcp")


@dataclass
class IDAResult:
    """IDA Pro MCP 调用结果。"""

    success: bool
    data: Any = None
    error: Optional[str] = None


@dataclass
class IDAFunction:
    """IDA Pro 中的函数信息。"""

    name: str
    address: str
    size: int = 0


@dataclass
class IDAConfig:
    """IDA Pro MCP 连接配置。"""

    enabled: bool = True
    timeout: int = 30


class IDAMCPClient:
    """IDA Pro MCP 客户端。

    封装与 IDA Pro MCP 服务器的通信，提供高层 API 供 CTF 解题流程调用。
    当 MCP 服务不可用时优雅降级，不抛出异常。

    使用方式:
        client = IDAMCPClient(mcp_call=my_mcp_caller)
        if client.is_available():
            result = client.decompile_function("0x401000")
    """

    def __init__(
        self,
        mcp_call: Optional[Callable[..., Any]] = None,
        config: Optional[IDAConfig] = None,
    ) -> None:
        """初始化 IDA Pro MCP 客户端。

        Args:
            mcp_call: MCP 工具调用函数，签名为 (tool_name, **kwargs) -> result。
                      如果为 None，客户端将处于不可用状态。
            config: 连接配置。
        """
        self._mcp_call = mcp_call
        self._config = config or IDAConfig()
        self._available: Optional[bool] = None  # 延迟检测
        self._last_error: Optional[str] = None

    # ------------------------------------------------------------------
    # 连接管理
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """检测 IDA Pro MCP 服务是否可用。

        首次调用时执行实际连接检测，后续使用缓存结果。
        如果连接曾经失败，返回 False。

        Returns:
            True 如果 MCP 服务可用且响应正常。
        """
        if not self._config.enabled:
            return False

        if self._mcp_call is None:
            return False

        if self._available is not None:
            return self._available

        # 执行连接检测
        try:
            result = self._mcp_call("check_connection")
            self._available = result is not None
        except Exception as e:
            self._available = False
            self._last_error = str(e)
            log.warning("IDA Pro MCP 连接检测失败: %s", e)

        return self._available or False

    def get_metadata(self) -> IDAResult:
        """获取当前 IDB 的元数据信息。"""
        return self._safe_call("get_metadata")

    # ------------------------------------------------------------------
    # 反编译与反汇编
    # ------------------------------------------------------------------

    def decompile_function(self, address: str) -> IDAResult:
        """反编译指定地址的函数。

        Args:
            address: 函数地址（十六进制字符串，如 "0x401000"）。

        Returns:
            IDAResult，成功时 data 为伪代码字符串。
        """
        return self._safe_call("decompile_function", address=address)

    def decompile_by_name(self, name: str) -> IDAResult:
        """通过函数名反编译。

        先查找函数地址，再执行反编译。

        Args:
            name: 函数名称。

        Returns:
            IDAResult，成功时 data 为伪代码字符串。
        """
        # 先通过名称获取函数信息
        func_result = self._safe_call("get_function_by_name", name=name)
        if not func_result.success:
            return func_result

        # 从结果中提取地址
        address = self._extract_address(func_result.data)
        if not address:
            return IDAResult(success=False, error=f"无法获取函数 '{name}' 的地址")

        return self.decompile_function(address)

    def disassemble_function(self, address: str) -> IDAResult:
        """获取指定地址函数的汇编代码。

        Args:
            address: 函数起始地址。

        Returns:
            IDAResult，成功时 data 为汇编代码字符串。
        """
        return self._safe_call("disassemble_function", start_address=address)

    def list_functions(self, offset: int = 0, count: int = 100) -> IDAResult:
        """列出二进制文件中的函数（分页）。

        Args:
            offset: 起始偏移。
            count: 返回数量。

        Returns:
            IDAResult，成功时 data 为函数列表。
        """
        return self._safe_call("list_functions", offset=offset, count=count)

    def get_function_by_name(self, name: str) -> IDAResult:
        """通过名称获取函数信息。"""
        return self._safe_call("get_function_by_name", name=name)

    def get_function_by_address(self, address: str) -> IDAResult:
        """通过地址获取函数信息。"""
        return self._safe_call("get_function_by_address", address=address)

    # ------------------------------------------------------------------
    # 交叉引用与调用关系
    # ------------------------------------------------------------------

    def get_xrefs_to(self, address: str) -> IDAResult:
        """获取所有引用指定地址的位置。

        Args:
            address: 目标地址。

        Returns:
            IDAResult，成功时 data 为引用位置列表。
        """
        return self._safe_call("get_xrefs_to", address=address)

    def get_callees(self, function_address: str) -> IDAResult:
        """获取函数调用的所有子函数。

        Args:
            function_address: 函数地址。

        Returns:
            IDAResult，成功时 data 为被调用函数列表。
        """
        return self._safe_call("get_callees", function_address=function_address)

    def get_callers(self, function_address: str) -> IDAResult:
        """获取所有调用指定函数的调用者。

        Args:
            function_address: 函数地址。

        Returns:
            IDAResult，成功时 data 为调用者列表。
        """
        return self._safe_call("get_callers", function_address=function_address)

    def get_xrefs_to_field(self, struct_name: str, field_name: str) -> IDAResult:
        """获取结构体字段的交叉引用。"""
        return self._safe_call(
            "get_xrefs_to_field",
            struct_name=struct_name,
            field_name=field_name,
        )

    # ------------------------------------------------------------------
    # 符号与类型信息
    # ------------------------------------------------------------------

    def list_strings(
        self, offset: int = 0, count: int = 100, filter_text: str = ""
    ) -> IDAResult:
        """列出二进制文件中的字符串。

        Args:
            offset: 起始偏移。
            count: 返回数量。
            filter_text: 过滤文本（可选）。

        Returns:
            IDAResult，成功时 data 为字符串列表。
        """
        if filter_text:
            return self._safe_call(
                "list_strings_filter",
                offset=offset,
                count=count,
                filter=filter_text,
            )
        return self._safe_call("list_strings", offset=offset, count=count)

    def list_globals(
        self, offset: int = 0, count: int = 100, filter_text: str = ""
    ) -> IDAResult:
        """列出全局变量。"""
        if filter_text:
            return self._safe_call(
                "list_globals_filter",
                offset=offset,
                count=count,
                filter=filter_text,
            )
        return self._safe_call("list_globals", offset=offset, count=count)

    def list_imports(self, offset: int = 0, count: int = 100) -> IDAResult:
        """获取导入函数列表。"""
        return self._safe_call("list_imports", offset=offset, count=count)

    def get_global_variable_value(self, variable_name: str) -> IDAResult:
        """读取全局变量的编译时已知值。"""
        return self._safe_call(
            "get_global_variable_value_by_name",
            variable_name=variable_name,
        )

    def get_struct_info(self, name: str) -> IDAResult:
        """获取结构体定义和字段详情。"""
        return self._safe_call("analyze_struct_detailed", name=name)

    def list_local_types(self) -> IDAResult:
        """列出所有本地类型定义。"""
        return self._safe_call("list_local_types")

    # ------------------------------------------------------------------
    # 标注与重命名
    # ------------------------------------------------------------------

    def rename_function(self, function_address: str, new_name: str) -> IDAResult:
        """重命名函数。

        Args:
            function_address: 函数地址。
            new_name: 新名称。

        Returns:
            IDAResult。
        """
        return self._safe_call(
            "rename_function",
            function_address=function_address,
            new_name=new_name,
        )

    def rename_local_variable(
        self, function_address: str, old_name: str, new_name: str
    ) -> IDAResult:
        """重命名函数中的局部变量。"""
        return self._safe_call(
            "rename_local_variable",
            function_address=function_address,
            old_name=old_name,
            new_name=new_name,
        )

    def set_comment(self, address: str, comment: str) -> IDAResult:
        """在指定地址设置注释。"""
        return self._safe_call("set_comment", address=address, comment=comment)

    def set_function_prototype(self, function_address: str, prototype: str) -> IDAResult:
        """设置函数原型。"""
        return self._safe_call(
            "set_function_prototype",
            function_address=function_address,
            prototype=prototype,
        )

    def set_local_variable_type(
        self, function_address: str, variable_name: str, new_type: str
    ) -> IDAResult:
        """设置局部变量类型。"""
        return self._safe_call(
            "set_local_variable_type",
            function_address=function_address,
            variable_name=variable_name,
            new_type=new_type,
        )

    # ------------------------------------------------------------------
    # 高级分析辅助
    # ------------------------------------------------------------------

    def find_flag_related_strings(self) -> IDAResult:
        """搜索与 flag 相关的字符串。

        自动搜索包含 'flag'、'key'、'secret'、'password' 等关键词的字符串。

        Returns:
            IDAResult，成功时 data 为匹配的字符串列表。
        """
        keywords = ["flag", "key", "secret", "password", "correct", "success", "win"]
        all_results = []

        for keyword in keywords:
            result = self.list_strings(offset=0, count=50, filter_text=keyword)
            if result.success and result.data:
                if isinstance(result.data, list):
                    all_results.extend(result.data)
                else:
                    all_results.append(result.data)

        return IDAResult(success=True, data=all_results)

    def analyze_main_function(self) -> IDAResult:
        """分析 main 函数。

        尝试查找并反编译 main 函数，返回伪代码。

        Returns:
            IDAResult，成功时 data 为 main 函数的伪代码。
        """
        # 尝试常见的 main 函数名
        main_names = ["main", "_main", "wmain", "_wmain", "WinMain"]
        for name in main_names:
            result = self.decompile_by_name(name)
            if result.success:
                return result

        # 尝试通过入口点
        entry_result = self._safe_call("get_entry_points")
        if entry_result.success and entry_result.data:
            entries = entry_result.data
            if isinstance(entries, list) and len(entries) > 0:
                first_entry = entries[0]
                addr = self._extract_address(first_entry)
                if addr:
                    return self.decompile_function(addr)

        return IDAResult(success=False, error="无法找到 main 函数")

    def get_vulnerable_functions(self) -> IDAResult:
        """搜索可能存在漏洞的危险函数调用。

        搜索 gets、strcpy、sprintf、scanf 等危险函数的导入和交叉引用。

        Returns:
            IDAResult，成功时 data 为危险函数及其调用位置的字典。
        """
        dangerous_funcs = [
            "gets", "strcpy", "strcat", "sprintf", "vsprintf",
            "scanf", "fscanf", "sscanf", "read", "recv",
            "memcpy", "memmove", "system", "exec", "popen",
        ]

        vuln_info: Dict[str, Any] = {}

        for func_name in dangerous_funcs:
            # 查找函数
            result = self.get_function_by_name(func_name)
            if result.success and result.data:
                address = self._extract_address(result.data)
                if address:
                    # 获取交叉引用（谁调用了这个危险函数）
                    xrefs = self.get_xrefs_to(address)
                    if xrefs.success and xrefs.data:
                        vuln_info[func_name] = {
                            "address": address,
                            "xrefs": xrefs.data,
                        }

        return IDAResult(success=bool(vuln_info), data=vuln_info)

    # ------------------------------------------------------------------
    # 内部方法
    # ------------------------------------------------------------------

    def _safe_call(self, tool_name: str, **kwargs: Any) -> IDAResult:
        """安全调用 MCP 工具，捕获所有异常。

        Args:
            tool_name: MCP 工具名称。
            **kwargs: 工具参数。

        Returns:
            IDAResult，失败时包含错误信息。
        """
        if not self.is_available():
            return IDAResult(
                success=False,
                error="IDA Pro MCP 服务不可用",
            )

        try:
            result = self._mcp_call(tool_name, **kwargs)
            return IDAResult(success=True, data=result)
        except Exception as e:
            error_msg = f"IDA MCP 调用失败 ({tool_name}): {e}"
            log.error(error_msg)
            # 标记为不可用（连接可能已断开）
            self._available = False
            self._last_error = error_msg
            return IDAResult(success=False, error=error_msg)

    def _extract_address(self, data: Any) -> Optional[str]:
        """从 MCP 返回数据中提取地址。"""
        if data is None:
            return None
        if isinstance(data, str):
            # 可能直接是地址字符串
            if data.startswith("0x") or data.startswith("0X"):
                return data
            return None
        if isinstance(data, dict):
            # 尝试常见的地址字段名
            for key in ("address", "addr", "start_address", "ea", "start"):
                if key in data:
                    val = data[key]
                    if isinstance(val, (int, str)):
                        return str(val) if isinstance(val, str) else hex(val)
            return None
        if isinstance(data, int):
            return hex(data)
        return None
