"""IDA Pro MCP 客户端单元测试。"""
import pytest

from autopnex.ctf.ida_mcp_client import IDAMCPClient, IDAConfig, IDAResult


class TestIDAMCPClientAvailability:
    """测试连接可用性检测。"""

    def test_unavailable_when_no_mcp_call(self):
        """无 mcp_call 时应不可用。"""
        client = IDAMCPClient(mcp_call=None)
        assert client.is_available() is False

    def test_unavailable_when_disabled(self):
        """配置禁用时应不可用。"""
        client = IDAMCPClient(
            mcp_call=lambda *a, **kw: True,
            config=IDAConfig(enabled=False),
        )
        assert client.is_available() is False

    def test_available_when_check_succeeds(self):
        """check_connection 成功时应可用。"""
        def mock_mcp(tool_name, **kwargs):
            if tool_name == "check_connection":
                return {"status": "ok"}
            return None

        client = IDAMCPClient(mcp_call=mock_mcp)
        assert client.is_available() is True

    def test_unavailable_when_check_raises(self):
        """check_connection 抛异常时应不可用。"""
        def mock_mcp(tool_name, **kwargs):
            raise ConnectionError("IDA not running")

        client = IDAMCPClient(mcp_call=mock_mcp)
        assert client.is_available() is False

    def test_caches_availability_result(self):
        """可用性结果应被缓存。"""
        call_count = [0]

        def mock_mcp(tool_name, **kwargs):
            call_count[0] += 1
            return {"status": "ok"}

        client = IDAMCPClient(mcp_call=mock_mcp)
        client.is_available()
        client.is_available()
        assert call_count[0] == 1  # 只调用一次


class TestIDAMCPClientDecompile:
    """测试反编译功能。"""

    def _make_client(self, responses=None):
        """创建带 mock 响应的客户端。"""
        responses = responses or {}

        def mock_mcp(tool_name, **kwargs):
            if tool_name == "check_connection":
                return {"status": "ok"}
            if tool_name in responses:
                return responses[tool_name]
            return f"result_for_{tool_name}"

        return IDAMCPClient(mcp_call=mock_mcp)

    def test_decompile_function_success(self):
        """反编译成功应返回伪代码。"""
        client = self._make_client({
            "decompile_function": "int main() { return 0; }"
        })
        result = client.decompile_function("0x401000")
        assert result.success is True
        assert "main" in result.data

    def test_decompile_by_name_success(self):
        """通过名称反编译成功。"""
        client = self._make_client({
            "get_function_by_name": {"address": 0x401000, "name": "main"},
            "decompile_function": "int main() { return 0; }",
        })
        result = client.decompile_by_name("main")
        assert result.success is True

    def test_decompile_unavailable_client(self):
        """不可用客户端应返回失败。"""
        client = IDAMCPClient(mcp_call=None)
        result = client.decompile_function("0x401000")
        assert result.success is False
        assert "不可用" in result.error


class TestIDAMCPClientXrefs:
    """测试交叉引用功能。"""

    def _make_client(self):
        def mock_mcp(tool_name, **kwargs):
            if tool_name == "check_connection":
                return {"status": "ok"}
            if tool_name == "get_xrefs_to":
                return [{"from": "0x401100"}, {"from": "0x401200"}]
            if tool_name == "get_callees":
                return [{"name": "puts", "address": "0x401050"}]
            if tool_name == "get_callers":
                return [{"name": "main", "address": "0x401000"}]
            return None

        return IDAMCPClient(mcp_call=mock_mcp)

    def test_get_xrefs_to(self):
        client = self._make_client()
        result = client.get_xrefs_to("0x401000")
        assert result.success is True
        assert len(result.data) == 2

    def test_get_callees(self):
        client = self._make_client()
        result = client.get_callees("0x401000")
        assert result.success is True

    def test_get_callers(self):
        client = self._make_client()
        result = client.get_callers("0x401050")
        assert result.success is True


class TestIDAMCPClientStrings:
    """测试字符串和符号功能。"""

    def _make_client(self):
        def mock_mcp(tool_name, **kwargs):
            if tool_name == "check_connection":
                return {"status": "ok"}
            if tool_name == "list_strings":
                return [{"value": "flag{test}", "address": "0x402000"}]
            if tool_name == "list_strings_filter":
                return [{"value": "flag{test}", "address": "0x402000"}]
            if tool_name == "list_imports":
                return [{"name": "puts", "module": "libc"}]
            return []

        return IDAMCPClient(mcp_call=mock_mcp)

    def test_list_strings(self):
        client = self._make_client()
        result = client.list_strings()
        assert result.success is True

    def test_list_strings_with_filter(self):
        client = self._make_client()
        result = client.list_strings(filter_text="flag")
        assert result.success is True

    def test_list_imports(self):
        client = self._make_client()
        result = client.list_imports()
        assert result.success is True


class TestIDAMCPClientRename:
    """测试重命名和标注功能。"""

    def _make_client(self):
        def mock_mcp(tool_name, **kwargs):
            if tool_name == "check_connection":
                return {"status": "ok"}
            return {"success": True}

        return IDAMCPClient(mcp_call=mock_mcp)

    def test_rename_function(self):
        client = self._make_client()
        result = client.rename_function("0x401000", "check_password")
        assert result.success is True

    def test_set_comment(self):
        client = self._make_client()
        result = client.set_comment("0x401000", "This is the main check")
        assert result.success is True

    def test_rename_local_variable(self):
        client = self._make_client()
        result = client.rename_local_variable("0x401000", "v1", "user_input")
        assert result.success is True


class TestIDAMCPClientHighLevel:
    """测试高级分析辅助功能。"""

    def _make_client(self):
        def mock_mcp(tool_name, **kwargs):
            if tool_name == "check_connection":
                return {"status": "ok"}
            if tool_name == "list_strings_filter":
                filter_val = kwargs.get("filter", "")
                if "flag" in filter_val:
                    return [{"value": "flag{found_it}", "address": "0x402000"}]
                return []
            if tool_name == "get_function_by_name":
                name = kwargs.get("name", "")
                if name == "main":
                    return {"address": 0x401000, "name": "main"}
                if name in ("gets", "strcpy"):
                    return {"address": 0x401500, "name": name}
                return None
            if tool_name == "decompile_function":
                return "int main() { char buf[64]; gets(buf); return 0; }"
            if tool_name == "get_xrefs_to":
                return [{"from": "0x401100"}]
            if tool_name == "get_entry_points":
                return [{"address": 0x401000}]
            return None

        return IDAMCPClient(mcp_call=mock_mcp)

    def test_find_flag_related_strings(self):
        client = self._make_client()
        result = client.find_flag_related_strings()
        assert result.success is True
        assert len(result.data) > 0

    def test_analyze_main_function(self):
        client = self._make_client()
        result = client.analyze_main_function()
        assert result.success is True
        assert "main" in result.data

    def test_get_vulnerable_functions(self):
        client = self._make_client()
        result = client.get_vulnerable_functions()
        assert result.success is True
        assert "gets" in result.data
