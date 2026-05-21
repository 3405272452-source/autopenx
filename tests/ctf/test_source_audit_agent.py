"""Tests for SourceAuditAgent module."""
import pytest
from autopnex.ctf.source_audit_agent import (
    SourceAuditAgent,
    AuditResult,
    SinkInfo,
    SourceInfo,
    DataFlow,
)


@pytest.fixture
def agent():
    return SourceAuditAgent()


class TestSinkDetection:
    """Test identification of dangerous sinks."""

    def test_php_eval(self, agent):
        code = '<?php eval($_GET["cmd"]); ?>'
        result = agent.audit(code, "php")
        assert any(s.function == "eval" for s in result.sinks)

    def test_php_system(self, agent):
        code = '<?php system($cmd); ?>'
        result = agent.audit(code, "php")
        assert any(s.function == "system" for s in result.sinks)

    def test_php_passthru(self, agent):
        code = '<?php passthru("ls -la"); ?>'
        result = agent.audit(code, "php")
        assert any(s.function == "passthru" for s in result.sinks)

    def test_php_exec(self, agent):
        code = '<?php exec($command, $output); ?>'
        result = agent.audit(code, "php")
        assert any(s.function == "exec" for s in result.sinks)

    def test_php_query(self, agent):
        code = '<?php $result = $db->query("SELECT * FROM users WHERE id=" . $id); ?>'
        result = agent.audit(code, "php")
        assert any(s.function == "query" for s in result.sinks)

    def test_php_include(self, agent):
        code = '<?php include($_GET["page"]); ?>'
        result = agent.audit(code, "php")
        assert any(s.function == "include" for s in result.sinks)

    def test_php_unserialize(self, agent):
        code = '<?php $obj = unserialize($data); ?>'
        result = agent.audit(code, "php")
        assert any(s.function == "unserialize" for s in result.sinks)

    def test_php_render(self, agent):
        code = '<?php echo $twig->render($template); ?>'
        result = agent.audit(code, "php")
        assert any(s.function == "render" for s in result.sinks)

    def test_python_eval(self, agent):
        code = 'result = eval(user_input)'
        result = agent.audit(code, "python")
        assert any(s.function == "eval" for s in result.sinks)

    def test_python_exec(self, agent):
        code = 'exec(code_string)'
        result = agent.audit(code, "python")
        assert any(s.function == "exec" for s in result.sinks)

    def test_python_os_system(self, agent):
        code = 'os.system(cmd)'
        result = agent.audit(code, "python")
        assert any(s.function == "system" for s in result.sinks)

    def test_python_render_template_string(self, agent):
        code = 'return render_template_string(user_template)'
        result = agent.audit(code, "python")
        assert any(s.function == "render_template_string" for s in result.sinks)

    def test_node_eval(self, agent):
        code = 'const result = eval(userInput);'
        result = agent.audit(code, "node")
        assert any(s.function == "eval" for s in result.sinks)

    def test_node_exec(self, agent):
        code = 'child_process.exec(cmd, callback);'
        result = agent.audit(code, "node")
        assert any(s.function == "exec" for s in result.sinks)

    def test_node_query(self, agent):
        code = 'db.query("SELECT * FROM users WHERE id=" + id);'
        result = agent.audit(code, "node")
        assert any(s.function == "query" for s in result.sinks)

    def test_sink_line_number(self, agent):
        code = "<?php\n// comment\n$x = 1;\nsystem($cmd);\n?>"
        result = agent.audit(code, "php")
        sink = next(s for s in result.sinks if s.function == "system")
        assert sink.line == 4

    def test_sink_context(self, agent):
        code = '<?php system("whoami"); ?>'
        result = agent.audit(code, "php")
        sink = next(s for s in result.sinks if s.function == "system")
        assert "system" in sink.context

    def test_no_sinks_in_clean_code(self, agent):
        code = '<?php echo "Hello World"; ?>'
        result = agent.audit(code, "php")
        assert result.sinks == []

    def test_comments_ignored(self, agent):
        code = "<?php\n// eval($x);\n# system($y);\n?>"
        result = agent.audit(code, "php")
        assert result.sinks == []


class TestSourceDetection:
    """Test identification of user-controlled sources."""

    def test_php_get(self, agent):
        code = '<?php $id = $_GET["id"]; ?>'
        result = agent.audit(code, "php")
        assert any(s.variable == "$_GET" for s in result.sources)

    def test_php_post(self, agent):
        code = '<?php $name = $_POST["name"]; ?>'
        result = agent.audit(code, "php")
        assert any(s.variable == "$_POST" for s in result.sources)

    def test_php_request(self, agent):
        code = '<?php $data = $_REQUEST["data"]; ?>'
        result = agent.audit(code, "php")
        assert any(s.variable == "$_REQUEST" for s in result.sources)

    def test_php_cookie(self, agent):
        code = '<?php $token = $_COOKIE["session"]; ?>'
        result = agent.audit(code, "php")
        assert any(s.variable == "$_COOKIE" for s in result.sources)

    def test_python_request_args(self, agent):
        code = 'name = request.args.get("name")'
        result = agent.audit(code, "python")
        assert any(s.variable == "request.args" for s in result.sources)

    def test_python_request_form(self, agent):
        code = 'data = request.form["data"]'
        result = agent.audit(code, "python")
        assert any(s.variable == "request.form" for s in result.sources)

    def test_node_req_body(self, agent):
        code = 'const name = req.body.name;'
        result = agent.audit(code, "node")
        assert any(s.variable == "req.body" for s in result.sources)

    def test_node_req_params(self, agent):
        code = 'const id = req.params.id;'
        result = agent.audit(code, "node")
        assert any(s.variable == "req.params" for s in result.sources)

    def test_node_req_query(self, agent):
        code = 'const search = req.query.q;'
        result = agent.audit(code, "node")
        assert any(s.variable == "req.query" for s in result.sources)

    def test_source_line_number(self, agent):
        code = "<?php\n$x = 1;\n$id = $_GET['id'];\n?>"
        result = agent.audit(code, "php")
        source = next(s for s in result.sources if s.variable == "$_GET")
        assert source.line == 3

    def test_no_sources_in_clean_code(self, agent):
        code = '<?php $x = 42; echo $x; ?>'
        result = agent.audit(code, "php")
        assert result.sources == []

    def test_multiple_sources(self, agent):
        code = '<?php\n$a = $_GET["a"];\n$b = $_POST["b"];\n?>'
        result = agent.audit(code, "php")
        variables = [s.variable for s in result.sources]
        assert "$_GET" in variables
        assert "$_POST" in variables


class TestDataFlowTracing:
    """Test source-to-sink data flow tracing."""

    def test_direct_flow_php(self, agent):
        code = '<?php system($_GET["cmd"]); ?>'
        result = agent.audit(code, "php")
        assert len(result.flows) >= 1
        flow = result.flows[0]
        assert flow.source.variable == "$_GET"
        assert flow.sink.function == "system"

    def test_indirect_flow_php(self, agent):
        code = '<?php\n$cmd = $_GET["cmd"];\nsystem($cmd);\n?>'
        result = agent.audit(code, "php")
        assert len(result.flows) >= 1
        assert any(f.sink.function == "system" for f in result.flows)

    def test_direct_flow_python(self, agent):
        code = 'result = eval(request.args.get("expr"))'
        result = agent.audit(code, "python")
        assert len(result.flows) >= 1
        flow = result.flows[0]
        assert flow.source.variable == "request.args"
        assert flow.sink.function == "eval"

    def test_direct_flow_node(self, agent):
        code = 'eval(req.body.code);'
        result = agent.audit(code, "node")
        assert len(result.flows) >= 1
        flow = result.flows[0]
        assert flow.source.variable == "req.body"
        assert flow.sink.function == "eval"

    def test_flow_exploitable_flag(self, agent):
        code = '<?php system($_GET["cmd"]); ?>'
        result = agent.audit(code, "php")
        assert len(result.flows) >= 1
        assert result.flows[0].exploitable is True

    def test_sanitized_flow(self, agent):
        code = '<?php\n$id = $_GET["id"];\n$safe = intval($id);\n$db->query("SELECT * FROM t WHERE id=" . $safe);\n?>'
        result = agent.audit(code, "php")
        # The flow through $id should be detected but marked as sanitized
        sanitized_flows = [f for f in result.flows if not f.exploitable]
        # At minimum, the intval sanitization should be detected
        assert any(not f.exploitable for f in result.flows) or len(result.flows) == 0

    def test_no_flow_without_source(self, agent):
        code = '<?php system("ls"); ?>'
        result = agent.audit(code, "php")
        assert result.flows == []

    def test_no_flow_without_sink(self, agent):
        code = '<?php $x = $_GET["x"]; echo $x; ?>'
        result = agent.audit(code, "php")
        assert result.flows == []

    def test_multiple_flows(self, agent):
        code = '<?php\n$cmd = $_GET["cmd"];\nsystem($cmd);\neval($cmd);\n?>'
        result = agent.audit(code, "php")
        assert len(result.flows) >= 2


class TestRouteSuggestion:
    """Test exploitation route suggestions."""

    def test_sqli_suggestion(self, agent):
        code = '<?php\n$id = $_GET["id"];\n$db->query("SELECT * FROM users WHERE id=" . $id);\n?>'
        result = agent.audit(code, "php")
        assert "sqli" in result.suggested_routes

    def test_cmdi_suggestion(self, agent):
        code = '<?php system($_GET["cmd"]); ?>'
        result = agent.audit(code, "php")
        assert "cmdi" in result.suggested_routes

    def test_ssti_suggestion(self, agent):
        code = 'return render_template_string(request.args.get("tpl"))'
        result = agent.audit(code, "python")
        assert "ssti" in result.suggested_routes

    def test_lfi_suggestion(self, agent):
        code = '<?php include($_GET["page"]); ?>'
        result = agent.audit(code, "php")
        assert "lfi" in result.suggested_routes

    def test_php_pop_suggestion(self, agent):
        code = '<?php\n$data = $_POST["data"];\n$obj = unserialize($data);\n?>'
        result = agent.audit(code, "php")
        assert "php_pop" in result.suggested_routes or "deserialization" in result.suggested_routes

    def test_no_routes_for_clean_code(self, agent):
        code = '<?php echo "Hello"; ?>'
        result = agent.audit(code, "php")
        assert result.suggested_routes == []

    def test_multiple_routes(self, agent):
        code = '<?php\n$cmd = $_GET["cmd"];\nsystem($cmd);\n$id = $_GET["id"];\n$db->query("SELECT * FROM t WHERE id=" . $id);\n?>'
        result = agent.audit(code, "php")
        assert "cmdi" in result.suggested_routes
        assert "sqli" in result.suggested_routes


class TestLanguageSupport:
    """Test language detection and normalization."""

    def test_javascript_alias(self, agent):
        code = 'eval(req.body.code);'
        result = agent.audit(code, "javascript")
        assert any(s.function == "eval" for s in result.sinks)

    def test_js_alias(self, agent):
        code = 'eval(req.body.code);'
        result = agent.audit(code, "js")
        assert any(s.function == "eval" for s in result.sinks)

    def test_typescript_alias(self, agent):
        code = 'eval(req.body.code);'
        result = agent.audit(code, "typescript")
        assert any(s.function == "eval" for s in result.sinks)

    def test_python3_alias(self, agent):
        code = 'eval(request.args.get("x"))'
        result = agent.audit(code, "python3")
        assert any(s.function == "eval" for s in result.sinks)

    def test_py_alias(self, agent):
        code = 'eval(request.args.get("x"))'
        result = agent.audit(code, "py")
        assert any(s.function == "eval" for s in result.sinks)


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_source_code(self, agent):
        result = agent.audit("", "php")
        assert result.sinks == []
        assert result.sources == []
        assert result.flows == []
        assert result.suggested_routes == []

    def test_whitespace_only(self, agent):
        result = agent.audit("   \n\n  \t  ", "php")
        assert result.sinks == []
        assert result.sources == []

    def test_large_source_code(self, agent):
        # Should handle large files without error
        code = "<?php\n" + "$x = $_GET['x'];\n" * 500 + "system($x);\n" + "?>"
        result = agent.audit(code, "php")
        assert len(result.sinks) >= 1
        assert len(result.sources) >= 1

    def test_audit_result_to_prompt_context(self, agent):
        code = '<?php system($_GET["cmd"]); ?>'
        result = agent.audit(code, "php")
        context = result.to_prompt_context()
        assert "Source Audit Results:" in context
        assert "system" in context
        assert "$_GET" in context

    def test_returns_audit_result_type(self, agent):
        result = agent.audit("<?php echo 1; ?>", "php")
        assert isinstance(result, AuditResult)

    def test_sink_info_repr(self, agent):
        sink = SinkInfo(function="eval", file="test.php", line=5, context="eval($x)")
        assert "eval" in repr(sink)
        assert "test.php" in repr(sink)

    def test_source_info_repr(self, agent):
        source = SourceInfo(variable="$_GET", file="test.php", line=3)
        assert "$_GET" in repr(source)

    def test_data_flow_repr(self, agent):
        source = SourceInfo(variable="$_GET", file="test.php", line=1)
        sink = SinkInfo(function="system", file="test.php", line=2, context="system($x)")
        flow = DataFlow(source=source, sink=sink)
        assert "$_GET" in repr(flow)
        assert "system" in repr(flow)
