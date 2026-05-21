from __future__ import annotations

import io
import asyncio
import zipfile

from fastapi.testclient import TestClient
from unittest.mock import MagicMock

from autopnex.ctf.react_agent import CTFReActAgent
from autopnex.ctf.tool_router import _exec_http_request
from autopnex.ctf.knowledge_base import CTFKnowledgeBase
from autopnex.ctf.source_analyzer import analyze_attachment
from autopnex.ctf.tool_workspace import CTFToolWorkspace
from autopnex.ctf.models import ChallengeProfile, ChallengeType
from autopnex.orchestrator import LLMOrchestrator
from autopnex.state_machine import PenTestStateMachine
from autopnex.tools.base import ToolRegistry
from autopnex.web.api import app
from config.settings import settings


def _build_strange_php_zip() -> bytes:
    source = """<?php
session_start();
class User {
  public $username;
  public function __destruct() {
    file_put_contents("log/".md5($this->username).".txt", serialize($this->username));
  }
}
class UserMessage {
  private $filePath;
  public function __set($name, $value) {
    $this->$name = $value;
    file_get_contents($this->filePath);
  }
  public function deleteMessage($path) {
    if (file_exists($path.".txt")) unlink($path.".txt");
  }
}
if (isset($_POST["encodedMessage"])) {
  $msg = base64_decode($_POST["encodedMessage"]);
  file_put_contents("./txt/msg.txt", $msg);
}
?>
<form action="welcome.php" method="post">
  <textarea name="message"></textarea>
  <input type="hidden" name="encodedMessage">
  <input type="hidden" name="action" value="message">
</form>
"""
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("welcome.php", source)
        zf.writestr("index.html", '<form action="main.php?action=login" method="post"><input name="username"><input name="password"></form>')
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w") as zf:
        zf.writestr("tempdir/src.zip", inner.getvalue())
    return outer.getvalue()


def test_source_analyzer_reads_nested_php_zip(tmp_path):
    archive = tmp_path / "strange_php.zip"
    archive.write_bytes(_build_strange_php_zip())

    analysis = analyze_attachment(archive)
    context = analysis.to_prompt_context()

    assert any(item["path"].endswith("welcome.php") for item in analysis.files)
    assert any(param["name"] == "encodedMessage" for param in analysis.parameters)
    assert any(finding.kind == "php_magic_method" for finding in analysis.findings)
    assert any(finding.kind == "path_probe" for finding in analysis.findings)
    assert any(finding.kind == "phar_trigger_candidate" for finding in analysis.findings)
    assert any(finding.kind == "php_set_file_read_gadget" for finding in analysis.findings)
    assert "UserMessage" in context


def test_ctf_react_agent_exposes_enabled_registry_tools(tmp_path):
    archive = tmp_path / "strange_php.zip"
    archive.write_bytes(_build_strange_php_zip())
    runtime = settings.snapshot(
        exploit_enabled=True,
        approved_scopes=("passive", "active_scan", "exploit"),
    )
    agent = CTFReActAgent(
        target="http://example.com",
        challenge_type="web",
        flag_format="flag{...}",
        enabled_tools=["http_request", "lfi_detect", "flag_reader"],
        runtime_config=runtime,
    )
    agent.add_file(str(archive))

    tool_names = {schema["function"]["name"] for schema in agent._tool_definitions()}
    assert {"http_request", "lfi_detect", "flag_reader", "scan_flag", "ctf_tool_manager"} <= tool_names
    assert "ssti_detect" not in tool_names
    assert agent.flag_format == r"flag\{[^}]+\}"
    assert "Static Source Attachment Analysis" in agent._build_initial_messages()[1]["content"]

    result = agent._execute_tool("lfi_detect", {"url": "http://example.com/?file=a", "parameter": "file"})
    assert result["tool"] == "lfi_detect"
    assert result["parsed_data"]["param"] == "file"


def test_ctf_react_agent_finds_flag_in_untruncated_tool_result(tmp_path, monkeypatch):
    class FakeLLMClient:
        enabled = True

    monkeypatch.setattr("autopnex.orchestrator.llm_client.LLMClient", FakeLLMClient)
    runtime = settings.snapshot(
        exploit_enabled=True,
        approved_scopes=("passive", "active_scan", "exploit"),
    )
    agent = CTFReActAgent(
        target="http://example.com",
        challenge_type="web",
        flag_format=r"flag\{[^}]+\}",
        max_iterations=1,
        enabled_tools=["http_request"],
        runtime_config=runtime,
        knowledge_base_path=str(tmp_path / "ctf_knowledge.json"),
    )
    agent._call_llm = lambda: {
        "content": "",
        "reasoning_content": "send one request",
        "tool_calls": [
            {
                "id": "call_1",
                "function": {
                    "name": "http_request",
                    "arguments": "{}",
                },
            }
        ],
    }
    agent._execute_tool = lambda _name, _args: {
        "status_code": 200,
        "body": "A" * 9000 + "</code>flag{auto-close-loop}",
    }

    result = asyncio.run(agent.solve())

    assert result["success"] is True
    assert result["flag"] == "flag{auto-close-loop}"


def test_ctf_react_agent_auto_solves_known_php_pop_source_after_get(tmp_path, monkeypatch):
    class FakeLLMClient:
        enabled = True

    class FakeResponse:
        status_code = 200
        headers = {}
        text = "</code>flag{deterministic-pop-close}\nHello"
        url = "http://example.com/"
        history = []
        cookies = {}

    source_body = "class Begin class Then class Handle class Super class CTF class WhiteGod @unserialize($_POST['pop']);"
    monkeypatch.setattr("autopnex.orchestrator.llm_client.LLMClient", FakeLLMClient)
    runtime = settings.snapshot(
        exploit_enabled=True,
        approved_scopes=("passive", "active_scan", "exploit"),
    )
    agent = CTFReActAgent(
        target="http://example.com/",
        challenge_type="web",
        flag_format=r"flag\{[^}]+\}",
        max_iterations=1,
        enabled_tools=["http_request"],
        runtime_config=runtime,
        knowledge_base_path=str(tmp_path / "ctf_knowledge.json"),
    )
    agent._call_llm = lambda: {
        "content": "",
        "reasoning_content": "fetch source",
        "tool_calls": [
            {
                "id": "call_1",
                "function": {
                    "name": "http_request",
                    "arguments": '{"url":"http://example.com/","method":"GET"}',
                },
            }
        ],
    }
    agent._execute_tool = lambda _name, _args: {
        "status_code": 200,
        "body": source_body,
    }
    agent._session.post = MagicMock(return_value=FakeResponse())

    result = asyncio.run(agent.solve())

    assert result["success"] is True
    assert result["flag"] == "flag{deterministic-pop-close}"
    assert agent._session.post.call_args.kwargs["data"]["pop"].startswith(b'O:5:"Begin"')


def test_ctf_react_agent_auto_probes_lfi_flag_parameter(tmp_path, monkeypatch):
    class FakeLLMClient:
        enabled = True

    class FakeResponse:
        status_code = 200
        headers = {}
        text = "flag{deterministic-lfi-close}"
        url = "http://example.com/view.php?file=/flag"
        history = []
        cookies = {}

    monkeypatch.setattr("autopnex.orchestrator.llm_client.LLMClient", FakeLLMClient)
    runtime = settings.snapshot(
        exploit_enabled=True,
        approved_scopes=("passive", "active_scan", "exploit"),
    )
    agent = CTFReActAgent(
        target="http://example.com/view.php?file=readme.txt",
        challenge_type="web",
        flag_format=r"flag\{[^}]+\}",
        max_iterations=1,
        enabled_tools=["http_request"],
        runtime_config=runtime,
        knowledge_base_path=str(tmp_path / "ctf_knowledge.json"),
    )
    agent._call_llm = lambda: {
        "content": "",
        "reasoning_content": "fetch file endpoint",
        "tool_calls": [
            {
                "id": "call_1",
                "function": {
                    "name": "http_request",
                    "arguments": '{"url":"http://example.com/view.php?file=readme.txt","method":"GET"}',
                },
            }
        ],
    }
    agent._execute_tool = lambda _name, _args: {
        "status_code": 200,
        "url": "http://example.com/view.php?file=readme.txt",
        "body": "README",
    }
    agent._session.get = MagicMock(return_value=FakeResponse())

    result = asyncio.run(agent.solve())

    assert result["success"] is True
    assert result["flag"] == "flag{deterministic-lfi-close}"
    assert agent._session.get.call_args.kwargs["params"]["file"] == "/flag"


def test_ctf_react_agent_auto_probes_ssti_parameter(tmp_path, monkeypatch):
    class FakeLLMClient:
        enabled = True

    class DetectionResponse:
        status_code = 200
        headers = {}
        text = "Hello 49"
        url = "http://example.com/render?name=%7B%7B7*7%7D%7D"
        history = []
        cookies = {}

    class ExploitResponse:
        status_code = 200
        headers = {}
        text = "flag{deterministic-ssti-close}"
        url = "http://example.com/render?name=payload"
        history = []
        cookies = {}

    monkeypatch.setattr("autopnex.orchestrator.llm_client.LLMClient", FakeLLMClient)
    runtime = settings.snapshot(
        exploit_enabled=True,
        approved_scopes=("passive", "active_scan", "exploit"),
    )
    agent = CTFReActAgent(
        target="http://example.com/render?name=test",
        challenge_type="web",
        flag_format=r"flag\{[^}]+\}",
        max_iterations=1,
        enabled_tools=["http_request"],
        runtime_config=runtime,
        knowledge_base_path=str(tmp_path / "ctf_knowledge.json"),
    )
    agent._call_llm = lambda: {
        "content": "",
        "reasoning_content": "fetch render endpoint",
        "tool_calls": [
            {
                "id": "call_1",
                "function": {
                    "name": "http_request",
                    "arguments": '{"url":"http://example.com/render?name=test","method":"GET"}',
                },
            }
        ],
    }
    agent._execute_tool = lambda _name, _args: {
        "status_code": 200,
        "url": "http://example.com/render?name=test",
        "body": "Hello test",
    }
    agent._session.get = MagicMock(side_effect=[DetectionResponse(), ExploitResponse()])

    result = asyncio.run(agent.solve())

    assert result["success"] is True
    assert result["flag"] == "flag{deterministic-ssti-close}"
    first_probe = agent._session.get.call_args_list[0].kwargs["params"]["name"]
    assert first_probe == "{{7*7}}"


def test_ctf_react_agent_auto_probes_sqli_parameter(tmp_path, monkeypatch):
    class FakeLLMClient:
        enabled = True

    class DetectionResponse:
        status_code = 500
        headers = {}
        text = "SQLSTATE[42000]: syntax error near '\''"
        url = "http://example.com/item?id=1%27"
        history = []
        cookies = {}

    class ExploitResponse:
        status_code = 200
        headers = {}
        text = "flag{deterministic-sqli-close}"
        url = "http://example.com/item?id=payload"
        history = []
        cookies = {}

    monkeypatch.setattr("autopnex.orchestrator.llm_client.LLMClient", FakeLLMClient)
    runtime = settings.snapshot(
        exploit_enabled=True,
        approved_scopes=("passive", "active_scan", "exploit"),
    )
    agent = CTFReActAgent(
        target="http://example.com/item?id=1",
        challenge_type="web",
        flag_format=r"flag\{[^}]+\}",
        max_iterations=1,
        enabled_tools=["http_request"],
        runtime_config=runtime,
        knowledge_base_path=str(tmp_path / "ctf_knowledge.json"),
    )
    agent._call_llm = lambda: {
        "content": "",
        "reasoning_content": "fetch item endpoint",
        "tool_calls": [
            {
                "id": "call_1",
                "function": {
                    "name": "http_request",
                    "arguments": '{"url":"http://example.com/item?id=1","method":"GET"}',
                },
            }
        ],
    }
    agent._execute_tool = lambda _name, _args: {
        "status_code": 200,
        "url": "http://example.com/item?id=1",
        "body": "Item 1",
    }
    agent._session.get = MagicMock(side_effect=[DetectionResponse(), ExploitResponse()])

    result = asyncio.run(agent.solve())

    assert result["success"] is True
    assert result["flag"] == "flag{deterministic-sqli-close}"
    first_probe = agent._session.get.call_args_list[0].kwargs["params"]["id"]
    second_probe = agent._session.get.call_args_list[1].kwargs["params"]["id"]
    assert first_probe.endswith("'")
    assert "UNION SELECT" in second_probe.upper()


def test_ctf_react_agent_preserves_tool_result_tail_for_llm(tmp_path, monkeypatch):
    class FakeLLMClient:
        enabled = True

    monkeypatch.setattr("autopnex.orchestrator.llm_client.LLMClient", FakeLLMClient)
    runtime = settings.snapshot(
        exploit_enabled=True,
        approved_scopes=("passive", "active_scan", "exploit"),
    )
    agent = CTFReActAgent(
        target="http://example.com",
        challenge_type="web",
        max_iterations=1,
        enabled_tools=["http_request"],
        runtime_config=runtime,
        knowledge_base_path=str(tmp_path / "ctf_knowledge.json"),
    )
    agent._call_llm = lambda: {
        "content": "",
        "tool_calls": [
            {
                "id": "call_1",
                "function": {
                    "name": "http_request",
                    "arguments": '{"url":"http://example.com/","method":"GET"}',
                },
            }
        ],
    }
    agent._execute_tool = lambda _name, _args: {
        "status_code": 200,
        "body": "A" * 12000 + "TAIL_MARKER_FOR_NEXT_STEP",
    }

    asyncio.run(agent.solve())

    tool_messages = [message["content"] for message in agent._messages if message["role"] == "tool"]
    assert tool_messages
    assert "TAIL_MARKER_FOR_NEXT_STEP" in tool_messages[-1]
    assert "[truncated middle" in tool_messages[-1]


def test_ctf_react_agent_finds_flag_after_html_normalisation(tmp_path, monkeypatch):
    class FakeLLMClient:
        enabled = True

    monkeypatch.setattr("autopnex.orchestrator.llm_client.LLMClient", FakeLLMClient)
    runtime = settings.snapshot(
        exploit_enabled=True,
        approved_scopes=("passive", "active_scan", "exploit"),
    )
    agent = CTFReActAgent(
        target="http://example.com",
        challenge_type="web",
        flag_format=r"flag\{[^}]+\}",
        max_iterations=1,
        enabled_tools=["http_request"],
        runtime_config=runtime,
        knowledge_base_path=str(tmp_path / "ctf_knowledge.json"),
    )
    agent._call_llm = lambda: {
        "content": "",
        "tool_calls": [
            {
                "id": "call_1",
                "function": {
                    "name": "http_request",
                    "arguments": '{"url":"http://example.com/","method":"GET"}',
                },
            }
        ],
    }
    agent._execute_tool = lambda _name, _args: {
        "status_code": 200,
        "body": "<span>flag</span>&#123;html-normalized&#125;",
    }

    result = asyncio.run(agent.solve())

    assert result["success"] is True
    assert result["flag"] == "flag{html-normalized}"


def test_ctf_react_agent_adds_tool_failure_diagnosis(tmp_path, monkeypatch):
    class FakeLLMClient:
        enabled = True

    monkeypatch.setattr("autopnex.orchestrator.llm_client.LLMClient", FakeLLMClient)
    runtime = settings.snapshot(
        exploit_enabled=True,
        approved_scopes=("passive", "active_scan", "exploit"),
    )
    agent = CTFReActAgent(
        target="http://example.com",
        challenge_type="web",
        max_iterations=1,
        enabled_tools=["http_request"],
        runtime_config=runtime,
        knowledge_base_path=str(tmp_path / "ctf_knowledge.json"),
    )
    agent._call_llm = lambda: {
        "content": "",
        "tool_calls": [
            {
                "id": "call_1",
                "function": {
                    "name": "http_request",
                    "arguments": '{"url":"http://example.com/admin","method":"GET"}',
                },
            }
        ],
    }
    agent._execute_tool = lambda _name, _args: {
        "status_code": 404,
        "headers": {"Content-Type": "text/html"},
        "body": "Not Found",
    }

    asyncio.run(agent.solve())

    user_messages = [message["content"] for message in agent._messages if message["role"] == "user"]
    assert any("工具结果诊断" in message and "HTTP 404" in message for message in user_messages)


def test_exec_http_request_supports_form_and_redirect_control():
    session = MagicMock()
    response = MagicMock()
    response.status_code = 302
    response.headers = {"Location": "welcome.php"}
    response.text = "Login successful!"
    response.url = "http://example.com/main.php?action=login"
    response.history = []
    response.cookies = {}
    session.request.return_value = response
    session.cookies = {"PHPSESSID": "abc"}

    result = _exec_http_request(
        {
            "url": "http://example.com/main.php?action=login",
            "method": "POST",
            "form": {"username": "u", "password": "p"},
            "allow_redirects": False,
        },
        session=session,
    )

    session.request.assert_called_once()
    assert session.request.call_args.kwargs["data"] == {"username": "u", "password": "p"}
    assert session.request.call_args.kwargs["allow_redirects"] is False
    assert result["status_code"] == 302
    assert result["location"] == "welcome.php"
    assert result["session_cookies"] == {"PHPSESSID": "abc"}


def test_ctf_api_upload_returns_source_analysis():
    client = TestClient(app)
    response = client.post(
        "/api/ctf/upload",
        files={"file": ("strange_php.zip", _build_strange_php_zip(), "application/zip")},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["source_analysis"]
    assert any(item["path"].endswith("welcome.php") for item in payload["source_analysis"]["files"])


def test_state_machine_plans_ctf_web_tasks():
    runtime = settings.snapshot(exploit_enabled=True, approved_scopes=("passive", "active_scan", "exploit"))
    orchestrator = LLMOrchestrator(mock=True, runtime_config=runtime)
    fsm = PenTestStateMachine(target="http://example.com", orchestrator=orchestrator)
    fsm.findings.add_parameter("http://example.com/welcome.php", "encodedMessage", "POST")

    vuln_tasks = fsm._plan_phase_tasks("VULN_DETECT")
    vuln_tool_names = {task.tool for task in vuln_tasks}
    assert {"ssti_detect", "lfi_detect", "unserialize_detect"} <= vuln_tool_names

    exploit_tasks = fsm._plan_phase_tasks("EXPLOIT")
    assert any(task.tool == "flag_reader" for task in exploit_tasks)
    assert ToolRegistry.get("flag_reader").availability(runtime)["enabled"] is True


def test_phar_pdo_chain_reports_external_mysql_blocker():
    runtime = settings.snapshot(
        exploit_enabled=True,
        approved_scopes=("passive", "active_scan", "exploit"),
    )
    result = ToolRegistry.execute("phar_pdo_chain", {"flag_path": "/flag"}, runtime)

    assert result.success is True
    assert result.parsed_data["chain_identified"] is True
    assert result.parsed_data["blocked"] is True
    assert result.parsed_data["blocker"] == "missing_public_mysql_host"
    assert result.parsed_data["recommended_next_tool"] == "ctf_mysql_helper"
    assert result.parsed_data["expected_log_path"] == "/log/0bc7be346d4df269543565b6b7cd231a.txt"
    assert "username VARCHAR" in result.parsed_data["sql_setup"]
    assert "FETCH_CLASS" in result.raw_output or "UserMessage" in result.raw_output


def test_ctf_mysql_helper_generates_strange_php_plan():
    runtime = settings.snapshot(
        exploit_enabled=True,
        approved_scopes=("passive", "active_scan", "exploit"),
    )
    result = ToolRegistry.execute(
        "ctf_mysql_helper",
        {"public_host": "203.0.113.10", "flag_path": "/flag"},
        runtime,
    )

    assert result.success is True
    assert result.parsed_data["next_tool"] == "phar_pdo_chain"
    assert result.parsed_data["phar_pdo_chain_args"]["db_host"] == "203.0.113.10"
    assert result.parsed_data["next_tool_if_docker_unavailable"] == "ctf_tunnel_helper"
    assert result.parsed_data["expected_log_path"] == "/log/0bc7be346d4df269543565b6b7cd231a.txt"
    assert "CREATE TABLE users" in result.parsed_data["sql_setup"]
    assert "username VARCHAR" in result.parsed_data["sql_setup"]
    assert "docker run" in result.parsed_data["docker_run"]


def test_ctf_tunnel_helper_generates_non_docker_routes():
    runtime = settings.snapshot(
        exploit_enabled=True,
        approved_scopes=("passive", "active_scan", "exploit"),
    )
    result = ToolRegistry.execute(
        "ctf_tunnel_helper",
        {"local_port": 3306, "service": "mysql", "preferred_method": "auto"},
        runtime,
    )

    assert result.success is True
    assert result.parsed_data["next_tool_if_missing_binary"] == "download_tool_url"
    assert result.parsed_data["next_tool_if_mysql_ready"] == "phar_pdo_chain"
    assert any(item["name"] == "ngrok_tcp" for item in result.parsed_data["all_methods"])
    assert any(item["name"] == "free_mysql" for item in result.parsed_data["all_methods"])
    assert result.parsed_data["download_suggestions"]
    assert "中文行动摘要" in result.raw_output


def test_ctf_tool_manager_plans_downloads_and_python_packages():
    runtime = settings.snapshot(
        exploit_enabled=True,
        approved_scopes=("passive", "active_scan", "exploit"),
    )
    jadx = ToolRegistry.execute(
        "ctf_tool_manager",
        {"needed_tool": "jadx", "task": "analyze android apk"},
        runtime,
    )
    z3 = ToolRegistry.execute(
        "ctf_tool_manager",
        {"needed_tool": "z3", "task": "solve constraints"},
        runtime,
    )

    assert jadx.success is True
    assert jadx.parsed_data["next_core_tool"] == "download_tool_url"
    assert any(item["kind"] == "download" for item in jadx.parsed_data["actions"])
    assert "中文行动摘要" in jadx.raw_output
    assert z3.success is True
    assert z3.parsed_data["next_core_tool"] == "install_python_package"
    assert any(item.get("package") == "z3-solver" for item in z3.parsed_data["actions"])


def test_ctf_tool_manager_prefers_existing_workspace_script(tmp_path):
    scripts_dir = tmp_path / "scripts"
    scripts_dir.mkdir(parents=True)
    helper = scripts_dir / "jadx_helper.py"
    helper.write_text("print('local jadx helper')\n", encoding="utf-8")
    runtime = settings.snapshot(
        exploit_enabled=True,
        approved_scopes=("passive", "active_scan", "exploit"),
        ctf_workspace_dir=str(tmp_path),
    )

    result = ToolRegistry.execute(
        "ctf_tool_manager",
        {"needed_tool": "jadx", "task": "analyze android apk"},
        runtime,
    )

    assert result.success is True
    assert result.parsed_data["next_core_tool"] == "run_tool_script"
    assert result.parsed_data["existing_artifacts"]
    assert result.parsed_data["existing_artifacts"][0]["path"] == str(helper)
    assert result.parsed_data["actions"][0]["kind"] == "use_existing"


def test_ctf_react_agent_static_preflight_injects_tunnel_plan(tmp_path):
    archive = tmp_path / "strange_php.zip"
    archive.write_bytes(_build_strange_php_zip())
    runtime = settings.snapshot(
        exploit_enabled=True,
        approved_scopes=("passive", "active_scan", "exploit"),
    )
    agent = CTFReActAgent(
        target="http://example.com",
        challenge_type="web",
        enabled_tools=[
            "phar_pdo_chain",
            "ctf_mysql_helper",
            "ctf_tunnel_helper",
        ],
        runtime_config=runtime,
    )
    agent.add_file(str(archive))

    from autopnex.ctf.preflight import run_static_preflight
    run_static_preflight(agent)

    tools = [step["tool"] for step in agent._steps]
    message_text = "\n".join(message["content"] for message in agent._messages)
    assert "phar_pdo_chain" in tools
    assert "ctf_mysql_helper" in tools
    assert "ctf_tunnel_helper" in tools
    assert "non-Docker tunnel plan" in message_text
    assert "中文行动摘要" in message_text


def test_knowledge_base_seeds_and_records_attempts(tmp_path):
    kb_path = tmp_path / "ctf_knowledge.json"
    kb = CTFKnowledgeBase(kb_path)

    hits = kb.search_knowledge("php phar file_exists __set PDO", challenge_type="web")
    assert any("Phar" in (hit.get("name") or "") for hit in hits)

    profile = ChallengeProfile(
        challenge_type=ChallengeType.WEB,
        sub_type="PHP-Phar",
        tech_stack=["PHP"],
        potential_vulns=["phar_trigger_candidate"],
        confidence=0.9,
    )
    kb.record_attempt(
        profile,
        {
            "success": False,
            "target": "http://example.test",
            "error": "missing_public_mysql_host",
            "tools_used": ["phar_pdo_chain"],
            "lessons": ["Need external MySQL for PDO FETCH_CLASS chain"],
            "blockers": ["missing_public_mysql_host"],
        },
    )

    kb2 = CTFKnowledgeBase(kb_path)
    learned = kb2.search_knowledge("external MySQL PDO FETCH_CLASS", challenge_type="web")
    assert any(hit.get("kind") == "attempt" and "missing_public_mysql_host" in str(hit) for hit in learned)


def test_ctf_tool_workspace_write_and_run(tmp_path):
    workspace = CTFToolWorkspace(tmp_path / "workspace")
    written = workspace.write_script("hello.py", "print('workspace-ok')\n")

    assert written["success"] is True
    result = workspace.run_script(written["path"])
    assert result["success"] is True
    assert "workspace-ok" in result["stdout"]


def test_ctf_agent_knowledge_and_workspace_tools(tmp_path):
    archive = tmp_path / "strange_php.zip"
    archive.write_bytes(_build_strange_php_zip())
    runtime = settings.snapshot(
        exploit_enabled=True,
        approved_scopes=("passive", "active_scan", "exploit"),
        ctf_workspace_dir=str(tmp_path / "agent_workspace"),
    )
    agent = CTFReActAgent(
        target="http://example.com",
        challenge_type="web",
        enabled_tools=[
            "ctf_knowledge_search",
            "write_tool_script",
            "run_tool_script",
            "install_python_package",
            "scan_flag",
        ],
        runtime_config=runtime,
        knowledge_base_path=str(tmp_path / "agent_knowledge.json"),
    )
    agent.add_file(str(archive))

    tool_names = {schema["function"]["name"] for schema in agent._tool_definitions()}
    assert {"ctf_knowledge_search", "write_tool_script", "run_tool_script", "install_python_package"} <= tool_names

    knowledge = agent._execute_tool("ctf_knowledge_search", {"query": "php phar file_exists __set PDO"})
    assert any("Phar" in (hit.get("name") or "") for hit in knowledge["results"])

    written = agent._execute_tool("write_tool_script", {"name": "solve.py", "content": "print('agent-tool-ok')"})
    assert written["success"] is True
    ran = agent._execute_tool("run_tool_script", {"path": written["path"]})
    assert ran["success"] is True
    assert "agent-tool-ok" in ran["stdout"]

    agent._steps.append({"tool": "phar_pdo_chain", "result_preview": "missing_public_mysql_host"})
    result = agent._result(False, error="Max iterations reached without finding flag")
    agent._record_attempt(result)
    learned = agent._kb.search_knowledge("missing_public_mysql_host", challenge_type="web")
    assert any(hit.get("kind") == "attempt" for hit in learned)
