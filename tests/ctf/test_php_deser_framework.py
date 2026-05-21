"""Tests for PHP deserialization framework."""
import pytest
from autopnex.ctf.php_deser_framework import (
    POPChain,
    POPChainSelector,
    PayloadGenerator,
    build_phar,
    quick_pop_payload,
)
from autopnex.ctf.pop_chains import (
    ALL_CHAINS,
    GENERIC_CHAINS,
)


class TestPOPChain:
    def test_generate_serialize(self):
        chain = GENERIC_CHAINS[0]  # generic_destruct_to_call
        payload = chain.generate_serialize("cat /flag")
        assert isinstance(payload, bytes)
        assert len(payload) > 10

    def test_generate_phar(self):
        chain = GENERIC_CHAINS[2]  # newstar_ctf_pop
        phar = chain.generate_phar("cat /flag")
        assert isinstance(phar, bytes)
        assert b"__HALT_COMPILER" in phar
        # The serialized payload is embedded - check that the phar is valid

    def test_generate_phar_as_image(self):
        chain = GENERIC_CHAINS[2]
        img = chain.generate_phar_as_image("cat /flag")
        assert img[:6] == b"GIF89a"


class TestPOPChainSelector:
    def test_select_thinkphp(self):
        selector = POPChainSelector()
        chains = selector.select(framework="ThinkPHP")
        assert len(chains) > 0
        assert any(c.framework == "ThinkPHP" for c in chains)

    def test_select_with_classes(self):
        selector = POPChainSelector()
        chains = selector.select(
            available_classes=["Begin", "Then", "Super", "Handle", "CTF", "WhiteGod"],
        )
        assert any("newstar" in c.name for c in chains)

    def test_select_source_text(self):
        selector = POPChainSelector()
        chains = selector.select(
            source_text="class Begin { function __destruct() { /* pop chain */ } }",
        )
        assert len(chains) > 0

    def test_list_all(self):
        selector = POPChainSelector()
        chains = selector.list_all()
        assert len(chains) > 10  # Should have many chains across all frameworks


class TestPayloadGenerator:
    def test_serialize_payload(self):
        chain = GENERIC_CHAINS[0]
        payload = PayloadGenerator.serialize_payload(chain, "id")
        assert isinstance(payload, bytes)

    def test_phar_payload(self):
        chain = GENERIC_CHAINS[2]
        phar = PayloadGenerator.phar_payload(chain, "ls")
        assert b"__HALT_COMPILER" in phar

    def test_phar_as_image(self):
        chain = GENERIC_CHAINS[2]
        img = PayloadGenerator.phar_as_image(chain)
        assert img[:6] == b"GIF89a"

    def test_gzip_payload(self):
        chain = GENERIC_CHAINS[0]
        gz = PayloadGenerator.gzip_payload(chain, "id")
        assert len(gz) > 0

    def test_base64_payload(self):
        chain = GENERIC_CHAINS[0]
        b64 = PayloadGenerator.base64_payload(chain, "id")
        assert len(b64) > 0


class TestBuildPhar:
    def test_valid_phar(self):
        serialized = b'O:1:"A":1:{s:1:"x";s:3:"cmd";}'
        phar = build_phar(serialized, alias="test.txt")
        assert b"__HALT_COMPILER" in phar
        assert b"test.txt" in phar

    def test_phar_contains_serialized(self):
        serialized = b'O:5:"Hello":0:{}'
        phar = build_phar(serialized, alias="a.jpg")
        assert b"Hello" in phar


class TestQuickPopPayload:
    def test_returns_bytes(self):
        payload = quick_pop_payload("Generic", "cat /flag")
        assert isinstance(payload, bytes) or payload is None
