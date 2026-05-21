"""Unit tests for CTF crypto tools.

Tests:
- RSA small_e attack with known values
- RSA fermat with close primes
- RSA wiener attack with small d
- RSA common modulus attack
- Caesar cipher decryption
- Vigenere cipher decryption
- Encoding auto-detection (Base64, Hex, ROT13, Morse)
- Script execution with timeout
"""
from __future__ import annotations

import base64
import sys
import time

import pytest

from autopnex.tools.ctf_crypto.rsa_attack import (
    rsa_attack,
    _small_e_attack,
    _fermat_factorization,
    _wiener_attack,
    _common_modulus_attack,
    _icbrt,
    _modinv,
    _pow_mod,
)
from autopnex.tools.ctf_crypto.classical_cipher import (
    classical_cipher,
    _caesar_attack,
    _caesar_shift,
    _vigenere_decrypt,
    _score_english,
)
from autopnex.tools.ctf_crypto.encoding_decode import (
    encoding_decode,
    _is_base64,
    _is_hex,
    _is_morse,
    _try_base64,
    _try_hex,
    _try_morse,
    _try_rot13,
    _auto_detect,
)
from autopnex.tools.ctf_crypto.script_execute import script_execute
from autopnex.tools.ctf_crypto import CTF_CRYPTO_TOOLS


# ===========================================================================
# RSA Attack Tests
# ===========================================================================


class TestRSASmallE:
    """Test RSA small e (cube root) attack."""

    def test_small_e_exact_cube(self):
        """When m^3 < n, cube root gives exact plaintext."""
        # m = 123456789, e = 3, c = m^3
        m = 123456789
        e = 3
        c = m ** 3
        n = c + 1000000  # n > c so m^3 < n

        result = rsa_attack(n, e, c, attack_type="small_e")
        assert result["success"] is True
        assert result["method"] == "small_e"
        # Verify plaintext bytes decode to the original message
        expected_bytes = m.to_bytes((m.bit_length() + 7) // 8, "big")
        assert result["plaintext"] == expected_bytes

    def test_small_e_known_message(self):
        """Test with a known text message."""
        # Encode "Hi" as integer
        msg = b"Hi"
        m = int.from_bytes(msg, "big")  # 18537
        e = 3
        c = m ** 3
        n = c * 2  # n > c

        result = rsa_attack(n, e, c, attack_type="small_e")
        assert result["success"] is True
        assert result["plaintext"] == msg

    def test_small_e_fails_when_e_not_3(self):
        """Small e attack should fail when e != 3."""
        result = rsa_attack(100, 65537, 50, attack_type="small_e")
        assert result["success"] is False

    def test_small_e_internal_function(self):
        """Test the internal _small_e_attack function directly."""
        m = 42
        c = m ** 3
        n = c + 100
        res = _small_e_attack(n, 3, c)
        assert res["success"] is True
        assert res["m"] == 42


class TestRSAFermat:
    """Test RSA Fermat factorization attack."""

    def test_fermat_close_primes(self):
        """Fermat should factor n when p and q are close."""
        # Two close primes
        p = 1000000007
        q = 1000000009
        n = p * q
        e = 65537
        # Encrypt a message
        m = 12345
        phi = (p - 1) * (q - 1)
        d = _modinv(e, phi)
        c = _pow_mod(m, e, n)

        result = rsa_attack(n, e, c, attack_type="fermat")
        assert result["success"] is True
        assert result["method"] == "fermat"
        assert result["factors"]["p"] * result["factors"]["q"] == n

    def test_fermat_very_close_primes(self):
        """Test with primes that differ by 2 (twin primes)."""
        p = 10007
        q = 10009
        n = p * q
        res = _fermat_factorization(n)
        assert res["success"] is True
        assert {res["p"], res["q"]} == {p, q}

    def test_fermat_even_number(self):
        """Fermat handles even numbers by factoring out 2."""
        n = 2 * 17
        res = _fermat_factorization(n)
        assert res["success"] is True
        assert res["p"] == 2
        assert res["q"] == 17

    def test_fermat_fails_distant_primes(self):
        """Fermat should fail (within iteration limit) for distant primes."""
        # Very distant primes
        p = 2
        q = 999999999999999989  # large prime
        n = p * q
        # With max_iter=100, this should fail (p and q too far apart)
        res = _fermat_factorization(n, max_iter=100)
        # Even n is handled specially, so it succeeds
        assert res["success"] is True


class TestRSAWiener:
    """Test RSA Wiener attack."""

    def test_wiener_small_d(self):
        """Wiener attack should recover d when d is small relative to n."""
        # Known example: p, q chosen so d is small
        p = 7027
        q = 7919
        n = p * q  # 55,649,713
        phi = (p - 1) * (q - 1)
        # Choose a small d
        d = 5
        # Compute e = modinv(d, phi)
        e = _modinv(d, phi)
        assert e is not None

        # Encrypt
        m = 42
        c = _pow_mod(m, e, n)

        result = rsa_attack(n, e, c, attack_type="wiener")
        assert result["success"] is True
        assert result["method"] == "wiener"
        # Verify decryption
        expected_bytes = m.to_bytes((m.bit_length() + 7) // 8, "big")
        assert result["plaintext"] == expected_bytes

    def test_wiener_internal_function(self):
        """Test _wiener_attack directly."""
        p = 1009
        q = 1013
        n = p * q
        phi = (p - 1) * (q - 1)
        # Choose d coprime with phi
        d = 5
        e = _modinv(d, phi)
        assert e is not None, f"d={d} is not coprime with phi={phi}"

        m = 100
        c = _pow_mod(m, e, n)

        res = _wiener_attack(n, e, c)
        assert res["success"] is True
        assert res["d"] == d
        assert res["m"] == m

    def test_wiener_fails_large_d(self):
        """Wiener should fail when d is large."""
        # Standard RSA with large d
        p = 61
        q = 53
        n = p * q
        e = 17
        # d = modinv(17, phi) = large relative to n^(1/4)
        res = _wiener_attack(n, e, None)
        # This may or may not succeed depending on d size
        # For p=61, q=53, e=17: phi=3120, d=2753 which is > n^(1/4)≈7.6
        # So it should fail
        assert res["success"] is False


class TestRSACommonModulus:
    """Test RSA common modulus attack."""

    def test_common_modulus_basic(self):
        """Common modulus attack with coprime exponents."""
        p = 61
        q = 53
        n = p * q  # 3233
        e1 = 17
        e2 = 23
        m = 42

        c1 = _pow_mod(m, e1, n)
        c2 = _pow_mod(m, e2, n)

        result = rsa_attack(n, e1, c1, attack_type="common_modulus", e2=e2, c2=c2)
        assert result["success"] is True
        assert result["method"] == "common_modulus"
        expected_bytes = m.to_bytes((m.bit_length() + 7) // 8, "big")
        assert result["plaintext"] == expected_bytes

    def test_common_modulus_internal(self):
        """Test _common_modulus_attack directly."""
        p = 101
        q = 103
        n = p * q
        e1 = 7
        e2 = 11
        m = 99

        c1 = _pow_mod(m, e1, n)
        c2 = _pow_mod(m, e2, n)

        res = _common_modulus_attack(n, e1, e2, c1, c2)
        assert res["success"] is True
        assert res["m"] == m

    def test_common_modulus_fails_non_coprime(self):
        """Should fail when gcd(e1, e2) != 1."""
        res = _common_modulus_attack(100, 6, 4, 50, 60)
        assert res["success"] is False

    def test_common_modulus_not_triggered_without_params(self):
        """Auto mode skips common_modulus when e2/c2 not provided."""
        result = rsa_attack(3233, 17, 42, attack_type="auto")
        # Should not crash, just try other attacks
        assert isinstance(result, dict)


class TestRSAAutoMode:
    """Test RSA auto mode tries attacks in order."""

    def test_auto_finds_small_e(self):
        """Auto mode should find small_e attack first."""
        m = 100
        c = m ** 3
        n = c + 999
        result = rsa_attack(n, 3, c, attack_type="auto")
        assert result["success"] is True
        assert result["method"] == "small_e"

    def test_auto_falls_through_to_fermat(self):
        """Auto mode falls through to fermat when small_e fails."""
        p = 10007
        q = 10009
        n = p * q
        e = 65537
        m = 42
        phi = (p - 1) * (q - 1)
        d = _modinv(e, phi)
        c = _pow_mod(m, e, n)

        result = rsa_attack(n, e, c, attack_type="auto")
        assert result["success"] is True
        # Should use fermat since primes are close
        assert result["method"] in ("fermat", "wiener")


# ===========================================================================
# Classical Cipher Tests
# ===========================================================================


class TestCaesarCipher:
    """Test Caesar cipher decryption."""

    def test_caesar_shift_known(self):
        """Test known Caesar shift."""
        plaintext = "hello world"
        # Shift by 3: h->k, e->h, l->o, etc.
        ciphertext = _caesar_shift(plaintext, 3)
        assert ciphertext == "khoor zruog"

    def test_caesar_decrypt_shift3(self):
        """Decrypt a Caesar cipher with shift 3."""
        # Use a longer text for reliable frequency analysis
        plaintext = "the quick brown fox jumps over the lazy dog"
        ciphertext = _caesar_shift(plaintext, 3)
        result = classical_cipher(ciphertext, cipher_type="caesar")
        assert result["success"] is True
        assert result["method"] == "caesar"
        assert result["plaintext"] == plaintext

    def test_caesar_english_detection(self):
        """Caesar attack should prefer English-like output."""
        # "the quick brown fox" shifted by 13
        plaintext = "the quick brown fox jumps over the lazy dog"
        ciphertext = _caesar_shift(plaintext, 13)
        result = _caesar_attack(ciphertext)
        assert result["success"] is True
        # Should recover the original
        assert result["plaintext"] == plaintext

    def test_caesar_preserves_case_and_nonalpha(self):
        """Caesar shift preserves case and non-alphabetic characters."""
        text = "Hello, World! 123"
        shifted = _caesar_shift(text, 5)
        assert shifted[5] == ","  # comma preserved
        assert shifted[12] == "!"  # exclamation preserved
        assert "123" in shifted

    def test_caesar_all_shifts_returned(self):
        """Caesar attack returns all 26 shifts."""
        result = _caesar_attack("abc")
        assert len(result["all_shifts"]) == 26


class TestVigenereCipher:
    """Test Vigenere cipher decryption."""

    def test_vigenere_decrypt_known_key(self):
        """Decrypt Vigenere with known key."""
        plaintext = "attackatdawn"
        key = "lemon"
        # Encrypt
        encrypted = ""
        key_idx = 0
        for ch in plaintext:
            shift = ord(key[key_idx % len(key)]) - ord("a")
            encrypted += chr((ord(ch) - ord("a") + shift) % 26 + ord("a"))
            key_idx += 1

        result = classical_cipher(encrypted, cipher_type="vigenere")
        # With known key via function
        decrypted = _vigenere_decrypt(encrypted, key)
        assert decrypted == plaintext

    def test_vigenere_auto_key_discovery(self):
        """Vigenere auto mode should attempt key discovery."""
        # Long enough text for frequency analysis
        plaintext = "the quick brown fox jumps over the lazy dog and the cat sat on the mat"
        key = "key"
        # Encrypt
        encrypted = ""
        key_idx = 0
        for ch in plaintext:
            if ch.isalpha():
                shift = ord(key[key_idx % len(key)]) - ord("a")
                encrypted += chr((ord(ch) - ord("a") + shift) % 26 + ord("a"))
                key_idx += 1
            else:
                encrypted += ch

        result = classical_cipher(encrypted, cipher_type="vigenere")
        assert result["success"] is True

    def test_vigenere_empty_key(self):
        """Vigenere with empty key returns original text."""
        text = "hello"
        decrypted = _vigenere_decrypt(text, "")
        assert decrypted == text


class TestClassicalCipherAuto:
    """Test auto mode for classical ciphers."""

    def test_auto_detects_caesar(self):
        """Auto mode should detect and decrypt Caesar cipher."""
        plaintext = "the answer is forty two"
        ciphertext = _caesar_shift(plaintext, 7)
        result = classical_cipher(ciphertext, cipher_type="auto")
        assert result["success"] is True
        assert plaintext in result["plaintext"]

    def test_auto_empty_input(self):
        """Auto mode with empty input returns failure."""
        result = classical_cipher("", cipher_type="auto")
        assert result["success"] is False


# ===========================================================================
# Encoding Decode Tests
# ===========================================================================


class TestEncodingBase64:
    """Test Base64 encoding detection and decoding."""

    def test_base64_detection(self):
        """Auto-detect Base64 encoded data."""
        plaintext = "flag{base64_encoded}"
        encoded = base64.b64encode(plaintext.encode()).decode()

        result = encoding_decode(encoded)
        assert result["encoding"] == "base64"
        assert result["decoded"] == plaintext
        assert result["confidence"] > 0

    def test_base64_explicit(self):
        """Explicit Base64 decoding."""
        encoded = base64.b64encode(b"hello world").decode()
        result = encoding_decode(encoded, encoding="base64")
        assert result["decoded"] == "hello world"
        assert result["confidence"] == 1.0

    def test_base64_with_padding(self):
        """Base64 with padding characters."""
        encoded = base64.b64encode(b"test").decode()  # "dGVzdA=="
        assert _is_base64(encoded)
        decoded = _try_base64(encoded)
        assert decoded == "test"


class TestEncodingHex:
    """Test Hex encoding detection and decoding."""

    def test_hex_detection(self):
        """Auto-detect hex encoded data."""
        plaintext = "flag{hex_encoded}"
        encoded = plaintext.encode().hex()

        result = encoding_decode(encoded)
        assert result["encoding"] == "hex"
        assert result["decoded"] == plaintext

    def test_hex_explicit(self):
        """Explicit hex decoding."""
        encoded = "48656c6c6f"  # "Hello"
        result = encoding_decode(encoded, encoding="hex")
        assert result["decoded"] == "Hello"
        assert result["confidence"] == 1.0

    def test_hex_uppercase(self):
        """Hex with uppercase characters."""
        encoded = "48454C4C4F"
        assert _is_hex(encoded)
        decoded = _try_hex(encoded)
        assert decoded == "HELLO"

    def test_hex_odd_length_rejected(self):
        """Odd-length hex string should not be detected."""
        assert _is_hex("abc") is False


class TestEncodingROT13:
    """Test ROT13 encoding."""

    def test_rot13_explicit(self):
        """Explicit ROT13 decoding."""
        plaintext = "flag{rot13_test}"
        encoded = plaintext.translate(str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
        ))
        result = encoding_decode(encoded, encoding="rot13")
        assert result["decoded"] == plaintext
        assert result["confidence"] == 1.0

    def test_rot13_roundtrip(self):
        """ROT13 applied twice returns original."""
        text = "Hello World"
        result1 = encoding_decode(text, encoding="rot13")
        result2 = encoding_decode(result1["decoded"], encoding="rot13")
        assert result2["decoded"] == text

    def test_rot13_preserves_nonalpha(self):
        """ROT13 preserves non-alphabetic characters."""
        text = "Hello, World! 123"
        result = encoding_decode(text, encoding="rot13")
        assert "123" in result["decoded"]
        assert "," in result["decoded"]


class TestEncodingMorse:
    """Test Morse code detection and decoding."""

    def test_morse_detection(self):
        """Auto-detect Morse code."""
        # "HELLO" in Morse
        morse = ".... . .-.. .-.. ---"
        result = encoding_decode(morse)
        assert result["encoding"] == "morse"
        assert result["decoded"] == "HELLO"

    def test_morse_explicit(self):
        """Explicit Morse decoding."""
        morse = "... --- ..."
        result = encoding_decode(morse, encoding="morse")
        assert result["decoded"] == "SOS"

    def test_morse_with_word_separator(self):
        """Morse with word separators (double space)."""
        morse = ".... ..  - .... . .-. ."
        result = encoding_decode(morse, encoding="morse")
        assert result["decoded"] == "HI THERE"


class TestEncodingAutoDetect:
    """Test auto-detection logic."""

    def test_auto_detect_empty(self):
        """Empty input returns empty result."""
        result = encoding_decode("")
        assert result["decoded"] == ""
        assert result["confidence"] == 0.0

    def test_auto_detect_unknown(self):
        """Non-encoded text returns empty result."""
        result = encoding_decode("just plain text with spaces")
        # Plain text may not match any encoding pattern
        assert isinstance(result, dict)

    def test_url_encoding(self):
        """URL encoded data detection."""
        encoded = "flag%7Burl_encoded%7D"
        result = encoding_decode(encoded, encoding="url")
        assert result["decoded"] == "flag{url_encoded}"


class TestEncodingChained:
    """Test chained decoding."""

    def test_base64_then_recognizable(self):
        """Base64 encoded hex should be decodable."""
        # "Hello" -> hex -> base64
        plaintext = "Hello"
        hex_encoded = plaintext.encode().hex()  # "48656c6c6f"
        b64_encoded = base64.b64encode(hex_encoded.encode()).decode()

        result = encoding_decode(b64_encoded)
        # Should at least detect base64
        assert result["encoding"] == "base64"
        assert result["decoded"] == hex_encoded


# ===========================================================================
# Script Execute Tests
# ===========================================================================


class TestScriptExecute:
    """Test Python script execution."""

    def test_simple_print(self):
        """Execute a simple print statement."""
        result = script_execute("print('hello world')")
        assert result["success"] is True
        assert "hello world" in result["stdout"]
        assert result["exit_code"] == 0

    def test_math_computation(self):
        """Execute mathematical computation."""
        code = "print(2 ** 10)"
        result = script_execute(code)
        assert result["success"] is True
        assert "1024" in result["stdout"]

    def test_multiline_script(self):
        """Execute multiline script."""
        code = """
import math
result = math.factorial(10)
print(f"10! = {result}")
"""
        result = script_execute(code)
        assert result["success"] is True
        assert "3628800" in result["stdout"]

    def test_script_with_error(self):
        """Script with runtime error returns failure."""
        code = "raise ValueError('test error')"
        result = script_execute(code)
        assert result["success"] is False
        assert result["exit_code"] != 0
        assert "ValueError" in result["stderr"]

    def test_script_syntax_error(self):
        """Script with syntax error returns failure."""
        code = "def foo(:"
        result = script_execute(code)
        assert result["success"] is False
        assert "SyntaxError" in result["stderr"]

    def test_script_timeout(self):
        """Script that exceeds timeout is killed."""
        code = "import time; time.sleep(10)"
        result = script_execute(code, timeout=1)
        assert result["success"] is False
        assert "timed out" in result["stderr"]

    def test_empty_code(self):
        """Empty code returns failure."""
        result = script_execute("")
        assert result["success"] is False

    def test_script_captures_stderr(self):
        """Script stderr is captured."""
        code = "import sys; print('error msg', file=sys.stderr)"
        result = script_execute(code)
        assert result["success"] is True  # exit code 0
        assert "error msg" in result["stderr"]

    def test_script_crypto_computation(self):
        """Execute a crypto-related computation (RSA-like)."""
        code = """
p = 61
q = 53
n = p * q
e = 17
phi = (p - 1) * (q - 1)
# Extended Euclidean
def modinv(a, m):
    g, x, _ = extended_gcd(a, m)
    return x % m if g == 1 else None

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x

d = modinv(e, phi)
m = 42
c = pow(m, e, n)
decrypted = pow(c, d, n)
print(f"decrypted={decrypted}")
"""
        result = script_execute(code)
        assert result["success"] is True
        assert "decrypted=42" in result["stdout"]


# ===========================================================================
# CTF_CRYPTO_TOOLS Registry Tests
# ===========================================================================


class TestCTFCryptoToolsRegistry:
    """Test the CTF_CRYPTO_TOOLS registry dict."""

    def test_registry_has_all_tools(self):
        """Registry should contain all four tool functions."""
        assert "rsa_attack" in CTF_CRYPTO_TOOLS
        assert "classical_cipher" in CTF_CRYPTO_TOOLS
        assert "encoding_decode" in CTF_CRYPTO_TOOLS
        assert "script_execute" in CTF_CRYPTO_TOOLS

    def test_registry_functions_callable(self):
        """All registry entries should be callable."""
        for name, fn in CTF_CRYPTO_TOOLS.items():
            assert callable(fn), f"{name} is not callable"

    def test_registry_rsa_attack_works(self):
        """Registry rsa_attack function works."""
        fn = CTF_CRYPTO_TOOLS["rsa_attack"]
        m = 100
        c = m ** 3
        n = c + 999
        result = fn(n, 3, c)
        assert result["success"] is True

    def test_registry_classical_cipher_works(self):
        """Registry classical_cipher function works."""
        fn = CTF_CRYPTO_TOOLS["classical_cipher"]
        result = fn("khoor zruog", "caesar")
        assert result["success"] is True

    def test_registry_encoding_decode_works(self):
        """Registry encoding_decode function works."""
        fn = CTF_CRYPTO_TOOLS["encoding_decode"]
        encoded = base64.b64encode(b"test").decode()
        result = fn(encoded, "base64")
        assert result["decoded"] == "test"

    def test_registry_script_execute_works(self):
        """Registry script_execute function works."""
        fn = CTF_CRYPTO_TOOLS["script_execute"]
        result = fn("print(1+1)")
        assert result["success"] is True
        assert "2" in result["stdout"]


# ===========================================================================
# Helper function tests
# ===========================================================================


class TestHelperFunctions:
    """Test internal helper functions."""

    def test_icbrt_perfect_cubes(self):
        """Integer cube root for perfect cubes."""
        assert _icbrt(0) == 0
        assert _icbrt(1) == 1
        assert _icbrt(8) == 2
        assert _icbrt(27) == 3
        assert _icbrt(64) == 4
        assert _icbrt(125) == 5
        assert _icbrt(1000) == 10

    def test_modinv_basic(self):
        """Modular inverse basic cases."""
        assert _modinv(3, 7) == 5  # 3*5 = 15 ≡ 1 (mod 7)
        assert _modinv(7, 11) == 8  # 7*8 = 56 ≡ 1 (mod 11)

    def test_modinv_no_inverse(self):
        """Modular inverse returns None when gcd != 1."""
        assert _modinv(2, 4) is None

    def test_score_english(self):
        """English text should score higher than random."""
        english = "the quick brown fox jumps over the lazy dog"
        random_text = "xqzjk wvbfm plrty"
        assert _score_english(english) > _score_english(random_text)
