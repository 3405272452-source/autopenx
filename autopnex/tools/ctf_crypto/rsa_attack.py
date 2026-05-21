"""RSA attack tool for CTF challenges.

Implements:
- Small e attack (cube root when e=3)
- Common modulus attack (same n, different e values)
- Wiener attack (small d via continued fractions)
- Fermat factorization (when p ≈ q)
- Auto mode: tries attacks in order of likelihood
"""
from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Tuple

from ..base import BaseTool, ToolResult, register

# Try to import gmpy2 for fast integer operations; fall back to pure Python
try:
    import gmpy2  # type: ignore

    _HAS_GMPY2 = True
except ImportError:
    _HAS_GMPY2 = False


# ---------------------------------------------------------------------------
# Pure-Python integer math helpers
# ---------------------------------------------------------------------------


def _isqrt(n: int) -> int:
    """Integer square root (Python 3.8+ has math.isqrt)."""
    return math.isqrt(n)


def _icbrt(n: int) -> int:
    """Integer cube root via Newton's method."""
    if n < 0:
        return -_icbrt(-n)
    if n == 0:
        return 0
    # Initial estimate
    x = int(round(n ** (1 / 3)))
    # Adjust around the estimate
    for candidate in (x - 2, x - 1, x, x + 1, x + 2):
        if candidate >= 0 and candidate ** 3 == n:
            return candidate
    # Newton refinement for large numbers
    x = n
    while True:
        x1 = (2 * x + n // (x * x)) // 3
        if x1 >= x:
            return x
        x = x1


def _gcd(a: int, b: int) -> int:
    """Greatest common divisor."""
    while b:
        a, b = b, a % b
    return a


def _modinv(a: int, m: int) -> Optional[int]:
    """Extended Euclidean algorithm to compute modular inverse."""
    g, x, _ = _extended_gcd(a, m)
    if g != 1:
        return None
    return x % m


def _extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended GCD returning (gcd, x, y) such that a*x + b*y = gcd."""
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def _pow_mod(base: int, exp: int, mod: int) -> int:
    """Modular exponentiation."""
    return pow(base, exp, mod)


def _int_to_bytes(n: int) -> str:
    """Convert integer to bytes string, attempting UTF-8 decode."""
    if n == 0:
        return ""
    try:
        length = (n.bit_length() + 7) // 8
        raw = n.to_bytes(length, "big")
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Continued fractions for Wiener attack
# ---------------------------------------------------------------------------


def _continued_fraction(numerator: int, denominator: int) -> List[int]:
    """Compute continued fraction expansion of numerator/denominator."""
    cf: List[int] = []
    while denominator:
        q = numerator // denominator
        cf.append(q)
        numerator, denominator = denominator, numerator - q * denominator
    return cf


def _convergents(cf: List[int]) -> List[Tuple[int, int]]:
    """Compute convergents (h/k) from continued fraction expansion."""
    convergents: List[Tuple[int, int]] = []
    h_prev, h_curr = 0, 1
    k_prev, k_curr = 1, 0
    for a in cf:
        h_prev, h_curr = h_curr, a * h_curr + h_prev
        k_prev, k_curr = k_curr, a * k_curr + k_prev
        convergents.append((h_curr, k_curr))
    return convergents


# ---------------------------------------------------------------------------
# Attack implementations
# ---------------------------------------------------------------------------


def _small_e_attack(n: int, e: int, c: Optional[int]) -> Dict[str, Any]:
    """Small e attack: if e=3 and m^3 < n, then m = cbrt(c)."""
    if e != 3:
        return {"success": False, "reason": "e is not 3"}

    if c is None:
        return {"success": False, "reason": "ciphertext required for small_e attack"}

    if _HAS_GMPY2:
        c_mpz = gmpy2.mpz(c)
        root, exact = gmpy2.iroot(c_mpz, 3)
        if exact:
            m = int(root)
            return {
                "success": True,
                "attack": "small_e",
                "m": m,
                "m_hex": hex(m),
                "m_bytes": _int_to_bytes(m),
            }
    else:
        root = _icbrt(c)
        if root ** 3 == c:
            m = root
            return {
                "success": True,
                "attack": "small_e",
                "m": m,
                "m_hex": hex(m),
                "m_bytes": _int_to_bytes(m),
            }

    return {
        "success": False,
        "reason": "cube root is not exact (m^3 >= n or padding used)",
    }


def _common_modulus_attack(
    n: int, e1: int, e2: int, c1: int, c2: int
) -> Dict[str, Any]:
    """Common modulus attack: same n encrypted with two different e values.

    If gcd(e1, e2) == 1, we can recover m without factoring n.
    m = c1^s1 * c2^s2 mod n, where e1*s1 + e2*s2 = 1.
    """
    g = _gcd(e1, e2)
    if g != 1:
        return {
            "success": False,
            "reason": f"gcd(e1, e2) = {g} != 1, common modulus attack not applicable",
        }

    _, s1, s2 = _extended_gcd(e1, e2)

    # Handle negative exponents via modular inverse
    if s1 < 0:
        c1_inv = _modinv(c1, n)
        if c1_inv is None:
            return {"success": False, "reason": "Cannot compute modular inverse of c1"}
        m = (_pow_mod(c1_inv, -s1, n) * _pow_mod(c2, s2, n)) % n
    elif s2 < 0:
        c2_inv = _modinv(c2, n)
        if c2_inv is None:
            return {"success": False, "reason": "Cannot compute modular inverse of c2"}
        m = (_pow_mod(c1, s1, n) * _pow_mod(c2_inv, -s2, n)) % n
    else:
        m = (_pow_mod(c1, s1, n) * _pow_mod(c2, s2, n)) % n

    return {
        "success": True,
        "attack": "common_modulus",
        "m": m,
        "m_hex": hex(m),
        "m_bytes": _int_to_bytes(m),
    }


def _wiener_attack(n: int, e: int, c: Optional[int]) -> Dict[str, Any]:
    """Wiener's attack: recovers d when d < n^(1/4) / 3.

    Uses continued fraction expansion of e/n to find d.
    """
    cf = _continued_fraction(e, n)
    convs = _convergents(cf)

    for k, d in convs:
        if k == 0 or d == 0:
            continue

        # Check if (e*d - 1) is divisible by k
        if (e * d - 1) % k != 0:
            continue

        phi = (e * d - 1) // k

        # phi(n) = n - p - q + 1, so p + q = n - phi + 1
        s = n - phi + 1  # p + q
        # p and q are roots of x^2 - s*x + n = 0
        discriminant = s * s - 4 * n
        if discriminant < 0:
            continue

        sqrt_disc = _isqrt(discriminant)
        if sqrt_disc * sqrt_disc != discriminant:
            continue

        p = (s + sqrt_disc) // 2
        q = (s - sqrt_disc) // 2

        if p * q == n and p > 1 and q > 1:
            result: Dict[str, Any] = {
                "success": True,
                "attack": "wiener",
                "d": d,
                "p": p,
                "q": q,
            }
            if c is not None:
                m = _pow_mod(c, d, n)
                result["m"] = m
                result["m_hex"] = hex(m)
                result["m_bytes"] = _int_to_bytes(m)
            return result

    return {"success": False, "reason": "Wiener attack failed (d may be too large)"}


def _fermat_factorization(n: int, max_iter: int = 100_000) -> Dict[str, Any]:
    """Fermat factorization: works when p and q are close to each other."""
    if n % 2 == 0:
        return {"success": True, "attack": "fermat", "p": 2, "q": n // 2}

    if _HAS_GMPY2:
        a = int(gmpy2.isqrt(n)) + 1
        b2 = a * a - n
        for _ in range(max_iter):
            b_root, exact = gmpy2.iroot(gmpy2.mpz(b2), 2)
            if exact:
                p = a - int(b_root)
                q = a + int(b_root)
                if p * q == n and p > 1 and q > 1:
                    return {"success": True, "attack": "fermat", "p": p, "q": q}
            a += 1
            b2 = a * a - n
    else:
        a = _isqrt(n) + 1
        b2 = a * a - n
        for _ in range(max_iter):
            b = _isqrt(b2)
            if b * b == b2:
                p = a - b
                q = a + b
                if p * q == n and p > 1 and q > 1:
                    return {"success": True, "attack": "fermat", "p": p, "q": q}
            a += 1
            b2 = a * a - n

    return {
        "success": False,
        "reason": f"Fermat factorization failed after {max_iter} iterations",
    }


def _decrypt_rsa(p: int, q: int, e: int, c: int) -> Dict[str, Any]:
    """Given p, q, e, c — compute plaintext m."""
    phi = (p - 1) * (q - 1)
    d = _modinv(e, phi)
    if d is None:
        return {"success": False, "reason": "e and phi(n) are not coprime"}
    n = p * q
    m = _pow_mod(c, d, n)
    return {
        "success": True,
        "d": d,
        "m": m,
        "m_hex": hex(m),
        "m_bytes": _int_to_bytes(m),
    }


# ---------------------------------------------------------------------------
# Standalone function interface
# ---------------------------------------------------------------------------


def rsa_attack(
    n: int,
    e: int,
    c: int,
    attack_type: str = "auto",
    *,
    e2: Optional[int] = None,
    c2: Optional[int] = None,
) -> dict:
    """RSA attack function for CTF challenges.

    Args:
        n: RSA modulus.
        e: RSA public exponent.
        c: Ciphertext.
        attack_type: One of "small_e", "common_modulus", "wiener", "fermat", "auto".
        e2: Second public exponent (for common_modulus attack).
        c2: Second ciphertext (for common_modulus attack).

    Returns:
        dict with keys: success, plaintext, method, factors.
    """
    result: Dict[str, Any] = {
        "success": False,
        "plaintext": b"",
        "method": "",
        "factors": {},
    }

    def _extract_result(attack_result: Dict[str, Any], method: str) -> bool:
        """Extract attack result into the standard return format."""
        if not attack_result.get("success"):
            return False
        result["success"] = True
        result["method"] = method
        m = attack_result.get("m")
        if m is not None:
            try:
                length = (m.bit_length() + 7) // 8
                result["plaintext"] = m.to_bytes(length, "big") if m > 0 else b""
            except Exception:
                result["plaintext"] = b""
        p = attack_result.get("p")
        q = attack_result.get("q")
        if p and q:
            result["factors"] = {"p": p, "q": q}
        return True

    attacks_to_try: List[str] = []

    if attack_type == "auto":
        attacks_to_try = ["small_e", "common_modulus", "wiener", "fermat"]
    else:
        attacks_to_try = [attack_type]

    for attack in attacks_to_try:
        if attack == "small_e":
            res = _small_e_attack(n, e, c)
            if _extract_result(res, "small_e"):
                return result

        elif attack == "common_modulus":
            if e2 is not None and c2 is not None:
                res = _common_modulus_attack(n, e, e2, c, c2)
                if _extract_result(res, "common_modulus"):
                    return result

        elif attack == "wiener":
            res = _wiener_attack(n, e, c)
            if _extract_result(res, "wiener"):
                return result

        elif attack == "fermat":
            res = _fermat_factorization(n)
            if res.get("success"):
                p, q = res["p"], res["q"]
                result["factors"] = {"p": p, "q": q}
                # Decrypt if we have ciphertext
                dec = _decrypt_rsa(p, q, e, c)
                if dec.get("success"):
                    result["success"] = True
                    result["method"] = "fermat"
                    m = dec["m"]
                    try:
                        length = (m.bit_length() + 7) // 8
                        result["plaintext"] = m.to_bytes(length, "big") if m > 0 else b""
                    except Exception:
                        result["plaintext"] = b""
                    return result
                else:
                    # Factored but couldn't decrypt
                    result["success"] = True
                    result["method"] = "fermat"
                    return result

    return result


# ---------------------------------------------------------------------------
# Tool class
# ---------------------------------------------------------------------------


@register
class RSAAttackTool(BaseTool):
    category = "ctf_crypto"

    @property
    def name(self) -> str:
        return "rsa_attack"

    @property
    def description(self) -> str:
        return (
            "RSA attack tool for CTF challenges. Supports small-e (cube root), "
            "common modulus, Wiener (small d), Fermat factorization (close primes), "
            "and auto mode. Provide n, e as decimal strings; optionally c (ciphertext)."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "n": {
                    "type": "string",
                    "description": "RSA modulus as decimal string.",
                },
                "e": {
                    "type": "string",
                    "description": "RSA public exponent as decimal string.",
                },
                "c": {
                    "type": "string",
                    "description": "Ciphertext as decimal string (optional).",
                },
                "e2": {
                    "type": "string",
                    "description": "Second public exponent for common modulus attack.",
                },
                "c2": {
                    "type": "string",
                    "description": "Second ciphertext for common modulus attack.",
                },
                "attack": {
                    "type": "string",
                    "enum": ["small_e", "common_modulus", "wiener", "fermat", "auto"],
                    "description": "Attack type. Default: auto.",
                },
            },
            "required": ["n", "e"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        n_str: str = kwargs.get("n", "")
        e_str: str = kwargs.get("e", "")
        c_str: str = kwargs.get("c", "")
        e2_str: str = kwargs.get("e2", "")
        c2_str: str = kwargs.get("c2", "")
        attack: str = kwargs.get("attack", "auto")

        # Parse integers
        try:
            n = int(n_str)
            e = int(e_str)
        except (ValueError, TypeError) as exc:
            return ToolResult(
                success=False,
                tool=self.name,
                summary="Invalid n or e",
                error=str(exc),
            )

        c: Optional[int] = None
        if c_str:
            try:
                c = int(c_str)
            except (ValueError, TypeError) as exc:
                return ToolResult(
                    success=False,
                    tool=self.name,
                    summary="Invalid ciphertext c",
                    error=str(exc),
                )

        e2: Optional[int] = None
        c2: Optional[int] = None
        if e2_str:
            try:
                e2 = int(e2_str)
            except (ValueError, TypeError):
                pass
        if c2_str:
            try:
                c2 = int(c2_str)
            except (ValueError, TypeError):
                pass

        results: Dict[str, Any] = {"n": n_str, "e": e_str, "attack_tried": []}
        p: Optional[int] = None
        q: Optional[int] = None
        decrypted: Optional[Dict[str, Any]] = None

        def _try_small_e() -> bool:
            nonlocal decrypted
            results["attack_tried"].append("small_e")
            res = _small_e_attack(n, e, c)
            results["small_e"] = res
            if res["success"]:
                decrypted = res
                return True
            return False

        def _try_common_modulus() -> bool:
            nonlocal decrypted
            if e2 is None or c2 is None or c is None:
                return False
            results["attack_tried"].append("common_modulus")
            res = _common_modulus_attack(n, e, e2, c, c2)
            results["common_modulus"] = res
            if res["success"]:
                decrypted = res
                return True
            return False

        def _try_wiener() -> bool:
            nonlocal p, q, decrypted
            results["attack_tried"].append("wiener")
            res = _wiener_attack(n, e, c)
            results["wiener"] = res
            if res["success"]:
                p = res.get("p")
                q = res.get("q")
                if p and q:
                    results["p"] = p
                    results["q"] = q
                decrypted = res
                return True
            return False

        def _try_fermat() -> bool:
            nonlocal p, q, decrypted
            results["attack_tried"].append("fermat")
            res = _fermat_factorization(n)
            results["fermat"] = res
            if res["success"]:
                p = res["p"]
                q = res["q"]
                results["p"] = p
                results["q"] = q
                if c is not None:
                    dec = _decrypt_rsa(p, q, e, c)
                    results["decryption"] = dec
                    if dec["success"]:
                        decrypted = dec
                return True
            return False

        if attack == "small_e":
            _try_small_e()
        elif attack == "common_modulus":
            _try_common_modulus()
        elif attack == "wiener":
            _try_wiener()
        elif attack == "fermat":
            _try_fermat()
        else:  # auto
            if not _try_small_e():
                if not _try_common_modulus():
                    if not _try_wiener():
                        _try_fermat()

        success = decrypted is not None or p is not None
        summary_parts = []
        if p and q:
            summary_parts.append(f"Factored: p={p}, q={q}")
        if decrypted:
            m_bytes = decrypted.get("m_bytes", "")
            summary_parts.append(
                f"Decrypted: {m_bytes!r} (hex={decrypted.get('m_hex', '')})"
            )
        if not summary_parts:
            summary_parts.append("No attack succeeded")

        return ToolResult(
            success=success,
            tool=self.name,
            summary="; ".join(summary_parts),
            parsed_data=results,
            raw_output=str(results),
        )
