"""Initialize DVWA: login, create DB, set security to Low."""
import re
import sys
import requests

BASE = "http://127.0.0.1:8080"
TOKEN_RE = re.compile(r"user_token.*?value=['\"]([a-f0-9]+)['\"]")


def get_token(html):
    m = TOKEN_RE.search(html)
    return m.group(1) if m else None


def main():
    s = requests.Session()

    # 1. Login
    r = s.get(f"{BASE}/login.php", timeout=5)
    token = get_token(r.text)
    if not token:
        print("ERROR: No token on login page")
        sys.exit(1)

    r = s.post(f"{BASE}/login.php", data={
        "username": "admin",
        "password": "password",
        "Login": "Login",
        "user_token": token,
    }, timeout=5, allow_redirects=True)
    print(f"[OK] Login -> {r.url}")

    # 2. Setup DB
    r = s.get(f"{BASE}/setup.php", timeout=5)
    token = get_token(r.text)
    if token:
        r = s.post(f"{BASE}/setup.php", data={
            "create_db": "Create / Reset Database",
            "user_token": token,
        }, timeout=15, allow_redirects=True)
        print("[OK] DB reset")

    # Re-login
    r = s.get(f"{BASE}/login.php", timeout=5)
    token = get_token(r.text)
    if token:
        s.post(f"{BASE}/login.php", data={
            "username": "admin", "password": "password",
            "Login": "Login", "user_token": token,
        }, timeout=5, allow_redirects=True)

    # 3. Set security Low
    r = s.get(f"{BASE}/security.php", timeout=5)
    token = get_token(r.text)
    if token:
        s.post(f"{BASE}/security.php", data={
            "security": "low", "seclev_submit": "Submit",
            "user_token": token,
        }, timeout=5, allow_redirects=True)
        print("[OK] Security = LOW")

    # 4. Verify
    r = s.get(f"{BASE}/vulnerabilities/sqli/?id=1&Submit=Submit", timeout=5)
    if "First name" in r.text:
        print("[OK] SQLi page works")
    else:
        print(f"[WARN] SQLi: {r.status_code}")

    r = s.get(f"{BASE}/vulnerabilities/exec/?ip=127.0.0.1&Submit=Submit", timeout=5)
    if "ttl" in r.text.lower() or "ping" in r.text.lower() or "bytes" in r.text.lower():
        print("[OK] CMDi page works")
    else:
        print(f"[WARN] CMDi: {r.status_code}")

    print(f"\n=== DVWA Ready at {BASE} ===")


if __name__ == "__main__":
    main()
