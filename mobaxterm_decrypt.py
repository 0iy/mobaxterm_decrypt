#!/usr/bin/env python3
"""
mobaxterm decryptor by 0iy
based on h0ny/MobaXtermDecryptor

usage:
    python mobaxterm_decrypt.py                  # show credentials
    python mobaxterm_decrypt.py --ssh          # ssh format
    python mobaxterm_decrypt.py --json          # json
    python mobaxterm_decrypt.py --export        # csv
    python mobaxterm_decrypt.py --ini <path>    # custom ini file
    python mobaxterm_decrypt.py --help
"""
import os
import sys
import json
import csv
import argparse
import base64
import ctypes
import winreg
from ctypes import wintypes

DPAPI_HEADER = bytes([0x01, 0x00, 0x00, 0x00, 0xd0, 0x8c, 0x9d, 0xdf,
                      0x01, 0x15, 0x11, 0x01, 0x8c, 0x7a, 0x00, 0xc0, 0x4f, 0xc2, 0x97, 0xeb])


def dpapi_unprotect(data, entropy=b''):
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(wintypes.BYTE))]
    crypt32 = ctypes.windll.crypt32
    in_blob = DATA_BLOB(len(data), ctypes.cast(data, ctypes.POINTER(wintypes.BYTE)))
    entropy_blob = DATA_BLOB(len(entropy), ctypes.cast(entropy, ctypes.POINTER(wintypes.BYTE)))
    out_blob = DATA_BLOB()
    if crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, ctypes.byref(entropy_blob),
                                   None, None, 0x01, ctypes.byref(out_blob)):
        result = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        ctypes.windll.kernel32.LocalFree(out_blob.pbData)
        return result
    return None


def decrypt(ciphertext_b64, master_password_b64, session_p):
    try:
        from Crypto.Cipher import AES
        decrypted = dpapi_unprotect(DPAPI_HEADER + base64.b64decode(master_password_b64), session_p.encode('utf-8'))
        if not decrypted:
            return None
        aes_key = base64.b64decode(decrypted.decode('utf-8', errors='ignore'))[:32]
        cipher = AES.new(aes_key, AES.MODE_ECB)
        iv = cipher.encrypt(b'\x00' * 16)[:16]
        cipher = AES.new(aes_key, AES.MODE_CFB, iv=iv, segment_size=8)
        return cipher.decrypt(base64.b64decode(ciphertext_b64)).decode('utf-8', errors='ignore')
    except:
        return None


def validate_ini(path):
    """check if file is a valid mobaxterm ini."""
    if not os.path.isfile(path):
        return False, "not a file"

    if not os.access(path, os.R_OK):
        return False, "not readable"

    # check file extension and basic mobaxterm markers
    has_misc = False
    has_sessionp = False
    has_credentials_or_passwords = False

    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read(8192)  # read first 8kb for quick check

        if '[Misc]' not in content and '[misc]' not in content.lower():
            return False, "missing [Misc] section"

        if 'SessionP=' not in content:
            return False, "missing SessionP"

        if '[Credentials]' in content or '[Passwords]' in content:
            has_credentials_or_passwords = True

    # full check
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line_lower = line.lower().strip()
            if line_lower.startswith('[misc]'):
                has_misc = True
            if line_lower.startswith('sessionp='):
                has_sessionp = True
            if line_lower.startswith('[credentials]') or line_lower.startswith('[passwords]'):
                has_credentials_or_passwords = True

    if not has_misc:
        return False, "missing [Misc] section"
    if not has_sessionp:
        return False, "missing SessionP"

    return True, "valid mobaxterm ini"


def find_ini_files():
    """find all mobaxterm ini files."""
    paths = []

    # standard appdata locations
    for appdata in [os.environ.get('APPDATA', ''), os.environ.get('LOCALAPPDATA', '')]:
        if appdata:
            path = os.path.join(appdata, 'MobaXterm', 'MobaXterm.ini')
            if os.path.exists(path) and path not in paths:
                valid, msg = validate_ini(path)
                if valid:
                    paths.append(path)

    # portable version - check registry for exe path
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Mobatek\MobaXterm") as key:
            try:
                exe_path, _ = winreg.QueryValueEx(key, "")
                if exe_path and os.path.exists(exe_path):
                    ini = os.path.join(os.path.dirname(exe_path), 'MobaXterm.ini')
                    if os.path.exists(ini) and ini not in paths:
                        valid, msg = validate_ini(ini)
                        if valid:
                            paths.append(ini)
            except: pass
    except: pass

    return paths


def parse_ini(path):
    if not os.path.exists(path):
        return {}
    sections, current = {}, None
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith(';'):
                continue
            if line.startswith('[') and line.endswith(']'):
                current = line[1:-1]
                sections[current] = []
            elif '=' in line and current:
                k, _, v = line.partition('=')
                sections[current].append((k.strip(), v.strip()))
    return sections


def main():
    parser = argparse.ArgumentParser(description="mobaxterm decryptor by 0iy", add_help=False)
    parser.add_argument('--help', action='store_true', help='show this help')
    parser.add_argument('--ini', metavar='PATH', help='path to custom mobaxterm.ini')
    parser.add_argument('--ssh', action='store_true', help='ssh format output')
    parser.add_argument('--json', action='store_true', help='json output')
    parser.add_argument('--export', action='store_true', help='csv export')
    args = parser.parse_args()

    if args.help:
        print(__doc__)
        return

    # get from registry first
    session_p, master_password = None, None
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Mobatek\MobaXterm") as key:
            try:
                session_p = str(winreg.QueryValueEx(key, "SessionP")[0])
            except: pass
    except: pass

    upn = f"{os.environ.get('USERNAME','')}@{os.environ.get('COMPUTERNAME','')}"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Mobatek\MobaXterm\M") as key:
            try:
                master_password = winreg.QueryValueEx(key, upn)[0]
            except: pass
    except: pass

    # custom ini path
    ini_files = []
    if args.ini:
        valid, msg = validate_ini(args.ini)
        if not valid:
            print(f"[ERROR] invalid ini: {msg}")
            sys.exit(1)
        ini_files = [args.ini]
    else:
        ini_files = find_ini_files()

    if not ini_files:
        print("[ERROR] no valid mobaxterm.ini found")
        sys.exit(1)

    # fallback to ini files for sessionp/master password
    for ini_path in ini_files:
        sections = parse_ini(ini_path)
        if not session_p:
            for k, v in sections.get('Misc', []):
                if k == 'SessionP':
                    session_p = v
                    break
        if not master_password:
            for k, v in sections.get('Sesspass', []):
                if os.environ.get('USERNAME', '') in k:
                    master_password = v
                    break

    if not session_p:
        print("[ERROR] sessionp not found in any ini")
        sys.exit(1)

    if not master_password:
        print("[WARNING] master password not found. some creds wont decrypt.")

    results = []

    # extract from ini files
    for ini_path in ini_files:
        sections = parse_ini(ini_path)

        for name, value in sections.get('Credentials', []):
            if ':' in value:
                user, pw_b64 = value.split(':', 1)
                pw = decrypt(pw_b64, master_password, session_p) if master_password else "[NO_MASTER_PWD]"
                results.append({'source': ini_path, 'name': name, 'user': user, 'pass': pw})

        for name, pw_b64 in sections.get('Passwords', []):
            pw = decrypt(pw_b64, master_password, session_p) if master_password else "[NO_MASTER_PWD]"
            results.append({'source': ini_path, 'name': name, 'user': '', 'pass': pw})

    # extract from registry (only if not using custom ini)
    if not args.ini:
        for reg_key in [r"Software\Mobatek\MobaXterm\C", r"Software\Mobatek\MobaXterm\P"]:
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_key) as key:
                    i = 0
                    while True:
                        try:
                            name = winreg.EnumValue(key, i)[0]
                            value = winreg.EnumValue(key, i)[1]
                            if ':' in value:
                                user, pw_b64 = value.split(':', 1)
                                pw = decrypt(pw_b64, master_password, session_p) if master_password else "[NO_MASTER_PWD]"
                                results.append({'source': 'registry', 'name': name, 'user': user, 'pass': pw})
                            else:
                                pw = decrypt(value, master_password, session_p) if master_password else "[NO_MASTER_PWD]"
                                results.append({'source': 'registry', 'name': name, 'user': '', 'pass': pw})
                            i += 1
                        except OSError:
                            break
            except: pass

    if not results:
        print("[WARNING] no credentials found")
        return

    if args.json:
        print(json.dumps(results, indent=2))
    elif args.ssh:
        for r in results:
            if r['user']:
                print(f"ssh {r['user']}@{r['name']}")
    elif args.export:
        with open("mobaxterm_credentials.csv", 'w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=['source', 'name', 'user', 'pass'])
            w.writeheader()
            w.writerows(results)
        print(f"[EXPORT] saved {len(results)} creds to mobaxterm_credentials.csv")
    else:
        print("=" * 60)
        print("mobaxterm credentials")
        print("=" * 60)
        for r in results:
            if r['user']:
                print(f"{r['name']}:{r['user']}:{r['pass']}")
            else:
                print(f"{r['name']}:{r['pass']}")


if __name__ == "__main__":
    try:
        from Crypto.Cipher import AES
    except ImportError:
        print("[ERROR] pip install pycryptodome")
        sys.exit(1)
    main()
