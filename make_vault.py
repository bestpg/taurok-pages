#!/usr/bin/env python3
"""
make_vault.py — create / read an Ansible-Vault (1.1, AES256) encrypted file
without needing ansible installed. Output is byte-for-byte compatible with
`ansible-vault view/edit/decrypt`.

Usage:
    python3 make_vault.py build      # secrets.env + .vault_pass -> group_vars/all/vault.yml
    python3 make_vault.py view       # decrypt group_vars/all/vault.yml and print to stdout
    python3 make_vault.py check      # round-trip self-test, prints OK / FAIL

Secrets are read from ./secrets.env (KEY=VALUE lines). The vault password is
read from ./.vault_pass. BOTH of those files are git-ignored and must never be
committed — only the encrypted vault.yml is safe to commit.
"""
import os
import sys
import hmac as hmaclib
import hashlib
import binascii

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

HEADER = b"$ANSIBLE_VAULT;1.1;AES256"
HERE = os.path.dirname(os.path.abspath(__file__))
VAULT_PATH = os.path.join(HERE, "group_vars", "all", "vault.yml")
SECRETS_PATH = os.path.join(HERE, "secrets.env")
PASS_PATH = os.path.join(HERE, ".vault_pass")


def _derive(password: bytes, salt: bytes):
    """Ansible key derivation: PBKDF2-HMAC-SHA256, 10000 iters, 80 bytes."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=80, salt=salt, iterations=10000)
    key = kdf.derive(password)
    return key[:32], key[32:64], key[64:80]  # cipher key, hmac key, iv


def encrypt(plaintext: bytes, password: bytes) -> bytes:
    salt = os.urandom(32)
    cipher_key, hmac_key, iv = _derive(password, salt)

    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()

    enc = Cipher(algorithms.AES(cipher_key), modes.CTR(iv)).encryptor()
    ciphertext = enc.update(padded) + enc.finalize()

    signature = hmaclib.new(hmac_key, ciphertext, hashlib.sha256).hexdigest().encode()

    combined = b"\n".join([binascii.hexlify(salt), signature, binascii.hexlify(ciphertext)])
    body = binascii.hexlify(combined)

    lines = [HEADER] + [body[i:i + 80] for i in range(0, len(body), 80)]
    return b"\n".join(lines) + b"\n"


def decrypt(vaulttext: bytes, password: bytes) -> bytes:
    lines = vaulttext.splitlines()
    if not lines or not lines[0].strip().startswith(b"$ANSIBLE_VAULT"):
        raise ValueError("not an ansible-vault file")
    body = b"".join(l.strip() for l in lines[1:])
    combined = binascii.unhexlify(body)
    hsalt, hsig, hct = combined.split(b"\n")
    salt = binascii.unhexlify(hsalt)
    sig = binascii.unhexlify(hsig)
    ciphertext = binascii.unhexlify(hct)

    cipher_key, hmac_key, iv = _derive(password, salt)
    expected = hmaclib.new(hmac_key, ciphertext, hashlib.sha256).digest()
    if not hmaclib.compare_digest(expected, sig):
        raise ValueError("HMAC mismatch — wrong password or corrupted vault")

    dec = Cipher(algorithms.AES(cipher_key), modes.CTR(iv)).decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def _read_password() -> bytes:
    with open(PASS_PATH, "rb") as f:
        return f.read().strip()


def _read_secrets() -> dict:
    data = {}
    with open(SECRETS_PATH, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            data[k.strip()] = v.strip().strip('"').strip("'")
    return data


def _yaml_escape(v: str) -> str:
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'


def build():
    s = _read_secrets()
    password = _read_password()
    if not password:
        sys.exit(".vault_pass is empty")

    plaintext = (
        "---\n"
        "# === Cloudflare ROOT credentials (account owner) ===\n"
        "# High privilege. Used only to provision the project + scoped deploy token.\n"
        f"cloudflare_email: {_yaml_escape(s.get('CF_EMAIL', ''))}\n"
        f"cloudflare_api_token: {_yaml_escape(s.get('CF_ROOT_TOKEN', ''))}\n"
        "\n"
        "# === Scoped Cloudflare Pages deploy token (created from the root token) ===\n"
        f"cloudflare_pages_deploy_token: {_yaml_escape(s.get('CF_DEPLOY_TOKEN') or 'PENDING_RUN_bootstrap.sh')}\n"
        f"cloudflare_pages_project: {_yaml_escape(s.get('CF_PAGES_PROJECT') or 'taurok')}\n"
        "\n"
        "# === GitHub ===\n"
        f"github_token: {_yaml_escape(s.get('GH_TOKEN', ''))}\n"
    ).encode("utf-8")

    os.makedirs(os.path.dirname(VAULT_PATH), exist_ok=True)
    enc = encrypt(plaintext, password)
    with open(VAULT_PATH, "wb") as f:
        f.write(enc)

    # self-verify
    back = decrypt(enc, password)
    assert back == plaintext, "round-trip verification failed!"
    os.chmod(VAULT_PATH, 0o600)
    print(f"wrote + verified {VAULT_PATH} ({len(enc)} bytes)")


def view():
    password = _read_password()
    with open(VAULT_PATH, "rb") as f:
        print(decrypt(f.read(), password).decode("utf-8"))


def check():
    # Self-test only — a throwaway password, NOT the real vault password
    # (the real one lives solely in the git-ignored .vault_pass).
    pw = b"selftest-password-not-the-vault-pass"
    sample = b"---\nfoo: bar\nsecret: hunter2\n"
    enc = encrypt(sample, pw)
    assert decrypt(enc, pw) == sample
    try:
        decrypt(enc, b"wrongpassword")
    except ValueError:
        print("OK — encrypt/decrypt round-trip works and wrong password is rejected")
        return
    print("FAIL — wrong password was not rejected")
    sys.exit(1)


if __name__ == "__m