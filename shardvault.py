"""ShardVault: threshold protection for files (computational secret sharing).

Construction (after Krawczyk 1993, "Secret Sharing Made Short"):
  1. Draw a fresh 256-bit data key K.
  2. Encrypt the file with AES-256-GCM under K. The public header is bound in
     as associated data, so tampering with the header breaks decryption.
  3. Split K with Shamir's (t, n) scheme over GF(p), p = 2**521 - 1.
     Any t shares recover K; t-1 shares reveal nothing about K.
  4. Store the ciphertext anywhere; hand each share to a different holder.

Nothing here is a new primitive: AES-GCM and Shamir sharing are standard,
and the security argument reduces to them.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

P = 2**521 - 1  # Mersenne prime; field for Shamir sharing
VERSION = 1


# ---------- Shamir secret sharing over GF(P) ----------

def _eval_poly(coeffs: list[int], x: int) -> int:
    acc = 0
    for c in reversed(coeffs):  # Horner's rule
        acc = (acc * x + c) % P
    return acc


def split_secret(secret: int, threshold: int, shares: int) -> list[tuple[int, int]]:
    if not 0 <= secret < P:
        raise ValueError("secret out of field range")
    if not 1 <= threshold <= shares <= 255:
        raise ValueError("need 1 <= threshold <= shares <= 255")
    coeffs = [secret] + [secrets.randbelow(P) for _ in range(threshold - 1)]
    return [(x, _eval_poly(coeffs, x)) for x in range(1, shares + 1)]


def combine_shares(points: list[tuple[int, int]]) -> int:
    xs = [x for x, _ in points]
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate share indices")
    secret = 0
    for i, (xi, yi) in enumerate(points):  # Lagrange interpolation at x = 0
        num, den = 1, 1
        for j, (xj, _) in enumerate(points):
            if i != j:
                num = (num * -xj) % P
                den = (den * (xi - xj)) % P
        secret = (secret + yi * num * pow(den, -1, P)) % P
    return secret


# ---------- File-level vault ----------

@dataclass
class Share:
    file_id: str
    threshold: int
    x: int
    y: int

    def encode(self) -> str:
        body = json.dumps({"v": VERSION, "f": self.file_id, "t": self.threshold,
                           "x": self.x, "y": format(self.y, "x")}, separators=(",", ":"))
        return "SV1-" + base64.urlsafe_b64encode(body.encode()).decode()

    @staticmethod
    def decode(token: str) -> "Share":
        if not token.startswith("SV1-"):
            raise ValueError("not a ShardVault share")
        d = json.loads(base64.urlsafe_b64decode(token[4:]))
        return Share(d["f"], d["t"], d["x"], int(d["y"], 16))


def seal(data: bytes, threshold: int, shares: int) -> tuple[bytes, list[str]]:
    """Encrypt data; return (vault blob, share tokens)."""
    key = AESGCM.generate_key(bit_length=256)
    file_id = secrets.token_hex(8)
    header = {"v": VERSION, "f": file_id, "t": threshold, "n": shares,
              "kc": hashlib.sha256(b"sv-key-check" + key).hexdigest()}
    aad = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, data, aad)
    blob = aad + b"\n" + nonce + ct
    pts = split_secret(int.from_bytes(key, "big"), threshold, shares)
    return blob, [Share(file_id, threshold, x, y).encode() for x, y in pts]


def open_vault(blob: bytes, tokens: list[str]) -> bytes:
    aad, rest = blob.split(b"\n", 1)
    header = json.loads(aad)
    got = [Share.decode(t) for t in tokens]
    got = [s for s in got if s.file_id == header["f"]]
    uniq = {s.x: s for s in got}
    if len(uniq) < header["t"]:
        raise ValueError(f"need {header['t']} shares for this file, got {len(uniq)}")
    pts = [(s.x, s.y) for s in list(uniq.values())[: header["t"]]]
    k = combine_shares(pts)
    if k >= 2**256:
        raise ValueError("shares inconsistent (reconstructed key out of range)")
    key = k.to_bytes(32, "big")
    if hashlib.sha256(b"sv-key-check" + key).hexdigest() != header["kc"]:
        raise ValueError("shares inconsistent or tampered")
    nonce, ct = rest[:12], rest[12:]
    return AESGCM(key).decrypt(nonce, ct, aad)  # raises on any tampering


if __name__ == "__main__":
    import argparse, pathlib, sys
    ap = argparse.ArgumentParser(description="ShardVault: split a file's key into t-of-n shares")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("seal"); s.add_argument("file"); s.add_argument("-t", type=int, default=3); s.add_argument("-n", type=int, default=5)
    o = sub.add_parser("open"); o.add_argument("vault"); o.add_argument("shares", nargs="+"); o.add_argument("-o", "--out")
    a = ap.parse_args()
    if a.cmd == "seal":
        blob, toks = seal(pathlib.Path(a.file).read_bytes(), a.t, a.n)
        pathlib.Path(a.file + ".svault").write_bytes(blob)
        for i, tok in enumerate(toks, 1):
            pathlib.Path(f"{a.file}.share{i}").write_text(tok)
        print(f"sealed -> {a.file}.svault, {a.n} shares, any {a.t} recover")
    else:
        toks = [pathlib.Path(p).read_text().strip() for p in a.shares]
        data = open_vault(pathlib.Path(a.vault).read_bytes(), toks)
        (pathlib.Path(a.out).write_bytes(data) if a.out else sys.stdout.buffer.write(data))
