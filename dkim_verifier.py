import hashlib
import base64
import re
import sys
from collections import defaultdict

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.exceptions import InvalidSignature
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


def parse_eml(file_path: str) -> tuple:
    """Return (header_block, body) as raw bytes, split at the first blank line."""
    with open(file_path, "rb") as f:
        raw = f.read()
    idx = raw.find(b"\r\n\r\n")
    if idx != -1:
        return raw[:idx + 2], raw[idx + 4:]
    idx = raw.find(b"\n\n")
    if idx != -1:
        return raw[:idx + 1], raw[idx + 2:]
    raise ValueError(
        "No header/body separator found — the file appears to be headers-only. "
        "In Gmail, use the ⋮ menu → 'Download message' to save the complete .eml."
    )


def _split_headers(block: bytes) -> list:
    """Split a header block into individual (possibly folded) header bytes."""
    result, current = [], b""
    for line in block.splitlines(keepends=True):
        if line and line[0:1] in (b" ", b"\t") and current:
            current += line
        else:
            if current:
                result.append(current)
            current = line
    if current:
        result.append(current)
    return result


def parse_dkim_signature(header_block: bytes) -> dict:
    """Parse the first DKIM-Signature header into a tag→value dict."""
    for h in _split_headers(header_block):
        if h.lower().startswith(b"dkim-signature:"):
            value = h.split(b":", 1)[1]
            value = re.sub(rb"\r?\n[ \t]+", b" ", value).strip()
            tags = {}
            for pair in value.split(b";"):
                pair = pair.strip()
                if b"=" in pair:
                    k, v = pair.split(b"=", 1)
                    tags[k.strip().decode()] = v.strip().decode()
            return tags
    raise ValueError("No DKIM-Signature header found")


def _get_dkim_sig_raw(header_block: bytes) -> bytes:
    """Return the raw (folded) bytes of the first DKIM-Signature header."""
    for h in _split_headers(header_block):
        if h.lower().startswith(b"dkim-signature:"):
            return h
    raise ValueError("No DKIM-Signature header found")


def _canonicalize_header(raw: bytes) -> bytes:
    """Relaxed-canonicalize one header field → b'lowername:value\\r\\n'."""
    colon = raw.index(b":")
    name = raw[:colon].strip().lower()
    value = raw[colon + 1:]
    value = re.sub(rb"\r?\n[ \t]+", b" ", value)  # unfold
    value = re.sub(rb"[ \t]+", b" ", value)        # collapse WSP
    value = value.strip(b" \t\r\n")                # strip surrounding whitespace
    return name + b":" + value + b"\r\n"


def canonicalize_body_relaxed(body: bytes) -> bytes:
    """RFC 6376 §3.4.3 relaxed body canonicalization."""
    body = re.sub(b"[ \t]+", b" ", body)
    lines = [line.rstrip(b" \t") for line in body.splitlines()]
    result = b"\r\n".join(lines).rstrip(b"\r\n")
    return result + b"\r\n" if result else b"\r\n"


def canonicalize_headers_relaxed(header_block: bytes, signed_names: list,
                                 dkim_raw: bytes) -> bytes:
    """
    Build the canonical header blob for signature verification (RFC 6376 §3.7).
    signed_names: ordered list from the h= tag.
    dkim_raw: raw bytes of the DKIM-Signature header (will be appended with b= emptied).
    """
    headers = _split_headers(header_block)

    hmap: dict = defaultdict(list)
    for h in headers:
        if b":" in h:
            n = h.split(b":", 1)[0].strip().lower().decode("ascii", errors="ignore")
            hmap[n].append(h)

    consumed: dict = defaultdict(int)
    out = b""
    for name in signed_names:
        nl = name.lower().strip()
        candidates = hmap.get(nl, [])
        idx = len(candidates) - 1 - consumed[nl]
        consumed[nl] += 1
        if idx >= 0:
            out += _canonicalize_header(candidates[idx])

    # Append DKIM-Signature with b= value emptied, no trailing CRLF
    dkim_canon = _canonicalize_header(dkim_raw).rstrip(b"\r\n")
    dkim_canon = re.sub(rb"(; *b=)[A-Za-z0-9+/= ]*", rb"\1", dkim_canon)
    return out + dkim_canon


def verify_body_hash(body: bytes, expected_bh: str, algo: str) -> tuple:
    """Returns (match: bool, computed_bh: str)."""
    canonical = canonicalize_body_relaxed(body)
    digest = hashlib.sha256(canonical).digest() if "sha256" in algo else hashlib.sha1(canonical).digest()
    computed = base64.b64encode(digest).decode()
    return computed == expected_bh, computed


def fetch_public_key(domain: str, selector: str) -> bytes:
    """Fetch DKIM public key via DNS TXT. Returns DER-encoded RSA public key."""
    if not HAS_DNSPYTHON:
        raise RuntimeError("dnspython not installed — run: pip3 install dnspython")
    qname = f"{selector}._domainkey.{domain}"
    answers = dns.resolver.resolve(qname, "TXT", lifetime=10)
    txt = b"".join(b"".join(rd.strings) for rd in answers).decode("ascii", errors="ignore")
    for tag in txt.split(";"):
        tag = tag.strip()
        if tag.startswith("p="):
            p = tag[2:].strip()
            if not p:
                raise ValueError("DKIM public key is empty — key has been revoked")
            return base64.b64decode(p)
    raise ValueError(f"No p= tag in TXT record for {qname}")


def verify_signature(canon_headers: bytes, b_value: str,
                     pubkey_der: bytes, algo: str) -> bool:
    """Verify RSA-PKCS1v15 signature over canonical headers. Raises on failure."""
    if not HAS_CRYPTOGRAPHY:
        raise RuntimeError("cryptography not installed — run: pip3 install cryptography")
    sig = base64.b64decode(re.sub(r"\s+", "", b_value))
    pubkey = serialization.load_der_public_key(pubkey_der)
    hash_algo = hashes.SHA256() if "sha256" in algo else hashes.SHA1()
    pubkey.verify(sig, canon_headers, padding.PKCS1v15(), hash_algo)
    return True


def _parse_header_value(header_block: bytes, name: str) -> str:
    """Return the unfolded value of the first matching header, or ''."""
    target = (name.lower() + ":").encode()
    for h in _split_headers(header_block):
        if h.lower().startswith(target):
            value = h.split(b":", 1)[1]
            value = re.sub(rb"\r?\n[ \t]+", b" ", value).strip()
            return value.decode("utf-8", errors="replace")
    return ""


def verify_email(file_path: str) -> dict:
    """
    Verify DKIM on an .eml file.
    Returns a result dict with keys:
      file, from, domain, selector, algorithm, canonicalization,
      signed_headers, bh_expected, bh_computed, bh_pass, b_pass, b_error.
    """
    result = {
        "file": file_path,
        "from": "",
        "domain": "",
        "selector": "",
        "algorithm": "",
        "canonicalization": "",
        "signed_headers": "",
        "bh_expected": "",
        "bh_computed": "",
        "bh_pass": False,
        "b_pass": None,
        "b_error": None,
    }

    header_block, body = parse_eml(file_path)
    tags = parse_dkim_signature(header_block)

    result["from"] = _parse_header_value(header_block, "From")
    result["domain"] = tags.get("d", "")
    result["selector"] = tags.get("s", "")
    result["algorithm"] = tags.get("a", "rsa-sha256")
    result["canonicalization"] = tags.get("c", "relaxed/relaxed")
    result["signed_headers"] = tags.get("h", "")
    result["bh_expected"] = tags.get("bh", "")

    bh_pass, bh_computed = verify_body_hash(body, result["bh_expected"], result["algorithm"])
    result["bh_pass"] = bh_pass
    result["bh_computed"] = bh_computed

    try:
        signed_names = [n.strip() for n in result["signed_headers"].split(":")]
        dkim_raw = _get_dkim_sig_raw(header_block)
        canon = canonicalize_headers_relaxed(header_block, signed_names, dkim_raw)
        pubkey_der = fetch_public_key(result["domain"], result["selector"])
        verify_signature(canon, tags.get("b", ""), pubkey_der, result["algorithm"])
        result["b_pass"] = True
    except Exception as exc:
        result["b_pass"] = False
        result["b_error"] = str(exc)

    return result


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <email.eml>")
        sys.exit(1)

    r = verify_email(sys.argv[1])
    print(f"File:    {r['file']}")
    print(f"From:    {r['from']}")
    print(f"Domain:  {r['domain']}   Selector: {r['selector']}")
    print(f"Algo:    {r['algorithm']}   Canon: {r['canonicalization']}")
    print(f"Signed:  {r['signed_headers']}")
    print()

    bh_label = "PASS" if r["bh_pass"] else "FAIL"
    print(f"Body Hash (bh=):  {bh_label}")
    print(f"  Expected: {r['bh_expected']}")
    print(f"  Computed: {r['bh_computed']}")
    print()

    if r["b_pass"] is True:
        print("Signature  (b=):  PASS")
    elif r["b_pass"] is False:
        print(f"Signature  (b=):  FAIL  [{r['b_error']}]")
    else:
        print("Signature  (b=):  SKIP")
