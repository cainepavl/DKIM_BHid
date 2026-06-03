"""Tests for dkim_verifier.py — covers parsing, canonicalization, hashing, and signature verification."""

import base64
import hashlib
import os
import tempfile
import unittest
from unittest.mock import patch

import dkim_verifier


# ── helpers ───────────────────────────────────────────────────────────────────

def _write_eml(content: bytes) -> str:
    f = tempfile.NamedTemporaryFile(delete=False, suffix=".eml")
    f.write(content)
    f.close()
    return f.name


def _bh_of(body: bytes) -> str:
    """Compute the relaxed-canonicalized SHA-256 bh= value for a body."""
    canon = dkim_verifier.canonicalize_body_relaxed(body)
    return base64.b64encode(hashlib.sha256(canon).digest()).decode()


# ── parse_eml ─────────────────────────────────────────────────────────────────

class TestParseEml(unittest.TestCase):

    def _run(self, content: bytes):
        path = _write_eml(content)
        try:
            return dkim_verifier.parse_eml(path)
        finally:
            os.unlink(path)

    def test_crlf_separator(self):
        headers, body = self._run(b"From: a@b.com\r\n\r\nHello")
        self.assertEqual(headers, b"From: a@b.com\r\n")
        self.assertEqual(body, b"Hello")

    def test_lf_separator(self):
        headers, body = self._run(b"From: a@b.com\n\nHello")
        self.assertEqual(headers, b"From: a@b.com\n")
        self.assertEqual(body, b"Hello")

    def test_empty_body(self):
        headers, body = self._run(b"From: a@b.com\r\n\r\n")
        self.assertEqual(headers, b"From: a@b.com\r\n")
        self.assertEqual(body, b"")

    def test_no_separator_raises(self):
        path = _write_eml(b"From: a@b.com\r\nNo blank line")
        try:
            with self.assertRaises(ValueError):
                dkim_verifier.parse_eml(path)
        finally:
            os.unlink(path)

    def test_multiline_headers(self):
        raw = b"From: a@b.com\r\nSubject: Hi\r\n\r\nBody text"
        headers, body = self._run(raw)
        self.assertIn(b"From:", headers)
        self.assertIn(b"Subject:", headers)
        self.assertEqual(body, b"Body text")


# ── _split_headers ────────────────────────────────────────────────────────────

class TestSplitHeaders(unittest.TestCase):

    def test_simple_headers(self):
        block = b"From: a@b.com\r\nSubject: Test\r\n"
        result = dkim_verifier._split_headers(block)
        self.assertEqual(result, [b"From: a@b.com\r\n", b"Subject: Test\r\n"])

    def test_folded_header_tab(self):
        block = b"DKIM-Signature: v=1;\r\n\ts=sel1\r\nFrom: a@b.com\r\n"
        result = dkim_verifier._split_headers(block)
        self.assertEqual(result, [
            b"DKIM-Signature: v=1;\r\n\ts=sel1\r\n",
            b"From: a@b.com\r\n",
        ])

    def test_folded_header_space(self):
        block = b"Subject: Long\r\n Subject continued\r\n"
        result = dkim_verifier._split_headers(block)
        self.assertEqual(result, [b"Subject: Long\r\n Subject continued\r\n"])

    def test_empty_block(self):
        self.assertEqual(dkim_verifier._split_headers(b""), [])


# ── parse_dkim_signature ──────────────────────────────────────────────────────

_DKIM_BLOCK = (
    b"From: sender@example.com\r\n"
    b"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;"
    b" d=example.com; s=sel1; h=from:subject; bh=abc123==; b=sig456==\r\n"
    b"Subject: Hello\r\n"
)


class TestParseDkimSignature(unittest.TestCase):

    def test_parses_all_tags(self):
        tags = dkim_verifier.parse_dkim_signature(_DKIM_BLOCK)
        self.assertEqual(tags["v"], "1")
        self.assertEqual(tags["a"], "rsa-sha256")
        self.assertEqual(tags["c"], "relaxed/relaxed")
        self.assertEqual(tags["d"], "example.com")
        self.assertEqual(tags["s"], "sel1")
        self.assertEqual(tags["h"], "from:subject")
        self.assertEqual(tags["bh"], "abc123==")
        self.assertEqual(tags["b"], "sig456==")

    def test_missing_header_raises(self):
        block = b"From: a@b.com\r\nSubject: Test\r\n"
        with self.assertRaises(ValueError):
            dkim_verifier.parse_dkim_signature(block)

    def test_folded_dkim_signature(self):
        block = (
            b"DKIM-Signature: v=1; a=rsa-sha256;\r\n"
            b"\td=example.com; s=sel1;\r\n"
            b"\th=from; bh=xyz==; b=abc==\r\n"
        )
        tags = dkim_verifier.parse_dkim_signature(block)
        self.assertEqual(tags["d"], "example.com")
        self.assertEqual(tags["bh"], "xyz==")
        self.assertEqual(tags["b"], "abc==")

    def test_case_insensitive_header_match(self):
        block = b"dkim-signature: v=1; d=example.com; s=s1; bh=x==; b=y==\r\n"
        tags = dkim_verifier.parse_dkim_signature(block)
        self.assertEqual(tags["d"], "example.com")


# ── _canonicalize_header ──────────────────────────────────────────────────────

class TestCanonicalizeHeader(unittest.TestCase):

    def test_basic(self):
        result = dkim_verifier._canonicalize_header(b"From: sender@example.com\r\n")
        self.assertEqual(result, b"from:sender@example.com\r\n")

    def test_lowercases_name(self):
        result = dkim_verifier._canonicalize_header(b"SUBJECT: Hello World\r\n")
        self.assertEqual(result, b"subject:Hello World\r\n")

    def test_collapses_whitespace(self):
        result = dkim_verifier._canonicalize_header(b"X-Hdr:  too   many   spaces\r\n")
        self.assertEqual(result, b"x-hdr:too many spaces\r\n")

    def test_unfolds_tab_continuation(self):
        raw = b"Subject: Long\r\n\tSubject line\r\n"
        result = dkim_verifier._canonicalize_header(raw)
        self.assertEqual(result, b"subject:Long Subject line\r\n")

    def test_strips_surrounding_whitespace(self):
        result = dkim_verifier._canonicalize_header(b"X-Test:   value   \r\n")
        self.assertEqual(result, b"x-test:value\r\n")

    def test_always_ends_with_crlf(self):
        result = dkim_verifier._canonicalize_header(b"From: a@b.com\r\n")
        self.assertTrue(result.endswith(b"\r\n"))


# ── canonicalize_body_relaxed ─────────────────────────────────────────────────

class TestCanonicalizeBodyRelaxed(unittest.TestCase):

    def test_simple_body(self):
        self.assertEqual(
            dkim_verifier.canonicalize_body_relaxed(b"Hello World\r\n"),
            b"Hello World\r\n",
        )

    def test_empty_body_returns_single_crlf(self):
        self.assertEqual(dkim_verifier.canonicalize_body_relaxed(b""), b"\r\n")

    def test_collapses_whitespace(self):
        self.assertEqual(
            dkim_verifier.canonicalize_body_relaxed(b"Hello  World\r\n"),
            b"Hello World\r\n",
        )

    def test_strips_trailing_line_whitespace(self):
        self.assertEqual(
            dkim_verifier.canonicalize_body_relaxed(b"Hello   \r\nWorld\r\n"),
            b"Hello\r\nWorld\r\n",
        )

    def test_removes_trailing_blank_lines(self):
        self.assertEqual(
            dkim_verifier.canonicalize_body_relaxed(b"Hello\r\n\r\n\r\n"),
            b"Hello\r\n",
        )

    def test_normalizes_lf_to_crlf(self):
        self.assertEqual(
            dkim_verifier.canonicalize_body_relaxed(b"Hello\nWorld\n"),
            b"Hello\r\nWorld\r\n",
        )

    def test_body_without_trailing_newline(self):
        self.assertEqual(
            dkim_verifier.canonicalize_body_relaxed(b"Hello"),
            b"Hello\r\n",
        )

    def test_collapses_tabs(self):
        self.assertEqual(
            dkim_verifier.canonicalize_body_relaxed(b"A\t\tB\r\n"),
            b"A B\r\n",
        )


# ── verify_body_hash ──────────────────────────────────────────────────────────

class TestVerifyBodyHash(unittest.TestCase):

    def test_matching_hash(self):
        body = b"Hello World\r\n"
        bh = _bh_of(body)
        match, computed = dkim_verifier.verify_body_hash(body, bh, "rsa-sha256")
        self.assertTrue(match)
        self.assertEqual(computed, bh)

    def test_non_matching_hash(self):
        body = b"Hello World\r\n"
        match, _ = dkim_verifier.verify_body_hash(body, "wronghash==", "rsa-sha256")
        self.assertFalse(match)

    def test_sha1_algorithm(self):
        body = b"Hello\r\n"
        canon = dkim_verifier.canonicalize_body_relaxed(body)
        expected = base64.b64encode(hashlib.sha1(canon).digest()).decode()
        match, computed = dkim_verifier.verify_body_hash(body, expected, "rsa-sha1")
        self.assertTrue(match)
        self.assertEqual(computed, expected)

    def test_tampered_body_detected(self):
        body = b"Hello World\r\n"
        bh = _bh_of(body)
        match, _ = dkim_verifier.verify_body_hash(b"Hello Tampered\r\n", bh, "rsa-sha256")
        self.assertFalse(match)

    def test_returns_computed_hash_on_mismatch(self):
        body = b"Some body\r\n"
        _, computed = dkim_verifier.verify_body_hash(body, "wrong==", "rsa-sha256")
        self.assertEqual(computed, _bh_of(body))


# ── verify_signature ──────────────────────────────────────────────────────────

@unittest.skipUnless(dkim_verifier.HAS_CRYPTOGRAPHY, "cryptography package not installed")
class TestVerifySignature(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from cryptography.hazmat.primitives.asymmetric import rsa, padding as apad
        from cryptography.hazmat.primitives import hashes as ahashes, serialization
        cls._priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls._pubkey_der = cls._priv.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def _sign(self, data: bytes) -> str:
        from cryptography.hazmat.primitives.asymmetric import padding as apad
        from cryptography.hazmat.primitives import hashes as ahashes
        sig = self._priv.sign(data, apad.PKCS1v15(), ahashes.SHA256())
        return base64.b64encode(sig).decode()

    def test_valid_signature_returns_true(self):
        data = b"canonical header data"
        b_val = self._sign(data)
        self.assertTrue(dkim_verifier.verify_signature(data, b_val, self._pubkey_der, "rsa-sha256"))

    def test_invalid_b_value_raises(self):
        data = b"canonical header data"
        bad_b = base64.b64encode(b"X" * 256).decode()
        with self.assertRaises(Exception):
            dkim_verifier.verify_signature(data, bad_b, self._pubkey_der, "rsa-sha256")

    def test_tampered_data_raises(self):
        data = b"canonical header data"
        b_val = self._sign(data)
        with self.assertRaises(Exception):
            dkim_verifier.verify_signature(b"different data entirely", b_val, self._pubkey_der, "rsa-sha256")

    def test_whitespace_stripped_from_b_value(self):
        data = b"test"
        b_val = self._sign(data)
        spaced = b_val[:10] + "  \n  " + b_val[10:]
        self.assertTrue(dkim_verifier.verify_signature(data, spaced, self._pubkey_der, "rsa-sha256"))


# ── verify_email (integration) ────────────────────────────────────────────────

@unittest.skipUnless(dkim_verifier.HAS_CRYPTOGRAPHY, "cryptography package not installed")
class TestVerifyEmail(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from cryptography.hazmat.primitives.asymmetric import rsa, padding as apad
        from cryptography.hazmat.primitives import hashes as ahashes, serialization
        cls._priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls._pubkey_der = cls._priv.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def _build_eml(self, body: bytes, *, real_sig: bool = True) -> bytes:
        """Construct a minimal .eml with correct bh= and optionally a valid b=."""
        from cryptography.hazmat.primitives.asymmetric import padding as apad
        from cryptography.hazmat.primitives import hashes as ahashes

        bh = _bh_of(body)
        base_headers = (
            b"From: sender@example.com\r\n"
            b"Subject: Test Email\r\n"
        )
        dkim_prefix = (
            f"v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=sel1;"
            f" h=from:subject; bh={bh}; b="
        )

        if real_sig:
            # Sign using the header block with an empty b= (as the spec requires)
            dkim_nosig = f"DKIM-Signature: {dkim_prefix}\r\n".encode()
            header_block = base_headers + dkim_nosig
            canon = dkim_verifier.canonicalize_headers_relaxed(
                header_block, ["from", "subject"], dkim_nosig
            )
            sig = self._priv.sign(canon, apad.PKCS1v15(), ahashes.SHA256())
            b_val = base64.b64encode(sig).decode()
        else:
            b_val = "invalidsignature=="

        dkim_line = f"DKIM-Signature: {dkim_prefix}{b_val}\r\n".encode()
        return base_headers + dkim_line + b"\r\n" + body

    def test_bh_and_b_both_pass(self):
        eml = self._build_eml(b"Hello World\r\n", real_sig=True)
        path = _write_eml(eml)
        try:
            with patch("dkim_verifier.fetch_public_key", return_value=self._pubkey_der):
                result = dkim_verifier.verify_email(path)
        finally:
            os.unlink(path)

        self.assertEqual(result["domain"], "example.com")
        self.assertEqual(result["selector"], "sel1")
        self.assertEqual(result["algorithm"], "rsa-sha256")
        self.assertTrue(result["bh_pass"])
        self.assertTrue(result["b_pass"])
        self.assertIsNone(result["b_error"])

    def test_wrong_bh_fails(self):
        body = b"Hello World\r\n"
        wrong_bh = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        dkim_line = (
            f"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com;"
            f" s=sel1; h=from:subject; bh={wrong_bh}; b=sig==\r\n"
        ).encode()
        raw = b"From: sender@example.com\r\nSubject: Hi\r\n" + dkim_line + b"\r\n" + body
        path = _write_eml(raw)
        try:
            with patch("dkim_verifier.fetch_public_key", return_value=self._pubkey_der):
                result = dkim_verifier.verify_email(path)
        finally:
            os.unlink(path)

        self.assertFalse(result["bh_pass"])

    def test_dns_failure_sets_b_fail(self):
        eml = self._build_eml(b"Hello\r\n", real_sig=False)
        path = _write_eml(eml)
        try:
            with patch("dkim_verifier.fetch_public_key", side_effect=RuntimeError("DNS timeout")):
                result = dkim_verifier.verify_email(path)
        finally:
            os.unlink(path)

        self.assertFalse(result["b_pass"])
        self.assertIn("DNS timeout", result["b_error"])

    def test_missing_dkim_signature_raises(self):
        raw = b"From: a@b.com\r\nSubject: Test\r\n\r\nBody"
        path = _write_eml(raw)
        try:
            with self.assertRaises(ValueError):
                dkim_verifier.verify_email(path)
        finally:
            os.unlink(path)

    def test_result_contains_from_field(self):
        eml = self._build_eml(b"Hi\r\n", real_sig=False)
        path = _write_eml(eml)
        try:
            with patch("dkim_verifier.fetch_public_key", return_value=self._pubkey_der):
                result = dkim_verifier.verify_email(path)
        finally:
            os.unlink(path)

        self.assertIn("sender@example.com", result["from"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
