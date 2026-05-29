# DKIM Verifier — Project Guide

## What This Is

A tool for fully verifying **DKIM (DomainKeys Identified Mail)** signatures on raw `.eml` files, implementing RFC 6376. Verifies both the body hash (`bh=`) and the RSA header signature (`b=`) via live DNS key lookup. Ships with a tkinter GUI with light and dark (cyber) themes.

## Files

| File | Purpose |
|---|---|
| `dkim_verifier.py` | Core library + CLI. All verification logic lives here. |
| `gui.py` | tkinter GUI — file picker, themed results display, light/dark toggle. |
| `requirements.txt` | `dnspython`, `cryptography` |
| `verify_bh.py` | Original single-file body-hash script — kept as reference. |
| `Test Email.eml` | Test email (Outlook → Gmail, DKIM from `selector1._domainkey.outlook.com`). |
| `raw_body.bin` | Pre-extracted body used by the legacy `verify_bh.py`. |
| `DKIM Signature.txt` | Extracted DKIM-Signature header from a separate Gmail test email. |
| `DKIM_Analysis.odt`, `testing.odt` | Working notes and analysis documents. |

## How to Run

```bash
pip3 install dnspython cryptography   # first time only

# GUI
python3 gui.py

# CLI
python3 dkim_verifier.py "Test Email.eml"
```

**Getting a valid .eml file from Gmail:** open the email → three-dot menu (⋮) → "Download message".

## Architecture

### `dkim_verifier.py` — functions in call order

| Function | Role |
|---|---|
| `parse_eml(path)` | Splits `.eml` into `(header_block, body)` at the first blank line. Handles CRLF and LF. |
| `_split_headers(block)` | Splits folded header block into individual raw header bytes. |
| `parse_dkim_signature(block)` | Finds the first `DKIM-Signature:` header, unfolds it, returns tag→value dict. |
| `_get_dkim_sig_raw(block)` | Returns the raw bytes of the DKIM-Signature header for use in `canonicalize_headers_relaxed`. |
| `_canonicalize_header(raw)` | RFC 6376 relaxed canonicalization of a single header: lowercase name, unfold, collapse WSP, strip, emit `name:value\r\n`. |
| `canonicalize_body_relaxed(body)` | RFC 6376 §3.4.3: collapse WSP, strip trailing WSP per line, strip trailing empty lines, add one trailing CRLF. |
| `canonicalize_headers_relaxed(block, names, dkim_raw)` | Builds canonical header blob for signature verification. Processes headers in `h=` order (consuming from end per spec), then appends DKIM-Signature with `b=` emptied and no trailing CRLF. |
| `verify_body_hash(body, expected, algo)` | Canonicalizes body, SHA-256 hashes, base64 encodes, compares. Returns `(bool, computed_str)`. |
| `fetch_public_key(domain, selector)` | DNS TXT lookup at `{selector}._domainkey.{domain}`, extracts `p=` field, base64-decodes to DER. |
| `verify_signature(canon, b_value, pubkey_der, algo)` | RSA-PKCS1v15 verify using `cryptography`. Raises `InvalidSignature` on failure. |
| `verify_email(path)` | Orchestrator. Returns result dict with all fields the GUI needs. |

### `gui.py` — structure

- **`PillSwitch`** — `tk.Canvas` subclass that draws a pill-shaped toggle, used for the light/dark mode switch.
- **`DKIMVerifierApp`** — main `tk.Tk` subclass. Widgets are bucketed into themed lists (`_bg_only`, `_fg_lbl`, `_dim_lbl`, `_btn_lst`, `_sep_lst`, `_lf_lst`, `_mono_lbl`) so `_apply_theme()` can restyle everything in one pass without rebuilding the UI.
- Verification runs in a background thread; result is dispatched back to the main thread via `self.after(0, ...)`.

### Themes

Two palette dicts at the top of `gui.py`:

| Key | Light | Dark |
|---|---|---|
| `bg` | `#f2f2f2` | `#0a0a0a` |
| `fg` | `#1a1a1a` | `#00ff41` |
| `font` | TkDefaultFont 12 bold | Courier New 14 bold |
| `font_mono` | TkFixedFont 11 | Courier New 13 bold |

## RFC 6376 Implementation Notes

**Relaxed body canonicalization:**
1. Collapse WSP sequences to single space
2. Strip trailing WSP from each line
3. Strip trailing empty lines
4. Add one trailing CRLF
5. SHA-256 → base64 → compare to `bh=`

**Relaxed header canonicalization:**
1. Lowercase header name
2. Unfold continuation lines (CRLF+WSP → space)
3. Collapse WSP sequences to single space
4. Strip WSP around the colon and at end of value
5. Emit `lowercasename:value\r\n`
6. Append DKIM-Signature last with `b=` emptied, no trailing CRLF

**Signature verification:** RSA-PKCS1v15 + SHA-256 over the canonical header blob, using the public key from `{selector}._domainkey.{domain}` DNS TXT `p=` field.

## Dependencies

```
dnspython      # DNS TXT lookup for public key
cryptography   # RSA-PKCS1v15 signature verification
tkinter        # GUI (system package: sudo dnf install python3-tkinter)
```
