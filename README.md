Since Ralphie decoded "Drink your Ovaltine" and Cap'n Crunch put decoder rings in his cereal, I have had a fascination with codes. I was intrigued to learn that a body hash was hiding right there in an email — and so were the decoding instructions: the algorithm (`rsa-sha256`), the canonicalization method (`relaxed/relaxed`), and the exact header fields used to compute it. Like finding the decoder ring and the secret message in the same cereal box. I searched high and low and couldn't really find good instructions on how to verify it yourself — until I met my friend Claude...

So we built a decoder ring — one that speaks RFC 6376.

---

# DKIM Body Hash (bh=) Integrity Verifier

A Python tool for fully verifying **DKIM (DomainKeys Identified Mail)** signatures on raw `.eml` files, implementing [RFC 6376](https://www.rfc-editor.org/rfc/rfc6376). Drop in any email, and it verifies both the body hash (`bh=`) and the RSA header signature (`b=`) via live DNS key lookup — no manual header extraction required.

[![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey?logo=linux&logoColor=white)](https://www.linux.org/)
[![RFC 6376](https://img.shields.io/badge/Standard-RFC%206376-blue)](https://www.rfc-editor.org/rfc/rfc6376)

<img width="1408" height="768" alt="work-dkim-hover" src="https://github.com/user-attachments/assets/bf3c9490-107d-46e0-a293-643a7c74790e" />

---

## Table of Contents

- [The Secret Code](#the-secret-code)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [How to Use](#how-to-use)
- [Step-by-Step Decode Walkthrough](#step-by-step-decode-walkthrough)
- [Privacy & Safety](#privacy--safety)
- [Workflow & Implementation](#workflow--implementation)
- [License](#license)

---

## The Secret Code

Every email you receive carries a hidden signature. The sending mail server signs it before delivery, and any recipient — or anyone curious enough to look — can verify it. That standard is DKIM.

**The body hash (`bh=`)** is the first layer. The message body is run through a specific recipe called *relaxed canonicalization*: collapse whitespace, strip trailing spaces from each line, normalize line endings, trim trailing blank lines, add one final line break. Hash the result with SHA-256, base64-encode it, and you get a fingerprint of the message body. That fingerprint is stamped right in the `DKIM-Signature` header — so the instructions *and* the answer are both sitting in the same envelope. This is the "Drink your Ovaltine" moment: follow the recipe yourself and see if your answer matches.

**Why CRLF is the hidden trap.** Email requires `\r\n` line endings, but most tools silently convert them to `\n` when saving files. Get this wrong and the hash never matches no matter how correct your math is — the spec gives you no error message, just a silent FAIL. Once you know to look for it, it's one of those "aha" moments that makes the whole puzzle click.

**The full signature (`b=`)** goes further. Beyond the body, a set of key headers (`From`, `Subject`, `Date`, etc.) are also signed with RSA. The public key lives in a DNS TXT record at `selector._domainkey.domain` — publicly available to anyone, like the decoder ring instructions printed on the side of the cereal box. Fetch the key, verify the signature, and you can prove the email genuinely came from the domain it claims.

---

## Project Structure

| File | Purpose |
|---|---|
| `dkim_verifier.py` | Core library + CLI. All verification logic lives here. |
| `gui.py` | tkinter GUI — file picker, themed results display, light/dark toggle. |
| `requirements.txt` | `dnspython`, `cryptography` |
| `verify_bh.py` | Original body-hash-only script — kept as a reference artifact showing the manual approach. |
| `Test Email.eml` | Test email used during development (Outlook → Gmail, DKIM from `selector1._domainkey.outlook.com`). |
| `DKIM Signature.txt` | Extracted DKIM-Signature header for reference. |

---

## Prerequisites

```bash
Python 3.x

pip3 install dnspython cryptography

# tkinter (GUI only)
sudo dnf install python3-tkinter   # Fedora / RHEL
sudo apt install python3-tk        # Debian / Ubuntu
```

---

## How to Use

### GUI (recommended)

```bash
python3 gui.py
```

Click **Load .eml File** and select any exported email. The body hash result appears immediately (no network needed). The full RSA signature check follows after a DNS lookup — usually a second or two.

Toggle the **DARK** switch in the top-right corner for the cyber theme.

### CLI

```bash
python3 dkim_verifier.py "my_email.eml"
```

### Getting a .eml file

This tool works with any email that carries a `DKIM-Signature` header — Gmail, Outlook, Yahoo, SendGrid, Mailchimp, and most other modern mail providers sign their outgoing mail.

| Client | How to export |
|---|---|
| Gmail | ⋮ menu → **Download message** |
| Outlook (web) | ⋮ menu → **Save as** |
| Thunderbird | Right-click the email → **Save As** |
| Apple Mail | **File** → **Save As** → `.eml` |

For a comprehensive guide covering dozens of clients — including Outlook 2003–2016, ProtonMail, Zoho, Exchange Online, and more — see the **[MXToolbox Email Headers Guide](https://mxtoolbox.com/public/content/emailheaders/)** *(credit: MXToolbox)*.

> **Note:** The MXToolbox guide is focused on viewing and copying headers into their online analyzer. For this tool you need the full `.eml` export (headers *and* body) — the body is required to verify the hash.

---

## Step-by-Step Decode Walkthrough

Here is how the tool cracks `Test Email.eml`, decoder-ring style.

**1. Find the ring**

Open the email and locate the `DKIM-Signature:` header. Everything you need is printed right there:

```
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=outlook.com;
  s=selector1;
  h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:...;
  bh=2Xz66rWfrVgWAeWuVgoYF3IZCwn50UywwNAlxj/m+Gc=;
  b=f27A6Pa2...
```

The algorithm (`a=`), the canonicalization recipe (`c=`), the signed headers (`h=`), the expected body hash (`bh=`), and where to fetch the public key (`d=` + `s=`) — all in plain sight.

**2. Follow the recipe**

Apply relaxed canonicalization to the message body:
- Collapse sequences of spaces/tabs to a single space
- Strip trailing whitespace from each line
- Normalize all line endings to `\r\n`
- Strip trailing empty lines from the body
- Add exactly one trailing `\r\n`

**3. Hash it**

SHA-256 the canonicalized body and base64-encode the result. If it matches `bh=`, the message body arrived exactly as the sender wrote it.

**4. Fetch the codebook**

DNS TXT lookup at `selector1._domainkey.outlook.com` returns the RSA public key — the `p=` field. It's public information, available to anyone on the internet.

**5. Verify the signature**

Canonicalize the headers listed in `h=`, append the DKIM-Signature header itself (with `b=` emptied), then verify the `b=` value against the public key using RSA-PKCS1v15 + SHA-256.

**Result on `Test Email.eml`:**

```
Body Hash (bh=):  PASS
  Expected: 2Xz66rWfrVgWAeWuVgoYF3IZCwn50UywwNAlxj/m+Gc=
  Computed: 2Xz66rWfrVgWAeWuVgoYF3IZCwn50UywwNAlxj/m+Gc=

Signature  (b=):  PASS
  Key fetched from selector1._domainkey.outlook.com
```

---

## Privacy & Safety

- The `.eml` file is read locally and never transmitted anywhere.
- The only network call is a DNS TXT lookup to fetch the signing domain's public key — the exact same lookup every receiving mail server performs automatically when the email is delivered.
- The query reveals only the signing domain and selector, both of which are already public in the `DKIM-Signature` header.

---

## Workflow & Implementation

### Parsing

`dkim_verifier.py` reads the `.eml` file as binary, locates the first blank line to split headers from body (handling both `\r\n` and `\n` line endings), then walks the header block to find and unfold the `DKIM-Signature` header. No manual `grep` or `tail` required.

The original `verify_bh.py` documents the manual approach for reference — useful if you want to understand what the tool is doing under the hood before the automation was added.

### Relaxed Canonicalization (body)

Per RFC 6376 §3.4.3:
1. Collapse all sequences of whitespace to a single space
2. Strip trailing whitespace from each line
3. Strip trailing empty lines from the body
4. Add exactly one trailing `\r\n`
5. SHA-256 → base64 → compare to `bh=`

### Relaxed Canonicalization (headers)

Per RFC 6376 §3.4.2, for each header named in `h=`:
1. Lowercase the header name
2. Unfold continuation lines (CRLF+WSP → single space)
3. Collapse whitespace sequences
4. Strip whitespace around the colon and at the end of the value
5. Emit `lowercasename:value\r\n`

The DKIM-Signature header is appended last with the `b=` value emptied, and no trailing CRLF.

### Signature Verification

The RSA public key is fetched from DNS (`selector._domainkey.domain` TXT record, `p=` field), loaded with the `cryptography` library, and used to verify the `b=` value with RSA-PKCS1v15 + SHA-256.

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
