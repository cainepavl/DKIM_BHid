# DKIM Body Hash (bh) Integrity Verifier

A technical implementation for manually verifying the **Body Hash (bh)** of an email using the **DKIM (DomainKeys Identified Mail)** standard (RFC 6376). This project demonstrates the process of isolating an email body and applying the "Relaxed" canonicalization algorithm to match cryptographic signatures.

## Project Structure
* `Test Email.eml`: The raw email source file including headers and multipart body.
* `raw_body.bin`: The isolated message body (extracted using `tail`).
* `verify_bh.py`: Python implementation of the Relaxed Canonicalization and SHA-256 hashing.

## Prerequisites
* **Python 3.x**: Uses `hashlib`, `base64`, and `re` modules.
* **Linux Environment**: Utilizes `grep`, `tail`, and `head` for initial data triage.
* **File Encoding**: The source email must maintain **CRLF** line terminators to pass DKIM validation.

## Workflow & Implementation

### 1. Data Triage
Identified the header-body split using regex to find the first empty line (including hidden carriage returns):
\`\`\`bash
grep -nP "^(?:\r)?$" "Test Email.eml" | head -n 1
\`\`\`

### 2. Extraction
Extracted the body from the identified line number (e.g., line 148) to a binary file:
\`\`\`bash
tail -n +148 "Test Email.eml" > raw_body.bin
\`\`\`

### 3. "Relaxed" Canonicalization Logic
The Python script handles the following RFC 6376 requirements:
* **WSP Reduction:** All sequences of internal spaces/tabs are collapsed to a single space character.
* **Trailing WSP:** Whitespace at the end of lines is stripped.
* **Empty Line Stripping:** All trailing empty lines at the end of the entire body are removed.
* **Standardization:** All lines are joined using \r\n (CRLF).

## How to Adapt for New Emails
1. Open the .eml file and locate the DKIM-Signature header.
2. Copy the bh= value (the expected body hash).
3. Paste the hash into the expected_bh variable in verify_bh.py.
4. Run the script: python3 verify_bh.py.
