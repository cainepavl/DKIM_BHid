import hashlib
import base64
import re

def verify_dkim_body():
    file_path = "raw_body.bin"
    expected_bh = "2Xz66rWfrVgWAeWuVgoYF3IZCwn50UywwNAlxj/m+Gc="

    try:
        with open(file_path, "rb") as f:
            body = f.read()

        # 1. Relaxed Canonicalization: Reduce sequences of WSP to a single space
        body = re.sub(b"[ \t]+", b" ", body)

        # 2. Relaxed Canonicalization: Ignore WSP at the end of lines
        lines = body.splitlines()
        relaxed_lines = [line.rstrip(b" \t") for line in lines]
        
        # 3. Standardize line endings to CRLF
        result = b"\r\n".join(relaxed_lines)

        # 4. Remove all empty lines at the end of the body
        result = result.rstrip(b"\r\n")

        # 5. Add the single required trailing CRLF
        final_body = result + b"\r\n" if result else b"\r\n"

        # 6. Hash using SHA-256
        h = hashlib.sha256(final_body).digest()
        calculated_bh = base64.b64encode(h).decode()

        print(f"Calculated: {calculated_bh}")
        print(f"Expected:   {expected_bh}")

        if calculated_bh == expected_bh:
            print("\n[SUCCESS] Body hash matches.")
        else:
            print("\n[FAILED] Body hash does not match.")

    except FileNotFoundError:
        print(f"Error: {file_path} not found. Run the 'tail' command first.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    verify_dkim_body()
