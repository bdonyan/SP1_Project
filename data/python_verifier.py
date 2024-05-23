import dkim
import email
from email import policy
from email.parser import BytesParser
import hashlib
import base64

def verify_dkim_signature(email_content):
    # Parse the email content
    msg = BytesParser(policy=policy.default).parsebytes(email_content)

    # Extract the body for verification
    if msg.is_multipart():
        body = ''
        for part in msg.iter_parts():
            if part.get_content_type() == 'text/plain':
                body = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8')
                break
    else:
        body = msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8')

    # Compute the body hash
    body_hash = base64.b64encode(hashlib.sha256(body.encode('utf-8')).digest()).decode()

    # Perform DKIM verification
    try:
        is_valid = dkim.verify(email_content)
        result = is_valid
    except Exception as e:
        print(f"Verification error: {e}")
        result = False

    # Output the required details
    print(f"Body Hash (Python): {body_hash}")
    print(f"Signature (Python): {msg['DKIM-Signature']}")
    print(f"Public Key (Python): Fetching public key is not included in this example")

    return result

def main():
    # Read the email content from the .eml file
    with open("email.eml", "rb") as f:
        email_content = f.read()

    # Verify DKIM signature
    is_valid = verify_dkim_signature(email_content)
    if is_valid:
        print("DKIM signature is valid.")
    else:
        print("DKIM signature is invalid.")

if __name__ == "__main__":
    main()
