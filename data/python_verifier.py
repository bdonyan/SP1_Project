# test: correct verifier

import dkim
import email
from email import policy
from email.parser import BytesParser

def verify_dkim_signature(email_content):
    # Parse the email content
    msg = BytesParser(policy=policy.default).parsebytes(email_content)

    # Extract the headers
    headers = [(k.encode('utf-8'), v.encode('utf-8')) for k, v in msg.items()]

    # Extract the body for verification
    if msg.is_multipart():
        body = ''
        for part in msg.iter_parts():
            if part.get_content_type() == 'text/plain':
                body = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8')
                break
    else:
        body = msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8')

    # Perform DKIM verification
    try:
        result = dkim.verify(email_content)
        return result
    except Exception as e:
        print(f"Verification error: {e}")
        return False

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
