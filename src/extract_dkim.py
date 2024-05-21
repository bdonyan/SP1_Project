import json
import email
from email import policy
from email.parser import BytesParser
import sys

def extract_dkim_signature(email_content):
    msg = BytesParser(policy=policy.default).parsebytes(email_content)
    dkim_signature = msg['DKIM-Signature']
    if dkim_signature:
        return dkim_signature, msg
    else:
        raise ValueError("No DKIM-Signature found in the email headers.")

def email_message_to_dict(msg):
    msg_dict = {}
    for header, value in msg.items():
        msg_dict[header] = value
    return msg_dict

def extract_body(msg):
    if msg.is_multipart():
        for part in msg.iter_parts():
            if part.get_content_type() == 'text/plain':
                charset = part.get_content_charset() or 'utf-8'
                return part.get_payload(decode=True).decode(charset)
    else:
        charset = msg.get_content_charset() or 'utf-8'
        return msg.get_payload(decode=True).decode(charset)

def main():
    # Read the email content from a file or standard input
    email_content = sys.stdin.read().encode('utf-8')

    dkim_signature, msg = extract_dkim_signature(email_content)
    signed_headers = email_message_to_dict(msg)
    body = extract_body(msg)

    data = {
        "dkim_signature": dkim_signature,
        "signed_headers": signed_headers,
        "body": body,
        "original_email": email_content.decode('utf-8')
    }

    with open("dkim_data.json", "w", encoding='utf-8') as outfile:
        json.dump(data, outfile, indent=4, ensure_ascii=False)

if __name__ == "__main__":
    main()
