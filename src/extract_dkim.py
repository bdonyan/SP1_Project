import os
import json
import quopri
from email import message_from_string

def decode_quoted_printable(text):
    return quopri.decodestring(text).decode('utf-8', errors='ignore')

def extract_dkim_info(raw_email):
    msg = message_from_string(raw_email)
    
    dkim_header = msg['DKIM-Signature']
    if dkim_header:
        parts = dkim_header.split(';')
        dkim_selector = next((part.split('=')[1].strip() for part in parts if part.strip().startswith('s=')), None)
        dkim_domain = next((part.split('=')[1].strip() for part in parts if part.strip().startswith('d=')), None)
    else:
        raise ValueError("No DKIM-Signature header found in the email")

    decoded_body = ""
    if msg.is_multipart():
        for part in msg.get_payload():
            if part.get_content_type() == "text/plain":
                decoded_body = decode_quoted_printable(part.get_payload())
                break
    else:
        decoded_body = decode_quoted_printable(msg.get_payload())
    
    return {
        "original_email": raw_email,
        "selector": dkim_selector,
        "domain": dkim_domain,
        "dkim_signature": dkim_header,
        "decoded_body": decoded_body
    }

def main():
    email_file_path = os.path.join(os.path.dirname(__file__), '../data/email.eml')
    output_json_path = os.path.join(os.path.dirname(__file__), '../data/dkim_data.json')

    with open(email_file_path, 'r', encoding='utf-8') as file:
        raw_email = file.read()

    dkim_info = extract_dkim_info(raw_email)

    with open(output_json_path, 'w', encoding='utf-8') as json_file:
        json.dump(dkim_info, json_file, indent=4)

    print(dkim_info)

if __name__ == "__main__":
    main()
