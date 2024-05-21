# test/main.py
from src.extract_dkim import extract_dkim_signature

def main():
    email_file_path = 'data/email.eml'
    
    # Read the email content
    with open(email_file_path, 'rb') as email_file:
        email_content = email_file.read()
    
    # Extract DKIM signature
    try:
        dkim_signature = extract_dkim_signature(email_content)
        print("DKIM-Signature:", dkim_signature)
    except ValueError as e:
        print(e)

if __name__ == "__main__":
    main()