import os
import json
import base64
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Scope remains the same for reading emails
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

def get_header(headers, name):
    """Helper to extract header values like Subject or From."""
    for header in headers:
        if header['name'].lower() == name.lower():
            return header['value']
    return "(Unknown)"

def main():
    """Fetches unread emails with label 'Newsletter' using Env Var Auth."""
    creds = None
    
    # --- AUTHENTICATION BLOCK (Same as before) ---
    token_env = os.environ.get("GMAIL_TOKEN")
    if token_env:
        try:
            info = json.loads(token_env)
            creds = Credentials.from_authorized_user_info(info, SCOPES)
        except json.JSONDecodeError:
            print("Error: GMAIL_TOKEN environment variable contains invalid JSON.")
    
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except Exception:
                creds = None
        if not creds:
            flow = InstalledAppFlow.from_client_secrets_file("..\gmail_API_Access_credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
            
            # Print new token for user to save
            print("\n" + "="*60)
            print("NEW TOKEN (Save to GMAIL_TOKEN env var):")
            print(creds.to_json())
            print("="*60 + "\n")
    # ---------------------------------------------

    try:
        service = build("gmail", "v1", credentials=creds)

        # 1. SEARCH: Find messages with specific filters
        # q parameters: "label:Newsletter" and "is:unread"
        query_string = 'label:Newsletter is:unread'
        
        print(f"Searching for emails matching: '{query_string}'...")
        
        # list() returns a list of message IDs, not the content yet
        results = service.users().messages().list(userId="me", q=query_string).execute()
        messages = results.get("messages", [])

        if not messages:
            print("No unread 'Newsletter' emails found.")
            return

        print(f"Found {len(messages)} unread email(s). Fetching details...\n")

        # 2. FETCH: Loop through IDs to get actual content
        for msg in messages:
            # Get full message details (format='full' is default)
            msg_detail = service.users().messages().get(userId="me", id=msg['id']).execute()
            
            payload = msg_detail.get('payload', {})
            headers = payload.get('headers', [])
            
            # Extract basic info
            subject = get_header(headers, 'Subject')
            sender = get_header(headers, 'From')
            snippet = msg_detail.get('snippet', '')

            # Print neatly
            print("-" * 50)
            print(f"FROM:    {sender}")
            print(f"SUBJECT: {subject}")
            print(f"SNIPPET: {snippet}")
            # Note: Full body decoding is complex due to HTML/Multipart structure. 
            # Snippet is usually sufficient for terminal viewing.
            
    except HttpError as error:
        print(f"An error occurred: {error}")

if __name__ == "__main__":
    main()