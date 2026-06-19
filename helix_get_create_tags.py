#!/usr/bin/env python3
"""
Trellix Helix API - Tags Management
Handles fetching and creating system/custom tags.
"""

import requests
import base64
import json

# ==========================================
# Configuration & Credentials
# ==========================================
CLIENT_ID = "YOUR_CLIENT_ID"
CLIENT_SECRET = "YOUR_CLIENT_SECRET"
API_KEY = "YOUR_API_KEY"

TOKEN_URL = "https://iam.cloud.trellix.com/iam/v1.0/token"
API_BASE_URL = "https://api.manage.trellix.com"

# Tags strictly require the xdr.rul.r (Read) and xdr.rul.rw (Write) scopes
XDR_SCOPES = ["xdr.rul.r xdr.rul.rw"]


def get_access_token(client_id, client_secret, scopes):
    auth_string = f"{client_id}:{client_secret}"
    b64_auth = base64.b64encode(auth_string.encode('utf-8')).decode('utf-8')

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": f"Basic {b64_auth}"
    }

    payload = {
        "grant_type": "client_credentials",
        "scope": " ".join(scopes)
    }

    print("[*] Authenticating with Trellix IAM...")
    response = requests.post(TOKEN_URL, headers=headers, data=payload)
    response.raise_for_status()
    print("[+] Successfully obtained access token.")
    return response.json().get("access_token")


def create_tag(token, api_key, name="testtag", description="just a tag test", color="#00CD00"):
    detail_url = f"{API_BASE_URL}/xdr/v2/tags"
    headers = {
        "Authorization": f"Bearer {token}",
        "x-api-key": api_key,
        "Content-Type": "application/vnd.api+json",
        "Accept": "application/vnd.api+json"
    }

    payload = {
        "data": {
            "type": "tags",
            "attributes": {
                "name": name,
                "description": description,
                "color": color
            }
        }
    }

    print(f"[*] Creating Tag: {name}...")
    response = requests.post(detail_url, headers=headers, data=json.dumps(payload))
    if response.status_code in (200, 201):
        print("  [+] Tag created successfully.")
        return response.json()
    
    print(f"  [-] Failed to create tag: {response.text}")
    return None


def get_tags(token, api_key):
    detail_url = f"{API_BASE_URL}/xdr/v2/tags"
    headers = {
        "Authorization": f"Bearer {token}",
        "x-api-key": api_key,
        "Content-Type": "application/vnd.api+json",
        "Accept": "application/vnd.api+json"
    }

    print("[*] Fetching Tags...")
    response = requests.get(detail_url, headers=headers)
    if response.status_code == 200:
        return response.json()
    
    print(f"  [-] Failed to fetch tags: {response.text}")
    return None


def main():
    if "YOUR_" in CLIENT_ID or "YOUR_" in API_KEY:
        print("[-] Please update your credentials before running.")
        return

    try:
        token = get_access_token(CLIENT_ID, CLIENT_SECRET, XDR_SCOPES)

        # Uncomment to test tag creation
        # create_tag(token, API_KEY)

        print("\n--- Fetching Tags ---")
        tags_response = get_tags(token, API_KEY)

        if not tags_response or 'data' not in tags_response:
            print("\nNo tags found.")
        else:
            tags_list = tags_response['data']
            print(f"\nFound {len(tags_list)} tags:")
            
            tag_names = [tag['attributes']['name'] for tag in tags_list]
            for name in tag_names:
                print(f"- {name}")

    except requests.exceptions.RequestException as e:
        print(f"\n[-] API error occurred: {e}")

if __name__ == "__main__":
    main()
