#!/usr/bin/env python3
"""
Trellix Helix API - Cases Management
Fetches investigation cases from the platform.
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

# Cases utilize the Alert scope mapping (xdr.alr.r). For new/edit cases (xdr.alr.rw).
XDR_SCOPES = ["xdr.alr.r"]


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


def get_cases(token, api_key):
    detail_url = f"{API_BASE_URL}/xdr/v2/cases"
    headers = {
        "Authorization": f"Bearer {token}",
        "x-api-key": api_key,
        "Content-Type": "application/vnd.api+json",
        "Accept": "application/vnd.api+json"
    }

    print("[*] Fetching Cases...")
    response = requests.get(detail_url, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    
    print(f"  [-] Failed to fetch cases: {response.text}")
    return None


def main():
    if "YOUR_" in CLIENT_ID or "YOUR_" in API_KEY:
        print("[-] Please update your credentials before running.")
        return

    try:
        token = get_access_token(CLIENT_ID, CLIENT_SECRET, XDR_SCOPES)

        print("\n--- Fetching Active Cases ---")
        cases_response = get_cases(token, API_KEY)
        
        if cases_response:
            cases_list = cases_response.get("data", [])
            print(f"[+] Successfully fetched {len(cases_list)} cases.\n")
            # Using JSON dumps to print a formatted block for inspection
            print(json.dumps(cases_response, indent=2))

    except requests.exceptions.RequestException as e:
        print(f"\n[-] API error occurred: {e}")

if __name__ == "__main__":
    main()
