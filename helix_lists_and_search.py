#!/usr/bin/env python3
"""
Trellix Helix API - Lists Management & Search
Demonstrates the usage of Trellix IAM client credentials authentication
with legacy Helix endpoints.
"""

import datetime
import json
import time
import requests

# ==========================================
# Configuration & Credentials
# ==========================================
CLIENT_ID = ""
CLIENT_SECRET = ""
API_KEY = ""
HELIX_ID = ""

TOKEN_URL = "https://iam.cloud.trellix.com/iam/v1.0/token"
BASE_URL = "https://xdr.trellix.com/helix/id"

XDR_SCOPES = [
    "xdr.ind.r",
    "xdr.ind.rw",
    "xdr.srh.adv",
    "xdr.srh.r",
    "xdr.srh.rw"
]


class TrellixHelixClient:
    def __init__(self, client_id, client_secret, api_key, helix_id):
        self.client_id = client_id
        self.client_secret = client_secret
        self.api_key = api_key
        self.helix_id = helix_id

        self.session = requests.Session()
        self.session.headers.update({
            "x-api-key": self.api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

    def authenticate(self, scopes):
        """Authenticates with Trellix IAM and stores the bearer token in the session."""
        payload = {
            "grant_type": "client_credentials",
            "scope": " ".join(scopes)
        }

        print("[*] Authenticating with Trellix IAM...")
        # auth=(uid, pwd) automatically handles standard Base64 Basic Auth header formatting
        response = self.session.post(TOKEN_URL, data=payload, auth=(self.client_id, self.client_secret))
        response.raise_for_status()

        token = response.json().get("access_token")
        self.session.headers.update({"Authorization": f"Bearer {token}"})
        print("[+] Successfully obtained access token and updated session.")

    def get_lists(self, limit=30, offset=0):
        """Fetches lists managed inside Helix."""
        print("[*] Fetching Lists...")
        url = f"{BASE_URL}/{self.helix_id}/api/v3/lists"
        params = {
            "limit": limit,
            "offset": offset,
            "order_by": "-updated_at"
        }

        response = self.session.get(url, params=params)
        if response.status_code == 200:
            return response.json()

        print(f"  [-] Failed to fetch lists: {response.text}")
        return None

    def search(self, query, hours=24, limit=100, timeout_seconds=60, page_size=100):
        """Run a Helix search over a recent time window and return result rows."""
        url = f"{BASE_URL}/{self.helix_id}/api/v1/search/"

        # Time formatting windows
        end_dt = datetime.datetime.now(datetime.timezone.utc)
        start_dt = end_dt - datetime.timedelta(hours=hours)
        start = start_dt.isoformat().replace("+00:00", "Z")
        end = end_dt.isoformat().replace("+00:00", "Z")

        results = []
        offset = 0
        deadline = time.time() + timeout_seconds

        print(f"[*] Running Search: '{query}'...")

        while len(results) < limit and time.time() < deadline:
            current_page_size = min(page_size, limit - len(results))
            payload = {
                "query": query,
                "transforms": [["sort", "<", "meta_ts"]],
                "options": {
                    "page_size": current_page_size,
                    "start": start,
                    "end": end,
                    "offset": offset,
                },
            }

            response = self.session.post(url, json=payload)
            if response.status_code != 200:
                print(f"  [-] Failed to run search: {response.text}")
                return None

            body = response.json()
            hits = (body or {}).get("results", {}).get("hits", {})
            page = hits.get("hits", [])

            for hit in page:
                results.append(hit.get("_source", hit))

            total = hits.get("total", len(results))
            offset += len(page)

            if not page or offset >= total:
                break

        return results


def main():
    if "YOUR_" in CLIENT_ID or "YOUR_" in API_KEY:
        print("[-] Please update your configuration credentials before running.")
        return

    try:
        # Initialize client and authenticate
        client = TrellixHelixClient(CLIENT_ID, CLIENT_SECRET, API_KEY, HELIX_ID)
        client.authenticate(XDR_SCOPES)

        # Run investigation search
        search_result = client.search("dstipv4=192.168.4.236")
        print("\n--- Search Results ---")
        print(json.dumps(search_result, indent=2) if search_result else "No results returned.")

        # Fetch Active Lists
        print("\n--- Fetching Active Lists ---")
        lists_response = client.get_lists()

        if lists_response:
            lists_list = lists_response.get("results", [])
            print(f"[+] Successfully fetched {len(lists_list)} lists.\n")
            print(json.dumps(lists_response, indent=2))

    except requests.exceptions.RequestException as e:
        print(f"\n[-] API network/communication error occurred: {e}")


if __name__ == "__main__":
    main()
