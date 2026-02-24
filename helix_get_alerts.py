import requests
import json
import base64

# ==========================================
# Configuration & Credentials
# ==========================================
# IMPORTANT: In a production environment, do not hardcode these.
# Use environment variables (os.environ.get) or a secrets manager.
CLIENT_ID = ""
CLIENT_SECRET = ""
API_KEY = ""

# URLs
TOKEN_URL = "https://iam.cloud.trellix.com/iam/v1.0/token"
API_BASE_URL = "https://api.manage.trellix.com"
ALERTS_ENDPOINT = f"{API_BASE_URL}/xdr/v2/alerts"

# The comprehensive list of scopes requested
XDR_SCOPES = [
    "xdr.alr.r"
]


def get_access_token(client_id, client_secret, scopes):
    """
    Authenticates with Trellix IAM using Client Credentials
    and returns an OAuth2 Bearer token.
    """
    auth_string = f"{client_id}:{client_secret}"
    b64_auth = base64.b64encode(auth_string.encode('utf-8')).decode('utf-8')

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": f"Basic {b64_auth}"
    }

    scope_string = " ".join(scopes)

    payload = {
        "grant_type": "client_credentials",
        "scope": scope_string
    }

    print("Authenticating with Trellix IAM...")
    response = requests.post(TOKEN_URL, headers=headers, data=payload)

    if response.status_code == 200:
        print("Successfully obtained access token.")
        return response.json().get("access_token")
    else:
        print(f"Failed to get token: HTTP {response.status_code} - {response.text}")
        response.raise_for_status()


def get_latest_alerts(token, api_key):
    """
    Fetches the latest 10 NEW alerts matching the specific DLP rule.
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "x-api-key": api_key,
        "Content-Type": "application/vnd.api+json",
        "Accept": "application/vnd.api+json"
    }

    # Corrected API query parameters with mix of object [eq] and string filters
    params = {
        "page[limit]": 1,
        "filter[name][eq]": "Trellix DLP: exfil to azure blob",
        "filter[status]": "NEW"
    }

    print(f"Fetching summary for the latest alert...")
    response = requests.get(ALERTS_ENDPOINT, headers=headers, params=params)

    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to fetch alerts list: HTTP {response.status_code} - {response.text}")
        response.raise_for_status()


def get_alert_details(token, api_key, alert_id):
    """
    Fetches the full forensic details for a specific alert ID.
    """
    detail_url = f"{API_BASE_URL}/xdr/v2/alerts/{alert_id}"

    headers = {
        "Authorization": f"Bearer {token}",
        "x-api-key": api_key,
        "Content-Type": "application/vnd.api+json",
        "Accept": "application/vnd.api+json"
    }

    params = {
        "details": "true"
    }

    print(f"  -> Fetching deep details for Alert ID: {alert_id}")
    response = requests.get(detail_url, headers=headers, params=params)

    if response.status_code == 200:
        return response.json()
    else:
        print(f"  [!] Failed to fetch details for {alert_id}: HTTP {response.status_code} - {response.text}")
        return None


def main():
    if "YOUR_" in CLIENT_ID or "YOUR_" in API_KEY:
        print("[!] Please update the CLIENT_ID, CLIENT_SECRET, and API_KEY variables before running.")
        return

    try:
        # 1. Authenticate
        token = get_access_token(CLIENT_ID, CLIENT_SECRET, XDR_SCOPES)

        # 2. Fetch the initial summary list
        print("\n--- Phase 1: Fetching Alert Summaries ---")
        summary_response = get_latest_alerts(token, API_KEY)

        # JSON:API spec puts the list of items inside a 'data' array
        alerts_list = summary_response.get("data", [])

        if not alerts_list:
            print("\nNo alerts found matching your criteria.")
            return

        print(f"\nFound {len(alerts_list)} matching alerts.")

        # 3. Loop through the summaries and fetch the deep details
        print("\n--- Phase 2: Fetching Alert Details ---")
        detailed_alerts = []

        for alert in alerts_list:
            # The ID is usually at the root of the item block in JSON:API
            alert_id = alert.get("id")
            if alert_id:
                details = get_alert_details(token, API_KEY, alert_id)
                if details:
                    detailed_alerts.append(details)

        print("\nSuccessfully retrieved all alert details!")

        # 4. Output Example
        if detailed_alerts:
            print("\nExample Data (First Alert Detail):")
            print("-" * 40)
            #print(json.dumps(detailed_alerts[0], indent=4))
            #print(detailed_alerts[0]['data']['attributes'])

            # ==========================================
            # 4. Parse and Output Specific Telemetry
            # ==========================================
            print("\n--- Phase 3: Extracting Telemetry ---")

            for detail in detailed_alerts:
                # Safely navigate the JSON tree to get the alert ID and the events array
                alert_data = detail.get("data", {})
                alert_id = alert_data.get("id", "Unknown ID")

                # The events live under relationship -> events
                events = alert_data.get("relationship", {}).get("events", [])

                # Use a set to deduplicate in case the alert aggregated 8 identical events
                unique_telemetry = set()

                for event in events:
                    event_telemetry = event.get("data", {})

                    # Extract the specific fields you requested
                    process_name = event_telemetry.get("process", "Not Found")
                    agent_id = event_telemetry.get("agentid", "Not Found")

                    # Add them to our set as a tuple
                    unique_telemetry.add((process_name, agent_id))

                # Print the extracted data for this specific alert
                print(f"\nAlert ID: {alert_id}")
                for proc, ag_id in unique_telemetry:
                    print(f"  -> Process Name: {proc}")
                    print(f"  -> Agent ID:     {ag_id}")

    except requests.exceptions.RequestException as e:
        print(f"\n[!] A network or API error occurred: {e}")
    except Exception as e:
        print(f"\n[!] An unexpected error occurred: {e}")


if __name__ == "__main__":

    main()
