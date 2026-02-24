# !/usr/bin/env python3

"""
Trellix EDR Automated Threat Containment

Purpose:
    Automates the remediation of threats by identifying and terminating the
    parent processes responsible for triggering specific security alerts.

Workflow:
    1. Alert Ingestion: Queries Trellix EDR for alerts matching specific
       severity levels and MITRE ATT&CK tags.
    2. Hash Extraction: Isolates the cryptographic hash (MD5) of the parent
       process ("mother process") that spawned the malicious child process.
    3. Enterprise Hunt: Executes a Real-Time Search across the environment
       to locate all active instances of the identified parent hash.
    4. Remediation: Automatically issues a 'killProcess' command to terminate
       the parent process on every affected endpoint, effectively stopping
       the attack chain.
"""
import requests
import sys
import json
import time
from collections import defaultdict, Counter
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Tuple

# --- CONFIGURATION ---
API_KEY = ''
CLIENT_ID = '-'
CLIENT_TOKEN = ''
DEFAULT_SCOPES = "soc.act.tg soc.cfg.r soc.cfg.w mi.user.investigate soc.hts.c soc.hts.r soc.rts.c soc.rts.r"

BASE_URL = "https://api.manage.trellix.com"
IAM_URL = "https://auth.trellix.com/auth/realms/IAM/protocol/openid-connect/token"


def get_epoch_utc_millis(past_days: int) -> int:
    """Calculates the epoch timestamp in milliseconds for a specific number of days in the past."""
    now = datetime.now(timezone.utc)
    past = now - timedelta(days=past_days)
    return int(past.timestamp() * 1000)


def get_time_range(timestamp_str: str, duration_minutes: int) -> Tuple[str, str]:
    """Parses a timestamp string and returns a start and end time window centered around it."""
    formats = ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ")
    center_time = None

    for fmt in formats:
        try:
            center_time = datetime.strptime(timestamp_str, fmt)
            break
        except ValueError:
            continue

    if not center_time:
        raise ValueError(f"Unknown timestamp format: {timestamp_str}")

    half_duration = timedelta(minutes=duration_minutes / 2)
    start_time = center_time - half_duration
    end_time = center_time + half_duration

    out_fmt = "%Y-%m-%dT%H:%M:%S.%f"
    return (
        f"{start_time.strftime(out_fmt)[:-3]}Z",
        f"{end_time.strftime(out_fmt)[:-3]}Z"
    )


def create_trellix_session(key: str, client_id: str, token: str, scopes: str) -> requests.Session:
    """Authenticates with the IAM service and returns a configured requests Session."""
    if not all([key, client_id, token]):
        print("Error: API Credentials must be set.", file=sys.stderr)
        sys.exit(1)

    session = requests.Session()
    headers = {'x-api-key': key, 'Content-Type': 'application/x-www-form-urlencoded'}
    auth = (client_id, token)
    payload = {'scope': scopes, 'grant_type': 'client_credentials'}

    try:
        res = session.post(IAM_URL, headers=headers, data=payload, auth=auth)
        res.raise_for_status()
        access_token = res.json()['access_token']

        session.headers.update({
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/vnd.api+json',
            'x-api-key': key
        })
        return session
    except requests.exceptions.RequestException as e:
        raise ConnectionError(f"Authentication Error: {e}") from e


def get_edr_alerts(session: requests.Session, days: int, severities: str) -> Dict[str, Any]:
    """Fetches EDR alerts for a given lookback period and severity filter."""
    filters = {
        'from': get_epoch_utc_millis(days),
        'filter': f'{{"severities":{severities}}}'
    }
    api_url = f"{BASE_URL}/edr/v2/alerts"

    try:
        response = session.get(api_url, params=filters)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        raise ConnectionError(f"Error fetching EDR alerts: {e}") from e


def filter_alerts_by_tags(alerts_data, target_tags):
    # 1. If it's a raw JSON string, parse it
    if isinstance(alerts_data, str):
        alerts_data = json.loads(alerts_data)

    # 2. If it's a dictionary (like {"data": [...]}), find the list inside it
    if isinstance(alerts_data, dict):
        for key, value in alerts_data.items():
            if isinstance(value, list):
                alerts = value
                break
        else:
            print("Debug: Passed a dictionary, but couldn't find a list inside.")
            return []
    elif isinstance(alerts_data, list):
        alerts = alerts_data
    else:
        print(f"Debug: Unrecognized data format: {type(alerts_data)}")
        return []

    # 3. Filter the actual list of alerts
    filtered_alerts = []

    # Strip whitespace to ensure perfect matching
    target_tags_clean = [tag.strip() for tag in target_tags]

    for alert in alerts:
        if isinstance(alert, dict):
            current_tags = alert.get("attributes", {}).get("Detection_Tags", [])
            current_tags_clean = [tag.strip() for tag in current_tags]

            # Check if all target tags are inside the current alert's tags
            if all(tag in current_tags_clean for tag in target_tags_clean):
                filtered_alerts.append(alert)

    return filtered_alerts


def extract_unique_process_md5(alerts_list):
    """
    Extracts unique Process_Md5 hashes from a list of alert dictionaries.
    """
    # The {} creates a Set, which automatically drops duplicate values
    unique_md5s = {
        alert.get("attributes", {}).get("Process_Md5")
        for alert in alerts_list
        if alert.get("attributes", {}).get("Process_Md5") is not None
    }

    # Convert the set back to a list before returning
    return list(unique_md5s)


def run_realtime_search(session: requests.Session, query: str) -> List[Dict[str, Any]]:
    """
    Executes a real-time search, polls the correct queue-jobs endpoint,
    and securely fetches the results without header stripping.
    """
    base_post_url = f"{BASE_URL}/edr/v2/searches/realtime"

    # We must explicitly define headers to survive the strict API Gateway
    headers = {
        'Authorization': session.headers.get('Authorization'),
        'x-api-key': session.headers.get('x-api-key'),
        'Content-Type': 'application/vnd.api+json'
    }

    payload = {
        "data": {
            "type": "realTimeSearches",
            "attributes": {
                "query": query
            }
        }
    }

    try:
        # 1. Start the Search
        print(f"[*] Initiating real-time search...")
        post_res = requests.post(base_post_url, json=payload, headers=headers)
        post_res.raise_for_status()

        search_id = post_res.json()['data']['id']

        # === THE CRITICAL FIX: The correct polling URL ===
        status_url = f"{BASE_URL}/edr/v2/searches/queue-jobs/{search_id}"
        results_url = f"{base_post_url}/{search_id}/results"

        print(f"[*] Search ID {search_id} created. Polling {status_url}...")

        # 2. Poll for Status
        completed = False
        for attempt in range(20):
            time.sleep(5)
            # allow_redirects=False prevents python from jumping to the results
            # endpoint prematurely without our required pagination parameters.
            status_res = requests.get(status_url, headers=headers, allow_redirects=False)

            # Trellix API returns HTTP 303 when the search is fully FINISHED
            if status_res.status_code == 303:
                print("    [+] Status: FINISHED")
                completed = True
                break

            status_res.raise_for_status()

            # If it's 200, it's still running. Let's print the status.
            status_data = status_res.json()
            status = status_data.get('data', {}).get('attributes', {}).get('status', 'RUNNING')
            print(f"    [+] Status: {status}")

            if status == 'FINISHED':
                completed = True
                break

        # 3. Fetch Results
        if completed:
            # Pagination params are required by the results endpoint
            params = {'page[offset]': 0, 'page[limit]': 50}
            print(f"[*] Fetching results from {results_url}...")

            res_data = requests.get(results_url, headers=headers, params=params)
            res_data.raise_for_status()

            out = res_data.json()
            return search_id, out.get('items', out.get('data', []))

        print("[-] Search timed out before finishing.")
        return search_id, []

    except Exception as e:
        print(f"[-] Real-time search failure: {e}")
        return None, []


def trigger_kill_process_remediation(session: requests.Session, search_id: str, search_results: List[Dict[str, Any]]) -> \
List[Dict[str, Any]]:
    """
    Iterates through search results and triggers a killProcess payload,
    ensuring we do not target the same PID on the same host more than once.
    """
    remediation_url = f"{BASE_URL}/edr/v2/remediation/search"

    headers = {
        'Authorization': session.headers.get('Authorization'),
        'x-api-key': session.headers.get('x-api-key'),
        'Content-Type': 'application/vnd.api+json',
        'Accept': 'application/vnd.api+json'
    }

    remediation_responses = []

    # This set will keep track of (hostname, target_pid) tuples
    seen_targets = set()

    print(f"[*] Analyzing {len(search_results)} search results for remediation targets...")
    print(search_results)
    for item in search_results:
        row_id = item.get("id")
        attributes = item.get("attributes", {})
        target_pid = attributes.get("ProcessHistory.parentid")
        target_name = attributes.get("ProcessHistory.parentname", "unknown_process.exe")
        hostname = attributes.get("HostInfo.hostname", "Unknown_Host")

        if not row_id or target_pid is None:
            continue

        # Create a unique identifier for this specific process on this specific host
        target_key = (hostname, target_pid)

        # Check if we already killed this exact process
        if target_key in seen_targets:
            print(f"    [-] Skipping PID {target_pid} on {hostname} (Already targeted in this run).")
            continue

        # Add to our tracker so we don't hit it again
        seen_targets.add(target_key)

        payload = {
            "data": {
                "type": "searchRemediation",
                "attributes": {
                    "action": "killProcess",
                    "searchId": search_id,
                    "rowIds": [row_id],
                    "actionInputs": [
                        {
                            "name": "pid",
                            "value": str(target_pid)
                        }
                    ]
                }
            }
        }

        payload_str = json.dumps(payload)

        try:
            print(f"    [+] Killing PID {target_pid} on {hostname} (Row: {row_id[:8]})...")
            res = requests.post(remediation_url, data=payload_str, headers=headers)
            res.raise_for_status()

            print(f"        -> Success!")
            remediation_responses.append(res.json())

        except requests.exceptions.RequestException as e:
            print(f"        -> [-] API Error: {e}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"           Details: {e.response.text}")

    print(f"\n[*] Finished processing. Successfully triggered {len(remediation_responses)} unique kill actions.")
    return remediation_responses

def main():
    days_to_query = 1
    severities = '["s4"]'
    tags_to_find = [
        "@ATE.T1567.002",
        "@MSI._process_suspicious_rclone_exc"
    ]

    try:
        with create_trellix_session(API_KEY, CLIENT_ID, CLIENT_TOKEN, DEFAULT_SCOPES) as session:

            print(f"Fetching {severities} alerts for the last {days_to_query} days...")
            alerts_list = get_edr_alerts(session, days_to_query, severities)
            matched_alerts = filter_alerts_by_tags(alerts_list, tags_to_find)
            #print(json.dumps(matched_alerts, indent=2))
            process_MD5_list = extract_unique_process_md5(matched_alerts)
            for process_MD5 in process_MD5_list:
                print("Search for: {}".format(process_MD5))
                rt_query = 'HostInfo hostname and ProcessHistory parentname, status,  parentid, started_at, finished_at where ProcessHistory md5 equals '+ process_MD5
                print(rt_query)
                search_id, results = run_realtime_search(session, rt_query)

                if results:
                    # Print what we found
                    print(f"[!] Found {len(results)} active processes.")

                    # 2. Trigger remediation
                    remediation_response = trigger_kill_process_remediation(session, search_id, results)

                    if remediation_response:
                        print("Remediation Response Details:")
                        print(json.dumps(remediation_response, indent=2))

                else:
                    print("No results found in real-time search.")


    except Exception as e:
        print(f"\nCritical Failure: {e}", file=sys.stderr)



if __name__ == "__main__":
    main()