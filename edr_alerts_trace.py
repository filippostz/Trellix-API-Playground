#!/usr/bin/env python3
import requests
import sys
import time
from collections import defaultdict, Counter
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Tuple

# --- CONFIGURATION ---
API_KEY = ''
CLIENT_ID = ''
CLIENT_TOKEN = ''
DEFAULT_SCOPES = "soc.act.tg soc.cfg.r soc.cfg.w mi.user.investigate soc.hts.c soc.hts.r"

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


def create_historical_search(session: requests.Session, from_date: str, to_date: str, query: str) -> str:
    """Submits a historical search job to the API and returns the Search ID."""
    endpoint = f"{BASE_URL}/edr/v2/searches/historical"
    payload = {
        "data": {
            "type": "historicalSearches",
            "attributes": {
                "query": query,
                "startTime": from_date,
                "endTime": to_date
            }
        }
    }

    try:
        resp = session.post(endpoint, json=payload)
        resp.raise_for_status()
        return resp.json()['data']['id']
    except requests.exceptions.RequestException as e:
        print(f"Error submitting search: {e.response.text if e.response else e}")
        raise


def get_search_results(session: requests.Session, search_id: str, results_per_page: int = 30) -> Dict[str, Any]:
    """Polls the API for the completion of a specific search job and returns the results with pagination control."""
    endpoint = f"{BASE_URL}/edr/v2/searches/historical/{search_id}/results"
    max_retries = 24
    sleep_seconds = 5
    params = {'page[limit]': results_per_page}

    for attempt in range(max_retries):
        try:
            resp = session.get(endpoint, params=params)
            if resp.status_code != 200:
                time.sleep(sleep_seconds)
                continue

            resp_json = resp.json()

            if isinstance(resp_json, list):
                return {"data": resp_json}

            status = resp_json.get('meta', {}).get('status')
            if not status:
                data_block = resp_json.get('data', {})
                if isinstance(data_block, list):
                    return resp_json
                if isinstance(data_block, dict):
                    status = data_block.get('attributes', {}).get('status')

            if status == 'COMPLETED':
                return resp_json
            elif status == 'FAILED':
                raise RuntimeError(f"Search job {search_id} failed on server.")

            time.sleep(sleep_seconds)

        except requests.exceptions.RequestException as e:
            print(f"Network warning during poll: {e}")
            time.sleep(sleep_seconds)

    raise TimeoutError("Search timed out waiting for results.")


def main():
    days_to_query = 30
    severities = '["s2","s3","s4"]'
    search_window_minutes = 2
    results_per_page = 100

    try:
        with create_trellix_session(API_KEY, CLIENT_ID, CLIENT_TOKEN, DEFAULT_SCOPES) as session:

            print(f"Fetching {severities} alerts for the last {days_to_query} days...")
            alerts = get_edr_alerts(session, days_to_query, severities)

            grouped_alerts = defaultdict(lambda: {
                "processes": set(),
                "rules": set(),
                "tags": set()
            })

            for alert in alerts.get("data", []):
                attrs = alert.get("attributes", {})
                key = (attrs.get("Event_Date", "N/A"), attrs.get("Host_Name", "N/A"))

                grouped_alerts[key]["processes"].add(attrs.get("ProcessName", "Unknown"))
                grouped_alerts[key]["rules"].add(attrs.get("RuleId", "Unknown"))

                tags = attrs.get("Detection_Tags", [])
                if isinstance(tags, list):
                    grouped_alerts[key]["tags"].update(tags)
                else:
                    grouped_alerts[key]["tags"].add(tags)

            for (date, host), data in grouped_alerts.items():
                print(f"\nTarget: {date} | Host: {host}")
                print(f"Processes: {', '.join(sorted(data['processes']))}")
                print(f"Rules: {', '.join(sorted(data['rules']))}")
                print(f"Tags: {', '.join(sorted(data['tags']))}")  # <--- Tags restored here

                try:
                    start_t, end_t = get_time_range(date, search_window_minutes)
                    search_query = f'DeviceName = "{host}"'

                    print(f"Initiating investigation ({search_window_minutes}m window)...")
                    search_id = create_historical_search(session, start_t, end_t, search_query)

                    results = get_search_results(session, search_id, results_per_page=results_per_page)
                    items = results.get('data', [])
                    total_count = results.get('meta', {}).get('totalResourceCount', len(items))

                    print(f"Results: {total_count} total items found ({results_per_page} per page).")
                    print(f"Preview page 01")
                    
                    activities = [
                        item.get("attributes", {}).get("Activity", "Unknown")
                        for item in items
                    ]
                    for activity, count in Counter(activities).items():
                        print(f"  - {activity}: {count}")

                except Exception as e:
                    print(f" Investigation failed for host {host}: {e}", file=sys.stderr)

    except Exception as e:
        print(f"\nCritical Failure: {e}", file=sys.stderr)


if __name__ == "__main__":

    main()
