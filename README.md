# Trellix API Playground

A collection of example Python scripts for interacting with the APIs of various Trellix security products.

These scripts are intended **purely for educational purposes** — to illustrate how to authenticate and make calls against Trellix APIs. They are **not production-ready** and should be treated as a starting point or reference only. The author assumes **no responsibility** for any use of these scripts in production environments or for any consequences arising from such use.

Before running any script, you must supply your own credentials (`API_KEY`, `CLIENT_ID`, `CLIENT_TOKEN`, etc.) in the configuration section of each file. Consider loading credentials from environment variables or a secrets manager rather than hardcoding them.

---

## Scripts

| Trellix Product | File | Description |
|---|---|---|
| EDR | `edr_alerts_trace.py` | Fetches EDR alerts and runs historical searches to trace process activity on affected hosts |
| EDR | `edr_get_threats.py` | Retrieves EDR threats with associated detections for a configurable lookback window |
| EDR | `edr_parent_alert_kill.py` | Automated containment: identifies the parent process behind an alert by MITRE tag, hunts it enterprise-wide via real-time search, and kills it |
| EDR / Active Response | `edr_custom_reaction.py` | Searches for a host by name and triggers a custom Active Response reaction on it |
| ePO | `epo_events.py` | Fetches and paginates threat events from Trellix ePolicy Orchestrator (ePO) |
| ETP | `etp_get_alert.py` | Searches and retrieves email threat alerts from Trellix Email Threat Prevention |
| ETP (FireEye legacy) | `etp_get_alerts_fireeye.py` | Searches alerts and message traces via the legacy FireEye ETP API endpoint |
| Helix / XDR | `helix_get_alerts.py` | Fetches XDR alerts and enriches them with full forensic telemetry details |
| Helix | `helix_send_event_to_integration-hub.py` | Sends a custom event payload to the Helix Integration Hub |
| HX | `hx_get_alerts.py` | Authenticates against Trellix HX and retrieves the latest endpoint alerts |
| HX + MISP | `hx_historical_search_misp.py` | Integrates MISP threat intelligence with HX historical search to hunt IOCs and tag results back in MISP |

---

## Disclaimer

These scripts are provided as-is, without warranty of any kind. They are examples meant to demonstrate API usage patterns and may require adaptation before use in any real environment. Always review and test code thoroughly before deploying it in production. The author is not liable for any damage, data loss, or security incidents resulting from the use of these scripts.
