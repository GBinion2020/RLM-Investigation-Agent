
import json
import os
import warnings
import urllib3
import elasticsearch
from dotenv import load_dotenv

load_dotenv()

ELASTIC_HOST = os.getenv("ELASTIC_HOST") or os.getenv("ELASTIC_BASE_URL")
ELASTIC_API_KEY = os.getenv("ELASTIC_API_KEY")
ELASTIC_COMPAT_VERSION = os.getenv("ELASTIC_COMPAT_VERSION", "8")
ELASTIC_VERIFY_CERTS = os.getenv("ELASTIC_VERIFY_CERTS", "false").lower() in {"1", "true", "yes"}
ELASTIC_CA_CERTS = os.getenv("ELASTIC_CA_CERTS")
if ELASTIC_COMPAT_VERSION not in {"7", "8"}:
    ELASTIC_COMPAT_VERSION = "8"

# Suppress warnings when verify_certs is disabled
if not ELASTIC_VERIFY_CERTS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    warnings.filterwarnings("ignore", message=".*verify_certs=False is insecure.*")
    try:
        from elastic_transport import SecurityWarning

        warnings.filterwarnings("ignore", category=SecurityWarning)
    except Exception:
        pass
    try:
        from elasticsearch import SecurityWarning as EsSecurityWarning

        warnings.filterwarnings("ignore", category=EsSecurityWarning)
    except Exception:
        pass

# Force compatibility headers for older Elastic clusters (7.x/8.x)
ES_HEADERS = {
    "Accept": f"application/vnd.elasticsearch+json; compatible-with={ELASTIC_COMPAT_VERSION}",
    "Content-Type": f"application/vnd.elasticsearch+json; compatible-with={ELASTIC_COMPAT_VERSION}",
}


def _raw_http_alert(alert_fetch: str, query: dict) -> dict:
    if not ELASTIC_HOST or not ELASTIC_API_KEY:
        raise ValueError("Elastic configuration missing. Set ELASTIC_HOST and ELASTIC_API_KEY.")

    cert_reqs = "CERT_REQUIRED" if ELASTIC_VERIFY_CERTS else "CERT_NONE"
    http = urllib3.PoolManager(cert_reqs=cert_reqs, ca_certs=ELASTIC_CA_CERTS if ELASTIC_VERIFY_CERTS else None)
    url = f"{ELASTIC_HOST.rstrip('/')}/{alert_fetch}/_search"
    headers = {
        "Accept": ES_HEADERS["Accept"],
        "Content-Type": ES_HEADERS["Content-Type"],
        "Authorization": f"ApiKey {ELASTIC_API_KEY}",
    }
    response = http.request("POST", url, body=json.dumps(query), headers=headers)
    if response.status >= 400:
        raise ValueError(f"Elastic HTTP {response.status}: {response.data[:500]}")
    payload = json.loads(response.data.decode("utf-8"))
    hits = payload.get("hits", {}).get("hits", [])
    if not hits:
        raise ValueError("Elastic returned zero alert hits.")
    return hits[0]["_source"]

class Elastic:
    def Alert():
        client_connection = elasticsearch.Elasticsearch(
            ELASTIC_HOST,
            api_key=ELASTIC_API_KEY,
            verify_certs=ELASTIC_VERIFY_CERTS,
            ca_certs=ELASTIC_CA_CERTS if ELASTIC_VERIFY_CERTS else None,
            headers=ES_HEADERS,
        )
        # This sets the alert index to pull from
        alert_fetch = ".alerts-security.alerts-*"

        query = {
            "size": 1,
            "sort": [{"@timestamp": "desc"}],
            "query": {"match_all": {}}
        }

        # Fix: Call .search() on the connection object
        try:
            response = client_connection.search(index=alert_fetch, body=query, headers=ES_HEADERS)
            raw_alert = response["hits"]["hits"][0]["_source"]
            return raw_alert
        except Exception as exc:
            message = str(exc)
            if "media_type_header_exception" in message or "compatible-with=9" in message:
                return _raw_http_alert(alert_fetch, query)
            raise

    
