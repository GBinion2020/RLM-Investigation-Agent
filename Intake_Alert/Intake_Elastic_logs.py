
import os
import elasticsearch
import warnings
from dotenv import load_dotenv
import urllib3

# Suppress warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", message=".*verify_certs=False is insecure.*")

load_dotenv()

ELASTIC_HOST = os.getenv("ELASTIC_HOST")
ELASTIC_API_KEY = os.getenv("ELASTIC_API_KEY")
ELASTIC_COMPAT_VERSION = os.getenv("ELASTIC_COMPAT_VERSION", "8")
if ELASTIC_COMPAT_VERSION not in {"7", "8"}:
    ELASTIC_COMPAT_VERSION = "8"

# Force compatibility headers for older Elastic clusters (7.x/8.x)
ES_HEADERS = {
    "accept": f"application/vnd.elasticsearch+json; compatible-with={ELASTIC_COMPAT_VERSION}",
    "content-type": f"application/vnd.elasticsearch+json; compatible-with={ELASTIC_COMPAT_VERSION}",
}

class Elastic:
    def Alert():
        client_connection = elasticsearch.Elasticsearch(
            ELASTIC_HOST,
            api_key=ELASTIC_API_KEY,
            verify_certs=False,  # Bypass SSL certificate check (common fix for Windows)
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
        response = client_connection.search(index=alert_fetch, body=query)

        # Fix: Use 'response' instead of 'respond'
        raw_alert = response['hits']['hits'][0]['_source']
        return raw_alert

    
