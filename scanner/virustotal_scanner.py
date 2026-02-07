import requests
import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VT_API_KEY")
VT_URL = "https://www.virustotal.com/api/v3/files/"

def scan_hash_virustotal(file_hash):
    headers = {
        "x-apikey": API_KEY
    }

    response = requests.get(VT_URL + file_hash, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return stats
    elif response.status_code == 404:
        return "Hash not found on VirusTotal"
    else:
        return f"Error: {response.status_code}"
