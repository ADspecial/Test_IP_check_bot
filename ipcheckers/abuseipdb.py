import requests

import json

from ipaddress import ip_address

from datetime import datetime

from geo_ip import get_geo_response

from config import settings


url = 'https://api.abuseipdb.com/api/v2/check'


def make_request_abuse(ip_address: ip_address):
    querystring = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90'
    }
    headers = {
        'Accept': 'application/json',
        'Key': settings.ABUSEIPDB_KEY
    }
    response = requests.request(method='GET', url=url, headers=headers, params=querystring)
    return json.loads(response.text)['data']

# print(make_request("185.138.131.234"))

# print (json.dumps(decodedResponse, sort_keys=True, indent=4)) # - pretty output

def get_hostnames(ip_address: str):
    response = make_request_abuse(ip_address)["hostnames"]
    return response


def get_domain(ip_address: str):
    response = make_request_abuse(ip_address)["domain"]
    return response


def get_confidence_emoji(abuse_confidence):
    abuse_emoji = "🟢 harmless"
    if abuse_confidence > 20:
        abuse_emoji = "🔴 malicious"
    elif abuse_confidence > 3:
        abuse_emoji = "🟡 suspicious"
    output = abuse_emoji + f" ({abuse_confidence}/100)"
    return output


def get_reputation(ip_address: str):
    decodedResponse = make_request_abuse(ip_address)
    abuse_confidence: int = decodedResponse['abuseConfidenceScore']
    is_whitelisted: str = decodedResponse['isWhitelisted']
    hostname: str = str()
    try:
        hostname = decodedResponse['hostnames'][0]
    except Exception as e:
        print(e)

    abuse_url: str = f"abuseipdb.com/check/{ip_address}"
    abuse_emoji = get_confidence_emoji(abuse_confidence)

    output = (abuse_emoji, is_whitelisted, hostname, abuse_url)
    return output


def get_only_emoji(ip_address: str):
    decodedResponse = make_request_abuse(ip_address)
    abuse_confidence: int = decodedResponse['abuseConfidenceScore']
    abuse_emoji = get_confidence_emoji(abuse_confidence)
    return abuse_emoji


def get_report_abuseipdb(ip_address: str):
    response = make_request_abuse(ip_address)
    report = {
        "verdict": get_confidence_emoji(response["abuseConfidenceScore"]),
        "whitelist": "yes" if response["isWhitelisted"] else "",
        "usage_type": response.get("usageType"),
        "domain": response.get("domain"),
        "hostnames": ", ".join(response.get("hostnames", [])),
        "tor": "yes" if response.get("isTor") else "",
        "reports": response.get("totalReports"),
        "country": get_geo_response(ip_address),
        "last_report": datetime.strptime(response.get("lastReportedAt")[:10], "%Y-%m-%d").strftime("%d.%m.%Y") if response.get("lastReportedAt") else ""
    }
    return report
