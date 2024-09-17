import requests

from ipaddress import ip_address
from includes.IPinfo.geo_ip import get_geo_response
from includes.config import KEYS
from includes.valid import extract_and_validate



# response = requests.request(method='GET', url=url_base+url_ip+'8.8.8.8', headers=headers)
# print(response.text)

# reverse dns, OTX telemetry, verdict

# json.loads(response.text)

def make_request_kasper(ip_address: ip_address):
    url = "https://opentip.kaspersky.com/api/v1/search/ip?request="
    headers = {
        'x-api-key': KEYS.KS_KEY
    }
    response = requests.request(method='GET', url=url+ip_address, headers=headers).json()
    return response

def format_res(response):
    report = {}
    try:
        zone = response["Zone"]
        if zone == "Red":
            verdict = "🔴 malicious"
        elif zone == "Orange":
            verdict = "🟡 suspicious"
        elif zone == "Green":
            verdict = "🟢 harmless"
        else:
            verdict = "⚫️ no info"
        report["verdict"] = verdict
    except KeyError:
        pass
    try:
        report["country"] = get_geo_response(ip_address)
    except KeyError:
        pass
    try:
        report["net_name"] = response["IpWhoIs"]["Net"]["Name"]
    except KeyError:
        pass
    try:
        report["net_description"] = response["IpWhoIs"]["Net"]["Description"]
    except KeyError:
        pass
    try:
        report["tags"] = ", ".join(categories.split("CATEGORY_")[1] for categories in response["IpGeneralInfo"]["Categories"])
    except KeyError:
        pass
    return report


def get_rep(text_ips: str):
    ips, dnss = extract_and_validate(text_ips)
    if not ips:
        return f"No valid IPs"
    else:
        try:
            results = []
            for ip in ips:
                details = make_request_kasper(ip)
                results.append(format_res(details))
            return '\n'.join(results)
        except Exception as e:
            print(e)
            return  f"bruh, it's looks like a error\n"


def get_report_kasper(ip_address: ip_address):
    response = make_request_kasper(ip_address=ip_address)
    report = {}
    try:
        zone = response["Zone"]
        if zone == "Red":
            verdict = "🔴 malicious"
        elif zone == "Orange":
            verdict = "🟡 suspicious"
        elif zone == "Green":
            verdict = "🟢 harmless"
        else:
            verdict = "⚫️ no info"
        report["verdict"] = verdict
    except KeyError:
        pass
    try:
        report["country"] = get_geo_response(ip_address)
    except KeyError:
        pass
    try:
        report["net_name"] = response["IpWhoIs"]["Net"]["Name"]
    except KeyError:
        pass
    try:
        report["net_description"] = response["IpWhoIs"]["Net"]["Description"]
    except KeyError:
        pass
    try:
        report["tags"] = ", ".join(categories.split("CATEGORY_")[1] for categories in response["IpGeneralInfo"]["Categories"])
    except KeyError:
        pass
    return report

# zone orange - Not trusted; green - ok, grey - hz, red - dangerous
