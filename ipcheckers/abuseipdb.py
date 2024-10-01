import requests
import json
import urllib.parse
import asyncio

from config.config import KEYS, URLS
from datetime import datetime
from typing import Callable, List, Dict, Union, Tuple


async def make_request_abuse(ip):
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }
    headers = {
        'Accept': 'application/json',
        'Key': KEYS.ABUSEIPDB_KEY
    }
    response = requests.request(method='GET', url=URLS.API_URL_ABUSEIPDB, headers=headers, params=querystring)
    return gen_res(json.loads(response.text)['data'])

async def get_abuseipdb_info(
    ips: List[str]
) -> Tuple[bool, List[Dict[str, Union[str, int]]]]:
    """
    Получает данные из AbuseIPDB для заданных IP-адресов и доменов.

    Параметры:
        ips (List[str]): Список IP-адресов.
        dnss (List[str]): Список доменных имен.

    Возвращает:
        Tuple[bool, List[Dict[str, Union[str, int, datetime.datetime]]]]:
            Кортеж, содержащий булево значение, указывающее на успех,
            и список словарей, содержащих данные из AbuseIPDB для каждого
            IP-адреса и домена.
    """
    results = []
    ip_info_tasks = [make_request_abuse(ip) for ip in ips]
    results = await asyncio.gather(*ip_info_tasks, return_exceptions=True)
    filtered_results = [
        result for result in results if not isinstance(result, Exception)
    ]
    return True, filtered_results

def gen_res(response):
    report = {
        "verdict": get_confidence_emoji(response["abuseConfidenceScore"]),
        "whitelist": "yes" if response["isWhitelisted"] else "",
        "usage_type": response.get("usageType"),
        "domain": response.get("domain"),
        "hostnames": ", ".join(response.get("hostnames", [])),
        "tor": "yes" if response.get("isTor") else "",
        "reports": response.get("totalReports"),
        #"country": get_geo_response(ip_address),
        "last_report": datetime.strptime(response.get("lastReportedAt")[:10], "%Y-%m-%d").strftime("%d.%m.%Y") if response.get("lastReportedAt") else ""
    }
    return report











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
        #"country": get_geo_response(ip_address),
        "last_report": datetime.strptime(response.get("lastReportedAt")[:10], "%Y-%m-%d").strftime("%d.%m.%Y") if response.get("lastReportedAt") else ""
    }
    return report
