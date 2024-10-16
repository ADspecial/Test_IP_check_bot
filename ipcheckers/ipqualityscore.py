import asyncio
import requests

from config.config import KEYS
from handlers.format import get_country_flag

from typing import List, Dict, Union, Tuple
from datetime import datetime, timedelta

from config.config import KEYS, URLS

async def make_request_ipqs(ip_address: str):
    url = URLS.API_URL_IP_IPQS %(KEYS.IPQS_KEY, ip_address)
    response = requests.request(method='GET', url=url).json()
    return  gen_result(ip_address, response)

async def get_ipqs_info(
    ips: List[str], dnss: List[str]
) -> Tuple[bool, List[Dict[str, Union[str, int, datetime]]]]:
    """
    Gets data from Kaspersky for given IP addresses.

    Args:
        ips: A list of IP addresses.

    Returns:
        A tuple containing a boolean indicating success and a list of dictionaries containing the response data.
    """
    results = []
    tasks = [make_request_ipqs(ip) for ip in ips]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    filtered_results = [
        result for result in results if not isinstance(result, Exception)
    ]
    return True, filtered_results

def gen_result(ip_address: str,response: Dict[str, Union[str, int]]) -> Dict[str, Union[str, int, datetime]]:
    fraud_score = response.get('fraud_score')
    verdict = '🟢 harmless'
    if fraud_score >= 90:
        verdict = '🔴 malicious'
    elif fraud_score >= 75:
        verdict = '🟡 suspicious'
    elif fraud_score < 10:
        verdict = '⚫️ undetected'
    result = {
        'ip_address': ip_address,
        'country': get_country_flag(response.get('country_code')),
        'host': response.get('host'),
        'isp': response.get('ISP'),
        'verdict': verdict,
        'fraud_score': response.get('fraud_score'),
        'proxy': response.get('proxy'),
        'vpn': response.get('vpn'),
        'tor': response.get('tor'),
        'active_vpn': response.get('active_vpn'),
        'active_tor': response.get('last_tor'),
        'recent_abuse': response.get('recent_abuse'),
        'bot_status': response.get('bot_status')
    }
    return result
