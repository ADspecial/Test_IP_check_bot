import asyncio
import requests
import urllib

from config.config import KEYS
from ipcheckers.format import get_country_flag

from typing import List, Dict, Union, Tuple, Literal
from datetime import datetime


from config.config import KEYS, URLS

async def make_request_kaspersky(address: str, version: str):
    headers = {
        'x-api-key': KEYS.KASPERSKY_KEY
    }
    if version == 'ip':
        url = URLS.API_URL_IP_KASPERSKY + urllib.parse.quote(address)
        response = requests.request(method='GET', url=url, headers=headers).json()
        return gen_result_ip(response)
    else:
        url = URLS.API_URL_DOMAIN_KASPERSKY + urllib.parse.quote(address)
        response = requests.request(method='GET', url=url, headers=headers).json()
        return gen_result_domain(response)

async def get_kaspersky_info(
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
    ip_info_tasks = [make_request_kaspersky(ip, 'ip') for ip in ips]
    domain_info_tasks = [make_request_kaspersky(dns, 'domain') for dns in dnss]
    tasks = ip_info_tasks + domain_info_tasks
    results = await asyncio.gather(*tasks, return_exceptions=True)
    filtered_results = [
        result for result in results if not isinstance(result, Exception)
    ]
    return True, filtered_results


def gen_result_ip(response: Dict[str, Union[str, int]]) -> Dict[str, Union[str, int, datetime]]:
    """
    Formats the response from AbuseIPDB to a dictionary with the required keys.

    Args:
        response: The response from AbuseIPDB.

    Returns:
        A dictionary with the response data.
    """
    result = {
        'ip_address': response['IpGeneralInfo']['Ip'],
        'status': response['IpGeneralInfo']['Status'],
        'country': get_country_flag(response['IpGeneralInfo']['CountryCode']),
        'net_name': response["IpWhoIs"]["Net"]["Name"],
        'verdict': determine_verdict_kaspersky(response['Zone']),
    }
    return result

def gen_result_domain(response: Dict[str, Union[str, int]]) -> Dict[str, Union[str, int, datetime]]:
    """
    Formats the response from AbuseIPDB to a dictionary with the required keys.

    Args:
        response: The response from AbuseIPDB.

    Returns:
        A dictionary with the response data.
    """
    result = {
        'ip_address': response['DomainWhoIsInfo']['DomainName'],
        'status': None,
        'country': None,
        'net_name': None,
        'verdict': determine_verdict_kaspersky(response['Zone']),
    }
    return result


def determine_verdict_kaspersky(zone: str) -> Literal['🔴 malicious', '🟡 suspicious', '🟢 harmless', '⚫️ undetected']:
    """
    Определение вердикта на основе зоны Kaspersky

    Аргументы:
        zone (str):
            Зона Kaspersky

    Возвращает:
        Literal[' malicious', ' suspicious', ' harmless', ' undetected']:
            Вердикт, вынесенный на основе зоны
    """
    verdict_map: Dict[str, Literal['🔴 malicious', '🟡 suspicious', '🟢 harmless', '⚫️ undetected']] = {
        'Red': '🔴 malicious',
        'Orange': '🟡 suspicious',
        'Yellow': '🟡 suspicious',
        'Grey': '⚫️ undetected'
    }
    return verdict_map.get(zone, '🟢 harmless')
