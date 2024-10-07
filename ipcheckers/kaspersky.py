import json
import aiohttp
import asyncio
import requests

from config.config import KEYS
from ipcheckers.format import get_country_flag

from typing import List, Dict, Union, Tuple
from datetime import datetime


from config.config import KEYS, URLS

async def make_request_kaspersky(ip: str):
    headers = {
        'x-api-key': KEYS.KASPERSKY_KEY
    }
    response = requests.request(method='GET', url=URLS.API_URL_KASPERSKY + "?request=" + ip, headers=headers).json()
    return gen_result(response)


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
    tasks = [make_request_kaspersky(ip) for ip in ips]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    filtered_results = [
        result for result in results if not isinstance(result, Exception)
    ]
    return True, filtered_results


def gen_result(response: Dict[str, Union[str, int]]) -> Dict[str, Union[str, int, datetime]]:
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
        'zone': response['Zone'],
        'last_changed_at': response["IpWhoIs"]['Net']['Changed'],
    }
    return result
