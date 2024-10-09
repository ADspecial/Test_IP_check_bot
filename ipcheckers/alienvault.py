import json
import aiohttp
import asyncio
import requests

from config.config import KEYS
from ipcheckers.format import get_country_flag

from typing import List, Dict, Union, Tuple
from datetime import datetime, timedelta

from config.config import KEYS, URLS


async def make_request_alienvault(ip_address: str, endpoint="general"):
    headers = {
        'Accept': 'application/json',
        'Key': KEYS.ALIENVAULT_KEY
    }
    response = requests.request(method='GET', url=(URLS.API_URL_ALIENVAULT+ip_address+"/"+endpoint), headers=headers).json()
    return gen_result(response)

async def get_alienvault_info(
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
    tasks = [make_request_alienvault(ip) for ip in ips]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    filtered_results = [
        result for result in results if not isinstance(result, Exception)
    ]
    return True, filtered_results

def gen_result(response: Dict[str, Union[str, int]]) -> Dict[str, Union[str, int, datetime]]:
    tags = 'None'
    otx_30days = False
    otx_historical = False

    if "pulse_info" in response and "pulses" in response["pulse_info"]:
        pulses = response["pulse_info"]["pulses"]

        if pulses:
            tags = ', '.join({tag for pulse in pulses for tag in pulse.get("tags", [])})

            modified_dates = []
            for pulse in pulses:
                modified = pulse.get("modified")
                if modified:
                    modified_dates.append(datetime.strptime(modified[:10], "%Y-%m-%d"))

            if modified_dates:
                max_modified = max(modified_dates)
                otx_30days = max_modified >= datetime.now() - timedelta(days=30)
                otx_historical = max_modified < datetime.now() - timedelta(days=30)

    if otx_30days or ("brute" or "ssh" or "attack" or "botnet" or "scan" or "malicious") in ''.join(tag.lower() for tag in tags):
        verdict = "🔴 malicious"
    elif otx_historical:
        verdict = "🟡 suspicious"
    else:
        verdict = "🟢 harmless"
    result = {
        'ip_address': response.get('indicator', 'Unknown'),
        'country': get_country_flag(response.get('country_code', 'Unknown')),
        'asn': response.get('asn', 'Unknown'),
        'verdict': verdict
    }

    return result
