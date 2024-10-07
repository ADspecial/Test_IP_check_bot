import json
import requests
from ipaddress import ip_address
from ipcheckers.geo_ip import get_geo_response
from config.config import KEYS
from ipcheckers.valid_ip import extract_and_validate

import aiohttp
from aiohttp import ClientSession
import asyncio
from typing import List, Dict, Union, Tuple
from datetime import datetime

from config.config import KEYS, URLS
from ipcheckers.format import get_country_flag


async def make_request_kaspersky(ip: str, session: ClientSession):
    headers = {
        'x-api-key': KEYS.KASPERSKY_KEY
    }
    async with session.get(URLS.API_URL_KASPERSKY+"?request="+ip, headers=headers) as response:
        return json.loads(await response.text()) if response.status == 200 else None


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
    async with aiohttp.ClientSession() as session:
        tasks = [make_request_kaspersky(ip, session) for ip in ips]
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
        "ip_address": response["ipAddress"],
        "is_public": response["isPublic"],
        "ip_version": response["ipVersion"],
        "is_whitelisted": response["isWhitelisted"],
        "abuse_confidence_score": response["abuseConfidenceScore"],
        "country": get_country_flag(response["countryCode"]),
        "usage_type": response["usageType"],
        "isp": response["isp"],
        "domain": response["domain"],
        "total_reports": response["totalReports"],
        "num_distinct_users": response["numDistinctUsers"],
        #"last_reported_at":response.get("lastReportedAt")
    }
    return result
