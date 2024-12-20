import aiohttp
from aiohttp import ClientSession
import json
import asyncio
from typing import List, Dict, Union, Tuple
from datetime import datetime

from config.config import KEYS, URLS
from handlers.format import get_country_flag


async def make_request_abuse(
    session: ClientSession, ip: str
) -> Dict[str, Union[str, int, datetime]]:
    """
    Makes a request to AbuseIPDB API and returns a dictionary with the response data.

    Args:
        session: Aiohttp session object.
        ip: IP address to query.

    Returns:
        A dictionary with the response data.
    """
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }
    headers = {
        'Accept': 'application/json',
        'Key': KEYS.ABUSEIPDB_KEY
    }
    async with session.get(URLS.API_URL_ABUSEIPDB, headers=headers, params=querystring) as response:
        return gen_result(json.loads(await response.text())['data'])


async def get_abuseipdb_info(
    ips: List[str], dnss: List[str]
) -> Tuple[bool, List[Dict[str, Union[str, int, datetime]]]]:
    """
    Gets data from AbuseIPDB for given IP addresses.

    Args:
        ips: A list of IP addresses.

    Returns:
        A tuple containing a boolean indicating success and a list of dictionaries containing the response data.
    """
    async with aiohttp.ClientSession() as session:
        ip_info_tasks = [make_request_abuse(session, ip) for ip in ips]
        results = await asyncio.gather(*ip_info_tasks, return_exceptions=True)
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
        "verdict": determine_verdict_abuseipdb(response["abuseConfidenceScore"], response["totalReports"])
    }
    return result

def determine_verdict_abuseipdb(confidence_score: int, total_reports: int) -> str:
    verdict = '🟢 harmless'
    if (confidence_score > 60 and total_reports > 0) or total_reports > 10: verdict   = "🔴 malicious"
    elif (confidence_score > 20) or total_reports > 3: verdict = "🟡 suspicious"
    elif confidence_score == 0: verdict = "⚫️ undetected"

    return verdict
