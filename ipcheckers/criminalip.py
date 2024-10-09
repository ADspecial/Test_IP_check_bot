import asyncio
import requests

from config.config import KEYS
from ipcheckers.format import get_country_flag

from typing import List, Dict, Union, Tuple, Literal
from datetime import datetime

from config.config import KEYS, URLS

async def make_request_criminalip(ip: str):
    headers = {
        'x-api-key': KEYS.CRIMINALIP_KEY
    }
    payload={}
    response = requests.request(method='GET', url=URLS.API_URL_CRIMINALIP + "?ip=" + ip, headers=headers, data=payload).json()
    return gen_result(ip, response)

async def get_criminalip_info(
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
    tasks = [make_request_criminalip(ip) for ip in ips]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    filtered_results = [
        result for result in results if not isinstance(result, Exception)
    ]
    return True, filtered_results

def gen_result(ip:str ,response: Dict[str, Union[str, int]]) -> Dict[str, Union[str, int, datetime]]:
    """
    Formats the response from AbuseIPDB to a dictionary with the required keys.

    Args:
        response: The response from AbuseIPDB.

    Returns:
        A dictionary with the response data.
    """
    result = {
        'ip_address': ip,
        'verdict': determine_verdict_criminalip(response['ip_scoring']['inbound'], response['ip_scoring']['outbound'], response['ip_scoring']['is_malicious']),
        'open_ports': response['current_open_ports'],
        'hostname': response['summary']['connection']['hostname'],
        'country': get_country_flag(response['summary']['connection']['country']),
    }
    return result

def determine_verdict_criminalip(
    inbound: Literal['Critical', 'Moderate', 'Low', 'Safe'],
    outbound: Literal['Critical', 'Moderate', 'Low', 'Safe'],
    is_malicious: bool
) -> Literal['🔴 malicious', '🟡 suspicious', '🟢 harmless', '⚫️ undetected']:
    """
    Определение вердикта на основе результатов CriminalIP

    Аргументы:
        inbound (Literal['Critical', 'Moderate', 'Low', 'Safe']):
            Оценка входящего трафика
        outbound (Literal['Critical', 'Moderate', 'Low', 'Safe']):
            Оценка исходящего трафика
        is_malicious (bool):
            Флаг, указывающий на то, является ли IP-адрес вредоносным

    Возвращает:
        Literal[' malicious', ' suspicious', ' harmless', ' undetected']:
            Вердикт, вынесенный на основе результатов
    """
    if is_malicious:
        return '🔴 malicious'

    # Определяем вердикт на основе значений inbound и outbound
    if inbound == 'Critical' or outbound == 'Critical':
        verdict = '🔴 malicious'
    elif inbound == 'Moderate' and outbound == 'Moderate':
        verdict = '🔴 malicious'
    elif (inbound == 'Low' and outbound == 'Moderate') or (inbound == 'Moderate' and outbound == 'Low'):
        verdict = '🟡 suspicious'
    elif inbound == 'Low' and outbound == 'Low':
        verdict = '🟡 suspicious'
    elif inbound == 'Safe' and outbound == 'Safe':
        verdict = '🟢 harmless'
    elif (inbound == 'Low' and outbound == 'Safe') or (inbound == 'Safe' and outbound == 'Low'):
        verdict = '🟡 suspicious'
    else:
        verdict = '⚫️ undetected'

    return verdict
