import asyncio
import requests
import urllib

from config.config import KEYS
from handlers.format import get_country_flag, get_date

from typing import List, Dict, Union, Tuple, Literal
from datetime import datetime

from config.config import KEYS, URLS


async def make_request_virustotal(address: str, version: str):
    headers = {
        'x-apikey': KEYS.VT_KEY
    }
    if version == 'ip':
        url = URLS.API_URL_IP_VT + urllib.parse.quote(address)
    else:
        url = URLS.API_URL_DOMAIN_VT + urllib.parse.quote(address)
    response = requests.request(method='GET', url=url, headers=headers).json()
    return gen_result(response)


async def get_vt_info(
    ips: List[str], dnss: List[str]
) -> Tuple[bool, List[Dict[str, Union[str, int, datetime]]]]:
    """
    Получает данные из VirusTotal для заданных IP-адресов и доменов.

    Параметры:
        ips (List[str]): Список IP-адресов.
        dnss (List[str]): Список доменных имен.

    Возвращает:
        Tuple[bool, List[Dict[str, Union[str, int, datetime.datetime]]]]:
            Кортеж, содержащий булево значение, указывающее на успех,
            и список словарей, содержащих данные из VirusTotal для каждого
            IP-адреса и домена.
    """
    results = []
    ip_info_tasks = [make_request_virustotal(ip, 'ip') for ip in ips]
    domain_info_tasks = [make_request_virustotal(dns, 'domain') for dns in dnss]
    all_tasks = ip_info_tasks + domain_info_tasks
    results = await asyncio.gather(*all_tasks, return_exceptions=True)
    filtered_results = [
        result for result in results if not isinstance(result, Exception)
    ]
    return True, filtered_results


def gen_result(response: Dict[str, Union[str, int]]) -> Dict[str, Union[str, int, datetime]]:
    attr = response.get('data', {}).get('attributes', {})
    lar = attr.get('last_analysis_stats', {})
    result = {
        'ip_address': response.get('data').get('id'),
        'network': attr.get('network'),
        'owner': attr.get('as_owner'),
        'country': get_country_flag(attr.get('country')),
        'rep_score': attr.get('reputation'),
        'votes': attr.get('total_votes'),
        'stats': lar,
        'verdict': determine_verdict(attr.get('total_votes'), lar)
    }
    return result

def determine_verdict(votes: Dict, stats: Dict)-> Literal['🔴 malicious', '🟡 suspicious', '🟢 harmless', '⚫️ undetected']:
    if stats['malicious'] + votes['malicious'] >= 3:
        return '🔴 malicious'

    if stats['suspicious'] > 5:
        return '🟡 suspicious'

    total_stats = stats['malicious'] + stats['suspicious'] + stats['harmless'] + stats['undetected'] + stats['timeout']

    if stats['undetected'] == total_stats:
        return '⚫️ undetected'

    return '🟢 harmless'
