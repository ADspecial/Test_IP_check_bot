import ipinfo
import flag
import datetime

from config.config import KEYS

from typing import List, Dict, Union, Tuple

def format_dict(data):
    formatted_string = "🌐"

    for key, value in data.items():
        if key in ['country_flag_url', 'country_flag', 'country_currency', 'isEU', 'loc']:
            continue
        if key == 'country':
            formatted_string += f"{key.capitalize()}: {value}-{flag.flag(value)}\n"
            continue
        if isinstance(value, dict):
            formatted_string += f"{key.capitalize()}:\n"
            for sub_key, sub_value in value.items():
                formatted_string += f"  {sub_key.capitalize()}: {sub_value}\n"
        else:
            formatted_string += f"{key.capitalize()}: {value}\n"

    return formatted_string.strip()

async def get_ipi_info(
    ips: List[str], dnss: List[str]
    ) -> Tuple[bool, List[Dict[str, Union[str, int, datetime.datetime]]]]:
    """
    Получает информацию об IP-адресе из ipinfo.io

    Аргументы:
        ips (List[str]): Список IP-адресов

    Возвращает:
        Tuple[bool, List[Dict[str, Union[str, int, datetime.datetime]]]]: Кортеж, содержащий флаг успеха и список словарей с информацией об IP-адресе
    """
    try:
        handler = ipinfo.getHandler(KEYS.GEOIP_KEY)
        return True, [handler.getDetails(ip).all for ip in ips]
    except Exception as e:
        print(e)
        return  False, None
