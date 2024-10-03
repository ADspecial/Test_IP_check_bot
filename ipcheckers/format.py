import datetime
from typing import Dict, Any, List

import flag

def dict_to_string(data: Dict[str, Any], indent: int = 0) -> str:
    """
    Convert a dictionary to a string representation.

    Args:
        data: The dictionary to convert.
        indent: The number of spaces to indent each line.

    Returns:
        The string representation of the dictionary.
    """
    lines = []
    for key, value in data.items():
        lines.append(" " * indent + f"{key}: {value}" if not isinstance(value, dict)
            else " " * indent + f"{key}:")
        if isinstance(value, dict):
            lines.extend(" " * (indent + 2) + line
                for line in dict_to_string(value, indent + 2).splitlines())
    return "\n".join(lines)

def listdict_to_string_vt(data_list: List[Dict[str, Any]]) -> str:
    """
    Convert a list of dictionaries to a string representation.

    Args:
        data_list: The list of dictionaries to convert.

    Returns:
        The string representation of the list of dictionaries.
    """
    return "\n".join(dict_summary(data) for data in data_list)

def dict_summary(data):
    verdict = '✅' if data['verdict'] else '❌'
    ip = data['ip']
    country = data['country']
    stats = data['stats']

    malicious_count = stats.get('malicious', 0)
    suspicious_count = stats.get('suspicious', 0)
    harmless_count = stats.get('harmless', 0)
    undetected_count = stats.get('undetected', 0)

    summary = f"{verdict} IP: {ip} | Country: {country} \nMalicious: {malicious_count} \nHarmless: {harmless_count} \nSuspicious: {suspicious_count} \nUndetected: {undetected_count} \n ================ "

    return summary

def format_to_output_dict_vt(data):
    votes = data['users_votes']
    stats = data['stats']
    output = {
        'verdict': '❌' if data['verdict'] == False else '✅',
        'ip': data['ip'],
        'network': data['network'],
        'owner': data['owner'],
        'country': data['country'],
        'rep_score': data['rep_score'],
        'users_votes': {'🔴 malicious': votes['malicious'],
                        '🟢 harmless': votes['harmless']},
        'stats': {'total engines' : stats['total engines'],
                  '🔴 malicious' : stats['malicious'],
                  '🟡 suspicious' : stats['suspicious'],
                  '🟢 harmless' : stats['harmless'],
                  '⚫️ undetected' : stats['undetected']},
        'last_analysis_date': data['last_analysis_date']
    }
    return output

from typing import Dict

def format_to_output_dict_ipi(data: Dict[str, str]) -> Dict[str, str]:
    """
    Format a dictionary from ipinfo to a dictionary with the keys formatted for output.

    Args:
        data: A dictionary with the keys 'ip', 'country', 'region', 'city', 'org', and 'loc'.
            The values for these keys are strings.

    Returns:
        A dictionary with the same keys as the input, but with the values formatted for output.
    """
    output = {
        'header': '🌐',
        'ip': data['ip'],
        'country': get_country_flag(data['country']),
        'region': data['region'],
        'city': data['city'],
        'org': data['org'],
        'loc': data['loc'],
    }
    return output

def format_to_output_dict_adb(data: Dict[str, str]) -> Dict[str, str]:
    """
    Format a dictionary from ipinfo to a dictionary with the keys formatted for output.

    Args:
        data: A dictionary with the keys 'ip', 'country', 'region', 'city', 'org', and 'loc'.
            The values for these keys are strings.

    Returns:
        A dictionary with the same keys as the input, but with the values formatted for output.
    """
    output = {
        'header': '🚫',
        'ip_address': data['ip_address'],
        'country': data['country'],
        'abuse_confidence_score': data['abuse_confidence_score'],
        'total_reports': data['total_reports'],
        'num_distinct_users': data['num_distinct_users'],
        'last_reported_at': data['last_reported_at'],
    }
    return output



def listdict_to_string(data: List[Dict[str, str]]) -> str:
    """
    Преобразует список словарей в строку.

    Аргументы:
        data: Список словарей для преобразования. Каждый словарь должен иметь строковые ключи и значения.

    Возвращает:
        Строку, представляющую список словарей.
    """
    if not data:
        return "Нет данных"

    formatted_entries: List[str] = []

    for entry in data:
        # Проверяем наличие ключа 'header'
        header = entry.get('header', None)

        if header:
            # Если ключ 'header' существует, добавляем его значение
            formatted_entry = f"{header}\n" + '\n'.join(f"{key}: {value}" for key, value in entry.items() if key != 'header')
        else:
            # Если ключа 'header' нет, просто добавляем стандартный формат
            formatted_entry = "\n" + '\n'.join(f"{key}: {value}" for key, value in entry.items())

        formatted_entries.append(formatted_entry)

    # Объединяем все записи с разделителем
    result = '\n================\n'.join(formatted_entries)
    return result


def get_country_flag(country_code):
    if country_code == None:
        return country_code
    else:
        return f"{flag.flag(country_code)} {country_code}"

def get_date(value):
    return value and datetime.datetime.utcfromtimestamp(value).strftime('%Y-%m-%d %H:%M:%S') or 'None'
