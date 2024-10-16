import datetime
from typing import Dict, Any, List, Union, Literal

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

def format_to_output_dict_vt(data: Dict[str, str]) -> Dict[str, str]:

    # Объединяем строки с новой строки\
    stats_line = "\n"
    for key, value in data['stats'].items():
        stats_line += f"         - {key}: {value}\n"

    try:
        votes = data['votes']['malicious']/data['votes']['malicious']+data['votes']['harmless']
    except ZeroDivisionError:
        votes = 0

    output: Dict[str, str] = {
        'header': '🔷 Virustotal',
        'address': data['ip_address'],
        'country': data['country'],
        'verdict': data['verdict'],
        'network': data['network'],
        'owner': data['owner'],
        'reputationscore': data['rep_score'],
        'users votes': votes,
        'stats agregation': stats_line
    }
    return output

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
        'header': '🌐 IPinfo',
        'ip_address': data.get('ip_address') or data.get('ip'),
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
        'header': '⭕️ AbuseIPDB',
        'ip_address': data['ip_address'],
        'country': data['country'],
        'verdict': data['verdict'],
        'abuse_confidence_score': data['abuse_confidence_score'],
        'total_reports': data['total_reports'],
        'num_distinct_users': data['num_distinct_users'],
        #'last_reported_at': data['last_reported_at'],
    }
    return output

def format_to_output_dict_ksp(data: Dict[str, str]) -> Dict[str, str]:
    """
    Format a dictionary from ipinfo to a dictionary with the keys formatted for output.

    Args:
        data: A dictionary with the keys 'ip', 'country', 'region', 'city', 'org', and 'loc'.
            The values for these keys are strings.

    Returns:
        A dictionary with the same keys as the input, but with the values formatted for output.
    """
    output = {
        'header': '🟩 Kaspersky',
        'address': data['ip_address'],
        'country': data['country'],
        'verdict': data['verdict'],
        'status': data['status'],
        'net name': data['net_name'],
    }
    return output

def format_to_output_dict_cip(data: Dict[str, Union[str, List[Dict[str, Union[str, bool]]]]]) -> Dict[str, str]:
    """
    Format a dictionary from ipinfo to a dictionary with the keys formatted for output.

    Args:
        data: A dictionary with string keys and values that are either strings or lists of dictionaries.
            The dictionaries have string keys and values that are either strings or booleans.

    Returns:
        A dictionary with string keys and values that are strings.
    """
    output_lines = []
    for protocol, ports in data['open_ports'].items():
        output_lines.append(f"  {protocol}:")
        for port_info in ports:
            output_lines.append(f"      Port: {port_info['port']}, Vulnerability: {port_info['has_vulnerability']}")
        if not ports:  # Если список пустой
            output_lines.append("       No open ports")
    # Объединяем строки с новой строки
    output_ports = "\n".join(output_lines)

    output: Dict[str, str] = {
        'header': '🔎 CriminalIP',
        'ip address': data['ip_address'],
        'hostname': data['hostname'],
        'country': data['country'],
        'verdict': data['verdict'],
        'open_ports': '\n' + output_ports,
    }
    return output

def format_to_output_dict_alv(data: Dict[str, Union[str, List[Dict[str, Union[str, bool]]]]]) -> Dict[str, str]:
    """
    Format a dictionary from ipinfo to a dictionary with the keys formatted for output.

    Args:
        data: A dictionary with string keys and values that are either strings or lists of dictionaries.
            The dictionaries have string keys and values that are either strings or booleans.

    Returns:
        A dictionary with string keys and values that are strings.
    """
    output: Dict[str, str] = {
        'header': '👽 Alienvault',
        'ip address': data['ip_address'],
        'asn': data['asn'],
        'country': data['country'],
        'verdict': data['verdict'],
    }
    return output

def format_to_output_dict_ipqs(data: Dict[str, Union[str, List[Dict[str, Union[str, bool]]]]]) -> Dict[str, str]:
    """
    Format a dictionary from ipinfo to a dictionary with the keys formatted for output.

    Args:
        data: A dictionary with string keys and values that are either strings or lists of dictionaries.
            The dictionaries have string keys and values that are either strings or booleans.

    Returns:
        A dictionary with string keys and values that are strings.
    """
    output: Dict[str, str] = {
        'header': '🔥 IPQS',
        'ip address': data['ip_address'],
        'host': data['host'],
        'country': data['country'],
        'verdict': data['verdict'],
        'fraud_score': data['fraud_score'],
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
            formatted_entry = f"{header}\n" + '\n'.join(
                f"{key}: {value}" for key, value in entry.items()
                if key != 'header' and value is not None
            )
        else:
            # Если ключа 'header' нет, просто добавляем стандартный формат
            formatted_entry = "\n" + '\n'.join(
                f"{key}: {value}" for key, value in entry.items()
                if value is not None
            )

        # Добавляем только непустые записи
        if formatted_entry.strip():  # Проверка на пустую строку
            formatted_entries.append(formatted_entry)

    # Объединяем все записи с разделителем
    result = '\n=======================\n'.join(formatted_entries)
    return result

def get_country_flag(country_code):
    if country_code == None:
        return country_code
    else:
        return f"{flag.flag(country_code)} {country_code}"

def get_date(value):
    return value and datetime.datetime.utcfromtimestamp(value).strftime('%Y-%m-%d %H:%M:%S') or 'None'

def summary_format(data: Dict) -> str:
    # Создаем словарь для хранения информации по адресам
    address_info = {}
    # Подсчет статистики
    verdict_stats = {}

    # Обрабатываем данные
    for service, records in data.items():
        for record in records:
            ip_address = record.get('ip address') or record.get('address') or record.get('ip_address')
            verdict = record.get('verdict', '⚫️ undetected')

            # Добавляем информацию из IPinfo
            if service == 'Ipinfo':
                country = record.get('country', '⚫️ undetected')
                region = record.get('region', '⚫️ undetected')
                city = record.get('city', '⚫️ undetected')
                # Форматируем информацию о местоположении
                info = f"{country}, {region}, {city}"
            else:
                info = verdict

            if ip_address not in address_info:
                address_info[ip_address] = {}
                verdict_stats[ip_address] = {'malicious': 0, 'harmless': 0, 'suspicious': 0, 'undetected': 0}

            address_info[ip_address][service] = info

            # Подсчет вердиктов
            if verdict == '🔴 malicious':
                verdict_stats[ip_address]['malicious'] += 1
            elif verdict == '🟢 harmless':
                verdict_stats[ip_address]['harmless'] += 1
            elif verdict == '🟡 suspicious':
                verdict_stats[ip_address]['suspicious'] += 1
            elif verdict == '⚫️ undetected':
                verdict_stats[ip_address]['undetected'] += 1

    # Форматируем вывод в строку с табуляцией
    output = []
    for ip in address_info:
        output.append(f"Адрес {ip}: {address_info[ip].get('Ipinfo', '⚫️ undetected')}")  # Выводим информацию из IPinfo

        # Подсчет общего количества проверок
        total_checks = sum(verdict_stats[ip].values())
        malicious_count = verdict_stats[ip]['malicious']

        # Добавляем статистику вердиктов в формате {malicious}/{total_checks}
        stats_line = f"{malicious_count}/{total_checks-1}"
        output.append(f"\tСтатистика: {stats_line}")

        for service in ['Alienvault', 'Virustotal', 'Abuseipdb', 'Kaspersky', 'Ipqualityscore']:  # Убрали Criminalip
            command_line = {
                'Alienvault': f"[Подробнее](https://otx.alienvault.com/indicator/ip/{ip})",
                'Virustotal': f"[Подробнее](https://www.virustotal.com/gui/ip-address/{ip})",
                'Abuseipdb': f"[Подробнее](https://www.abuseipdb.com/check/{ip})",
                'Kaspersky': f"[Подробнее](https://opentip.kaspersky.com/{ip}/?tab=lookup)",
                'Ipqualityscore': f"[Подробнее](https://www.ipqualityscore.com/ip-lookup/search/{ip})"
            }

            verdict = address_info[ip].get(service, '⚫️ undetected')
            output.append(f"\t- {service}: {verdict} ({command_line[service]})")  # Добавлена команда
        output.append("")  # Пустая строка для разделения адресов

    return "\n".join(output)
