import datetime
from typing import Dict, Any, List, Union, Literal,  Optional
from tabulate import tabulate
import textwrap

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

async def block_output(blocked_addreses):
    output = []

    # Проверяем и добавляем заблокированные адреса
    if blocked_addreses:
        accepted_str = "\n".join(blocked_addreses)
        output.append("**Следующие адреса были успешно заблокированы:**\n```\n" + accepted_str + "\n```\n")

    # Возвращаем объединенный вывод или сообщение о том, что нет информации
    return "\n".join(output) if output else "Ошибка! Нет информации о заблокированных адресах."

def escape_markdown(text: str) -> str:
    """
    Экранирует специальные символы Markdown, кроме * и `.

    :param text: Исходный текст.
    :return: Текст с экранированными специальными символами.
    """
    special_chars = r'_[]()~>#+-=|{}.!'
    for char in special_chars:
        text = text.replace(char, f'\\{char}')
    return text

async def blocklist_info(blocklist_info: list[dict], time: str = None, timeparam: str = "дней") -> str:
    """
    Форматирует информацию о блокировочных списках.

    :param blocklist_info: Список словарей с информацией о блокировочных списках.
    :param time: Время (или описание периода) для отображения в заголовке.
    :param timeparam: Единицы измерения времени, например 'дней' или 'всего периода'.
    :return: Строка с отформатированной информацией о блокировочных списках.
    """
    if not blocklist_info:
        return "Нет блокировочных списков за указанный период."

    # Заголовок с проверкой на параметр времени
    if time and time != "all":
        result = [f"Блоклисты за последние {time} {timeparam}:", "--------------------------------------------"]
    else:
        result = ["Блоклисты за весь период:", "--------------------------------------------"]

    # Форматируем данные для текстового отображения
    for blocklist in blocklist_info:
        name = blocklist['name'] if blocklist['name'] else 'Нет имени'
        username = f"@{blocklist['username']}" if blocklist['username'] else 'Нет автора'
        updated = blocklist['updated'].strftime("%d.%m.%Y %H:%M:%S") if blocklist['updated'] else 'Нет времени'
        description = blocklist['description'] if blocklist['description'] else 'Нет описания'
        addresses = "\n".join(blocklist['addresses']) if blocklist['addresses'] else 'Нет адресов'

        result.append(f"**{name}**")
        result.append(f"Автор - {username}")
        result.append(f"Время создания - {updated}")
        result.append(f"Описание - {description}")
        result.append("```" + "\n".join(blocklist['addresses']) + "```")
        result.append("--------------------------------------------")

    return "\n".join(result)


async def delete_blocklist_info(success_names, error_names) -> str:
    response_lines = []
    if success_names:
        response_lines.append("Были удалены следующие блоклисты:")
        response_lines.append("```\n" + "\n".join(success_names) + "\n```")

    if error_names:
        response_lines.append("Следующие блоклисты не были найдены:")
        response_lines.append("```\n" + "\n".join(error_names) + "\n```")

    if response_lines:
        return "\n".join(response_lines)
    else:
        return "Не было удалено ни одного блоклиста."

async def sechost_output(data):
    output = []

    # Проверяем и добавляем заблокированные адреса
    if data:
        accepted_str = "\n".join(data)
        output.append("**Был добавлен СЗИ:**\n```\n" + accepted_str + "\n```\n")

    # Возвращаем объединенный вывод или сообщение о том, что нет информации
    return "\n".join(output) if output else "Ошибка! Не был добавлен СЗИ."

async def delete_sechost_info(success_hosts: List[str], error_hosts: List[str]) -> str:
    response_lines = []

    if success_hosts:
        response_lines.append("Были удалены следующие СЗИ:")
        response_lines.append("```\n" + "\n".join(success_hosts) + "\n```")

    if error_hosts:
        response_lines.append("Следующие СЗИ не были найдены:")
        response_lines.append("```\n" + "\n".join(error_hosts) + "\n```")

    if response_lines:
        return "\n".join(response_lines)
    else:
        return "Не было удалено ни одного СЗИ."

async def sechost_info(sechost_info: List[Dict], time: Optional[str] = None, timeparam: str = "дней") -> str:
    """
    Форматирует информацию о СЗИ для отображения в виде таблицы с разметкой для Telegram.

    :param sechost_info: Список словарей с информацией о СЗИ.
    :param time: Время (или описание периода) для отображения в заголовке.
    :param timeparam: Единицы измерения времени, например 'дней' или 'всего периода'.
    :return: Строка с отформатированной табличной информацией о СЗИ.
    """
    if not sechost_info:
        return "Нет записей о СЗИ за указанный период."

    # Заголовок с проверкой на параметр времени
    if time and time != "all":
        result = [f"Информация о СЗИ за последние {time} {timeparam}:"]
    else:
        result = ["Информация о СЗИ за весь период:"]

    # Формируем данные для табличного отображения
    table_data = []
    headers = ["Имя", "Описание", "Адрес", "Группы", "Правила"]

    for sechost in sechost_info:
        name = sechost['name'] if sechost['name'] else 'Нет имени'
        address = sechost['address'] if sechost['address'] else 'Нет адреса'
        description = textwrap.fill(sechost['description'], width=20) if sechost['description'] else 'Нет описания'
        groups = '\n'.join(textwrap.fill(group, width=15) for group in sechost['groups']) if sechost['groups'] else 'Нет групп'
        rules = '\n'.join(textwrap.fill(rule, width=15) for rule in sechost['rules']) if sechost['rules'] else 'Нет правил'
        table_data.append([name, description, address, groups, rules])

    # Форматируем таблицу с использованием tabulate
    table = tabulate(table_data, headers=headers, tablefmt="grid")

    result.append(f"\n```{table}```")

    return "\n".join(result)

async def group_sechost_info(group_sechost_info: list[dict], time: str = None, timeparam: str = "дней") -> str:
    """
    Форматирует информацию о группах СЗИ для отображения в виде таблицы с разметкой для Telegram.

    :param group_sechost_info: Список словарей с информацией о группах СЗИ.
    :param time: Время (или описание периода) для отображения в заголовке.
    :param timeparam: Единицы измерения времени, например 'дней' или 'всего периода'.
    :return: Строка с отформатированной табличной информацией о группах СЗИ.
    """
    if not group_sechost_info:
        return "Нет записей о группах СЗИ за указанный период."

    # Заголовок с проверкой на параметр времени
    if time and time != "all":
        result = [f"Информация о группах СЗИ за последние {time} {timeparam}:"]
    else:
        result = ["Информация о группах СЗИ за весь период:"]

    # Формируем данные для табличного отображения
    table_data = []
    headers = ["Имя группы", "Описание", "Хосты СЗИ"]

    for group in group_sechost_info:
        name = group['name'] if group['name'] else 'Нет имени'
        description = group['description'] if group['description'] else 'Нет описания'
        hosts = "\n".join(group['security_hosts']) if group['security_hosts'] else 'Нет хостов'
        table_data.append([name, description, hosts])

    # Форматируем таблицу с использованием tabulate
    table = tabulate(table_data, headers=headers, tablefmt="grid")

    result.append(f"```\n{table}\n```")

    return "\n".join(result)

async def delete_group_sechost_info(success_names: list[str], error_names: list[str]) -> str:
    response_lines = []
    if success_names:
        response_lines.append("Были удалены следующие группы:")
        response_lines.append("```\n" + "\n".join(success_names) + "\n```")

    if error_names:
        response_lines.append("Следующие группы не были найдены:")
        response_lines.append("```\n" + "\n".join(error_names) + "\n```")

    if response_lines:
        return "\n".join(response_lines)
    else:
        return "Не было удалено ни одной группы безопасности."
