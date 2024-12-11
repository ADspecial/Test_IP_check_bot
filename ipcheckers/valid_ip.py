import re
from typing import List, Tuple

def is_valid_ip(ip: str) -> bool:
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)

def is_valid_dns(dns: str) -> bool:
    return (
        dns and
        '.' in dns and
        dns[-1] != '-' and
        all(
            part and part[0] != '-' and part[-1] != '-' and len(part) <= 63
            for part in dns.split('.')
        )
    )

def extract_and_validate(text: str) -> Tuple[List[str], List[str]]:
    """
    Extracts and validates IP addresses and DNS names from a given text.

    :param text: The input text
    :return: A tuple of two lists: the first contains the valid IP addresses, the second contains the valid DNS names
    """
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    dns_pattern = r'\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b'

    valid_ips = [ip for ip in re.findall(ip_pattern, text) if is_valid_ip(ip)]
    valid_dns = [dns for dns in re.findall(dns_pattern, text) if is_valid_dns(dns)]

    # Сортируем оба списка
    return valid_ips, valid_dns
