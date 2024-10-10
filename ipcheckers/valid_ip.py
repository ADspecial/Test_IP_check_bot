import re

def is_valid_ip(ip):
    return all(0 <= int(part) <= 255 and part.isdigit() for part in ip.split('.'))
def is_valid_dns(dns):
    return dns and dns[-1] != '-' and all(
        part and part[0] != '-' and part[-1] != '-' and len(part) <= 63
        for part in dns.split('.')
    )

from typing import List

def extract_and_validate(text: str) -> tuple[List[str], List[str]]:
    """
    Extracts IP addresses and DNS names from a string and validates them.

    Args:
        text: The string to extract from.

    Returns:
        A tuple of two lists: the first contains valid IP addresses, and the
        second contains valid DNS names.
    """
    ip_pattern = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
    dns_pattern = re.compile(r'\b[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.[A-Za-z]{2,}\b')

    ip_matches = ip_pattern.findall(text)
    dns_matches = dns_pattern.findall(text)

    return [
        ip for ip in ip_matches if is_valid_ip(ip)
    ], [
        dns for dns in dns_matches if is_valid_dns(dns)
    ]
