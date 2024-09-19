import re

def is_valid_ip(ip):
    return all(0 <= int(part) <= 255 and part.isdigit() for part in ip.split('.'))
def is_valid_dns(dns):
    return dns and dns[-1] != '-' and all(
        part and part[0] != '-' and part[-1] != '-' and len(part) <= 63
        for part in dns.split('.')
    )

def extract_and_validate(text):
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    dns_pattern = r'\b[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.[A-Za-z]{2,}\b'

    return [
        ip for ip in re.findall(ip_pattern, text) if is_valid_ip(ip)
    ], [
        dns for dns in re.findall(dns_pattern, text) if is_valid_dns(dns)
    ]
