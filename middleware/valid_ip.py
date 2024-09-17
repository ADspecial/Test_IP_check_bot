import re
import socket

def is_valid_ip(ip):
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or int(part) < 0 or int(part) > 255:
            return False
    return True

def is_valid_dns(dns):
    try:
        socket.inet_aton(dns)
        return False
    except socket.error:
        pass
    dns_pattern = r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$'
    return re.match(dns_pattern, dns) is not None

def extract_and_validate(text):
    ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    dns_pattern = r'\b[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'

    found_ips = re.findall(ip_pattern, text)
    found_dns = re.findall(dns_pattern, text)

    valid_ips = [ip for ip in found_ips if is_valid_ip(ip)]
    valid_dns = [dns for dns in found_dns if is_valid_dns(dns)]

    return valid_ips, valid_dns
