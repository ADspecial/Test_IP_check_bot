import re
import socket
import os
import csv
import json
import flag
import urllib.request
import urllib.parse
from datetime import datetime
from includes.config import KEYS, URLS
from includes.IPinfo.geo_ip import get_geo_response

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
        socket.inet_aton(dns)  # Проверка, что это не IP-адрес
        return False
    except socket.error:
        pass

    # Проверка на корректность DNS-имени
    dns_pattern = r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$'
    return re.match(dns_pattern, dns) is not None

def fetch_data(url):
    request = urllib.request.Request(url, headers={'x-apikey': KEYS.VT_KEY})
    try:
        with urllib.request.urlopen(request) as response:
            data = json.load(response)
            return data
    except urllib.error.URLError as e:
        print(f"Failed to retrieve data: {e}")
        return None

def check_ip_list(text_ips):
    ips, dnss = extract_and_validate(text_ips)
    if not ips:
        print(f"No valid IPs or domains")
        return

    results = []
    for ip in ips:
        results.append(get_ip_summary(ip))
    for dns in dnss:
        results.append(get_domain_summary(dns))

    return results

def get_ip_summary(ip):
    url = URLS.API_URL_IP_VT + urllib.parse.quote(ip)
    data = fetch_data(url)
    if not data:
        return f"IP: {ip} - No data"
    country = get_geo_response(ip)
    attributes = data.get('data', {}).get('attributes', {})
    last_analysis_results = attributes.get('last_analysis_results', {})
    malicious_count = sum(1 for result in last_analysis_results.values() if result['category'] == 'malicious')
    total_engines = len(last_analysis_results)
    reputation_score = f"{malicious_count}/{total_engines}" if total_engines > 0 else "N/A"
    if malicious_count > 0:
        check = '❌'
    else:
        check = '✅'
    return f"{check} IP: {ip}, Country: {country} {flag.flag(attributes.get('country'))}, Last Analysis Results Count: {malicious_count}, Malicious Count: {malicious_count}, Total Engines: {total_engines}, Reputation Score: {reputation_score}"

def get_domain_summary(domain):
    url = URLS.API_URL_DOMAIN_VT + urllib.parse.quote(domain)
    data = fetch_data(url)
    if not data:
        return f"Domain: {domain} - No data"

    attributes = data.get('data', {}).get('attributes', {})
    last_analysis_results = attributes.get('last_analysis_results', {})
    malicious_count = sum(1 for result in last_analysis_results.values() if result['category'] == 'malicious')
    total_engines = len(last_analysis_results)
    reputation_score = f"{malicious_count}/{total_engines}" if total_engines > 0 else "N/A"
    if malicious_count > 0:
        check = '❌'
    else:
        check = '✅'
    return f"{check} Domain: {domain}, Country: {attributes.get('country')}, Last Analysis Results Count: {malicious_count}, Malicious Count: {malicious_count}, Total Engines: {total_engines}, Reputation Score: {reputation_score}"

def extract_and_validate(text):
    ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    dns_pattern = r'\b[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'

    found_ips = re.findall(ip_pattern, text)
    found_dns = re.findall(dns_pattern, text)

    valid_ips = [ip for ip in found_ips if is_valid_ip(ip)]
    valid_dns = [dns for dns in found_dns if is_valid_dns(dns)]

    return valid_ips, valid_dns
