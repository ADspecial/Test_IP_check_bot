import json
import flag
import urllib.request
import urllib.parse

from includes.config import KEYS, URLS
from includes.valid import extract_and_validate

def get_country_flag(country_code):
    if country_code == None:
        return country_code
    else:
        return f"{country_code}-{flag.flag(country_code)}"

def fetch_data(url):
    request = urllib.request.Request(url, headers={'x-apikey': KEYS.VT_KEY})
    try:
        with urllib.request.urlopen(request) as response:
            data = json.load(response)
            return data
    except urllib.error.URLError as e:
        print(f"Failed to retrieve data: {e}")
        return None

def get_associated_domains(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions"
    request = urllib.request.Request(url, headers={'x-apikey': KEYS.VT_KEY})
    associated_domains = []
    try:
        with urllib.request.urlopen(request) as response:
            data = json.load(response)
            associated_domains.extend([res['attributes']['host_name'] for res in data.get('data', [])])
    except urllib.error.URLError as e:
        print(f"Failed to retrieve associated domains for {ip}: {e}")
    return associated_domains

def get_info_ip(ip):
    url = URLS.API_URL_IP_VT + urllib.parse.quote(ip)
    data = fetch_data(url)
    if not data:
        return

    attributes = data.get('data', {}).get('attributes', {})
    last_analysis_stats = attributes.get('last_analysis_stats', {})
    associated_domains = get_associated_domains(ip)
    mal =  last_analysis_stats.get('malicious', 0)
    check = '❌' if mal > 0 else '✅'

    result = [
        f"{check}"
        f"IP: {ip}",
        f"AS Owner: {attributes.get('as_owner')}",
        f"ASN: {attributes.get('asn')}",
        f"Continent: {attributes.get('continent')}",
        f"Country: {get_country_flag(attributes.get('country'))}",
        f"JARM: {attributes.get('jarm')}",
        f"Last Analysis Date: {attributes.get('last_analysis_date')}",
        f"Reputation Score: {attributes.get('reputation')}",
        f"Tags: {', '.join(attributes.get('tags', []))}",
        f"Total Votes: Harmless - {attributes.get('total_votes', {}).get('harmless', 0)}, Malicious - {attributes.get('total_votes', {}).get('malicious', 0)}",
        "Last Analysis Stats:",
        f"  Harmless: {last_analysis_stats.get('harmless', 0)}",
        f"  Malicious: {last_analysis_stats.get('malicious', 0)}",
        f"  Suspicious: {last_analysis_stats.get('suspicious', 0)}",
        f"  Timeout: {last_analysis_stats.get('timeout', 0)}",
        f"  Undetected: {last_analysis_stats.get('undetected', 0)}",
        f"Last HTTPS Certificate Date: {attributes.get('last_https_certificate_date')}",
        f"Last Modification Date: {attributes.get('last_modification_date')}",
        f"Network: {attributes.get('network')}",
        f"Regional Internet Registry: {attributes.get('regional_internet_registry')}",
        f"WHOIS: {attributes.get('whois')}",
        f"WHOIS Date: {attributes.get('whois_date')}",
        f"Associated Domains: {', '.join(associated_domains) if associated_domains else 'No associated domains'}",
        "-" * 40
    ]
    return result

def get_ip_list_info(text_ips):
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
    attributes = data.get('data', {}).get('attributes', {})
    last_analysis_results = attributes.get('last_analysis_results', {})
    malicious_count = sum(1 for result in last_analysis_results.values() if result['category'] == 'malicious')
    total_engines = len(last_analysis_results)
    reputation_score = f"{malicious_count}/{total_engines}" if total_engines > 0 else "N/A"
    check = '❌' if malicious_count > 0 else '✅'
    return f"{check} IP: {ip}, Country: {get_country_flag(attributes.get('country'))}, Last Analysis Results Count: {malicious_count}, Malicious Count: {malicious_count}, Total Engines: {total_engines}, Reputation Score: {reputation_score}"

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
    check = '❌' if malicious_count > 0 else '✅'
    return f"{check} Domain: {domain}, Country: {get_country_flag(attributes.get('country'))}, Last Analysis Results Count: {malicious_count}, Malicious Count: {malicious_count}, Total Engines: {total_engines}, Reputation Score: {reputation_score}"
