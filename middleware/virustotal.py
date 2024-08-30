import json
import flag
import urllib.request
import urllib.parse
import datetime

from middleware.config import KEYS, URLS
from middleware.valid_ip import extract_and_validate

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

def get_ip_list_info(text_ips):
    ips, dnss = extract_and_validate(text_ips)
    if not ips:
        print(f"No valid IPs or domains")
        return

    results = []
    for ip in ips:
        results.append(get_info_ip(ip))
    for dns in dnss:
        results.append(get_domain_info(dns))

    return results

def get_info_ip(text_ips):
    ips, dnss = extract_and_validate(text_ips)
    url = URLS.API_URL_IP_VT + urllib.parse.quote(ips[0])
    data = fetch_data(url)
    if not data:
        return

    attributes = data.get('data', {}).get('attributes', {})
    last_analysis_stats = attributes.get('last_analysis_stats', {})

    return gen_res(ip,attributes,last_analysis_stats)

def get_domain_info(domain):
    url = URLS.API_URL_DOMAIN_VT + urllib.parse.quote(domain)
    data = fetch_data(url)
    if not data:
        return f"Domain: {domain} - No data"

    attributes = data.get('data', {}).get('attributes', {})
    last_analysis_results = attributes.get('last_analysis_results', {})

    return gen_res(domain,attributes,last_analysis_results)

def gen_res(ip,attr,lar):
    result = {
        'verdict': None,
        'ip': ip,
        'network': attr.get('network'),
        #'whois': attributes.get('whois'),
        'owner': attr.get('as_owner'),
        'country': get_country_flag(attr.get('country')),
        'rep_score': attr.get('reputation'),
        'users_votes': {'🔴 malicious': attr.get('total_votes', {}).get('malicious', 0),
                        '🟢 harmless': attr.get('total_votes', {}).get('harmless', 0)},
        'stats': {  'total engines' : lar.get('malicious', 0) + lar.get('suspicious', 0)
                  + lar.get('harmless', 0) + lar.get('undetected', 0),
                    '🔴 malicious': lar.get('malicious', 0),
                    '🟡 suspicious': lar.get('suspicious', 0),
                    '🟢 harmless': lar.get('harmless', 0),
                    '⚫️ undetected': lar.get('undetected', 0)
                  },
        #'last_analysis_date': datetime.datetime.fromtimestamp(attr.get('last_analysis_date')).strftime('%Y-%m-%d %H:%M:%S')
    }
    malicious_votes = result['users_votes'].get('🔴 malicious', 0)
    malicious_stats = result['stats'].get('🔴 malicious', 0)
    if malicious_votes > 0 or malicious_stats > 0:
        result['verdict'] = '❌'
    else:
        result['verdict'] = '✅'
    return result

def get_country_flag(country_code):
    if country_code == None:
        return country_code
    else:
        return f"{flag.flag(country_code)} {country_code}"
