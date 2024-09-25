import json
import flag
import urllib.request
import urllib.parse
import datetime
from config.config import KEYS, URLS
from ipcheckers.valid_ip import extract_and_validate

def fetch_data(url):
    request = urllib.request.Request(url, headers={'x-apikey': KEYS.VT_KEY})
    with urllib.request.urlopen(request) as response:
        return json.load(response) if response.getcode() == 200 else None

def get_associated_domains(ip):
    url = f"{URLS.API_URL_IP_VT}/{ip}/resolutions"
    request = urllib.request.Request(url, headers={'x-apikey': KEYS.VT_KEY})
    try:
        with urllib.request.urlopen(request) as response:
            return [
                res['attributes']['host_name']
                for res in json.load(response)['data']
                if 'attributes' in res and 'host_name' in res['attributes']
            ]
    except urllib.error.URLError as e:
        print(f"Failed to retrieve associated domains for {ip}: {e}")
        return []

def get_vt_info(text_ips):
    ips, dnss = extract_and_validate(text_ips)
    if not ips and not dnss:
        print(f"No valid IPs or domains")
        return

    results = []
    ip_info_tasks = [get_ip_info(ip) for ip in ips]
    domain_info_tasks = [get_domain_info(dns) for dns in dnss]

    for task in ip_info_tasks + domain_info_tasks:
        result = task
        if result:
            results.append(result)

    return results

def get_ip_info(ip):
    url = URLS.API_URL_IP_VT + urllib.parse.quote(ip)
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
    last_analysis_stats = attributes.get('last_analysis_stats', {})

    return gen_res(domain,attributes,last_analysis_stats)

def gen_res(ip, attr, lar):
    result = {
        'verdict': 'False' if lar.get('malicious', 0) + attr.get('total_votes', {}).get('malicious', 0) > 0 else 'True',
        'ip': ip,
        'network': attr.get('network'),
        'owner': attr.get('as_owner'),
        'country': get_country_flag(attr.get('country')),
        'rep_score': attr.get('reputation'),
        'users_votes': {'malicious': attr.get('total_votes', {}).get('malicious', 0),
                        'harmless': attr.get('total_votes', {}).get('harmless', 0)},
        'stats': {'total engines' : sum(lar.values()),
                  **{k: v for k, v in lar.items() if k in {'malicious', 'suspicious', 'harmless', 'undetected'}}},
        'last_analysis_date': get_date(attr.get('last_analysis_date'))
    }
    return result

def get_country_flag(country_code):
    if country_code == None:
        return country_code
    else:
        return f"{flag.flag(country_code)} {country_code}"

def get_date(value):
    return value and datetime.datetime.utcfromtimestamp(value).strftime('%Y-%m-%d %H:%M:%S') or 'None'
