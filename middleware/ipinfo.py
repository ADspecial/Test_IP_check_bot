import ipinfo
import flag

from middleware.config import KEYS
from middleware.valid_ip import extract_and_validate

def format_dict(data):
    formatted_string = "🌐"

    for key, value in data.items():
        if key in ['country_flag_url', 'country_flag', 'country_currency', 'isEU', 'loc']:
            continue
        if key == 'country':
            formatted_string += f"{key.capitalize()}: {value}-{flag.flag(value)}\n"
            continue
        if isinstance(value, dict):
            formatted_string += f"{key.capitalize()}:\n"
            for sub_key, sub_value in value.items():
                formatted_string += f"  {sub_key.capitalize()}: {sub_value}\n"
        else:
            formatted_string += f"{key.capitalize()}: {value}\n"

    return formatted_string.strip()

def get_info(text_ips: str):
    ips, dnss = extract_and_validate(text_ips)
    if not ips:
        return f"No valid IPs"
    else:
        try:
            results = []
            handler = ipinfo.getHandler(KEYS.GEOIP_KEY)
            for ip in ips:
                details = handler.getDetails(ip)
                results.append(format_dict(details.all))
            return '\n'.join(results)
        except Exception as e:
            print(e)
            return  f"bruh, it's looks like a error\n"
