import ipinfo
import flag

from includes.config import KEYS


def get_geo_ip(ip_address: str):# -> tuple(str, str):
    access_token = KEYS.GEOIP_KEY
    handler = ipinfo.getHandler(access_token)
    details = handler.getDetails(ip_address)
    return {"country_code": details.country, "country_name": details.country_name}


def get_geo_response(ip_address):
    output = ""
    try:
        geoip = get_geo_ip(ip_address)
        country_code, country_name = geoip["country_code"], geoip["country_name"]
        output += f"{flag.flag(country_code)} {country_name}"
    except Exception as e:
        print(e)
        output += f"bruh, it's looks like a local IP\n"
    return output
