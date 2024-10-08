# settings.py
import os
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())

class KEYS:
    TG_KEY: str = os.getenv("API_KEY_TG")
    VT_KEY: str = os.getenv("API_KEY_VT")
    GEOIP_KEY: str = os.getenv("API_GEOIP_KEY")
    KASPERSKY_KEY: str = os.getenv("API_KASPERSKY_KEY")
    ABUSEIPDB_KEY: str = os.getenv("API_ABUSEIPDB_KEY")
    CRIMINALIP_KEY: str = os.getenv("API_CRIMINALIP_KEY")


class URLS:

    API_URL_IP_VT: str = os.getenv("API_URL_IP_VT")
    API_URL_DOMAIN_VT: str = os.getenv("API_URL_DOMAIN_VT")
    API_URL_ABUSEIPDB: str = os.getenv("API_URL_ABUSEIPDB")
    API_URL_KASPERSKY: str = os.getenv("API_URL_KASPERSKY")
    API_URL_CRIMINALIP: str = os.getenv("API_URL_CRIMINALIP")

class DB:
    url: str = os.getenv("DB_URL")
