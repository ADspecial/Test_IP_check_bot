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
    ALIENVAULT_KEY: str = os.getenv("API_ALIENVAULT_KEY")
    IPQS_KEY: str = os.getenv("API_IPQS_KEY")


class URLS:

    API_URL_IP_VT: str = os.getenv("API_URL_IP_VT")
    API_URL_DOMAIN_VT: str = os.getenv("API_URL_DOMAIN_VT")

    API_URL_IP_KASPERSKY: str = os.getenv("API_URL_IP_KASPERSKY")
    API_URL_DOMAIN_KASPERSKY: str = os.getenv("API_URL_DOMAIN_KASPERSKY")

    API_URL_ABUSEIPDB: str = os.getenv("API_URL_ABUSEIPDB")

    API_URL_IP_CRIMINALIP: str = os.getenv("API_URL_IP_CRIMINALIP")
    API_URL_DOMAIN_CRIMINALIP: str = os.getenv("API_URL_DOMAIN_CRIMINALIP")

    API_URL_ALIENVAULT: str = os.getenv("API_URL_ALIENVAULT")

    API_URL_IP_IPQS: str = os.getenv("API_URL_IP_IPQS")
    API_URL_DOMAIN_IPQS: str = os.getenv("API_URL_DOMAIN_IPQS")

class DB:
    url: str = os.getenv("DB_URL")
    mode: str = os.getenv("SSL_MODE")
    root_cert: str = os.getenv("SSL_ROOT_CERT")
    cert: str = os.getenv("SSL_CERT")
    key: str = os.getenv("SSL_KEY")


class CRYPT:
    PASSWORD_ENCRYPTION_KEY: str = os.getenv("ENCRYPTION_KEY_PASSWORD")
    LOGIN_ENCRYPTION_KEY: str = os.getenv("ENCRYPTION_KEY_LOGIN")
    API_TOKEN_ENCRYPTION_KEY: str = os.getenv("ENCRYPTION_KEY_API")
