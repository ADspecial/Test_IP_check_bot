# settings.py
import os
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())

class KEYS:
    TG_KEY: str = os.getenv("API_KEY_TG")
    VT_KEY: str = os.getenv("API_KEY_VT")
    GEOIP_KEY: str = os.getenv("API_GEOIP_KEY")
    KS_KEY: str = os.getenv("API_KASPERSKY_KEY")


class URLS:
    API_URL_IP_VT: str = os.getenv("API_URL_IP_VT")
    API_URL_DOMAIN_VT: str = os.getenv("API_URL_DOMAIN_VT")

class DB:
    name: str = os.getenv("DB_NAME")
    user: str = os.getenv("DB_USER")
    password: str = os.getenv("DB_PASSWORD")
    host: str = os.getenv("DB_HOST")
    port: str = os.getenv("DB_PORT")
    url: str = os.getenv("DB_URL")
