# settings.py
import os
from dotenv import load_dotenv

load_dotenv()

TG_KEY = os.getenv("API_KEY_TG")
VT_KEY = os.getenv("API_KEY_VT")
API_URL_IP_VT = os.getenv("API_URL_IP_VT")
