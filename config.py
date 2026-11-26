# file: config.py
import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    def __init__(self):
        self.reload()

    def reload(self):
        self.SOC_SERVER_IP = os.getenv("SOC_SERVER_IP", "192.168.1.64")
        self.SOC_PORT = int(os.getenv("SOC_PORT", "8080"))
        self.DB_PATH = os.getenv("SOC_DB_PATH", "trustaira_socaas.db")
        self.CACHE_TTL = int(os.getenv("CACHE_TTL", "15"))

        # SIEM & XDR
        self.ES_HOST = os.getenv("ES_HOST", "https://192.168.1.64:9200").rstrip("/")
        self.ES_API_KEY = os.getenv("ES_API_KEY", "")
        self.ES_VERIFY = os.getenv("ES_VERIFY", "false").lower() == "true"
        self.ES_ALERT_INDEX = os.getenv("ES_ALERT_INDEX", ".alerts-security.alerts-*")
        self.ES_LOG_INDEX = os.getenv("ES_LOG_INDEX", "*,-.*")

        self.V1_BASE_URL = os.getenv("V1_BASE_URL", "https://api.sg.xdr.trendmicro.com").rstrip("/")
        self.V1_API_KEY = os.getenv("V1_API_KEY", "")

        # 1. MULTI-CLOUD LLM & AI STUDIO CREDENTIALS
        self.ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
        self.OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
        self.GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
        self.GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
        self.GROK_API_KEY = os.getenv("GROK_API_KEY", "")
        self.BYTEZ_API_KEY = os.getenv("BYTEZ_API_KEY", "")

        # 2. THREAT INTELLIGENCE & OSINT CREDENTIALS
        self.SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
        self.ALIENVAULT_OTX_KEY = os.getenv("OTX_API_KEY", "")
        self.VIRUSTOTAL_API_KEY = os.getenv("VT_API_KEY", "")
        self.ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
        self.URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "")

        # 3. WORLD TELEMETRY
        self.OPENWEATHER_API_KEY = os.getenv("OPENWEATHER_API_KEY", "")
        self.REST_COUNTRIES_KEY = os.getenv("REST_COUNTRIES_KEY", "")
        self.NEWS_API_KEY = os.getenv("NEWS_API_KEY", "")
        self.EXCHANGERATE_API_KEY = os.getenv("EXCHANGERATE_API_KEY", "")

        # 4. REST ENDPOINT TEMPLATES
        self.SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}?key={key}"
        self.SHODAN_INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
        self.OTX_IP_PULSES_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        self.VT_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        self.MALWARE_BAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
        self.IP_API_GEOLOCATION_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,isp,org,as,hosting,lat,lon,query"
        self.OPEN_METEO_URL = "https://api.open-meteo.com/v1/forecast?latitude={lat}&longitude={lon}&current_weather=true"
        self.OPENWEATHER_URL = "https://api.openweathermap.org/data/2.5/weather?q={city}&appid={key}&units=metric"
        self.NEWS_API_HEADLINES_URL = "https://newsapi.org/v2/top-headlines?q={query}&pageSize=5&apiKey={key}"
        self.EXCHANGERATE_URL = "https://v6.exchangerate-api.com/v6/{key}/latest/{base}"
        self.REST_COUNTRIES_URL = "https://restcountries.com/v3.1/name/{country}"


settings = Settings()