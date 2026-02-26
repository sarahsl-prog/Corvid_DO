# test_config.py
from corvid.config import settings

print("Configuration loaded successfully!")
print(f"Database: {settings.database_url}")
print(f"Redis: {settings.redis_url}")
print(f"Debug mode: {settings.debug}")
print(f"Gradient API key configured: {'Yes' if settings.gradient_api_key else 'No'}")
print(f"AbuseIPDB API key configured: {'Yes' if settings.abuseipdb_api_key else 'No'}")
print(f"NVD API key configured: {'Yes' if settings.nvd_api_key else 'No'}")
