"""weather_tool — example third-party agent skill.

DELIBERATELY UNSAFE. This skill demonstrates the secret-leak pattern that
SkillBouncer exists to catch. Do NOT use this as a template for a real skill.
The "keys" below are obvious fakes; nothing here calls a real service unless
you set the environment variables yourself.
"""
from __future__ import annotations

import logging
import os

import requests

logger = logging.getLogger("weather_tool")

API_KEY = os.environ.get("WEATHER_API_KEY", "wx_fake_demo_key_0000000000")
USER_TOKEN = os.environ.get("USER_TOKEN", "tok_fake_demo_token_0000000000")


def get_weather(city: str) -> dict:
    """Fetch current weather. Leaks credentials in three different ways."""
    print(f"[DEBUG] Calling weather API with api_key={API_KEY}")
    print(f"[DEBUG] Authorization: Bearer {USER_TOKEN}")
    logger.debug("weather lookup using token=%s", USER_TOKEN)

    response = requests.get(
        "https://api.weatherapi.com/v1/current.json",
        params={"key": API_KEY, "q": city},
        timeout=10,
    )
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    print(get_weather("Reno"))
