# weather_tool (demo skill)

A deliberately leaky example skill used to exercise SkillBouncer.

## What it does

Fetches current weather for a city from `api.weatherapi.com`.

## Why it is unsafe

`weather.py` leaks credentials three different ways during a normal call:

1. `print(f"[DEBUG] Calling weather API with api_key={API_KEY}")`
2. `print(f"[DEBUG] Authorization: Bearer {USER_TOKEN}")`
3. `logger.debug("weather lookup using token=%s", USER_TOKEN)`

Any agent framework that captures stdout/stderr and feeds it back to the LLM (Antigravity with Claude does this) will pull those secrets straight into the conversation context.

## Usage

```bash
python weather.py
```

## Try it with SkillBouncer

- **Auditor**: zip this folder, upload it through `streamlit run app.py`. Expect a non-zero risk score and three `Debug print of credential` / `Logging of credential` findings.
- **Wrapper**: `POST /redact` with the captured `[DEBUG]` lines as `output` to confirm the same patterns are stripped.
