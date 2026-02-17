# AI SOC Assistant (Telegram + Splunk + OpenAI)

Single-entry bot for security operations:
- You message the bot from your phone on Telegram.
- The bot runs Splunk queries via REST API.
- OpenAI summarizes risk and recommended actions.

## One-command start

```bash
cd /path/to/splunk_bot
chmod +x start.sh
./start.sh
```

`start.sh` automatically:
- creates `.venv` if missing
- installs dependencies
- starts the Telegram bot

## Keys expected (already in your setup)

- `~/keys/openaikey.json`
- `~/keys/telegramkey.json`
- `~/keys/subscribers.json`

Supported JSON key names:
- OpenAI: `OPENAI_API_KEY` (or `key`, `api_key`)
- Telegram: `key` (or `TELEGRAM_BOT_TOKEN`, `token`)
- Subscribers: JSON array of Telegram user IDs, e.g. `[12345, 67890]`

## Splunk connection

Defaults:
- URL: `https://localhost:8089`
- user: `admin`
- password: `changeme`
- TLS verify: disabled (good for local/self-signed lab)

Override using environment variables:

```bash
export SPLUNK_BASE_URL="https://127.0.0.1:8089"
export SPLUNK_USERNAME="admin"
export SPLUNK_PASSWORD="your_password"
export SPLUNK_VERIFY_TLS="false"
./start.sh
```

Optional file override:
- `~/keys/splunk.json`

## Telegram commands

- `/start`
- `/help`
- `/failed_logins 30m`
- `/errors 15m`
- `/suspicious_process 1h`
- `/ask is there anything suspicious in the last hour?`

You can also send plain text questions directly (same behavior as `/ask`).

## Notes

- Only Telegram users listed in `subscribers.json` can use the bot.
- Query result rows are capped and summarized for Telegram-friendly output.
- Splunk job SID is returned with each response for traceability.

