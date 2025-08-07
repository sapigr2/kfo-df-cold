"""
Crypto Sentinel Scanner — самый мощный Python-инструмент, объединяющий:
- Анализ активности кошельков (cold/warm)
- Мониторинг крупных транзакций (whale alert)
- Обнаружение подозрительных токенов (scam drop detector)
- Уведомления на email и Telegram

Авторизация через Etherscan API. Поддержка CLI-параметров.
"""

import requests
import argparse
import datetime
import smtplib
import ssl
from email.mime.text import MIMEText


ETHERSCAN_API = "https://api.etherscan.io/api"


def fetch_transactions(address, api_key, action="txlist"):
    params = {
        "module": "account",
        "action": action,
        "address": address,
        "startblock": 0,
        "endblock": 99999999,
        "sort": "desc",
        "apikey": api_key
    }
    r = requests.get(ETHERSCAN_API, params=params)
    return r.json().get("result", [])


def analyze_wallet_activity(txs, months_idle=12):
    if not txs:
        return "🔒 Кошелёк пуст или неактивен."
    last_tx = txs[0]
    timestamp = int(last_tx["timeStamp"])
    last_active_date = datetime.datetime.utcfromtimestamp(timestamp)
    now = datetime.datetime.utcnow()
    delta = now - last_active_date

    if delta.days >= months_idle * 30:
        return f"🧊 Кошелёк холодный (неактивен более {months_idle} мес.): {last_active_date.strftime('%Y-%m-%d')}"
    else:
        return f"🔥 Кошелёк активен. Последняя активность: {last_active_date.strftime('%Y-%m-%d')} ({delta.days} дней назад)"


def detect_large_transactions(txs, min_eth=100):
    results = []
    for tx in txs:
        eth_value = int(tx["value"]) / 1e18
        if eth_value >= min_eth:
            results.append({
                "from": tx["from"],
                "to": tx["to"],
                "value": eth_value,
                "hash": tx["hash"],
                "timestamp": datetime.datetime.utcfromtimestamp(int(tx["timeStamp"])).strftime("%Y-%m-%d %H:%M:%S")
            })
    return results


def detect_scam_airdrops(txs):
    suspicious = []
    for tx in txs:
        from_addr = tx["from"].lower()
        token_name = tx.get("tokenName", "").lower()
        if from_addr.startswith("0x000") or "airdrop" in token_name or "claim" in token_name:
            suspicious.append({
                "token": tx.get("tokenName", ""),
                "from": from_addr,
                "to": tx["to"],
                "value": tx.get("value"),
                "hash": tx["hash"]
            })
    return suspicious


def send_email_notification(subject, body, sender, password, recipient):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = recipient

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
        server.login(sender, password)
        server.sendmail(sender, recipient, msg.as_string())


def send_telegram_message(token, chat_id, message):
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    requests.post(url, data={"chat_id": chat_id, "text": message})


def main():
    parser = argparse.ArgumentParser(description="Crypto Sentinel Scanner — защита и мониторинг Ethereum-кошельков.")
    parser.add_argument("address", help="Ethereum-адрес")
    parser.add_argument("api_key", help="Etherscan API Key")
    parser.add_argument("--min_eth", type=float, default=100, help="Порог крупной транзакции (ETH)")
    parser.add_argument("--months_idle", type=int, default=12, help="Сколько месяцев считать кошелёк 'cold'")
    parser.add_argument("--email", help="Email получателя (опционально)")
    parser.add_argument("--email_pass", help="Пароль почты отправителя")
    parser.add_argument("--email_from", help="Email отправителя")
    parser.add_argument("--telegram_token", help="Telegram Bot Token")
    parser.add_argument("--telegram_chat", help="Telegram Chat ID")
    args = parser.parse_args()

    print("📡 Сканируем адрес:", args.address)

    normal_txs = fetch_transactions(args.address, args.api_key)
    token_txs = fetch_transactions(args.address, args.api_key, action="tokentx")

    report = []

    # Анализ активности
    activity = analyze_wallet_activity(normal_txs, args.months_idle)
    report.append(activity)

    # Анализ whale-транзакций
    whales = detect_large_transactions(normal_txs, args.min_eth)
    report.append(f"🐳 Найдено {len(whales)} крупных транзакций.")
    for tx in whales:
        report.append(f"- {tx['timestamp']}: {tx['value']} ETH | {tx['from']} → {tx['to']}")

    # Airdrop scam
    scams = detect_scam_airdrops(token_txs)
    report.append(f"🚨 Обнаружено {len(scams)} подозрительных токенов.")
    for s in scams:
        report.append(f"- {s['token']} | от {s['from']} | хэш: {s['hash']}")

    full_report = "\n".join(report)
    print("\n📋 Отчёт:\n")
    print(full_report)

    if args.email and args.email_pass and args.email_from:
        send_email_notification("🛡 Crypto Sentinel Alert", full_report, args.email_from, args.email_pass, args.email)

    if args.telegram_token and args.telegram_chat:
        send_telegram_message(args.telegram_token, args.telegram_chat, full_report)


if __name__ == "__main__":
    main()
