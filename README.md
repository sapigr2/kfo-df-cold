# Crypto Sentinel Scanner

**Crypto Sentinel Scanner** — суперутилита для безопасности и мониторинга Ethereum-кошельков.

---

## 🧠 Что умеет

- 🧊 Проверка активности кошелька (холодный / активный)
- 🐋 Обнаружение крупных переводов (whale transactions)
- 🎯 Фильтр фишинговых airdrop-токенов
- 📬 Уведомления на Email и Telegram

---

## 🚀 Быстрый старт

```bash
pip install -r requirements.txt
python crypto_sentinel.py <ETH_ADDRESS> <ETHERSCAN_API_KEY> --months_idle 12 --min_eth 100
```

Для уведомлений:

```bash
--email your@email.com --email_pass yourpass --email_from your@email.com
--telegram_token <bot_token> --telegram_chat <chat_id>
```

---

## 📦 Пример использования

```
python crypto_sentinel.py 0xABC... <API_KEY> --min_eth 200 --months_idle 18
```

---

## 📄 Лицензия

MIT
