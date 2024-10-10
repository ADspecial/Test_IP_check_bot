# Проект Telegram-бота для администрирования сети
## Команды бота
### Основные команды
- `/start` — запуск бота и приветственное слово
- `/help` — справка
### Команды проверки адресов
- `/vtcheck` — проверка ip-адресов по базе VirusTotal
- `/vtfile` — проверка ip-адресов из txt файла

## Запуск
1. Получить API ключи:
- Ключ для доступа к Telegram API. В Telegram создайте новый бот и получите его токен.
- Ключ API для VirusTotal можно зарегистрировався на сайте https://www.virustotal.com/ru/
2. Создать файл в папке config `.env` в корне проекта и добавить в него следующие переменные окружения: API_KEY_TG, API_KEY_VT, API_URL_IP_VT, API_URL_DOMAIN_VT,API_GEOIP_KEY, API_KASPERSKY_KEY,
DB_URL
3. Создать виртуальное окружение и установить зависимости: `pip install -r requirements.txt`
4. Запустить бота через контейнеры в папке docker `docker-compose up`

## Технологии

- Python
- Telegram Bot API
- Postgresql

## Идеи для дальнейшего улучшения

-
-
-
-

## Деплой

[Описание того, как можно развернуть бота на сервере](DEPLOY.md)
