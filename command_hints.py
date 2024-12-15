from aiogram import Bot
from aiogram.types import BotCommand

async def set_bot_commands(bot: Bot):
    commands = [
        # Команды управления сетевыми устройствами (требуется права администратора)
        BotCommand(
            command="add_host",
            description="Добавить СУ: /add_host [name] [ip] [login=login] [password=pass] [api_token=token] [description] (админ)"
        ),
        BotCommand(
            command="delete_host",
            description="Удалить СУ: /delete_host [name|ip] (админ)"
        ),
        BotCommand(
            command="view_host",
            description="Просмотреть СУ: /view_host [all|<количество> <sec|min|hour|day|week>] (админ)"
        ),
        BotCommand(
            command="add_sechost",
            description="Добавить СУ: /add_sechost [name] [ip] [login] [password] [api_token] [description] (админ)"
        ),
        BotCommand(
            command="delete_sechost",
            description="Удалить СУ: /delete_sechost [name|ip] (админ)"
        ),
        BotCommand(
            command="view_sechost",
            description="Просмотреть СУ: /view_sechost [all|<количество> <sec|min|hour|day|week>] (админ)"
        ),

        # Команды управления черными списками (требуется права администратора)
        BotCommand(
            command="add_blocklist",
            description="Добавить ЧС: /add_blocklist [name] [ip_list] (админ)"
        ),
        BotCommand(
            command="view_blocklist",
            description="Просмотреть ЧС: /view_blocklist [all|int: time {sec, min, hour, day}] (админ)"
        ),
        BotCommand(
            command="delete_blocklist",
            description="Удалить ЧС: /delete_blocklist [names] (админ)"
        ),

        # Команды управления группами сетевыми устройствами (требуется права супер-администратора)
        BotCommand(
            command="add_group",
            description="Добавить группу СУ: /add_group [name] description=описание [имена или IP-адреса Security Hosts через пробел] (супер-админ)"
        ),
        BotCommand(
            command="delete_group",
            description="Удалить группу СУ: /delete_group [names] (супер-админ)"
        ),
        BotCommand(
            command="view_group",
            description="Просмотреть группы СУ: /view_group [all|int: time {sec, min, hour, day, week}] (супер-админ)"
        ),

        # Команды проверки IP-адресов (доступно всем пользователям)
        BotCommand(
            command="adbcheck",
            description="Проверить адреса в AbuseIPDB: /adbcheck <IP>"
        ),
        BotCommand(
            command="adbfile",
            description="Проверить адреса из файла в AbuseIPDB: /adbfile"
        ),
        BotCommand(
            command="alvcheck",
            description="Проверить адреса в AlienVault: /alvcheck <IP>"
        ),
        BotCommand(
            command="alvfile",
            description="Проверить адреса из файла в AlienVault: /alvfile"
        ),
        BotCommand(
            command="ipicheck",
            description="Проверить адреса в IPInfo: /ipicheck <IP>"
        ),
        BotCommand(
            command="ipifile",
            description="Проверить адреса из файла в IPInfo: /ipifile"
        ),
        BotCommand(
            command="ipqscheck",
            description="Проверить адреса в IPQualityScore: /ipqscheck <IP>"
        ),
        BotCommand(
            command="ipqsfile",
            description="Проверить адреса из файла в IPQualityScore: /ipqsfile"
        ),
        BotCommand(
            command="kspcheck",
            description="Проверить адреса в Kaspersky: /kspcheck <IP>"
        ),
        BotCommand(
            command="kspfile",
            description="Проверить адреса из файла в Kaspersky: /kspfile"
        ),
        BotCommand(
            command="vtcheck",
            description="Проверить адреса в VirusTotal: /vtcheck <IP>"
        ),
        BotCommand(
            command="vtfile",
            description="Проверить адреса из файла в VirusTotal: /vtfile"
        ),
        BotCommand(
            command="check",
            description="Проверить адреса с помощью всех сервисов: /check <IP>"
        ),
        BotCommand(
            command="checkfile",
            description="Проверить адреса из файла с помощью всех сервисов: /checkfile"
        ),

        # Команды меню и навигации (доступно всем пользователям)
        BotCommand(
            command="start",
            description="Запустить бота: /start"
        ),
        BotCommand(
            command="menu",
            description="Показать основное меню: /menu"
        ),
        BotCommand(
            command="blockmenu",
            description="Меню блокировки IP: /blockmenu (админ)"
        ),
        BotCommand(
            command="blocklist_menu",
            description="Меню управления ЧС: /blocklist_menu (админ)"
        ),
        BotCommand(
            command="sechost_menu",
            description="Меню управления СУ: /sechost_menu (админ)"
        ),
        BotCommand(
            command="group_sechost_menu",
            description="Меню управления группами СУ: /group_sechost_menu (супер-админ)"
        ),
        BotCommand(
            command="rules_menu",
            description="Меню управления правилами: /rules_menu (супер-админ)"
        ),
        BotCommand(
            command="check_menu",
            description="Меню проверки адресов: /check_menu"
        ),

        # Команда справки (доступно всем пользователям)
        BotCommand(
            command="help",
            description="Справка по доступным командам"
        ),
    ]
    await bot.set_my_commands(commands)
