#Точка входа

import sys;
from includes.settings import *;
from includes.single_ip import ip_info
from includes.ip_list import process_ip_list
import asyncio
import logging
from aiogram import Bot, Dispatcher, types
from aiogram.filters.command import Command
import vt;


# Ensure the output directories exist
def ensure_directories():
    os.makedirs('output/single-ip', exist_ok=True)
    os.makedirs('output/single-domain', exist_ok=True)
    os.makedirs('output/domain-ip-lists', exist_ok=True)

#print(API_URL_IP_VT)
#print(VT_KEY)

# Включаем логирование, чтобы не пропустить важные сообщения
logging.basicConfig(level=logging.INFO)
# Объект бота
bot = Bot(token=TG_KEY)
# Диспетчер
dp = Dispatcher()

# Хэндлер на команду /start
@dp.message(Command("start"))
async def cmd_start(message: types.Message):
    await message.answer("Hello!")

# Запуск процесса поллинга новых апдейтов
async def main():
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())


'''
bot = telebot.TeleBot(TG_KEY);

@bot.message_handler(content_types=['text'])
def get_text_messages(message):
    if message.text == "Привет":
        bot.send_message(message.from_user.id, "Привет чем могу помочь?")
    elif message.text == "/help":
        bot.send_message(message.from_user.id, "Напиши привет")
    else:
        bot.send_message(message.from_user.id, "Я тебя не понимаю. Напиши /help")

bot.polling(none_stop=True, interval=0)

test = ip_info('193.124.92.111')
print(test)

file_path = input("Type the input file (Example: input.txt): ")
process_ip_list(file_path)
'''
